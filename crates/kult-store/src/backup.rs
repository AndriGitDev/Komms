//! Encrypted single-file backup (docs/07-storage.md §4,
//! docs/06-identity-trust.md §5).
//!
//! One export carries identity + contacts + message history (pairwise and
//! group) + group state + session-reset markers, sealed under a key derived
//! from a 24-word mnemonic ([`kult_crypto::mnemonic_from_entropy`]) via
//! Argon2id. What it deliberately does **not** carry:
//!
//! - **Ratchet session state** — importing stale ratchet state is a
//!   correctness and security hazard (old message keys resurrected, replay
//!   windows confused). Instead, the peers that had live sessions at export
//!   time are recorded as *reset markers*, and the restored node
//!   re-handshakes them from the stored prekey bundles.
//! - **Group chains** (ADR-0012) — same hazard class as ratchets: restored
//!   chain state forks the moment either copy advances. A restored node
//!   mints a fresh sending chain per group (announced to the roster on the
//!   first tick), and co-members redistribute theirs over the
//!   re-handshaken sessions.
//! - **Own prekey secrets** — a restored device mints a fresh vault; the
//!   old device's one-time prekeys must never be honored twice.
//! - **Queues and stashes** — in-flight envelopes belong to the old
//!   device's sessions and are honestly lost; the *senders'* end-to-end
//!   retries are the source of reliability.
//!
//! File layout (strict, all-or-nothing, like the sneakernet bundle format):
//!
//! ```text
//! magic "KKR7" (4) ‖ m_cost_kib u32 LE ‖ t_cost u32 LE ‖ p_cost u32 LE
//!   ‖ salt (16) ‖ sealed( postcard(BackupPayload) )
//! ```
//!
//! Files with the older `KKR1` through `KKR6` magic still restore with the
//! same header layout.
//!
//! The Argon2id cost parameters ride in the header so a backup written on
//! one device class (mobile profile) restores on any other; the sealed
//! blob is an ordinary [`kult_crypto::StorageKey`] AEAD envelope
//! (XChaCha20-Poly1305, random 24-byte nonce). A wrong mnemonic and a
//! corrupted file are deliberately indistinguishable — uniform AEAD
//! failure, no oracle.

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use kult_crypto::{
    derive_kek, mnemonic_from_entropy, mnemonic_to_entropy, DeviceCertificate, DeviceManifest,
    DeviceManifestEntry, GroupSenderChain, Identity, KdfProfile, StorageKey, MAX_LINKED_DEVICES,
};
use kult_protocol::DeviceSyncEvent;

use crate::{
    ContactDeviceRecord, ContactRecord, DeviceStateRecord, EphemeralConversation, EphemeralRecord,
    EphemeralState, GroupAuthorityRecord, GroupMember, GroupMessageRecord, GroupRecord,
    LocalMetadataRecord, MessageRecord, NoteMessageRecord, PendingAnnounce, Result, Store,
    StoreError,
};

/// Backup file magic: Komms recovery file, format 7 (linked-device authority).
pub const BACKUP_MAGIC: [u8; 4] = *b"KKR7";
/// The pre-linked-device format 6 magic — still restorable.
pub const BACKUP_MAGIC_V6: [u8; 4] = *b"KKR6";
/// The pre-group-authority format 5 magic — still restorable.
pub const BACKUP_MAGIC_V5: [u8; 4] = *b"KKR5";
/// The pre-ephemeral-tombstone format 4 magic — still restorable.
pub const BACKUP_MAGIC_V4: [u8; 4] = *b"KKR4";
/// The pre-note-to-self format 3 magic — still restorable.
pub const BACKUP_MAGIC_V3: [u8; 4] = *b"KKR3";
/// The pre-local-metadata format 2 magic — still restorable.
pub const BACKUP_MAGIC_V2: [u8; 4] = *b"KKR2";
/// The pre-groups format 1 magic — still restorable.
pub const BACKUP_MAGIC_V1: [u8; 4] = *b"KKR1";

const BACKUP_AD: &[u8] = b"KK-backup-v1";
const HEADER_LEN: usize = 4 + 12 + 16;

/// A group's durable identity in a backup: everything but the chains.
#[derive(Serialize, Deserialize)]
struct BackupGroup {
    id: [u8; 32],
    name: String,
    creator: [u8; 32],
    members: Vec<GroupMember>,
    secret: [u8; 32],
    generation: u64,
}

/// Everything a backup carries, sealed as one postcard blob.
#[derive(Serialize, Deserialize)]
struct BackupPayload {
    /// Export time (Unix seconds) — display only, never trusted for crypto.
    created_at: u64,
    /// [`Identity::to_bytes`] output (64 bytes).
    identity: Vec<u8>,
    /// All contacts, verbatim (names, bundles, hints, verification state).
    contacts: Vec<ContactRecord>,
    /// Full message history, verbatim.
    messages: Vec<MessageRecord>,
    /// Session-reset markers: peers with a live ratchet session at export
    /// time. The restored node re-handshakes exactly these.
    reset_peers: Vec<[u8; 32]>,
    /// Group identities (never chains — module docs).
    groups: Vec<BackupGroup>,
    /// Group message history (wire bodies stripped: any unserved fan-out
    /// belonged to the dead chains).
    group_messages: Vec<GroupMessageRecord>,
    /// Signed C6 authority state and consumed admin request ids.
    group_authorities: Vec<GroupAuthorityRecord>,
    /// User-authored local organization, drafts, preferences, and icons.
    local_metadata: Vec<LocalMetadataRecord>,
    /// First-class local note-to-self text history.
    note_messages: Vec<NoteMessageRecord>,
    /// Tombstones only: ephemeral plaintext/media is never backed up.
    ephemeral: Vec<EphemeralRecord>,
    /// Latest signed device authority, but never local device/channel secrets.
    device_manifest: Option<DeviceManifest>,
    /// Exporting physical device, revoked during recovery.
    local_device: Option<[u8; 32]>,
    /// Authenticated convergence events used for revocation cutoffs and sync.
    device_sync_events: Vec<Vec<u8>>,
    /// Contact physical endpoints; ratchet session state remains excluded.
    contact_devices: Vec<ContactDeviceRecord>,
}

/// The `KKR6` payload shape, before linked-device authority existed.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV6 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    group_authorities: Vec<GroupAuthorityRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
}

/// The `KKR5` payload shape, before C6 signed group authority existed.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV5 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
}

/// The `KKR4` payload shape, before ephemeral tombstones existed.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV4 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
}

/// The `KKR1` payload shape, for restoring pre-groups backups.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV1 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
}

/// The `KKR2` payload shape, before F5 local metadata existed.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV2 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
}

/// The `KKR3` payload shape, before note-to-self history existed.
#[derive(Serialize, Deserialize)]
struct BackupPayloadV3 {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let (value, remainder) =
        postcard::take_from_bytes(bytes).map_err(|_| StoreError::NotABackup)?;
    if !remainder.is_empty() {
        return Err(StoreError::NotABackup);
    }
    Ok(value)
}

impl Store {
    /// Export this store as an encrypted backup file. Returns the file
    /// bytes and the freshly minted 24-word mnemonic that seals them —
    /// show it to the user once, then drop it; it is not stored anywhere.
    ///
    /// The backup key is derived with this store's own Argon2id profile
    /// (recorded in the file header for restore).
    pub fn export_backup(
        &self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, Zeroizing<String>)> {
        let identity = self.get_identity()?.ok_or(StoreError::NotAStore)?;
        let mut ephemeral = self.ephemeral_records()?;
        // Recovery never resurrects content carrying an erasure promise.
        // Convert even currently-live markers into terminal tombstones and
        // omit all associated plaintext and media (media is excluded from
        // every backup generation already).
        for record in &mut ephemeral {
            record.state = EphemeralState::Expired;
            record.transfer_ids.clear();
        }
        let me = identity.public().ed;
        let device_state = self.get_device_state()?;
        let payload = BackupPayload {
            created_at: now,
            identity: identity.to_bytes().to_vec(),
            contacts: self.contacts()?,
            messages: self
                .all_messages()?
                .into_iter()
                .filter(|message| {
                    let author = if message.direction == crate::Direction::Outbound {
                        me
                    } else {
                        message.peer
                    };
                    !ephemeral.iter().any(|record| {
                        record.conversation == EphemeralConversation::Pairwise(message.peer)
                            && record.author == author
                            && record.content_id == message.id
                    })
                })
                .collect(),
            reset_peers: self.session_peers()?,
            groups: self
                .groups()?
                .into_iter()
                .map(|g| BackupGroup {
                    id: g.id,
                    name: g.name,
                    creator: g.creator,
                    members: g.members,
                    secret: g.secret,
                    generation: g.generation,
                })
                .collect(),
            group_messages: self
                .all_group_messages()?
                .into_iter()
                .filter(|message| {
                    !ephemeral.iter().any(|record| {
                        record.conversation == EphemeralConversation::Group(message.group)
                            && record.author == message.sender
                            && record.content_id == message.id
                    })
                })
                .map(|mut m| {
                    m.wire_body = None;
                    m
                })
                .collect(),
            group_authorities: self.group_authorities()?,
            local_metadata: self.local_metadata()?,
            note_messages: self.note_messages()?,
            ephemeral,
            device_manifest: device_state.as_ref().map(|state| state.manifest.clone()),
            local_device: device_state
                .as_ref()
                .map(|state| state.local_certificate.device_id()),
            device_sync_events: self.device_sync_events()?,
            contact_devices: self.contact_devices()?,
        };
        let plain =
            Zeroizing::new(postcard::to_allocvec(&payload).map_err(|_| StoreError::Serialization)?);

        let mut entropy = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(entropy.as_mut());
        let mnemonic = mnemonic_from_entropy(&entropy);

        let profile = self.kdf_profile()?;
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let kek = derive_kek(&entropy[..], &salt, profile)?;
        let key = StorageKey::from_bytes(*kek);

        let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + 40);
        out.extend_from_slice(&BACKUP_MAGIC);
        out.extend_from_slice(&profile.m_cost_kib.to_le_bytes());
        out.extend_from_slice(&profile.t_cost.to_le_bytes());
        out.extend_from_slice(&profile.p_cost.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&key.seal(BACKUP_AD, &plain, rng));
        Ok((out, mnemonic))
    }

    /// Restore a backup into a **new** store at `path` (refuses to clobber
    /// an existing one), unlocked by `mnemonic` and re-encrypted at rest
    /// under `passphrase` with the given Argon2id profile.
    ///
    /// The restored store resumes the exported identity with contacts and
    /// history intact; sessions and prekeys are deliberately absent (the
    /// node layer mints fresh prekeys and re-handshakes the reset-marker
    /// peers). Any parse or authentication failure rejects the whole file.
    pub fn restore_backup(
        path: &std::path::Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if backup.len() <= HEADER_LEN {
            return Err(StoreError::NotABackup);
        }
        let version = match <[u8; 4]>::try_from(&backup[..4]).expect("length checked") {
            BACKUP_MAGIC => 7,
            BACKUP_MAGIC_V6 => 6,
            BACKUP_MAGIC_V5 => 5,
            BACKUP_MAGIC_V4 => 4,
            BACKUP_MAGIC_V3 => 3,
            BACKUP_MAGIC_V2 => 2,
            BACKUP_MAGIC_V1 => 1,
            _ => return Err(StoreError::NotABackup),
        };
        let word = |at: usize| -> u32 {
            u32::from_le_bytes(backup[at..at + 4].try_into().expect("length checked"))
        };
        let file_profile = KdfProfile {
            m_cost_kib: word(4),
            t_cost: word(8),
            p_cost: word(12),
        };
        let salt: [u8; 16] = backup[16..32].try_into().expect("length checked");

        let entropy = mnemonic_to_entropy(mnemonic)?;
        let kek = derive_kek(&entropy[..], &salt, file_profile)?;
        let key = StorageKey::from_bytes(*kek);
        let plain = Zeroizing::new(key.open(BACKUP_AD, &backup[HEADER_LEN..])?);
        let mut payload: BackupPayload = match version {
            1 => {
                let v1: BackupPayloadV1 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v1.created_at,
                    identity: v1.identity,
                    contacts: v1.contacts,
                    messages: v1.messages,
                    reset_peers: v1.reset_peers,
                    groups: Vec::new(),
                    group_messages: Vec::new(),
                    group_authorities: Vec::new(),
                    local_metadata: Vec::new(),
                    note_messages: Vec::new(),
                    ephemeral: Vec::new(),
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            2 => {
                let v2: BackupPayloadV2 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v2.created_at,
                    identity: v2.identity,
                    contacts: v2.contacts,
                    messages: v2.messages,
                    reset_peers: v2.reset_peers,
                    groups: v2.groups,
                    group_messages: v2.group_messages,
                    group_authorities: Vec::new(),
                    local_metadata: Vec::new(),
                    note_messages: Vec::new(),
                    ephemeral: Vec::new(),
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            3 => {
                let v3: BackupPayloadV3 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v3.created_at,
                    identity: v3.identity,
                    contacts: v3.contacts,
                    messages: v3.messages,
                    reset_peers: v3.reset_peers,
                    groups: v3.groups,
                    group_messages: v3.group_messages,
                    group_authorities: Vec::new(),
                    local_metadata: v3.local_metadata,
                    note_messages: Vec::new(),
                    ephemeral: Vec::new(),
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            4 => {
                let v4: BackupPayloadV4 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v4.created_at,
                    identity: v4.identity,
                    contacts: v4.contacts,
                    messages: v4.messages,
                    reset_peers: v4.reset_peers,
                    groups: v4.groups,
                    group_messages: v4.group_messages,
                    group_authorities: Vec::new(),
                    local_metadata: v4.local_metadata,
                    note_messages: v4.note_messages,
                    ephemeral: Vec::new(),
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            5 => {
                let v5: BackupPayloadV5 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v5.created_at,
                    identity: v5.identity,
                    contacts: v5.contacts,
                    messages: v5.messages,
                    reset_peers: v5.reset_peers,
                    groups: v5.groups,
                    group_messages: v5.group_messages,
                    group_authorities: Vec::new(),
                    local_metadata: v5.local_metadata,
                    note_messages: v5.note_messages,
                    ephemeral: v5.ephemeral,
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            6 => {
                let v6: BackupPayloadV6 = decode_exact(&plain)?;
                BackupPayload {
                    created_at: v6.created_at,
                    identity: v6.identity,
                    contacts: v6.contacts,
                    messages: v6.messages,
                    reset_peers: v6.reset_peers,
                    groups: v6.groups,
                    group_messages: v6.group_messages,
                    group_authorities: v6.group_authorities,
                    local_metadata: v6.local_metadata,
                    note_messages: v6.note_messages,
                    ephemeral: v6.ephemeral,
                    device_manifest: None,
                    local_device: None,
                    device_sync_events: Vec::new(),
                    contact_devices: Vec::new(),
                }
            }
            7 => decode_exact(&plain)?,
            _ => unreachable!("version matched above"),
        };
        let identity_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
            payload.identity[..]
                .try_into()
                .map_err(|_| StoreError::NotABackup)?,
        );
        payload.identity.zeroize();
        let identity = Identity::from_bytes(&identity_bytes);
        let me = identity.public().ed;

        let store = Store::create(path, passphrase, profile, rng)?;
        store.put_identity(&identity, rng)?;
        for contact in &payload.contacts {
            store.put_contact(contact, rng)?;
        }
        for endpoint in &payload.contact_devices {
            store.put_contact_device(endpoint, rng)?;
        }
        for message in &payload.messages {
            store.put_message(message, rng)?;
        }
        for peer in &payload.reset_peers {
            store.put_reset_marker(peer)?;
        }
        for group in payload.groups {
            // Fresh chain, announced to the full roster: the old chains died
            // with the old device (module docs). Receiving chains rebuild as
            // co-members redistribute over the re-handshaken sessions.
            let chain = GroupSenderChain::generate(rng);
            let (key_id, chain_key, iteration) = chain.snapshot();
            let pending = group
                .members
                .iter()
                .filter(|m| m.peer != me)
                .map(|m| PendingAnnounce {
                    peer: m.peer,
                    key_id,
                    chain_key: *chain_key,
                    iteration,
                    wire_id: None,
                    last_sent: 0,
                })
                .collect();
            store.put_group(
                &GroupRecord {
                    id: group.id,
                    name: group.name,
                    creator: group.creator,
                    members: group.members,
                    secret: group.secret,
                    prev_secret: None,
                    generation: group.generation,
                    sender_chain: postcard::to_allocvec(&chain)
                        .map_err(|_| StoreError::Serialization)?,
                    sent_since_rotation: 0,
                    pending,
                },
                rng,
            )?;
        }
        for message in &payload.group_messages {
            store.put_group_message(message, rng)?;
        }
        for authority in &payload.group_authorities {
            store.put_group_authority(authority, rng)?;
        }
        for record in &payload.local_metadata {
            store.put_local_metadata(record, rng)?;
        }
        for message in &payload.note_messages {
            store.put_note_message(message, rng)?;
        }
        for record in &payload.ephemeral {
            store.put_ephemeral_record(record, rng)?;
        }
        for event in &payload.device_sync_events {
            let decoded = DeviceSyncEvent::decode(event)?;
            if let Some(manifest) = &payload.device_manifest {
                decoded.verify(manifest)?;
            } else {
                return Err(StoreError::NotABackup);
            }
            store.put_device_sync_event(event, rng)?;
        }
        restore_device_state(
            &store,
            &identity,
            payload.device_manifest,
            payload.local_device,
            &payload.device_sync_events,
            payload.created_at,
            rng,
        )?;
        Ok(store)
    }

    /// The Argon2id profile this store was created with.
    fn kdf_profile(&self) -> Result<KdfProfile> {
        let blob: Vec<u8> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'kdf'", [], |r| r.get(0))
            .map_err(|_| StoreError::NotAStore)?;
        let (m, t, p): (u32, u32, u32) =
            postcard::from_bytes(&blob).map_err(|_| StoreError::NotAStore)?;
        Ok(KdfProfile {
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
        })
    }

    /// Every stored message, in insertion order.
    pub(crate) fn all_messages(&self) -> Result<Vec<MessageRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT blob FROM messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_messages.open(b"message", &row?)?;
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    /// Peers with a persisted ratchet session.
    fn session_peers(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare("SELECT peer FROM sessions")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(peer) = <[u8; 32]>::try_from(row?) {
                out.push(peer);
            }
        }
        Ok(out)
    }

    // ---- session-reset markers ---------------------------------------------

    /// Record that any pre-restore session with this peer is dead and must
    /// be re-established (docs/07-storage.md §4).
    pub fn put_reset_marker(&self, peer: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO resets (peer) VALUES (?1)",
            params![peer.as_slice()],
        )?;
        Ok(())
    }

    /// All pending session-reset markers.
    pub fn reset_markers(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare("SELECT peer FROM resets")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(peer) = <[u8; 32]>::try_from(row?) {
                out.push(peer);
            }
        }
        Ok(out)
    }

    /// Remove a session-reset marker (the re-handshake was queued).
    pub fn clear_reset_marker(&self, peer: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM resets WHERE peer = ?1",
            params![peer.as_slice()],
        )?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn restore_device_state(
    store: &Store,
    account: &Identity,
    prior_manifest: Option<DeviceManifest>,
    prior_local_device: Option<[u8; 32]>,
    sync_events: &[Vec<u8>],
    created_at: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let device = Identity::generate(rng);
    let certificate = DeviceCertificate::issue(account, &device, created_at, rng);
    let manifest =
        if let Some(mut manifest) = prior_manifest {
            manifest.verify()?;
            if manifest.account != account.public() {
                return Err(StoreError::NotABackup);
            }
            let prior_local = prior_local_device.ok_or(StoreError::NotABackup)?;
            if !manifest.devices.iter().any(|entry| {
                entry.certificate.device_id() == prior_local && entry.revoked_at.is_none()
            }) {
                return Err(StoreError::NotABackup);
            }
            let counter_for = |device_id: &[u8; 32]| -> Result<u64> {
                let mut counter = 0u64;
                for encoded in sync_events {
                    let event = DeviceSyncEvent::decode(encoded)?;
                    if &event.author_device == device_id {
                        counter = counter.max(event.counter);
                    }
                }
                Ok(counter)
            };
            let active = manifest
                .devices
                .iter()
                .filter(|entry| entry.revoked_at.is_none())
                .count();
            if active >= MAX_LINKED_DEVICES {
                let cutoff = counter_for(&prior_local)?;
                manifest.revoke_device(account, &prior_local, created_at, cutoff)?;
            }
            manifest.add_device(
                account,
                DeviceManifestEntry {
                    certificate: certificate.clone(),
                    name: "Recovered device".into(),
                    last_seen: created_at,
                    revoked_at: None,
                    revoked_after_counter: None,
                },
            )?;
            let old_active: Vec<[u8; 32]> = manifest
                .devices
                .iter()
                .filter(|entry| {
                    entry.revoked_at.is_none()
                        && entry.certificate.device_id() != certificate.device_id()
                })
                .map(|entry| entry.certificate.device_id())
                .collect();
            for old in old_active {
                let cutoff = counter_for(&old)?;
                manifest.revoke_device(account, &old, created_at, cutoff)?;
            }
            manifest
        } else {
            DeviceManifest::initial(
                account,
                certificate.clone(),
                "Recovered device".into(),
                created_at,
            )?
        };
    store.put_device_state(
        &DeviceStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: certificate,
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
        },
        rng,
    )?;
    Ok(())
}
