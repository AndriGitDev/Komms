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
//! magic "KKR3" (4) ‖ m_cost_kib u32 LE ‖ t_cost u32 LE ‖ p_cost u32 LE
//!   ‖ salt (16) ‖ sealed( postcard(BackupPayload) )
//! ```
//!
//! Files with the older `KKR1` (pre-groups) and `KKR2` (pre-local-metadata)
//! magic still restore with the same header layout.
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
    derive_kek, mnemonic_from_entropy, mnemonic_to_entropy, GroupSenderChain, Identity, KdfProfile,
    StorageKey,
};

use crate::{
    ContactRecord, GroupMember, GroupMessageRecord, GroupRecord, LocalMetadataRecord,
    MessageRecord, PendingAnnounce, Result, Store, StoreError,
};

/// Backup file magic: Komms recovery file, format 3 (local metadata included).
pub const BACKUP_MAGIC: [u8; 4] = *b"KKR3";
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
    /// User-authored local organization, drafts, preferences, and icons.
    local_metadata: Vec<LocalMetadataRecord>,
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
        let payload = BackupPayload {
            created_at: now,
            identity: identity.to_bytes().to_vec(),
            contacts: self.contacts()?,
            messages: self.all_messages()?,
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
                .map(|mut m| {
                    m.wire_body = None;
                    m
                })
                .collect(),
            local_metadata: self.local_metadata()?,
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
            BACKUP_MAGIC => 3,
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
                    local_metadata: Vec::new(),
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
                    local_metadata: Vec::new(),
                }
            }
            3 => decode_exact(&plain)?,
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
        for record in &payload.local_metadata {
            store.put_local_metadata(record, rng)?;
        }
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
    fn all_messages(&self) -> Result<Vec<MessageRecord>> {
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
