//! Encrypted single-file backup (docs/07-storage.md §4,
//! docs/06-identity-trust.md §5).
//!
//! Current `KKR10` export carries the public account anchor, accepted authority
//! proof, contacts, eligible history, local organization, and local block
//! rules, sealed under a
//! key derived from a 24-word mnemonic
//! ([`kult_crypto::mnemonic_from_entropy`]) via Argon2id. Legacy `KKR1`
//! through copied-root `KKR7` remain decodable only for the explicit
//! new-identity archive reset; root-free `KKR8` remains directly restorable.
//! What current export deliberately does **not** carry:
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
//! - **Provisional first-contact state** — invitation capabilities, detached
//!   provisional sessions, request previews, and replay tombstones are
//!   short-lived device-local admission state.
//! - **Queues and stashes** — in-flight envelopes belong to the old
//!   device's sessions and are honestly lost; the *senders'* end-to-end
//!   retries are the source of reliability.
//!
//! File layout (strict, all-or-nothing, like the sneakernet bundle format):
//!
//! ```text
//! magic "KKR10" (represented as `KKRA`, 4 bytes) ‖ m_cost_kib u32 LE
//!   ‖ t_cost u32 LE ‖ p_cost u32 LE
//!   ‖ salt (16) ‖ sealed( postcard(AuthorityBackupPayload) )
//! ```
//!
//! Files with `KKR1` through `KKR7` use the same header layout but a legacy
//! associated-data domain and payload. They never resume their former account.
//!
//! The Argon2id cost parameters ride in the header so a backup written on
//! one device class (mobile profile) restores on any other; the sealed
//! blob is an ordinary [`kult_crypto::StorageKey`] AEAD envelope
//! (XChaCha20-Poly1305, random 24-byte nonce). A wrong mnemonic and a
//! corrupted file are deliberately indistinguishable — uniform AEAD
//! failure, no oracle.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use rand_core::CryptoRngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use kult_crypto::{
    derive_kek, mnemonic_from_entropy, mnemonic_to_entropy, ConnectCode, DeviceAuthorityManifest,
    DeviceManifest, GroupSenderChain, Identity, IdentityPublic, KdfProfile, StorageKey,
};
#[cfg(test)]
use kult_crypto::{DeviceCertificate, DeviceManifestEntry, MAX_LINKED_DEVICES};
#[cfg(test)]
use kult_protocol::DeviceSyncEvent;

use crate::{
    acquire_database_identity_lock, acquire_store_lock, decode_exact as decode_store_exact,
    migration, store_v2, AuthorityProfileBootstrapPlan, AuthorityResetHistoryRecord,
    BlockedIdentityRecord, CommitPlan, ContactDeviceRecord, ContactRecord, ConversationId,
    CustomIconTarget, DeviceAuthorityStateRecord, DiscoveryCapabilityState, EphemeralConversation,
    EphemeralRecord, EphemeralState, GroupAuthorityRecord, GroupMember, GroupMessageRecord,
    GroupRecord, LocalMetadataRecord, MessageRecord, NoteMessageRecord, PendingAnnounce, Result,
    Store, StoreError, AUTHORITY_RESET_HISTORY_KEY, MAX_AUTHORITY_RESET_CONTACTS,
    THEME_PREFERENCE_KEY,
};
#[cfg(any(test, feature = "legacy-test-fixtures"))]
use crate::{DeviceStateRecord, ProfileBootstrapPlan};

/// Current root-free backup magic: Komms recovery file, format 10.
pub const AUTHORITY_BACKUP_MAGIC: [u8; 4] = *b"KKRA";
/// Root-free backup format 9, before the Connect capability was retained.
pub const AUTHORITY_BACKUP_MAGIC_V9: [u8; 4] = *b"KKR9";
/// Root-free backup format 8, before durable local block rules were retained.
pub const AUTHORITY_BACKUP_MAGIC_V8: [u8; 4] = *b"KKR8";
/// Legacy copied-root backup magic, format 7.
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
const AUTHORITY_BACKUP_AD: &[u8] = b"Komms-root-free-backup-v10";
const AUTHORITY_BACKUP_AD_V9: &[u8] = b"Komms-root-free-backup-v9";
const AUTHORITY_BACKUP_AD_V8: &[u8] = b"Komms-root-free-backup-v8";
const HEADER_LEN: usize = 4 + 12 + 16;
const MAX_BACKUP_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BACKUP_RECORDS: u64 = 50_000_000;
const RESTORE_SPACE_RESERVE: u64 = 64 * 1024 * 1024;
const ESTIMATED_RESTORED_ROW_BYTES: u64 = 2_048;

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

/// Root-free ADR-0026 backup payload. The account root, reusable physical
/// device credentials, sync channel roots, ratchets, sender/receiver chains,
/// rendezvous/wake state, and queued delivery work have no fields here.
#[derive(Serialize, Deserialize)]
struct AuthorityBackupPayload {
    created_at: u64,
    account: IdentityPublic,
    authority: DeviceAuthorityManifest,
    discovery: DiscoveryCapabilityState,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    group_authorities: Vec<GroupAuthorityRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
    contact_devices: Vec<ContactDeviceRecord>,
    blocked_identities: Vec<BlockedIdentityRecord>,
}

/// Root-free format 9, before the Connect capability was retained.
#[derive(Serialize, Deserialize)]
struct AuthorityBackupPayloadV9 {
    created_at: u64,
    account: IdentityPublic,
    authority: DeviceAuthorityManifest,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    group_authorities: Vec<GroupAuthorityRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
    contact_devices: Vec<ContactDeviceRecord>,
    blocked_identities: Vec<BlockedIdentityRecord>,
}

/// Root-free format 8, before durable local block rules were retained.
#[derive(Serialize, Deserialize)]
struct AuthorityBackupPayloadV8 {
    created_at: u64,
    account: IdentityPublic,
    authority: DeviceAuthorityManifest,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<BackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    group_authorities: Vec<GroupAuthorityRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
    contact_devices: Vec<ContactDeviceRecord>,
}

impl From<AuthorityBackupPayloadV8> for AuthorityBackupPayload {
    fn from(payload: AuthorityBackupPayloadV8) -> Self {
        Self {
            created_at: payload.created_at,
            account: payload.account,
            authority: payload.authority,
            discovery: DiscoveryCapabilityState::default(),
            contacts: payload.contacts,
            messages: payload.messages,
            reset_peers: payload.reset_peers,
            groups: payload.groups,
            group_messages: payload.group_messages,
            group_authorities: payload.group_authorities,
            local_metadata: payload.local_metadata,
            note_messages: payload.note_messages,
            ephemeral: payload.ephemeral,
            contact_devices: payload.contact_devices,
            blocked_identities: Vec::new(),
        }
    }
}

impl From<AuthorityBackupPayloadV9> for AuthorityBackupPayload {
    fn from(payload: AuthorityBackupPayloadV9) -> Self {
        Self {
            created_at: payload.created_at,
            account: payload.account,
            authority: payload.authority,
            discovery: DiscoveryCapabilityState::default(),
            contacts: payload.contacts,
            messages: payload.messages,
            reset_peers: payload.reset_peers,
            groups: payload.groups,
            group_messages: payload.group_messages,
            group_authorities: payload.group_authorities,
            local_metadata: payload.local_metadata,
            note_messages: payload.note_messages,
            ephemeral: payload.ephemeral,
            contact_devices: payload.contact_devices,
            blocked_identities: payload.blocked_identities,
        }
    }
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

struct AuthorityResetProjection {
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    notes: Vec<NoteMessageRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    history: AuthorityResetHistoryRecord,
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
    /// Create and fully initialize a new profile in a same-directory sibling,
    /// then publish it at `path` with one crash-safe atomic replacement.
    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    #[doc(hidden)]
    pub fn create_legacy_profile_fixture(
        path: &Path,
        passphrase: &[u8],
        profile: KdfProfile,
        identity: &Identity,
        device_state: &DeviceStateRecord,
        prekeys: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let temporary = initialization_temporary_path(path)?;
        if temporary.exists() {
            cleanup_initialization_temporary(&temporary)?;
        }
        let store = match Store::create(&temporary, passphrase, profile, rng) {
            Ok(store) => store,
            Err(error) => {
                cleanup_initialization_temporary(&temporary)?;
                return Err(error);
            }
        };
        if let Err(error) = store.commit_plan(
            CommitPlan::ProfileBootstrap(ProfileBootstrapPlan {
                identity,
                device_state,
                prekeys,
            }),
            rng,
        ) {
            drop(store);
            cleanup_initialization_temporary(&temporary)?;
            return Err(error);
        }
        store.validate_open_state()?;
        migration::sync_database_for_replacement(&store.conn)?;
        drop(store);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        initialization_failpoint(1)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        migration::atomic_replace(&temporary, path)?;
        initialization_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        initialization_failpoint(3)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        let store = Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok(store)
    }

    /// Create and publish a new ADR-0026 profile without storing the account root.
    pub fn create_authority_profile(
        path: &Path,
        passphrase: &[u8],
        profile: KdfProfile,
        account: &IdentityPublic,
        device_state: &DeviceAuthorityStateRecord,
        prekeys: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let temporary = initialization_temporary_path(path)?;
        if temporary.exists() {
            cleanup_initialization_temporary(&temporary)?;
        }
        let store = match Store::create(&temporary, passphrase, profile, rng) {
            Ok(store) => store,
            Err(error) => {
                cleanup_initialization_temporary(&temporary)?;
                return Err(error);
            }
        };
        if let Err(error) = store.commit_plan(
            CommitPlan::AuthorityProfileBootstrap(AuthorityProfileBootstrapPlan {
                account,
                device_state,
                prekeys,
            }),
            rng,
        ) {
            drop(store);
            cleanup_initialization_temporary(&temporary)?;
            return Err(error);
        }
        store.validate_open_state()?;
        migration::sync_database_for_replacement(&store.conn)?;
        drop(store);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        initialization_failpoint(1)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        migration::atomic_replace(&temporary, path)?;
        initialization_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        initialization_failpoint(3)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        let store = Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok(store)
    }

    /// Replace one copied-root Alpha profile with a fresh root-free identity.
    ///
    /// The new database preserves only explicitly local compatibility data:
    /// petnames and public contact identities (with routes and verification
    /// cleared), non-ephemeral pairwise history marked by the durable reset
    /// record, note-to-self history, and eligible local organization. Device,
    /// session, delivery, group, rendezvous, wake, queue, prekey, and media
    /// state never enters the sibling. The completed sibling replaces the
    /// source database atomically while the source writer lock remains held.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_copied_root_profile(
        self,
        passphrase: &[u8],
        account: &IdentityPublic,
        device_state: &DeviceAuthorityStateRecord,
        prekeys: &[u8],
        reset_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, AuthorityResetHistoryRecord)> {
        account.verify()?;
        device_state.validate(account)?;
        let former_root = self.get_identity()?.ok_or(StoreError::InvalidTransition)?;
        self.get_device_state()?
            .ok_or(StoreError::InvalidTransition)?;
        if former_root.public() == *account {
            return Err(StoreError::InvalidTransition);
        }

        let mut contacts = self.contacts()?;
        if contacts.len() > MAX_AUTHORITY_RESET_CONTACTS {
            return Err(StoreError::RecordBounds);
        }
        for contact in &mut contacts {
            contact.bundle.clear();
            contact.hints.clear();
            contact.verified = false;
        }
        let contact_ids = contacts
            .iter()
            .map(|contact| contact.peer)
            .collect::<HashSet<_>>();

        let ephemeral_pairwise = self
            .ephemeral_records()?
            .into_iter()
            .filter_map(|record| match record.conversation {
                EphemeralConversation::Pairwise(peer) => Some((peer, record.content_id)),
                EphemeralConversation::Group(_) => None,
            })
            .collect::<HashSet<_>>();
        let mut messages = self
            .all_messages()?
            .into_iter()
            .filter(|message| {
                contact_ids.contains(&message.peer)
                    && !ephemeral_pairwise.contains(&(message.peer, message.id))
            })
            .collect::<Vec<_>>();
        for message in &mut messages {
            if message.direction == crate::Direction::Outbound
                && matches!(
                    message.state,
                    crate::DeliveryState::Queued | crate::DeliveryState::Sent
                )
            {
                message.state = crate::DeliveryState::Failed;
            }
            message.wire_id = None;
        }
        let notes = self.note_messages()?;
        let groups = self.groups()?;
        let group_messages = self.all_group_messages()?;

        let local_metadata = self
            .local_metadata()?
            .into_iter()
            .filter(|record| match record {
                LocalMetadataRecord::Conversation(record) => {
                    reset_conversation_survives(&record.conversation, &contact_ids)
                }
                LocalMetadataRecord::Folder(_) | LocalMetadataRecord::Label(_) => true,
                LocalMetadataRecord::FolderAssignment(record) => {
                    reset_conversation_survives(&record.conversation, &contact_ids)
                }
                LocalMetadataRecord::Pin(record) => {
                    reset_conversation_survives(&record.conversation, &contact_ids)
                }
                LocalMetadataRecord::LabelAssignment(record) => {
                    reset_conversation_survives(&record.conversation, &contact_ids)
                }
                LocalMetadataRecord::Draft(_) => false,
                LocalMetadataRecord::UiPreference(record) => {
                    record.key == THEME_PREFERENCE_KEY && record.key != AUTHORITY_RESET_HISTORY_KEY
                }
                LocalMetadataRecord::CustomIcon(record) => match &record.target {
                    CustomIconTarget::Contact(peer) => contact_ids.contains(peer),
                    CustomIconTarget::Folder(_) | CustomIconTarget::NoteToSelf => true,
                    CustomIconTarget::Group(_) => false,
                },
            })
            .collect::<Vec<_>>();

        let record_count = contacts
            .len()
            .checked_add(messages.len())
            .and_then(|count| count.checked_add(notes.len()))
            .and_then(|count| count.checked_add(local_metadata.len()))
            .and_then(|count| count.checked_add(3))
            .ok_or(StoreError::RecordBounds)?;
        if u64::try_from(record_count).map_or(true, |count| count > MAX_BACKUP_RECORDS) {
            return Err(StoreError::RecordBounds);
        }
        let history = AuthorityResetHistoryRecord {
            former_account: former_root.public().ed,
            new_account: account.ed,
            reset_at,
            preserved_contacts: u32::try_from(contacts.len())
                .map_err(|_| StoreError::RecordBounds)?,
            preserved_pairwise_messages: u64::try_from(messages.len())
                .map_err(|_| StoreError::RecordBounds)?,
            preserved_note_messages: u64::try_from(notes.len())
                .map_err(|_| StoreError::RecordBounds)?,
            omitted_groups: u64::try_from(groups.len()).map_err(|_| StoreError::RecordBounds)?,
            omitted_group_messages: u64::try_from(group_messages.len())
                .map_err(|_| StoreError::RecordBounds)?,
            pending_reverification: contacts.iter().map(|contact| contact.peer).collect(),
        };

        let path = self.path.clone();
        let profile = self.kdf_profile;
        let temporary = authority_reset_temporary_path(&path)?;
        if temporary.exists() {
            cleanup_authority_reset_temporary(&temporary)?;
        }
        let source_bytes =
            usize::try_from(fs::metadata(&path)?.len()).map_err(|_| StoreError::RecordBounds)?;
        ensure_restore_workspace(
            &path,
            source_bytes,
            u64::try_from(record_count).map_err(|_| StoreError::RecordBounds)?,
        )?;

        let target = match Store::create(&temporary, passphrase, profile, rng) {
            Ok(target) => target,
            Err(error) => {
                cleanup_authority_reset_temporary(&temporary)?;
                return Err(error);
            }
        };
        let build = (|| {
            target.commit_plan(
                CommitPlan::AuthorityProfileBootstrap(AuthorityProfileBootstrapPlan {
                    account,
                    device_state,
                    prekeys,
                }),
                rng,
            )?;
            for contact in &contacts {
                target.put_contact(contact, rng)?;
            }
            for message in &messages {
                target.put_message(message, rng)?;
            }
            for note in &notes {
                target.put_note_message(note, rng)?;
            }
            for record in &local_metadata {
                target.put_local_metadata(record, rng)?;
            }
            target.put_authority_reset_history(&history, rng)?;
            target.validate_open_state()?;
            migration::sync_database_for_replacement(&target.conn)
        })();
        if let Err(error) = build {
            drop(target);
            cleanup_authority_reset_temporary(&temporary)?;
            return Err(error);
        }
        drop(target);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(&path))?;
        authority_reset_failpoint(1)?;

        let Store {
            conn,
            _database_lock: database_lock,
            _lock: lock,
            ..
        } = self;
        migration::sync_database_for_replacement(&conn)?;
        drop(conn);
        drop(database_lock);
        migration::atomic_replace(&temporary, &path)?;
        authority_reset_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(&path))?;
        authority_reset_failpoint(3)?;

        let conn = Connection::open(&path)?;
        let database_lock = acquire_database_identity_lock(&path)?;
        let mut store =
            Store::open_v2_with_parts(&path, passphrase, conn, database_lock, lock, false)?;
        // No attachment/media authority or transfer state survives the reset.
        // The old media directory is now entirely orphaned under the fresh
        // store key and is removed before the returned node becomes live.
        store.reconcile_media(rng)?;
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok((store, history))
    }

    /// Recover local archive data from a copied-root `KKR1` through `KKR7`
    /// file into a fresh ADR-0026 identity.
    ///
    /// The legacy root is decrypted only in memory long enough to identify
    /// the former account. It is never written to the unpublished sibling or
    /// the final store. Only the same explicitly local projection used by an
    /// in-place copied-root reset is admitted, and the fully initialized
    /// root-free sibling is published with one atomic replacement.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_legacy_backup_as_authority_reset(
        path: &Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        account: &IdentityPublic,
        device_state: &DeviceAuthorityStateRecord,
        prekeys: &[u8],
        reset_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, AuthorityResetHistoryRecord)> {
        account.verify()?;
        device_state.validate(account)?;
        let (payload, plain_len) = open_legacy_backup(backup, mnemonic)?;
        let source_record_count = validate_backup_payload(&payload)?;
        let projection = project_legacy_backup_authority_reset(payload, account, reset_at)?;

        let lock = acquire_store_lock(path)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let temporary = restore_temporary_path(path)?;
        if temporary.exists() {
            cleanup_restore_temporary(&temporary)?;
        }
        ensure_restore_workspace(path, plain_len, source_record_count)?;
        let target = match Store::create(&temporary, passphrase, profile, rng) {
            Ok(target) => target,
            Err(error) => {
                cleanup_restore_temporary(&temporary)?;
                return Err(error);
            }
        };
        let build = (|| {
            target.commit_plan(
                CommitPlan::AuthorityProfileBootstrap(AuthorityProfileBootstrapPlan {
                    account,
                    device_state,
                    prekeys,
                }),
                rng,
            )?;
            for contact in &projection.contacts {
                target.put_contact(contact, rng)?;
            }
            for message in &projection.messages {
                target.put_message(message, rng)?;
            }
            for note in &projection.notes {
                target.put_note_message(note, rng)?;
            }
            for record in &projection.local_metadata {
                target.put_local_metadata(record, rng)?;
            }
            target.put_authority_reset_history(&projection.history, rng)?;
            target.validate_open_state()?;
            migration::sync_database_for_replacement(&target.conn)
        })();
        if let Err(error) = build {
            drop(target);
            cleanup_restore_temporary(&temporary)?;
            return Err(error);
        }
        drop(target);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(1)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        migration::atomic_replace(&temporary, path)?;
        restore_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(3)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        let store = Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        if store.contains_legacy_account_root()?
            || store.get_account_identity()?.as_ref() != Some(account)
            || store.get_device_authority_state()?.as_ref() != Some(device_state)
        {
            return Err(StoreError::MigrationValidation);
        }
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok((store, projection.history))
    }

    /// Encode a historical copied-root KKR7 fixture. This is deliberately
    /// absent from production builds; current exports use KKR10.
    #[cfg(test)]
    fn export_backup(
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

    /// Export an ADR-0026 root-free backup.
    ///
    /// Released `KKR1` through `KKR7` payloads contain a copied account root
    /// and are decode-only migration inputs. Restoring this payload also
    /// requires the user's separately held encrypted recovery-authority
    /// package.
    pub fn export_authority_backup(
        &self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, Zeroizing<String>)> {
        let account = self.get_account_identity()?.ok_or(StoreError::NotAStore)?;
        let device_state = self
            .get_device_authority_state()?
            .ok_or(StoreError::NotAStore)?;
        device_state.validate(&account)?;
        let mut ephemeral = self.ephemeral_records()?;
        for record in &mut ephemeral {
            record.state = EphemeralState::Expired;
            record.transfer_ids.clear();
        }
        let me = account.ed;
        let mut messages = self
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
            .collect::<Vec<_>>();
        for message in &mut messages {
            if message.direction == crate::Direction::Outbound
                && matches!(
                    message.state,
                    crate::DeliveryState::Queued | crate::DeliveryState::Sent
                )
            {
                message.state = crate::DeliveryState::Failed;
            }
            message.wire_id = None;
        }
        let mut group_messages = self
            .all_group_messages()?
            .into_iter()
            .filter(|message| {
                !ephemeral.iter().any(|record| {
                    record.conversation == EphemeralConversation::Group(message.group)
                        && record.author == message.sender
                        && record.content_id == message.id
                })
            })
            .collect::<Vec<_>>();
        for message in &mut group_messages {
            message.wire_body = None;
            for delivery in &mut message.deliveries {
                if matches!(
                    delivery.state,
                    crate::DeliveryState::Queued | crate::DeliveryState::Sent
                ) {
                    delivery.state = crate::DeliveryState::Failed;
                }
                delivery.wire_id = None;
            }
        }
        let payload = AuthorityBackupPayload {
            created_at: now,
            account,
            authority: device_state.manifest,
            discovery: device_state.discovery,
            contacts: self.contacts()?,
            messages,
            reset_peers: self.session_peers()?,
            groups: self
                .groups()?
                .into_iter()
                .map(|group| BackupGroup {
                    id: group.id,
                    name: group.name,
                    creator: group.creator,
                    members: group.members,
                    secret: group.secret,
                    generation: group.generation,
                })
                .collect(),
            group_messages,
            group_authorities: self.group_authorities()?,
            local_metadata: self.local_metadata()?,
            note_messages: self.note_messages()?,
            ephemeral,
            contact_devices: self.contact_devices()?,
            blocked_identities: self.blocked_identities()?,
        };
        validate_authority_backup_payload(&payload)?;
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
        out.extend_from_slice(&AUTHORITY_BACKUP_MAGIC);
        out.extend_from_slice(&profile.m_cost_kib.to_le_bytes());
        out.extend_from_slice(&profile.t_cost.to_le_bytes());
        out.extend_from_slice(&profile.p_cost.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&key.seal(AUTHORITY_BACKUP_AD, &plain, rng));
        Ok((out, mnemonic))
    }

    /// Restore a root-free backup and create one fresh root-authorized
    /// recovery device inside a higher authority epoch.
    ///
    /// `root` is borrowed only while verifying the account binding and
    /// signing that one recovery transition. The returned store contains
    /// only the public account, the fresh device credential, and the new
    /// manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_authority_backup_with_initializer<R, T, F>(
        path: &Path,
        backup: &[u8],
        mnemonic: &str,
        root: &Identity,
        recovered_at: u64,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut R,
        initializer: F,
    ) -> Result<(Self, Identity, DeviceAuthorityStateRecord, T)>
    where
        R: CryptoRngCore,
        F: FnOnce(&Store, &mut R) -> Result<T>,
    {
        let (mut payload, plain_len) = open_authority_backup(backup, mnemonic)?;
        let record_count = validate_authority_backup_payload(&payload)?;
        if root.public() != payload.account || payload.authority.account() != &payload.account {
            return Err(StoreError::NotABackup);
        }
        let device = Identity::generate(rng);
        let manifest = payload.authority.recover(
            root,
            &device,
            "Recovered device".into(),
            recovered_at,
            rng,
        )?;
        if payload.discovery.capability == [0u8; 32] {
            let code = ConnectCode::generate(&payload.account, rng)?;
            payload.discovery = DiscoveryCapabilityState {
                capability: code.capability(),
                generation: 1,
                legacy_v1_enabled: true,
            };
        } else {
            payload.discovery.generation = payload
                .discovery
                .generation
                .checked_add(1)
                .ok_or(StoreError::RecordBounds)?;
        }
        let device_state = DeviceAuthorityStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: manifest
                .active_certificate(&device.public().ed)
                .cloned()
                .ok_or(StoreError::NotABackup)?,
            accepted_recovery_epoch: manifest.recovery_epoch(),
            accepted_recovery_anchor: manifest.recovery_anchor_id(),
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
            conflicts: Vec::new(),
            discovery: payload.discovery.clone(),
        };

        let lock = acquire_store_lock(path)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let temporary = restore_temporary_path(path)?;
        if temporary.exists() {
            cleanup_restore_temporary(&temporary)?;
        }
        ensure_restore_workspace(path, plain_len, record_count)?;
        let restored = populate_authority_restored_store(
            &temporary,
            passphrase,
            profile,
            payload,
            &device_state,
            rng,
        );
        let store = match restored {
            Ok(store) => store,
            Err(error) => {
                cleanup_restore_temporary(&temporary)?;
                return Err(error);
            }
        };
        let initialized = match initializer(&store, rng) {
            Ok(initialized) => initialized,
            Err(error) => {
                drop(store);
                cleanup_restore_temporary(&temporary)?;
                return Err(error);
            }
        };
        store.validate_open_state()?;
        migration::sync_database_for_replacement(&store.conn)?;
        drop(store);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(1)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        migration::atomic_replace(&temporary, path)?;
        restore_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(3)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        let store = Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok((store, device, device_state, initialized))
    }

    /// Historical copied-root restore retained only to exercise migration
    /// fixtures. Production callers must use
    /// [`Self::restore_legacy_backup_as_authority_reset`].
    #[cfg(test)]
    fn restore_backup(
        path: &std::path::Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        Self::restore_backup_with_initializer(
            path,
            backup,
            mnemonic,
            passphrase,
            profile,
            rng,
            |_store, _rng| Ok(()),
        )
        .map(|(store, ())| store)
    }

    /// Historical copied-root restore retained only to exercise atomic
    /// migration failpoints. It is intentionally absent from production
    /// builds.
    #[cfg(test)]
    fn restore_backup_with_initializer<R, T, F>(
        path: &std::path::Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut R,
        initializer: F,
    ) -> Result<(Self, T)>
    where
        R: CryptoRngCore,
        F: FnOnce(&Store, &mut R) -> Result<T>,
    {
        let (payload, plain_len) = open_legacy_backup(backup, mnemonic)?;
        let record_count = validate_backup_payload(&payload)?;
        let lock = acquire_store_lock(path)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let temporary = restore_temporary_path(path)?;
        if temporary.exists() {
            cleanup_restore_temporary(&temporary)?;
        }
        ensure_restore_workspace(path, plain_len, record_count)?;
        let restored = populate_restored_store(&temporary, passphrase, profile, payload, rng);
        let store = match restored {
            Ok(store) => store,
            Err(error) => {
                cleanup_restore_temporary(&temporary)?;
                return Err(error);
            }
        };
        let initialized = match initializer(&store, rng) {
            Ok(initialized) => initialized,
            Err(error) => {
                drop(store);
                cleanup_restore_temporary(&temporary)?;
                return Err(error);
            }
        };
        store.validate_open_state()?;
        migration::sync_database_for_replacement(&store.conn)?;
        drop(store);
        migration::sync_file(&temporary)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(1)?;
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        migration::atomic_replace(&temporary, path)?;
        restore_failpoint(2)?;
        store_v2::sync_directory(migration::parent_directory(path))?;
        restore_failpoint(3)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        let store = Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        migration::cleanup_obsolete_siblings(&temporary)?;
        Ok((store, initialized))
    }

    /// The Argon2id profile this store was created with.
    fn kdf_profile(&self) -> Result<KdfProfile> {
        Ok(self.kdf_profile)
    }

    /// Every stored message, in insertion order.
    pub(crate) fn all_messages(&self) -> Result<Vec<MessageRecord>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::MessageRows>()? {
            out.push(self.decode_message_row_ref(&row, None)?);
        }
        Ok(out)
    }

    /// Peers with a persisted ratchet session.
    fn session_peers(&self) -> Result<Vec<[u8; 32]>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::SessionRows>()? {
            let peer = *store_v2::AccountKey::decode(&row.logical_key)?.value();
            let _: kult_crypto::Session = decode_store_exact(&row.payload)?;
            out.push(peer);
        }
        Ok(out)
    }

    // ---- session-reset markers ---------------------------------------------

    /// Record that any pre-restore session with this peer is dead and must
    /// be re-established (docs/07-storage.md §4).
    pub fn put_reset_marker(&self, peer: &[u8; 32]) -> Result<()> {
        let mut rng = rand_core::OsRng;
        self.put_reset_marker_with_rng(peer, &mut rng)
    }

    pub(crate) fn put_reset_marker_with_rng(
        &self,
        peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.put_equality::<store_v2::ResetRows>(
            &store_v2::AccountKey::new(*peer),
            peer,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// All pending session-reset markers.
    pub fn reset_markers(&self) -> Result<Vec<[u8; 32]>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::ResetRows>()? {
            let peer = *store_v2::AccountKey::decode(&row.logical_key)?.value();
            if row.payload.as_slice() != peer {
                return Err(StoreError::LogicalKeyMismatch);
            }
            out.push(peer);
        }
        Ok(out)
    }

    /// Remove a session-reset marker (the re-handshake was queued).
    pub fn clear_reset_marker(&self, peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::ResetRows>(&store_v2::AccountKey::new(*peer))?;
        Ok(())
    }
}

fn open_authority_backup(backup: &[u8], mnemonic: &str) -> Result<(AuthorityBackupPayload, usize)> {
    if backup.len() <= HEADER_LEN
        || u64::try_from(backup.len()).map_or(true, |length| length > MAX_BACKUP_FILE_BYTES)
    {
        return Err(StoreError::NotABackup);
    }
    let (version, associated_data) =
        match <[u8; 4]>::try_from(&backup[..4]).expect("length checked") {
            AUTHORITY_BACKUP_MAGIC => (10, AUTHORITY_BACKUP_AD),
            AUTHORITY_BACKUP_MAGIC_V9 => (9, AUTHORITY_BACKUP_AD_V9),
            AUTHORITY_BACKUP_MAGIC_V8 => (8, AUTHORITY_BACKUP_AD_V8),
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
    let plain = Zeroizing::new(key.open(associated_data, &backup[HEADER_LEN..])?);
    let plain_len = plain.len();
    let payload = match version {
        10 => decode_exact(&plain)?,
        9 => AuthorityBackupPayload::from(decode_exact::<AuthorityBackupPayloadV9>(&plain)?),
        8 => AuthorityBackupPayload::from(decode_exact::<AuthorityBackupPayloadV8>(&plain)?),
        _ => return Err(StoreError::NotABackup),
    };
    Ok((payload, plain_len))
}

fn open_legacy_backup(backup: &[u8], mnemonic: &str) -> Result<(BackupPayload, usize)> {
    if backup.len() <= HEADER_LEN
        || u64::try_from(backup.len()).map_or(true, |length| length > MAX_BACKUP_FILE_BYTES)
    {
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
    let plain_len = plain.len();
    let payload = match version {
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
    Ok((payload, plain_len))
}

fn project_legacy_backup_authority_reset(
    mut payload: BackupPayload,
    account: &IdentityPublic,
    reset_at: u64,
) -> Result<AuthorityResetProjection> {
    let identity_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
        payload.identity[..]
            .try_into()
            .map_err(|_| StoreError::NotABackup)?,
    );
    payload.identity.zeroize();
    let former_root = Identity::from_bytes(&identity_bytes);
    let former_account = former_root.public();
    drop(former_root);
    if former_account == *account || payload.contacts.len() > MAX_AUTHORITY_RESET_CONTACTS {
        return Err(StoreError::InvalidTransition);
    }

    let mut contacts = payload.contacts;
    for contact in &mut contacts {
        contact.bundle.clear();
        contact.hints.clear();
        contact.verified = false;
    }
    let contact_ids = contacts
        .iter()
        .map(|contact| contact.peer)
        .collect::<HashSet<_>>();
    let ephemeral_pairwise = payload
        .ephemeral
        .into_iter()
        .filter_map(|record| match record.conversation {
            EphemeralConversation::Pairwise(peer) => Some((peer, record.content_id)),
            EphemeralConversation::Group(_) => None,
        })
        .collect::<HashSet<_>>();
    let mut messages = payload
        .messages
        .into_iter()
        .filter(|message| {
            contact_ids.contains(&message.peer)
                && !ephemeral_pairwise.contains(&(message.peer, message.id))
        })
        .collect::<Vec<_>>();
    for message in &mut messages {
        if message.direction == crate::Direction::Outbound
            && matches!(
                message.state,
                crate::DeliveryState::Queued | crate::DeliveryState::Sent
            )
        {
            message.state = crate::DeliveryState::Failed;
        }
        message.wire_id = None;
    }
    let local_metadata = payload
        .local_metadata
        .into_iter()
        .filter(|record| match record {
            LocalMetadataRecord::Conversation(record) => {
                reset_conversation_survives(&record.conversation, &contact_ids)
            }
            LocalMetadataRecord::Folder(_) | LocalMetadataRecord::Label(_) => true,
            LocalMetadataRecord::FolderAssignment(record) => {
                reset_conversation_survives(&record.conversation, &contact_ids)
            }
            LocalMetadataRecord::Pin(record) => {
                reset_conversation_survives(&record.conversation, &contact_ids)
            }
            LocalMetadataRecord::LabelAssignment(record) => {
                reset_conversation_survives(&record.conversation, &contact_ids)
            }
            LocalMetadataRecord::Draft(_) => false,
            LocalMetadataRecord::UiPreference(record) => {
                record.key == THEME_PREFERENCE_KEY && record.key != AUTHORITY_RESET_HISTORY_KEY
            }
            LocalMetadataRecord::CustomIcon(record) => match &record.target {
                CustomIconTarget::Contact(peer) => contact_ids.contains(peer),
                CustomIconTarget::Folder(_) | CustomIconTarget::NoteToSelf => true,
                CustomIconTarget::Group(_) => false,
            },
        })
        .collect::<Vec<_>>();
    let record_count = contacts
        .len()
        .checked_add(messages.len())
        .and_then(|count| count.checked_add(payload.note_messages.len()))
        .and_then(|count| count.checked_add(local_metadata.len()))
        .and_then(|count| count.checked_add(3))
        .ok_or(StoreError::RecordBounds)?;
    if u64::try_from(record_count).map_or(true, |count| count > MAX_BACKUP_RECORDS) {
        return Err(StoreError::RecordBounds);
    }
    let history = AuthorityResetHistoryRecord {
        former_account: former_account.ed,
        new_account: account.ed,
        reset_at,
        preserved_contacts: u32::try_from(contacts.len()).map_err(|_| StoreError::RecordBounds)?,
        preserved_pairwise_messages: u64::try_from(messages.len())
            .map_err(|_| StoreError::RecordBounds)?,
        preserved_note_messages: u64::try_from(payload.note_messages.len())
            .map_err(|_| StoreError::RecordBounds)?,
        omitted_groups: u64::try_from(payload.groups.len())
            .map_err(|_| StoreError::RecordBounds)?,
        omitted_group_messages: u64::try_from(payload.group_messages.len())
            .map_err(|_| StoreError::RecordBounds)?,
        pending_reverification: contacts.iter().map(|contact| contact.peer).collect(),
    };
    Ok(AuthorityResetProjection {
        contacts,
        messages,
        notes: payload.note_messages,
        local_metadata,
        history,
    })
}

fn populate_authority_restored_store(
    path: &Path,
    passphrase: &[u8],
    profile: KdfProfile,
    payload: AuthorityBackupPayload,
    device_state: &DeviceAuthorityStateRecord,
    rng: &mut impl CryptoRngCore,
) -> Result<Store> {
    let account = payload.account;
    device_state.validate(&account)?;
    let me = account.ed;
    let store = Store::create(path, passphrase, profile, rng)?;
    store.put_account_identity(&account, rng)?;
    store.put_device_authority_state(device_state, rng)?;
    for contact in &payload.contacts {
        store.put_contact(contact, rng)?;
    }
    for endpoint in &payload.contact_devices {
        store.put_contact_device(endpoint, rng)?;
    }
    for message in &payload.messages {
        store.put_message(message, rng)?;
    }
    let mut reset_peers = payload.reset_peers.into_iter().collect::<BTreeSet<_>>();
    for endpoint in &payload.contact_devices {
        if !endpoint.bundle.is_empty() && endpoint.revoked_at.is_none() {
            reset_peers.insert(endpoint.device);
        }
    }
    for contact in &payload.contacts {
        if !contact.bundle.is_empty()
            && !payload
                .contact_devices
                .iter()
                .any(|endpoint| endpoint.account == contact.peer)
        {
            reset_peers.insert(contact.peer);
        }
    }
    for peer in reset_peers {
        store.put_reset_marker_with_rng(&peer, rng)?;
    }
    for group in payload.groups {
        let chain = GroupSenderChain::generate(rng);
        let (key_id, chain_key, iteration) = chain.snapshot();
        let pending = group
            .members
            .iter()
            .filter(|member| member.peer != me)
            .map(|member| PendingAnnounce {
                peer: member.peer,
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
    for record in &payload.blocked_identities {
        store.put_blocked_identity(record, rng)?;
    }
    Ok(store)
}

#[cfg(test)]
fn populate_restored_store(
    path: &Path,
    passphrase: &[u8],
    profile: KdfProfile,
    mut payload: BackupPayload,
    rng: &mut impl CryptoRngCore,
) -> Result<Store> {
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
        let chain = GroupSenderChain::generate(rng);
        let (key_id, chain_key, iteration) = chain.snapshot();
        let pending = group
            .members
            .iter()
            .filter(|member| member.peer != me)
            .map(|member| PendingAnnounce {
                peer: member.peer,
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

fn validate_authority_backup_payload(payload: &AuthorityBackupPayload) -> Result<u64> {
    payload.account.verify()?;
    payload.authority.verify()?;
    if payload.authority.account() != &payload.account
        || (payload.discovery.capability == [0u8; 32]) != (payload.discovery.generation == 0)
        || payload.contacts.len() > 100_000
        || payload.messages.len() > 10_000_000
        || payload.reset_peers.len() > 100_000
        || payload.groups.len() > 100_000
        || payload.group_messages.len() > 10_000_000
        || payload.group_authorities.len() > 100_000
        || payload.local_metadata.len() > 100_000
        || payload.note_messages.len() > 10_000_000
        || payload.ephemeral.len() > 10_000_000
        || payload.contact_devices.len() > 1_000_000
        || payload.blocked_identities.len() > crate::MAX_BLOCKED_IDENTITIES
    {
        return Err(StoreError::RecordBounds);
    }
    let total = [
        payload.contacts.len(),
        payload.messages.len(),
        payload.reset_peers.len(),
        payload.groups.len(),
        payload.group_messages.len(),
        payload.group_authorities.len(),
        payload.local_metadata.len(),
        payload.note_messages.len(),
        payload.ephemeral.len(),
        payload.contact_devices.len(),
        payload.blocked_identities.len(),
    ]
    .into_iter()
    .try_fold(0u64, |total, count| {
        total
            .checked_add(u64::try_from(count).map_err(|_| StoreError::RecordBounds)?)
            .ok_or(StoreError::RecordBounds)
    })?;
    if total > MAX_BACKUP_RECORDS {
        return Err(StoreError::RecordBounds);
    }

    let mut contacts = BTreeSet::new();
    for record in &payload.contacts {
        if !contacts.insert(record.peer) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut message_ids = BTreeSet::new();
    for record in &payload.messages {
        if !message_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let reset_peers = payload.reset_peers.iter().copied().collect::<BTreeSet<_>>();
    if reset_peers.len() != payload.reset_peers.len() {
        return Err(StoreError::MigrationValidation);
    }
    let mut groups = BTreeSet::new();
    for record in &payload.groups {
        if !groups.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut group_message_ids = BTreeSet::new();
    for record in &payload.group_messages {
        if record.wire_body.is_some() || !group_message_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut authorities = BTreeSet::new();
    for record in &payload.group_authorities {
        if !groups.contains(&record.group) || !authorities.insert(record.group) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut metadata_keys = BTreeSet::new();
    for record in &payload.local_metadata {
        let key = postcard::to_allocvec(&record.key()).map_err(|_| StoreError::Serialization)?;
        if !metadata_keys.insert(key) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut note_ids = BTreeSet::new();
    for record in &payload.note_messages {
        if !note_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut ephemeral_keys = BTreeSet::new();
    for record in &payload.ephemeral {
        if record.state == EphemeralState::Active || !record.transfer_ids.is_empty() {
            return Err(StoreError::MigrationValidation);
        }
        let key = postcard::to_allocvec(&(record.conversation, record.author, record.content_id))
            .map_err(|_| StoreError::Serialization)?;
        if !ephemeral_keys.insert(key) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut devices = BTreeSet::new();
    for record in &payload.contact_devices {
        if !contacts.contains(&record.account) || !devices.insert((record.account, record.device)) {
            return Err(StoreError::MigrationValidation);
        }
        crate::devices::validate_contact_device(record)?;
        validate_backup_record(record)?;
    }
    let mut blocked = BTreeSet::new();
    for record in &payload.blocked_identities {
        if !blocked.insert((record.account, record.device)) {
            return Err(StoreError::MigrationValidation);
        }
        record.validate()?;
        validate_backup_record(record)?;
    }
    Ok(total)
}

fn validate_backup_payload(payload: &BackupPayload) -> Result<u64> {
    if payload.identity.len() != 64
        || payload.contacts.len() > 100_000
        || payload.messages.len() > 10_000_000
        || payload.reset_peers.len() > 100_000
        || payload.groups.len() > 100_000
        || payload.group_messages.len() > 10_000_000
        || payload.group_authorities.len() > 100_000
        || payload.local_metadata.len() > 100_000
        || payload.note_messages.len() > 10_000_000
        || payload.ephemeral.len() > 10_000_000
        || payload.device_sync_events.len() > crate::MAX_DEVICE_SYNC_EVENTS
        || payload.contact_devices.len() > 1_000_000
    {
        return Err(StoreError::RecordBounds);
    }
    let total = [
        payload.contacts.len(),
        payload.messages.len(),
        payload.reset_peers.len(),
        payload.groups.len(),
        payload.group_messages.len(),
        payload.group_authorities.len(),
        payload.local_metadata.len(),
        payload.note_messages.len(),
        payload.ephemeral.len(),
        payload.device_sync_events.len(),
        payload.contact_devices.len(),
    ]
    .into_iter()
    .try_fold(0u64, |total, count| {
        total
            .checked_add(u64::try_from(count).map_err(|_| StoreError::RecordBounds)?)
            .ok_or(StoreError::RecordBounds)
    })?;
    if total > MAX_BACKUP_RECORDS {
        return Err(StoreError::RecordBounds);
    }

    let mut contacts = BTreeSet::new();
    for record in &payload.contacts {
        if !contacts.insert(record.peer) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut message_ids = BTreeSet::new();
    for record in &payload.messages {
        if !message_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    if payload
        .reset_peers
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != payload.reset_peers.len()
    {
        return Err(StoreError::MigrationValidation);
    }
    let mut groups = BTreeSet::new();
    for record in &payload.groups {
        if !groups.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut group_message_ids = BTreeSet::new();
    for record in &payload.group_messages {
        if record.wire_body.is_some() || !group_message_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut authorities = BTreeSet::new();
    for record in &payload.group_authorities {
        if !authorities.insert(record.group) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut metadata_keys = BTreeSet::new();
    for record in &payload.local_metadata {
        let key = postcard::to_allocvec(&record.key()).map_err(|_| StoreError::Serialization)?;
        if !metadata_keys.insert(key) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut note_ids = BTreeSet::new();
    for record in &payload.note_messages {
        if !note_ids.insert(record.id) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut ephemeral_keys = BTreeSet::new();
    for record in &payload.ephemeral {
        if record.state == EphemeralState::Active || !record.transfer_ids.is_empty() {
            return Err(StoreError::MigrationValidation);
        }
        let key = postcard::to_allocvec(&(record.conversation, record.author, record.content_id))
            .map_err(|_| StoreError::Serialization)?;
        if !ephemeral_keys.insert(key) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    let mut devices = BTreeSet::new();
    for record in &payload.contact_devices {
        if !contacts.contains(&record.account) || !devices.insert((record.account, record.device)) {
            return Err(StoreError::MigrationValidation);
        }
        validate_backup_record(record)?;
    }
    for event in &payload.device_sync_events {
        if event.is_empty() || event.len() > crate::MAX_DEVICE_SYNC_EVENT_BYTES {
            return Err(StoreError::RecordBounds);
        }
    }
    if payload.device_manifest.is_some() != payload.local_device.is_some()
        || (payload.device_manifest.is_none() && !payload.device_sync_events.is_empty())
    {
        return Err(StoreError::MigrationValidation);
    }
    Ok(total)
}

fn validate_backup_record<T: Serialize>(record: &T) -> Result<()> {
    let encoded = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
    if encoded.len() > store_v2::MAX_RECORD_BYTES {
        return Err(StoreError::RecordBounds);
    }
    Ok(())
}

fn restore_temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(StoreError::NotAStore)?;
    let mut temporary = name.to_os_string();
    temporary.push(".restore-v2-sibling");
    Ok(path.with_file_name(temporary))
}

fn initialization_temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(StoreError::NotAStore)?;
    let mut temporary = name.to_os_string();
    temporary.push(".initialize-v1-sibling");
    Ok(path.with_file_name(temporary))
}

fn authority_reset_temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(StoreError::NotAStore)?;
    let mut temporary = name.to_os_string();
    temporary.push(".authority-reset-v1-sibling");
    Ok(path.with_file_name(temporary))
}

fn reset_conversation_survives(
    conversation: &ConversationId,
    contacts: &HashSet<[u8; 32]>,
) -> bool {
    match conversation {
        ConversationId::Peer(peer) => contacts.contains(peer),
        ConversationId::NoteToSelf => true,
        ConversationId::Group(_) => false,
    }
}

fn ensure_restore_workspace(path: &Path, logical_bytes: usize, record_count: u64) -> Result<()> {
    let logical_bytes =
        u64::try_from(logical_bytes).map_err(|_| StoreError::InsufficientMigrationSpace)?;
    let required = logical_bytes
        .checked_mul(2)
        .and_then(|bytes| {
            record_count
                .checked_mul(ESTIMATED_RESTORED_ROW_BYTES)
                .and_then(|overhead| bytes.checked_add(overhead))
        })
        .and_then(|bytes| bytes.checked_add(RESTORE_SPACE_RESERVE))
        .ok_or(StoreError::InsufficientMigrationSpace)?;
    if fs2::available_space(migration::parent_directory(path))? < required {
        return Err(StoreError::InsufficientMigrationSpace);
    }
    Ok(())
}

fn cleanup_restore_temporary(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    migration::cleanup_obsolete_siblings(path)?;
    store_v2::sync_directory(migration::parent_directory(path))
}

fn cleanup_initialization_temporary(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    migration::cleanup_obsolete_siblings(path)?;
    store_v2::sync_directory(migration::parent_directory(path))
}

fn cleanup_authority_reset_temporary(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    migration::cleanup_obsolete_siblings(path)?;
    store_v2::sync_directory(migration::parent_directory(path))
}

pub(crate) fn cleanup_completed_restore(path: &Path) -> Result<()> {
    let temporary = restore_temporary_path(path)?;
    if temporary.exists() {
        return Err(StoreError::ReplacementRecovery);
    }
    migration::cleanup_obsolete_siblings(&temporary)
}

pub(crate) fn cleanup_completed_initialization(path: &Path) -> Result<()> {
    let temporary = initialization_temporary_path(path)?;
    if temporary.exists() {
        return Err(StoreError::ReplacementRecovery);
    }
    migration::cleanup_obsolete_siblings(&temporary)
}

pub(crate) fn cleanup_completed_authority_reset(path: &Path) -> Result<()> {
    let temporary = authority_reset_temporary_path(path)?;
    // A complete sibling still present means publication did not happen.
    // Leave it for an explicitly retried reset, which revalidates the source
    // and replaces the sibling from scratch. Once atomic rename consumed the
    // database file, only empty sidecars remain and are safe to remove.
    if temporary.exists() {
        return Ok(());
    }
    migration::cleanup_obsolete_siblings(&temporary)
}

#[cfg(test)]
std::thread_local! {
    static INITIALIZATION_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static AUTHORITY_RESET_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static RESTORE_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn set_initialization_failpoint(phase: u8) {
    INITIALIZATION_FAILPOINT.with(|failpoint| failpoint.set(phase));
}

fn initialization_failpoint(phase: u8) -> Result<()> {
    #[cfg(test)]
    if INITIALIZATION_FAILPOINT.with(|failpoint| {
        let armed = failpoint.get() == phase;
        if armed {
            failpoint.set(0);
        }
        armed
    }) {
        return Err(StoreError::MigrationValidation);
    }
    let _ = phase;
    Ok(())
}

#[cfg(test)]
fn set_authority_reset_failpoint(phase: u8) {
    AUTHORITY_RESET_FAILPOINT.with(|failpoint| failpoint.set(phase));
}

fn authority_reset_failpoint(phase: u8) -> Result<()> {
    #[cfg(test)]
    if AUTHORITY_RESET_FAILPOINT.with(|failpoint| {
        let armed = failpoint.get() == phase;
        if armed {
            failpoint.set(0);
        }
        armed
    }) {
        return Err(StoreError::MigrationValidation);
    }
    let _ = phase;
    Ok(())
}

#[cfg(test)]
fn set_restore_failpoint(phase: u8) {
    RESTORE_FAILPOINT.with(|failpoint| failpoint.set(phase));
}

fn restore_failpoint(phase: u8) -> Result<()> {
    #[cfg(test)]
    if RESTORE_FAILPOINT.with(|failpoint| {
        let armed = failpoint.get() == phase;
        if armed {
            failpoint.set(0);
        }
        armed
    }) {
        return Err(StoreError::MigrationValidation);
    }
    let _ = phase;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    let state = DeviceStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: certificate,
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
    };
    store.commit_plan(
        CommitPlan::DeviceControl(crate::DeviceControlPlan {
            state: Some(crate::DeviceStateTransition {
                before: None,
                after: &state,
            }),
            link_recovery: None,
            groups: &[],
            insert_events: &[],
            delete_events: &[],
            presentation_changed: false,
        }),
        rng,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_v2::TableSpec;
    use crate::{DeviceChannelRecord, DeviceLinkRecoveryRecord, GroupDelivery};
    use kult_crypto::DeviceAuthorityManifest;
    use rand::{rngs::StdRng, SeedableRng};
    use rusqlite::params;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn authority_store(
        path: &Path,
        rng: &mut StdRng,
    ) -> (Store, Identity, Identity, DeviceAuthorityStateRecord) {
        let root = Identity::generate(rng);
        let device = Identity::generate(rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &device, "This device".into(), 0, rng).unwrap();
        let discovery = ConnectCode::generate(&root.public(), rng).unwrap();
        let state = DeviceAuthorityStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: manifest.devices()[0].certificate.clone(),
            accepted_recovery_epoch: manifest.recovery_epoch(),
            accepted_recovery_anchor: manifest.recovery_anchor_id(),
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
            conflicts: Vec::new(),
            discovery: DiscoveryCapabilityState {
                capability: discovery.capability(),
                generation: 1,
                legacy_v1_enabled: false,
            },
        };
        let store = Store::create_authority_profile(
            path,
            b"profile-pass",
            TEST_KDF,
            &root.public(),
            &state,
            b"live-prekey-vault-secret-that-must-not-enter-a-backup",
            rng,
        )
        .unwrap();
        (store, root, device, state)
    }

    fn copied_root_store(path: &Path, rng: &mut StdRng) -> (Store, Identity) {
        let root = Identity::generate(rng);
        let first = Identity::generate(rng);
        let first_certificate = DeviceCertificate::issue(&root, &first, 1, rng);
        let mut manifest = DeviceManifest::initial(
            &root,
            first_certificate.clone(),
            "Original device".into(),
            1,
        )
        .unwrap();
        let copied = Identity::generate(rng);
        let copied_certificate = DeviceCertificate::issue(&root, &copied, 2, rng);
        manifest
            .add_device(
                &root,
                DeviceManifestEntry {
                    certificate: copied_certificate,
                    name: "Copied-root device".into(),
                    last_seen: 2,
                    revoked_at: None,
                    revoked_after_counter: None,
                },
            )
            .unwrap();
        manifest
            .revoke_device(&root, &copied.public().ed, 3, 0)
            .unwrap();
        let state = DeviceStateRecord {
            local_device_secret: first.to_bytes().to_vec(),
            local_certificate: first_certificate,
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
        };
        let store = Store::create_legacy_profile_fixture(
            path,
            b"profile-pass",
            TEST_KDF,
            &root,
            &state,
            b"legacy-prekeys",
            rng,
        )
        .unwrap();
        (store, root)
    }

    #[test]
    fn authority_profile_persists_no_account_root() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority-profile.db");
        let mut rng = StdRng::seed_from_u64(0x2600);
        let root = Identity::generate(&mut rng);
        let device = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &device, "This device".into(), 0, &mut rng)
                .unwrap();
        let state = DeviceAuthorityStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: manifest.devices()[0].certificate.clone(),
            accepted_recovery_epoch: manifest.recovery_epoch(),
            accepted_recovery_anchor: manifest.recovery_anchor_id(),
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
            conflicts: Vec::new(),
            discovery: DiscoveryCapabilityState::default(),
        };
        let root_bytes = root.to_bytes();
        let store = Store::create_authority_profile(
            &path,
            b"profile-pass",
            TEST_KDF,
            &root.public(),
            &state,
            b"fresh-prekeys",
            &mut rng,
        )
        .unwrap();
        assert!(!store.contains_legacy_account_root().unwrap());
        assert!(store.get_identity().unwrap().is_none());
        assert_eq!(
            store.get_account_identity().unwrap().unwrap(),
            root.public()
        );
        assert_eq!(store.get_device_authority_state().unwrap().unwrap(), state);
        drop(store);
        let database = std::fs::read(path).unwrap();
        assert!(database
            .windows(root_bytes.len())
            .all(|window| window != &root_bytes[..]));
    }

    #[test]
    fn authority_backup_plaintext_excludes_live_and_recovery_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority-backup.db");
        let mut rng = StdRng::seed_from_u64(0x2601);
        let (store, root, device, mut state) = authority_store(&path, &mut rng);
        let root_secret = root.to_bytes();
        let device_secret = device.to_bytes();
        let live_prekeys = store.get_prekeys().unwrap().unwrap();
        let linked_device = Identity::generate(&mut rng);
        let linked_certificate = kult_crypto::DeviceAuthorityCertificate::issue(
            root.public(),
            &linked_device,
            1,
            &mut rng,
        )
        .unwrap();
        let mut link_transition = state
            .manifest
            .propose_add_device(linked_certificate, "Linked device".into(), 1, &mut rng)
            .unwrap();
        state
            .manifest
            .sign_transition(&mut link_transition, &device)
            .unwrap();
        state.manifest = state.manifest.append(link_transition).unwrap();
        let sync_channel_secret = [0xa6; 32];
        state.channels.push(DeviceChannelRecord {
            peer_device: linked_device.public().ed,
            root: sync_channel_secret,
            send_counter: 4,
            receive_counter: 3,
        });
        store.put_device_authority_state(&state, &mut rng).unwrap();
        let pending_link_secret = [0xc6; 32];
        store
            .put_device_link_recovery(
                &DeviceLinkRecoveryRecord {
                    target_device: [0xd6; 32],
                    response_hash: [0xe6; 32],
                    link_key: pending_link_secret,
                    contacts: true,
                    organization: true,
                    history: true,
                },
                &mut rng,
            )
            .unwrap();
        let peer = [0xf6; 32];
        store
            .put_message(
                &MessageRecord {
                    id: [0x16; 16],
                    peer,
                    direction: crate::Direction::Outbound,
                    state: crate::DeliveryState::Sent,
                    timestamp: 120,
                    body: b"unfinished pairwise history".to_vec(),
                    wire_id: Some([0x26; 16]),
                },
                &mut rng,
            )
            .unwrap();
        let group_id = [0x36; 32];
        let live_group_chain =
            postcard::to_allocvec(&GroupSenderChain::generate(&mut rng)).unwrap();
        store
            .put_group(
                &GroupRecord {
                    id: group_id,
                    name: "Backup boundary".into(),
                    creator: root.public().ed,
                    members: Vec::new(),
                    secret: [0x46; 32],
                    prev_secret: None,
                    generation: 1,
                    sender_chain: live_group_chain.clone(),
                    sent_since_rotation: 2,
                    pending: Vec::new(),
                },
                &mut rng,
            )
            .unwrap();
        store
            .put_group_message(
                &GroupMessageRecord {
                    id: [0x56; 16],
                    group: group_id,
                    sender: root.public().ed,
                    direction: crate::Direction::Outbound,
                    timestamp: 121,
                    body: b"unfinished group history".to_vec(),
                    deliveries: vec![
                        GroupDelivery {
                            peer,
                            wire_id: Some([0x66; 16]),
                            state: crate::DeliveryState::Queued,
                        },
                        GroupDelivery {
                            peer: [0x76; 32],
                            wire_id: Some([0x86; 16]),
                            state: crate::DeliveryState::Delivered,
                        },
                    ],
                    wire_body: Some(b"live shared ciphertext".to_vec()),
                    origin: crate::GroupOriginAuthentication::LegacyMembership,
                },
                &mut rng,
            )
            .unwrap();
        let blocked = BlockedIdentityRecord {
            account: [0x96; 32],
            device: [0xa7; 32],
            created_at: 122,
        };
        store.put_blocked_identity(&blocked, &mut rng).unwrap();
        let wake_static_key = [0xb7; 32];
        let wake_capability = kult_protocol::WakeCapability::from_parts(
            7,
            [0xc7; 24],
            &[0xd7; kult_protocol::WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let wake_capability_secret = wake_capability.clone();
        let wake_state = crate::WakeServiceState {
            version: crate::WAKE_SERVICE_STATE_VERSION,
            session_id: [0xe7; 32],
            remote_generation: 1,
            remote_conflict_generation: None,
            issued_generation: 0,
            capabilities: vec![crate::WakeStoredCapability::new(
                crate::WakeCapabilityDirection::Remote,
                "https://wake.backup-boundary.invalid".to_owned(),
                wake_static_key,
                wake_capability,
                123 + kult_protocol::WAKE_CAPABILITY_MAX_LIFETIME_SECS,
            )
            .unwrap()],
        };
        let encoded_wake = postcard::to_allocvec(&wake_state).unwrap();
        store
            .put_equality::<store_v2::WakeServiceRows>(
                &store_v2::AccountKey::new(peer),
                &encoded_wake,
                store_v2::IndexKeys::none(),
                &mut rng,
            )
            .unwrap();
        let revoked_capability = kult_protocol::WakeCapability::from_parts(
            8,
            [0xe8; 24],
            &[0xf8; kult_protocol::WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
        )
        .unwrap()
        .as_bytes()
        .to_vec();
        let revoked_capability_secret = revoked_capability.clone();
        let revocation_state = crate::WakeServiceState {
            version: crate::WAKE_SERVICE_STATE_VERSION,
            session_id: [0xf7; 32],
            remote_generation: 0,
            remote_conflict_generation: None,
            issued_generation: 1,
            capabilities: vec![crate::WakeStoredCapability::new(
                crate::WakeCapabilityDirection::Issued,
                "https://wake.backup-boundary.invalid".to_owned(),
                wake_static_key,
                revoked_capability,
                123 + kult_protocol::WAKE_CAPABILITY_MAX_LIFETIME_SECS,
            )
            .unwrap()],
        };
        store
            .enqueue_issued_wake_revocations(&revocation_state, &mut rng)
            .unwrap();
        assert_eq!(
            store
                .wake_revocations(crate::MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            1
        );

        let (backup, mnemonic) = store.export_authority_backup(123, &mut rng).unwrap();
        assert_eq!(&backup[..4], &AUTHORITY_BACKUP_MAGIC);
        let entropy = mnemonic_to_entropy(&mnemonic).unwrap();
        let salt: [u8; 16] = backup[16..32].try_into().unwrap();
        let kek = derive_kek(&entropy[..], &salt, TEST_KDF).unwrap();
        let plain = StorageKey::from_bytes(*kek)
            .open(AUTHORITY_BACKUP_AD, &backup[HEADER_LEN..])
            .unwrap();
        let decoded: AuthorityBackupPayload = decode_exact(&plain).unwrap();

        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.account, root.public());
        assert_eq!(decoded.authority, state.manifest);
        assert_eq!(decoded.discovery, state.discovery);
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].state, crate::DeliveryState::Failed);
        assert_eq!(decoded.messages[0].wire_id, None);
        assert_eq!(decoded.group_messages.len(), 1);
        assert_eq!(decoded.blocked_identities, vec![blocked]);
        assert_eq!(decoded.group_messages[0].wire_body, None);
        assert_eq!(
            decoded.group_messages[0]
                .deliveries
                .iter()
                .map(|delivery| (delivery.state, delivery.wire_id))
                .collect::<Vec<_>>(),
            vec![
                (crate::DeliveryState::Failed, None),
                (crate::DeliveryState::Delivered, None),
            ]
        );
        for secret in [
            root_secret.as_slice(),
            device_secret.as_slice(),
            live_prekeys.as_slice(),
            sync_channel_secret.as_slice(),
            pending_link_secret.as_slice(),
            live_group_chain.as_slice(),
            wake_static_key.as_slice(),
            wake_capability_secret.as_slice(),
            revoked_capability_secret.as_slice(),
        ] {
            assert!(
                plain
                    .windows(secret.len())
                    .all(|candidate| candidate != secret),
                "root-free backup plaintext retained a live or recovery secret"
            );
        }
    }

    #[test]
    fn authority_backup_restores_discovery_blocks_and_predecessor_formats() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("authority-block-source.db");
        let target_path = directory.path().join("authority-block-target.db");
        let v9_target_path = directory.path().join("authority-v9-target.db");
        let legacy_target_path = directory.path().join("authority-v8-target.db");
        let mut rng = StdRng::seed_from_u64(0x2603);
        let (source, root, _device, _state) = authority_store(&source_path, &mut rng);
        let blocked = BlockedIdentityRecord {
            account: [0xb8; 32],
            device: [0xc8; 32],
            created_at: 120,
        };
        source.put_blocked_identity(&blocked, &mut rng).unwrap();
        let (backup, mnemonic) = source.export_authority_backup(123, &mut rng).unwrap();
        drop(source);

        let (restored, _, _, ()) = Store::restore_authority_backup_with_initializer(
            &target_path,
            &backup,
            &mnemonic,
            &root,
            124,
            b"target-pass",
            TEST_KDF,
            &mut rng,
            |store, rng| store.put_prekeys(b"fresh-target-prekeys", rng),
        )
        .unwrap();
        assert_eq!(
            restored.blocked_identities().unwrap(),
            vec![blocked.clone()]
        );
        assert!(restored.provisional_requests().unwrap().is_empty());
        assert!(restored.admission_tombstones().unwrap().is_empty());
        let restored_discovery = restored
            .get_device_authority_state()
            .unwrap()
            .unwrap()
            .discovery;
        assert_ne!(restored_discovery.capability, [0u8; 32]);
        assert!(!restored_discovery.legacy_v1_enabled);
        drop(restored);

        let entropy = mnemonic_to_entropy(&mnemonic).unwrap();
        let salt: [u8; 16] = backup[16..32].try_into().unwrap();
        let kek = derive_kek(&entropy[..], &salt, TEST_KDF).unwrap();
        let key = StorageKey::from_bytes(*kek);
        let plain = key
            .open(AUTHORITY_BACKUP_AD, &backup[HEADER_LEN..])
            .unwrap();
        let current: AuthorityBackupPayload = decode_exact(&plain).unwrap();
        let current_discovery = current.discovery.clone();
        let v9 = AuthorityBackupPayloadV9 {
            created_at: current.created_at,
            account: current.account,
            authority: current.authority,
            contacts: current.contacts,
            messages: current.messages,
            reset_peers: current.reset_peers,
            groups: current.groups,
            group_messages: current.group_messages,
            group_authorities: current.group_authorities,
            local_metadata: current.local_metadata,
            note_messages: current.note_messages,
            ephemeral: current.ephemeral,
            contact_devices: current.contact_devices,
            blocked_identities: current.blocked_identities,
        };
        let v9_plain = postcard::to_allocvec(&v9).unwrap();
        let mut v9_backup = Vec::with_capacity(HEADER_LEN + v9_plain.len() + 40);
        v9_backup.extend_from_slice(&AUTHORITY_BACKUP_MAGIC_V9);
        v9_backup.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
        v9_backup.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
        v9_backup.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
        v9_backup.extend_from_slice(&salt);
        v9_backup.extend_from_slice(&key.seal(AUTHORITY_BACKUP_AD_V9, &v9_plain, &mut rng));
        let (v9_restored, _, _, ()) = Store::restore_authority_backup_with_initializer(
            &v9_target_path,
            &v9_backup,
            &mnemonic,
            &root,
            125,
            b"v9-target-pass",
            TEST_KDF,
            &mut rng,
            |store, rng| store.put_prekeys(b"fresh-v9-prekeys", rng),
        )
        .unwrap();
        assert_eq!(v9_restored.blocked_identities().unwrap(), vec![blocked]);
        let v9_discovery = v9_restored
            .get_device_authority_state()
            .unwrap()
            .unwrap()
            .discovery;
        assert_ne!(v9_discovery.capability, [0u8; 32]);
        assert_ne!(v9_discovery.capability, current_discovery.capability);
        assert_eq!(v9_discovery.generation, 1);
        assert!(v9_discovery.legacy_v1_enabled);
        drop(v9_restored);

        let current: AuthorityBackupPayload = decode_exact(&plain).unwrap();
        let v8 = AuthorityBackupPayloadV8 {
            created_at: current.created_at,
            account: current.account,
            authority: current.authority,
            contacts: current.contacts,
            messages: current.messages,
            reset_peers: current.reset_peers,
            groups: current.groups,
            group_messages: current.group_messages,
            group_authorities: current.group_authorities,
            local_metadata: current.local_metadata,
            note_messages: current.note_messages,
            ephemeral: current.ephemeral,
            contact_devices: current.contact_devices,
        };
        let v8_plain = postcard::to_allocvec(&v8).unwrap();
        let mut v8_backup = Vec::with_capacity(HEADER_LEN + v8_plain.len() + 40);
        v8_backup.extend_from_slice(&AUTHORITY_BACKUP_MAGIC_V8);
        v8_backup.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
        v8_backup.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
        v8_backup.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
        v8_backup.extend_from_slice(&salt);
        v8_backup.extend_from_slice(&key.seal(AUTHORITY_BACKUP_AD_V8, &v8_plain, &mut rng));

        let (legacy_restored, _, _, ()) = Store::restore_authority_backup_with_initializer(
            &legacy_target_path,
            &v8_backup,
            &mnemonic,
            &root,
            126,
            b"legacy-target-pass",
            TEST_KDF,
            &mut rng,
            |store, rng| store.put_prekeys(b"fresh-v8-prekeys", rng),
        )
        .unwrap();
        assert!(legacy_restored.blocked_identities().unwrap().is_empty());
        let v8_discovery = legacy_restored
            .get_device_authority_state()
            .unwrap()
            .unwrap()
            .discovery;
        assert_ne!(v8_discovery.capability, [0u8; 32]);
        assert_ne!(v8_discovery.capability, current_discovery.capability);
        assert_eq!(v8_discovery.generation, 1);
        assert!(v8_discovery.legacy_v1_enabled);
    }

    #[test]
    fn authority_backup_requires_the_exact_offline_root() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("authority-source.db");
        let target_path = directory.path().join("authority-target.db");
        let mut rng = StdRng::seed_from_u64(0x2602);
        let (store, _root, _device, _state) = authority_store(&source_path, &mut rng);
        let wrong_root = Identity::generate(&mut rng);
        let (backup, mnemonic) = store.export_authority_backup(123, &mut rng).unwrap();
        drop(store);

        assert!(matches!(
            Store::restore_authority_backup_with_initializer(
                &target_path,
                &backup,
                &mnemonic,
                &wrong_root,
                124,
                b"target-pass",
                TEST_KDF,
                &mut rng,
                |_store, _rng| Ok(()),
            ),
            Err(StoreError::NotABackup)
        ));
        assert!(!target_path.exists());
        assert!(!restore_temporary_path(&target_path).unwrap().exists());
    }

    #[test]
    fn profile_publication_restarts_safely_at_every_replacement_phase() {
        for phase in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("profile-{phase}.db"));
            let mut rng = StdRng::seed_from_u64(0x6f00 + phase as u64);
            let identity = Identity::generate(&mut rng);
            let device = Identity::generate(&mut rng);
            let certificate = DeviceCertificate::issue(&identity, &device, 0, &mut rng);
            let manifest =
                DeviceManifest::initial(&identity, certificate.clone(), "This device".into(), 0)
                    .unwrap();
            let state = DeviceStateRecord {
                local_device_secret: device.to_bytes().to_vec(),
                local_certificate: certificate,
                manifest,
                sync_counter: 0,
                channels: Vec::new(),
            };
            let prekeys = vec![phase; 32];

            set_initialization_failpoint(phase);
            let interrupted = Store::create_legacy_profile_fixture(
                &path,
                b"profile-pass",
                TEST_KDF,
                &identity,
                &state,
                &prekeys,
                &mut rng,
            );
            match interrupted {
                Err(StoreError::MigrationValidation) => {}
                Err(error) => panic!("phase {phase}: {error:?}"),
                Ok(_) => panic!("phase {phase}: publication unexpectedly completed"),
            }
            let store = if phase == 1 {
                Store::create_legacy_profile_fixture(
                    &path,
                    b"profile-pass",
                    TEST_KDF,
                    &identity,
                    &state,
                    &prekeys,
                    &mut rng,
                )
                .unwrap()
            } else {
                Store::open(&path, b"profile-pass").unwrap()
            };
            assert_eq!(
                store.get_identity().unwrap().unwrap().public(),
                identity.public()
            );
            assert_eq!(store.get_device_state().unwrap(), Some(state));
            assert_eq!(store.get_prekeys().unwrap().unwrap().as_slice(), prekeys);
            assert!(!initialization_temporary_path(&path).unwrap().exists());

            let authority_path = directory
                .path()
                .join(format!("authority-profile-{phase}.db"));
            let root = Identity::generate(&mut rng);
            let physical_device = Identity::generate(&mut rng);
            let authority = DeviceAuthorityManifest::initial(
                &root,
                &physical_device,
                "This device".into(),
                0,
                &mut rng,
            )
            .unwrap();
            let authority_state = DeviceAuthorityStateRecord {
                local_device_secret: physical_device.to_bytes().to_vec(),
                local_certificate: authority.devices()[0].certificate.clone(),
                accepted_recovery_epoch: authority.recovery_epoch(),
                accepted_recovery_anchor: authority.recovery_anchor_id(),
                manifest: authority,
                sync_counter: 0,
                channels: Vec::new(),
                conflicts: Vec::new(),
                discovery: DiscoveryCapabilityState::default(),
            };
            let authority_prekeys = vec![phase + 3; 32];

            set_initialization_failpoint(phase);
            let interrupted = Store::create_authority_profile(
                &authority_path,
                b"authority-profile-pass",
                TEST_KDF,
                &root.public(),
                &authority_state,
                &authority_prekeys,
                &mut rng,
            );
            match interrupted {
                Err(StoreError::MigrationValidation) => {}
                Err(error) => panic!("authority phase {phase}: {error:?}"),
                Ok(_) => panic!("authority phase {phase}: publication unexpectedly completed"),
            }
            let authority_store = if phase == 1 {
                Store::create_authority_profile(
                    &authority_path,
                    b"authority-profile-pass",
                    TEST_KDF,
                    &root.public(),
                    &authority_state,
                    &authority_prekeys,
                    &mut rng,
                )
                .unwrap()
            } else {
                Store::open(&authority_path, b"authority-profile-pass").unwrap()
            };
            assert!(authority_store.get_identity().unwrap().is_none());
            assert_eq!(
                authority_store.get_account_identity().unwrap(),
                Some(root.public())
            );
            assert_eq!(
                authority_store.get_device_authority_state().unwrap(),
                Some(authority_state)
            );
            assert_eq!(
                authority_store.get_prekeys().unwrap().unwrap().as_slice(),
                authority_prekeys
            );
            assert!(!initialization_temporary_path(&authority_path)
                .unwrap()
                .exists());
        }
    }

    #[test]
    fn authority_reset_restarts_safely_at_every_replacement_phase() {
        for phase in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("authority-reset-{phase}.db"));
            let mut rng = StdRng::seed_from_u64(0xa260 + phase as u64);
            let (store, former_root) = copied_root_store(&path, &mut rng);
            let contact_identity = Identity::generate(&mut rng).public();
            store
                .put_contact(
                    &ContactRecord {
                        peer: contact_identity.ed,
                        identity: postcard::to_allocvec(&contact_identity).unwrap(),
                        name: "Local petname".into(),
                        bundle: vec![7; 32],
                        hints: vec![vec![8; 8]],
                        verified: true,
                    },
                    &mut rng,
                )
                .unwrap();
            let new_root = Identity::generate(&mut rng);
            let new_device = Identity::generate(&mut rng);
            let manifest = DeviceAuthorityManifest::initial(
                &new_root,
                &new_device,
                "Reset device".into(),
                10,
                &mut rng,
            )
            .unwrap();
            let state = DeviceAuthorityStateRecord {
                local_device_secret: new_device.to_bytes().to_vec(),
                local_certificate: manifest.devices()[0].certificate.clone(),
                accepted_recovery_epoch: manifest.recovery_epoch(),
                accepted_recovery_anchor: manifest.recovery_anchor_id(),
                manifest,
                sync_counter: 0,
                channels: Vec::new(),
                conflicts: Vec::new(),
                discovery: DiscoveryCapabilityState::default(),
            };

            set_authority_reset_failpoint(phase);
            let interrupted = store.replace_copied_root_profile(
                b"profile-pass",
                &new_root.public(),
                &state,
                b"new-prekeys",
                11,
                &mut rng,
            );
            match interrupted {
                Err(StoreError::MigrationValidation) => {}
                Err(error) => panic!("phase {phase}: {error:?}"),
                Ok(_) => panic!("phase {phase}: reset unexpectedly completed"),
            }

            let store = Store::open(&path, b"profile-pass").unwrap();
            let store = if phase == 1 {
                assert_eq!(
                    store.get_identity().unwrap().unwrap().public(),
                    former_root.public()
                );
                store
                    .replace_copied_root_profile(
                        b"profile-pass",
                        &new_root.public(),
                        &state,
                        b"new-prekeys",
                        11,
                        &mut rng,
                    )
                    .unwrap()
                    .0
            } else {
                store
            };
            assert!(store.get_identity().unwrap().is_none());
            assert_eq!(
                store.get_account_identity().unwrap(),
                Some(new_root.public())
            );
            assert_eq!(
                store
                    .authority_reset_history()
                    .unwrap()
                    .unwrap()
                    .pending_reverification,
                vec![contact_identity.ed]
            );
            let contact = store.get_contact(&contact_identity.ed).unwrap().unwrap();
            assert_eq!(contact.name, "Local petname");
            assert!(contact.bundle.is_empty());
            assert!(contact.hints.is_empty());
            assert!(!contact.verified);
            assert!(!authority_reset_temporary_path(&path).unwrap().exists());
        }
    }

    #[test]
    fn legacy_backup_reset_never_publishes_the_copied_root() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("legacy-backup-source.db");
        let target_path = directory.path().join("legacy-backup-reset.db");
        let mut rng = StdRng::seed_from_u64(0x7a26);
        let (source, former_root) = copied_root_store(&source_path, &mut rng);
        let contact_identity = Identity::generate(&mut rng).public();
        source
            .put_contact(
                &ContactRecord {
                    peer: contact_identity.ed,
                    identity: postcard::to_allocvec(&contact_identity).unwrap(),
                    name: "Remembered petname".into(),
                    bundle: vec![0x71; 32],
                    hints: vec![vec![0x72; 8]],
                    verified: true,
                },
                &mut rng,
            )
            .unwrap();
        source
            .put_message(
                &MessageRecord {
                    id: [0x73; 16],
                    peer: contact_identity.ed,
                    direction: crate::Direction::Outbound,
                    state: crate::DeliveryState::Sent,
                    timestamp: 7,
                    body: b"former identity archive".to_vec(),
                    wire_id: Some([0x74; 16]),
                },
                &mut rng,
            )
            .unwrap();
        source
            .put_note_message(
                &NoteMessageRecord {
                    id: [0x75; 16],
                    timestamp: 8,
                    body: "local note".into(),
                },
                &mut rng,
            )
            .unwrap();
        let (backup, mnemonic) = source.export_backup(9, &mut rng).unwrap();
        drop(source);

        let new_root = Identity::generate(&mut rng);
        let new_device = Identity::generate(&mut rng);
        let manifest = DeviceAuthorityManifest::initial(
            &new_root,
            &new_device,
            "Recovered archive device".into(),
            10,
            &mut rng,
        )
        .unwrap();
        let state = DeviceAuthorityStateRecord {
            local_device_secret: new_device.to_bytes().to_vec(),
            local_certificate: manifest.devices()[0].certificate.clone(),
            accepted_recovery_epoch: manifest.recovery_epoch(),
            accepted_recovery_anchor: manifest.recovery_anchor_id(),
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
            conflicts: Vec::new(),
            discovery: DiscoveryCapabilityState::default(),
        };
        let (restored, history) = Store::restore_legacy_backup_as_authority_reset(
            &target_path,
            &backup,
            &mnemonic,
            b"target-pass",
            TEST_KDF,
            &new_root.public(),
            &state,
            b"fresh-prekeys",
            11,
            &mut rng,
        )
        .unwrap();

        assert!(restored.get_identity().unwrap().is_none());
        assert!(!restored.contains_legacy_account_root().unwrap());
        assert_eq!(
            restored.get_account_identity().unwrap(),
            Some(new_root.public())
        );
        assert_eq!(history.former_account, former_root.public().ed);
        assert_eq!(history.new_account, new_root.public().ed);
        assert_eq!(history.pending_reverification, vec![contact_identity.ed]);
        let contact = restored.get_contact(&contact_identity.ed).unwrap().unwrap();
        assert_eq!(contact.name, "Remembered petname");
        assert!(contact.bundle.is_empty());
        assert!(contact.hints.is_empty());
        assert!(!contact.verified);
        let message = restored
            .messages_with(&contact_identity.ed)
            .unwrap()
            .remove(0);
        assert_eq!(message.state, crate::DeliveryState::Failed);
        assert_eq!(message.wire_id, None);
        assert_eq!(restored.note_messages().unwrap().len(), 1);
        assert!(restored.groups().unwrap().is_empty());
        assert_eq!(restored.authority_reset_history().unwrap(), Some(history));
    }

    #[test]
    fn legacy_backup_reset_restarts_root_free_at_every_replacement_phase() {
        for phase in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let source_path = directory
                .path()
                .join(format!("legacy-reset-source-{phase}.db"));
            let target_path = directory
                .path()
                .join(format!("legacy-reset-target-{phase}.db"));
            let mut rng = StdRng::seed_from_u64(0x7a30 + phase as u64);
            let (source, former_root) = copied_root_store(&source_path, &mut rng);
            let (backup, mnemonic) = source.export_backup(20, &mut rng).unwrap();
            drop(source);

            let new_root = Identity::generate(&mut rng);
            let new_device = Identity::generate(&mut rng);
            let manifest = DeviceAuthorityManifest::initial(
                &new_root,
                &new_device,
                "Recovered archive device".into(),
                21,
                &mut rng,
            )
            .unwrap();
            let state = DeviceAuthorityStateRecord {
                local_device_secret: new_device.to_bytes().to_vec(),
                local_certificate: manifest.devices()[0].certificate.clone(),
                accepted_recovery_epoch: manifest.recovery_epoch(),
                accepted_recovery_anchor: manifest.recovery_anchor_id(),
                manifest,
                sync_counter: 0,
                channels: Vec::new(),
                conflicts: Vec::new(),
                discovery: DiscoveryCapabilityState::default(),
            };

            set_restore_failpoint(phase);
            assert!(matches!(
                Store::restore_legacy_backup_as_authority_reset(
                    &target_path,
                    &backup,
                    &mnemonic,
                    b"target-pass",
                    TEST_KDF,
                    &new_root.public(),
                    &state,
                    b"fresh-prekeys",
                    22,
                    &mut rng,
                ),
                Err(StoreError::MigrationValidation)
            ));

            let restored = if phase == 1 {
                assert!(!target_path.exists());
                let temporary = restore_temporary_path(&target_path).unwrap();
                let staged = Store::open(&temporary, b"target-pass").unwrap();
                assert!(!staged.contains_legacy_account_root().unwrap());
                assert_eq!(
                    staged.get_account_identity().unwrap(),
                    Some(new_root.public())
                );
                drop(staged);
                Store::restore_legacy_backup_as_authority_reset(
                    &target_path,
                    &backup,
                    &mnemonic,
                    b"target-pass",
                    TEST_KDF,
                    &new_root.public(),
                    &state,
                    b"fresh-prekeys",
                    22,
                    &mut rng,
                )
                .unwrap()
                .0
            } else {
                Store::open(&target_path, b"target-pass").unwrap()
            };

            assert!(restored.get_identity().unwrap().is_none());
            assert!(!restored.contains_legacy_account_root().unwrap());
            assert_eq!(
                restored.get_account_identity().unwrap(),
                Some(new_root.public())
            );
            assert_eq!(
                restored
                    .authority_reset_history()
                    .unwrap()
                    .unwrap()
                    .former_account,
                former_root.public().ed
            );
            assert!(!restore_temporary_path(&target_path).unwrap().exists());
        }
    }

    #[test]
    fn restore_restarts_safely_at_every_replacement_phase() {
        for phase in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let source_path = directory.path().join(format!("source-{phase}.db"));
            let target_path = directory.path().join(format!("target-{phase}.db"));
            let mut rng = StdRng::seed_from_u64(0x7000 + phase as u64);
            let source = Store::create(&source_path, b"source-pass", TEST_KDF, &mut rng).unwrap();
            let identity = Identity::generate(&mut rng);
            let expected = identity.public();
            source.put_identity(&identity, &mut rng).unwrap();
            let (backup, mnemonic) = source.export_backup(123, &mut rng).unwrap();
            drop(source);

            set_restore_failpoint(phase);
            assert!(matches!(
                Store::restore_backup_with_initializer(
                    &target_path,
                    &backup,
                    &mnemonic,
                    b"target-pass",
                    TEST_KDF,
                    &mut rng,
                    |store, rng| {
                        store.put_prekeys(&[phase; 4], rng)?;
                        Ok(())
                    },
                ),
                Err(StoreError::MigrationValidation)
            ));
            let restored = if phase == 1 {
                Store::restore_backup_with_initializer(
                    &target_path,
                    &backup,
                    &mnemonic,
                    b"target-pass",
                    TEST_KDF,
                    &mut rng,
                    |store, rng| {
                        store.put_prekeys(&[phase; 4], rng)?;
                        Ok(())
                    },
                )
                .unwrap()
                .0
            } else {
                Store::open(&target_path, b"target-pass").unwrap()
            };
            assert_eq!(restored.get_identity().unwrap().unwrap().public(), expected);
            assert_eq!(
                restored.get_prekeys().unwrap().unwrap().as_slice(),
                &[phase; 4]
            );
            assert!(!restore_temporary_path(&target_path).unwrap().exists());

            let authority_source_path = directory
                .path()
                .join(format!("authority-source-{phase}.db"));
            let authority_target_path = directory
                .path()
                .join(format!("authority-target-{phase}.db"));
            let (authority_source, root, _device, _state) =
                authority_store(&authority_source_path, &mut rng);
            let expected_account = root.public();
            let (authority_backup, authority_mnemonic) = authority_source
                .export_authority_backup(200, &mut rng)
                .unwrap();
            drop(authority_source);

            set_restore_failpoint(phase);
            assert!(matches!(
                Store::restore_authority_backup_with_initializer(
                    &authority_target_path,
                    &authority_backup,
                    &authority_mnemonic,
                    &root,
                    201,
                    b"authority-target-pass",
                    TEST_KDF,
                    &mut rng,
                    |store, rng| {
                        store.put_prekeys(&[phase; 4], rng)?;
                        Ok(())
                    },
                ),
                Err(StoreError::MigrationValidation)
            ));
            let authority_restored = if phase == 1 {
                Store::restore_authority_backup_with_initializer(
                    &authority_target_path,
                    &authority_backup,
                    &authority_mnemonic,
                    &root,
                    201,
                    b"authority-target-pass",
                    TEST_KDF,
                    &mut rng,
                    |store, rng| {
                        store.put_prekeys(&[phase; 4], rng)?;
                        Ok(())
                    },
                )
                .unwrap()
                .0
            } else {
                Store::open(&authority_target_path, b"authority-target-pass").unwrap()
            };
            let authority_state = authority_restored
                .get_device_authority_state()
                .unwrap()
                .unwrap();
            assert_eq!(
                authority_restored.get_account_identity().unwrap(),
                Some(expected_account)
            );
            assert!(authority_restored.get_identity().unwrap().is_none());
            assert_eq!(authority_state.manifest.recovery_epoch(), 1);
            assert_eq!(
                authority_state
                    .manifest
                    .devices()
                    .iter()
                    .filter(|entry| entry.is_active())
                    .count(),
                1
            );
            assert_eq!(
                authority_restored
                    .get_prekeys()
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                &[phase; 4]
            );
            assert!(!restore_temporary_path(&authority_target_path)
                .unwrap()
                .exists());
        }
    }

    #[test]
    fn restore_initializer_failure_leaves_no_visible_destination() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let target_path = directory.path().join("target.db");
        let mut rng = StdRng::seed_from_u64(0x7005);
        let source = Store::create(&source_path, b"source-pass", TEST_KDF, &mut rng).unwrap();
        source
            .put_identity(&Identity::generate(&mut rng), &mut rng)
            .unwrap();
        let (backup, mnemonic) = source.export_backup(123, &mut rng).unwrap();
        drop(source);

        assert!(matches!(
            Store::restore_backup_with_initializer(
                &target_path,
                &backup,
                &mnemonic,
                b"target-pass",
                TEST_KDF,
                &mut rng,
                |_store, _rng| Err::<(), _>(StoreError::MigrationValidation),
            ),
            Err(StoreError::MigrationValidation)
        ));
        assert!(!target_path.exists());
        assert!(!restore_temporary_path(&target_path).unwrap().exists());
        Store::restore_backup(
            &target_path,
            &backup,
            &mnemonic,
            b"target-pass",
            TEST_KDF,
            &mut rng,
        )
        .unwrap();
    }

    #[test]
    fn backup_plaintext_contains_logical_records_not_store_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logical-backup.db");
        let mut rng = StdRng::seed_from_u64(0x7004);
        let store = Store::create(&path, b"source-pass", TEST_KDF, &mut rng).unwrap();
        let identity = Identity::generate(&mut rng);
        store.put_identity(&identity, &mut rng).unwrap();
        let message = MessageRecord {
            id: [3; 16],
            peer: [4; 32],
            direction: crate::Direction::Inbound,
            state: crate::DeliveryState::Received,
            timestamp: 5,
            body: b"logical backup record".to_vec(),
            wire_id: None,
        };
        store.put_message(&message, &mut rng).unwrap();
        let (locator, opaque_index, wrapped_row): (Vec<u8>, Vec<u8>, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT locator, unique_index, blob FROM store_records
                 WHERE table_domain = ?1",
                params![store_v2::MessageRows::DOMAIN],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let database_id = store.metadata.database_id;

        let (backup, mnemonic) = store.export_backup(6, &mut rng).unwrap();
        let entropy = mnemonic_to_entropy(&mnemonic).unwrap();
        let salt: [u8; 16] = backup[16..32].try_into().unwrap();
        let kek = derive_kek(&entropy[..], &salt, TEST_KDF).unwrap();
        let plain = StorageKey::from_bytes(*kek)
            .open(BACKUP_AD, &backup[HEADER_LEN..])
            .unwrap();
        let decoded: BackupPayload = decode_exact(&plain).unwrap();
        assert_eq!(decoded.messages, vec![message]);
        assert_eq!(decoded.identity, identity.to_bytes().to_vec());
        assert!(!plain.starts_with(b"SQLite format 3"));
        for artifact in [
            database_id.as_slice(),
            locator.as_slice(),
            opaque_index.as_slice(),
            wrapped_row.as_slice(),
        ] {
            assert!(!plain
                .windows(artifact.len())
                .any(|candidate| candidate == artifact));
        }
    }
}
