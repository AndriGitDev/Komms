//! Komms encrypted local-first storage (docs/07-storage.md).
//!
//! SQLite as the container, but **every stored blob is individually
//! AEAD-sealed** (XChaCha20-Poly1305, random nonce, table-domain associated
//! data) under a per-domain key derived from the storage master key. A copied
//! database file leaks only row counts and approximate sizes; rows cannot be
//! transplanted across tables or databases.
//!
//! Key hierarchy (docs/04-cryptography.md §8):
//! passphrase → Argon2id → KEK → unwraps SK (master) → HKDF per-domain keys.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use rand_core::CryptoRngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{derive_kek, CryptoError, Identity, KdfProfile, Session, StorageKey};
use kult_protocol::{CapabilityControl, Envelope};

mod backup;
mod devices;
mod ephemeral;
mod local_metadata;
mod media;
mod note;
mod scheduled;
#[doc(hidden)]
pub mod store_v2;

pub use backup::BACKUP_MAGIC;
pub use devices::{
    ContactDeviceRecord, DeviceChannelRecord, DeviceStateRecord, DeviceTransferGroup,
    DeviceTransferSelection, DeviceTransferSnapshot, MessageDeviceDeliveryRecord,
    MAX_DEVICE_SYNC_EVENTS, MAX_DEVICE_SYNC_EVENT_BYTES,
};
pub use ephemeral::{EphemeralConversation, EphemeralMode, EphemeralRecord, EphemeralState};
pub use local_metadata::{
    render_label_color, valid_folder_name, valid_label_color, valid_label_name, ConversationId,
    ConversationMetadata, CustomIconRecord, CustomIconTarget, DraftRecord, FolderAssignment,
    FolderConversationResult, FolderRecord, FolderSelection, LabelAssignment, LabelFilterMode,
    LabelFilterResult, LabelRecord, LocalMetadataKey, LocalMetadataRecord, PinConversationRecord,
    PinConversationResult, PinRecord, PinStatusRecord, StaleFolderAssignment, StaleFolderReason,
    StaleLabelAssignment, StaleLabelReason, ThemePreference, UiPreferenceRecord,
    CUSTOM_ICON_BUNDLED_GLYPHS, CUSTOM_ICON_DIMENSION, CUSTOM_ICON_MEDIA_TYPE,
    FOLDER_ID_RETRY_LIMIT, LABEL_COLORS, LABEL_ID_RETRY_LIMIT, MAX_CUSTOM_ICONS,
    MAX_CUSTOM_ICON_BYTES, MAX_CUSTOM_ICON_TOTAL_BYTES, MAX_DRAFT_BYTES, MAX_FOLDERS,
    MAX_FOLDER_ASSIGNMENTS, MAX_LABELS, MAX_LABELS_PER_CONVERSATION, MAX_LABEL_ASSIGNMENTS,
    MAX_LOCAL_METADATA_STRING_BYTES, MAX_PINS, MAX_UI_PREFERENCE_VALUE_BYTES, THEME_PREFERENCES,
    THEME_PREFERENCE_KEY, THEME_SEMANTIC_ROLES,
};
pub use media::{
    MediaDirection, MediaLimits, MediaObjectRecord, MediaReconciliation, MediaRecord, MediaScope,
    MediaTransferRecord, MediaTransferState, MediaUsage, DEFAULT_MEDIA_STORE_QUOTA,
    MAX_MEDIA_STORE_QUOTA,
};
pub use note::{NoteMessageRecord, MAX_NOTE_TEXT_BYTES, NOTE_TO_SELF_CONVERSATION_ID};
pub use scheduled::{ScheduledConversation, ScheduledMessageRecord};

/// Failures surfaced by the store.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Underlying SQLite failure.
    Db(rusqlite::Error),
    /// Cryptographic failure — wrong passphrase, tampered blob, bad params.
    Crypto(CryptoError),
    /// Protocol-level decode failure on a stored envelope.
    Protocol(kult_protocol::ProtocolError),
    /// The database is missing required metadata (not a Komms store).
    NotAStore,
    /// The file is not a Komms backup (bad magic, truncated, or its sealed
    /// payload fails to parse). A wrong mnemonic surfaces as
    /// [`StoreError::Crypto`] instead — uniform AEAD failure, no oracle.
    NotABackup,
    /// (De)serialization of a stored record failed.
    Serialization,
    /// Filesystem operation for private store state failed.
    Io(std::io::Error),
    /// Another live store owner already holds this database's writer lock.
    AlreadyOpen,
    /// A typed protocol transition did not match the durable source state it
    /// named and was rolled back without changing the store.
    InvalidTransition,
    /// The bounded deferred-inbox item or sealed-byte quota is exhausted.
    PendingQuota,
    /// Configured or protocol-hard media quota would be exceeded.
    MediaQuota,
    /// Committing a media chunk would violate the free-space reserve.
    LowStorage,
    /// Media state or a chunk transition is inconsistent.
    MediaState,
    /// A local metadata record exceeds its documented resource bound.
    LocalMetadataBounds,
    /// The durable custom-icon record limit is exhausted.
    CustomIconLimit,
    /// The durable aggregate custom-icon byte quota would be exceeded.
    CustomIconQuota,
    /// A new folder name is empty, fixed-Pattern_White_Space-only, or too long.
    InvalidFolderName,
    /// The stable folder id has no durable definition.
    UnknownFolder,
    /// The durable folder-definition limit is exhausted.
    FolderLimit,
    /// The durable folder-assignment limit is exhausted.
    FolderAssignmentLimit,
    /// Random folder-id generation exhausted its bounded collision budget.
    FolderIdCollision,
    /// A folder reorder did not contain the exact active id set once each.
    InvalidFolderOrder,
    /// A stale-cleanup request now names an active or absent folder assignment.
    FolderAssignmentActive,
    /// A new label name is empty, fixed-Pattern_White_Space-only, or too long.
    InvalidLabelName,
    /// A new label color is outside the canonical vocabulary.
    InvalidLabelColor,
    /// The stable label id has no durable definition.
    UnknownLabel,
    /// The exact typed pairwise/group conversation is unavailable.
    UnavailableConversation,
    /// The durable label-definition limit is exhausted.
    LabelLimit,
    /// The durable aggregate assignment limit is exhausted.
    LabelAssignmentLimit,
    /// One conversation already carries the maximum number of labels.
    ConversationLabelLimit,
    /// Random label-id generation exhausted its bounded collision budget.
    LabelIdCollision,
    /// A stale-cleanup request now names an active or absent membership.
    LabelAssignmentActive,
    /// The durable conversation-pin limit is exhausted.
    PinLimit,
    /// A pin reorder did not contain the exact durable target set once each.
    InvalidPinOrder,
    /// A stale-cleanup request now names an active or absent pin.
    PinActive,
    /// A note-to-self text record is empty or exceeds its documented bound.
    NoteBounds,
    /// A database or metadata record declares a schema newer than this build.
    FutureSchema,
    /// Authenticated metadata and the physical SQLite schema disagree.
    SchemaMismatch,
    /// A migration ledger contains a migration that did not complete.
    IncompleteMigration,
    /// A migration ledger repeats one stable migration identifier.
    DuplicateMigration,
    /// A migration ledger does not form one complete monotonic version chain.
    InvalidMigrationLedger,
    /// More than one row carries the same table-scoped opaque locator.
    DuplicateIndex,
    /// A decrypted record's logical key does not match its opaque locator or lookup key.
    LogicalKeyMismatch,
    /// A decrypted logical record uses a version this build cannot interpret.
    UnsupportedRecordVersion,
    /// A versioned logical record exceeds the internal migration bound.
    RecordBounds,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::NotAStore => f.write_str("not a Komms store"),
            Self::NotABackup => f.write_str("not a Komms backup file"),
            Self::Serialization => f.write_str("record serialization failure"),
            Self::Io(e) => write!(f, "store filesystem error: {e}"),
            Self::AlreadyOpen => f.write_str("store is already open by another process"),
            Self::InvalidTransition => f.write_str("invalid durable protocol transition"),
            Self::PendingQuota => f.write_str("deferred inbox quota exhausted"),
            Self::MediaQuota => f.write_str("media quota exceeded"),
            Self::LowStorage => f.write_str("insufficient reserved filesystem space"),
            Self::MediaState => f.write_str("invalid media transfer state"),
            Self::LocalMetadataBounds => f.write_str("local metadata bounds exceeded"),
            Self::CustomIconLimit => f.write_str("custom icon record limit exhausted"),
            Self::CustomIconQuota => f.write_str("custom icon byte quota exceeded"),
            Self::InvalidFolderName => f.write_str("invalid folder name"),
            Self::UnknownFolder => f.write_str("folder id does not exist"),
            Self::FolderLimit => f.write_str("folder definition limit exhausted"),
            Self::FolderAssignmentLimit => f.write_str("folder assignment limit exhausted"),
            Self::FolderIdCollision => f.write_str("folder id collision budget exhausted"),
            Self::InvalidFolderOrder => f.write_str("invalid complete folder order"),
            Self::FolderAssignmentActive => f.write_str("folder assignment is active or absent"),
            Self::InvalidLabelName => f.write_str("invalid label name"),
            Self::InvalidLabelColor => f.write_str("unsupported label color"),
            Self::UnknownLabel => f.write_str("label id does not exist"),
            Self::UnavailableConversation => {
                f.write_str("typed conversation target is unavailable")
            }
            Self::LabelLimit => f.write_str("label definition limit exhausted"),
            Self::LabelAssignmentLimit => f.write_str("label assignment limit exhausted"),
            Self::ConversationLabelLimit => f.write_str("conversation label limit exhausted"),
            Self::LabelIdCollision => f.write_str("label id collision budget exhausted"),
            Self::LabelAssignmentActive => f.write_str("label assignment is active or absent"),
            Self::PinLimit => f.write_str("conversation pin limit exhausted"),
            Self::InvalidPinOrder => f.write_str("invalid complete pin order"),
            Self::PinActive => f.write_str("conversation pin is active or absent"),
            Self::NoteBounds => f.write_str("note-to-self text bounds exceeded"),
            Self::FutureSchema => f.write_str("store schema is newer than this build"),
            Self::SchemaMismatch => {
                f.write_str("authenticated metadata and physical schema disagree")
            }
            Self::IncompleteMigration => f.write_str("store migration is incomplete"),
            Self::DuplicateMigration => f.write_str("store migration id is duplicated"),
            Self::InvalidMigrationLedger => f.write_str("store migration ledger is invalid"),
            Self::DuplicateIndex => f.write_str("opaque row locator is duplicated"),
            Self::LogicalKeyMismatch => {
                f.write_str("sealed record logical key does not match its locator")
            }
            Self::UnsupportedRecordVersion => {
                f.write_str("sealed logical record version is unsupported")
            }
            Self::RecordBounds => f.write_str("sealed logical record exceeds its bound"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e)
    }
}
impl From<CryptoError> for StoreError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<kult_protocol::ProtocolError> for StoreError {
    fn from(e: kult_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Direction of a stored message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Sent by this device.
    Outbound,
    /// Received from a peer.
    Inbound,
}

/// Delivery state of a stored message (docs/03-architecture.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// Persisted locally, not yet handed to any transport.
    Queued,
    /// Handed to at least one transport.
    Sent,
    /// Encrypted delivery receipt received.
    Delivered,
    /// Inbound message (no delivery tracking).
    Received,
    /// The delivery window elapsed without an end-to-end receipt.
    Failed,
}

/// A message record (sealed as one blob in the `messages` table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    /// Random 16-byte message id.
    pub id: [u8; 16],
    /// Conversation key: the peer's Ed25519 identity key bytes.
    pub peer: [u8; 32],
    /// Sent or received.
    pub direction: Direction,
    /// Delivery state.
    pub state: DeliveryState,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message body (plaintext — sealed at rest by the store).
    pub body: Vec<u8>,
    /// Content id of the envelope this message left in (outbound only) —
    /// what encrypted delivery receipts acknowledge.
    pub wire_id: Option<[u8; 16]>,
}

/// Complete durable consequences of accepting one ordinary pairwise message.
///
/// The session is a candidate advanced from the last durable session. Applying
/// this plan either commits every field in one immediate SQLite transaction or
/// leaves the prior session and source pending row unchanged.
pub struct PairwiseReceivePlan<'a> {
    /// Exact physical-device ratchet route whose receiving state advanced.
    pub peer_device: &'a [u8; 32],
    /// Candidate session after authenticating and decrypting the envelope.
    pub session: &'a Session,
    /// Accepted immutable history row, or `None` for an application-level
    /// duplicate whose envelope still needs replay and receipt state.
    pub message: Option<&'a MessageRecord>,
    /// Authenticated envelope content id used for durable transport dedup.
    pub content_id: &'a [u8; 16],
    /// Local receive time stored with the duplicate-receipt route.
    pub received_at: u64,
    /// Stable deferred-inbox row consumed by this transition, when the
    /// envelope came from the pending inbox rather than a fresh carrier read.
    pub source_pending_sequence: Option<i64>,
}

/// A contact (sealed as one blob in the `contacts` table).
///
/// Delivery hints are opaque bytes to the store — the runtime serializes
/// its transport addressing there; the store interprets nothing
/// (docs/03-architecture.md §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecord {
    /// The contact's Ed25519 identity key bytes (conversation key).
    pub peer: [u8; 32],
    /// The contact's full encoded public identity (opaque bytes; the runtime
    /// decodes it for safety numbers and handshakes).
    pub identity: Vec<u8>,
    /// Local display name.
    pub name: String,
    /// The contact's last known encoded prekey bundle (opaque bytes).
    pub bundle: Vec<u8>,
    /// Opaque per-transport delivery hints (runtime-serialized).
    pub hints: Vec<Vec<u8>>,
    /// Whether safety numbers were verified out-of-band.
    pub verified: bool,
}

/// One outbound queue entry: a sealed envelope plus the routing context the
/// delivery engine needs (which peer, and which message record to advance
/// when the envelope is acknowledged).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueItem {
    /// The recipient's Ed25519 identity key bytes.
    pub peer: [u8; 32],
    /// The message record this envelope carries, if any (receipts carry none).
    pub msg_id: Option<[u8; 16]>,
    /// The group message record this envelope is one member's copy of, if
    /// any (drives the per-member delivery ladder, ADR-0012).
    pub group_msg_id: Option<[u8; 16]>,
    /// Durable traffic class used by schedulers independently of size.
    pub class: QueueClass,
    /// Unix seconds when this delivery first entered the durable queue.
    pub created_at: u64,
    /// Failed delivery rounds already attempted for this exact envelope.
    pub attempts: u32,
    /// Earliest Unix second at which passive delivery may try again.
    pub next_attempt_at: u64,
    /// The sealed envelope to deliver.
    pub envelope: Envelope,
}

/// Durable outbound traffic class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueClass {
    /// Ordinary messages, receipts, and control traffic.
    #[default]
    Normal,
    /// Attachment manifests and bulk-lane records; never eligible for airtime.
    Bulk,
    /// Transient call control; eligible only for an immediate direct QUIC
    /// route and discarded rather than resumed after process restart.
    Realtime,
    /// A foreground user action. It is attempted ahead of maintenance and
    /// older passive retries, but becomes passive after repeated failures.
    Interactive,
}

/// A group member as stored: peer id plus their encoded public identity
/// (opaque bytes — the runtime uses it for contact stubs and DHT lookup).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// The member's Ed25519 identity key bytes.
    pub peer: [u8; 32],
    /// Their full encoded public identity.
    pub identity: Vec<u8>,
}

/// One pending announce (ADR-0012): a member entitled to this device's
/// sender key whose announce has not been end-to-end acknowledged yet. The
/// chain snapshot is frozen at entitlement time, never the live chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAnnounce {
    /// The member to serve.
    pub peer: [u8; 32],
    /// Chain id of the snapshot.
    pub key_id: [u8; 16],
    /// Chain key at `iteration`.
    pub chain_key: [u8; 32],
    /// First iteration the member may read.
    pub iteration: u32,
    /// Content id of the last announce envelope sent (what a receipt acks).
    pub wire_id: Option<[u8; 16]>,
    /// When that envelope was queued (0 = never) — paces end-to-end resends.
    pub last_sent: u64,
}

/// A sender-key group (sealed as one blob in the `groups` table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    /// Random 32-byte group id.
    pub id: [u8; 32],
    /// Display name (creator-controlled).
    pub name: String,
    /// The managing member (ADR-0012: single writer for the roster).
    pub creator: [u8; 32],
    /// Full roster, this device included.
    pub members: Vec<GroupMember>,
    /// Current group secret (header-key input).
    pub secret: [u8; 32],
    /// Previous secret, kept one generation deep so in-flight traffic
    /// sealed under it still header-decrypts across a re-key.
    pub prev_secret: Option<[u8; 32]>,
    /// Roster generation (monotonic; stale updates never regress).
    pub generation: u64,
    /// This device's sending chain (postcard of
    /// `kult_crypto::GroupSenderChain` — opaque to the store).
    pub sender_chain: Vec<u8>,
    /// Messages sent on the current chain (drives periodic PCS rotation).
    pub sent_since_rotation: u32,
    /// Announces owed to members (see [`PendingAnnounce`]).
    pub pending: Vec<PendingAnnounce>,
}

/// Sealed C6 authority state kept separate from the ADR-0012 group blob so
/// legacy postcard records remain byte-compatible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAuthorityRecord {
    /// Exact group id and table key.
    pub group: [u8; 32],
    /// Winning immutable authority content event id.
    pub state_id: [u8; 16],
    /// Canonical signed authority payload (content frame payload only).
    pub state_payload: Vec<u8>,
    /// Bounded signed admin request ids already terminally processed.
    pub consumed_requests: Vec<[u8; 16]>,
}

/// Per-member delivery state of one outbound group message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDelivery {
    /// The member this copy addresses.
    pub peer: [u8; 32],
    /// Content id of their envelope copy (set once it could be created —
    /// creating it needs the pairwise session for the delivery token).
    pub wire_id: Option<[u8; 16]>,
    /// `Queued` → `Sent` → `Delivered`, or terminal `Failed`, per member.
    pub state: DeliveryState,
}

/// A group message record (sealed as one blob in the `group_msgs` table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMessageRecord {
    /// Random 16-byte record id.
    pub id: [u8; 16],
    /// The group (conversation key).
    pub group: [u8; 32],
    /// Who sent it (this device's peer id for outbound).
    pub sender: [u8; 32],
    /// Sent or received.
    pub direction: Direction,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message body (plaintext — sealed at rest by the store).
    pub body: Vec<u8>,
    /// Outbound only: one entry per co-member.
    pub deliveries: Vec<GroupDelivery>,
    /// The encrypted wire body, retained while any member's copy could not
    /// be created yet (their session is still forming); dropped once every
    /// member is served.
    pub wire_body: Option<Vec<u8>>,
}

/// Legacy queue row: `(peer, msg_id, group_msg_id, envelope)`.
type LegacyQueueRow = ([u8; 32], Option<[u8; 16]>, Option<[u8; 16]>, Vec<u8>);
#[derive(Serialize, Deserialize)]
struct QueueRowV1 {
    peer: [u8; 32],
    msg_id: Option<[u8; 16]>,
    group_msg_id: Option<[u8; 16]>,
    class: QueueClass,
    envelope: Vec<u8>,
}
const QUEUE_ROW_MAGIC_V1: &[u8; 4] = b"KQ\0\x01";
#[derive(Serialize, Deserialize)]
struct QueueRowV2 {
    peer: [u8; 32],
    msg_id: Option<[u8; 16]>,
    group_msg_id: Option<[u8; 16]>,
    class: QueueClass,
    created_at: u64,
    attempts: u32,
    next_attempt_at: u64,
    envelope: Vec<u8>,
}
const QUEUE_ROW_MAGIC_V2: &[u8; 4] = b"KQ\0\x02";
/// One member's receiving-chain row: `(peer, opaque chain blob)`.
type GroupChainRow = ([u8; 32], Zeroizing<Vec<u8>>);

const WRAP_AD: &[u8] = b"KK-store-wrap-v1";
/// Maximum number of envelopes waiting for a session or handshake.
pub const MAX_PENDING_ENVELOPES: usize = 2_048;
/// Maximum aggregate sealed bytes retained by the deferred inbox.
pub const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta     (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS capabilities (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS messages (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS queue    (seq INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS seen     (id BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS receipt_replay (id BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS prekeys  (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS pending  (seq INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS resets   (peer BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS groups       (gid BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS group_authority (gid BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS group_chains (gid BLOB NOT NULL, peer BLOB NOT NULL, blob BLOB NOT NULL, PRIMARY KEY (gid, peer));
CREATE TABLE IF NOT EXISTS group_msgs   (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media_transfers (id BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media_objects   (id BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_metadata  (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS note_messages   (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scheduled_messages (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ephemeral (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS device_state (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS device_sync (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS contact_devices (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS message_device_delivery (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
";

/// Resolve one stable sidecar name without replacing the database extension.
///
/// Existing database symlinks resolve to the target before the suffix is
/// appended. For a new database, canonicalizing its parent gives relative and
/// absolute spellings the same lock file.
fn store_lock_path(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "store path has no file name",
        ))
    })?;
    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::canonicalize(parent)?.join(file_name)
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    let mut sidecar = resolved.into_os_string();
    sidecar.push(".lock");
    Ok(PathBuf::from(sidecar))
}

/// Acquire this database's non-blocking process-wide writer exclusion.
///
/// The sidecar intentionally remains after drop: unlinking a lock file can
/// split contenders across different inodes. Dropping the returned handle
/// releases the advisory lock.
fn acquire_store_lock(path: &Path) -> Result<File> {
    let lock_path = store_lock_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(lock_path)?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(StoreError::AlreadyOpen);
        }
        Err(error) => return Err(StoreError::Io(error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(lock)
}

/// Lock the opened database inode as a second writer-identity boundary.
///
/// On Unix, this closes the hardlink-alias gap left by a pathname sidecar.
/// The connection opens first but performs no schema or application write
/// before this lock succeeds. Other platforms retain the canonical sidecar
/// boundary until an equivalent file-identity strategy is qualified.
fn acquire_database_identity_lock(path: &Path) -> Result<Option<File>> {
    #[cfg(unix)]
    {
        let database = OpenOptions::new().read(true).write(true).open(path)?;
        match fs2::FileExt::try_lock_exclusive(&database) {
            Ok(()) => Ok(Some(database)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(StoreError::AlreadyOpen)
            }
            Err(error) => Err(StoreError::Io(error)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

/// An open Komms store with its encrypted domains unlocked.
pub struct Store {
    conn: Connection,
    k_identity: StorageKey,
    k_sessions: StorageKey,
    k_capabilities: StorageKey,
    k_messages: StorageKey,
    k_queue: StorageKey,
    k_contacts: StorageKey,
    k_prekeys: StorageKey,
    k_pending: StorageKey,
    /// One key for the three group tables; the associated-data strings
    /// (`group` / `group-chain` / `group-msg`) keep the domains disjoint.
    k_groups: StorageKey,
    k_media: StorageKey,
    k_local_metadata: StorageKey,
    k_notes: StorageKey,
    k_scheduled: StorageKey,
    k_ephemeral: StorageKey,
    k_devices: StorageKey,
    media_dir: PathBuf,
    media_limits: MediaLimits,
    // Prevents another Unix process from bypassing the pathname sidecar via a
    // hardlink alias to the same database inode.
    _database_lock: Option<File>,
    // Kept last so normal field drop order closes SQLite and clears every
    // store field before releasing the process-wide writer exclusion.
    _lock: File,
}

impl Store {
    /// Create a new store at `path`, deriving the KEK from `passphrase` with
    /// the given Argon2id profile. Fails if the file already contains a store.
    pub fn create(
        path: &Path,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        if store_v2::is_inactive_migration_target(&conn)? {
            return Err(StoreError::SchemaMismatch);
        }
        conn.execute_batch(SCHEMA)?;
        let existing: Option<Vec<u8>> = conn
            .query_row("SELECT v FROM meta WHERE k = 'wrapped_sk'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if existing.is_some() {
            return Err(StoreError::NotAStore); // refuse to clobber
        }

        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let kek = derive_kek(passphrase, &salt, profile)?;
        let kek_key = StorageKey::from_bytes(*kek);

        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(sk_bytes.as_mut());
        let wrapped = kek_key.seal(WRAP_AD, sk_bytes.as_ref(), rng);

        conn.execute("INSERT INTO meta (k, v) VALUES ('salt', ?1)", params![salt])?;
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('kdf', ?1)",
            params![
                postcard::to_allocvec(&(profile.m_cost_kib, profile.t_cost, profile.p_cost))
                    .map_err(|_| StoreError::Serialization)?
            ],
        )?;
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('wrapped_sk', ?1)",
            params![wrapped],
        )?;

        Self::with_master(
            conn,
            database_lock,
            lock,
            StorageKey::from_bytes(*sk_bytes),
            path,
        )
    }

    /// Open and unlock an existing store.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        if store_v2::is_inactive_migration_target(&conn)? {
            return Err(StoreError::SchemaMismatch);
        }
        // Idempotent: also creates any table added since this store was —
        // the only schema evolution so far is purely additive.
        conn.execute_batch(SCHEMA)?;
        let get = |k: &str| -> Result<Vec<u8>> {
            conn.query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get(0))
                .optional()?
                .ok_or(StoreError::NotAStore)
        };
        let salt: [u8; 16] = get("salt")?.try_into().map_err(|_| StoreError::NotAStore)?;
        let (m, t, p): (u32, u32, u32) =
            postcard::from_bytes(&get("kdf")?).map_err(|_| StoreError::NotAStore)?;
        let wrapped = get("wrapped_sk")?;

        let profile = KdfProfile {
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
        };
        let kek = derive_kek(passphrase, &salt, profile)?;
        let kek_key = StorageKey::from_bytes(*kek);
        let sk_vec = Zeroizing::new(kek_key.open(WRAP_AD, &wrapped)?); // wrong passphrase fails here
        let sk_bytes: [u8; 32] = sk_vec[..].try_into().map_err(|_| StoreError::NotAStore)?;

        Self::with_master(
            conn,
            database_lock,
            lock,
            StorageKey::from_bytes(sk_bytes),
            path,
        )
    }

    fn with_master(
        conn: Connection,
        database_lock: Option<File>,
        lock: File,
        master: StorageKey,
        path: &Path,
    ) -> Result<Self> {
        let media_dir = media::prepare_media_directory(path)?;
        Ok(Self {
            k_identity: master.derive(b"KK-store-identity"),
            k_sessions: master.derive(b"KK-store-sessions"),
            k_capabilities: master.derive(b"KK-store-capabilities"),
            k_messages: master.derive(b"KK-store-messages"),
            k_queue: master.derive(b"KK-store-queue"),
            k_contacts: master.derive(b"KK-store-contacts"),
            k_prekeys: master.derive(b"KK-store-prekeys"),
            k_pending: master.derive(b"KK-store-pending"),
            k_groups: master.derive(b"KK-store-groups"),
            k_media: master.derive(b"KK-store-media"),
            k_local_metadata: master.derive(b"KK-store-local-metadata"),
            k_notes: master.derive(b"KK-store-notes"),
            k_scheduled: master.derive(b"KK-store-scheduled"),
            k_ephemeral: master.derive(b"KK-store-ephemeral"),
            k_devices: master.derive(b"KK-store-devices"),
            media_dir,
            media_limits: MediaLimits::default(),
            conn,
            _database_lock: database_lock,
            _lock: lock,
        })
    }

    // ---- identity ---------------------------------------------------------

    /// Persist the device identity (sealed).
    pub fn put_identity(&self, id: &Identity, rng: &mut impl CryptoRngCore) -> Result<()> {
        let sealed = self
            .k_identity
            .seal(b"identity", id.to_bytes().as_ref(), rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO identity (id, blob) VALUES (1, ?1)",
            params![sealed],
        )?;
        Ok(())
    }

    /// Load the device identity, if one was stored.
    pub fn get_identity(&self) -> Result<Option<Identity>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT blob FROM identity WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let plain = Zeroizing::new(self.k_identity.open(b"identity", &sealed)?);
        let bytes: [u8; 64] = plain[..]
            .try_into()
            .map_err(|_| StoreError::Serialization)?;
        Ok(Some(Identity::from_bytes(&bytes)))
    }

    // ---- sessions ---------------------------------------------------------

    /// Persist (or replace) the ratchet session for a peer.
    pub fn put_session(
        &self,
        peer: &[u8; 32],
        session: &Session,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let sealed = session.seal(&self.k_sessions, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (peer, blob) VALUES (?1, ?2)",
            params![peer.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load the session for a peer.
    pub fn get_session(&self, peer: &[u8; 32]) -> Result<Option<Session>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM sessions WHERE peer = ?1",
                params![peer.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(s) => Ok(Some(Session::unseal(&s, &self.k_sessions)?)),
            None => Ok(None),
        }
    }

    /// Atomically commit an accepted ordinary pairwise receive transition.
    ///
    /// Sealing and serialization complete before `BEGIN IMMEDIATE`. The
    /// transaction advances the ratchet, appends optional history, records
    /// envelope dedup and receipt replay state, and acknowledges the exact
    /// deferred-inbox row together. A missing named pending row or any SQL
    /// failure rolls back the entire transition.
    pub fn commit_pairwise_receive(
        &self,
        plan: PairwiseReceivePlan<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if plan.message.is_some_and(|message| {
            message.direction != Direction::Inbound
                || message.state != DeliveryState::Received
                || message.wire_id.is_some()
        }) {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(sequence) = plan.source_pending_sequence {
            let sealed: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT blob FROM pending WHERE seq = ?1",
                    params![sequence],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(sealed) = sealed else {
                return Err(StoreError::InvalidTransition);
            };
            let plain = self.k_pending.open(b"pending", &sealed)?;
            let (envelope, _): (Vec<u8>, u64) =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if Envelope::decode(&envelope)?.content_id() != *plan.content_id {
                return Err(StoreError::InvalidTransition);
            }
        }

        let sealed_session = plan.session.seal(&self.k_sessions, rng);
        let sealed_message = if let Some(message) = plan.message {
            let plain = postcard::to_allocvec(message).map_err(|_| StoreError::Serialization)?;
            Some(self.k_messages.seal(b"message", &plain, rng))
        } else {
            None
        };
        let replay = postcard::to_allocvec(&(*plan.peer_device, plan.received_at))
            .map_err(|_| StoreError::Serialization)?;
        let sealed_replay = self.k_queue.seal(b"receipt-replay", &replay, rng);

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let applied = (|| -> Result<()> {
            tx.execute(
                "INSERT OR REPLACE INTO sessions (peer, blob) VALUES (?1, ?2)",
                params![plan.peer_device.as_slice(), sealed_session],
            )?;
            if let Some(sealed) = sealed_message {
                tx.execute("INSERT INTO messages (blob) VALUES (?1)", params![sealed])?;
            }
            tx.execute(
                "INSERT INTO seen (id) VALUES (?1)",
                params![plan.content_id.as_slice()],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO receipt_replay (id, blob) VALUES (?1, ?2)",
                params![plan.content_id.as_slice(), sealed_replay],
            )?;
            if let Some(sequence) = plan.source_pending_sequence {
                let removed =
                    tx.execute("DELETE FROM pending WHERE seq = ?1", params![sequence])?;
                if removed != 1 {
                    return Err(StoreError::InvalidTransition);
                }
            }
            Ok(())
        })();

        match applied {
            Ok(()) => {
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                let _ = tx.rollback();
                Err(error)
            }
        }
    }

    /// Delete one exact physical-endpoint ratchet session.
    pub fn delete_session(&self, peer: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE peer = ?1",
            params![peer.as_slice()],
        )?;
        Ok(())
    }

    // ---- authenticated peer capabilities ---------------------------------

    /// Persist (or replace) the authenticated content-capability snapshot
    /// tied to a peer's current ratchet session.
    pub fn put_capabilities(
        &self,
        peer: &[u8; 32],
        capabilities: &CapabilityControl,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let encoded = capabilities.encode()?;
        let sealed = self.k_capabilities.seal(b"capability", &encoded, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO capabilities (peer, blob) VALUES (?1, ?2)",
            params![peer.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load the authenticated content-capability snapshot for a peer's
    /// current ratchet session.
    pub fn get_capabilities(&self, peer: &[u8; 32]) -> Result<Option<CapabilityControl>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM capabilities WHERE peer = ?1",
                params![peer.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match sealed {
            Some(sealed) => {
                let plain = self.k_capabilities.open(b"capability", &sealed)?;
                Ok(Some(CapabilityControl::decode(&plain)?))
            }
            None => Ok(None),
        }
    }

    /// Clear a peer capability snapshot when its ratchet session is reset or
    /// replaced. Capability state is re-creatable and never backed up.
    pub fn delete_capabilities(&self, peer: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM capabilities WHERE peer = ?1",
            params![peer.as_slice()],
        )?;
        Ok(())
    }

    // ---- messages ---------------------------------------------------------

    /// Append a message record (sealed).
    pub fn put_message(&self, rec: &MessageRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_messages.seal(b"message", &plain, rng);
        self.conn
            .execute("INSERT INTO messages (blob) VALUES (?1)", params![sealed])?;
        Ok(())
    }

    /// All messages for a peer, in insertion order.
    pub fn messages_with(&self, peer: &[u8; 32]) -> Result<Vec<MessageRecord>> {
        Ok(self
            .all_messages()?
            .into_iter()
            .filter(|record| &record.peer == peer)
            .collect())
    }

    /// Replace the stored record with the same `id` as `rec`. Returns `true`
    /// if a record was found and updated. (Records are sealed individually,
    /// so lookup is a scan — fine at local-history scale.)
    pub fn update_message(
        &self,
        rec: &MessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_messages.open(b"message", &sealed)?;
            let stored: MessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if stored.id == rec.id {
                let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
                let sealed = self.k_messages.seal(b"message", &plain, rng);
                self.conn.execute(
                    "UPDATE messages SET blob = ?2 WHERE rowid_ = ?1",
                    params![rowid, sealed],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Delete one exact pairwise history row after an expiry tombstone is durable.
    pub fn delete_message_record(
        &self,
        peer: &[u8; 32],
        direction: Direction,
        id: &[u8; 16],
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_messages.open(b"message", &sealed)?;
            let record: MessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &record.peer == peer && record.direction == direction && &record.id == id {
                self.conn
                    .execute("DELETE FROM messages WHERE rowid_ = ?1", params![rowid])?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ---- contacts ----------------------------------------------------------

    /// Insert or replace a contact (sealed).
    pub fn put_contact(&self, rec: &ContactRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_contacts.seal(b"contact", &plain, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (peer, blob) VALUES (?1, ?2)",
            params![rec.peer.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load one contact.
    pub fn get_contact(&self, peer: &[u8; 32]) -> Result<Option<ContactRecord>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM contacts WHERE peer = ?1",
                params![peer.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(s) => {
                let plain = self.k_contacts.open(b"contact", &s)?;
                Ok(Some(
                    postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?,
                ))
            }
            None => Ok(None),
        }
    }

    /// All contacts.
    pub fn contacts(&self) -> Result<Vec<ContactRecord>> {
        let mut stmt = self.conn.prepare("SELECT blob FROM contacts")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_contacts.open(b"contact", &row?)?;
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    /// Delete one exact sealed contact. Missing peers are an honest no-op.
    pub fn delete_contact(&self, peer: &[u8; 32]) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM contacts WHERE peer = ?1",
            params![peer.as_slice()],
        )? == 1)
    }

    // ---- own prekey secrets -------------------------------------------------

    /// Persist this device's prekey secrets as one opaque sealed blob (the
    /// runtime owns the serialization; the store interprets nothing).
    pub fn put_prekeys(&self, blob: &[u8], rng: &mut impl CryptoRngCore) -> Result<()> {
        let sealed = self.k_prekeys.seal(b"prekeys", blob, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO prekeys (id, blob) VALUES (1, ?1)",
            params![sealed],
        )?;
        Ok(())
    }

    /// Load this device's prekey secrets blob, if stored.
    pub fn get_prekeys(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT blob FROM prekeys WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        match sealed {
            Some(s) => Ok(Some(Zeroizing::new(self.k_prekeys.open(b"prekeys", &s)?))),
            None => Ok(None),
        }
    }

    // ---- outbound queue ---------------------------------------------------

    /// Enqueue an envelope for delivery (sealed at rest; survives restarts).
    pub fn queue_push(&self, item: &QueueItem, rng: &mut impl CryptoRngCore) -> Result<i64> {
        let envelope = item.envelope.try_encode()?;
        let row = QueueRowV2 {
            peer: item.peer,
            msg_id: item.msg_id,
            group_msg_id: item.group_msg_id,
            class: item.class,
            created_at: item.created_at,
            attempts: item.attempts,
            next_attempt_at: item.next_attempt_at,
            envelope,
        };
        let encoded = postcard::to_allocvec(&row).map_err(|_| StoreError::Serialization)?;
        let mut plain = Vec::with_capacity(QUEUE_ROW_MAGIC_V2.len() + encoded.len());
        plain.extend_from_slice(QUEUE_ROW_MAGIC_V2);
        plain.extend_from_slice(&encoded);
        let sealed = self.k_queue.seal(b"queue", &plain, rng);
        self.conn
            .execute("INSERT INTO queue (blob) VALUES (?1)", params![sealed])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// All queued items with their sequence numbers.
    pub fn queue_all(&self) -> Result<Vec<(i64, QueueItem)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, blob FROM queue ORDER BY seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, sealed) = row?;
            let plain = self.k_queue.open(b"queue", &sealed)?;
            let (
                peer,
                msg_id,
                group_msg_id,
                class,
                created_at,
                attempts,
                next_attempt_at,
                env_bytes,
            ) = if let Some(encoded) = plain.strip_prefix(QUEUE_ROW_MAGIC_V2) {
                let (row, remainder): (QueueRowV2, &[u8]) =
                    postcard::take_from_bytes(encoded).map_err(|_| StoreError::Serialization)?;
                if !remainder.is_empty() {
                    return Err(StoreError::Serialization);
                }
                (
                    row.peer,
                    row.msg_id,
                    row.group_msg_id,
                    row.class,
                    row.created_at,
                    row.attempts,
                    row.next_attempt_at,
                    row.envelope,
                )
            } else if let Some(encoded) = plain.strip_prefix(QUEUE_ROW_MAGIC_V1) {
                let (row, remainder): (QueueRowV1, &[u8]) =
                    postcard::take_from_bytes(encoded).map_err(|_| StoreError::Serialization)?;
                if !remainder.is_empty() {
                    return Err(StoreError::Serialization);
                }
                (
                    row.peer,
                    row.msg_id,
                    row.group_msg_id,
                    row.class,
                    0,
                    0,
                    0,
                    row.envelope,
                )
            } else {
                let (legacy, remainder): (LegacyQueueRow, &[u8]) =
                    postcard::take_from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
                if !remainder.is_empty() {
                    return Err(StoreError::Serialization);
                }
                (
                    legacy.0,
                    legacy.1,
                    legacy.2,
                    QueueClass::Normal,
                    0,
                    0,
                    0,
                    legacy.3,
                )
            };
            out.push((
                seq,
                QueueItem {
                    peer,
                    msg_id,
                    group_msg_id,
                    class,
                    created_at,
                    attempts,
                    next_attempt_at,
                    envelope: Envelope::decode(&env_bytes)?,
                },
            ));
        }
        Ok(out)
    }

    /// Remove a delivered/acked envelope from the queue.
    pub fn queue_ack(&self, seq: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM queue WHERE seq = ?1", params![seq])?;
        Ok(())
    }

    /// Replace one queued item's sealed scheduling metadata without changing
    /// its FIFO sequence number.
    pub fn queue_update(
        &self,
        seq: i64,
        item: &QueueItem,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let envelope = item.envelope.try_encode()?;
        let row = QueueRowV2 {
            peer: item.peer,
            msg_id: item.msg_id,
            group_msg_id: item.group_msg_id,
            class: item.class,
            created_at: item.created_at,
            attempts: item.attempts,
            next_attempt_at: item.next_attempt_at,
            envelope,
        };
        let encoded = postcard::to_allocvec(&row).map_err(|_| StoreError::Serialization)?;
        let mut plain = Vec::with_capacity(QUEUE_ROW_MAGIC_V2.len() + encoded.len());
        plain.extend_from_slice(QUEUE_ROW_MAGIC_V2);
        plain.extend_from_slice(&encoded);
        let sealed = self.k_queue.seal(b"queue", &plain, rng);
        self.conn.execute(
            "UPDATE queue SET blob = ?1 WHERE seq = ?2",
            params![sealed, seq],
        )?;
        Ok(())
    }

    /// Remove every queued envelope addressed to one revoked physical endpoint.
    pub fn queue_remove_peer(&self, peer: &[u8; 32]) -> Result<usize> {
        let sequences: Vec<i64> = self
            .queue_all()?
            .into_iter()
            .filter_map(|(seq, item)| (&item.peer == peer).then_some(seq))
            .collect();
        for sequence in &sequences {
            self.queue_ack(*sequence)?;
        }
        Ok(sequences.len())
    }

    /// Retarget durable queue ownership after a legacy endpoint is bound to
    /// its certified physical id. Envelope bytes remain end-to-end identical.
    pub fn queue_retarget_peer(
        &self,
        old_peer: &[u8; 32],
        new_peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize> {
        let rows: Vec<(i64, QueueItem)> = self
            .queue_all()?
            .into_iter()
            .filter(|(_, item)| &item.peer == old_peer)
            .collect();
        for (sequence, mut item) in rows.iter().cloned() {
            self.queue_ack(sequence)?;
            item.peer = *new_peer;
            self.queue_push(&item, rng)?;
        }
        Ok(rows.len())
    }

    /// Remove every queued envelope associated with one expired pairwise message.
    pub fn queue_remove_message(&self, id: &[u8; 16]) -> Result<usize> {
        let sequences: Vec<i64> = self
            .queue_all()?
            .into_iter()
            .filter_map(|(seq, item)| (item.msg_id.as_ref() == Some(id)).then_some(seq))
            .collect();
        for sequence in &sequences {
            self.queue_ack(*sequence)?;
        }
        Ok(sequences.len())
    }

    /// Remove every queued member copy associated with one expired group message.
    pub fn queue_remove_group_message(&self, id: &[u8; 16]) -> Result<usize> {
        let sequences: Vec<i64> = self
            .queue_all()?
            .into_iter()
            .filter_map(|(seq, item)| (item.group_msg_id.as_ref() == Some(id)).then_some(seq))
            .collect();
        for sequence in &sequences {
            self.queue_ack(*sequence)?;
        }
        Ok(sequences.len())
    }

    /// Remove queued copies of one exact sealed envelope after its encrypted
    /// end-to-end receipt returns. Matching the content id keeps other linked
    /// devices' copies of the same logical message independently retryable.
    pub fn queue_remove_envelope(&self, content_id: &[u8; 16]) -> Result<usize> {
        let sequences: Vec<i64> = self
            .queue_all()?
            .into_iter()
            .filter_map(|(seq, item)| (item.envelope.content_id() == *content_id).then_some(seq))
            .collect();
        for sequence in &sequences {
            self.queue_ack(*sequence)?;
        }
        Ok(sequences.len())
    }

    // ---- inbound pending (envelopes that cannot be processed yet) ---------

    /// Stash an inbound envelope that cannot be consumed yet (e.g. it arrived
    /// before the handshake that establishes its session). Survives restarts
    /// so out-of-order arrival across carriers never loses messages. Returns
    /// the stable sequence used for later acknowledgement.
    pub fn pending_push(
        &self,
        env: &Envelope,
        first_seen: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<i64> {
        let encoded = env.try_encode()?;
        let plain =
            postcard::to_allocvec(&(encoded, first_seen)).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_pending.seal(b"pending", &plain, rng);
        if sealed.len() > MAX_PENDING_BYTES {
            return Err(StoreError::PendingQuota);
        }

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let (count, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(blob)), 0) FROM pending",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let count = usize::try_from(count).map_err(|_| StoreError::Serialization)?;
        let bytes = usize::try_from(bytes).map_err(|_| StoreError::Serialization)?;
        if count >= MAX_PENDING_ENVELOPES
            || bytes
                .checked_add(sealed.len())
                .is_none_or(|total| total > MAX_PENDING_BYTES)
        {
            tx.rollback()?;
            return Err(StoreError::PendingQuota);
        }
        tx.execute("INSERT INTO pending (blob) VALUES (?1)", params![sealed])?;
        let sequence = tx.last_insert_rowid();
        tx.commit()?;
        Ok(sequence)
    }

    /// Return every stashed inbound envelope without removing it.
    ///
    /// Each tuple is `(stable sequence, envelope, first-seen timestamp)`.
    /// The caller must explicitly [`Store::pending_ack`] a sequence only
    /// after the envelope is consumed or has expired. This gives deferred
    /// receive processing at-least-once crash semantics.
    pub fn pending_all(&self) -> Result<Vec<(i64, Envelope, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, blob FROM pending ORDER BY seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, sealed) = row?;
            let plain = self.k_pending.open(b"pending", &sealed)?;
            let (env_bytes, first_seen): (Vec<u8>, u64) =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            out.push((sequence, Envelope::decode(&env_bytes)?, first_seen));
        }
        Ok(out)
    }

    /// Acknowledge one consumed or expired inbound envelope.
    ///
    /// The stable sequence makes acknowledgement row-scoped: retryable and
    /// not-yet-visited rows remain durable if processing returns an error or
    /// the process stops between envelopes.
    pub fn pending_ack(&self, sequence: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending WHERE seq = ?1", params![sequence])?;
        Ok(())
    }

    // ---- groups (ADR-0012) --------------------------------------------------

    /// Insert or replace a group (sealed).
    pub fn put_group(&self, rec: &GroupRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain =
            Zeroizing::new(postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?);
        let sealed = self.k_groups.seal(b"group", &plain, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO groups (gid, blob) VALUES (?1, ?2)",
            params![rec.id.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load one group.
    pub fn get_group(&self, id: &[u8; 32]) -> Result<Option<GroupRecord>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM groups WHERE gid = ?1",
                params![id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(s) => {
                let plain = Zeroizing::new(self.k_groups.open(b"group", &s)?);
                Ok(Some(
                    postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?,
                ))
            }
            None => Ok(None),
        }
    }

    /// All groups.
    pub fn groups(&self) -> Result<Vec<GroupRecord>> {
        let mut stmt = self.conn.prepare("SELECT blob FROM groups")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = Zeroizing::new(self.k_groups.open(b"group", &row?)?);
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    /// Remove a group and every receiving chain under it (leaving keeps the
    /// message history — that is this device's data).
    pub fn delete_group(&self, id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("DELETE FROM groups WHERE gid = ?1", params![id.as_slice()])?;
        self.conn.execute(
            "DELETE FROM group_chains WHERE gid = ?1",
            params![id.as_slice()],
        )?;
        self.conn.execute(
            "DELETE FROM group_authority WHERE gid = ?1",
            params![id.as_slice()],
        )?;
        Ok(())
    }

    /// Persist or replace one sealed signed authority state.
    pub fn put_group_authority(
        &self,
        rec: &GroupAuthorityRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let plain =
            Zeroizing::new(postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?);
        let sealed = self.k_groups.seal(b"group-authority", &plain, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO group_authority (gid, blob) VALUES (?1, ?2)",
            params![rec.group.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load one group's sealed signed authority state.
    pub fn get_group_authority(&self, group: &[u8; 32]) -> Result<Option<GroupAuthorityRecord>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM group_authority WHERE gid = ?1",
                params![group.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match sealed {
            Some(sealed) => {
                let plain = Zeroizing::new(self.k_groups.open(b"group-authority", &sealed)?);
                Ok(Some(
                    postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?,
                ))
            }
            None => Ok(None),
        }
    }

    /// All sealed C6 authority records for backup and audit.
    pub fn group_authorities(&self) -> Result<Vec<GroupAuthorityRecord>> {
        let mut stmt = self.conn.prepare("SELECT blob FROM group_authority")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = Zeroizing::new(self.k_groups.open(b"group-authority", &row?)?);
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    /// Persist (or replace) a co-member's receiving chain for a group. The
    /// blob is opaque (postcard of `kult_crypto::GroupReceiverChain`).
    pub fn put_group_chain(
        &self,
        group: &[u8; 32],
        peer: &[u8; 32],
        blob: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let sealed = self.k_groups.seal(b"group-chain", blob, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO group_chains (gid, peer, blob) VALUES (?1, ?2, ?3)",
            params![group.as_slice(), peer.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Load one member's receiving chain blob for a group.
    pub fn get_group_chain(
        &self,
        group: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM group_chains WHERE gid = ?1 AND peer = ?2",
                params![group.as_slice(), peer.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match sealed {
            Some(s) => Ok(Some(Zeroizing::new(
                self.k_groups.open(b"group-chain", &s)?,
            ))),
            None => Ok(None),
        }
    }

    /// All receiving chains for a group, as `(peer, blob)`.
    pub fn group_chains(&self, group: &[u8; 32]) -> Result<Vec<GroupChainRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer, blob FROM group_chains WHERE gid = ?1")?;
        let rows = stmt.query_map(params![group.as_slice()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (peer, sealed) = row?;
            let peer: [u8; 32] = peer.try_into().map_err(|_| StoreError::Serialization)?;
            out.push((
                peer,
                Zeroizing::new(self.k_groups.open(b"group-chain", &sealed)?),
            ));
        }
        Ok(out)
    }

    /// Drop one member's receiving chain (they were removed or rotated to a
    /// new chain that replaces this one).
    pub fn delete_group_chain(&self, group: &[u8; 32], peer: &[u8; 32]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_chains WHERE gid = ?1 AND peer = ?2",
            params![group.as_slice(), peer.as_slice()],
        )?;
        Ok(())
    }

    /// Append a group message record (sealed).
    pub fn put_group_message(
        &self,
        rec: &GroupMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_groups.seal(b"group-msg", &plain, rng);
        self.conn
            .execute("INSERT INTO group_msgs (blob) VALUES (?1)", params![sealed])?;
        Ok(())
    }

    /// Replace the stored group message with the same `id` as `rec`.
    /// Returns `true` if a record was found and updated.
    pub fn update_group_message(
        &self,
        rec: &GroupMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM group_msgs ORDER BY rowid_")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_groups.open(b"group-msg", &sealed)?;
            let stored: GroupMessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if stored.id == rec.id {
                let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
                let sealed = self.k_groups.seal(b"group-msg", &plain, rng);
                self.conn.execute(
                    "UPDATE group_msgs SET blob = ?2 WHERE rowid_ = ?1",
                    params![rowid, sealed],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Delete one exact group history row after an expiry tombstone is durable.
    pub fn delete_group_message_record(
        &self,
        group: &[u8; 32],
        sender: &[u8; 32],
        id: &[u8; 16],
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM group_msgs ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_groups.open(b"group-msg", &sealed)?;
            let record: GroupMessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &record.group == group && &record.sender == sender && &record.id == id {
                self.conn
                    .execute("DELETE FROM group_msgs WHERE rowid_ = ?1", params![rowid])?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// All messages for a group, in insertion order.
    pub fn group_messages(&self, group: &[u8; 32]) -> Result<Vec<GroupMessageRecord>> {
        Ok(self
            .all_group_messages()?
            .into_iter()
            .filter(|r| &r.group == group)
            .collect())
    }

    /// Every stored group message across all groups, in insertion order
    /// (receipt application scans this; local history stays small).
    pub fn all_group_messages(&self) -> Result<Vec<GroupMessageRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT blob FROM group_msgs ORDER BY rowid_")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_groups.open(b"group-msg", &row?)?;
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    // ---- dedup ------------------------------------------------------------

    /// Record an envelope content id; returns `true` if it was new
    /// (multipath duplicates return `false` and must be dropped).
    pub fn mark_seen(&self, content_id: &[u8; 16]) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO seen (id) VALUES (?1)",
            params![content_id.as_slice()],
        )?;
        Ok(n == 1)
    }

    /// Has this envelope content id been consumed before?
    pub fn is_seen(&self, content_id: &[u8; 16]) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM seen WHERE id = ?1",
                params![content_id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Remember where an accepted envelope's encrypted receipt must return,
    /// allowing exact transport duplicates to replay the receipt without
    /// decrypting or storing the message twice.
    pub fn put_receipt_replay(
        &self,
        id: &[u8; 16],
        peer: &[u8; 32],
        received_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let encoded =
            postcard::to_allocvec(&(*peer, received_at)).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_queue.seal(b"receipt-replay", &encoded, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO receipt_replay (id, blob) VALUES (?1, ?2)",
            params![id.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Return the physical sender route for a previously accepted envelope.
    pub fn receipt_replay_peer(&self, id: &[u8; 16]) -> Result<Option<[u8; 32]>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM receipt_replay WHERE id = ?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let plain = self.k_queue.open(b"receipt-replay", &sealed)?;
        let (peer, _): ([u8; 32], u64) =
            postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
        Ok(Some(peer))
    }

    /// Remove duplicate-receipt routes older than the endpoint delivery
    /// window. Seen ids remain independent and keep deduplication durable.
    pub fn sweep_receipt_replay(&self, cutoff: u64) -> Result<usize> {
        let mut stmt = self.conn.prepare("SELECT id, blob FROM receipt_replay")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut expired = Vec::new();
        for row in rows {
            let (id, sealed) = row?;
            let plain = self.k_queue.open(b"receipt-replay", &sealed)?;
            let (_, received_at): ([u8; 32], u64) =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if received_at <= cutoff {
                expired.push(id);
            }
        }
        drop(stmt);
        for id in &expired {
            self.conn
                .execute("DELETE FROM receipt_replay WHERE id = ?1", params![id])?;
        }
        Ok(expired.len())
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use kult_crypto::{
        initiate, respond, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle,
        RatchetMessage, SignedPrekeySecret,
    };
    use kult_protocol::{pad, unpad, EnvelopeKind};
    use rand::{rngs::StdRng, SeedableRng};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn queue_v2_schedule_round_trips_and_legacy_rows_default_normal() {
        let mut rng = StdRng::seed_from_u64(0x511ce);
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::create(&dir.path().join("queue.db"), b"pass", TEST_KDF, &mut rng).unwrap();
        let envelope = Envelope::new(EnvelopeKind::Receipt, [2; 32], vec![3]);
        store
            .queue_push(
                &QueueItem {
                    peer: [1; 32],
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Bulk,
                    created_at: 123,
                    attempts: 4,
                    next_attempt_at: 456,
                    envelope: envelope.clone(),
                },
                &mut rng,
            )
            .unwrap();

        let legacy = postcard::to_allocvec(&(
            [4u8; 32],
            None::<[u8; 16]>,
            None::<[u8; 16]>,
            envelope.encode(),
        ))
        .unwrap();
        let sealed = store.k_queue.seal(b"queue", &legacy, &mut rng);
        store
            .conn
            .execute("INSERT INTO queue (blob) VALUES (?1)", params![sealed])
            .unwrap();

        let rows = store.queue_all().unwrap();
        assert_eq!(rows[0].1.class, QueueClass::Bulk);
        assert_eq!(rows[0].1.created_at, 123);
        assert_eq!(rows[0].1.attempts, 4);
        assert_eq!(rows[0].1.next_attempt_at, 456);
        assert_eq!(rows[1].1.class, QueueClass::Normal);
        assert_eq!(rows[1].1.created_at, 0);
        assert_eq!(rows[1].1.attempts, 0);
        assert_eq!(rows[1].1.peer, [4; 32]);
    }

    #[test]
    fn queue_rejects_oversized_objects_before_insert_or_update() {
        let mut rng = StdRng::seed_from_u64(0x511cf);
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(
            &dir.path().join("queue-limit.db"),
            b"pass",
            TEST_KDF,
            &mut rng,
        )
        .unwrap();
        let mut item = QueueItem {
            peer: [1; 32],
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: 1,
            attempts: 0,
            next_attempt_at: 1,
            envelope: Envelope::new(EnvelopeKind::Message, [2; 32], vec![3]),
        };
        let sequence = store.queue_push(&item, &mut rng).unwrap();
        item.envelope = Envelope::new(
            EnvelopeKind::Message,
            [4; 32],
            vec![5; kult_protocol::MAX_ENVELOPE_BYTES],
        );
        assert!(matches!(
            store.queue_update(sequence, &item, &mut rng),
            Err(StoreError::Protocol(
                kult_protocol::ProtocolError::EnvelopeTooLarge
            ))
        ));
        assert_eq!(store.queue_all().unwrap()[0].1.envelope.body, vec![3]);

        store.queue_ack(sequence).unwrap();
        assert!(matches!(
            store.queue_push(&item, &mut rng),
            Err(StoreError::Protocol(
                kult_protocol::ProtocolError::EnvelopeTooLarge
            ))
        ));
        assert!(store.queue_all().unwrap().is_empty());
    }

    #[test]
    fn accepted_envelope_receipt_route_is_sealed_and_expires() {
        let mut rng = StdRng::seed_from_u64(0xacc);
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::create(&dir.path().join("replay.db"), b"pass", TEST_KDF, &mut rng).unwrap();
        let id = [7; 16];
        let peer = [8; 32];
        store.put_receipt_replay(&id, &peer, 123, &mut rng).unwrap();
        assert_eq!(store.receipt_replay_peer(&id).unwrap(), Some(peer));
        assert_eq!(store.sweep_receipt_replay(122).unwrap(), 0);
        assert_eq!(store.sweep_receipt_replay(123).unwrap(), 1);
        assert_eq!(store.receipt_replay_peer(&id).unwrap(), None);
    }

    #[test]
    fn pending_rows_keep_stable_ids_until_explicit_acknowledgement() {
        let mut rng = StdRng::seed_from_u64(0x1b0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending.db");
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let first = Envelope::new(EnvelopeKind::Message, [1; 32], vec![2]);
        let second = Envelope::new(EnvelopeKind::Receipt, [3; 32], vec![4]);

        let first_sequence = store.pending_push(&first, 100, &mut rng).unwrap();
        let second_sequence = store.pending_push(&second, 200, &mut rng).unwrap();
        assert_ne!(first_sequence, second_sequence);

        let first_read = store.pending_all().unwrap();
        let second_read = store.pending_all().unwrap();
        assert_eq!(first_read, second_read);
        assert_eq!(
            first_read,
            vec![
                (first_sequence, first.clone(), 100),
                (second_sequence, second.clone(), 200),
            ]
        );

        drop(store);
        let reopened = Store::open(&path, b"pass").unwrap();
        assert_eq!(reopened.pending_all().unwrap(), first_read);

        reopened.pending_ack(first_sequence).unwrap();
        assert_eq!(
            reopened.pending_all().unwrap(),
            vec![(second_sequence, second, 200)]
        );
        reopened.pending_ack(second_sequence).unwrap();
        assert!(reopened.pending_all().unwrap().is_empty());
    }

    #[test]
    fn pending_inbox_enforces_item_and_sealed_byte_quotas() {
        let mut rng = StdRng::seed_from_u64(0x1b1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-quota.db");
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let envelope = Envelope::new(EnvelopeKind::Message, [1; 32], vec![2]);
        let oversized = Envelope::new(
            EnvelopeKind::Message,
            [3; 32],
            vec![4; kult_protocol::MAX_ENVELOPE_BYTES],
        );
        assert!(matches!(
            store.pending_push(&oversized, 100, &mut rng),
            Err(StoreError::Protocol(
                kult_protocol::ProtocolError::EnvelopeTooLarge
            ))
        ));
        assert!(store.pending_all().unwrap().is_empty());

        let tx = Transaction::new_unchecked(&store.conn, TransactionBehavior::Immediate).unwrap();
        for _ in 0..MAX_PENDING_ENVELOPES {
            tx.execute("INSERT INTO pending (blob) VALUES (zeroblob(1))", [])
                .unwrap();
        }
        tx.commit().unwrap();
        assert!(matches!(
            store.pending_push(&envelope, 100, &mut rng),
            Err(StoreError::PendingQuota)
        ));

        store.conn.execute("DELETE FROM pending", []).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO pending (blob) VALUES (zeroblob(?1))",
                params![MAX_PENDING_BYTES as i64],
            )
            .unwrap();
        assert!(matches!(
            store.pending_push(&envelope, 100, &mut rng),
            Err(StoreError::PendingQuota)
        ));
    }

    #[test]
    fn pairwise_receive_failure_rolls_back_ratchet_and_every_consequence() {
        const NOW: u64 = 1_800_000_000;

        let mut rng = StdRng::seed_from_u64(0xa70c);
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::create(&dir.path().join("receive.db"), b"pass", TEST_KDF, &mut rng).unwrap();

        let alice = Identity::generate(&mut rng);
        let bob = Identity::generate(&mut rng);
        let spk = SignedPrekeySecret::generate(&mut rng, 1);
        let pqspk = PqPrekeySecret::generate(&mut rng, 2);
        let opk = OneTimePrekeySecret::generate(&mut rng, 3);
        let bundle = PrekeyBundle::build(&bob, &spk, &pqspk, Some(&opk), NOW + 86_400, vec![])
            .verify(NOW)
            .unwrap();
        let (mut alice_session, initial) =
            initiate(&alice, &bundle, &pad(b"first").unwrap(), NOW, &mut rng).unwrap();
        let (bob_session, first) =
            respond(&bob, &spk, &pqspk, Some(&opk), &initial, NOW, &mut rng).unwrap();
        assert_eq!(unpad(&first).unwrap(), b"first");

        let peer_device = alice.public().ed;
        store
            .put_session(&peer_device, &bob_session, &mut rng)
            .unwrap();
        let ratchet = alice_session.encrypt(&mut rng, NOW + 1, &pad(b"second").unwrap(), &[]);
        let envelope = Envelope::new(EnvelopeKind::Message, [4; 32], ratchet.encode());
        let content_id = envelope.content_id();
        let pending_sequence = store.pending_push(&envelope, NOW + 1, &mut rng).unwrap();
        let unrelated = Envelope::new(EnvelopeKind::Receipt, [6; 32], vec![7]);
        let unrelated_sequence = store.pending_push(&unrelated, NOW + 2, &mut rng).unwrap();
        let message = MessageRecord {
            id: [5; 16],
            peer: peer_device,
            direction: Direction::Inbound,
            state: DeliveryState::Received,
            timestamp: NOW + 1,
            body: b"second".to_vec(),
            wire_id: None,
        };

        let decoded = RatchetMessage::decode(&envelope.body).unwrap();
        let mut failed_candidate = store.get_session(&peer_device).unwrap().unwrap();
        assert_eq!(
            unpad(
                &failed_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );

        // Force the third statement to fail after the candidate session and
        // message insert. SQLite must roll both back and retain the source.
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER fail_pairwise_receive
                 BEFORE INSERT ON seen
                 BEGIN
                   SELECT RAISE(ABORT, 'injected receive failure');
                 END;",
            )
            .unwrap();
        assert!(store
            .commit_pairwise_receive(
                PairwiseReceivePlan {
                    peer_device: &peer_device,
                    session: &failed_candidate,
                    message: Some(&message),
                    content_id: &content_id,
                    received_at: NOW + 1,
                    source_pending_sequence: Some(pending_sequence),
                },
                &mut rng,
            )
            .is_err());
        store
            .conn
            .execute_batch("DROP TRIGGER fail_pairwise_receive")
            .unwrap();

        assert!(store.all_messages().unwrap().is_empty());
        assert!(!store.is_seen(&content_id).unwrap());
        assert_eq!(
            store.pending_all().unwrap(),
            vec![
                (pending_sequence, envelope.clone(), NOW + 1),
                (unrelated_sequence, unrelated.clone(), NOW + 2),
            ]
        );
        assert_eq!(store.receipt_replay_peer(&content_id).unwrap(), None);

        // The original durable ratchet still decrypts the same ciphertext,
        // proving the failed candidate was not persisted.
        let mut wrong_source_candidate = store.get_session(&peer_device).unwrap().unwrap();
        assert_eq!(
            unpad(
                &wrong_source_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
        assert!(matches!(
            store.commit_pairwise_receive(
                PairwiseReceivePlan {
                    peer_device: &peer_device,
                    session: &wrong_source_candidate,
                    message: Some(&message),
                    content_id: &content_id,
                    received_at: NOW + 1,
                    source_pending_sequence: Some(unrelated_sequence),
                },
                &mut rng,
            ),
            Err(StoreError::InvalidTransition)
        ));
        assert!(store.all_messages().unwrap().is_empty());
        assert!(!store.is_seen(&content_id).unwrap());
        assert_eq!(
            store.pending_all().unwrap(),
            vec![
                (pending_sequence, envelope, NOW + 1),
                (unrelated_sequence, unrelated.clone(), NOW + 2),
            ]
        );
        assert_eq!(store.receipt_replay_peer(&content_id).unwrap(), None);

        // A final retry from the still-unchanged durable session commits all
        // consequences and consumes exactly the named pending source.
        let mut retry_candidate = store.get_session(&peer_device).unwrap().unwrap();
        assert_eq!(
            unpad(
                &retry_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
        store
            .commit_pairwise_receive(
                PairwiseReceivePlan {
                    peer_device: &peer_device,
                    session: &retry_candidate,
                    message: Some(&message),
                    content_id: &content_id,
                    received_at: NOW + 1,
                    source_pending_sequence: Some(pending_sequence),
                },
                &mut rng,
            )
            .unwrap();

        assert_eq!(store.all_messages().unwrap(), vec![message]);
        assert!(store.is_seen(&content_id).unwrap());
        assert_eq!(
            store.pending_all().unwrap(),
            vec![(unrelated_sequence, unrelated, NOW + 2)]
        );
        assert_eq!(
            store.receipt_replay_peer(&content_id).unwrap(),
            Some(peer_device)
        );
        let mut committed = store.get_session(&peer_device).unwrap().unwrap();
        assert!(committed.decrypt(&mut rng, NOW + 1, &decoded, &[]).is_err());
    }
}
