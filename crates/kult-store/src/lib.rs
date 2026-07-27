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

#[cfg(feature = "test-failpoints")]
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use rand_core::CryptoRngCore;
#[cfg(test)]
use rusqlite::params;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{derive_kek, CryptoError, Identity, KdfProfile, Session, StorageKey};
use kult_protocol::{CapabilityControl, Envelope};

mod backup;
mod commit;
mod devices;
mod ephemeral;
mod local_metadata;
mod maintenance;
mod media;
mod migration;
mod note;
#[cfg(test)]
mod opaque_tests;
#[cfg(test)]
mod scale_bench;
mod scheduled;
mod store_v2;

pub use backup::BACKUP_MAGIC;
#[cfg(feature = "test-failpoints")]
pub use commit::{CommitFailpoint, CommitFailure};
pub use commit::{
    CommitPlan, CommitReceipt, CommittedRecordIds, ContactDeviceDelete, DeferredControlKind,
    DeferredControlRecord, DeliveryTransition, EphemeralTransition, GroupMessageDelete,
    GroupMessageTransition, GroupTransition, HandshakeReceivePlan, MaintenancePlan, MediaDelete,
    MessageDelete, MessageTransition, PairwiseReceivePlan, PairwiseSendPlan, PendingDelete,
    PrekeyTransition, QueueDelete, QueueTransition, ReceiptReceivePlan, SessionTransition,
    MAX_COMMIT_MUTATIONS, MAX_COMMIT_QUEUE_ROWS, MAX_DEFERRED_CONTROLS,
    MAX_MAINTENANCE_TRANSITIONS, MAX_PAIRWISE_COMMIT_DEVICES,
};
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
pub use maintenance::{
    StorageMaintenanceOptions, StorageMaintenanceReport, MAX_MAINTENANCE_VACUUM_PAGES,
    MAX_MAINTENANCE_WAL_BYTES,
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
    /// An opaque history cursor is malformed, forged, stale, or belongs to
    /// another database or conversation.
    InvalidCursor,
    /// The legacy database does not match a released schema fixture.
    UnsupportedLegacySchema,
    /// A migration or restore does not have enough same-filesystem workspace.
    InsufficientMigrationSpace,
    /// A sibling migration checkpoint no longer matches its source database.
    MigrationSourceChanged,
    /// Atomic replacement recovery found an ambiguous set of sibling files.
    ReplacementRecovery,
    /// A bounded migration count or referential check failed.
    MigrationValidation,
    /// A requested maintenance bound exceeds the supported per-call limit.
    MaintenanceBounds,
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
            Self::InvalidCursor => f.write_str("invalid or stale opaque history cursor"),
            Self::UnsupportedLegacySchema => {
                f.write_str("legacy store schema is not a released Komms schema")
            }
            Self::InsufficientMigrationSpace => {
                f.write_str("insufficient temporary space for store replacement")
            }
            Self::MigrationSourceChanged => {
                f.write_str("migration source changed after its checkpoint")
            }
            Self::ReplacementRecovery => {
                f.write_str("store replacement requires explicit recovery")
            }
            Self::MigrationValidation => f.write_str("store migration validation failed"),
            Self::MaintenanceBounds => f.write_str("store maintenance bound exceeded"),
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

fn decode_exact<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let (value, remainder) =
        postcard::take_from_bytes(bytes).map_err(|_| StoreError::Serialization)?;
    if !remainder.is_empty() {
        return Err(StoreError::Serialization);
    }
    Ok(value)
}

fn direction_code(direction: Direction) -> u8 {
    match direction {
        Direction::Outbound => 0,
        Direction::Inbound => 1,
    }
}

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

/// Stable opaque continuation token for one database and conversation.
///
/// The bytes reveal neither a logical identifier nor a usable SQLite row
/// number and fail closed if replayed against another store or conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryCursor(Vec<u8>);

impl HistoryCursor {
    /// Reconstruct a cursor received through an RPC or FFI boundary.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Opaque bytes suitable for persistence by a caller.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One bounded page of pairwise message history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagePage {
    /// Records in stable insertion order.
    pub records: Vec<MessageRecord>,
    /// Continuation after the final returned row, when more rows may exist.
    pub next: Option<HistoryCursor>,
}

/// One bounded page of group message history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessagePage {
    /// Records in stable insertion order.
    pub records: Vec<GroupMessageRecord>,
    /// Continuation after the final returned row, when more rows may exist.
    pub next: Option<HistoryCursor>,
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
#[cfg(test)]
pub(crate) const LEGACY_SCHEMA_CURRENT: &str = "
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
fn is_lock_contention(error: &std::io::Error) -> bool {
    let expected = fs2::lock_contended_error();
    error.kind() == std::io::ErrorKind::WouldBlock
        || (expected.raw_os_error().is_some() && error.raw_os_error() == expected.raw_os_error())
}

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
        Err(error) if is_lock_contention(&error) => {
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
            Err(error) if is_lock_contention(&error) => Err(StoreError::AlreadyOpen),
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
    metadata: store_v2::DatabaseMetadata,
    metadata_key: StorageKey,
    index_root: StorageKey,
    row_root: StorageKey,
    cursor_root: StorageKey,
    path: PathBuf,
    kdf_profile: KdfProfile,
    k_media: StorageKey,
    media_dir: PathBuf,
    media_limits: MediaLimits,
    #[cfg(feature = "test-failpoints")]
    commit_failpoint: RefCell<Option<commit::ArmedCommitFailpoint>>,
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
        if path.exists() {
            return Err(StoreError::NotAStore);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;

        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let kek = derive_kek(passphrase, &salt, profile)?;
        let kek_key = StorageKey::from_bytes(*kek);

        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(sk_bytes.as_mut());
        let wrapped = kek_key.seal(WRAP_AD, sk_bytes.as_ref(), rng);
        let master = StorageKey::from_bytes(*sk_bytes);
        let metadata = store_v2::DatabaseMetadata::fresh(store_v2::random_database_id(rng)?);
        let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)?;
        store_v2::create_schema(&tx)?;
        store_v2::write_bootstrap(&tx, &salt, profile, &wrapped)?;
        store_v2::write_metadata(&tx, &master, &metadata, rng)?;
        tx.commit()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        store_v2::configure_connection(&conn)?;
        store_v2::protect_sqlite_files(path)?;

        Self::with_master(conn, database_lock, lock, master, metadata, profile, path)
    }

    /// Open and unlock an existing store.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        migration::recover_missing_source(path)?;
        if !path.is_file() {
            return Err(StoreError::NotAStore);
        }
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        if !store_v2::is_v2(&conn)? {
            drop(conn);
            return migration::migrate_legacy(path, passphrase, lock, database_lock);
        }
        let store = Self::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)?;
        migration::cleanup_completed_replacement(path)?;
        backup::cleanup_completed_restore(path)?;
        Ok(store)
    }

    fn open_v2_with_parts(
        path: &Path,
        passphrase: &[u8],
        conn: Connection,
        database_lock: Option<File>,
        lock: File,
        allow_incomplete: bool,
    ) -> Result<Self> {
        store_v2::validate_physical_schema(&conn)?;
        store_v2::configure_connection(&conn)?;
        let (salt, profile, wrapped) = store_v2::read_bootstrap(&conn)?;
        let kek = derive_kek(passphrase, &salt, profile)?;
        let kek_key = StorageKey::from_bytes(*kek);
        let sk_vec = Zeroizing::new(kek_key.open(WRAP_AD, &wrapped)?); // wrong passphrase fails here
        let sk_bytes: [u8; 32] = sk_vec[..].try_into().map_err(|_| StoreError::NotAStore)?;
        let master = StorageKey::from_bytes(sk_bytes);
        let metadata = store_v2::read_metadata(&conn, &master, allow_incomplete)?;
        let store = Self::with_master(conn, database_lock, lock, master, metadata, profile, path)?;
        store.validate_open_state()?;
        store.conn.pragma_update(None, "journal_mode", "WAL")?;
        store_v2::protect_sqlite_files(path)?;
        Ok(store)
    }

    fn open_incomplete(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let lock = acquire_store_lock(path)?;
        let conn = Connection::open(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        Self::open_v2_with_parts(path, passphrase, conn, database_lock, lock, true)
    }

    fn with_master(
        conn: Connection,
        database_lock: Option<File>,
        lock: File,
        master: StorageKey,
        metadata: store_v2::DatabaseMetadata,
        profile: KdfProfile,
        path: &Path,
    ) -> Result<Self> {
        let media_dir = media::prepare_media_directory(path)?;
        let keys = store_v2::derive_store_keys(&master);
        let metadata_key = master.derive(b"KK-store-v2-metadata");
        Ok(Self {
            metadata,
            metadata_key,
            index_root: keys.index_root,
            row_root: keys.row_root,
            cursor_root: keys.cursor_root,
            path: path.to_path_buf(),
            kdf_profile: profile,
            k_media: keys.media,
            media_dir,
            media_limits: MediaLimits::default(),
            #[cfg(feature = "test-failpoints")]
            commit_failpoint: RefCell::new(None),
            conn,
            _database_lock: database_lock,
            _lock: lock,
        })
    }

    fn validate_open_state(&self) -> Result<()> {
        store_v2::validate_physical_schema(&self.conn)?;
        self.validate_all_opaque_rows()?;
        migration::validate_checkpoint_state(self)?;
        self.validate_core_logical_rows()?;
        self.validate_media_logical_rows()?;
        self.validate_local_metadata_logical_rows()?;
        self.validate_note_logical_rows()?;
        self.validate_scheduled_logical_rows()?;
        self.validate_ephemeral_logical_rows()?;
        self.validate_device_logical_rows()?;
        self.validate_presentation_marker()?;
        self.validate_deferred_controls()
    }

    fn validate_core_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::IdentityRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let bytes: [u8; 64] = row.payload[..]
                .try_into()
                .map_err(|_| StoreError::Serialization)?;
            let _ = Identity::from_bytes(&bytes);
            Ok(())
        })?;
        self.validate_rows::<store_v2::SessionRows, _>(|row| {
            let _ = store_v2::AccountKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let _: Session = decode_exact(&row.payload)?;
            Ok(())
        })?;
        self.validate_rows::<store_v2::CapabilityRows, _>(|row| {
            let _ = store_v2::AccountKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let _ = CapabilityControl::decode(&row.payload)?;
            Ok(())
        })?;
        self.validate_rows::<store_v2::MessageRows, _>(|row| {
            let record = self.decode_message_row_ref(row, None)?;
            row.verify_indexes(&store_v2::IndexKeys::message(
                &store_v2::ContentKey::new(record.id),
                &store_v2::AccountKey::new(record.peer),
            ))
        })?;
        self.validate_rows::<store_v2::QueueRows, _>(|row| {
            let item = Self::decode_queue_item(&row.payload)?;
            row.verify_indexes(&Self::queue_indexes(&item))
        })?;
        self.validate_rows::<store_v2::SeenRows, _>(|row| {
            let key = store_v2::ContentKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            if row.payload.as_slice() != key.value() {
                return Err(StoreError::LogicalKeyMismatch);
            }
            Ok(())
        })?;
        self.validate_rows::<store_v2::ReceiptReplayRows, _>(|row| {
            let _ = store_v2::ContentKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let _: ([u8; 32], u64) = decode_exact(&row.payload)?;
            Ok(())
        })?;
        self.validate_rows::<store_v2::ContactRows, _>(|row| {
            let record: ContactRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::AccountKey::new(record.peer))?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })?;
        self.validate_rows::<store_v2::PrekeyRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })?;
        self.validate_rows::<store_v2::PendingRows, _>(|row| {
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let (encoded, _): (Vec<u8>, u64) = decode_exact(&row.payload)?;
            let _ = Envelope::decode(&encoded)?;
            Ok(())
        })?;
        self.validate_rows::<store_v2::ResetRows, _>(|row| {
            let key = store_v2::AccountKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            if row.payload.as_slice() != key.value() {
                return Err(StoreError::LogicalKeyMismatch);
            }
            Ok(())
        })?;
        self.validate_rows::<store_v2::GroupRows, _>(|row| {
            let record: GroupRecord = decode_exact(&row.payload)?;
            let key = store_v2::GroupKey::decode(&row.logical_key)?;
            if key.value() != &record.id {
                return Err(StoreError::LogicalKeyMismatch);
            }
            row.verify_indexes(&store_v2::IndexKeys::none())
        })?;
        self.validate_rows::<store_v2::GroupAuthorityRows, _>(|row| {
            let record: GroupAuthorityRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::GroupKey::new(record.group))?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })?;
        self.validate_rows::<store_v2::GroupChainRows, _>(|row| {
            let key = store_v2::GroupMemberKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::group_chain(&store_v2::GroupKey::new(
                *key.group(),
            )))
        })?;
        self.validate_rows::<store_v2::GroupMessageRows, _>(|row| {
            let record = self.decode_group_message_row(row)?;
            row.verify_indexes(&store_v2::IndexKeys::group_message(
                &store_v2::ContentKey::new(record.id),
                &store_v2::GroupKey::new(record.group),
            ))
        })
    }

    // ---- identity ---------------------------------------------------------

    /// Persist the device identity (sealed).
    pub fn put_identity(&self, id: &Identity, rng: &mut impl CryptoRngCore) -> Result<()> {
        self.put_equality::<store_v2::IdentityRows>(
            &store_v2::SingletonKey,
            id.to_bytes().as_ref(),
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load the device identity, if one was stored.
    pub fn get_identity(&self) -> Result<Option<Identity>> {
        let Some(row) = self.get_equality::<store_v2::IdentityRows>(&store_v2::SingletonKey)?
        else {
            return Ok(None);
        };
        let bytes: [u8; 64] = row.payload[..]
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
        let payload =
            Zeroizing::new(postcard::to_allocvec(session).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::SessionRows>(
            &store_v2::AccountKey::new(*peer),
            &payload,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load the session for a peer.
    pub fn get_session(&self, peer: &[u8; 32]) -> Result<Option<Session>> {
        self.get_equality::<store_v2::SessionRows>(&store_v2::AccountKey::new(*peer))?
            .map(|row| decode_exact(&row.payload))
            .transpose()
    }

    /// Delete one exact physical-endpoint ratchet session.
    pub fn delete_session(&self, peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::SessionRows>(&store_v2::AccountKey::new(*peer))?;
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
        self.put_equality::<store_v2::CapabilityRows>(
            &store_v2::AccountKey::new(*peer),
            &capabilities.encode()?,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load the authenticated content-capability snapshot for a peer's
    /// current ratchet session.
    pub fn get_capabilities(&self, peer: &[u8; 32]) -> Result<Option<CapabilityControl>> {
        self.get_equality::<store_v2::CapabilityRows>(&store_v2::AccountKey::new(*peer))?
            .map(|row| CapabilityControl::decode(&row.payload).map_err(StoreError::from))
            .transpose()
    }

    /// Clear a peer capability snapshot when its ratchet session is reset or
    /// replaced. Capability state is re-creatable and never backed up.
    pub fn delete_capabilities(&self, peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::CapabilityRows>(&store_v2::AccountKey::new(*peer))?;
        Ok(())
    }

    // ---- messages ---------------------------------------------------------

    /// Append a message record (sealed).
    pub fn put_message(&self, rec: &MessageRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        let key = store_v2::MessageKey::new(rec.peer, direction_code(rec.direction), rec.id);
        let indexes = store_v2::IndexKeys::message(
            &store_v2::ContentKey::new(rec.id),
            &store_v2::AccountKey::new(rec.peer),
        );
        self.append::<store_v2::MessageRows>(&key, &plain, indexes, rng)?;
        Ok(())
    }

    /// All messages for a peer, in insertion order.
    pub fn messages_with(&self, peer: &[u8; 32]) -> Result<Vec<MessageRecord>> {
        let rows = self.rows_by_index::<store_v2::MessageConversationIndex>(
            &store_v2::AccountKey::new(*peer),
        )?;
        rows.into_iter()
            .map(|row| self.decode_message_row(row, Some(peer)))
            .collect()
    }

    /// Return one bounded pairwise history page without scanning another
    /// conversation or decrypting rows beyond the requested page.
    pub fn messages_page(
        &self,
        peer: &[u8; 32],
        after: Option<&HistoryCursor>,
        limit: usize,
    ) -> Result<MessagePage> {
        if limit == 0 || limit > store_v2::MAX_PAGE_SIZE {
            return Err(StoreError::RecordBounds);
        }
        let conversation = store_v2::AccountKey::new(*peer);
        let after_rowid = after
            .map(|cursor| {
                self.decode_cursor::<store_v2::MessageConversationIndex>(
                    &conversation,
                    cursor.as_bytes(),
                )
            })
            .transpose()?;
        let rows = self.rows_by_index_after::<store_v2::MessageConversationIndex>(
            &conversation,
            after_rowid,
            limit + 1,
        )?;
        let has_more = rows.len() > limit;
        let selected = rows.into_iter().take(limit).collect::<Vec<_>>();
        let next = if has_more {
            selected.last().map(|row| {
                HistoryCursor(
                    self.encode_cursor::<store_v2::MessageConversationIndex>(&conversation, row),
                )
            })
        } else {
            None
        };
        let records = selected
            .into_iter()
            .map(|row| self.decode_message_row(row, Some(peer)))
            .collect::<Result<Vec<_>>>()?;
        Ok(MessagePage { records, next })
    }

    fn decode_message_row(
        &self,
        row: store_v2::RawRow,
        expected_peer: Option<&[u8; 32]>,
    ) -> Result<MessageRecord> {
        self.decode_message_row_ref(&row, expected_peer)
    }

    fn decode_message_row_ref(
        &self,
        row: &store_v2::RawRow,
        expected_peer: Option<&[u8; 32]>,
    ) -> Result<MessageRecord> {
        let record: MessageRecord = decode_exact(&row.payload)?;
        if expected_peer.is_some_and(|peer| peer != &record.peer) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        row.verify_key(&store_v2::MessageKey::new(
            record.peer,
            direction_code(record.direction),
            record.id,
        ))?;
        Ok(record)
    }

    /// Replace the stored record with the same `id` as `rec`. Returns `true`
    /// if a record was found and updated.
    pub fn update_message(
        &self,
        rec: &MessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let id = store_v2::ContentKey::new(rec.id);
        let Some(row) = self.row_by_unique::<store_v2::MessageIdIndex>(&id)? else {
            return Ok(false);
        };
        let stored = self.decode_message_row_ref(&row, None)?;
        if stored.peer != rec.peer || stored.direction != rec.direction {
            return Err(StoreError::InvalidTransition);
        }
        let key = store_v2::MessageKey::new(rec.peer, direction_code(rec.direction), rec.id);
        let indexes = store_v2::IndexKeys::message(&id, &store_v2::AccountKey::new(rec.peer));
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        self.update_row::<store_v2::MessageRows>(&row.locator, &key, &plain, indexes, rng)
    }

    /// Delete one exact pairwise history row after an expiry tombstone is durable.
    pub fn delete_message_record(
        &self,
        peer: &[u8; 32],
        direction: Direction,
        id: &[u8; 16],
    ) -> Result<bool> {
        let Some(row) =
            self.row_by_unique::<store_v2::MessageIdIndex>(&store_v2::ContentKey::new(*id))?
        else {
            return Ok(false);
        };
        let record = self.decode_message_row_ref(&row, Some(peer))?;
        if record.direction != direction || &record.id != id {
            return Ok(false);
        }
        self.delete_row::<store_v2::MessageRows>(&row.locator)
    }

    // ---- contacts ----------------------------------------------------------

    /// Insert or replace a contact (sealed).
    pub fn put_contact(&self, rec: &ContactRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain = postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?;
        self.put_equality::<store_v2::ContactRows>(
            &store_v2::AccountKey::new(rec.peer),
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load one contact.
    pub fn get_contact(&self, peer: &[u8; 32]) -> Result<Option<ContactRecord>> {
        self.get_equality::<store_v2::ContactRows>(&store_v2::AccountKey::new(*peer))?
            .map(|row| {
                let record: ContactRecord = decode_exact(&row.payload)?;
                if record.peer != *peer {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(record)
            })
            .transpose()
    }

    /// All contacts.
    pub fn contacts(&self) -> Result<Vec<ContactRecord>> {
        self.rows::<store_v2::ContactRows>()?
            .into_iter()
            .map(|row| {
                let record: ContactRecord = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::AccountKey::new(record.peer))?;
                Ok(record)
            })
            .collect()
    }

    /// Delete one exact sealed contact. Missing peers are an honest no-op.
    pub fn delete_contact(&self, peer: &[u8; 32]) -> Result<bool> {
        self.delete_equality::<store_v2::ContactRows>(&store_v2::AccountKey::new(*peer))
    }

    // ---- own prekey secrets -------------------------------------------------

    /// Persist this device's prekey secrets as one opaque sealed blob (the
    /// runtime owns the serialization; the store interprets nothing).
    pub fn put_prekeys(&self, blob: &[u8], rng: &mut impl CryptoRngCore) -> Result<()> {
        self.put_equality::<store_v2::PrekeyRows>(
            &store_v2::SingletonKey,
            blob,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load this device's prekey secrets blob, if stored.
    pub fn get_prekeys(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .get_equality::<store_v2::PrekeyRows>(&store_v2::SingletonKey)?
            .map(|row| row.payload))
    }

    // ---- outbound queue ---------------------------------------------------

    /// Enqueue an envelope for delivery (sealed at rest; survives restarts).
    pub fn queue_push(&self, item: &QueueItem, rng: &mut impl CryptoRngCore) -> Result<i64> {
        let payload = Self::encode_queue_item(item)?;
        let row =
            self.append_opaque::<store_v2::QueueRows>(&payload, Self::queue_indexes(item), rng)?;
        Ok(row.rowid)
    }

    /// All queued items with their sequence numbers.
    pub fn queue_all(&self) -> Result<Vec<(i64, QueueItem)>> {
        self.rows::<store_v2::QueueRows>()?
            .into_iter()
            .map(|row| Ok((row.rowid, Self::decode_queue_item(&row.payload)?)))
            .collect()
    }

    /// Remove a delivered/acked envelope from the queue.
    pub fn queue_ack(&self, seq: i64) -> Result<()> {
        self.delete_rowid::<store_v2::QueueRows>(seq)?;
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
        let Some(row) = self.row_by_rowid::<store_v2::QueueRows>(seq)? else {
            return Ok(());
        };
        let locator: [u8; 16] = row
            .locator
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::SchemaMismatch)?;
        self.update_row::<store_v2::QueueRows>(
            &row.locator,
            &store_v2::OpaqueRowKey::from_locator(locator),
            &Self::encode_queue_item(item)?,
            Self::queue_indexes(item),
            rng,
        )?;
        Ok(())
    }

    /// Remove every queued envelope addressed to one revoked physical endpoint.
    pub fn queue_remove_peer(&self, peer: &[u8; 32]) -> Result<usize> {
        let rows =
            self.rows_by_index::<store_v2::QueuePeerIndex>(&store_v2::AccountKey::new(*peer))?;
        for row in &rows {
            self.delete_row::<store_v2::QueueRows>(&row.locator)?;
        }
        Ok(rows.len())
    }

    /// Retarget durable queue ownership after a legacy endpoint is bound to
    /// its certified physical id. Envelope bytes remain end-to-end identical.
    pub fn queue_retarget_peer(
        &self,
        old_peer: &[u8; 32],
        new_peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize> {
        let rows =
            self.rows_by_index::<store_v2::QueuePeerIndex>(&store_v2::AccountKey::new(*old_peer))?;
        for row in &rows {
            let mut item = Self::decode_queue_item(&row.payload)?;
            if item.peer != *old_peer {
                return Err(StoreError::LogicalKeyMismatch);
            }
            item.peer = *new_peer;
            let locator: [u8; 16] = row
                .locator
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::SchemaMismatch)?;
            self.update_row::<store_v2::QueueRows>(
                &row.locator,
                &store_v2::OpaqueRowKey::from_locator(locator),
                &Self::encode_queue_item(&item)?,
                Self::queue_indexes(&item),
                rng,
            )?;
        }
        Ok(rows.len())
    }

    /// Remove every queued envelope associated with one expired pairwise message.
    pub fn queue_remove_message(&self, id: &[u8; 16]) -> Result<usize> {
        let rows =
            self.rows_by_index::<store_v2::QueueMessageIndex>(&store_v2::ContentKey::new(*id))?;
        for row in &rows {
            self.delete_row::<store_v2::QueueRows>(&row.locator)?;
        }
        Ok(rows.len())
    }

    /// Remove every queued member copy associated with one expired group message.
    pub fn queue_remove_group_message(&self, id: &[u8; 16]) -> Result<usize> {
        let rows = self
            .rows_by_index::<store_v2::QueueGroupMessageIndex>(&store_v2::ContentKey::new(*id))?;
        for row in &rows {
            self.delete_row::<store_v2::QueueRows>(&row.locator)?;
        }
        Ok(rows.len())
    }

    /// Remove queued copies of one exact sealed envelope after its encrypted
    /// end-to-end receipt returns. Matching the content id keeps other linked
    /// devices' copies of the same logical message independently retryable.
    pub fn queue_remove_envelope(&self, content_id: &[u8; 16]) -> Result<usize> {
        let rows = self.rows_by_index::<store_v2::QueueEnvelopeIndex>(
            &store_v2::ContentKey::new(*content_id),
        )?;
        for row in &rows {
            self.delete_row::<store_v2::QueueRows>(&row.locator)?;
        }
        Ok(rows.len())
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
        if plain.len() > MAX_PENDING_BYTES {
            return Err(StoreError::PendingQuota);
        }

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let count = usize::try_from(self.count_rows_on::<store_v2::PendingRows>(&tx)?)
            .map_err(|_| StoreError::Serialization)?;
        if count >= MAX_PENDING_ENVELOPES {
            tx.rollback()?;
            return Err(StoreError::PendingQuota);
        }
        let row = self.append_on::<store_v2::PendingRows>(
            &tx,
            None,
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        if self.sealed_bytes_on::<store_v2::PendingRows>(&tx)? > MAX_PENDING_BYTES as u64 {
            tx.rollback()?;
            return Err(StoreError::PendingQuota);
        }
        let sequence = row.rowid;
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
        self.rows::<store_v2::PendingRows>()?
            .into_iter()
            .map(|row| {
                let (env_bytes, first_seen): (Vec<u8>, u64) = decode_exact(&row.payload)?;
                Ok((row.rowid, Envelope::decode(&env_bytes)?, first_seen))
            })
            .collect()
    }

    /// Acknowledge one consumed or expired inbound envelope.
    ///
    /// The stable sequence makes acknowledgement row-scoped: retryable and
    /// not-yet-visited rows remain durable if processing returns an error or
    /// the process stops between envelopes.
    pub fn pending_ack(&self, sequence: i64) -> Result<()> {
        self.delete_rowid::<store_v2::PendingRows>(sequence)?;
        Ok(())
    }

    fn encode_queue_item(item: &QueueItem) -> Result<Vec<u8>> {
        let row = QueueRowV2 {
            peer: item.peer,
            msg_id: item.msg_id,
            group_msg_id: item.group_msg_id,
            class: item.class,
            created_at: item.created_at,
            attempts: item.attempts,
            next_attempt_at: item.next_attempt_at,
            envelope: item.envelope.try_encode()?,
        };
        let encoded = postcard::to_allocvec(&row).map_err(|_| StoreError::Serialization)?;
        let mut plain = Vec::with_capacity(QUEUE_ROW_MAGIC_V2.len() + encoded.len());
        plain.extend_from_slice(QUEUE_ROW_MAGIC_V2);
        plain.extend_from_slice(&encoded);
        Ok(plain)
    }

    fn decode_queue_item(plain: &[u8]) -> Result<QueueItem> {
        let (peer, msg_id, group_msg_id, class, created_at, attempts, next_attempt_at, envelope) =
            if let Some(encoded) = plain.strip_prefix(QUEUE_ROW_MAGIC_V2) {
                let row: QueueRowV2 = decode_exact(encoded)?;
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
                let row: QueueRowV1 = decode_exact(encoded)?;
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
                let legacy: LegacyQueueRow = decode_exact(plain)?;
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
        Ok(QueueItem {
            peer,
            msg_id,
            group_msg_id,
            class,
            created_at,
            attempts,
            next_attempt_at,
            envelope: Envelope::decode(&envelope)?,
        })
    }

    fn queue_indexes(item: &QueueItem) -> store_v2::IndexKeys {
        let message = item.msg_id.map(store_v2::ContentKey::new);
        let group_message = item.group_msg_id.map(store_v2::ContentKey::new);
        store_v2::IndexKeys::queue(
            &store_v2::AccountKey::new(item.peer),
            message.as_ref(),
            group_message.as_ref(),
            &store_v2::ContentKey::new(item.envelope.content_id()),
        )
    }

    // ---- groups (ADR-0012) --------------------------------------------------

    /// Insert or replace a group (sealed).
    pub fn put_group(&self, rec: &GroupRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let plain =
            Zeroizing::new(postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::GroupRows>(
            &store_v2::GroupKey::new(rec.id),
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// Load one group.
    pub fn get_group(&self, id: &[u8; 32]) -> Result<Option<GroupRecord>> {
        let key = store_v2::GroupKey::new(*id);
        let Some(row) = self.get_equality::<store_v2::GroupRows>(&key)? else {
            return Ok(None);
        };
        row.verify_key(&key)?;
        let record: GroupRecord = decode_exact(&row.payload)?;
        if record.id != *id {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Some(record))
    }

    /// All groups.
    pub fn groups(&self) -> Result<Vec<GroupRecord>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::GroupRows>()? {
            let record: GroupRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::GroupKey::new(record.id))?;
            out.push(record);
        }
        Ok(out)
    }

    /// Remove a group and every receiving chain under it (leaving keeps the
    /// message history — that is this device's data).
    pub fn delete_group(&self, id: &[u8; 32]) -> Result<()> {
        let group = store_v2::GroupKey::new(*id);
        let chains = self.rows_by_index::<store_v2::GroupChainGroupIndex>(&group)?;
        let tx = self.conn.unchecked_transaction()?;
        self.delete_equality_on::<store_v2::GroupRows>(&tx, &group)?;
        self.delete_equality_on::<store_v2::GroupAuthorityRows>(&tx, &group)?;
        for chain in chains {
            self.delete_rowid_on::<store_v2::GroupChainRows>(&tx, chain.rowid)?;
        }
        tx.commit()?;
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
        self.put_equality::<store_v2::GroupAuthorityRows>(
            &store_v2::GroupKey::new(rec.group),
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// Load one group's sealed signed authority state.
    pub fn get_group_authority(&self, group: &[u8; 32]) -> Result<Option<GroupAuthorityRecord>> {
        let key = store_v2::GroupKey::new(*group);
        let Some(row) = self.get_equality::<store_v2::GroupAuthorityRows>(&key)? else {
            return Ok(None);
        };
        row.verify_key(&key)?;
        let record: GroupAuthorityRecord = decode_exact(&row.payload)?;
        if record.group != *group {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Some(record))
    }

    /// All sealed C6 authority records for backup and audit.
    pub fn group_authorities(&self) -> Result<Vec<GroupAuthorityRecord>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::GroupAuthorityRows>()? {
            let record: GroupAuthorityRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::GroupKey::new(record.group))?;
            out.push(record);
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
        let key = store_v2::GroupMemberKey::new(*group, *peer);
        self.put_equality::<store_v2::GroupChainRows>(
            &key,
            blob,
            store_v2::IndexKeys::group_chain(&store_v2::GroupKey::new(*group)),
            rng,
        )?;
        Ok(())
    }

    /// Load one member's receiving chain blob for a group.
    pub fn get_group_chain(
        &self,
        group: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let key = store_v2::GroupMemberKey::new(*group, *peer);
        let Some(row) = self.get_equality::<store_v2::GroupChainRows>(&key)? else {
            return Ok(None);
        };
        row.verify_key(&key)?;
        Ok(Some(row.payload))
    }

    /// All receiving chains for a group, as `(peer, blob)`.
    pub fn group_chains(&self, group: &[u8; 32]) -> Result<Vec<GroupChainRow>> {
        let group_key = store_v2::GroupKey::new(*group);
        let mut out = Vec::new();
        for row in self.rows_by_index::<store_v2::GroupChainGroupIndex>(&group_key)? {
            let key = store_v2::GroupMemberKey::decode(&row.logical_key)?;
            if key.group() != group {
                return Err(StoreError::LogicalKeyMismatch);
            }
            out.push((*key.peer(), row.payload));
        }
        Ok(out)
    }

    /// Drop one member's receiving chain (they were removed or rotated to a
    /// new chain that replaces this one).
    pub fn delete_group_chain(&self, group: &[u8; 32], peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::GroupChainRows>(&store_v2::GroupMemberKey::new(
            *group, *peer,
        ))?;
        Ok(())
    }

    /// Append a group message record (sealed).
    pub fn put_group_message(
        &self,
        rec: &GroupMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let plain =
            Zeroizing::new(postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?);
        let id = store_v2::ContentKey::new(rec.id);
        let group = store_v2::GroupKey::new(rec.group);
        self.append::<store_v2::GroupMessageRows>(
            &store_v2::GroupMessageKey::new(
                rec.group,
                rec.sender,
                direction_code(rec.direction),
                rec.id,
            ),
            &plain,
            store_v2::IndexKeys::group_message(&id, &group),
            rng,
        )?;
        Ok(())
    }

    /// Replace the stored group message with the same `id` as `rec`.
    /// Returns `true` if a record was found and updated.
    pub fn update_group_message(
        &self,
        rec: &GroupMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let id = store_v2::ContentKey::new(rec.id);
        let Some(row) = self.row_by_unique::<store_v2::GroupMessageIdIndex>(&id)? else {
            return Ok(false);
        };
        let expected = store_v2::GroupMessageKey::new(
            rec.group,
            rec.sender,
            direction_code(rec.direction),
            rec.id,
        );
        row.verify_key(&expected)?;
        let plain =
            Zeroizing::new(postcard::to_allocvec(rec).map_err(|_| StoreError::Serialization)?);
        self.update_row::<store_v2::GroupMessageRows>(
            &row.locator,
            &expected,
            &plain,
            store_v2::IndexKeys::group_message(&id, &store_v2::GroupKey::new(rec.group)),
            rng,
        )
    }

    /// Delete one exact group history row after an expiry tombstone is durable.
    pub fn delete_group_message_record(
        &self,
        group: &[u8; 32],
        sender: &[u8; 32],
        id: &[u8; 16],
    ) -> Result<bool> {
        let id_key = store_v2::ContentKey::new(*id);
        let Some(row) = self.row_by_unique::<store_v2::GroupMessageIdIndex>(&id_key)? else {
            return Ok(false);
        };
        let record = self.decode_group_message_row(&row)?;
        if record.group != *group || record.sender != *sender || record.id != *id {
            return Err(StoreError::LogicalKeyMismatch);
        }
        self.delete_row::<store_v2::GroupMessageRows>(&row.locator)
    }

    /// All messages for a group, in insertion order.
    pub fn group_messages(&self, group: &[u8; 32]) -> Result<Vec<GroupMessageRecord>> {
        let mut out = Vec::new();
        for row in self.rows_by_index::<store_v2::GroupMessageConversationIndex>(
            &store_v2::GroupKey::new(*group),
        )? {
            out.push(self.decode_group_message_row(&row)?);
        }
        Ok(out)
    }

    /// One bounded page of group history in stable insertion order.
    pub fn group_messages_page(
        &self,
        group: &[u8; 32],
        after: Option<&HistoryCursor>,
        limit: usize,
    ) -> Result<GroupMessagePage> {
        if limit == 0 || limit > store_v2::MAX_PAGE_SIZE {
            return Err(StoreError::RecordBounds);
        }
        let group_key = store_v2::GroupKey::new(*group);
        let after_rowid = after
            .map(|cursor| {
                self.decode_cursor::<store_v2::GroupMessageConversationIndex>(
                    &group_key,
                    cursor.as_bytes(),
                )
            })
            .transpose()?;
        let rows = self.rows_by_index_after::<store_v2::GroupMessageConversationIndex>(
            &group_key,
            after_rowid,
            limit,
        )?;
        let next = rows.last().map(|row| {
            HistoryCursor(
                self.encode_cursor::<store_v2::GroupMessageConversationIndex>(&group_key, row),
            )
        });
        let records = rows
            .iter()
            .map(|row| self.decode_group_message_row(row))
            .collect::<Result<Vec<_>>>()?;
        Ok(GroupMessagePage { records, next })
    }

    /// Every stored group message across all groups, in insertion order
    /// (receipt application scans this; local history stays small).
    pub fn all_group_messages(&self) -> Result<Vec<GroupMessageRecord>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::GroupMessageRows>()? {
            out.push(self.decode_group_message_row(&row)?);
        }
        Ok(out)
    }

    fn decode_group_message_row(&self, row: &store_v2::RawRow) -> Result<GroupMessageRecord> {
        let record: GroupMessageRecord = decode_exact(&row.payload)?;
        row.verify_key(&store_v2::GroupMessageKey::new(
            record.group,
            record.sender,
            direction_code(record.direction),
            record.id,
        ))?;
        Ok(record)
    }

    // ---- dedup ------------------------------------------------------------

    /// Record an envelope content id; returns `true` if it was new
    /// (multipath duplicates return `false` and must be dropped).
    pub fn mark_seen(&self, content_id: &[u8; 16]) -> Result<bool> {
        let key = store_v2::ContentKey::new(*content_id);
        if self.get_equality::<store_v2::SeenRows>(&key)?.is_some() {
            return Ok(false);
        }
        let mut rng = rand_core::OsRng;
        self.put_equality::<store_v2::SeenRows>(
            &key,
            content_id,
            store_v2::IndexKeys::none(),
            &mut rng,
        )?;
        Ok(true)
    }

    /// Has this envelope content id been consumed before?
    pub fn is_seen(&self, content_id: &[u8; 16]) -> Result<bool> {
        let key = store_v2::ContentKey::new(*content_id);
        let Some(row) = self.get_equality::<store_v2::SeenRows>(&key)? else {
            return Ok(false);
        };
        row.verify_key(&key)?;
        if row.payload.as_slice() != content_id {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(true)
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
        self.put_equality::<store_v2::ReceiptReplayRows>(
            &store_v2::ContentKey::new(*id),
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// Return the physical sender route for a previously accepted envelope.
    pub fn receipt_replay_peer(&self, id: &[u8; 16]) -> Result<Option<[u8; 32]>> {
        let key = store_v2::ContentKey::new(*id);
        let Some(row) = self.get_equality::<store_v2::ReceiptReplayRows>(&key)? else {
            return Ok(None);
        };
        row.verify_key(&key)?;
        let (peer, _): ([u8; 32], u64) = decode_exact(&row.payload)?;
        Ok(Some(peer))
    }

    /// Return a bounded set of duplicate-receipt routes at or before a cutoff.
    pub fn expired_receipt_replay_ids(&self, cutoff: u64, limit: usize) -> Result<Vec<[u8; 16]>> {
        if limit == 0 || limit > MAX_MAINTENANCE_TRANSITIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        let mut expired = Vec::new();
        for row in self.rows::<store_v2::ReceiptReplayRows>()? {
            let (_, received_at): ([u8; 32], u64) = decode_exact(&row.payload)?;
            if received_at <= cutoff {
                expired.push(*store_v2::ContentKey::decode(&row.logical_key)?.value());
                if expired.len() == limit {
                    break;
                }
            }
        }
        Ok(expired)
    }

    /// Remove duplicate-receipt routes older than the endpoint delivery
    /// window. Seen ids remain independent and keep deduplication durable.
    pub fn sweep_receipt_replay(&self, cutoff: u64) -> Result<usize> {
        let mut expired = Vec::new();
        for row in self.rows::<store_v2::ReceiptReplayRows>()? {
            let (_, received_at): ([u8; 32], u64) = decode_exact(&row.payload)?;
            if received_at <= cutoff {
                expired.push(row.rowid);
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        for rowid in &expired {
            self.delete_rowid_on::<store_v2::ReceiptReplayRows>(&tx, *rowid)?;
        }
        tx.commit()?;
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
        let legacy_item = QueueItem {
            peer: [4; 32],
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: 0,
            attempts: 0,
            next_attempt_at: 0,
            envelope: envelope.clone(),
        };
        store
            .append_opaque::<store_v2::QueueRows>(
                &legacy,
                Store::queue_indexes(&legacy_item),
                &mut rng,
            )
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
    fn wrong_passphrase_does_not_rewrite_the_database() {
        let mut rng = StdRng::seed_from_u64(0xbad5ea);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong-pass.db");
        let store = Store::create(&path, b"right", TEST_KDF, &mut rng).unwrap();
        drop(store);
        let before = std::fs::read(&path).unwrap();

        assert!(matches!(
            Store::open(&path, b"wrong"),
            Err(StoreError::Crypto(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
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
            tx.execute(
                "INSERT INTO store_records (table_domain, locator, blob)
                 VALUES (10, randomblob(16), zeroblob(1))",
                [],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        assert!(matches!(
            store.pending_push(&envelope, 100, &mut rng),
            Err(StoreError::PendingQuota)
        ));

        store
            .conn
            .execute("DELETE FROM store_records WHERE table_domain = 10", [])
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO store_records (table_domain, locator, blob)
                 VALUES (10, randomblob(16), zeroblob(?1))",
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
        let failed_before = store.get_session(&peer_device).unwrap().unwrap();
        let mut failed_candidate = failed_before.clone();
        assert_eq!(
            unpad(
                &failed_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
        let failed_receipt =
            failed_candidate.encrypt(&mut rng, NOW + 1, &pad(b"receipt").unwrap(), &[]);
        let failed_queue = QueueItem {
            peer: peer_device,
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: NOW + 1,
            attempts: 0,
            next_attempt_at: NOW + 1,
            envelope: Envelope::new(EnvelopeKind::Receipt, [8; 32], failed_receipt.encode()),
        };

        // Fail the seen-marker statement after the candidate session,
        // message, and encrypted receipt. SQLite must roll every write back
        // and retain the exact source row.
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER fail_pairwise_receive
                 BEFORE INSERT ON store_records
                 WHEN NEW.table_domain = 6
                 BEGIN
                   SELECT RAISE(ABORT, 'injected receive failure');
                 END;",
            )
            .unwrap();
        assert!(store
            .commit_plan(
                CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                    session: SessionTransition {
                        peer_device,
                        before: Some(&failed_before),
                        after: &failed_candidate,
                    },
                    message: Some(&message),
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    capabilities: None,
                    queue: std::slice::from_ref(&failed_queue),
                    content_id,
                    received_at: NOW + 1,
                    receipt_replay: true,
                    source_pending: Some(PendingDelete {
                        sequence: pending_sequence,
                        content_id,
                    }),
                    presentation_changed: true,
                }),
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
        assert!(store.queue_all().unwrap().is_empty());

        // The original durable ratchet still decrypts the same ciphertext,
        // proving the failed candidate was not persisted.
        let wrong_source_before = store.get_session(&peer_device).unwrap().unwrap();
        let mut wrong_source_candidate = wrong_source_before.clone();
        assert_eq!(
            unpad(
                &wrong_source_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
        let wrong_source_receipt =
            wrong_source_candidate.encrypt(&mut rng, NOW + 1, &pad(b"receipt").unwrap(), &[]);
        let wrong_source_queue = QueueItem {
            peer: peer_device,
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: NOW + 1,
            attempts: 0,
            next_attempt_at: NOW + 1,
            envelope: Envelope::new(
                EnvelopeKind::Receipt,
                [8; 32],
                wrong_source_receipt.encode(),
            ),
        };
        assert!(matches!(
            store.commit_plan(
                CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                    session: SessionTransition {
                        peer_device,
                        before: Some(&wrong_source_before),
                        after: &wrong_source_candidate,
                    },
                    message: Some(&message),
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    capabilities: None,
                    queue: std::slice::from_ref(&wrong_source_queue),
                    content_id,
                    received_at: NOW + 1,
                    receipt_replay: true,
                    source_pending: Some(PendingDelete {
                        sequence: unrelated_sequence,
                        content_id,
                    }),
                    presentation_changed: true,
                }),
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
        assert!(store.queue_all().unwrap().is_empty());

        // A final retry from the still-unchanged durable session commits all
        // consequences and consumes exactly the named pending source.
        let retry_before = store.get_session(&peer_device).unwrap().unwrap();
        let mut retry_candidate = retry_before.clone();
        assert_eq!(
            unpad(
                &retry_candidate
                    .decrypt(&mut rng, NOW + 1, &decoded, &[])
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
        let retry_receipt =
            retry_candidate.encrypt(&mut rng, NOW + 1, &pad(b"receipt").unwrap(), &[]);
        let retry_queue = QueueItem {
            peer: peer_device,
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: NOW + 1,
            attempts: 0,
            next_attempt_at: NOW + 1,
            envelope: Envelope::new(EnvelopeKind::Receipt, [8; 32], retry_receipt.encode()),
        };
        store
            .commit_plan(
                CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                    session: SessionTransition {
                        peer_device,
                        before: Some(&retry_before),
                        after: &retry_candidate,
                    },
                    message: Some(&message),
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    capabilities: None,
                    queue: std::slice::from_ref(&retry_queue),
                    content_id,
                    received_at: NOW + 1,
                    receipt_replay: true,
                    source_pending: Some(PendingDelete {
                        sequence: pending_sequence,
                        content_id,
                    }),
                    presentation_changed: true,
                }),
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
        assert_eq!(store.queue_all().unwrap().len(), 1);
        let mut committed = store.get_session(&peer_device).unwrap().unwrap();
        assert!(committed.decrypt(&mut rng, NOW + 1, &decoded, &[]).is_err());
    }
}
