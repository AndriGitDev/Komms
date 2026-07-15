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

use std::path::{Path, PathBuf};

use rand_core::CryptoRngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{derive_kek, CryptoError, Identity, KdfProfile, Session, StorageKey};
use kult_protocol::{CapabilityControl, Envelope};

mod backup;
mod local_metadata;
mod media;
mod note;
mod scheduled;

pub use backup::BACKUP_MAGIC;
pub use local_metadata::{
    render_label_color, valid_label_color, valid_label_name, ConversationId, ConversationMetadata,
    CustomIconRecord, CustomIconTarget, DraftRecord, FolderAssignment, FolderRecord,
    LabelAssignment, LabelFilterMode, LabelFilterResult, LabelRecord, LocalMetadataKey,
    LocalMetadataRecord, PinRecord, StaleLabelAssignment, StaleLabelReason, UiPreferenceRecord,
    LABEL_COLORS, LABEL_ID_RETRY_LIMIT, MAX_CUSTOM_ICON_BYTES, MAX_DRAFT_BYTES, MAX_LABELS,
    MAX_LABELS_PER_CONVERSATION, MAX_LABEL_ASSIGNMENTS, MAX_LOCAL_METADATA_STRING_BYTES,
    MAX_UI_PREFERENCE_VALUE_BYTES,
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
    /// Filesystem operation for the private media store failed.
    Io(std::io::Error),
    /// Configured or protocol-hard media quota would be exceeded.
    MediaQuota,
    /// Committing a media chunk would violate the free-space reserve.
    LowStorage,
    /// Media state or a chunk transition is inconsistent.
    MediaState,
    /// A local metadata record exceeds its documented resource bound.
    LocalMetadataBounds,
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
    /// A note-to-self text record is empty or exceeds its documented bound.
    NoteBounds,
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
            Self::Io(e) => write!(f, "media filesystem error: {e}"),
            Self::MediaQuota => f.write_str("media quota exceeded"),
            Self::LowStorage => f.write_str("insufficient reserved filesystem space"),
            Self::MediaState => f.write_str("invalid media transfer state"),
            Self::LocalMetadataBounds => f.write_str("local metadata bounds exceeded"),
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
            Self::NoteBounds => f.write_str("note-to-self text bounds exceeded"),
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

/// Per-member delivery state of one outbound group message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDelivery {
    /// The member this copy addresses.
    pub peer: [u8; 32],
    /// Content id of their envelope copy (set once it could be created —
    /// creating it needs the pairwise session for the delivery token).
    pub wire_id: Option<[u8; 16]>,
    /// `Queued` → `Sent` → `Delivered`, per member, honestly.
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
/// One member's receiving-chain row: `(peer, opaque chain blob)`.
type GroupChainRow = ([u8; 32], Zeroizing<Vec<u8>>);

const WRAP_AD: &[u8] = b"KK-store-wrap-v1";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta     (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS capabilities (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS messages (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS queue    (seq INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS seen     (id BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS contacts (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS prekeys  (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS pending  (seq INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS resets   (peer BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS groups       (gid BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS group_chains (gid BLOB NOT NULL, peer BLOB NOT NULL, blob BLOB NOT NULL, PRIMARY KEY (gid, peer));
CREATE TABLE IF NOT EXISTS group_msgs   (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media_transfers (id BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media_objects   (id BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS local_metadata  (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS note_messages   (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS scheduled_messages (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
";

/// An open, unlocked Komms store.
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
    media_dir: PathBuf,
    media_limits: MediaLimits,
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
        let conn = Connection::open(path)?;
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

        Self::with_master(conn, StorageKey::from_bytes(*sk_bytes), path)
    }

    /// Open and unlock an existing store.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
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

        Self::with_master(conn, StorageKey::from_bytes(sk_bytes), path)
    }

    fn with_master(conn: Connection, master: StorageKey, path: &Path) -> Result<Self> {
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
            media_dir,
            media_limits: MediaLimits::default(),
            conn,
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
        let mut stmt = self
            .conn
            .prepare("SELECT blob FROM messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_messages.open(b"message", &row?)?;
            let rec: MessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &rec.peer == peer {
                out.push(rec);
            }
        }
        Ok(out)
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
        let row = QueueRowV1 {
            peer: item.peer,
            msg_id: item.msg_id,
            group_msg_id: item.group_msg_id,
            class: item.class,
            envelope: item.envelope.encode(),
        };
        let encoded = postcard::to_allocvec(&row).map_err(|_| StoreError::Serialization)?;
        let mut plain = Vec::with_capacity(QUEUE_ROW_MAGIC_V1.len() + encoded.len());
        plain.extend_from_slice(QUEUE_ROW_MAGIC_V1);
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
            let (peer, msg_id, group_msg_id, class, env_bytes) =
                if let Some(encoded) = plain.strip_prefix(QUEUE_ROW_MAGIC_V1) {
                    let (row, remainder): (QueueRowV1, &[u8]) = postcard::take_from_bytes(encoded)
                        .map_err(|_| StoreError::Serialization)?;
                    if !remainder.is_empty() {
                        return Err(StoreError::Serialization);
                    }
                    (
                        row.peer,
                        row.msg_id,
                        row.group_msg_id,
                        row.class,
                        row.envelope,
                    )
                } else {
                    let (legacy, remainder): (LegacyQueueRow, &[u8]) =
                        postcard::take_from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
                    if !remainder.is_empty() {
                        return Err(StoreError::Serialization);
                    }
                    (legacy.0, legacy.1, legacy.2, QueueClass::Normal, legacy.3)
                };
            out.push((
                seq,
                QueueItem {
                    peer,
                    msg_id,
                    group_msg_id,
                    class,
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

    // ---- inbound pending (envelopes that cannot be processed yet) ---------

    /// Stash an inbound envelope that cannot be consumed yet (e.g. it arrived
    /// before the handshake that establishes its session). Survives restarts
    /// so out-of-order arrival across carriers never loses messages.
    pub fn pending_push(
        &self,
        env: &Envelope,
        first_seen: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let plain = postcard::to_allocvec(&(env.encode(), first_seen))
            .map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_pending.seal(b"pending", &plain, rng);
        self.conn
            .execute("INSERT INTO pending (blob) VALUES (?1)", params![sealed])?;
        Ok(())
    }

    /// Remove and return all stashed inbound envelopes with their
    /// first-seen timestamps (the runtime re-stashes what it still can't
    /// consume).
    pub fn pending_drain(&self) -> Result<Vec<(Envelope, u64)>> {
        let mut stmt = self.conn.prepare("SELECT blob FROM pending ORDER BY seq")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_pending.open(b"pending", &row?)?;
            let (env_bytes, first_seen): (Vec<u8>, u64) =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            out.push((Envelope::decode(&env_bytes)?, first_seen));
        }
        self.conn.execute("DELETE FROM pending", [])?;
        Ok(out)
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
        Ok(())
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
}

#[cfg(test)]
mod queue_tests {
    use super::*;
    use kult_crypto::KdfProfile;
    use kult_protocol::EnvelopeKind;
    use rand::{rngs::StdRng, SeedableRng};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn queue_v1_class_round_trips_and_legacy_rows_default_normal() {
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
        assert_eq!(rows[1].1.class, QueueClass::Normal);
        assert_eq!(rows[1].1.peer, [4; 32]);
    }
}
