//! KommsKult encrypted local-first storage (docs/07-storage.md).
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

use std::path::Path;

use rand_core::CryptoRngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{derive_kek, CryptoError, Identity, KdfProfile, Session, StorageKey};
use kult_protocol::Envelope;

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
    /// The database is missing required metadata (not a KommsKult store).
    NotAStore,
    /// (De)serialization of a stored record failed.
    Serialization,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::NotAStore => f.write_str("not a KommsKult store"),
            Self::Serialization => f.write_str("record serialization failure"),
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
}

const WRAP_AD: &[u8] = b"KK-store-wrap-v1";
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta     (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (peer BLOB PRIMARY KEY, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS messages (rowid_ INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS queue    (seq INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS seen     (id BLOB PRIMARY KEY);
";

/// An open, unlocked KommsKult store.
pub struct Store {
    conn: Connection,
    k_identity: StorageKey,
    k_sessions: StorageKey,
    k_messages: StorageKey,
    k_queue: StorageKey,
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

        Ok(Self::with_master(conn, StorageKey::from_bytes(*sk_bytes)))
    }

    /// Open and unlock an existing store.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
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

        Ok(Self::with_master(conn, StorageKey::from_bytes(sk_bytes)))
    }

    fn with_master(conn: Connection, master: StorageKey) -> Self {
        Self {
            k_identity: master.derive(b"KK-store-identity"),
            k_sessions: master.derive(b"KK-store-sessions"),
            k_messages: master.derive(b"KK-store-messages"),
            k_queue: master.derive(b"KK-store-queue"),
            conn,
        }
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

    // ---- outbound queue ---------------------------------------------------

    /// Enqueue an envelope for delivery (sealed at rest; survives restarts).
    pub fn queue_push(&self, env: &Envelope, rng: &mut impl CryptoRngCore) -> Result<i64> {
        let sealed = self.k_queue.seal(b"queue", &env.encode(), rng);
        self.conn
            .execute("INSERT INTO queue (blob) VALUES (?1)", params![sealed])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// All queued envelopes with their sequence numbers.
    pub fn queue_all(&self) -> Result<Vec<(i64, Envelope)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, blob FROM queue ORDER BY seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, sealed) = row?;
            let plain = self.k_queue.open(b"queue", &sealed)?;
            out.push((seq, Envelope::decode(&plain)?));
        }
        Ok(out)
    }

    /// Remove a delivered/acked envelope from the queue.
    pub fn queue_ack(&self, seq: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM queue WHERE seq = ?1", params![seq])?;
        Ok(())
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
}
