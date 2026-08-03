//! Durable leased mailbox-v2 storage and wire records (ADR-0032).

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use kult_crypto::StorageKey;
use kult_protocol::{Envelope, MAX_ENVELOPE_BYTES};
use rand_core::{OsRng, RngCore};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::MailboxConfig;

const SCHEMA_VERSION: u32 = 2;
const RECORD_VERSION: u8 = 1;
const ROW_AD: &[u8] = b"Komms-Mailbox-Row-v2";
const INDEX_LABEL: &[u8] = b"Komms-Mailbox-Index-v2";
const ROW_KEY_LABEL: &[u8] = b"Komms-Mailbox-Seal-v2";
const TOKEN_INDEX_LABEL: &[u8] = b"token";
const CLIENT_INDEX_LABEL: &[u8] = b"client";
const GLOBAL_RATE_INDEX_LABEL: &[u8] = b"global-rate";
const CONTENT_INDEX_LABEL: &[u8] = b"content";
const FILTER_INDEX_LABEL: &[u8] = b"filter";
const RATE_WINDOW_SECS: u64 = 60;
const DOMAIN_REGISTRATION: u8 = 1;
const DOMAIN_DEPOSIT: u8 = 2;
const DOMAIN_LEASE: u8 = 3;
const DOMAIN_LEASE_ROW: u8 = 4;
const DOMAIN_RATE: u8 = 5;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MailboxStoreFailpoint {
    BeforeDepositCommit,
    AfterDepositCommit,
    BeforeLeaseCommit,
    AfterLeaseCommit,
    BeforeAckDelete,
    BeforeAckCommit,
    AfterAckCommit,
    BeforeSweepCommit,
    AfterSweepCommit,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InjectedFailure {
    Interrupted,
    DiskFull,
}

/// Maximum raw ciphertext bytes returned by one mailbox-v2 lease page.
pub const MAILBOX_V2_PAGE_MAX_BYTES: usize = 1024 * 1024;
/// Maximum rows returned by one mailbox-v2 lease page.
pub const MAILBOX_V2_PAGE_MAX_ROWS: usize = 128;
/// Maximum exact row ids accepted by one acknowledgement.
pub const MAILBOX_V2_ACK_MAX_ROWS: usize = MAILBOX_V2_PAGE_MAX_ROWS;
/// Maximum canonical CBOR request bytes accepted on `/komms/mailbox/2`.
pub const MAILBOX_V2_REQUEST_MAX_BYTES: usize = 320 * 1024;
/// Maximum canonical CBOR response bytes accepted on `/komms/mailbox/2`.
pub const MAILBOX_V2_RESPONSE_MAX_BYTES: usize = 3 * 1024 * 1024;

/// Persistent service paths and resource policy for one mailbox-v2 relay.
#[derive(Clone, Debug)]
pub struct MailboxServiceConfig {
    /// Dedicated relay database. It is not part of the endpoint profile or
    /// encrypted user backup.
    pub database_path: PathBuf,
    /// Dedicated 32-byte service key file. Operators back it up only with the
    /// relay database and never reuse a user, directory, or release key.
    pub key_path: PathBuf,
    /// Dedicated libp2p service identity. This keeps the published mailbox
    /// address stable across restart without using any account identity key.
    pub transport_key_path: PathBuf,
    /// Explicit bounded retention and capacity policy.
    pub limits: MailboxConfig,
    /// Whether this relay exposes destructive mailbox-v1 compatibility.
    ///
    /// Disabled by default because a v1 response can be lost after deletion.
    pub allow_v1_compat: bool,
}

impl MailboxServiceConfig {
    /// Place the dedicated database and key below `data_dir`.
    pub fn in_directory(data_dir: impl AsRef<Path>, limits: MailboxConfig) -> Self {
        let data_dir = data_dir.as_ref();
        Self {
            database_path: data_dir.join("mailbox-v2.db"),
            key_path: data_dir.join("mailbox-v2.key"),
            transport_key_path: data_dir.join("mailbox-v2.transport.key"),
            limits,
            allow_v1_compat: false,
        }
    }
}

/// One opaque relay row used only for authenticated-store validation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MailboxStoredRow {
    row_id: [u8; 16],
    ciphertext: Vec<u8>,
    expires_at: u64,
}

/// Content-free aggregate mailbox-v2 health snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MailboxMetrics {
    /// Durable deposit rows.
    pub stored_items: u64,
    /// Durable ciphertext bytes.
    pub stored_bytes: u64,
    /// Configured durable deposit-row capacity.
    pub capacity_items: u64,
    /// Configured durable ciphertext-byte capacity.
    pub capacity_bytes: u64,
    /// Configured maximum envelope retention.
    pub retention_secs: u64,
    /// Configured relay-wide fixed-window request budget.
    pub request_capacity_per_minute: u64,
    /// Configured per-client fixed-window request budget.
    pub request_capacity_per_client_per_minute: u64,
    /// Bytes currently available on the mailbox database filesystem.
    pub disk_available_bytes: Option<u64>,
    /// Live token registrations.
    pub registrations: u64,
    /// Live collection leases.
    pub live_leases: u64,
    /// Configured relay-wide live-lease capacity.
    pub lease_capacity: u64,
    /// Age in seconds of the oldest live lease, if any.
    pub oldest_lease_age_secs: Option<u64>,
    /// Deposits refused since this process opened the database.
    pub rejected_deposits: u64,
    /// Collection or acknowledgement requests refused since open.
    pub rejected_requests: u64,
    /// Rows expired since open.
    pub expired_rows: u64,
    /// Physical mailbox schema version.
    pub schema_version: u32,
}

/// One random-id row in a leased page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxV2LeasedRow {
    /// Relay-local random non-zero row identifier.
    pub row_id: [u8; 16],
    /// Exact opaque Komms envelope retained by the relay.
    pub envelope: Vec<u8>,
}

/// Wire request on `/komms/mailbox/2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxV2Request {
    /// Persist a content-blind sealed envelope.
    Deposit {
        /// Exact bounded opaque Komms envelope.
        envelope: Vec<u8>,
    },
    /// Refresh bounded token registrations and obtain one idempotent lease.
    Lease {
        /// Opaque rotating delivery tokens to register and collect.
        tokens: Vec<[u8; 32]>,
    },
    /// Delete only the named, durably staged rows from one lease.
    AckLease {
        /// Exact non-zero live lease identifier.
        lease_id: [u8; 16],
        /// Distinct exact relay row identifiers staged by the endpoint.
        row_ids: Vec<[u8; 16]>,
    },
}

/// Wire response on `/komms/mailbox/2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxV2Response {
    /// Uniform deposit result. `true` means the durable transaction committed.
    Deposit {
        /// Whether the exact deposit committed durably.
        accepted: bool,
    },
    /// Uniform lease result. Refusal has `serving = false` and an empty page.
    Lease {
        /// Whether this response represents one live idempotent lease.
        serving: bool,
        /// Exact lease id, or all zeroes for a bounded refusal/miss.
        lease_id: [u8; 16],
        /// Lease expiry in Unix seconds, or zero for a refusal/miss.
        expires_at: u64,
        /// Bounded leased rows; empty for a refusal/miss.
        rows: Vec<MailboxV2LeasedRow>,
    },
    /// Uniform exact-row acknowledgement result.
    AckLease {
        /// Whether the exact row deletion transaction committed.
        accepted: bool,
    },
}

/// Encode one mailbox-v2 request using the exact canonical CBOR wire shape.
pub fn encode_mailbox_v2_request(request: &MailboxV2Request) -> io::Result<Vec<u8>> {
    encode_mailbox_v2(request, MAILBOX_V2_REQUEST_MAX_BYTES)
}

/// Decode one exact canonical mailbox-v2 request and reject alternate CBOR
/// encodings, trailing data, and values above the fixed request bound.
pub fn decode_mailbox_v2_request(bytes: &[u8]) -> io::Result<MailboxV2Request> {
    decode_mailbox_v2(bytes, MAILBOX_V2_REQUEST_MAX_BYTES)
}

/// Encode one mailbox-v2 response using the exact canonical CBOR wire shape.
pub fn encode_mailbox_v2_response(response: &MailboxV2Response) -> io::Result<Vec<u8>> {
    encode_mailbox_v2(response, MAILBOX_V2_RESPONSE_MAX_BYTES)
}

/// Decode one exact canonical mailbox-v2 response and reject alternate CBOR
/// encodings, trailing data, and values above the fixed response bound.
pub fn decode_mailbox_v2_response(bytes: &[u8]) -> io::Result<MailboxV2Response> {
    decode_mailbox_v2(bytes, MAILBOX_V2_RESPONSE_MAX_BYTES)
}

fn encode_mailbox_v2<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    let encoded = cbor4ii::serde::to_vec(Vec::new(), value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    if encoded.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mailbox-v2 wire value exceeds its fixed bound",
        ));
    }
    Ok(encoded)
}

fn decode_mailbox_v2<T>(bytes: &[u8], limit: usize) -> io::Result<T>
where
    T: Serialize + DeserializeOwned,
{
    if bytes.is_empty() || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mailbox-v2 wire value has an invalid length",
        ));
    }
    let decoded: T = cbor4ii::serde::from_slice(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let canonical = encode_mailbox_v2(&decoded, limit)?;
    if canonical != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mailbox-v2 wire value is not canonical",
        ));
    }
    Ok(decoded)
}

#[derive(Clone, Debug)]
pub(crate) struct MailboxV2LeasePage {
    pub(crate) lease_id: [u8; 16],
    pub(crate) expires_at: u64,
    pub(crate) rows: Vec<MailboxV2LeasedRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MailboxDepositDisposition {
    Accepted,
    Unregistered,
    Refused,
}

#[derive(Serialize, Deserialize)]
struct RegistrationRecord {
    version: u8,
    token: [u8; 32],
    client_idx: [u8; 32],
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct DepositRecord {
    version: u8,
    row_id: [u8; 16],
    token_idx: [u8; 32],
    content_id: [u8; 16],
    client_idx: [u8; 32],
    expires_at: u64,
    envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct LeaseRecord {
    version: u8,
    lease_id: [u8; 16],
    client_idx: [u8; 32],
    filter_idx: [u8; 32],
    created_at: u64,
    expires_at: u64,
    closed: bool,
}

#[derive(Clone, Copy)]
struct LeaseColumns {
    lease_id: [u8; 16],
    client_idx: [u8; 32],
    filter_idx: [u8; 32],
    created_at: u64,
    expires_at: u64,
    closed: bool,
}

#[derive(Serialize, Deserialize)]
struct LeaseRowRecord {
    version: u8,
    lease_id: [u8; 16],
    row_id: [u8; 16],
    acknowledged: bool,
}

#[derive(Serialize, Deserialize)]
struct RateRecord {
    version: u8,
    client_idx: [u8; 32],
    window_start: u64,
    requests: u32,
}

/// Durable relay-side mailbox state.
pub(crate) struct MailboxV2Store {
    conn: Connection,
    database_path: PathBuf,
    database_id: [u8; 32],
    index_key: StorageKey,
    row_key: StorageKey,
    config: MailboxConfig,
    rejected_deposits: u64,
    rejected_requests: u64,
    expired_rows: u64,
    allow_v1_compat: bool,
    #[cfg(test)]
    failpoint: std::cell::Cell<Option<(MailboxStoreFailpoint, InjectedFailure)>>,
}

impl MailboxV2Store {
    pub(crate) fn open(config: &MailboxServiceConfig) -> io::Result<Self> {
        if let Some(parent) = config.database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = config.key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let root = load_or_create_key(&config.key_path)?;
        let database_path = resolve_existing_parent(&config.database_path)?;
        let database_existed = match std::fs::symlink_metadata(&database_path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(invalid("mailbox database is not a regular file"));
            }
            Ok(metadata) => metadata.len() != 0,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut conn = sql(Connection::open_with_flags(
            &database_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ))?;
        configure(&conn)?;
        let database_id = if database_existed {
            read_metadata(&conn)?
        } else {
            create_schema(&mut conn)?
        };
        protect_sqlite_files(&database_path)?;
        let mut store = Self {
            conn,
            database_path,
            database_id,
            index_key: root.derive(INDEX_LABEL),
            row_key: root.derive(ROW_KEY_LABEL),
            config: config.limits,
            rejected_deposits: 0,
            rejected_requests: 0,
            expired_rows: 0,
            allow_v1_compat: config.allow_v1_compat,
            #[cfg(test)]
            failpoint: std::cell::Cell::new(None),
        };
        store.validate_all()?;
        let _ = store.sweep(unix_now())?;
        Ok(store)
    }

    pub(crate) fn allow_v1_compat(&self) -> bool {
        self.allow_v1_compat
    }

    pub(crate) fn deposit(
        &mut self,
        client: &[u8],
        envelope: &Envelope,
        encoded: Vec<u8>,
        now: u64,
    ) -> io::Result<bool> {
        Ok(self.deposit_disposition(client, envelope, encoded, now)?
            == MailboxDepositDisposition::Accepted)
    }

    pub(crate) fn deposit_disposition(
        &mut self,
        client: &[u8],
        envelope: &Envelope,
        encoded: Vec<u8>,
        now: u64,
    ) -> io::Result<MailboxDepositDisposition> {
        let result = self.deposit_inner(client, envelope, encoded, now);
        match result {
            Ok(MailboxDepositDisposition::Accepted) => Ok(MailboxDepositDisposition::Accepted),
            Ok(disposition) => {
                self.rejected_deposits = self.rejected_deposits.saturating_add(1);
                Ok(disposition)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn refuse_deposit_request(&mut self, client: &[u8], now: u64) -> io::Result<()> {
        let client_idx = self.client_index(client);
        let tx = sql(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        ))?;
        let expired = self.sweep_on(&tx, now)?;
        self.expired_rows = self.expired_rows.saturating_add(expired);
        let _ = self.rate_allowed_on(&tx, client_idx, now)?;
        sql(tx.commit())?;
        self.rejected_deposits = self.rejected_deposits.saturating_add(1);
        Ok(())
    }

    pub(crate) fn lease(
        &mut self,
        client: &[u8],
        tokens: &[[u8; 32]],
        now: u64,
    ) -> io::Result<Option<MailboxV2LeasePage>> {
        let result = self.lease_inner(client, tokens, now);
        if matches!(result, Ok(None)) {
            self.rejected_requests = self.rejected_requests.saturating_add(1);
        }
        result
    }

    pub(crate) fn ack(
        &mut self,
        client: &[u8],
        lease_id: [u8; 16],
        row_ids: &[[u8; 16]],
        now: u64,
    ) -> io::Result<bool> {
        let result = self.ack_inner(client, lease_id, row_ids, now);
        if matches!(result, Ok(false)) {
            self.rejected_requests = self.rejected_requests.saturating_add(1);
        }
        result
    }

    fn contents(&self) -> io::Result<Vec<MailboxStoredRow>> {
        let mut statement = sql(self.conn.prepare(
            "SELECT row_id, token_idx, content_idx, client_idx, expires_at, sealed
             FROM deposits ORDER BY sequence",
        ))?;
        let rows = sql(statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        }))?;
        let mut out = Vec::new();
        for row in rows {
            let (row_id, token_idx, content_idx, client_idx, expires_at, sealed) = sql(row)?;
            let row_id = array::<16>(&row_id)?;
            let token_idx = array::<32>(&token_idx)?;
            let content_idx = array::<32>(&content_idx)?;
            let client_idx = array::<32>(&client_idx)?;
            let record = self.open_deposit(
                row_id,
                token_idx,
                content_idx,
                client_idx,
                expires_at,
                &sealed,
            )?;
            out.push(MailboxStoredRow {
                row_id,
                ciphertext: record.envelope,
                expires_at,
            });
        }
        Ok(out)
    }

    pub(crate) fn metrics(&mut self, now: u64) -> io::Result<MailboxMetrics> {
        let _ = self.sweep(now)?;
        let (stored_items, stored_bytes) = sql(self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(encoded_len), 0) FROM deposits",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let registrations = sql(self.conn.query_row(
            "SELECT COUNT(*) FROM registrations WHERE expires_at > ?1",
            params![now],
            |row| row.get::<_, u64>(0),
        ))?;
        let (live_leases, oldest_created) = sql(self.conn.query_row(
            "SELECT COUNT(*), MIN(created_at) FROM leases
             WHERE expires_at > ?1 AND closed = 0",
            params![now],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Option<u64>>(1)?)),
        ))?;
        Ok(MailboxMetrics {
            stored_items,
            stored_bytes,
            capacity_items: self.config.max_total_items as u64,
            capacity_bytes: self.config.max_total_bytes as u64,
            retention_secs: self.config.envelope_ttl_secs,
            request_capacity_per_minute: self.config.max_requests_per_minute as u64,
            request_capacity_per_client_per_minute: self.config.max_requests_per_client_per_minute
                as u64,
            disk_available_bytes: fs2::available_space(&self.database_path).ok(),
            registrations,
            live_leases,
            lease_capacity: self.config.max_live_leases as u64,
            oldest_lease_age_secs: oldest_created.map(|created| now.saturating_sub(created)),
            rejected_deposits: self.rejected_deposits,
            rejected_requests: self.rejected_requests,
            expired_rows: self.expired_rows,
            schema_version: SCHEMA_VERSION,
        })
    }

    #[cfg(test)]
    fn arm_failpoint(&self, point: MailboxStoreFailpoint) {
        self.arm_failure(point, InjectedFailure::Interrupted);
    }

    #[cfg(test)]
    fn arm_failure(&self, point: MailboxStoreFailpoint, failure: InjectedFailure) {
        self.failpoint.set(Some((point, failure)));
    }

    #[cfg(test)]
    fn check_failpoint(&self, point: MailboxStoreFailpoint) -> io::Result<()> {
        if self
            .failpoint
            .get()
            .is_some_and(|(armed, _)| armed == point)
        {
            let (_, failure) = self.failpoint.get().expect("checked above");
            self.failpoint.set(None);
            let kind = match failure {
                InjectedFailure::Interrupted => io::ErrorKind::Interrupted,
                InjectedFailure::DiskFull => io::ErrorKind::WriteZero,
            };
            return Err(io::Error::new(kind, "injected mailbox write failure"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use kult_protocol::EnvelopeKind;

    const NOW: u64 = 1_800_000_000;

    fn service(dir: &Path, limits: MailboxConfig) -> MailboxServiceConfig {
        MailboxServiceConfig::in_directory(dir, limits)
    }

    fn envelope(token: [u8; 32], body: &[u8]) -> Envelope {
        Envelope::new(EnvelopeKind::Message, token, body.to_vec())
    }

    #[test]
    fn zero_length_database_from_interrupted_creation_is_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        File::create(&config.database_path)
            .unwrap()
            .sync_all()
            .unwrap();
        let mut store = MailboxV2Store::open(&config).unwrap();
        let metrics = store.metrics(NOW).unwrap();
        assert_eq!(metrics.schema_version, SCHEMA_VERSION);
        assert_eq!(metrics.capacity_items, config.limits.max_total_items as u64);
        assert_eq!(metrics.capacity_bytes, config.limits.max_total_bytes as u64);
        assert_eq!(metrics.retention_secs, config.limits.envelope_ttl_secs);
        assert_eq!(
            metrics.request_capacity_per_minute,
            config.limits.max_requests_per_minute as u64
        );
        assert_eq!(
            metrics.request_capacity_per_client_per_minute,
            config.limits.max_requests_per_client_per_minute as u64
        );
        assert_eq!(metrics.lease_capacity, config.limits.max_live_leases as u64);
        assert!(metrics.disk_available_bytes.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn database_sidecars_and_storage_key_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [0x17; 32];
        let env = envelope(token, b"permissions");
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &env, env.try_encode().unwrap(), NOW + 1)
            .unwrap());

        for path in [&config.database_path, &config.key_path] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = config.database_path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                assert_eq!(
                    std::fs::metadata(sidecar).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn owner_read_only_storage_key_reopens_without_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        drop(MailboxV2Store::open(&config).unwrap());
        std::fs::set_permissions(&config.key_path, std::fs::Permissions::from_mode(0o400)).unwrap();

        drop(MailboxV2Store::open(&config).unwrap());
        assert_eq!(
            std::fs::metadata(&config.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }

    #[cfg(unix)]
    #[test]
    fn database_and_storage_key_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key_config = service(&dir.path().join("key"), MailboxConfig::default());
        std::fs::create_dir_all(key_config.key_path.parent().unwrap()).unwrap();
        let key_target = dir.path().join("key-target");
        File::create(&key_target)
            .unwrap()
            .write_all(&[0u8; 32])
            .unwrap();
        symlink(&key_target, &key_config.key_path).unwrap();
        assert!(MailboxV2Store::open(&key_config).is_err());

        let database_config = service(&dir.path().join("database"), MailboxConfig::default());
        std::fs::create_dir_all(database_config.database_path.parent().unwrap()).unwrap();
        let database_target = dir.path().join("database-target");
        File::create(&database_target).unwrap();
        symlink(&database_target, &database_config.database_path).unwrap();
        assert!(MailboxV2Store::open(&database_config).is_err());
    }

    #[test]
    fn deposit_lease_ack_and_duplicate_ack_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [7u8; 32];
        let env = envelope(token, b"opaque durable row");
        let encoded = env.try_encode().unwrap();

        {
            let mut store = MailboxV2Store::open(&config).unwrap();
            let empty = store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
            assert!(empty.rows.is_empty());
            assert!(store
                .deposit(b"sender", &env, encoded.clone(), NOW + 1)
                .unwrap());
            assert_eq!(store.metrics(NOW + 1).unwrap().stored_items, 1);
        }

        let (lease_id, row_id) = {
            let mut store = MailboxV2Store::open(&config).unwrap();
            let page = store
                .lease(b"recipient", &[token], NOW + 2)
                .unwrap()
                .unwrap();
            assert_eq!(page.rows.len(), 1);
            assert_eq!(page.rows[0].envelope, encoded);
            let repeated = store
                .lease(b"recipient", &[token], NOW + 3)
                .unwrap()
                .unwrap();
            assert_eq!(repeated.lease_id, page.lease_id);
            assert_eq!(repeated.rows[0].row_id, page.rows[0].row_id);
            (page.lease_id, page.rows[0].row_id)
        };

        {
            let mut store = MailboxV2Store::open(&config).unwrap();
            assert!(store
                .ack(b"recipient", lease_id, &[row_id], NOW + 4)
                .unwrap());
            assert!(
                store
                    .ack(b"recipient", lease_id, &[row_id], NOW + 5)
                    .unwrap(),
                "response loss makes the same exact acknowledgement harmless"
            );
            assert!(store.contents().unwrap().is_empty());
        }
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert_eq!(store.metrics(NOW + 6).unwrap().stored_items, 0);
    }

    #[test]
    fn partial_ack_keeps_unrelated_rows_and_expired_lease_releases_them() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            lease_ttl_secs: 10,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let token = [8u8; 32];
        let first = envelope(token, b"first");
        let second = envelope(token, b"second");
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &first, first.try_encode().unwrap(), NOW + 1)
            .unwrap());
        assert!(store
            .deposit(b"sender", &second, second.try_encode().unwrap(), NOW + 1)
            .unwrap());
        let page = store
            .lease(b"recipient", &[token], NOW + 2)
            .unwrap()
            .unwrap();
        assert_eq!(page.rows.len(), 2);
        assert!(!store
            .ack(
                b"other recipient",
                page.lease_id,
                &[page.rows[0].row_id],
                NOW + 3,
            )
            .unwrap());
        assert!(!store
            .ack(b"recipient", page.lease_id, &[[0x55; 16]], NOW + 3)
            .unwrap());
        assert!(!store
            .ack(
                b"recipient",
                page.lease_id,
                &[page.rows[0].row_id, page.rows[0].row_id],
                NOW + 3,
            )
            .unwrap());
        assert_eq!(store.contents().unwrap().len(), 2);
        assert!(store
            .ack(b"recipient", page.lease_id, &[page.rows[0].row_id], NOW + 4,)
            .unwrap());
        let repeated = store
            .lease(b"recipient", &[token], NOW + 5)
            .unwrap()
            .unwrap();
        assert_eq!(repeated.lease_id, page.lease_id);
        assert_eq!(repeated.rows.len(), 1);
        assert_eq!(store.contents().unwrap().len(), 1);

        drop(store);
        let mut store = MailboxV2Store::open(&config).unwrap();
        let released = store
            .lease(b"recipient", &[token], NOW + 14)
            .unwrap()
            .unwrap();
        assert_ne!(released.lease_id, page.lease_id);
        assert_eq!(released.rows.len(), 1);
    }

    #[test]
    fn quotas_and_rate_limits_refuse_without_false_custody() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_total_items: 1,
            max_per_token: 1,
            max_per_client: 1,
            max_requests_per_client_per_minute: 3,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let token = [9u8; 32];
        let first = envelope(token, b"one");
        let second = envelope(token, b"two");
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &first, first.try_encode().unwrap(), NOW + 1)
            .unwrap());
        assert!(!store
            .deposit(b"sender", &second, second.try_encode().unwrap(), NOW + 2)
            .unwrap());
        assert!(
            !store
                .deposit(b"sender", &second, second.try_encode().unwrap(), NOW + 3)
                .unwrap(),
            "the fixed request window remains bounded after quota refusal"
        );
        assert_eq!(store.contents().unwrap().len(), 1);
        drop(store);
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert!(
            !store
                .deposit(b"sender", &second, second.try_encode().unwrap(), NOW + 4)
                .unwrap(),
            "durable rate and capacity state survives restart"
        );
        assert_eq!(store.contents().unwrap().len(), 1);
    }

    #[test]
    fn global_request_rate_is_persisted_across_distinct_clients() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_requests_per_minute: 2,
            max_requests_per_client_per_minute: 10,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert!(store.lease(b"one", &[[1; 32]], NOW).unwrap().is_some());
        assert!(store.lease(b"two", &[[2; 32]], NOW + 1).unwrap().is_some());
        assert!(store
            .lease(b"three", &[[3; 32]], NOW + 2)
            .unwrap()
            .is_none());

        drop(store);
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert!(store.lease(b"four", &[[4; 32]], NOW + 3).unwrap().is_none());
        assert!(store
            .lease(b"four", &[[4; 32]], NOW + RATE_WINDOW_SECS + 3)
            .unwrap()
            .is_some());
    }

    #[test]
    fn unregistered_deposits_consume_the_persisted_request_budget() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_requests_per_client_per_minute: 2,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let env = envelope([0x28; 32], b"foreign");
        let encoded = env.try_encode().unwrap();
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded.clone(), NOW)
                .unwrap(),
            MailboxDepositDisposition::Unregistered
        );
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded.clone(), NOW + 1)
                .unwrap(),
            MailboxDepositDisposition::Unregistered
        );
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded.clone(), NOW + 2)
                .unwrap(),
            MailboxDepositDisposition::Refused
        );
        drop(store);

        let mut store = MailboxV2Store::open(&config).unwrap();
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded, NOW + 3)
                .unwrap(),
            MailboxDepositDisposition::Refused
        );
    }

    #[test]
    fn malformed_deposits_consume_the_persisted_request_budget() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_requests_per_client_per_minute: 1,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let env = envelope([0x29; 32], b"foreign");
        let encoded = env.try_encode().unwrap();
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.refuse_deposit_request(b"sender", NOW).unwrap();
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded.clone(), NOW + 1)
                .unwrap(),
            MailboxDepositDisposition::Refused
        );
        drop(store);

        let mut store = MailboxV2Store::open(&config).unwrap();
        assert_eq!(
            store
                .deposit_disposition(b"sender", &env, encoded, NOW + 2)
                .unwrap(),
            MailboxDepositDisposition::Refused
        );
    }

    #[test]
    fn registration_quota_refusal_still_consumes_the_request_budget() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_tokens: 1,
            registration_ttl_secs: 5,
            max_requests_per_client_per_minute: 2,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let mut store = MailboxV2Store::open(&config).unwrap();
        assert!(store
            .lease(b"recipient", &[[1; 32]], NOW)
            .unwrap()
            .is_some());
        assert!(store
            .lease(b"recipient", &[[2; 32]], NOW + 1)
            .unwrap()
            .is_none());
        assert!(
            store
                .lease(b"recipient", &[[2; 32]], NOW + 6)
                .unwrap()
                .is_none(),
            "quota refusal must not roll back its durable rate charge"
        );
        assert!(store
            .lease(b"recipient", &[[2; 32]], NOW + RATE_WINDOW_SECS + 1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn relay_wide_live_lease_capacity_releases_after_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            max_live_leases: 1,
            lease_ttl_secs: 5,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let first_token = [0x31; 32];
        let second_token = [0x32; 32];
        let first = envelope(first_token, b"first");
        let second = envelope(second_token, b"second");
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"one", &[first_token], NOW).unwrap().unwrap();
        store.lease(b"two", &[second_token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &first, first.try_encode().unwrap(), NOW + 1)
            .unwrap());
        assert!(store
            .deposit(b"sender", &second, second.try_encode().unwrap(), NOW + 1)
            .unwrap());
        assert!(store
            .lease(b"one", &[first_token], NOW + 2)
            .unwrap()
            .is_some());
        assert!(store
            .lease(b"two", &[second_token], NOW + 2)
            .unwrap()
            .is_none());
        assert!(store
            .lease(b"two", &[second_token], NOW + 8)
            .unwrap()
            .is_some());
    }

    #[test]
    fn lease_pages_are_bounded_by_exact_row_count() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [0x39u8; 32];
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        for index in 0..=MAILBOX_V2_PAGE_MAX_ROWS {
            let body = (index as u16).to_be_bytes();
            let env = envelope(token, &body);
            assert!(store
                .deposit(b"sender", &env, env.try_encode().unwrap(), NOW + 1)
                .unwrap());
        }

        let first = store
            .lease(b"recipient", &[token], NOW + 2)
            .unwrap()
            .unwrap();
        assert_eq!(first.rows.len(), MAILBOX_V2_PAGE_MAX_ROWS);
        let first_ids = first.rows.iter().map(|row| row.row_id).collect::<Vec<_>>();
        assert!(store
            .ack(b"recipient", first.lease_id, &first_ids, NOW + 3)
            .unwrap());
        let second = store
            .lease(b"recipient", &[token], NOW + 4)
            .unwrap()
            .unwrap();
        assert_eq!(second.rows.len(), 1);
    }

    #[test]
    fn lease_pages_are_bounded_by_exact_ciphertext_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [0x3au8; 32];
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        for index in 0u8..9 {
            let mut body = vec![index; MAX_ENVELOPE_BYTES - kult_protocol::ENVELOPE_V1_HEADER_LEN];
            body[0] = index;
            let env = envelope(token, &body);
            let encoded = env.try_encode().unwrap();
            assert_eq!(encoded.len(), MAX_ENVELOPE_BYTES);
            assert!(store.deposit(b"sender", &env, encoded, NOW + 1).unwrap());
        }

        let first = store
            .lease(b"recipient", &[token], NOW + 2)
            .unwrap()
            .unwrap();
        assert_eq!(first.rows.len(), 8);
        assert_eq!(
            first
                .rows
                .iter()
                .map(|row| row.envelope.len())
                .sum::<usize>(),
            MAILBOX_V2_PAGE_MAX_BYTES
        );
        let first_ids = first.rows.iter().map(|row| row.row_id).collect::<Vec<_>>();
        assert!(store
            .ack(b"recipient", first.lease_id, &first_ids, NOW + 3)
            .unwrap());
        let second = store
            .lease(b"recipient", &[token], NOW + 4)
            .unwrap()
            .unwrap();
        assert_eq!(second.rows.len(), 1);
        assert_eq!(second.rows[0].envelope.len(), MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn locked_database_contains_no_plain_token_or_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [0xA7u8; 32];
        let env = envelope(token, b"recognizable mailbox ciphertext fixture");
        let encoded = env.try_encode().unwrap();
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &env, encoded.clone(), NOW + 1)
            .unwrap());
        sql(store.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")).unwrap();
        drop(store);

        let raw = std::fs::read(&config.database_path).unwrap();
        assert!(!raw.windows(token.len()).any(|window| window == token));
        assert!(!raw
            .windows(encoded.len())
            .any(|window| window == encoded.as_slice()));
    }

    #[test]
    fn wrong_service_key_and_row_transplant_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let config = service(dir.path(), MailboxConfig::default());
        let token = [0x44u8; 32];
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        for body in [b"one".as_slice(), b"two".as_slice()] {
            let env = envelope(token, body);
            assert!(store
                .deposit(b"sender", &env, env.try_encode().unwrap(), NOW + 1)
                .unwrap());
        }
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut statement = store
                .conn
                .prepare("SELECT row_id, sealed FROM deposits ORDER BY sequence")
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        store
            .conn
            .execute(
                "UPDATE deposits SET sealed = ?1 WHERE row_id = ?2",
                params![rows[0].1.as_slice(), rows[1].0.as_slice()],
            )
            .unwrap();
        drop(store);
        assert!(MailboxV2Store::open(&config).is_err());

        let wrong = service(dir.path().join("other").as_path(), MailboxConfig::default());
        std::fs::create_dir_all(wrong.database_path.parent().unwrap()).unwrap();
        std::fs::copy(&config.database_path, &wrong.database_path).unwrap();
        assert!(MailboxV2Store::open(&wrong).is_err());
    }

    #[test]
    fn commit_failpoints_leave_only_absent_or_complete_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            envelope_ttl_secs: 20,
            lease_ttl_secs: 10,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let token = [0x52u8; 32];
        let env = envelope(token, b"failpoint custody");
        let encoded = env.try_encode().unwrap();
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();

        store.arm_failure(
            MailboxStoreFailpoint::BeforeDepositCommit,
            InjectedFailure::DiskFull,
        );
        let disk_full = store
            .deposit(b"sender", &env, encoded.clone(), NOW + 1)
            .unwrap_err();
        assert_eq!(disk_full.kind(), io::ErrorKind::WriteZero);
        assert!(store.contents().unwrap().is_empty());

        store.arm_failpoint(MailboxStoreFailpoint::BeforeDepositCommit);
        assert!(store
            .deposit(b"sender", &env, encoded.clone(), NOW + 2)
            .is_err());
        assert!(store.contents().unwrap().is_empty());

        store.arm_failpoint(MailboxStoreFailpoint::AfterDepositCommit);
        assert!(store
            .deposit(b"sender", &env, encoded.clone(), NOW + 3)
            .is_err());
        assert_eq!(store.contents().unwrap().len(), 1);
        assert!(
            store
                .deposit(b"sender", &env, encoded.clone(), NOW + 3)
                .unwrap(),
            "retry after lost deposit response finds the durable duplicate"
        );

        store.arm_failpoint(MailboxStoreFailpoint::BeforeLeaseCommit);
        assert!(store.lease(b"recipient", &[token], NOW + 4).is_err());
        store.arm_failpoint(MailboxStoreFailpoint::AfterLeaseCommit);
        assert!(store.lease(b"recipient", &[token], NOW + 5).is_err());
        let page = store
            .lease(b"recipient", &[token], NOW + 6)
            .unwrap()
            .unwrap();
        assert_eq!(page.rows.len(), 1);

        store.arm_failpoint(MailboxStoreFailpoint::BeforeAckDelete);
        assert!(store
            .ack(b"recipient", page.lease_id, &[page.rows[0].row_id], NOW + 7,)
            .is_err());
        assert_eq!(store.contents().unwrap().len(), 1);

        store.arm_failpoint(MailboxStoreFailpoint::BeforeAckCommit);
        assert!(store
            .ack(b"recipient", page.lease_id, &[page.rows[0].row_id], NOW + 8,)
            .is_err());
        assert_eq!(store.contents().unwrap().len(), 1);

        store.arm_failpoint(MailboxStoreFailpoint::AfterAckCommit);
        assert!(store
            .ack(b"recipient", page.lease_id, &[page.rows[0].row_id], NOW + 9,)
            .is_err());
        assert!(store.contents().unwrap().is_empty());
        assert!(
            store
                .ack(
                    b"recipient",
                    page.lease_id,
                    &[page.rows[0].row_id],
                    NOW + 10,
                )
                .unwrap(),
            "retry after lost ack response is idempotent"
        );
    }

    #[test]
    fn expiry_failpoints_preserve_or_complete_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let limits = MailboxConfig {
            envelope_ttl_secs: 5,
            ..MailboxConfig::default()
        };
        let config = service(dir.path(), limits);
        let token = [0x63u8; 32];
        let env = envelope(token, b"expiring");
        let mut store = MailboxV2Store::open(&config).unwrap();
        store.lease(b"recipient", &[token], NOW).unwrap().unwrap();
        assert!(store
            .deposit(b"sender", &env, env.try_encode().unwrap(), NOW + 1)
            .unwrap());

        store.arm_failpoint(MailboxStoreFailpoint::BeforeSweepCommit);
        assert!(store.sweep(NOW + 7).is_err());
        assert_eq!(store.contents().unwrap().len(), 1);

        store.arm_failpoint(MailboxStoreFailpoint::AfterSweepCommit);
        assert!(store.sweep(NOW + 7).is_err());
        assert!(store.contents().unwrap().is_empty());
        drop(store);
        assert!(MailboxV2Store::open(&config)
            .unwrap()
            .contents()
            .unwrap()
            .is_empty());
    }
}

impl MailboxV2Store {
    fn available_rows_on(
        &self,
        tx: &Transaction<'_>,
        token_indexes: &[[u8; 32]],
        now: u64,
    ) -> io::Result<Vec<MailboxV2LeasedRow>> {
        if token_indexes.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = (1..=token_indexes.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let now_parameter = token_indexes.len() + 1;
        let limit_parameter = token_indexes.len() + 2;
        let query = format!(
            "SELECT d.row_id, d.token_idx, d.content_idx, d.client_idx,
                    d.expires_at, d.encoded_len, d.sealed
             FROM deposits d
             WHERE d.token_idx IN ({placeholders})
               AND d.expires_at > ?{now_parameter}
               AND NOT EXISTS (
                   SELECT 1 FROM lease_rows lr
                   JOIN leases l ON l.lease_id = lr.lease_id
                   WHERE lr.row_id = d.row_id
                     AND lr.acknowledged = 0
                     AND l.closed = 0
                     AND l.expires_at > ?{now_parameter}
               )
             ORDER BY d.sequence
             LIMIT ?{limit_parameter}"
        );
        let mut values: Vec<rusqlite::types::Value> = token_indexes
            .iter()
            .map(|index| rusqlite::types::Value::Blob(index.to_vec()))
            .collect();
        values.push(rusqlite::types::Value::Integer(
            i64::try_from(now).map_err(|_| invalid("mailbox clock"))?,
        ));
        values.push(rusqlite::types::Value::Integer(
            i64::try_from(MAILBOX_V2_PAGE_MAX_ROWS).map_err(|_| invalid("mailbox page limit"))?,
        ));
        let mut statement = sql(tx.prepare(&query))?;
        let rows = sql(
            statement.query_map(rusqlite::params_from_iter(values), |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            }),
        )?;
        let mut page = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let (row_id, token_idx, content_idx, client_idx, expires_at, encoded_len, sealed) =
                sql(row)?;
            let row_id = array::<16>(&row_id)?;
            let token_idx = array::<32>(&token_idx)?;
            let content_idx = array::<32>(&content_idx)?;
            let client_idx = array::<32>(&client_idx)?;
            let record = self.open_deposit(
                row_id,
                token_idx,
                content_idx,
                client_idx,
                expires_at,
                &sealed,
            )?;
            if record.envelope.len() as u64 != encoded_len {
                return Err(invalid("mailbox encoded-length binding mismatch"));
            }
            let Some(next_bytes) = bytes.checked_add(record.envelope.len()) else {
                return Err(invalid("mailbox page byte overflow"));
            };
            if next_bytes > MAILBOX_V2_PAGE_MAX_BYTES {
                continue;
            }
            bytes = next_bytes;
            page.push(MailboxV2LeasedRow {
                row_id,
                envelope: record.envelope,
            });
        }
        Ok(page)
    }

    fn insert_lease_on(
        &self,
        tx: &Transaction<'_>,
        client_idx: [u8; 32],
        filter_idx: [u8; 32],
        created_at: u64,
        expires_at: u64,
        closed: bool,
    ) -> io::Result<[u8; 16]> {
        for _ in 0..16 {
            let lease_id = random_id();
            let record = LeaseRecord {
                version: RECORD_VERSION,
                lease_id,
                client_idx,
                filter_idx,
                created_at,
                expires_at,
                closed,
            };
            let sealed = self.seal(
                DOMAIN_LEASE,
                &lease_id,
                &lease_binding(&client_idx, &filter_idx, created_at, expires_at, closed),
                &record,
            )?;
            let result = tx.execute(
                "INSERT INTO leases(
                     lease_id, client_idx, filter_idx, created_at,
                     expires_at, closed, sealed
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    lease_id.as_slice(),
                    client_idx.as_slice(),
                    filter_idx.as_slice(),
                    created_at,
                    expires_at,
                    closed,
                    sealed
                ],
            );
            match result {
                Ok(1) => return Ok(lease_id),
                Ok(_) => return Err(invalid("mailbox lease insert count")),
                Err(error) if is_unique_violation(&error) => continue,
                Err(error) => return Err(sql_error(error)),
            }
        }
        Err(invalid("could not allocate a unique mailbox lease id"))
    }

    fn load_lease_rows_on(
        &self,
        tx: &Transaction<'_>,
        lease: &LeaseRecord,
    ) -> io::Result<Vec<MailboxV2LeasedRow>> {
        let expected = sql(tx.query_row(
            "SELECT COUNT(*) FROM lease_rows
             WHERE lease_id = ?1 AND acknowledged = 0",
            params![lease.lease_id.as_slice()],
            |row| row.get::<_, u64>(0),
        ))?;
        let mut statement = sql(tx.prepare(
            "SELECT lr.row_id, lr.sealed,
                    d.token_idx, d.content_idx, d.client_idx,
                    d.expires_at, d.encoded_len, d.sealed
             FROM lease_rows lr
             JOIN deposits d ON d.row_id = lr.row_id
             WHERE lr.lease_id = ?1 AND lr.acknowledged = 0
             ORDER BY d.sequence",
        ))?;
        let rows = sql(
            statement.query_map(params![lease.lease_id.as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            }),
        )?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let (
                row_id,
                mapping_sealed,
                token_idx,
                content_idx,
                client_idx,
                expires_at,
                encoded_len,
                deposit_sealed,
            ) = sql(row)?;
            let row_id = array::<16>(&row_id)?;
            let mapping: LeaseRowRecord = self.open_record(
                DOMAIN_LEASE_ROW,
                &lease_row_locator(&lease.lease_id, &row_id),
                &[0],
                &mapping_sealed,
            )?;
            if mapping.version != RECORD_VERSION
                || mapping.lease_id != lease.lease_id
                || mapping.row_id != row_id
                || mapping.acknowledged
            {
                return Err(invalid("mailbox lease-row binding mismatch"));
            }
            let token_idx = array::<32>(&token_idx)?;
            let content_idx = array::<32>(&content_idx)?;
            let client_idx = array::<32>(&client_idx)?;
            let record = self.open_deposit(
                row_id,
                token_idx,
                content_idx,
                client_idx,
                expires_at,
                &deposit_sealed,
            )?;
            if record.envelope.len() as u64 != encoded_len {
                return Err(invalid("mailbox encoded-length binding mismatch"));
            }
            bytes = bytes
                .checked_add(record.envelope.len())
                .ok_or_else(|| invalid("mailbox page byte overflow"))?;
            if bytes > MAILBOX_V2_PAGE_MAX_BYTES || out.len() >= MAILBOX_V2_PAGE_MAX_ROWS {
                return Err(invalid("persisted mailbox lease exceeds page bounds"));
            }
            out.push(MailboxV2LeasedRow {
                row_id,
                envelope: record.envelope,
            });
        }
        if out.len() as u64 != expected {
            return Err(invalid("mailbox lease references a missing deposit"));
        }
        Ok(out)
    }

    fn rate_allowed_on(
        &self,
        tx: &Transaction<'_>,
        client_idx: [u8; 32],
        now: u64,
    ) -> io::Result<bool> {
        let global_idx = self
            .index_key
            .derive(GLOBAL_RATE_INDEX_LABEL)
            .hmac_sha256(&self.database_id);
        if !self.rate_subject_allowed_on(
            tx,
            global_idx,
            self.config.max_requests_per_minute,
            now,
        )? {
            return Ok(false);
        }
        self.rate_subject_allowed_on(
            tx,
            client_idx,
            self.config.max_requests_per_client_per_minute,
            now,
        )
    }

    fn rate_subject_allowed_on(
        &self,
        tx: &Transaction<'_>,
        subject_idx: [u8; 32],
        limit: usize,
        now: u64,
    ) -> io::Result<bool> {
        let existing = sql(tx
            .query_row(
                "SELECT window_start, requests, sealed
                 FROM rate_buckets WHERE client_idx = ?1",
                params![subject_idx.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional())?;
        let (window_start, requests) = match existing {
            Some((window_start, requests, sealed)) => {
                let record: RateRecord = self.open_record(
                    DOMAIN_RATE,
                    &subject_idx,
                    &rate_binding(window_start, requests),
                    &sealed,
                )?;
                if record.version != RECORD_VERSION
                    || record.client_idx != subject_idx
                    || record.window_start != window_start
                    || record.requests != requests
                {
                    return Err(invalid("mailbox rate binding mismatch"));
                }
                if now.saturating_sub(window_start) >= RATE_WINDOW_SECS {
                    (now, 0)
                } else {
                    (window_start, requests)
                }
            }
            None => (now, 0),
        };
        if requests as usize >= limit {
            return Ok(false);
        }
        let requests = requests.saturating_add(1);
        let record = RateRecord {
            version: RECORD_VERSION,
            client_idx: subject_idx,
            window_start,
            requests,
        };
        let sealed = self.seal(
            DOMAIN_RATE,
            &subject_idx,
            &rate_binding(window_start, requests),
            &record,
        )?;
        sql(tx.execute(
            "INSERT INTO rate_buckets(client_idx, window_start, requests, sealed)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(client_idx) DO UPDATE SET
                 window_start = excluded.window_start,
                 requests = excluded.requests,
                 sealed = excluded.sealed",
            params![subject_idx.as_slice(), window_start, requests, sealed],
        ))?;
        Ok(true)
    }

    fn sweep(&mut self, now: u64) -> io::Result<u64> {
        let tx = sql(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        ))?;
        let expired = self.sweep_on(&tx, now)?;
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::BeforeSweepCommit)?;
        sql(tx.commit())?;
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::AfterSweepCommit)?;
        self.expired_rows = self.expired_rows.saturating_add(expired);
        Ok(expired)
    }

    fn sweep_on(&self, tx: &Transaction<'_>, now: u64) -> io::Result<u64> {
        sql(tx.execute(
            "DELETE FROM leases
             WHERE lease_id IN (
                 SELECT DISTINCT lr.lease_id
                 FROM lease_rows lr
                 JOIN deposits d ON d.row_id = lr.row_id
                 WHERE d.expires_at <= ?1
             )",
            params![now],
        ))?;
        sql(tx.execute("DELETE FROM leases WHERE expires_at <= ?1", params![now]))?;
        let expired =
            sql(tx.execute("DELETE FROM deposits WHERE expires_at <= ?1", params![now]))? as u64;
        sql(tx.execute(
            "DELETE FROM registrations WHERE expires_at <= ?1",
            params![now],
        ))?;
        sql(tx.execute(
            "DELETE FROM rate_buckets
             WHERE window_start <= ?1",
            params![now.saturating_sub(2 * RATE_WINDOW_SECS)],
        ))?;
        Ok(expired)
    }

    fn token_index(&self, token: &[u8; 32]) -> [u8; 32] {
        self.index_key.derive(TOKEN_INDEX_LABEL).hmac_sha256(token)
    }

    fn client_index(&self, client: &[u8]) -> [u8; 32] {
        self.index_key
            .derive(CLIENT_INDEX_LABEL)
            .hmac_sha256(client)
    }

    fn content_index(&self, content_id: &[u8; 16]) -> [u8; 32] {
        self.index_key
            .derive(CONTENT_INDEX_LABEL)
            .hmac_sha256(content_id)
    }

    fn filter_index(&self, token_indexes: &[[u8; 32]]) -> [u8; 32] {
        let mut canonical = Vec::with_capacity(4 + token_indexes.len() * 32);
        canonical.extend_from_slice(&(token_indexes.len() as u32).to_be_bytes());
        for index in token_indexes {
            canonical.extend_from_slice(index);
        }
        self.index_key
            .derive(FILTER_INDEX_LABEL)
            .hmac_sha256(&canonical)
    }

    fn seal<T: Serialize>(
        &self,
        domain: u8,
        locator: &[u8],
        binding: &[u8],
        record: &T,
    ) -> io::Result<Vec<u8>> {
        let plain = postcard::to_allocvec(record).map_err(|_| invalid("mailbox serialization"))?;
        Ok(self.row_key.derive(&[domain]).seal(
            &self.row_ad(domain, locator, binding),
            &plain,
            &mut OsRng,
        ))
    }

    fn open_record<T: DeserializeOwned>(
        &self,
        domain: u8,
        locator: &[u8],
        binding: &[u8],
        sealed: &[u8],
    ) -> io::Result<T> {
        let plain = self
            .row_key
            .derive(&[domain])
            .open(&self.row_ad(domain, locator, binding), sealed)
            .map_err(|_| invalid("mailbox row authentication failed"))?;
        let (record, rest) =
            postcard::take_from_bytes(&plain).map_err(|_| invalid("mailbox serialization"))?;
        if !rest.is_empty() {
            return Err(invalid("mailbox row has trailing bytes"));
        }
        Ok(record)
    }

    fn row_ad(&self, domain: u8, locator: &[u8], binding: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(
            ROW_AD.len() + self.database_id.len() + 4 + 1 + 4 + locator.len() + binding.len(),
        );
        ad.extend_from_slice(ROW_AD);
        ad.extend_from_slice(&self.database_id);
        ad.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
        ad.push(domain);
        ad.extend_from_slice(&(locator.len() as u32).to_be_bytes());
        ad.extend_from_slice(locator);
        ad.extend_from_slice(binding);
        ad
    }

    fn open_deposit(
        &self,
        row_id: [u8; 16],
        token_idx: [u8; 32],
        content_idx: [u8; 32],
        client_idx: [u8; 32],
        expires_at: u64,
        sealed: &[u8],
    ) -> io::Result<DepositRecord> {
        let record: DepositRecord = self.open_record(
            DOMAIN_DEPOSIT,
            &row_id,
            &deposit_binding(&token_idx, &content_idx, &client_idx, expires_at),
            sealed,
        )?;
        if record.version != RECORD_VERSION
            || record.row_id != row_id
            || record.token_idx != token_idx
            || record.client_idx != client_idx
            || record.expires_at != expires_at
        {
            return Err(invalid("mailbox deposit binding mismatch"));
        }
        let envelope =
            Envelope::decode(&record.envelope).map_err(|_| invalid("mailbox envelope corrupt"))?;
        if self.token_index(&envelope.token) != token_idx
            || self.content_index(&record.content_id) != content_idx
            || envelope.content_id() != record.content_id
        {
            return Err(invalid("mailbox deposit logical-key mismatch"));
        }
        Ok(record)
    }

    fn open_lease(&self, columns: LeaseColumns, sealed: &[u8]) -> io::Result<LeaseRecord> {
        let record: LeaseRecord = self.open_record(
            DOMAIN_LEASE,
            &columns.lease_id,
            &lease_binding(
                &columns.client_idx,
                &columns.filter_idx,
                columns.created_at,
                columns.expires_at,
                columns.closed,
            ),
            sealed,
        )?;
        if record.version != RECORD_VERSION
            || record.lease_id != columns.lease_id
            || record.client_idx != columns.client_idx
            || record.filter_idx != columns.filter_idx
            || record.created_at != columns.created_at
            || record.expires_at != columns.expires_at
            || record.closed != columns.closed
        {
            return Err(invalid("mailbox lease binding mismatch"));
        }
        Ok(record)
    }

    fn validate_all(&self) -> io::Result<()> {
        {
            let mut statement = sql(self
                .conn
                .prepare("SELECT token_idx, client_idx, expires_at, sealed FROM registrations"))?;
            let rows = sql(statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            }))?;
            for row in rows {
                let (token_idx, client_idx, expires_at, sealed) = sql(row)?;
                let token_idx = array::<32>(&token_idx)?;
                let client_idx = array::<32>(&client_idx)?;
                let record: RegistrationRecord = self.open_record(
                    DOMAIN_REGISTRATION,
                    &token_idx,
                    &registration_binding(&client_idx, expires_at),
                    &sealed,
                )?;
                validate_registration(&record, &record.token, &client_idx, expires_at)?;
                if self.token_index(&record.token) != token_idx {
                    return Err(invalid("mailbox registration logical-key mismatch"));
                }
            }
        }

        // Opening the local inspection projection validates every deposit's
        // AEAD binding, inner token/content identity, and canonical envelope.
        let deposits = self.contents()?;
        let (stored_items, stored_bytes) = sql(self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(encoded_len), 0) FROM deposits",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let projected_bytes = deposits.iter().try_fold(0u64, |total, row| {
            let bytes = u64::try_from(row.ciphertext.len())
                .map_err(|_| invalid("mailbox ciphertext length"))?;
            total
                .checked_add(bytes)
                .ok_or_else(|| invalid("mailbox ciphertext-byte overflow"))
        })?;
        let distinct_row_ids = deposits
            .iter()
            .map(|row| row.row_id)
            .collect::<HashSet<_>>();
        if deposits.len() as u64 != stored_items
            || projected_bytes != stored_bytes
            || distinct_row_ids.len() != deposits.len()
            || deposits
                .iter()
                .any(|row| row.row_id == [0u8; 16] || row.expires_at == 0)
            || stored_items > self.config.max_total_items as u64
            || stored_bytes > self.config.max_total_bytes as u64
        {
            return Err(invalid(
                "mailbox durable capacity exceeds configured bounds",
            ));
        }
        let now = unix_now();
        let (registrations, max_registrations_per_client) = sql(self.conn.query_row(
            "SELECT
                 (SELECT COUNT(*) FROM registrations WHERE expires_at > ?1),
                 COALESCE(MAX(owned), 0)
             FROM (
                 SELECT COUNT(*) AS owned
                 FROM registrations
                 WHERE expires_at > ?1
                 GROUP BY client_idx
             )",
            params![now],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let (max_items_per_token, max_bytes_per_token) = sql(self.conn.query_row(
            "SELECT COALESCE(MAX(items), 0), COALESCE(MAX(bytes), 0)
             FROM (
                 SELECT COUNT(*) AS items, SUM(encoded_len) AS bytes
                 FROM deposits GROUP BY token_idx
             )",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let (max_items_per_client, max_bytes_per_client) = sql(self.conn.query_row(
            "SELECT COALESCE(MAX(items), 0), COALESCE(MAX(bytes), 0)
             FROM (
                 SELECT COUNT(*) AS items, SUM(encoded_len) AS bytes
                 FROM deposits GROUP BY client_idx
             )",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let (max_lease_rows, max_lease_bytes) = sql(self.conn.query_row(
            "SELECT COALESCE(MAX(items), 0), COALESCE(MAX(bytes), 0)
             FROM (
                 SELECT COUNT(*) AS items, SUM(d.encoded_len) AS bytes
                 FROM lease_rows lr
                 JOIN deposits d ON d.row_id = lr.row_id
                 WHERE lr.acknowledged = 0
                 GROUP BY lr.lease_id
             )",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        ))?;
        let max_live_leases_per_client = sql(self.conn.query_row(
            "SELECT COALESCE(MAX(items), 0)
             FROM (
                 SELECT COUNT(*) AS items
                 FROM leases
                 WHERE closed = 0 AND expires_at > ?1
                 GROUP BY client_idx
             )",
            params![now],
            |row| row.get::<_, u64>(0),
        ))?;
        let live_leases = sql(self.conn.query_row(
            "SELECT COUNT(*) FROM leases
             WHERE closed = 0 AND expires_at > ?1",
            params![now],
            |row| row.get::<_, u64>(0),
        ))?;
        let max_live_leases_per_token = sql(self.conn.query_row(
            "SELECT COALESCE(MAX(items), 0)
             FROM (
                 SELECT COUNT(DISTINCT lr.lease_id) AS items
                 FROM lease_rows lr
                 JOIN leases l ON l.lease_id = lr.lease_id
                 JOIN deposits d ON d.row_id = lr.row_id
                 WHERE lr.acknowledged = 0
                   AND l.closed = 0 AND l.expires_at > ?1
                 GROUP BY d.token_idx
             )",
            params![now],
            |row| row.get::<_, u64>(0),
        ))?;
        if registrations > self.config.max_tokens as u64
            || max_registrations_per_client > self.config.max_tokens_per_client as u64
            || max_items_per_token > self.config.max_per_token as u64
            || max_bytes_per_token > self.config.max_bytes_per_token as u64
            || max_items_per_client > self.config.max_per_client as u64
            || max_bytes_per_client > self.config.max_bytes_per_client as u64
            || max_lease_rows > MAILBOX_V2_PAGE_MAX_ROWS as u64
            || max_lease_bytes > MAILBOX_V2_PAGE_MAX_BYTES as u64
            || live_leases > self.config.max_live_leases as u64
            || max_live_leases_per_client > self.config.max_live_leases_per_client as u64
            || max_live_leases_per_token > self.config.max_live_leases_per_token as u64
        {
            return Err(invalid(
                "mailbox durable per-owner capacity exceeds configured bounds",
            ));
        }

        {
            let mut statement = sql(self.conn.prepare(
                "SELECT lease_id, client_idx, filter_idx, created_at,
                        expires_at, closed, sealed
                 FROM leases",
            ))?;
            let rows = sql(statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            }))?;
            for row in rows {
                let (lease_id, client_idx, filter_idx, created_at, expires_at, closed, sealed) =
                    sql(row)?;
                self.open_lease(
                    LeaseColumns {
                        lease_id: array::<16>(&lease_id)?,
                        client_idx: array::<32>(&client_idx)?,
                        filter_idx: array::<32>(&filter_idx)?,
                        created_at,
                        expires_at,
                        closed,
                    },
                    &sealed,
                )?;
            }
        }

        {
            let mut statement = sql(self
                .conn
                .prepare("SELECT lease_id, row_id, acknowledged, sealed FROM lease_rows"))?;
            let rows = sql(statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            }))?;
            for row in rows {
                let (lease_id, row_id, acknowledged, sealed) = sql(row)?;
                let lease_id = array::<16>(&lease_id)?;
                let row_id = array::<16>(&row_id)?;
                let record: LeaseRowRecord = self.open_record(
                    DOMAIN_LEASE_ROW,
                    &lease_row_locator(&lease_id, &row_id),
                    &[u8::from(acknowledged)],
                    &sealed,
                )?;
                if record.version != RECORD_VERSION
                    || record.lease_id != lease_id
                    || record.row_id != row_id
                    || record.acknowledged != acknowledged
                {
                    return Err(invalid("mailbox lease-row binding mismatch"));
                }
                if !acknowledged {
                    let exists = sql(self.conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM deposits WHERE row_id = ?1)",
                        params![row_id.as_slice()],
                        |row| row.get::<_, bool>(0),
                    ))?;
                    if !exists {
                        return Err(invalid("live mailbox lease references missing row"));
                    }
                }
            }
        }

        {
            let mut statement = sql(self
                .conn
                .prepare("SELECT client_idx, window_start, requests, sealed FROM rate_buckets"))?;
            let rows = sql(statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            }))?;
            for row in rows {
                let (client_idx, window_start, requests, sealed) = sql(row)?;
                let client_idx = array::<32>(&client_idx)?;
                let record: RateRecord = self.open_record(
                    DOMAIN_RATE,
                    &client_idx,
                    &rate_binding(window_start, requests),
                    &sealed,
                )?;
                if record.version != RECORD_VERSION
                    || record.client_idx != client_idx
                    || record.window_start != window_start
                    || record.requests != requests
                {
                    return Err(invalid("mailbox rate binding mismatch"));
                }
            }
        }
        Ok(())
    }
}

fn registration_binding(client_idx: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut binding = Vec::with_capacity(40);
    binding.extend_from_slice(client_idx);
    binding.extend_from_slice(&expires_at.to_be_bytes());
    binding
}

fn deposit_binding(
    token_idx: &[u8; 32],
    content_idx: &[u8; 32],
    client_idx: &[u8; 32],
    expires_at: u64,
) -> Vec<u8> {
    let mut binding = Vec::with_capacity(104);
    binding.extend_from_slice(token_idx);
    binding.extend_from_slice(content_idx);
    binding.extend_from_slice(client_idx);
    binding.extend_from_slice(&expires_at.to_be_bytes());
    binding
}

fn lease_binding(
    client_idx: &[u8; 32],
    filter_idx: &[u8; 32],
    created_at: u64,
    expires_at: u64,
    closed: bool,
) -> Vec<u8> {
    let mut binding = Vec::with_capacity(81);
    binding.extend_from_slice(client_idx);
    binding.extend_from_slice(filter_idx);
    binding.extend_from_slice(&created_at.to_be_bytes());
    binding.extend_from_slice(&expires_at.to_be_bytes());
    binding.push(u8::from(closed));
    binding
}

fn rate_binding(window_start: u64, requests: u32) -> [u8; 12] {
    let mut binding = [0u8; 12];
    binding[..8].copy_from_slice(&window_start.to_be_bytes());
    binding[8..].copy_from_slice(&requests.to_be_bytes());
    binding
}

fn lease_row_locator(lease_id: &[u8; 16], row_id: &[u8; 16]) -> [u8; 32] {
    let mut locator = [0u8; 32];
    locator[..16].copy_from_slice(lease_id);
    locator[16..].copy_from_slice(row_id);
    locator
}

fn validate_registration(
    record: &RegistrationRecord,
    token: &[u8; 32],
    client_idx: &[u8; 32],
    expires_at: u64,
) -> io::Result<()> {
    if record.version != RECORD_VERSION
        || &record.token != token
        || &record.client_idx != client_idx
        || record.expires_at != expires_at
    {
        return Err(invalid("mailbox registration binding mismatch"));
    }
    Ok(())
}

fn count_and_bytes(
    tx: &Transaction<'_>,
    clause: &str,
    indexes: &[[u8; 32]],
) -> io::Result<(u64, u64)> {
    let query = format!("SELECT COUNT(*), COALESCE(SUM(encoded_len), 0) FROM deposits {clause}");
    match indexes {
        [] => sql(tx.query_row(&query, [], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
        })),
        [index] => sql(tx.query_row(&query, params![index.as_slice()], |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
        })),
        _ => Err(invalid("unsupported mailbox count query")),
    }
}

fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    if id == [0u8; 16] {
        id[0] = 1;
    }
    id
}

fn resolve_existing_parent(path: &Path) -> io::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid("mailbox storage path has no file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(std::fs::canonicalize(parent)?.join(file_name))
}

fn load_or_create_key(path: &Path) -> io::Result<StorageKey> {
    let mut bytes = [0u8; 32];
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(invalid("mailbox service key is not a regular file"));
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("mailbox service key is not a regular file"));
            }
            require_owner_only_open_file(&file)?;
            file.read_exact(&mut bytes)?;
            let mut trailing = [0u8; 1];
            if file.read(&mut trailing)? != 0 {
                return Err(invalid("mailbox service key has the wrong length"));
            }
            Ok(StorageKey::from_bytes(bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            OsRng.fill_bytes(&mut bytes);
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("mailbox service key is not a regular file"));
            }
            protect_open_file(&file)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(StorageKey::from_bytes(bytes))
        }
        Err(error) => Err(error),
    }
}

fn require_owner_only_open_file(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(invalid("mailbox storage path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mailbox service key must be owner-only",
            ));
        }
    }
    Ok(())
}

fn protect_open_file(file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(invalid("mailbox storage path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn protect_file(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("mailbox storage path is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    protect_open_file(&file)
}

fn protect_sqlite_files(path: &Path) -> io::Result<()> {
    protect_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => protect_file(&sidecar)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8]) -> io::Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| invalid("mailbox database field has the wrong length"))
}

fn sql<T>(result: rusqlite::Result<T>) -> io::Result<T> {
    result.map_err(sql_error)
}

fn sql_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(format!("mailbox database: {error}"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn is_unique_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn configure(conn: &Connection) -> io::Result<()> {
    sql(conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA fullfsync = ON;
         PRAGMA checkpoint_fullfsync = ON;
         PRAGMA wal_autocheckpoint = 256;
         PRAGMA journal_size_limit = 16777216;
         PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA busy_timeout = 5000;",
    ))
}

fn create_schema(conn: &mut Connection) -> io::Result<[u8; 32]> {
    let mut database_id = [0u8; 32];
    OsRng.fill_bytes(&mut database_id);
    let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
    sql(tx.execute_batch(
        "CREATE TABLE mailbox_meta (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL,
             database_id BLOB NOT NULL CHECK (length(database_id) = 32)
         );
         CREATE TABLE registrations (
             token_idx BLOB PRIMARY KEY CHECK (length(token_idx) = 32),
             client_idx BLOB NOT NULL CHECK (length(client_idx) = 32),
             expires_at INTEGER NOT NULL,
             sealed BLOB NOT NULL
         );
         CREATE INDEX registrations_client ON registrations(client_idx);
         CREATE TABLE deposits (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             row_id BLOB NOT NULL UNIQUE CHECK (length(row_id) = 16),
             token_idx BLOB NOT NULL CHECK (length(token_idx) = 32),
             content_idx BLOB NOT NULL CHECK (length(content_idx) = 32),
             client_idx BLOB NOT NULL CHECK (length(client_idx) = 32),
             expires_at INTEGER NOT NULL,
             encoded_len INTEGER NOT NULL,
             sealed BLOB NOT NULL,
             UNIQUE(token_idx, content_idx)
         );
         CREATE INDEX deposits_token ON deposits(token_idx, sequence);
         CREATE INDEX deposits_client ON deposits(client_idx);
         CREATE INDEX deposits_expiry ON deposits(expires_at);
         CREATE TABLE leases (
             lease_id BLOB PRIMARY KEY CHECK (length(lease_id) = 16),
             client_idx BLOB NOT NULL CHECK (length(client_idx) = 32),
             filter_idx BLOB NOT NULL CHECK (length(filter_idx) = 32),
             created_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL,
             closed INTEGER NOT NULL CHECK (closed IN (0, 1)),
             sealed BLOB NOT NULL
         );
         CREATE INDEX leases_client_filter
             ON leases(client_idx, filter_idx, closed, expires_at);
         CREATE TABLE lease_rows (
             lease_id BLOB NOT NULL CHECK (length(lease_id) = 16),
             row_id BLOB NOT NULL CHECK (length(row_id) = 16),
             acknowledged INTEGER NOT NULL CHECK (acknowledged IN (0, 1)),
             sealed BLOB NOT NULL,
             PRIMARY KEY(lease_id, row_id),
             FOREIGN KEY(lease_id) REFERENCES leases(lease_id) ON DELETE CASCADE
         );
         CREATE INDEX lease_rows_row ON lease_rows(row_id, acknowledged);
         CREATE TABLE rate_buckets (
             client_idx BLOB PRIMARY KEY CHECK (length(client_idx) = 32),
             window_start INTEGER NOT NULL,
             requests INTEGER NOT NULL,
             sealed BLOB NOT NULL
         );",
    ))?;
    sql(tx.execute(
        "INSERT INTO mailbox_meta(singleton, schema_version, database_id)
         VALUES (1, ?1, ?2)",
        params![SCHEMA_VERSION, database_id.as_slice()],
    ))?;
    sql(tx.commit())?;
    Ok(database_id)
}

fn read_metadata(conn: &Connection) -> io::Result<[u8; 32]> {
    let (version, database_id) = sql(conn.query_row(
        "SELECT schema_version, database_id FROM mailbox_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ))?;
    if version != SCHEMA_VERSION {
        return Err(invalid("unsupported mailbox database schema"));
    }
    array::<32>(&database_id)
}

impl MailboxV2Store {
    fn deposit_inner(
        &mut self,
        client: &[u8],
        envelope: &Envelope,
        encoded: Vec<u8>,
        now: u64,
    ) -> io::Result<MailboxDepositDisposition> {
        let client_idx = self.client_index(client);
        let tx = sql(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        ))?;
        let expired = self.sweep_on(&tx, now)?;
        self.expired_rows = self.expired_rows.saturating_add(expired);
        if !self.rate_allowed_on(&tx, client_idx, now)? {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Refused);
        }
        if encoded.is_empty()
            || encoded.len() > MAX_ENVELOPE_BYTES
            || envelope.try_encode().ok().as_deref() != Some(encoded.as_slice())
        {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Refused);
        }
        let policy_expiry = now.saturating_add(self.config.envelope_ttl_secs);
        let expires_at = envelope
            .retention_until
            .map_or(policy_expiry, |hint| hint.min(policy_expiry));
        if expires_at <= now {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Refused);
        }

        let token_idx = self.token_index(&envelope.token);
        let content_id = envelope.content_id();
        let content_idx = self.content_index(&content_id);

        let registration = sql(tx
            .query_row(
                "SELECT client_idx, expires_at, sealed
                 FROM registrations WHERE token_idx = ?1",
                params![token_idx.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional())?;
        let Some((registered_client, registered_until, sealed)) = registration else {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Unregistered);
        };
        let registered_client = array::<32>(&registered_client)?;
        let record: RegistrationRecord = self.open_record(
            DOMAIN_REGISTRATION,
            &token_idx,
            &registration_binding(&registered_client, registered_until),
            &sealed,
        )?;
        validate_registration(
            &record,
            &envelope.token,
            &registered_client,
            registered_until,
        )?;
        if registered_until <= now {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Unregistered);
        }

        let duplicate = sql(tx
            .query_row(
                "SELECT row_id, client_idx, expires_at, sealed
                 FROM deposits WHERE token_idx = ?1 AND content_idx = ?2",
                params![token_idx.as_slice(), content_idx.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional())?;
        if let Some((row_id, stored_client, stored_expiry, sealed)) = duplicate {
            let row_id = array::<16>(&row_id)?;
            let stored_client = array::<32>(&stored_client)?;
            let stored = self.open_deposit(
                row_id,
                token_idx,
                content_idx,
                stored_client,
                stored_expiry,
                &sealed,
            )?;
            let same = stored.content_id == content_id && stored.envelope == encoded;
            sql(tx.commit())?;
            return Ok(if same {
                MailboxDepositDisposition::Accepted
            } else {
                MailboxDepositDisposition::Refused
            });
        }

        let (global_items, global_bytes) = count_and_bytes(&tx, "", &[])?;
        let (token_items, token_bytes) =
            count_and_bytes(&tx, "WHERE token_idx = ?1", &[token_idx])?;
        let (client_items, client_bytes) =
            count_and_bytes(&tx, "WHERE client_idx = ?1", &[client_idx])?;
        let encoded_len = u64::try_from(encoded.len()).map_err(|_| invalid("envelope length"))?;
        if global_items >= self.config.max_total_items as u64
            || global_bytes.saturating_add(encoded_len) > self.config.max_total_bytes as u64
            || token_items >= self.config.max_per_token as u64
            || token_bytes.saturating_add(encoded_len) > self.config.max_bytes_per_token as u64
            || client_items >= self.config.max_per_client as u64
            || client_bytes.saturating_add(encoded_len) > self.config.max_bytes_per_client as u64
        {
            sql(tx.commit())?;
            return Ok(MailboxDepositDisposition::Refused);
        }

        let mut inserted = false;
        for _ in 0..16 {
            let row_id = random_id();
            let record = DepositRecord {
                version: RECORD_VERSION,
                row_id,
                token_idx,
                content_id,
                client_idx,
                expires_at,
                envelope: encoded.clone(),
            };
            let sealed = self.seal(
                DOMAIN_DEPOSIT,
                &row_id,
                &deposit_binding(&token_idx, &content_idx, &client_idx, expires_at),
                &record,
            )?;
            let result = tx.execute(
                "INSERT INTO deposits(
                     row_id, token_idx, content_idx, client_idx,
                     expires_at, encoded_len, sealed
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    row_id.as_slice(),
                    token_idx.as_slice(),
                    content_idx.as_slice(),
                    client_idx.as_slice(),
                    expires_at,
                    encoded_len,
                    sealed
                ],
            );
            match result {
                Ok(1) => {
                    inserted = true;
                    break;
                }
                Ok(_) => return Err(invalid("mailbox deposit insert count")),
                Err(error) if is_unique_violation(&error) => continue,
                Err(error) => return Err(sql_error(error)),
            }
        }
        if !inserted {
            return Err(invalid("could not allocate a unique mailbox row id"));
        }
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::BeforeDepositCommit)?;
        sql(tx.commit())?;
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::AfterDepositCommit)?;
        Ok(MailboxDepositDisposition::Accepted)
    }

    fn lease_inner(
        &mut self,
        client: &[u8],
        tokens: &[[u8; 32]],
        now: u64,
    ) -> io::Result<Option<MailboxV2LeasePage>> {
        let client_idx = self.client_index(client);
        let tx = sql(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        ))?;
        let expired = self.sweep_on(&tx, now)?;
        self.expired_rows = self.expired_rows.saturating_add(expired);
        if !self.rate_allowed_on(&tx, client_idx, now)? {
            sql(tx.commit())?;
            return Ok(None);
        }
        if tokens.is_empty() || tokens.len() > crate::MAX_MAILBOX_CHECKIN_TOKENS {
            sql(tx.commit())?;
            return Ok(None);
        }
        let mut unique_tokens = tokens.to_vec();
        unique_tokens.sort_unstable();
        unique_tokens.dedup();
        let token_indexes: Vec<[u8; 32]> = unique_tokens
            .iter()
            .map(|token| self.token_index(token))
            .collect();
        let filter_idx = self.filter_index(&token_indexes);

        let total_registrations = sql(tx.query_row(
            "SELECT COUNT(*) FROM registrations",
            [],
            |row| row.get::<_, u64>(0),
        ))?;
        let owned_registrations = sql(tx.query_row(
            "SELECT COUNT(*) FROM registrations WHERE client_idx = ?1",
            params![client_idx.as_slice()],
            |row| row.get::<_, u64>(0),
        ))?;
        let mut new_global = 0u64;
        let mut newly_owned = 0u64;
        for token_idx in &token_indexes {
            let owner = sql(tx
                .query_row(
                    "SELECT client_idx FROM registrations WHERE token_idx = ?1",
                    params![token_idx.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional())?;
            match owner {
                None => {
                    new_global += 1;
                    newly_owned += 1;
                }
                Some(owner) if array::<32>(&owner)? != client_idx => newly_owned += 1,
                Some(_) => {}
            }
        }
        if total_registrations.saturating_add(new_global) > self.config.max_tokens as u64
            || owned_registrations.saturating_add(newly_owned)
                > self.config.max_tokens_per_client as u64
        {
            sql(tx.commit())?;
            return Ok(None);
        }

        let registration_expiry = now.saturating_add(self.config.registration_ttl_secs);
        for (token, token_idx) in unique_tokens.iter().zip(&token_indexes) {
            let record = RegistrationRecord {
                version: RECORD_VERSION,
                token: *token,
                client_idx,
                expires_at: registration_expiry,
            };
            let sealed = self.seal(
                DOMAIN_REGISTRATION,
                token_idx,
                &registration_binding(&client_idx, registration_expiry),
                &record,
            )?;
            sql(tx.execute(
                "INSERT INTO registrations(token_idx, client_idx, expires_at, sealed)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(token_idx) DO UPDATE SET
                     client_idx = excluded.client_idx,
                     expires_at = excluded.expires_at,
                     sealed = excluded.sealed",
                params![
                    token_idx.as_slice(),
                    client_idx.as_slice(),
                    registration_expiry,
                    sealed
                ],
            ))?;
        }

        let existing = sql(tx
            .query_row(
                "SELECT lease_id, created_at, expires_at, sealed
                 FROM leases
                 WHERE client_idx = ?1 AND filter_idx = ?2
                   AND closed = 0 AND expires_at > ?3
                 ORDER BY created_at LIMIT 1",
                params![client_idx.as_slice(), filter_idx.as_slice(), now],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional())?;
        if let Some((lease_id, created_at, expires_at, sealed)) = existing {
            let lease_id = array::<16>(&lease_id)?;
            let record = self.open_lease(
                LeaseColumns {
                    lease_id,
                    client_idx,
                    filter_idx,
                    created_at,
                    expires_at,
                    closed: false,
                },
                &sealed,
            )?;
            let rows = self.load_lease_rows_on(&tx, &record)?;
            sql(tx.commit())?;
            return Ok(Some(MailboxV2LeasePage {
                lease_id,
                expires_at,
                rows,
            }));
        }

        let live_total = sql(tx.query_row(
            "SELECT COUNT(*) FROM leases
             WHERE closed = 0 AND expires_at > ?1",
            params![now],
            |row| row.get::<_, u64>(0),
        ))?;
        if live_total >= self.config.max_live_leases as u64 {
            sql(tx.commit())?;
            return Ok(None);
        }
        let live_for_client = sql(tx.query_row(
            "SELECT COUNT(*) FROM leases
             WHERE client_idx = ?1 AND closed = 0 AND expires_at > ?2",
            params![client_idx.as_slice(), now],
            |row| row.get::<_, u64>(0),
        ))?;
        if live_for_client >= self.config.max_live_leases_per_client as u64 {
            sql(tx.commit())?;
            return Ok(None);
        }
        for token_idx in &token_indexes {
            let live_for_token = sql(tx.query_row(
                "SELECT COUNT(DISTINCT lr.lease_id)
                 FROM lease_rows lr
                 JOIN leases l ON l.lease_id = lr.lease_id
                 JOIN deposits d ON d.row_id = lr.row_id
                 WHERE d.token_idx = ?1 AND lr.acknowledged = 0
                   AND l.closed = 0 AND l.expires_at > ?2",
                params![token_idx.as_slice(), now],
                |row| row.get::<_, u64>(0),
            ))?;
            if live_for_token >= self.config.max_live_leases_per_token as u64 {
                sql(tx.commit())?;
                return Ok(None);
            }
        }

        let candidates = self.available_rows_on(&tx, &token_indexes, now)?;
        let expires_at = now.saturating_add(self.config.lease_ttl_secs);
        let lease_id = self.insert_lease_on(
            &tx,
            client_idx,
            filter_idx,
            now,
            expires_at,
            candidates.is_empty(),
        )?;
        for row in &candidates {
            let record = LeaseRowRecord {
                version: RECORD_VERSION,
                lease_id,
                row_id: row.row_id,
                acknowledged: false,
            };
            let sealed = self.seal(
                DOMAIN_LEASE_ROW,
                &lease_row_locator(&lease_id, &row.row_id),
                &[0],
                &record,
            )?;
            sql(tx.execute(
                "INSERT INTO lease_rows(lease_id, row_id, acknowledged, sealed)
                 VALUES (?1, ?2, 0, ?3)",
                params![lease_id.as_slice(), row.row_id.as_slice(), sealed],
            ))?;
        }
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::BeforeLeaseCommit)?;
        sql(tx.commit())?;
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::AfterLeaseCommit)?;
        Ok(Some(MailboxV2LeasePage {
            lease_id,
            expires_at,
            rows: candidates,
        }))
    }

    fn ack_inner(
        &mut self,
        client: &[u8],
        lease_id: [u8; 16],
        row_ids: &[[u8; 16]],
        now: u64,
    ) -> io::Result<bool> {
        let client_idx = self.client_index(client);
        let tx = sql(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        ))?;
        let expired = self.sweep_on(&tx, now)?;
        self.expired_rows = self.expired_rows.saturating_add(expired);
        if !self.rate_allowed_on(&tx, client_idx, now)? {
            sql(tx.commit())?;
            return Ok(false);
        }
        if lease_id == [0u8; 16] || row_ids.is_empty() || row_ids.len() > MAILBOX_V2_ACK_MAX_ROWS {
            sql(tx.commit())?;
            return Ok(false);
        }
        let mut unique = HashSet::with_capacity(row_ids.len());
        if row_ids.iter().any(|row_id| !unique.insert(*row_id)) {
            sql(tx.commit())?;
            return Ok(false);
        }

        let lease = sql(tx
            .query_row(
                "SELECT client_idx, filter_idx, created_at, expires_at, closed, sealed
                 FROM leases WHERE lease_id = ?1",
                params![lease_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional())?;
        let Some((stored_client, filter_idx, created_at, expires_at, closed, sealed)) = lease
        else {
            sql(tx.commit())?;
            return Ok(false);
        };
        let stored_client = array::<32>(&stored_client)?;
        if stored_client != client_idx {
            sql(tx.commit())?;
            return Ok(false);
        }
        let filter_idx = array::<32>(&filter_idx)?;
        let mut lease_record = self.open_lease(
            LeaseColumns {
                lease_id,
                client_idx: stored_client,
                filter_idx,
                created_at,
                expires_at,
                closed,
            },
            &sealed,
        )?;
        if lease_record.client_idx != client_idx || expires_at <= now {
            sql(tx.commit())?;
            return Ok(false);
        }

        let mut rows = Vec::with_capacity(row_ids.len());
        for row_id in row_ids {
            let mapping = sql(tx
                .query_row(
                    "SELECT acknowledged, sealed FROM lease_rows
                     WHERE lease_id = ?1 AND row_id = ?2",
                    params![lease_id.as_slice(), row_id.as_slice()],
                    |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional())?;
            let Some((acknowledged, sealed)) = mapping else {
                sql(tx.commit())?;
                return Ok(false);
            };
            let record: LeaseRowRecord = self.open_record(
                DOMAIN_LEASE_ROW,
                &lease_row_locator(&lease_id, row_id),
                &[u8::from(acknowledged)],
                &sealed,
            )?;
            if record.version != RECORD_VERSION
                || record.lease_id != lease_id
                || record.row_id != *row_id
                || record.acknowledged != acknowledged
            {
                return Err(invalid("mailbox lease-row binding mismatch"));
            }
            rows.push((*row_id, acknowledged));
        }

        for (row_id, acknowledged) in rows {
            if acknowledged {
                continue;
            }
            #[cfg(test)]
            self.check_failpoint(MailboxStoreFailpoint::BeforeAckDelete)?;
            if sql(tx.execute(
                "DELETE FROM deposits WHERE row_id = ?1",
                params![row_id.as_slice()],
            ))? != 1
            {
                return Err(invalid(
                    "leased mailbox row disappeared before acknowledgement",
                ));
            }
            let record = LeaseRowRecord {
                version: RECORD_VERSION,
                lease_id,
                row_id,
                acknowledged: true,
            };
            let sealed = self.seal(
                DOMAIN_LEASE_ROW,
                &lease_row_locator(&lease_id, &row_id),
                &[1],
                &record,
            )?;
            if sql(tx.execute(
                "UPDATE lease_rows SET acknowledged = 1, sealed = ?3
                 WHERE lease_id = ?1 AND row_id = ?2",
                params![lease_id.as_slice(), row_id.as_slice(), sealed],
            ))? != 1
            {
                return Err(invalid("mailbox lease-row acknowledgement mismatch"));
            }
        }
        let remaining = sql(tx.query_row(
            "SELECT COUNT(*) FROM lease_rows
             WHERE lease_id = ?1 AND acknowledged = 0",
            params![lease_id.as_slice()],
            |row| row.get::<_, u64>(0),
        ))?;
        if remaining == 0 && !lease_record.closed {
            lease_record.closed = true;
            let sealed = self.seal(
                DOMAIN_LEASE,
                &lease_id,
                &lease_binding(&client_idx, &filter_idx, created_at, expires_at, true),
                &lease_record,
            )?;
            if sql(tx.execute(
                "UPDATE leases SET closed = 1, sealed = ?2 WHERE lease_id = ?1",
                params![lease_id.as_slice(), sealed],
            ))? != 1
            {
                return Err(invalid("mailbox lease close mismatch"));
            }
        }
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::BeforeAckCommit)?;
        sql(tx.commit())?;
        #[cfg(test)]
        self.check_failpoint(MailboxStoreFailpoint::AfterAckCommit)?;
        Ok(true)
    }
}
