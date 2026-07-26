//! Inactive ADR-0027 migration-target foundation.
//!
//! The public [`crate::Store`] continues to open only the complete legacy
//! schema. This module gives the future all-table sibling migration one
//! independently testable destination format without rewriting any existing
//! user database or allowing callers to assemble raw index/row domains.

use std::collections::BTreeSet;
use std::fs::File;
use std::path::Path;

use rand_core::CryptoRngCore;
use rusqlite::{
    params, Connection, ErrorCode, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::StorageKey;

use crate::{acquire_database_identity_lock, acquire_store_lock, Result, StoreError};

const APPLICATION_ID: u32 = 0x4b53_5632;
const SCHEMA_VERSION: u32 = 2;
const METADATA_RECORD_VERSION: u8 = 1;
const LOGICAL_RECORD_VERSION: u8 = 1;
const MAX_MIGRATIONS: usize = 64;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const ROW_LOCATOR_ATTEMPTS: usize = 16;

const METADATA_AD: &[u8] = b"Komms-Store-Metadata-v2";
const INDEX_INPUT_DOMAIN: &[u8] = b"Komms-Store-Index-v2";
const INDEX_KEY_DOMAIN: &[u8] = b"Komms-Store-Index-Key-v2";
const ROW_KEY_DOMAIN: &[u8] = b"Komms-Store-Row-Key-v2";
const ROW_AD_DOMAIN: &[u8] = b"Komms-Store-Row-v2";
const FOUNDATION_MIGRATION_ID: [u8; 16] = *b"opaque-store-v2!";

const METADATA_TABLE_SCHEMA: &str = "CREATE TABLE store_v2_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    blob BLOB NOT NULL
) STRICT";
const RECORDS_TABLE_SCHEMA: &str = "CREATE TABLE store_v2_records (
    rowid_ INTEGER PRIMARY KEY,
    table_domain INTEGER NOT NULL,
    locator BLOB NOT NULL CHECK (length(locator) IN (16, 32)),
    blob BLOB NOT NULL
) STRICT";
const RECORD_LOCATOR_INDEX_SCHEMA: &str = "CREATE UNIQUE INDEX store_v2_record_locator
    ON store_v2_records (table_domain, locator)";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationEntry {
    id: [u8; 16],
    from_version: u32,
    to_version: u32,
    completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DatabaseMetadata {
    database_id: [u8; 32],
    schema_version: u32,
    migrations: Vec<MigrationEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocatorKind {
    Equality,
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// Closed set of v2 table domains; callers never provide raw domain bytes.
enum TableDomain {
    /// Contact equality records.
    Contacts = 1,
    /// Session-scoped capability equality records.
    Capabilities = 2,
    /// Append-only pairwise history records.
    Messages = 3,
}

impl TableDomain {
    fn from_sql(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::Contacts),
            2 => Ok(Self::Capabilities),
            3 => Ok(Self::Messages),
            _ => Err(StoreError::SchemaMismatch),
        }
    }

    fn locator_kind(self) -> LocatorKind {
        match self {
            Self::Contacts | Self::Capabilities => LocatorKind::Equality,
            Self::Messages => LocatorKind::Random,
        }
    }

    fn key_kind(self) -> u8 {
        match self {
            Self::Contacts | Self::Capabilities => AccountKey::KIND,
            Self::Messages => MessageKey::KIND,
        }
    }

    fn expected_key_len(self) -> usize {
        match self {
            Self::Contacts | Self::Capabilities => AccountKey::ENCODED_LEN,
            Self::Messages => MessageKey::ENCODED_LEN,
        }
    }
}

/// Closed canonical logical-key encoding used inside sealed records.
trait CanonicalLogicalKey {
    /// Encode the type byte followed by the key's fixed-width fields.
    fn encode(&self) -> Vec<u8>;
}

/// Table marker binding one logical key type to one fixed table domain.
trait RecordTable {
    /// Exact logical key accepted by this table.
    type Key: CanonicalLogicalKey;

    /// Fixed domain used for key derivation, SQLite classification, and AD.
    const DOMAIN: TableDomain;
}

/// Marker for a table whose locator is a keyed equality index.
trait EqualityTable: RecordTable {}
/// Marker for a table whose locator is freshly random for every row.
trait AppendTable: RecordTable {}

/// Typed account identity used by v2 equality-index tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountKey([u8; 32]);

impl AccountKey {
    const KIND: u8 = 1;
    const ENCODED_LEN: usize = 1 + 32;

    /// Bind an exact account public key to the account-key logical domain.
    pub fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl CanonicalLogicalKey for AccountKey {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::ENCODED_LEN);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.0);
        encoded
    }
}

/// Typed immutable message identity used inside append-only v2 records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageKey {
    conversation: [u8; 32],
    message_id: [u8; 16],
}

impl MessageKey {
    const KIND: u8 = 2;
    const ENCODED_LEN: usize = 1 + 32 + 16;

    /// Bind one message id to its exact pairwise conversation.
    pub fn new(conversation: [u8; 32], message_id: [u8; 16]) -> Self {
        Self {
            conversation,
            message_id,
        }
    }
}

impl CanonicalLogicalKey for MessageKey {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::ENCODED_LEN);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.conversation);
        encoded.extend_from_slice(&self.message_id);
        encoded
    }
}

/// Contact-table marker; its physical locator is a keyed account index.
struct ContactRecords;

impl RecordTable for ContactRecords {
    type Key = AccountKey;

    const DOMAIN: TableDomain = TableDomain::Contacts;
}

impl EqualityTable for ContactRecords {}

/// Capability-table marker; it derives an index unrelated to contacts.
struct CapabilityRecords;

impl RecordTable for CapabilityRecords {
    type Key = AccountKey;

    const DOMAIN: TableDomain = TableDomain::Capabilities;
}

impl EqualityTable for CapabilityRecords {}

/// Pairwise history marker; append rows use random locators.
struct MessageRecords;

impl RecordTable for MessageRecords {
    type Key = MessageKey;

    const DOMAIN: TableDomain = TableDomain::Messages;
}

impl AppendTable for MessageRecords {}

/// Opaque random locator returned for one append-only row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowLocator([u8; 16]);

impl RowLocator {
    /// The locator bytes are safe to pass back only to this database.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

struct DecodedRecord<'a> {
    logical_key: &'a [u8],
    payload: &'a [u8],
}

/// Unconstructable outside `kult-store`; gates the inactive migration target.
///
/// The complete sibling migrator will construct this token inside this module
/// when it is ready to activate the destination atomically.
pub struct MigrationAuthority {
    private: (),
}

/// A complete but inactive v2 destination used by the future sibling migration.
///
/// It deliberately takes an already available master key. Passphrase wrapping,
/// backup restore, and atomic path replacement remain responsibilities of the
/// all-table migration and are not activated by this foundation.
pub struct MigrationTarget {
    conn: Connection,
    metadata: DatabaseMetadata,
    index_root: StorageKey,
    row_root: StorageKey,
    _database_lock: Option<File>,
    _lock: File,
}

impl MigrationTarget {
    /// Create one empty v2 migration destination without touching a legacy store.
    pub fn create(
        authority: &MigrationAuthority,
        path: &Path,
        master: &StorageKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let () = authority.private;
        let lock = acquire_store_lock(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        protect_database_file(path)?;
        let database_lock = acquire_database_identity_lock(path)?;
        if user_object_count(&conn)? != 0 {
            return Err(StoreError::NotAStore);
        }

        let mut database_id = [0u8; 32];
        rng.fill_bytes(&mut database_id);
        if database_id == [0; 32] {
            return Err(StoreError::SchemaMismatch);
        }
        let metadata = DatabaseMetadata {
            database_id,
            schema_version: SCHEMA_VERSION,
            migrations: vec![MigrationEntry {
                id: FOUNDATION_MIGRATION_ID,
                from_version: 0,
                to_version: SCHEMA_VERSION,
                completed: true,
            }],
        };
        let metadata_key = master.derive(b"KK-store-v2-metadata");
        let sealed_metadata = seal_metadata(&metadata_key, &metadata, rng)?;

        let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)?;
        tx.execute_batch(METADATA_TABLE_SCHEMA)?;
        tx.execute_batch(RECORDS_TABLE_SCHEMA)?;
        tx.execute_batch(RECORD_LOCATOR_INDEX_SCHEMA)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.execute(
            "INSERT INTO store_v2_metadata (id, blob) VALUES (1, ?1)",
            params![sealed_metadata],
        )?;
        tx.commit()?;

        let target = Self {
            conn,
            metadata,
            index_root: master.derive(b"KK-store-v2-index-root"),
            row_root: master.derive(b"KK-store-v2-row-root"),
            _database_lock: database_lock,
            _lock: lock,
        };
        target.validate_complete()?;
        Ok(target)
    }

    /// Open and fully validate one completed v2 migration destination.
    pub fn open(authority: &MigrationAuthority, path: &Path, master: &StorageKey) -> Result<Self> {
        let () = authority.private;
        let lock = acquire_store_lock(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let database_lock = acquire_database_identity_lock(path)?;
        validate_preamble(&conn)?;
        validate_table_names(&conn)?;
        let metadata_key = master.derive(b"KK-store-v2-metadata");
        let metadata = read_metadata(&conn, &metadata_key)?;
        validate_metadata(&metadata, physical_schema_version(&conn)?)?;

        let target = Self {
            conn,
            metadata,
            index_root: master.derive(b"KK-store-v2-index-root"),
            row_root: master.derive(b"KK-store-v2-row-root"),
            _database_lock: database_lock,
            _lock: lock,
        };
        target.validate_complete()?;
        Ok(target)
    }

    /// Random identity authenticated inside this database's metadata.
    pub fn database_id(&self) -> [u8; 32] {
        self.metadata.database_id
    }

    /// Explicit physical and authenticated schema version.
    pub fn schema_version(&self) -> u32 {
        self.metadata.schema_version
    }

    /// Insert one contact record under a table-separated keyed account index.
    pub fn insert_contact(
        &self,
        key: &AccountKey,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.insert_equality::<ContactRecords>(key, payload, rng)
    }

    /// Read one contact record and recheck its inner account key.
    pub fn contact(&self, key: &AccountKey) -> Result<Option<Vec<u8>>> {
        self.get_equality::<ContactRecords>(key)
    }

    /// Insert one capability record under a domain distinct from contacts.
    pub fn insert_capability(
        &self,
        key: &AccountKey,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.insert_equality::<CapabilityRecords>(key, payload, rng)
    }

    /// Read one capability record and recheck its inner account key.
    pub fn capability(&self, key: &AccountKey) -> Result<Option<Vec<u8>>> {
        self.get_equality::<CapabilityRecords>(key)
    }

    /// Append one message record under a fresh random row locator.
    pub fn append_message(
        &self,
        key: &MessageKey,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<RowLocator> {
        self.insert_append::<MessageRecords>(key, payload, rng)
    }

    /// Read an append-only message by opaque locator and expected logical key.
    pub fn message(
        &self,
        locator: &RowLocator,
        expected_key: &MessageKey,
    ) -> Result<Option<Vec<u8>>> {
        self.get_append::<MessageRecords>(locator, expected_key)
    }

    fn insert_equality<T: EqualityTable>(
        &self,
        key: &T::Key,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let locator = self.equality_index::<T>(key);
        let plain = encode_record(key, payload)?;
        let sealed = self.seal_row(T::DOMAIN, &locator, &plain, rng);
        match self.conn.execute(
            "INSERT INTO store_v2_records (table_domain, locator, blob)
             VALUES (?1, ?2, ?3)",
            params![T::DOMAIN as u8, locator.as_slice(), sealed],
        ) {
            Ok(_) => Ok(()),
            Err(error) if constraint_violation(&error) => Err(StoreError::DuplicateIndex),
            Err(error) => Err(StoreError::Db(error)),
        }
    }

    /// Read one typed equality record and recheck its inner logical key.
    fn get_equality<T: EqualityTable>(&self, key: &T::Key) -> Result<Option<Vec<u8>>> {
        let locator = self.equality_index::<T>(key);
        self.read_exact(T::DOMAIN, &locator, key)
    }

    /// Append one typed record under a fresh random row locator.
    fn insert_append<T: AppendTable>(
        &self,
        key: &T::Key,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<RowLocator> {
        let plain = encode_record(key, payload)?;
        for _ in 0..ROW_LOCATOR_ATTEMPTS {
            let mut locator = [0u8; 16];
            rng.fill_bytes(&mut locator);
            let sealed = self.seal_row(T::DOMAIN, &locator, &plain, rng);
            match self.conn.execute(
                "INSERT INTO store_v2_records (table_domain, locator, blob)
                 VALUES (?1, ?2, ?3)",
                params![T::DOMAIN as u8, locator.as_slice(), sealed],
            ) {
                Ok(_) => return Ok(RowLocator(locator)),
                Err(error) if constraint_violation(&error) => continue,
                Err(error) => return Err(StoreError::Db(error)),
            }
        }
        Err(StoreError::DuplicateIndex)
    }

    /// Read an append-only row by its opaque locator and expected logical key.
    fn get_append<T: AppendTable>(
        &self,
        locator: &RowLocator,
        expected_key: &T::Key,
    ) -> Result<Option<Vec<u8>>> {
        self.read_exact(T::DOMAIN, locator.as_bytes(), expected_key)
    }

    fn read_exact<K: CanonicalLogicalKey>(
        &self,
        domain: TableDomain,
        locator: &[u8],
        expected_key: &K,
    ) -> Result<Option<Vec<u8>>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM store_v2_records
                 WHERE table_domain = ?1 AND locator = ?2",
                params![domain as u8, locator],
                |row| row.get(0),
            )
            .optional()?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let plain = Zeroizing::new(self.open_row(domain, locator, &sealed)?);
        let decoded = decode_record(&plain)?;
        validate_logical_key(domain, decoded.logical_key)?;
        let expected_key = expected_key.encode();
        if decoded.logical_key != expected_key.as_slice() {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Some(decoded.payload.to_vec()))
    }

    fn equality_index<T: EqualityTable>(&self, key: &T::Key) -> [u8; 32] {
        self.index_for(T::DOMAIN, &key.encode())
    }

    fn index_for(&self, domain: TableDomain, logical_key: &[u8]) -> [u8; 32] {
        let mut key_label =
            Vec::with_capacity(INDEX_KEY_DOMAIN.len() + 32 + core::mem::size_of::<u8>());
        key_label.extend_from_slice(INDEX_KEY_DOMAIN);
        key_label.extend_from_slice(&self.metadata.database_id);
        key_label.push(domain as u8);
        let table_key = self.index_root.derive(&key_label);

        let mut input = Vec::with_capacity(INDEX_INPUT_DOMAIN.len() + logical_key.len());
        input.extend_from_slice(INDEX_INPUT_DOMAIN);
        input.extend_from_slice(logical_key);
        table_key.hmac_sha256(&input)
    }

    fn row_key(&self, domain: TableDomain) -> StorageKey {
        let mut label = Vec::with_capacity(ROW_KEY_DOMAIN.len() + 32 + 1);
        label.extend_from_slice(ROW_KEY_DOMAIN);
        label.extend_from_slice(&self.metadata.database_id);
        label.push(domain as u8);
        self.row_root.derive(&label)
    }

    fn row_ad(&self, domain: TableDomain, locator: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(ROW_AD_DOMAIN.len() + 32 + 4 + 1 + locator.len());
        ad.extend_from_slice(ROW_AD_DOMAIN);
        ad.extend_from_slice(&self.metadata.database_id);
        ad.extend_from_slice(&self.metadata.schema_version.to_be_bytes());
        ad.push(domain as u8);
        ad.extend_from_slice(locator);
        ad
    }

    fn seal_row(
        &self,
        domain: TableDomain,
        locator: &[u8],
        plain: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<u8> {
        self.row_key(domain)
            .seal(&self.row_ad(domain, locator), plain, rng)
    }

    fn open_row(&self, domain: TableDomain, locator: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .row_key(domain)
            .open(&self.row_ad(domain, locator), sealed)?)
    }

    fn validate_complete(&self) -> Result<()> {
        validate_preamble(&self.conn)?;
        validate_table_names(&self.conn)?;
        validate_metadata(&self.metadata, physical_schema_version(&self.conn)?)?;
        validate_duplicate_locators(&self.conn)?;
        validate_columns_and_indexes(&self.conn)?;
        self.validate_rows()
    }

    fn validate_rows(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT table_domain, locator, blob
             FROM store_v2_records ORDER BY rowid_",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        for row in rows {
            let (domain, locator, sealed) = row?;
            let domain = TableDomain::from_sql(domain)?;
            validate_locator(domain, &locator)?;
            let plain = Zeroizing::new(self.open_row(domain, &locator, &sealed)?);
            let decoded = decode_record(&plain)?;
            validate_logical_key(domain, decoded.logical_key)?;
            if domain.locator_kind() == LocatorKind::Equality
                && self.index_for(domain, decoded.logical_key).as_slice() != locator.as_slice()
            {
                return Err(StoreError::LogicalKeyMismatch);
            }
        }
        Ok(())
    }
}

pub(crate) fn is_inactive_migration_target(conn: &Connection) -> Result<bool> {
    let application_id: u32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id == APPLICATION_ID {
        return Ok(true);
    }
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE name IN ('store_v2_metadata', 'store_v2_records')
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn encode_record<K: CanonicalLogicalKey>(key: &K, payload: &[u8]) -> Result<Vec<u8>> {
    let logical_key = key.encode();
    let key_len = u16::try_from(logical_key.len()).map_err(|_| StoreError::RecordBounds)?;
    let total = 1usize
        .checked_add(2)
        .and_then(|value| value.checked_add(logical_key.len()))
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(StoreError::RecordBounds)?;
    if total > MAX_RECORD_BYTES {
        return Err(StoreError::RecordBounds);
    }
    let mut plain = Vec::with_capacity(total);
    plain.push(LOGICAL_RECORD_VERSION);
    plain.extend_from_slice(&key_len.to_be_bytes());
    plain.extend_from_slice(&logical_key);
    plain.extend_from_slice(payload);
    Ok(plain)
}

fn decode_record(plain: &[u8]) -> Result<DecodedRecord<'_>> {
    let Some((&version, remainder)) = plain.split_first() else {
        return Err(StoreError::Serialization);
    };
    if version != LOGICAL_RECORD_VERSION {
        return Err(StoreError::UnsupportedRecordVersion);
    }
    if remainder.len() < 2 {
        return Err(StoreError::Serialization);
    }
    let key_len = usize::from(u16::from_be_bytes(
        remainder[..2]
            .try_into()
            .map_err(|_| StoreError::Serialization)?,
    ));
    let body = &remainder[2..];
    if key_len > body.len() {
        return Err(StoreError::Serialization);
    }
    let (logical_key, payload) = body.split_at(key_len);
    Ok(DecodedRecord {
        logical_key,
        payload,
    })
}

fn validate_logical_key(domain: TableDomain, logical_key: &[u8]) -> Result<()> {
    if logical_key.len() != domain.expected_key_len()
        || logical_key.first().copied() != Some(domain.key_kind())
    {
        return Err(StoreError::LogicalKeyMismatch);
    }
    Ok(())
}

fn validate_locator(domain: TableDomain, locator: &[u8]) -> Result<()> {
    let expected = match domain.locator_kind() {
        LocatorKind::Equality => 32,
        LocatorKind::Random => 16,
    };
    if locator.len() != expected {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn seal_metadata(
    key: &StorageKey,
    metadata: &DatabaseMetadata,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let encoded = postcard::to_allocvec(metadata).map_err(|_| StoreError::Serialization)?;
    let mut plain = Vec::with_capacity(1 + encoded.len());
    plain.push(METADATA_RECORD_VERSION);
    plain.extend_from_slice(&encoded);
    Ok(key.seal(METADATA_AD, &plain, rng))
}

fn open_metadata(key: &StorageKey, sealed: &[u8]) -> Result<DatabaseMetadata> {
    let plain = Zeroizing::new(key.open(METADATA_AD, sealed)?);
    let Some((&version, encoded)) = plain.split_first() else {
        return Err(StoreError::Serialization);
    };
    if version > METADATA_RECORD_VERSION {
        return Err(StoreError::FutureSchema);
    }
    if version != METADATA_RECORD_VERSION {
        return Err(StoreError::Serialization);
    }
    let (metadata, remainder): (DatabaseMetadata, &[u8]) =
        postcard::take_from_bytes(encoded).map_err(|_| StoreError::Serialization)?;
    if !remainder.is_empty() {
        return Err(StoreError::Serialization);
    }
    Ok(metadata)
}

fn read_metadata(conn: &Connection, key: &StorageKey) -> Result<DatabaseMetadata> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM store_v2_metadata", [], |row| {
        row.get(0)
    })?;
    if count != 1 {
        return Err(StoreError::SchemaMismatch);
    }
    let sealed: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob FROM store_v2_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    open_metadata(key, &sealed.ok_or(StoreError::SchemaMismatch)?)
}

fn validate_metadata(metadata: &DatabaseMetadata, physical_version: u32) -> Result<()> {
    if metadata.schema_version > SCHEMA_VERSION || physical_version > SCHEMA_VERSION {
        return Err(StoreError::FutureSchema);
    }
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.schema_version != physical_version
        || metadata.database_id == [0; 32]
    {
        return Err(StoreError::SchemaMismatch);
    }
    if metadata.migrations.is_empty() || metadata.migrations.len() > MAX_MIGRATIONS {
        return Err(StoreError::InvalidMigrationLedger);
    }

    let mut seen = BTreeSet::new();
    let mut current = 0u32;
    for migration in &metadata.migrations {
        if !seen.insert(migration.id) {
            return Err(StoreError::DuplicateMigration);
        }
        if !migration.completed {
            return Err(StoreError::IncompleteMigration);
        }
        if migration.id != FOUNDATION_MIGRATION_ID {
            return Err(StoreError::InvalidMigrationLedger);
        }
        if migration.from_version != current || migration.to_version <= migration.from_version {
            return Err(StoreError::InvalidMigrationLedger);
        }
        current = migration.to_version;
    }
    if current != metadata.schema_version {
        return Err(StoreError::InvalidMigrationLedger);
    }
    Ok(())
}

fn validate_preamble(conn: &Connection) -> Result<()> {
    let application_id: u32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::SchemaMismatch);
    }
    let version = physical_schema_version(conn)?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::FutureSchema);
    }
    if version != SCHEMA_VERSION {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn physical_schema_version(conn: &Connection) -> Result<u32> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

fn user_object_count(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?)
}

fn validate_table_names(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if tables != ["store_v2_metadata", "store_v2_records"] {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn validate_duplicate_locators(conn: &Connection) -> Result<()> {
    let duplicate: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM store_v2_records
             GROUP BY table_domain, locator HAVING COUNT(*) > 1 LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if duplicate.is_some() {
        return Err(StoreError::DuplicateIndex);
    }
    Ok(())
}

fn validate_columns_and_indexes(conn: &Connection) -> Result<()> {
    validate_schema_sql(conn)?;
    validate_columns(
        conn,
        "store_v2_metadata",
        &[("id", "INTEGER", 0, 1), ("blob", "BLOB", 1, 0)],
    )?;
    validate_columns(
        conn,
        "store_v2_records",
        &[
            ("rowid_", "INTEGER", 0, 1),
            ("table_domain", "INTEGER", 1, 0),
            ("locator", "BLOB", 1, 0),
            ("blob", "BLOB", 1, 0),
        ],
    )?;

    let mut statement = conn.prepare("PRAGMA index_list('store_v2_records')")?;
    let indexes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if indexes != [("store_v2_record_locator".to_owned(), 1, "c".to_owned(), 0)] {
        return Err(StoreError::SchemaMismatch);
    }

    let mut statement = conn.prepare("PRAGMA index_info('store_v2_record_locator')")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns != ["table_domain", "locator"] {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn validate_schema_sql(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare(
        "SELECT type, name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = [
        (
            "table".to_owned(),
            "store_v2_metadata".to_owned(),
            METADATA_TABLE_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_v2_record_locator".to_owned(),
            RECORD_LOCATOR_INDEX_SCHEMA.to_owned(),
        ),
        (
            "table".to_owned(),
            "store_v2_records".to_owned(),
            RECORDS_TABLE_SCHEMA.to_owned(),
        ),
    ];
    if objects != expected {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn validate_columns(
    conn: &Connection,
    table: &str,
    expected: &[(&str, &str, i64, i64)],
) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info('{table}')"))?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .map(|(name, kind, not_null, primary_key)| {
            (
                (*name).to_owned(),
                (*kind).to_owned(),
                *not_null,
                *primary_key,
            )
        })
        .collect::<Vec<_>>();
    if columns != expected {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

fn constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(unix)]
fn protect_database_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn protect_database_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::Store;

    const MASTER_BYTES: [u8; 32] = [0x51; 32];

    fn master() -> StorageKey {
        StorageKey::from_bytes(MASTER_BYTES)
    }

    fn target_at(path: &Path, seed: u64) -> (MigrationTarget, StdRng) {
        let mut rng = StdRng::seed_from_u64(seed);
        let target = MigrationTarget::create(
            &MigrationAuthority { private: () },
            path,
            &master(),
            &mut rng,
        )
        .unwrap();
        (target, rng)
    }

    fn open_target(path: &Path, master: &StorageKey) -> Result<MigrationTarget> {
        MigrationTarget::open(&MigrationAuthority { private: () }, path, master)
    }

    fn rewrite_metadata(path: &Path, seed: u64, mutate: impl FnOnce(&mut DatabaseMetadata)) {
        let conn = Connection::open(path).unwrap();
        let metadata_key = master().derive(b"KK-store-v2-metadata");
        let sealed: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM store_v2_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut metadata = open_metadata(&metadata_key, &sealed).unwrap();
        mutate(&mut metadata);
        let mut rng = StdRng::seed_from_u64(seed);
        let sealed = seal_metadata(&metadata_key, &metadata, &mut rng).unwrap();
        conn.execute(
            "UPDATE store_v2_metadata SET blob = ?1 WHERE id = 1",
            params![sealed],
        )
        .unwrap();
    }

    fn contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn authenticated_metadata_indexes_and_random_rows_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first-v2.db");
        let second_path = directory.path().join("second-v2.db");
        let account = AccountKey::new([0x11; 32]);
        let message = MessageKey::new([0x11; 32], [0x22; 16]);

        let (first, mut first_rng) = target_at(&first_path, 0x2701);
        let (second, mut second_rng) = target_at(&second_path, 0x2702);
        assert_eq!(first.schema_version(), SCHEMA_VERSION);
        assert_eq!(second.schema_version(), SCHEMA_VERSION);
        assert_ne!(first.database_id(), [0; 32]);
        assert_ne!(first.database_id(), second.database_id());

        let contact_index = first.equality_index::<ContactRecords>(&account);
        let capability_index = first.equality_index::<CapabilityRecords>(&account);
        let other_database_index = second.equality_index::<ContactRecords>(&account);
        assert_ne!(contact_index, capability_index);
        assert_ne!(contact_index, other_database_index);

        first
            .insert_contact(&account, b"contact payload", &mut first_rng)
            .unwrap();
        first
            .insert_capability(&account, b"capability payload", &mut first_rng)
            .unwrap();
        let first_row = first
            .append_message(&message, b"first message", &mut first_rng)
            .unwrap();
        let second_row = first
            .append_message(&message, b"second message", &mut first_rng)
            .unwrap();
        assert_ne!(first_row, second_row);
        assert_eq!(
            first.contact(&account).unwrap(),
            Some(b"contact payload".to_vec())
        );
        assert_eq!(
            first.capability(&account).unwrap(),
            Some(b"capability payload".to_vec())
        );
        assert_eq!(
            first.message(&first_row, &message).unwrap(),
            Some(b"first message".to_vec())
        );
        assert_eq!(
            first.message(&second_row, &message).unwrap(),
            Some(b"second message".to_vec())
        );

        second
            .insert_contact(&account, b"same key", &mut second_rng)
            .unwrap();
        drop(first);
        drop(second);

        let reopened = open_target(&first_path, &master()).unwrap();
        assert_eq!(
            reopened.contact(&account).unwrap(),
            Some(b"contact payload".to_vec())
        );
        assert_eq!(
            reopened.message(&first_row, &message).unwrap(),
            Some(b"first message".to_vec())
        );
    }

    #[test]
    fn legacy_entry_points_refuse_the_inactive_target_without_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inactive-v2.db");
        let (target, _) = target_at(&path, 0x2703);
        drop(target);
        let before = std::fs::read(&path).unwrap();

        assert!(matches!(
            Store::open(&path, b"irrelevant"),
            Err(StoreError::SchemaMismatch)
        ));
        let mut rng = StdRng::seed_from_u64(0x2704);
        assert!(matches!(
            Store::create(
                &path,
                b"irrelevant",
                kult_crypto::KdfProfile {
                    m_cost_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                &mut rng,
            ),
            Err(StoreError::SchemaMismatch)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let reopened = open_target(&path, &master()).unwrap();
        assert_eq!(reopened.schema_version(), SCHEMA_VERSION);
    }

    #[test]
    fn future_and_disagreeing_schema_fixtures_fail_closed() {
        let directory = tempfile::tempdir().unwrap();

        let future_physical = directory.path().join("future-physical.db");
        let (target, _) = target_at(&future_physical, 0x2710);
        drop(target);
        Connection::open(&future_physical)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            open_target(&future_physical, &master()),
            Err(StoreError::FutureSchema)
        ));

        let future_metadata = directory.path().join("future-metadata.db");
        let (target, _) = target_at(&future_metadata, 0x2711);
        drop(target);
        rewrite_metadata(&future_metadata, 0x2712, |metadata| {
            metadata.schema_version = SCHEMA_VERSION + 1;
            metadata.migrations[0].to_version = SCHEMA_VERSION + 1;
        });
        assert!(matches!(
            open_target(&future_metadata, &master()),
            Err(StoreError::FutureSchema)
        ));

        let older_metadata = directory.path().join("older-metadata.db");
        let (target, _) = target_at(&older_metadata, 0x2713);
        drop(target);
        rewrite_metadata(&older_metadata, 0x2714, |metadata| {
            metadata.schema_version = SCHEMA_VERSION - 1;
            metadata.migrations[0].to_version = SCHEMA_VERSION - 1;
        });
        assert!(matches!(
            open_target(&older_metadata, &master()),
            Err(StoreError::SchemaMismatch)
        ));

        let older_physical = directory.path().join("older-physical.db");
        let (target, _) = target_at(&older_physical, 0x2715);
        drop(target);
        Connection::open(&older_physical)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION - 1)
            .unwrap();
        assert!(matches!(
            open_target(&older_physical, &master()),
            Err(StoreError::SchemaMismatch)
        ));

        let drifted_schema = directory.path().join("drifted-schema.db");
        let (target, _) = target_at(&drifted_schema, 0x2716);
        drop(target);
        Connection::open(&drifted_schema)
            .unwrap()
            .execute_batch("DROP INDEX store_v2_record_locator")
            .unwrap();
        assert!(matches!(
            open_target(&drifted_schema, &master()),
            Err(StoreError::SchemaMismatch)
        ));

        let non_strict_schema = directory.path().join("non-strict-schema.db");
        let (target, _) = target_at(&non_strict_schema, 0x2717);
        drop(target);
        Connection::open(&non_strict_schema)
            .unwrap()
            .execute_batch(
                "ALTER TABLE store_v2_records RENAME TO store_v2_records_old;
                 DROP TABLE store_v2_records_old;
                 CREATE TABLE store_v2_records (
                     rowid_ INTEGER PRIMARY KEY,
                     table_domain INTEGER NOT NULL,
                     locator BLOB NOT NULL,
                     blob BLOB NOT NULL
                 );
                 CREATE UNIQUE INDEX store_v2_record_locator
                     ON store_v2_records (table_domain, locator);",
            )
            .unwrap();
        assert!(matches!(
            open_target(&non_strict_schema, &master()),
            Err(StoreError::SchemaMismatch)
        ));
    }

    #[test]
    fn incomplete_duplicate_and_discontinuous_migration_fixtures_fail_closed() {
        let directory = tempfile::tempdir().unwrap();

        let incomplete = directory.path().join("incomplete.db");
        let (target, _) = target_at(&incomplete, 0x2720);
        drop(target);
        rewrite_metadata(&incomplete, 0x2721, |metadata| {
            metadata.migrations[0].completed = false;
        });
        assert!(matches!(
            open_target(&incomplete, &master()),
            Err(StoreError::IncompleteMigration)
        ));

        let duplicate = directory.path().join("duplicate.db");
        let (target, _) = target_at(&duplicate, 0x2722);
        drop(target);
        rewrite_metadata(&duplicate, 0x2723, |metadata| {
            metadata.migrations.push(metadata.migrations[0].clone());
        });
        assert!(matches!(
            open_target(&duplicate, &master()),
            Err(StoreError::DuplicateMigration)
        ));

        let discontinuous = directory.path().join("discontinuous.db");
        let (target, _) = target_at(&discontinuous, 0x2724);
        drop(target);
        rewrite_metadata(&discontinuous, 0x2725, |metadata| {
            metadata.migrations[0].from_version = 1;
        });
        assert!(matches!(
            open_target(&discontinuous, &master()),
            Err(StoreError::InvalidMigrationLedger)
        ));

        let unknown = directory.path().join("unknown-migration.db");
        let (target, _) = target_at(&unknown, 0x2726);
        drop(target);
        rewrite_metadata(&unknown, 0x2727, |metadata| {
            metadata.migrations[0].id = [0x7f; 16];
        });
        assert!(matches!(
            open_target(&unknown, &master()),
            Err(StoreError::InvalidMigrationLedger)
        ));

        let zero_database = directory.path().join("zero-database.db");
        let (target, _) = target_at(&zero_database, 0x2728);
        drop(target);
        rewrite_metadata(&zero_database, 0x2729, |metadata| {
            metadata.database_id = [0; 32];
        });
        assert!(matches!(
            open_target(&zero_database, &master()),
            Err(StoreError::SchemaMismatch)
        ));
    }

    #[test]
    fn cross_database_cross_table_and_cross_row_transplants_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let account = AccountKey::new([0x31; 32]);

        let source_path = directory.path().join("source.db");
        let target_path = directory.path().join("target.db");
        let (source, mut rng) = target_at(&source_path, 0x2730);
        source
            .insert_contact(&account, b"source", &mut rng)
            .unwrap();
        let (target, _) = target_at(&target_path, 0x2731);
        drop(source);
        drop(target);
        let source_conn = Connection::open(&source_path).unwrap();
        let copied: (i64, Vec<u8>, Vec<u8>) = source_conn
            .query_row(
                "SELECT table_domain, locator, blob FROM store_v2_records",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        drop(source_conn);
        Connection::open(&target_path)
            .unwrap()
            .execute(
                "INSERT INTO store_v2_records (table_domain, locator, blob)
                 VALUES (?1, ?2, ?3)",
                params![copied.0, copied.1, copied.2],
            )
            .unwrap();
        assert!(matches!(
            open_target(&target_path, &master()),
            Err(StoreError::Crypto(_))
        ));

        let table_path = directory.path().join("cross-table.db");
        let (table_target, mut rng) = target_at(&table_path, 0x2732);
        table_target
            .insert_contact(&account, b"contact", &mut rng)
            .unwrap();
        drop(table_target);
        Connection::open(&table_path)
            .unwrap()
            .execute(
                "UPDATE store_v2_records SET table_domain = ?1",
                params![TableDomain::Capabilities as u8],
            )
            .unwrap();
        assert!(matches!(
            open_target(&table_path, &master()),
            Err(StoreError::Crypto(_))
        ));

        let row_path = directory.path().join("cross-row.db");
        let (row_target, mut rng) = target_at(&row_path, 0x2733);
        row_target
            .append_message(&MessageKey::new([1; 32], [1; 16]), b"first", &mut rng)
            .unwrap();
        row_target
            .append_message(&MessageKey::new([2; 32], [2; 16]), b"second", &mut rng)
            .unwrap();
        drop(row_target);
        let conn = Connection::open(&row_path).unwrap();
        let rows = conn
            .prepare("SELECT rowid_, blob FROM store_v2_records ORDER BY rowid_")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        conn.execute(
            "UPDATE store_v2_records SET blob = ?1 WHERE rowid_ = ?2",
            params![rows[1].1, rows[0].0],
        )
        .unwrap();
        conn.execute(
            "UPDATE store_v2_records SET blob = ?1 WHERE rowid_ = ?2",
            params![rows[0].1, rows[1].0],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            open_target(&row_path, &master()),
            Err(StoreError::Crypto(_))
        ));
    }

    #[test]
    fn wrong_master_inner_key_and_record_version_fail_closed() {
        let directory = tempfile::tempdir().unwrap();

        let wrong_master_path = directory.path().join("wrong-master.db");
        let (target, _) = target_at(&wrong_master_path, 0x2740);
        drop(target);
        assert!(matches!(
            open_target(&wrong_master_path, &StorageKey::from_bytes([0x52; 32])),
            Err(StoreError::Crypto(_))
        ));

        let wrong_inner_path = directory.path().join("wrong-inner.db");
        let (target, mut rng) = target_at(&wrong_inner_path, 0x2741);
        let expected = AccountKey::new([0x41; 32]);
        target
            .insert_contact(&expected, b"payload", &mut rng)
            .unwrap();
        let locator = target.equality_index::<ContactRecords>(&expected);
        let wrong_plain = encode_record(&AccountKey::new([0x42; 32]), b"payload").unwrap();
        let wrong_sealed = target.seal_row(TableDomain::Contacts, &locator, &wrong_plain, &mut rng);
        target
            .conn
            .execute(
                "UPDATE store_v2_records SET blob = ?1",
                params![wrong_sealed],
            )
            .unwrap();
        drop(target);
        assert!(matches!(
            open_target(&wrong_inner_path, &master()),
            Err(StoreError::LogicalKeyMismatch)
        ));

        let version_path = directory.path().join("record-version.db");
        let (target, mut rng) = target_at(&version_path, 0x2742);
        let key = AccountKey::new([0x43; 32]);
        target.insert_contact(&key, b"payload", &mut rng).unwrap();
        let locator = target.equality_index::<ContactRecords>(&key);
        let mut future = encode_record(&key, b"payload").unwrap();
        future[0] = LOGICAL_RECORD_VERSION + 1;
        let sealed = target.seal_row(TableDomain::Contacts, &locator, &future, &mut rng);
        target
            .conn
            .execute("UPDATE store_v2_records SET blob = ?1", params![sealed])
            .unwrap();
        drop(target);
        assert!(matches!(
            open_target(&version_path, &master()),
            Err(StoreError::UnsupportedRecordVersion)
        ));
    }

    #[test]
    fn duplicate_indexes_fail_on_typed_write_and_corrupt_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("duplicate-index.db");
        let account = AccountKey::new([0x61; 32]);
        let (target, mut rng) = target_at(&path, 0x2750);
        target.insert_contact(&account, b"first", &mut rng).unwrap();
        assert!(matches!(
            target.insert_contact(&account, b"second", &mut rng),
            Err(StoreError::DuplicateIndex)
        ));
        drop(target);

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP INDEX store_v2_record_locator")
            .unwrap();
        let row: (i64, Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT table_domain, locator, blob FROM store_v2_records LIMIT 1",
                [],
                |record| Ok((record.get(0)?, record.get(1)?, record.get(2)?)),
            )
            .unwrap();
        conn.execute(
            "INSERT INTO store_v2_records (table_domain, locator, blob)
             VALUES (?1, ?2, ?3)",
            params![row.0, row.1, row.2],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            open_target(&path, &master()),
            Err(StoreError::DuplicateIndex)
        ));
    }

    #[test]
    fn locked_copy_exposes_only_static_domains_opaque_locators_and_sizes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locked-copy.db");
        let account_bytes = *b"locked-copy-contact-key-32-bytes";
        let message_id = *b"row-message-id!!";
        let contact_payload = b"locked-copy-contact-payload";
        let message_payload = b"locked-copy-message-payload";
        let (target, mut rng) = target_at(&path, 0x2760);
        let database_id = target.database_id();
        let account = AccountKey::new(account_bytes);
        let message_key = MessageKey::new(account_bytes, message_id);
        target
            .insert_contact(&account, contact_payload, &mut rng)
            .unwrap();
        let row_locator = target
            .append_message(&message_key, message_payload, &mut rng)
            .unwrap();
        let equality_locator = target.equality_index::<ContactRecords>(&account);
        assert_ne!(equality_locator.as_slice(), account_bytes.as_slice());
        assert_ne!(row_locator.as_bytes().as_slice(), message_id.as_slice());
        drop(target);

        let bytes = std::fs::read(&path).unwrap();
        for secret in [
            account_bytes.as_slice(),
            message_id.as_slice(),
            contact_payload.as_slice(),
            message_payload.as_slice(),
            database_id.as_slice(),
        ] {
            assert!(!contains(&bytes, secret));
        }

        let raw = Connection::open(&path).unwrap();
        let columns = raw
            .prepare("PRAGMA table_info('store_v2_records')")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(columns, ["rowid_", "table_domain", "locator", "blob"]);
        let rows = raw
            .prepare(
                "SELECT table_domain, length(locator), length(blob)
                 FROM store_v2_records ORDER BY rowid_",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|row| (row.0, row.1)).collect::<Vec<_>>(),
            vec![
                (TableDomain::Contacts as i64, 32),
                (TableDomain::Messages as i64, 16),
            ]
        );
        assert!(rows.iter().all(|row| row.2 > 24 + 16));
        let sealed_metadata: Vec<u8> = raw
            .query_row("SELECT blob FROM store_v2_metadata", [], |row| row.get(0))
            .unwrap();
        assert!(!contains(&sealed_metadata, &database_id));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn canonical_records_round_trip_without_trailing_ambiguity(
            account in any::<[u8; 32]>(),
            message_id in any::<[u8; 16]>(),
            payload in prop::collection::vec(any::<u8>(), 0..4096),
        ) {
            let key = MessageKey::new(account, message_id);
            let encoded = encode_record(&key, &payload).unwrap();
            let decoded = decode_record(&encoded).unwrap();
            prop_assert_eq!(decoded.logical_key, key.encode());
            prop_assert_eq!(decoded.payload, payload);
        }

        #[test]
        fn equality_indexes_are_stable_and_table_separated(account in any::<[u8; 32]>()) {
            let directory = tempfile::tempdir().unwrap();
            let (target, _) = target_at(&directory.path().join("property.db"), 0x2770);
            let key = AccountKey::new(account);
            let first = target.equality_index::<ContactRecords>(&key);
            let repeated = target.equality_index::<ContactRecords>(&key);
            let other_table = target.equality_index::<CapabilityRecords>(&key);
            prop_assert_eq!(first, repeated);
            prop_assert_ne!(first, other_table);
        }
    }
}
