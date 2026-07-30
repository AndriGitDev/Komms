//! ADR-0027 opaque, versioned, row-bound storage primitives.
//!
//! Every logical table is represented inside one strict SQLite record table.
//! Callers select tables and lookup indexes through marker types; raw table,
//! index, key-derivation, and associated-data domains remain private here.

#[cfg(unix)]
use std::fs::File;
use std::path::Path;

use rand_core::CryptoRngCore;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{KdfProfile, StorageKey};

use crate::{Result, Store, StoreError};

pub(crate) const APPLICATION_ID: u32 = 0x4b53_5632;
pub(crate) const SCHEMA_VERSION: u32 = 2;
const METADATA_RECORD_VERSION: u8 = 1;
const LOGICAL_RECORD_VERSION: u8 = 1;
const MAX_MIGRATIONS: usize = 64;
pub(crate) const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_CANONICAL_KEY_BYTES: usize = 2 * 1024;
const ROW_LOCATOR_ATTEMPTS: usize = 16;
pub(crate) const MAX_PAGE_SIZE: usize = 512;

const METADATA_AD: &[u8] = b"Komms-Store-Metadata-v2";
const INDEX_INPUT_DOMAIN: &[u8] = b"Komms-Store-Index-v2";
const INDEX_KEY_DOMAIN: &[u8] = b"Komms-Store-Index-Key-v2";
const ROW_KEY_DOMAIN: &[u8] = b"Komms-Store-Row-Key-v2";
const ROW_AD_DOMAIN: &[u8] = b"Komms-Store-Row-v2";
const CURSOR_KEY_DOMAIN: &[u8] = b"Komms-Store-Cursor-Key-v2";
const CURSOR_MASK_DOMAIN: &[u8] = b"Komms-Store-Cursor-Mask-v2";
const CURSOR_TAG_DOMAIN: &[u8] = b"Komms-Store-Cursor-Tag-v2";
const FRESH_MIGRATION_ID: [u8; 16] = *b"opaque-store-v2!";
pub(crate) const LEGACY_MIGRATION_ID: [u8; 16] = *b"legacy-schema-v1";
pub(crate) const OPAQUE_MIGRATION_ID: [u8; 16] = *b"opaque-all-v2!!!";

pub(crate) const BOOTSTRAP_TABLE_SCHEMA: &str = "CREATE TABLE store_bootstrap (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL CHECK (length(salt) = 16),
    kdf BLOB NOT NULL,
    wrapped_sk BLOB NOT NULL
) STRICT";
pub(crate) const METADATA_TABLE_SCHEMA: &str = "CREATE TABLE store_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    blob BLOB NOT NULL
) STRICT";
pub(crate) const RECORDS_TABLE_SCHEMA: &str = "CREATE TABLE store_records (
    rowid_ INTEGER PRIMARY KEY AUTOINCREMENT,
    table_domain INTEGER NOT NULL,
    locator BLOB NOT NULL CHECK (length(locator) IN (16, 32)),
    unique_index BLOB CHECK (unique_index IS NULL OR length(unique_index) = 32),
    index_a BLOB CHECK (index_a IS NULL OR length(index_a) = 32),
    index_b BLOB CHECK (index_b IS NULL OR length(index_b) = 32),
    index_c BLOB CHECK (index_c IS NULL OR length(index_c) = 32),
    index_d BLOB CHECK (index_d IS NULL OR length(index_d) = 32),
    blob BLOB NOT NULL
) STRICT";
pub(crate) const RECORD_LOCATOR_INDEX_SCHEMA: &str =
    "CREATE UNIQUE INDEX store_record_locator ON store_records (table_domain, locator)";
pub(crate) const RECORD_UNIQUE_INDEX_SCHEMA: &str = "CREATE UNIQUE INDEX store_record_unique
    ON store_records (table_domain, unique_index) WHERE unique_index IS NOT NULL";
pub(crate) const RECORD_INDEX_A_SCHEMA: &str =
    "CREATE INDEX store_record_index_a ON store_records (table_domain, index_a, rowid_)";
pub(crate) const RECORD_INDEX_B_SCHEMA: &str =
    "CREATE INDEX store_record_index_b ON store_records (table_domain, index_b, rowid_)";
pub(crate) const RECORD_INDEX_C_SCHEMA: &str =
    "CREATE INDEX store_record_index_c ON store_records (table_domain, index_c, rowid_)";
pub(crate) const RECORD_INDEX_D_SCHEMA: &str =
    "CREATE INDEX store_record_index_d ON store_records (table_domain, index_d, rowid_)";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MigrationEntry {
    pub(crate) id: [u8; 16],
    pub(crate) from_version: u32,
    pub(crate) to_version: u32,
    pub(crate) completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DatabaseMetadata {
    pub(crate) database_id: [u8; 32],
    pub(crate) schema_version: u32,
    pub(crate) migrations: Vec<MigrationEntry>,
    pub(crate) source_fingerprint: Option<[u8; 32]>,
}

impl DatabaseMetadata {
    pub(crate) fn fresh(database_id: [u8; 32]) -> Self {
        Self {
            database_id,
            schema_version: SCHEMA_VERSION,
            migrations: vec![MigrationEntry {
                id: FRESH_MIGRATION_ID,
                from_version: 0,
                to_version: SCHEMA_VERSION,
                completed: true,
            }],
            source_fingerprint: None,
        }
    }

    pub(crate) fn legacy_destination(
        database_id: [u8; 32],
        source_fingerprint: [u8; 32],
        completed: bool,
    ) -> Self {
        Self {
            database_id,
            schema_version: SCHEMA_VERSION,
            migrations: vec![
                MigrationEntry {
                    id: LEGACY_MIGRATION_ID,
                    from_version: 0,
                    to_version: 1,
                    completed: true,
                },
                MigrationEntry {
                    id: OPAQUE_MIGRATION_ID,
                    from_version: 1,
                    to_version: SCHEMA_VERSION,
                    completed,
                },
            ],
            source_fingerprint: Some(source_fingerprint),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocatorKind {
    Equality,
    Random,
}

pub(crate) trait LogicalKey {
    const KIND: u8;

    fn encode(&self) -> Vec<u8>;

    fn validate_encoded(encoded: &[u8]) -> bool;
}

pub(crate) trait TableSpec {
    type Key: LogicalKey;

    const DOMAIN: u8;
    const LOCATOR_KIND: LocatorKind;
}

macro_rules! fixed_key {
    ($name:ident, $kind:expr, $size:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name(pub(crate) [u8; $size]);

        impl $name {
            pub(crate) fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            pub(crate) fn decode(encoded: &[u8]) -> Result<Self> {
                if !Self::validate_encoded(encoded) {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(Self(
                    encoded[1..]
                        .try_into()
                        .map_err(|_| StoreError::LogicalKeyMismatch)?,
                ))
            }

            pub(crate) fn value(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl LogicalKey for $name {
            const KIND: u8 = $kind;

            fn encode(&self) -> Vec<u8> {
                let mut encoded = Vec::with_capacity(1 + $size);
                encoded.push(Self::KIND);
                encoded.extend_from_slice(&self.0);
                encoded
            }

            fn validate_encoded(encoded: &[u8]) -> bool {
                encoded.len() == 1 + $size && encoded.first() == Some(&Self::KIND)
            }
        }
    };
}

fixed_key!(AccountKey, 1, 32);
fixed_key!(GroupKey, 2, 32);
fixed_key!(ContentKey, 3, 16);
fixed_key!(LocalIdKey, 4, 16);
fixed_key!(DigestKey, 5, 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SingletonKey;

impl LogicalKey for SingletonKey {
    const KIND: u8 = 6;

    fn encode(&self) -> Vec<u8> {
        vec![Self::KIND, 1]
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded == [Self::KIND, 1]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageKey {
    peer: [u8; 32],
    direction: u8,
    id: [u8; 16],
}

impl MessageKey {
    pub(crate) fn new(peer: [u8; 32], direction: u8, id: [u8; 16]) -> Self {
        Self {
            peer,
            direction,
            id,
        }
    }
}

impl LogicalKey for MessageKey {
    const KIND: u8 = 7;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(50);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.peer);
        encoded.push(self.direction);
        encoded.extend_from_slice(&self.id);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 50
            && encoded.first() == Some(&Self::KIND)
            && matches!(encoded.get(33), Some(0 | 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupMessageKey {
    group: [u8; 32],
    sender: [u8; 32],
    direction: u8,
    id: [u8; 16],
}

impl GroupMessageKey {
    pub(crate) fn new(group: [u8; 32], sender: [u8; 32], direction: u8, id: [u8; 16]) -> Self {
        Self {
            group,
            sender,
            direction,
            id,
        }
    }
}

impl LogicalKey for GroupMessageKey {
    const KIND: u8 = 8;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(82);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.group);
        encoded.extend_from_slice(&self.sender);
        encoded.push(self.direction);
        encoded.extend_from_slice(&self.id);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 82
            && encoded.first() == Some(&Self::KIND)
            && matches!(encoded.get(65), Some(0 | 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupMemberKey {
    group: [u8; 32],
    peer: [u8; 32],
}

impl GroupMemberKey {
    pub(crate) fn new(group: [u8; 32], peer: [u8; 32]) -> Self {
        Self { group, peer }
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self> {
        if !Self::validate_encoded(encoded) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        let group = encoded[1..33]
            .try_into()
            .map_err(|_| StoreError::LogicalKeyMismatch)?;
        let peer = encoded[33..65]
            .try_into()
            .map_err(|_| StoreError::LogicalKeyMismatch)?;
        Ok(Self { group, peer })
    }

    pub(crate) fn group(&self) -> &[u8; 32] {
        &self.group
    }

    pub(crate) fn peer(&self) -> &[u8; 32] {
        &self.peer
    }
}

impl LogicalKey for GroupMemberKey {
    const KIND: u8 = 9;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(65);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.group);
        encoded.extend_from_slice(&self.peer);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 65 && encoded.first() == Some(&Self::KIND)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AccountDeviceKey {
    account: [u8; 32],
    device: [u8; 32],
}

impl AccountDeviceKey {
    pub(crate) fn new(account: [u8; 32], device: [u8; 32]) -> Self {
        Self { account, device }
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self> {
        if !Self::validate_encoded(encoded) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Self {
            account: encoded[1..33]
                .try_into()
                .map_err(|_| StoreError::LogicalKeyMismatch)?,
            device: encoded[33..65]
                .try_into()
                .map_err(|_| StoreError::LogicalKeyMismatch)?,
        })
    }

    pub(crate) fn account(&self) -> &[u8; 32] {
        &self.account
    }

    pub(crate) fn device(&self) -> &[u8; 32] {
        &self.device
    }
}

impl LogicalKey for AccountDeviceKey {
    const KIND: u8 = 10;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(65);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.account);
        encoded.extend_from_slice(&self.device);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 65 && encoded.first() == Some(&Self::KIND)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageDeviceKey {
    message: [u8; 16],
    device: [u8; 32],
}

impl MessageDeviceKey {
    pub(crate) fn new(message: [u8; 16], device: [u8; 32]) -> Self {
        Self { message, device }
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self> {
        if !Self::validate_encoded(encoded) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Self {
            message: encoded[1..17]
                .try_into()
                .map_err(|_| StoreError::LogicalKeyMismatch)?,
            device: encoded[17..49]
                .try_into()
                .map_err(|_| StoreError::LogicalKeyMismatch)?,
        })
    }

    pub(crate) fn message(&self) -> &[u8; 16] {
        &self.message
    }

    pub(crate) fn device(&self) -> &[u8; 32] {
        &self.device
    }
}

impl LogicalKey for MessageDeviceKey {
    const KIND: u8 = 11;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(49);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.message);
        encoded.extend_from_slice(&self.device);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 49 && encoded.first() == Some(&Self::KIND)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataKey(Vec<u8>);

impl MetadataKey {
    pub(crate) fn new(encoded_key: Vec<u8>) -> Result<Self> {
        if encoded_key.is_empty() || encoded_key.len() > MAX_CANONICAL_KEY_BYTES - 3 {
            return Err(StoreError::RecordBounds);
        }
        Ok(Self(encoded_key))
    }
}

impl LogicalKey for MetadataKey {
    const KIND: u8 = 12;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(3 + self.0.len());
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.0);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        if encoded.len() < 4
            || encoded.first() != Some(&Self::KIND)
            || encoded.len() > MAX_CANONICAL_KEY_BYTES
        {
            return false;
        }
        let Ok(length) = <[u8; 2]>::try_from(&encoded[1..3]) else {
            return false;
        };
        usize::from(u16::from_be_bytes(length)) == encoded.len() - 3
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EphemeralKey(Vec<u8>);

impl EphemeralKey {
    pub(crate) fn new(
        conversation_kind: u8,
        conversation: [u8; 32],
        author: [u8; 32],
        content_id: [u8; 16],
    ) -> Result<Self> {
        if !matches!(conversation_kind, 0 | 1) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        let mut body = Vec::with_capacity(81);
        body.push(conversation_kind);
        body.extend_from_slice(&conversation);
        body.extend_from_slice(&author);
        body.extend_from_slice(&content_id);
        Ok(Self(body))
    }
}

impl LogicalKey for EphemeralKey {
    const KIND: u8 = 13;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(82);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.0);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 82
            && encoded.first() == Some(&Self::KIND)
            && matches!(encoded.get(1), Some(0 | 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpaqueRowKey([u8; 16]);

impl OpaqueRowKey {
    pub(crate) fn from_locator(locator: [u8; 16]) -> Self {
        Self(locator)
    }
}

impl LogicalKey for OpaqueRowKey {
    const KIND: u8 = 14;

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(17);
        encoded.push(Self::KIND);
        encoded.extend_from_slice(&self.0);
        encoded
    }

    fn validate_encoded(encoded: &[u8]) -> bool {
        encoded.len() == 17 && encoded.first() == Some(&Self::KIND)
    }
}

macro_rules! table {
    ($name:ident, $domain:expr, $locator:ident, $key:ty) => {
        pub(crate) struct $name;

        impl TableSpec for $name {
            type Key = $key;

            const DOMAIN: u8 = $domain;
            const LOCATOR_KIND: LocatorKind = LocatorKind::$locator;
        }
    };
}

table!(IdentityRows, 1, Equality, SingletonKey);
table!(SessionRows, 2, Equality, AccountKey);
table!(CapabilityRows, 3, Equality, AccountKey);
table!(MessageRows, 4, Random, MessageKey);
table!(QueueRows, 5, Random, OpaqueRowKey);
table!(SeenRows, 6, Equality, ContentKey);
table!(ReceiptReplayRows, 7, Equality, ContentKey);
table!(ContactRows, 8, Equality, AccountKey);
table!(PrekeyRows, 9, Equality, SingletonKey);
table!(PendingRows, 10, Random, OpaqueRowKey);
table!(ResetRows, 11, Equality, AccountKey);
table!(GroupRows, 12, Equality, GroupKey);
table!(GroupAuthorityRows, 13, Equality, GroupKey);
table!(GroupChainRows, 14, Equality, GroupMemberKey);
table!(GroupMessageRows, 15, Random, GroupMessageKey);
table!(MediaTransferRows, 16, Equality, LocalIdKey);
table!(MediaObjectRows, 17, Equality, LocalIdKey);
table!(LocalMetadataRows, 18, Equality, MetadataKey);
table!(NoteRows, 19, Random, ContentKey);
table!(ScheduledRows, 20, Equality, ContentKey);
table!(EphemeralRows, 21, Equality, EphemeralKey);
table!(DeviceStateRows, 22, Equality, SingletonKey);
table!(DeviceSyncRows, 23, Random, DigestKey);
table!(ContactDeviceRows, 24, Equality, AccountDeviceKey);
table!(MessageDeviceDeliveryRows, 25, Equality, MessageDeviceKey);
table!(PresentationMarkerRows, 26, Equality, SingletonKey);
table!(DeferredControlRows, 27, Equality, ContentKey);
table!(DeviceLinkRecoveryRows, 28, Equality, AccountKey);
table!(ProvisionalRequestRows, 29, Equality, AccountKey);
table!(AdmissionReplayRows, 30, Equality, ContentKey);
table!(BlockedIdentityRows, 31, Equality, AccountDeviceKey);
pub(crate) struct MigrationCheckpointRows;

impl TableSpec for MigrationCheckpointRows {
    type Key = SingletonKey;

    const DOMAIN: u8 = 250;
    const LOCATOR_KIND: LocatorKind = LocatorKind::Equality;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IndexKeys {
    unique: Option<Vec<u8>>,
    a: Option<Vec<u8>>,
    b: Option<Vec<u8>>,
    c: Option<Vec<u8>>,
    d: Option<Vec<u8>>,
}

impl IndexKeys {
    pub(crate) fn none() -> Self {
        Self::default()
    }

    pub(crate) fn message(id: &ContentKey, conversation: &AccountKey) -> Self {
        Self {
            unique: Some(id.encode()),
            a: Some(conversation.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn group_message(id: &ContentKey, conversation: &GroupKey) -> Self {
        Self {
            unique: Some(id.encode()),
            a: Some(conversation.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn queue(
        peer: &AccountKey,
        message: Option<&ContentKey>,
        group_message: Option<&ContentKey>,
        envelope: &ContentKey,
    ) -> Self {
        Self {
            a: Some(peer.encode()),
            b: message.map(LogicalKey::encode),
            c: group_message.map(LogicalKey::encode),
            d: Some(envelope.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn pending(content: &ContentKey) -> Self {
        Self {
            unique: Some(content.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn group_chain(group: &GroupKey) -> Self {
        Self {
            a: Some(group.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn media_object(transfer: &LocalIdKey) -> Self {
        Self {
            a: Some(transfer.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn note(id: &ContentKey) -> Self {
        Self {
            unique: Some(id.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn device_sync(digest: &DigestKey) -> Self {
        Self {
            unique: Some(digest.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn contact_device(account: &AccountKey) -> Self {
        Self {
            a: Some(account.encode()),
            ..Self::default()
        }
    }

    pub(crate) fn message_device_delivery(message: &ContentKey, account: &AccountKey) -> Self {
        Self {
            a: Some(message.encode()),
            b: Some(account.encode()),
            ..Self::default()
        }
    }

    fn as_array(&self) -> [Option<&[u8]>; 5] {
        [
            self.unique.as_deref(),
            self.a.as_deref(),
            self.b.as_deref(),
            self.c.as_deref(),
            self.d.as_deref(),
        ]
    }
}

pub(crate) trait LookupIndex {
    type Table: TableSpec;
    type Key: LogicalKey;

    const SLOT: usize;
    const COLUMN: &'static str;
}

macro_rules! lookup_index {
    ($name:ident, $table:ty, $key:ty, $slot:expr, $column:literal) => {
        pub(crate) struct $name;

        impl LookupIndex for $name {
            type Table = $table;
            type Key = $key;

            const SLOT: usize = $slot;
            const COLUMN: &'static str = $column;
        }
    };
}

lookup_index!(MessageIdIndex, MessageRows, ContentKey, 1, "unique_index");
lookup_index!(
    MessageConversationIndex,
    MessageRows,
    AccountKey,
    2,
    "index_a"
);
lookup_index!(QueuePeerIndex, QueueRows, AccountKey, 2, "index_a");
lookup_index!(QueueMessageIndex, QueueRows, ContentKey, 3, "index_b");
lookup_index!(QueueGroupMessageIndex, QueueRows, ContentKey, 4, "index_c");
lookup_index!(QueueEnvelopeIndex, QueueRows, ContentKey, 5, "index_d");
lookup_index!(
    PendingContentIndex,
    PendingRows,
    ContentKey,
    1,
    "unique_index"
);
lookup_index!(GroupChainGroupIndex, GroupChainRows, GroupKey, 2, "index_a");
lookup_index!(
    GroupMessageIdIndex,
    GroupMessageRows,
    ContentKey,
    1,
    "unique_index"
);
lookup_index!(
    GroupMessageConversationIndex,
    GroupMessageRows,
    GroupKey,
    2,
    "index_a"
);
lookup_index!(
    MediaObjectTransferIndex,
    MediaObjectRows,
    LocalIdKey,
    2,
    "index_a"
);
lookup_index!(
    DeviceSyncDigestIndex,
    DeviceSyncRows,
    DigestKey,
    1,
    "unique_index"
);
lookup_index!(
    ContactDeviceAccountIndex,
    ContactDeviceRows,
    AccountKey,
    2,
    "index_a"
);
lookup_index!(
    MessageDeliveryMessageIndex,
    MessageDeviceDeliveryRows,
    ContentKey,
    2,
    "index_a"
);
lookup_index!(
    MessageDeliveryAccountIndex,
    MessageDeviceDeliveryRows,
    AccountKey,
    3,
    "index_b"
);

#[derive(Debug)]
pub(crate) struct RawRow {
    pub(crate) rowid: i64,
    pub(crate) locator: Vec<u8>,
    pub(crate) logical_key: Vec<u8>,
    indexes: IndexKeys,
    pub(crate) payload: Zeroizing<Vec<u8>>,
}

impl RawRow {
    pub(crate) fn verify_key<K: LogicalKey>(&self, expected: &K) -> Result<()> {
        if self.logical_key == expected.encode() {
            Ok(())
        } else {
            Err(StoreError::LogicalKeyMismatch)
        }
    }

    pub(crate) fn verify_indexes(&self, expected: &IndexKeys) -> Result<()> {
        if &self.indexes == expected {
            Ok(())
        } else {
            Err(StoreError::LogicalKeyMismatch)
        }
    }

    pub(crate) fn verify_pending_indexes(&self, content: &ContentKey) -> Result<()> {
        if self.indexes == IndexKeys::none() || self.indexes == IndexKeys::pending(content) {
            Ok(())
        } else {
            Err(StoreError::LogicalKeyMismatch)
        }
    }
}

struct DecodedRecord<'a> {
    logical_key: &'a [u8],
    indexes: [Option<&'a [u8]>; 5],
    payload: &'a [u8],
}

pub(crate) struct DerivedKeys {
    pub(crate) index_root: StorageKey,
    pub(crate) row_root: StorageKey,
    pub(crate) cursor_root: StorageKey,
    pub(crate) media: StorageKey,
}

pub(crate) fn derive_store_keys(master: &StorageKey) -> DerivedKeys {
    DerivedKeys {
        index_root: master.derive(b"KK-store-v2-index-root"),
        row_root: master.derive(b"KK-store-v2-row-root"),
        cursor_root: master.derive(CURSOR_KEY_DOMAIN),
        media: master.derive(b"KK-store-media"),
    }
}

pub(crate) fn random_database_id(rng: &mut impl CryptoRngCore) -> Result<[u8; 32]> {
    let mut database_id = [0u8; 32];
    rng.fill_bytes(&mut database_id);
    if database_id == [0; 32] {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(database_id)
}

pub(crate) fn create_schema(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    conn.execute_batch(BOOTSTRAP_TABLE_SCHEMA)?;
    conn.execute_batch(METADATA_TABLE_SCHEMA)?;
    conn.execute_batch(RECORDS_TABLE_SCHEMA)?;
    conn.execute_batch(RECORD_LOCATOR_INDEX_SCHEMA)?;
    conn.execute_batch(RECORD_UNIQUE_INDEX_SCHEMA)?;
    conn.execute_batch(RECORD_INDEX_A_SCHEMA)?;
    conn.execute_batch(RECORD_INDEX_B_SCHEMA)?;
    conn.execute_batch(RECORD_INDEX_C_SCHEMA)?;
    conn.execute_batch(RECORD_INDEX_D_SCHEMA)?;
    conn.pragma_update(None, "application_id", APPLICATION_ID)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

pub(crate) fn configure_connection(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.pragma_update(None, "secure_delete", true)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "wal_autocheckpoint", 1_000u32)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

pub(crate) fn write_bootstrap(
    conn: &Connection,
    salt: &[u8; 16],
    profile: KdfProfile,
    wrapped_sk: &[u8],
) -> Result<()> {
    let kdf = postcard::to_allocvec(&(profile.m_cost_kib, profile.t_cost, profile.p_cost))
        .map_err(|_| StoreError::Serialization)?;
    conn.execute(
        "INSERT INTO store_bootstrap (id, salt, kdf, wrapped_sk) VALUES (1, ?1, ?2, ?3)",
        params![salt.as_slice(), kdf, wrapped_sk],
    )?;
    Ok(())
}

pub(crate) fn read_bootstrap(conn: &Connection) -> Result<([u8; 16], KdfProfile, Vec<u8>)> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM store_bootstrap", [], |row| row.get(0))?;
    if count != 1 {
        return Err(StoreError::SchemaMismatch);
    }
    let (salt, kdf, wrapped): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT salt, kdf, wrapped_sk FROM store_bootstrap WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(StoreError::NotAStore)?;
    let salt: [u8; 16] = salt.try_into().map_err(|_| StoreError::NotAStore)?;
    let (m_cost_kib, t_cost, p_cost): (u32, u32, u32) =
        decode_exact(&kdf).map_err(|_| StoreError::NotAStore)?;
    if wrapped.len() < 24 + 16 {
        return Err(StoreError::NotAStore);
    }
    Ok((
        salt,
        KdfProfile {
            m_cost_kib,
            t_cost,
            p_cost,
        },
        wrapped,
    ))
}

pub(crate) fn write_metadata(
    conn: &Connection,
    master: &StorageKey,
    metadata: &DatabaseMetadata,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let metadata_key = master.derive(b"KK-store-v2-metadata");
    write_metadata_with_key(conn, &metadata_key, metadata, rng)
}

pub(crate) fn write_metadata_with_key(
    conn: &Connection,
    metadata_key: &StorageKey,
    metadata: &DatabaseMetadata,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let sealed = seal_metadata(metadata_key, metadata, rng)?;
    conn.execute(
        "INSERT INTO store_metadata (id, blob) VALUES (1, ?1)
         ON CONFLICT(id) DO UPDATE SET blob = excluded.blob",
        params![sealed],
    )?;
    Ok(())
}

pub(crate) fn read_metadata(
    conn: &Connection,
    master: &StorageKey,
    allow_incomplete: bool,
) -> Result<DatabaseMetadata> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM store_metadata", [], |row| row.get(0))?;
    if count != 1 {
        return Err(StoreError::SchemaMismatch);
    }
    let sealed: Vec<u8> = conn
        .query_row("SELECT blob FROM store_metadata WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or(StoreError::SchemaMismatch)?;
    let metadata_key = master.derive(b"KK-store-v2-metadata");
    let metadata = open_metadata(&metadata_key, &sealed)?;
    validate_metadata(&metadata, physical_schema_version(conn)?, allow_incomplete)?;
    Ok(metadata)
}

pub(crate) fn validate_physical_schema(conn: &Connection) -> Result<()> {
    validate_preamble(conn)?;
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
    let mut expected = vec![
        (
            "table".to_owned(),
            "store_bootstrap".to_owned(),
            BOOTSTRAP_TABLE_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_index_a".to_owned(),
            RECORD_INDEX_A_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_index_b".to_owned(),
            RECORD_INDEX_B_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_index_c".to_owned(),
            RECORD_INDEX_C_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_index_d".to_owned(),
            RECORD_INDEX_D_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_locator".to_owned(),
            RECORD_LOCATOR_INDEX_SCHEMA.to_owned(),
        ),
        (
            "index".to_owned(),
            "store_record_unique".to_owned(),
            RECORD_UNIQUE_INDEX_SCHEMA.to_owned(),
        ),
        (
            "table".to_owned(),
            "store_records".to_owned(),
            RECORDS_TABLE_SCHEMA.to_owned(),
        ),
        (
            "table".to_owned(),
            "store_metadata".to_owned(),
            METADATA_TABLE_SCHEMA.to_owned(),
        ),
    ];
    expected.sort_by(|left, right| left.1.cmp(&right.1));
    if objects != expected {
        return Err(StoreError::SchemaMismatch);
    }
    Ok(())
}

pub(crate) fn is_v2(conn: &Connection) -> Result<bool> {
    let application_id: u32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id == APPLICATION_ID {
        return Ok(true);
    }
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE name IN ('store_bootstrap', 'store_metadata', 'store_records')
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub(crate) fn physical_schema_version(conn: &Connection) -> Result<u32> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

impl Store {
    pub(crate) fn put_equality<T: TableSpec>(
        &self,
        key: &T::Key,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.put_equality_on::<T>(&self.conn, key, payload, indexes, rng)
    }

    pub(crate) fn put_equality_on<T: TableSpec>(
        &self,
        conn: &Connection,
        key: &T::Key,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if T::LOCATOR_KIND != LocatorKind::Equality {
            return Err(StoreError::SchemaMismatch);
        }
        validate_index_shape(T::DOMAIN, &indexes)?;
        let logical_key = key.encode();
        let locator = self.index_for(T::DOMAIN, 0, &logical_key);
        let sealed = self.seal_logical_row(T::DOMAIN, &locator, key, &indexes, payload, rng)?;
        let physical = self.physical_indexes(T::DOMAIN, &indexes);
        match conn.execute(
            "INSERT INTO store_records
             (table_domain, locator, unique_index, index_a, index_b, index_c, index_d, blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(table_domain, locator) DO UPDATE SET
                 unique_index = excluded.unique_index,
                 index_a = excluded.index_a,
                 index_b = excluded.index_b,
                 index_c = excluded.index_c,
                 index_d = excluded.index_d,
                 blob = excluded.blob",
            params![
                T::DOMAIN,
                locator.as_slice(),
                physical[0].as_deref(),
                physical[1].as_deref(),
                physical[2].as_deref(),
                physical[3].as_deref(),
                physical[4].as_deref(),
                sealed
            ],
        ) {
            Ok(_) => Ok(()),
            Err(error) if constraint_violation(&error) => Err(StoreError::DuplicateIndex),
            Err(error) => Err(StoreError::Db(error)),
        }
    }

    pub(crate) fn append<T: TableSpec>(
        &self,
        key: &T::Key,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<RawRow> {
        self.append_on::<T>(&self.conn, Some(key), payload, indexes, rng)
    }

    pub(crate) fn append_opaque<T>(
        &self,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<RawRow>
    where
        T: TableSpec<Key = OpaqueRowKey>,
    {
        self.append_on::<T>(&self.conn, None, payload, indexes, rng)
    }

    pub(crate) fn append_on<T: TableSpec>(
        &self,
        conn: &Connection,
        key: Option<&T::Key>,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<RawRow> {
        if T::LOCATOR_KIND != LocatorKind::Random {
            return Err(StoreError::SchemaMismatch);
        }
        validate_index_shape(T::DOMAIN, &indexes)?;
        for _ in 0..ROW_LOCATOR_ATTEMPTS {
            let mut locator = [0u8; 16];
            rng.fill_bytes(&mut locator);
            let generated;
            let key = match key {
                Some(key) => key,
                None if T::Key::KIND == OpaqueRowKey::KIND => {
                    generated = OpaqueRowKey::from_locator(locator);
                    // This branch is reachable only through `append_opaque`,
                    // whose associated key type is statically constrained.
                    let encoded = generated.encode();
                    let sealed = self.seal_encoded_row(
                        T::DOMAIN,
                        &locator,
                        &encoded,
                        &indexes,
                        payload,
                        rng,
                    )?;
                    let physical = self.physical_indexes(T::DOMAIN, &indexes);
                    match insert_record(conn, T::DOMAIN, &locator, &physical, &sealed) {
                        Ok(rowid) => {
                            return Ok(RawRow {
                                rowid,
                                locator: locator.to_vec(),
                                logical_key: encoded,
                                indexes: indexes.clone(),
                                payload: Zeroizing::new(payload.to_vec()),
                            });
                        }
                        Err(StoreError::DuplicateIndex) => continue,
                        Err(error) => return Err(error),
                    }
                }
                None => return Err(StoreError::LogicalKeyMismatch),
            };
            let encoded = key.encode();
            let sealed =
                self.seal_encoded_row(T::DOMAIN, &locator, &encoded, &indexes, payload, rng)?;
            let physical = self.physical_indexes(T::DOMAIN, &indexes);
            match insert_record(conn, T::DOMAIN, &locator, &physical, &sealed) {
                Ok(rowid) => {
                    return Ok(RawRow {
                        rowid,
                        locator: locator.to_vec(),
                        logical_key: encoded,
                        indexes: indexes.clone(),
                        payload: Zeroizing::new(payload.to_vec()),
                    });
                }
                Err(StoreError::DuplicateIndex) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::DuplicateIndex)
    }

    pub(crate) fn get_equality<T: TableSpec>(&self, key: &T::Key) -> Result<Option<RawRow>> {
        if T::LOCATOR_KIND != LocatorKind::Equality {
            return Err(StoreError::SchemaMismatch);
        }
        let encoded = key.encode();
        let locator = self.index_for(T::DOMAIN, 0, &encoded);
        self.raw_row_by_locator::<T>(&self.conn, &locator)?
            .map(|row| {
                row.verify_key(key)?;
                Ok(row)
            })
            .transpose()
    }

    pub(crate) fn delete_equality<T: TableSpec>(&self, key: &T::Key) -> Result<bool> {
        self.delete_equality_on::<T>(&self.conn, key)
    }

    pub(crate) fn delete_equality_on<T: TableSpec>(
        &self,
        conn: &Connection,
        key: &T::Key,
    ) -> Result<bool> {
        if T::LOCATOR_KIND != LocatorKind::Equality {
            return Err(StoreError::SchemaMismatch);
        }
        let locator = self.index_for(T::DOMAIN, 0, &key.encode());
        Ok(conn.execute(
            "DELETE FROM store_records WHERE table_domain = ?1 AND locator = ?2",
            params![T::DOMAIN, locator.as_slice()],
        )? == 1)
    }

    pub(crate) fn rows<T: TableSpec>(&self) -> Result<Vec<RawRow>> {
        self.rows_on::<T>(&self.conn)
    }

    pub(crate) fn row_by_rowid<T: TableSpec>(&self, rowid: i64) -> Result<Option<RawRow>> {
        self.row_by_rowid_on::<T>(&self.conn, rowid)
    }

    pub(crate) fn row_by_rowid_on<T: TableSpec>(
        &self,
        conn: &Connection,
        rowid: i64,
    ) -> Result<Option<RawRow>> {
        let row = conn
            .query_row(
                "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
                 FROM store_records WHERE table_domain = ?1 AND rowid_ = ?2",
                params![T::DOMAIN, rowid],
                sql_row,
            )
            .optional()?;
        row.map(|row| self.open_sql_row::<T>(row)).transpose()
    }

    pub(crate) fn rows_on<T: TableSpec>(&self, conn: &Connection) -> Result<Vec<RawRow>> {
        let mut statement = conn.prepare(
            "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
             FROM store_records WHERE table_domain = ?1 ORDER BY rowid_",
        )?;
        let rows = statement.query_map(params![T::DOMAIN], sql_row)?;
        let mut decoded = Vec::new();
        for row in rows {
            decoded.push(self.open_sql_row::<T>(row?)?);
        }
        Ok(decoded)
    }

    pub(crate) fn validate_rows<T, F>(&self, mut validate: F) -> Result<()>
    where
        T: TableSpec,
        F: FnMut(&RawRow) -> Result<()>,
    {
        let mut statement = self.conn.prepare(
            "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
             FROM store_records WHERE table_domain = ?1 ORDER BY rowid_",
        )?;
        let rows = statement.query_map(params![T::DOMAIN], sql_row)?;
        for row in rows {
            let decoded = self.open_sql_row::<T>(row?)?;
            validate(&decoded)?;
        }
        Ok(())
    }

    pub(crate) fn row_by_unique<I: LookupIndex>(&self, key: &I::Key) -> Result<Option<RawRow>> {
        let index = self.index_for(
            <I::Table as TableSpec>::DOMAIN,
            I::SLOT as u8,
            &key.encode(),
        );
        let sql = format!(
            "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
             FROM store_records WHERE table_domain = ?1 AND {} = ?2",
            I::COLUMN
        );
        let row = self
            .conn
            .query_row(
                &sql,
                params![<I::Table as TableSpec>::DOMAIN, index.as_slice()],
                sql_row,
            )
            .optional()?;
        row.map(|row| self.open_sql_row::<I::Table>(row))
            .transpose()
    }

    pub(crate) fn rows_by_index<I: LookupIndex>(&self, key: &I::Key) -> Result<Vec<RawRow>> {
        self.rows_by_index_after::<I>(key, None, i64::MAX as usize)
    }

    pub(crate) fn rows_by_index_after<I: LookupIndex>(
        &self,
        key: &I::Key,
        after_rowid: Option<i64>,
        limit: usize,
    ) -> Result<Vec<RawRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| StoreError::RecordBounds)?;
        let index = self.index_for(
            <I::Table as TableSpec>::DOMAIN,
            I::SLOT as u8,
            &key.encode(),
        );
        let sql = format!(
            "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
             FROM store_records
             WHERE table_domain = ?1 AND {} = ?2 AND rowid_ > ?3
             ORDER BY rowid_ LIMIT ?4",
            I::COLUMN
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                <I::Table as TableSpec>::DOMAIN,
                index.as_slice(),
                after_rowid.unwrap_or(0),
                limit
            ],
            sql_row,
        )?;
        let mut decoded = Vec::new();
        for row in rows {
            decoded.push(self.open_sql_row::<I::Table>(row?)?);
        }
        Ok(decoded)
    }

    pub(crate) fn update_row<T: TableSpec>(
        &self,
        locator: &[u8],
        expected_key: &T::Key,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        self.update_row_on::<T>(&self.conn, locator, expected_key, payload, indexes, rng)
    }

    pub(crate) fn update_row_on<T: TableSpec>(
        &self,
        conn: &Connection,
        locator: &[u8],
        expected_key: &T::Key,
        payload: &[u8],
        indexes: IndexKeys,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(current) = self.raw_row_by_locator::<T>(conn, locator)? else {
            return Ok(false);
        };
        current.verify_key(expected_key)?;
        validate_index_shape(T::DOMAIN, &indexes)?;
        let sealed =
            self.seal_logical_row(T::DOMAIN, locator, expected_key, &indexes, payload, rng)?;
        let physical = self.physical_indexes(T::DOMAIN, &indexes);
        match conn.execute(
            "UPDATE store_records SET unique_index = ?1, index_a = ?2, index_b = ?3,
                    index_c = ?4, index_d = ?5, blob = ?6
             WHERE table_domain = ?7 AND locator = ?8",
            params![
                physical[0].as_deref(),
                physical[1].as_deref(),
                physical[2].as_deref(),
                physical[3].as_deref(),
                physical[4].as_deref(),
                sealed,
                T::DOMAIN,
                locator
            ],
        ) {
            Ok(changed) => Ok(changed == 1),
            Err(error) if constraint_violation(&error) => Err(StoreError::DuplicateIndex),
            Err(error) => Err(StoreError::Db(error)),
        }
    }

    pub(crate) fn delete_row<T: TableSpec>(&self, locator: &[u8]) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM store_records WHERE table_domain = ?1 AND locator = ?2",
            params![T::DOMAIN, locator],
        )? == 1)
    }

    pub(crate) fn delete_rowid<T: TableSpec>(&self, rowid: i64) -> Result<bool> {
        self.delete_rowid_on::<T>(&self.conn, rowid)
    }

    pub(crate) fn delete_rowid_on<T: TableSpec>(
        &self,
        conn: &Connection,
        rowid: i64,
    ) -> Result<bool> {
        Ok(conn.execute(
            "DELETE FROM store_records WHERE table_domain = ?1 AND rowid_ = ?2",
            params![T::DOMAIN, rowid],
        )? == 1)
    }

    pub(crate) fn delete_row_on<T: TableSpec>(
        &self,
        conn: &Connection,
        locator: &[u8],
    ) -> Result<bool> {
        Ok(conn.execute(
            "DELETE FROM store_records WHERE table_domain = ?1 AND locator = ?2",
            params![T::DOMAIN, locator],
        )? == 1)
    }

    pub(crate) fn count_rows<T: TableSpec>(&self) -> Result<u64> {
        self.count_rows_on::<T>(&self.conn)
    }

    pub(crate) fn count_rows_on<T: TableSpec>(&self, conn: &Connection) -> Result<u64> {
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM store_records WHERE table_domain = ?1",
            params![T::DOMAIN],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| StoreError::Serialization)
    }

    pub(crate) fn sealed_bytes_on<T: TableSpec>(&self, conn: &Connection) -> Result<u64> {
        let bytes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(length(blob)), 0) FROM store_records WHERE table_domain = ?1",
            params![T::DOMAIN],
            |row| row.get(0),
        )?;
        u64::try_from(bytes).map_err(|_| StoreError::Serialization)
    }

    pub(crate) fn validate_all_opaque_rows(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT rowid_, table_domain, locator, unique_index, index_a, index_b, index_c,
                    index_d, blob
             FROM store_records ORDER BY rowid_",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;
        for row in rows {
            let (_, domain, locator, unique, a, b, c, d, sealed) = row?;
            let domain = u8::try_from(domain).map_err(|_| StoreError::SchemaMismatch)?;
            let locator_kind = table_locator_kind(domain)?;
            let expected_locator_len = match locator_kind {
                LocatorKind::Equality => 32,
                LocatorKind::Random => 16,
            };
            if locator.len() != expected_locator_len {
                return Err(StoreError::SchemaMismatch);
            }
            let physical = [unique, a, b, c, d];
            let plain = Zeroizing::new(self.open_row(domain, &locator, &sealed)?);
            let decoded = decode_record(&plain)?;
            validate_key_for_domain(domain, decoded.logical_key)?;
            let indexes = decoded_indexes_owned(&decoded)?;
            validate_index_shape(domain, &indexes)?;
            let expected = self.physical_indexes(domain, &indexes);
            if physical != expected {
                return Err(StoreError::LogicalKeyMismatch);
            }
            if locator_kind == LocatorKind::Equality
                && self.index_for(domain, 0, decoded.logical_key).as_slice() != locator.as_slice()
            {
                return Err(StoreError::LogicalKeyMismatch);
            }
            if locator_kind == LocatorKind::Random
                && domain_uses_opaque_key(domain)
                && decoded.logical_key.get(1..) != Some(locator.as_slice())
            {
                return Err(StoreError::LogicalKeyMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn encode_cursor<I: LookupIndex>(&self, key: &I::Key, row: &RawRow) -> Vec<u8> {
        let index = self.index_for(
            <I::Table as TableSpec>::DOMAIN,
            I::SLOT as u8,
            &key.encode(),
        );
        let mut mask_input = Vec::with_capacity(CURSOR_MASK_DOMAIN.len() + 1 + 32 + 16);
        mask_input.extend_from_slice(CURSOR_MASK_DOMAIN);
        mask_input.push(<I::Table as TableSpec>::DOMAIN);
        mask_input.extend_from_slice(&index);
        mask_input.extend_from_slice(&row.locator);
        let mask = self.cursor_root.hmac_sha256(&mask_input);
        let order = row.rowid.to_be_bytes();
        let mut masked = [0u8; 8];
        for (out, (value, key_byte)) in masked.iter_mut().zip(order.iter().zip(mask.iter())) {
            *out = value ^ key_byte;
        }
        let mut token = Vec::with_capacity(1 + 16 + 8 + 32);
        token.push(1);
        token.extend_from_slice(&row.locator);
        token.extend_from_slice(&masked);
        let mut tag_input = Vec::with_capacity(CURSOR_TAG_DOMAIN.len() + 1 + 32 + token.len());
        tag_input.extend_from_slice(CURSOR_TAG_DOMAIN);
        tag_input.push(<I::Table as TableSpec>::DOMAIN);
        tag_input.extend_from_slice(&index);
        tag_input.extend_from_slice(&token);
        token.extend_from_slice(&self.cursor_root.hmac_sha256(&tag_input));
        token
    }

    pub(crate) fn decode_cursor<I: LookupIndex>(&self, key: &I::Key, token: &[u8]) -> Result<i64> {
        if token.len() != 57 || token.first() != Some(&1) {
            return Err(StoreError::InvalidCursor);
        }
        let index = self.index_for(
            <I::Table as TableSpec>::DOMAIN,
            I::SLOT as u8,
            &key.encode(),
        );
        let mut tag_input = Vec::with_capacity(CURSOR_TAG_DOMAIN.len() + 1 + 32 + 25);
        tag_input.extend_from_slice(CURSOR_TAG_DOMAIN);
        tag_input.push(<I::Table as TableSpec>::DOMAIN);
        tag_input.extend_from_slice(&index);
        tag_input.extend_from_slice(&token[..25]);
        if self.cursor_root.hmac_sha256(&tag_input).as_slice() != &token[25..] {
            return Err(StoreError::InvalidCursor);
        }
        let locator = &token[1..17];
        let mut mask_input = Vec::with_capacity(CURSOR_MASK_DOMAIN.len() + 1 + 32 + 16);
        mask_input.extend_from_slice(CURSOR_MASK_DOMAIN);
        mask_input.push(<I::Table as TableSpec>::DOMAIN);
        mask_input.extend_from_slice(&index);
        mask_input.extend_from_slice(locator);
        let mask = self.cursor_root.hmac_sha256(&mask_input);
        let mut order = [0u8; 8];
        for (out, (value, key_byte)) in order.iter_mut().zip(token[17..25].iter().zip(mask.iter()))
        {
            *out = value ^ key_byte;
        }
        let rowid = i64::from_be_bytes(order);
        if rowid <= 0 {
            return Err(StoreError::InvalidCursor);
        }
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM store_records WHERE table_domain = ?1 AND rowid_ = ?2
                 AND locator = ?3 LIMIT 1",
                params![<I::Table as TableSpec>::DOMAIN, rowid, locator],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::InvalidCursor);
        }
        Ok(rowid)
    }

    fn raw_row_by_locator<T: TableSpec>(
        &self,
        conn: &Connection,
        locator: &[u8],
    ) -> Result<Option<RawRow>> {
        let row = conn
            .query_row(
                "SELECT rowid_, locator, unique_index, index_a, index_b, index_c, index_d, blob
                 FROM store_records WHERE table_domain = ?1 AND locator = ?2",
                params![T::DOMAIN, locator],
                sql_row,
            )
            .optional()?;
        row.map(|row| self.open_sql_row::<T>(row)).transpose()
    }

    fn open_sql_row<T: TableSpec>(&self, row: SqlRow) -> Result<RawRow> {
        let physical = [
            row.unique_index,
            row.index_a,
            row.index_b,
            row.index_c,
            row.index_d,
        ];
        let plain = Zeroizing::new(self.open_row(T::DOMAIN, &row.locator, &row.blob)?);
        let decoded = decode_record(&plain)?;
        if !T::Key::validate_encoded(decoded.logical_key) {
            return Err(StoreError::LogicalKeyMismatch);
        }
        let indexes = decoded_indexes_owned(&decoded)?;
        validate_index_shape(T::DOMAIN, &indexes)?;
        if self.physical_indexes(T::DOMAIN, &indexes) != physical {
            return Err(StoreError::LogicalKeyMismatch);
        }
        if T::LOCATOR_KIND == LocatorKind::Equality
            && self.index_for(T::DOMAIN, 0, decoded.logical_key).as_slice()
                != row.locator.as_slice()
        {
            return Err(StoreError::LogicalKeyMismatch);
        }
        if T::LOCATOR_KIND == LocatorKind::Random
            && T::Key::KIND == OpaqueRowKey::KIND
            && decoded.logical_key.get(1..) != Some(row.locator.as_slice())
        {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(RawRow {
            rowid: row.rowid,
            locator: row.locator,
            logical_key: decoded.logical_key.to_vec(),
            indexes,
            payload: Zeroizing::new(decoded.payload.to_vec()),
        })
    }

    fn seal_logical_row<K: LogicalKey>(
        &self,
        domain: u8,
        locator: &[u8],
        key: &K,
        indexes: &IndexKeys,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.seal_encoded_row(domain, locator, &key.encode(), indexes, payload, rng)
    }

    fn seal_encoded_row(
        &self,
        domain: u8,
        locator: &[u8],
        logical_key: &[u8],
        indexes: &IndexKeys,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(encode_record(logical_key, indexes, payload)?);
        Ok(self
            .row_key(domain)
            .seal(&self.row_ad(domain, locator), &plain, rng))
    }

    fn open_row(&self, domain: u8, locator: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .row_key(domain)
            .open(&self.row_ad(domain, locator), sealed)?)
    }

    fn physical_indexes(&self, domain: u8, indexes: &IndexKeys) -> [Option<Vec<u8>>; 5] {
        let keys = indexes.as_array();
        std::array::from_fn(|position| {
            keys[position].map(|key| self.index_for(domain, (position + 1) as u8, key).to_vec())
        })
    }

    fn index_for(&self, table_domain: u8, index_domain: u8, logical_key: &[u8]) -> [u8; 32] {
        let mut key_label = Vec::with_capacity(INDEX_KEY_DOMAIN.len() + 32 + 2);
        key_label.extend_from_slice(INDEX_KEY_DOMAIN);
        key_label.extend_from_slice(&self.metadata.database_id);
        key_label.push(table_domain);
        key_label.push(index_domain);
        let index_key = self.index_root.derive(&key_label);

        let mut input = Vec::with_capacity(INDEX_INPUT_DOMAIN.len() + logical_key.len());
        input.extend_from_slice(INDEX_INPUT_DOMAIN);
        input.extend_from_slice(logical_key);
        index_key.hmac_sha256(&input)
    }

    fn row_key(&self, table_domain: u8) -> StorageKey {
        let mut label = Vec::with_capacity(ROW_KEY_DOMAIN.len() + 32 + 1);
        label.extend_from_slice(ROW_KEY_DOMAIN);
        label.extend_from_slice(&self.metadata.database_id);
        label.push(table_domain);
        self.row_root.derive(&label)
    }

    fn row_ad(&self, table_domain: u8, locator: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(ROW_AD_DOMAIN.len() + 32 + 4 + 1 + locator.len());
        ad.extend_from_slice(ROW_AD_DOMAIN);
        ad.extend_from_slice(&self.metadata.database_id);
        ad.extend_from_slice(&self.metadata.schema_version.to_be_bytes());
        ad.push(table_domain);
        ad.extend_from_slice(locator);
        ad
    }
}

#[derive(Debug)]
struct SqlRow {
    rowid: i64,
    locator: Vec<u8>,
    unique_index: Option<Vec<u8>>,
    index_a: Option<Vec<u8>>,
    index_b: Option<Vec<u8>>,
    index_c: Option<Vec<u8>>,
    index_d: Option<Vec<u8>>,
    blob: Vec<u8>,
}

fn sql_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SqlRow> {
    Ok(SqlRow {
        rowid: row.get(0)?,
        locator: row.get(1)?,
        unique_index: row.get(2)?,
        index_a: row.get(3)?,
        index_b: row.get(4)?,
        index_c: row.get(5)?,
        index_d: row.get(6)?,
        blob: row.get(7)?,
    })
}

fn insert_record(
    conn: &Connection,
    domain: u8,
    locator: &[u8; 16],
    indexes: &[Option<Vec<u8>>; 5],
    sealed: &[u8],
) -> Result<i64> {
    match conn.execute(
        "INSERT INTO store_records
         (table_domain, locator, unique_index, index_a, index_b, index_c, index_d, blob)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            domain,
            locator.as_slice(),
            indexes[0].as_deref(),
            indexes[1].as_deref(),
            indexes[2].as_deref(),
            indexes[3].as_deref(),
            indexes[4].as_deref(),
            sealed
        ],
    ) {
        Ok(_) => Ok(conn.last_insert_rowid()),
        Err(error) if constraint_violation(&error) => Err(StoreError::DuplicateIndex),
        Err(error) => Err(StoreError::Db(error)),
    }
}

fn encode_record(logical_key: &[u8], indexes: &IndexKeys, payload: &[u8]) -> Result<Vec<u8>> {
    if logical_key.is_empty() || logical_key.len() > MAX_CANONICAL_KEY_BYTES {
        return Err(StoreError::RecordBounds);
    }
    let key_length = u16::try_from(logical_key.len()).map_err(|_| StoreError::RecordBounds)?;
    let mut flags = 0u8;
    let mut index_bytes = 0usize;
    for (position, key) in indexes.as_array().iter().enumerate() {
        if let Some(key) = key {
            if key.is_empty() || key.len() > MAX_CANONICAL_KEY_BYTES {
                return Err(StoreError::RecordBounds);
            }
            flags |= 1 << position;
            index_bytes = index_bytes
                .checked_add(2 + key.len())
                .ok_or(StoreError::RecordBounds)?;
        }
    }
    let total = 1usize
        .checked_add(2)
        .and_then(|value| value.checked_add(logical_key.len()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(index_bytes))
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(StoreError::RecordBounds)?;
    if total > MAX_RECORD_BYTES {
        return Err(StoreError::RecordBounds);
    }
    let mut plain = Vec::with_capacity(total);
    plain.push(LOGICAL_RECORD_VERSION);
    plain.extend_from_slice(&key_length.to_be_bytes());
    plain.extend_from_slice(logical_key);
    plain.push(flags);
    for key in indexes.as_array().into_iter().flatten() {
        let length = u16::try_from(key.len()).map_err(|_| StoreError::RecordBounds)?;
        plain.extend_from_slice(&length.to_be_bytes());
        plain.extend_from_slice(key);
    }
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
    if remainder.len() < 3 {
        return Err(StoreError::Serialization);
    }
    let key_length = usize::from(u16::from_be_bytes(
        remainder[..2]
            .try_into()
            .map_err(|_| StoreError::Serialization)?,
    ));
    let mut body = &remainder[2..];
    if key_length == 0 || key_length > MAX_CANONICAL_KEY_BYTES || body.len() <= key_length {
        return Err(StoreError::Serialization);
    }
    let logical_key = &body[..key_length];
    body = &body[key_length..];
    let flags = body[0];
    if flags & !0b1_1111 != 0 {
        return Err(StoreError::Serialization);
    }
    body = &body[1..];
    let mut indexes = [None; 5];
    for (position, slot) in indexes.iter_mut().enumerate() {
        if flags & (1 << position) == 0 {
            continue;
        }
        if body.len() < 2 {
            return Err(StoreError::Serialization);
        }
        let length = usize::from(u16::from_be_bytes(
            body[..2]
                .try_into()
                .map_err(|_| StoreError::Serialization)?,
        ));
        body = &body[2..];
        if length == 0 || length > MAX_CANONICAL_KEY_BYTES || body.len() < length {
            return Err(StoreError::Serialization);
        }
        *slot = Some(&body[..length]);
        body = &body[length..];
    }
    Ok(DecodedRecord {
        logical_key,
        indexes,
        payload: body,
    })
}

fn decoded_indexes_owned(decoded: &DecodedRecord<'_>) -> Result<IndexKeys> {
    let [unique, a, b, c, d] = decoded.indexes;
    Ok(IndexKeys {
        unique: unique.map(ToOwned::to_owned),
        a: a.map(ToOwned::to_owned),
        b: b.map(ToOwned::to_owned),
        c: c.map(ToOwned::to_owned),
        d: d.map(ToOwned::to_owned),
    })
}

fn validate_index_shape(domain: u8, indexes: &IndexKeys) -> Result<()> {
    let shape = indexes.as_array().map(|value| value.is_some());
    let expected = match domain {
        MessageRows::DOMAIN => [true, true, false, false, false],
        QueueRows::DOMAIN => [false, true, shape[2], shape[3], true],
        PendingRows::DOMAIN => [shape[0], false, false, false, false],
        GroupChainRows::DOMAIN => [false, true, false, false, false],
        GroupMessageRows::DOMAIN => [true, true, false, false, false],
        MediaObjectRows::DOMAIN => [false, true, false, false, false],
        NoteRows::DOMAIN => [true, false, false, false, false],
        DeviceSyncRows::DOMAIN => [true, false, false, false, false],
        ContactDeviceRows::DOMAIN => [false, true, false, false, false],
        MessageDeviceDeliveryRows::DOMAIN => [false, true, true, false, false],
        1..=31 => [false; 5],
        MigrationCheckpointRows::DOMAIN => [false; 5],
        _ => return Err(StoreError::SchemaMismatch),
    };
    if shape != expected {
        return Err(StoreError::LogicalKeyMismatch);
    }
    for key in indexes.as_array().into_iter().flatten() {
        if key.is_empty() || key.len() > MAX_CANONICAL_KEY_BYTES {
            return Err(StoreError::RecordBounds);
        }
    }
    Ok(())
}

fn table_locator_kind(domain: u8) -> Result<LocatorKind> {
    match domain {
        IdentityRows::DOMAIN
        | SessionRows::DOMAIN
        | CapabilityRows::DOMAIN
        | SeenRows::DOMAIN
        | ReceiptReplayRows::DOMAIN
        | ContactRows::DOMAIN
        | PrekeyRows::DOMAIN
        | ResetRows::DOMAIN
        | GroupRows::DOMAIN
        | GroupAuthorityRows::DOMAIN
        | GroupChainRows::DOMAIN
        | MediaTransferRows::DOMAIN
        | MediaObjectRows::DOMAIN
        | LocalMetadataRows::DOMAIN
        | ScheduledRows::DOMAIN
        | EphemeralRows::DOMAIN
        | DeviceStateRows::DOMAIN
        | ContactDeviceRows::DOMAIN
        | MessageDeviceDeliveryRows::DOMAIN
        | PresentationMarkerRows::DOMAIN
        | DeferredControlRows::DOMAIN
        | DeviceLinkRecoveryRows::DOMAIN
        | ProvisionalRequestRows::DOMAIN
        | AdmissionReplayRows::DOMAIN
        | BlockedIdentityRows::DOMAIN
        | MigrationCheckpointRows::DOMAIN => Ok(LocatorKind::Equality),
        MessageRows::DOMAIN
        | QueueRows::DOMAIN
        | PendingRows::DOMAIN
        | GroupMessageRows::DOMAIN
        | NoteRows::DOMAIN
        | DeviceSyncRows::DOMAIN => Ok(LocatorKind::Random),
        _ => Err(StoreError::SchemaMismatch),
    }
}

fn validate_key_for_domain(domain: u8, key: &[u8]) -> Result<()> {
    let valid = match domain {
        IdentityRows::DOMAIN
        | PrekeyRows::DOMAIN
        | DeviceStateRows::DOMAIN
        | PresentationMarkerRows::DOMAIN
        | MigrationCheckpointRows::DOMAIN => SingletonKey::validate_encoded(key),
        SessionRows::DOMAIN
        | CapabilityRows::DOMAIN
        | ContactRows::DOMAIN
        | ResetRows::DOMAIN
        | DeviceLinkRecoveryRows::DOMAIN
        | ProvisionalRequestRows::DOMAIN => AccountKey::validate_encoded(key),
        MessageRows::DOMAIN => MessageKey::validate_encoded(key),
        QueueRows::DOMAIN | PendingRows::DOMAIN => OpaqueRowKey::validate_encoded(key),
        SeenRows::DOMAIN
        | ReceiptReplayRows::DOMAIN
        | DeferredControlRows::DOMAIN
        | NoteRows::DOMAIN
        | ScheduledRows::DOMAIN => ContentKey::validate_encoded(key),
        AdmissionReplayRows::DOMAIN => ContentKey::validate_encoded(key),
        GroupRows::DOMAIN | GroupAuthorityRows::DOMAIN => GroupKey::validate_encoded(key),
        GroupChainRows::DOMAIN => GroupMemberKey::validate_encoded(key),
        GroupMessageRows::DOMAIN => GroupMessageKey::validate_encoded(key),
        MediaTransferRows::DOMAIN | MediaObjectRows::DOMAIN => LocalIdKey::validate_encoded(key),
        LocalMetadataRows::DOMAIN => MetadataKey::validate_encoded(key),
        EphemeralRows::DOMAIN => EphemeralKey::validate_encoded(key),
        DeviceSyncRows::DOMAIN => DigestKey::validate_encoded(key),
        ContactDeviceRows::DOMAIN | BlockedIdentityRows::DOMAIN => {
            AccountDeviceKey::validate_encoded(key)
        }
        MessageDeviceDeliveryRows::DOMAIN => MessageDeviceKey::validate_encoded(key),
        _ => return Err(StoreError::SchemaMismatch),
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::LogicalKeyMismatch)
    }
}

fn domain_uses_opaque_key(domain: u8) -> bool {
    matches!(domain, QueueRows::DOMAIN | PendingRows::DOMAIN)
}

fn seal_metadata(
    key: &StorageKey,
    metadata: &DatabaseMetadata,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let encoded = postcard::to_allocvec(metadata).map_err(|_| StoreError::Serialization)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(1 + encoded.len()));
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
    decode_exact(encoded)
}

fn validate_metadata(
    metadata: &DatabaseMetadata,
    physical_version: u32,
    allow_incomplete: bool,
) -> Result<()> {
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
    let mut ids = std::collections::BTreeSet::new();
    let mut current = 0u32;
    for (position, migration) in metadata.migrations.iter().enumerate() {
        if !ids.insert(migration.id) {
            return Err(StoreError::DuplicateMigration);
        }
        if !(migration.completed || allow_incomplete && position + 1 == metadata.migrations.len()) {
            return Err(StoreError::IncompleteMigration);
        }
        if migration.from_version != current || migration.to_version <= migration.from_version {
            return Err(StoreError::InvalidMigrationLedger);
        }
        current = migration.to_version;
    }
    let known_fresh = metadata.migrations.len() == 1
        && metadata.migrations[0].id == FRESH_MIGRATION_ID
        && metadata.migrations[0].from_version == 0
        && metadata.migrations[0].to_version == SCHEMA_VERSION;
    let known_legacy = metadata.migrations.len() == 2
        && metadata.migrations[0].id == LEGACY_MIGRATION_ID
        && metadata.migrations[0].from_version == 0
        && metadata.migrations[0].to_version == 1
        && metadata.migrations[1].id == OPAQUE_MIGRATION_ID
        && metadata.migrations[1].from_version == 1
        && metadata.migrations[1].to_version == SCHEMA_VERSION;
    if (known_fresh && metadata.source_fingerprint.is_some())
        || (known_legacy && metadata.source_fingerprint.is_none())
    {
        return Err(StoreError::InvalidMigrationLedger);
    }
    if (!known_fresh && !known_legacy) || current != metadata.schema_version {
        return Err(StoreError::InvalidMigrationLedger);
    }
    if !allow_incomplete && metadata.migrations.iter().any(|entry| !entry.completed) {
        return Err(StoreError::IncompleteMigration);
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

fn constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
                && matches!(inner.extended_code, 1555 | 2067)
    )
}

#[cfg(unix)]
pub(crate) fn protect_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn protect_file(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn protect_sqlite_files(path: &Path) -> Result<()> {
    protect_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        if sidecar.exists() {
            protect_file(&sidecar)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn logical_record_encoding_is_exact_and_bounded() {
        let key = MessageKey::new([1; 32], 0, [2; 16]);
        let indexes = IndexKeys::message(&ContentKey::new([2; 16]), &AccountKey::new([1; 32]));
        let encoded = encode_record(&key.encode(), &indexes, b"payload").unwrap();
        let decoded = decode_record(&encoded).unwrap();
        assert_eq!(decoded.logical_key, key.encode());
        assert_eq!(decoded.payload, b"payload");
        let content_key = ContentKey::new([2; 16]).encode();
        assert_eq!(decoded.indexes[0], Some(content_key.as_slice()));
        let mut future = encoded;
        future[0] = 2;
        assert!(matches!(
            decode_record(&future),
            Err(StoreError::UnsupportedRecordVersion)
        ));
    }

    #[test]
    fn metadata_accepts_only_fresh_or_legacy_complete_chains() {
        let fresh = DatabaseMetadata::fresh([1; 32]);
        validate_metadata(&fresh, SCHEMA_VERSION, false).unwrap();
        let mut legacy = DatabaseMetadata::legacy_destination([2; 32], [3; 32], false);
        assert!(matches!(
            validate_metadata(&legacy, SCHEMA_VERSION, false),
            Err(StoreError::IncompleteMigration)
        ));
        validate_metadata(&legacy, SCHEMA_VERSION, true).unwrap();
        legacy.migrations[1].completed = true;
        validate_metadata(&legacy, SCHEMA_VERSION, false).unwrap();
        legacy.migrations.push(legacy.migrations[1].clone());
        assert!(matches!(
            validate_metadata(&legacy, SCHEMA_VERSION, false),
            Err(StoreError::DuplicateMigration)
        ));
    }

    #[test]
    fn random_database_ids_are_nonzero() {
        let mut rng = StdRng::seed_from_u64(0x2700);
        assert_ne!(random_database_id(&mut rng).unwrap(), [0; 32]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_logical_record_bytes_fail_closed_without_panicking(
            bytes in proptest::collection::vec(any::<u8>(), 0..4_096),
        ) {
            let _ = decode_record(&bytes);
        }
    }
}
