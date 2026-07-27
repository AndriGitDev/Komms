//! Released-schema migration into the ADR-0027 opaque store.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use rand_core::OsRng;
use rusqlite::types::Value;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{derive_kek, Identity, KdfProfile, Session, StorageKey};
use kult_protocol::{CapabilityControl, Envelope};

use crate::{
    store_lock_path, store_v2, ContactDeviceRecord, ContactRecord, DeviceStateRecord,
    EphemeralRecord, GroupAuthorityRecord, GroupMessageRecord, GroupRecord, LocalMetadataRecord,
    MediaObjectRecord, MediaTransferRecord, MessageDeviceDeliveryRecord, MessageRecord,
    NoteMessageRecord, Result, ScheduledMessageRecord, Store, StoreError,
};

const SCHEMA_V0_1: &str = include_str!("../tests/fixtures/schema-v0.1.0.sql");
const SCHEMA_V0_2: &str = include_str!("../tests/fixtures/schema-v0.2.0.sql");
const SCHEMA_V0_3: &str = include_str!("../tests/fixtures/schema-v0.3.0.sql");
const BATCH_ROWS: usize = 256;
const MAX_TOTAL_ROWS: u64 = 50_000_000;
const MAX_LEGACY_CIPHERTEXT: usize = store_v2::MAX_RECORD_BYTES + 128;
const WORKSPACE_RESERVE: u64 = 64 * 1024 * 1024;
const ESTIMATED_OPAQUE_ROW_OVERHEAD: u64 = 1_024;
const CHECKPOINT_TABLES: usize = 25;
const SOURCE_FINGERPRINT_DOMAIN: &[u8] = b"Komms-Store-Legacy-Fingerprint-v2";
const WRAP_AD: &[u8] = b"KK-store-wrap-v1";

#[derive(Clone, Copy)]
struct TableSpec {
    name: &'static str,
    columns: &'static str,
    max_rows: u64,
    optional_receipt: bool,
}

const TABLES: [TableSpec; CHECKPOINT_TABLES] = [
    TableSpec {
        name: "identity",
        columns: "blob",
        max_rows: 1,
        optional_receipt: false,
    },
    TableSpec {
        name: "sessions",
        columns: "peer, blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "capabilities",
        columns: "peer, blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "messages",
        columns: "blob",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "queue",
        columns: "blob",
        max_rows: 1_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "seen",
        columns: "id",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "receipt_replay",
        columns: "id, blob",
        max_rows: 1_000_000,
        optional_receipt: true,
    },
    TableSpec {
        name: "contacts",
        columns: "peer, blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "prekeys",
        columns: "blob",
        max_rows: 1,
        optional_receipt: false,
    },
    TableSpec {
        name: "pending",
        columns: "blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "resets",
        columns: "peer",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "groups",
        columns: "gid, blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "group_authority",
        columns: "gid, blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "group_chains",
        columns: "gid, peer, blob",
        max_rows: 1_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "group_msgs",
        columns: "blob",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "media_transfers",
        columns: "id, blob",
        max_rows: 1_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "media_objects",
        columns: "id, blob",
        max_rows: 2_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "local_metadata",
        columns: "blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "note_messages",
        columns: "blob",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "scheduled_messages",
        columns: "blob",
        max_rows: 1_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "ephemeral",
        columns: "blob",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "device_state",
        columns: "blob",
        max_rows: 1,
        optional_receipt: false,
    },
    TableSpec {
        name: "device_sync",
        columns: "blob",
        max_rows: 100_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "contact_devices",
        columns: "blob",
        max_rows: 1_000_000,
        optional_receipt: false,
    },
    TableSpec {
        name: "message_device_delivery",
        columns: "blob",
        max_rows: 10_000_000,
        optional_receipt: false,
    },
];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MigrationCheckpoint {
    source_fingerprint: [u8; 32],
    next_table: u8,
    last_rowid: i64,
    copied_counts: [u64; CHECKPOINT_TABLES],
}

struct LegacyRow {
    rowid: i64,
    values: Vec<Value>,
}

struct LegacyKeys {
    fingerprint: StorageKey,
    identity: StorageKey,
    sessions: StorageKey,
    capabilities: StorageKey,
    messages: StorageKey,
    queue: StorageKey,
    contacts: StorageKey,
    prekeys: StorageKey,
    pending: StorageKey,
    groups: StorageKey,
    media: StorageKey,
    local_metadata: StorageKey,
    notes: StorageKey,
    scheduled: StorageKey,
    ephemeral: StorageKey,
    devices: StorageKey,
}

struct LegacyReader {
    conn: Connection,
    keys: LegacyKeys,
    profile: KdfProfile,
    has_receipt_replay: bool,
    meta_fingerprint: Vec<u8>,
}

struct SourceSnapshot {
    fingerprint: [u8; 32],
    counts: [u64; CHECKPOINT_TABLES],
}

pub(crate) fn recover_missing_source(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let rollback = rollback_path(path)?;
    if !rollback.is_file() {
        return Ok(());
    }
    atomic_replace(&rollback, path)?;
    store_v2::sync_directory(parent_directory(path))?;
    Ok(())
}

pub(crate) fn cleanup_completed_replacement(path: &Path) -> Result<()> {
    let temporary = migration_path(path)?;
    if temporary.exists() {
        return Err(StoreError::ReplacementRecovery);
    }
    let rollback = rollback_path(path)?;
    if rollback.exists() {
        fs::remove_file(&rollback)?;
        store_v2::sync_directory(parent_directory(path))?;
    }
    cleanup_obsolete_siblings(&temporary)?;
    Ok(())
}

pub(crate) fn migrate_legacy(
    path: &Path,
    passphrase: &[u8],
    lock: File,
    source_database_lock: Option<File>,
) -> Result<Store> {
    let source = LegacyReader::open(path, passphrase)?;
    let snapshot = source.validate_and_fingerprint()?;
    ensure_workspace(path, &snapshot)?;

    let temporary = migration_path(path)?;
    let mut target = if temporary.exists() {
        Store::open_incomplete(&temporary, passphrase)?
    } else {
        let mut rng = OsRng;
        let mut store = Store::create(&temporary, passphrase, source.profile, &mut rng)?;
        store.metadata = store_v2::DatabaseMetadata::legacy_destination(
            store.metadata.database_id,
            snapshot.fingerprint,
            false,
        );
        let checkpoint = MigrationCheckpoint {
            source_fingerprint: snapshot.fingerprint,
            next_table: 0,
            last_rowid: 0,
            copied_counts: [0; CHECKPOINT_TABLES],
        };
        let tx = store.conn.unchecked_transaction()?;
        store_v2::write_metadata_with_key(&tx, &store.metadata_key, &store.metadata, &mut rng)?;
        write_checkpoint_on(&store, &tx, &checkpoint, &mut rng)?;
        tx.commit()?;
        store
    };

    if target.metadata.source_fingerprint != Some(snapshot.fingerprint) {
        return Err(StoreError::MigrationSourceChanged);
    }
    let incomplete = target
        .metadata
        .migrations
        .last()
        .is_some_and(|entry| !entry.completed);
    if incomplete {
        let checkpoint = read_checkpoint(&target)?.ok_or(StoreError::MigrationValidation)?;
        if checkpoint.source_fingerprint != snapshot.fingerprint {
            return Err(StoreError::MigrationSourceChanged);
        }
        copy_rows(&source, &target, checkpoint)?;
        finish_target(&mut target, &snapshot)?;
    } else {
        if read_checkpoint(&target)?.is_some() {
            return Err(StoreError::MigrationValidation);
        }
        validate_target_counts(&target, &snapshot.counts)?;
        target.validate_open_state()?;
    }

    sync_database_for_replacement(&target.conn)?;
    target.validate_open_state()?;
    drop(target);
    sync_file(&temporary)?;
    store_v2::sync_directory(parent_directory(path))?;
    failpoint(1)?;

    let rollback = rollback_path(path)?;
    if rollback.exists() {
        let rollback_reader = LegacyReader::open(&rollback, passphrase)?;
        let rollback_snapshot = rollback_reader.validate_and_fingerprint()?;
        if rollback_snapshot.fingerprint != snapshot.fingerprint {
            return Err(StoreError::ReplacementRecovery);
        }
    } else {
        sync_database_for_replacement(&source.conn)?;
        fs::copy(path, &rollback)?;
        store_v2::protect_sqlite_files(&rollback)?;
        sync_file(&rollback)?;
        store_v2::sync_directory(parent_directory(path))?;
    }
    failpoint(2)?;

    drop(source);
    drop(source_database_lock);
    atomic_replace(&temporary, path)?;
    failpoint(3)?;
    store_v2::sync_directory(parent_directory(path))?;
    failpoint(4)?;

    let conn = Connection::open(path)?;
    let database_lock = super::acquire_database_identity_lock(path)?;
    let store = match Store::open_v2_with_parts(path, passphrase, conn, database_lock, lock, false)
    {
        Ok(store) => store,
        Err(_) => {
            restore_rollback(path, &rollback)?;
            return Err(StoreError::ReplacementRecovery);
        }
    };
    failpoint(5)?;
    fs::remove_file(&rollback)?;
    store_v2::sync_directory(parent_directory(path))?;
    cleanup_obsolete_siblings(&temporary)?;
    Ok(store)
}

impl LegacyReader {
    fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
        sync_database_for_replacement(&conn)?;
        let has_receipt_replay = validate_released_schema(&conn)?;
        let meta_count: i64 = conn.query_row("SELECT COUNT(*) FROM meta", [], |row| row.get(0))?;
        if meta_count != 3 {
            return Err(StoreError::UnsupportedLegacySchema);
        }
        let get = |key: &str| -> Result<Vec<u8>> {
            conn.query_row("SELECT v FROM meta WHERE k = ?1", params![key], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or(StoreError::NotAStore)
        };
        let salt_bytes = get("salt")?;
        let salt: [u8; 16] = salt_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::NotAStore)?;
        let kdf_bytes = get("kdf")?;
        let (m_cost_kib, t_cost, p_cost): (u32, u32, u32) =
            crate::decode_exact(&kdf_bytes).map_err(|_| StoreError::NotAStore)?;
        let profile = KdfProfile {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        let wrapped = get("wrapped_sk")?;
        if wrapped.len() < 40 || wrapped.len() > 256 {
            return Err(StoreError::NotAStore);
        }
        let kek = derive_kek(passphrase, &salt, profile)?;
        let kek_key = StorageKey::from_bytes(*kek);
        let master_bytes = Zeroizing::new(kek_key.open(WRAP_AD, &wrapped)?);
        let master: [u8; 32] = master_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::NotAStore)?;
        let master = StorageKey::from_bytes(master);
        let mut meta_fingerprint = Vec::new();
        meta_fingerprint.extend_from_slice(&salt);
        meta_fingerprint.extend_from_slice(&kdf_bytes);
        meta_fingerprint.extend_from_slice(&wrapped);
        Ok(Self {
            conn,
            keys: LegacyKeys {
                fingerprint: master.derive(SOURCE_FINGERPRINT_DOMAIN),
                identity: master.derive(b"KK-store-identity"),
                sessions: master.derive(b"KK-store-sessions"),
                capabilities: master.derive(b"KK-store-capabilities"),
                messages: master.derive(b"KK-store-messages"),
                queue: master.derive(b"KK-store-queue"),
                contacts: master.derive(b"KK-store-contacts"),
                prekeys: master.derive(b"KK-store-prekeys"),
                pending: master.derive(b"KK-store-pending"),
                groups: master.derive(b"KK-store-groups"),
                media: master.derive(b"KK-store-media"),
                local_metadata: master.derive(b"KK-store-local-metadata"),
                notes: master.derive(b"KK-store-notes"),
                scheduled: master.derive(b"KK-store-scheduled"),
                ephemeral: master.derive(b"KK-store-ephemeral"),
                devices: master.derive(b"KK-store-devices"),
            },
            profile,
            has_receipt_replay,
            meta_fingerprint,
        })
    }

    fn validate_and_fingerprint(&self) -> Result<SourceSnapshot> {
        let mut state = self.keys.fingerprint.hmac_sha256(&self.meta_fingerprint);
        let mut counts = [0u64; CHECKPOINT_TABLES];
        let mut total = 0u64;
        for (index, spec) in TABLES.iter().enumerate() {
            if spec.optional_receipt && !self.has_receipt_replay {
                continue;
            }
            let count_sql = format!("SELECT COUNT(*) FROM {}", spec.name);
            let count: i64 = self.conn.query_row(&count_sql, [], |row| row.get(0))?;
            let count = u64::try_from(count).map_err(|_| StoreError::MigrationValidation)?;
            if count > spec.max_rows {
                return Err(StoreError::RecordBounds);
            }
            total = total.checked_add(count).ok_or(StoreError::RecordBounds)?;
            if total > MAX_TOTAL_ROWS {
                return Err(StoreError::RecordBounds);
            }
            counts[index] = count;
            let mut after = 0i64;
            loop {
                let batch = read_batch(&self.conn, spec, after)?;
                if batch.is_empty() {
                    break;
                }
                for row in &batch {
                    validate_raw_row(row)?;
                    let mut input = Vec::new();
                    input.extend_from_slice(&state);
                    input.push(index as u8);
                    input.extend_from_slice(&row.rowid.to_be_bytes());
                    for value in &row.values {
                        append_fingerprint_value(&mut input, value)?;
                    }
                    state = self.keys.fingerprint.hmac_sha256(&input);
                    after = row.rowid;
                }
            }
        }
        Ok(SourceSnapshot {
            fingerprint: state,
            counts,
        })
    }
}

fn copy_rows(
    source: &LegacyReader,
    target: &Store,
    mut checkpoint: MigrationCheckpoint,
) -> Result<()> {
    let mut rng = OsRng;
    while usize::from(checkpoint.next_table) < TABLES.len() {
        let index = usize::from(checkpoint.next_table);
        let spec = &TABLES[index];
        if spec.optional_receipt && !source.has_receipt_replay {
            checkpoint.next_table += 1;
            checkpoint.last_rowid = 0;
            let tx = target.conn.unchecked_transaction()?;
            write_checkpoint_on(target, &tx, &checkpoint, &mut rng)?;
            tx.commit()?;
            continue;
        }
        let batch = read_batch(&source.conn, spec, checkpoint.last_rowid)?;
        if batch.is_empty() {
            checkpoint.next_table += 1;
            checkpoint.last_rowid = 0;
            let tx = target.conn.unchecked_transaction()?;
            write_checkpoint_on(target, &tx, &checkpoint, &mut rng)?;
            tx.commit()?;
            continue;
        }
        let tx = target.conn.unchecked_transaction()?;
        for row in &batch {
            validate_raw_row(row)?;
            migrate_row(source, target, index, row, &mut rng)?;
            checkpoint.last_rowid = row.rowid;
            checkpoint.copied_counts[index] = checkpoint.copied_counts[index]
                .checked_add(1)
                .ok_or(StoreError::RecordBounds)?;
        }
        write_checkpoint_on(target, &tx, &checkpoint, &mut rng)?;
        tx.commit()?;
    }
    Ok(())
}

fn finish_target(target: &mut Store, snapshot: &SourceSnapshot) -> Result<()> {
    let checkpoint = read_checkpoint(target)?.ok_or(StoreError::MigrationValidation)?;
    if checkpoint.next_table as usize != TABLES.len()
        || checkpoint.last_rowid != 0
        || checkpoint.copied_counts != snapshot.counts
    {
        return Err(StoreError::MigrationValidation);
    }
    validate_target_counts(target, &snapshot.counts)?;
    let mut completed = target.metadata.clone();
    completed
        .migrations
        .last_mut()
        .ok_or(StoreError::InvalidMigrationLedger)?
        .completed = true;
    let mut rng = OsRng;
    let tx = target.conn.unchecked_transaction()?;
    target.delete_equality_on::<store_v2::MigrationCheckpointRows>(&tx, &store_v2::SingletonKey)?;
    store_v2::write_metadata_with_key(&tx, &target.metadata_key, &completed, &mut rng)?;
    tx.commit()?;
    target.metadata = completed;
    let integrity: String = target
        .conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StoreError::MigrationValidation);
    }
    target.validate_open_state()
}

fn read_checkpoint(target: &Store) -> Result<Option<MigrationCheckpoint>> {
    let Some(row) =
        target.get_equality::<store_v2::MigrationCheckpointRows>(&store_v2::SingletonKey)?
    else {
        return Ok(None);
    };
    row.verify_key(&store_v2::SingletonKey)?;
    Ok(Some(crate::decode_exact(&row.payload)?))
}

pub(crate) fn validate_checkpoint_state(target: &Store) -> Result<()> {
    let incomplete = target
        .metadata
        .migrations
        .last()
        .is_some_and(|entry| !entry.completed);
    let mut count = 0u8;
    target.validate_rows::<store_v2::MigrationCheckpointRows, _>(|row| {
        count = count
            .checked_add(1)
            .ok_or(StoreError::MigrationValidation)?;
        row.verify_key(&store_v2::SingletonKey)?;
        row.verify_indexes(&store_v2::IndexKeys::none())?;
        let checkpoint: MigrationCheckpoint = crate::decode_exact(&row.payload)?;
        if Some(checkpoint.source_fingerprint) != target.metadata.source_fingerprint
            || usize::from(checkpoint.next_table) > TABLES.len()
            || checkpoint.last_rowid < 0
            || checkpoint
                .copied_counts
                .iter()
                .any(|count| *count > MAX_TOTAL_ROWS)
        {
            return Err(StoreError::MigrationValidation);
        }
        Ok(())
    })?;
    if (incomplete && count != 1) || (!incomplete && count != 0) {
        return Err(StoreError::MigrationValidation);
    }
    Ok(())
}

fn write_checkpoint_on(
    target: &Store,
    conn: &Connection,
    checkpoint: &MigrationCheckpoint,
    rng: &mut OsRng,
) -> Result<()> {
    let encoded =
        Zeroizing::new(postcard::to_allocvec(checkpoint).map_err(|_| StoreError::Serialization)?);
    target.put_equality_on::<store_v2::MigrationCheckpointRows>(
        conn,
        &store_v2::SingletonKey,
        &encoded,
        store_v2::IndexKeys::none(),
        rng,
    )
}

fn migrate_row(
    source: &LegacyReader,
    target: &Store,
    table: usize,
    row: &LegacyRow,
    rng: &mut OsRng,
) -> Result<()> {
    match table {
        0 => {
            let plain = open_legacy(&source.keys.identity, b"identity", blob(row, 0)?)?;
            let bytes: [u8; 64] = plain
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Serialization)?;
            target.put_identity(&Identity::from_bytes(&bytes), rng)
        }
        1 => {
            let peer = fixed_blob::<32>(row, 0)?;
            let session = Session::unseal(blob(row, 1)?, &source.keys.sessions)?;
            target.put_session(&peer, &session, rng)
        }
        2 => {
            let peer = fixed_blob::<32>(row, 0)?;
            let plain = open_legacy(&source.keys.capabilities, b"capability", blob(row, 1)?)?;
            let capability = CapabilityControl::decode(&plain)?;
            target.put_capabilities(&peer, &capability, rng)
        }
        3 => {
            let plain = open_legacy(&source.keys.messages, b"message", blob(row, 0)?)?;
            let record: MessageRecord = crate::decode_exact(&plain)?;
            target.put_message(&record, rng)
        }
        4 => {
            let plain = open_legacy(&source.keys.queue, b"queue", blob(row, 0)?)?;
            let item = Store::decode_queue_item(&plain)?;
            target.queue_push(&item, rng).map(|_| ())
        }
        5 => {
            let id = fixed_blob::<16>(row, 0)?;
            if !target.mark_seen(&id)? {
                return Err(StoreError::MigrationValidation);
            }
            Ok(())
        }
        6 => {
            let id = fixed_blob::<16>(row, 0)?;
            let plain = open_legacy(&source.keys.queue, b"receipt-replay", blob(row, 1)?)?;
            let (peer, received_at): ([u8; 32], u64) = crate::decode_exact(&plain)?;
            target.put_receipt_replay(&id, &peer, received_at, rng)
        }
        7 => {
            let peer = fixed_blob::<32>(row, 0)?;
            let plain = open_legacy(&source.keys.contacts, b"contact", blob(row, 1)?)?;
            let record: ContactRecord = crate::decode_exact(&plain)?;
            if record.peer != peer {
                return Err(StoreError::LogicalKeyMismatch);
            }
            target.put_contact(&record, rng)
        }
        8 => {
            let plain = open_legacy(&source.keys.prekeys, b"prekeys", blob(row, 0)?)?;
            target.put_prekeys(&plain, rng)
        }
        9 => {
            let plain = open_legacy(&source.keys.pending, b"pending", blob(row, 0)?)?;
            let (encoded, received_at): (Vec<u8>, u64) = crate::decode_exact(&plain)?;
            let envelope = Envelope::decode(&encoded)?;
            target.pending_push(&envelope, received_at, rng).map(|_| ())
        }
        10 => {
            let peer = fixed_blob::<32>(row, 0)?;
            target.put_reset_marker(&peer)
        }
        11 => {
            let group = fixed_blob::<32>(row, 0)?;
            let plain = open_legacy(&source.keys.groups, b"group", blob(row, 1)?)?;
            let record: GroupRecord = crate::decode_exact(&plain)?;
            if record.id != group {
                return Err(StoreError::LogicalKeyMismatch);
            }
            target.put_group(&record, rng)
        }
        12 => {
            let group = fixed_blob::<32>(row, 0)?;
            if target.get_group(&group)?.is_none() {
                return Err(StoreError::MigrationValidation);
            }
            let plain = open_legacy(&source.keys.groups, b"group-authority", blob(row, 1)?)?;
            let record: GroupAuthorityRecord = crate::decode_exact(&plain)?;
            if record.group != group {
                return Err(StoreError::LogicalKeyMismatch);
            }
            target.put_group_authority(&record, rng)
        }
        13 => {
            let group = fixed_blob::<32>(row, 0)?;
            let peer = fixed_blob::<32>(row, 1)?;
            if target.get_group(&group)?.is_none() {
                return Err(StoreError::MigrationValidation);
            }
            let plain = open_legacy(&source.keys.groups, b"group-chain", blob(row, 2)?)?;
            target.put_group_chain(&group, &peer, &plain, rng)
        }
        14 => {
            let plain = open_legacy(&source.keys.groups, b"group-msg", blob(row, 0)?)?;
            let record: GroupMessageRecord = crate::decode_exact(&plain)?;
            target.put_group_message(&record, rng)
        }
        15 => {
            let local_id = fixed_blob::<16>(row, 0)?;
            let plain = open_legacy(&source.keys.media, b"media-transfer", blob(row, 1)?)?;
            let record: MediaTransferRecord = decode_legacy_media(&plain)?;
            if record.local_id != local_id {
                return Err(StoreError::LogicalKeyMismatch);
            }
            target.put_media_transfer(&record, rng)
        }
        16 => {
            let local_id = fixed_blob::<16>(row, 0)?;
            let plain = open_legacy(&source.keys.media, b"media-object", blob(row, 1)?)?;
            let record: MediaObjectRecord = decode_legacy_media(&plain)?;
            if record.local_id != local_id
                || target.get_media_transfer(&record.transfer_id)?.is_none()
            {
                return Err(StoreError::MigrationValidation);
            }
            target.put_media_object(&record, rng)
        }
        17 => {
            let plain = open_legacy(
                &source.keys.local_metadata,
                b"local-metadata",
                blob(row, 0)?,
            )?;
            let encoded = plain
                .strip_prefix(b"KLM1")
                .ok_or(StoreError::Serialization)?;
            let record: LocalMetadataRecord = crate::decode_exact(encoded)?;
            target.put_local_metadata(&record, rng)
        }
        18 => {
            let plain = open_legacy(&source.keys.notes, b"note-to-self-message", blob(row, 0)?)?;
            let encoded = plain
                .strip_prefix(b"KNT1")
                .ok_or(StoreError::Serialization)?;
            let record: NoteMessageRecord = crate::decode_exact(encoded)?;
            target.put_note_message(&record, rng)
        }
        19 => {
            let plain = open_legacy(&source.keys.scheduled, b"scheduled-message", blob(row, 0)?)?;
            let record: ScheduledMessageRecord = crate::decode_exact(&plain)?;
            target.put_scheduled_message(&record, rng)
        }
        20 => {
            let plain = open_legacy(&source.keys.ephemeral, b"ephemeral-v1", blob(row, 0)?)?;
            let record: EphemeralRecord = crate::decode_exact(&plain)?;
            target.put_ephemeral_record(&record, rng)
        }
        21 => {
            let plain = open_legacy(&source.keys.devices, b"device-state-v1", blob(row, 0)?)?;
            let record: DeviceStateRecord = crate::decode_exact(&plain)?;
            target.put_device_state(&record, rng)
        }
        22 => {
            let plain = open_legacy(&source.keys.devices, b"device-sync-v1", blob(row, 0)?)?;
            if !target.put_device_sync_event(&plain, rng)? {
                return Err(StoreError::MigrationValidation);
            }
            Ok(())
        }
        23 => {
            let plain = open_legacy(&source.keys.devices, b"contact-device-v1", blob(row, 0)?)?;
            let record: ContactDeviceRecord = crate::decode_exact(&plain)?;
            if target.get_contact(&record.account)?.is_none() {
                return Err(StoreError::MigrationValidation);
            }
            target.put_contact_device(&record, rng)
        }
        24 => {
            let plain = open_legacy(
                &source.keys.devices,
                b"message-device-delivery-v1",
                blob(row, 0)?,
            )?;
            let record: MessageDeviceDeliveryRecord = crate::decode_exact(&plain)?;
            if target
                .row_by_unique::<store_v2::MessageIdIndex>(&store_v2::ContentKey::new(
                    record.message,
                ))?
                .is_none()
            {
                return Err(StoreError::MigrationValidation);
            }
            target.put_message_device_delivery(&record, rng)
        }
        _ => Err(StoreError::MigrationValidation),
    }
}

fn decode_legacy_media<T>(plain: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let Some((&version, encoded)) = plain.split_first() else {
        return Err(StoreError::Serialization);
    };
    if version != 1 {
        return Err(StoreError::UnsupportedRecordVersion);
    }
    crate::decode_exact(encoded)
}

fn open_legacy(
    key: &StorageKey,
    associated_data: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 40 || sealed.len() > MAX_LEGACY_CIPHERTEXT {
        return Err(StoreError::RecordBounds);
    }
    let plain = Zeroizing::new(key.open(associated_data, sealed)?);
    if plain.len() > store_v2::MAX_RECORD_BYTES {
        return Err(StoreError::RecordBounds);
    }
    Ok(plain)
}

fn read_batch(conn: &Connection, spec: &TableSpec, after: i64) -> Result<Vec<LegacyRow>> {
    let sql = format!(
        "SELECT rowid, {} FROM {} WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        spec.columns, spec.name
    );
    let mut statement = conn.prepare(&sql)?;
    let column_count = statement.column_count();
    let rows = statement.query_map(params![after, BATCH_ROWS as i64], |row| {
        let rowid = row.get::<_, i64>(0)?;
        let mut values = Vec::with_capacity(column_count.saturating_sub(1));
        for column in 1..column_count {
            values.push(row.get::<_, Value>(column)?);
        }
        Ok(LegacyRow { rowid, values })
    })?;
    let mut batch = Vec::new();
    for row in rows {
        batch.push(row?);
    }
    Ok(batch)
}

fn validate_raw_row(row: &LegacyRow) -> Result<()> {
    if row.rowid <= 0 {
        return Err(StoreError::MigrationValidation);
    }
    for value in &row.values {
        match value {
            Value::Blob(bytes) if bytes.len() <= MAX_LEGACY_CIPHERTEXT => {}
            Value::Integer(_) => {}
            _ => return Err(StoreError::MigrationValidation),
        }
    }
    Ok(())
}

fn blob(row: &LegacyRow, index: usize) -> Result<&[u8]> {
    match row.values.get(index) {
        Some(Value::Blob(bytes)) if bytes.len() <= MAX_LEGACY_CIPHERTEXT => Ok(bytes),
        _ => Err(StoreError::MigrationValidation),
    }
}

fn fixed_blob<const N: usize>(row: &LegacyRow, index: usize) -> Result<[u8; N]> {
    blob(row, index)?
        .try_into()
        .map_err(|_| StoreError::MigrationValidation)
}

fn append_fingerprint_value(output: &mut Vec<u8>, value: &Value) -> Result<()> {
    match value {
        Value::Integer(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        Value::Blob(bytes) if bytes.len() <= MAX_LEGACY_CIPHERTEXT => {
            output.push(2);
            output.extend_from_slice(
                &u64::try_from(bytes.len())
                    .map_err(|_| StoreError::RecordBounds)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(bytes);
        }
        _ => return Err(StoreError::MigrationValidation),
    }
    Ok(())
}

fn validate_target_counts(target: &Store, expected: &[u64; CHECKPOINT_TABLES]) -> Result<()> {
    let actual = [
        target.count_rows::<store_v2::IdentityRows>()?,
        target.count_rows::<store_v2::SessionRows>()?,
        target.count_rows::<store_v2::CapabilityRows>()?,
        target.count_rows::<store_v2::MessageRows>()?,
        target.count_rows::<store_v2::QueueRows>()?,
        target.count_rows::<store_v2::SeenRows>()?,
        target.count_rows::<store_v2::ReceiptReplayRows>()?,
        target.count_rows::<store_v2::ContactRows>()?,
        target.count_rows::<store_v2::PrekeyRows>()?,
        target.count_rows::<store_v2::PendingRows>()?,
        target.count_rows::<store_v2::ResetRows>()?,
        target.count_rows::<store_v2::GroupRows>()?,
        target.count_rows::<store_v2::GroupAuthorityRows>()?,
        target.count_rows::<store_v2::GroupChainRows>()?,
        target.count_rows::<store_v2::GroupMessageRows>()?,
        target.count_rows::<store_v2::MediaTransferRows>()?,
        target.count_rows::<store_v2::MediaObjectRows>()?,
        target.count_rows::<store_v2::LocalMetadataRows>()?,
        target.count_rows::<store_v2::NoteRows>()?,
        target.count_rows::<store_v2::ScheduledRows>()?,
        target.count_rows::<store_v2::EphemeralRows>()?,
        target.count_rows::<store_v2::DeviceStateRows>()?,
        target.count_rows::<store_v2::DeviceSyncRows>()?,
        target.count_rows::<store_v2::ContactDeviceRows>()?,
        target.count_rows::<store_v2::MessageDeviceDeliveryRows>()?,
    ];
    if &actual != expected {
        return Err(StoreError::MigrationValidation);
    }
    Ok(())
}

fn validate_released_schema(conn: &Connection) -> Result<bool> {
    let actual = schema_objects(conn)?;
    for (fixture, has_receipt) in [
        (SCHEMA_V0_1, false),
        (SCHEMA_V0_2, false),
        (SCHEMA_V0_3, true),
    ] {
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(fixture)?;
        if actual == schema_objects(&expected)? {
            return Ok(has_receipt);
        }
    }
    Err(StoreError::UnsupportedLegacySchema)
}

fn schema_objects(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut statement = conn.prepare(
        "SELECT type, name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        ))
    })?;
    let mut objects = Vec::new();
    for row in rows {
        let (kind, name, sql) = row?;
        objects.push((kind, name, normalize_sql(&sql)));
    }
    Ok(objects)
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn ensure_workspace(path: &Path, snapshot: &SourceSnapshot) -> Result<()> {
    let main = fs::metadata(path)?.len();
    let wal = sidecar_path(path, "-wal");
    let wal = fs::metadata(wal).map_or(0, |metadata| metadata.len());
    let source = main
        .checked_add(wal)
        .ok_or(StoreError::InsufficientMigrationSpace)?;
    let rows = snapshot.counts.into_iter().try_fold(0u64, |total, count| {
        total
            .checked_add(count)
            .ok_or(StoreError::InsufficientMigrationSpace)
    })?;
    let opaque_overhead = rows
        .checked_mul(ESTIMATED_OPAQUE_ROW_OVERHEAD)
        .ok_or(StoreError::InsufficientMigrationSpace)?;
    let required = source
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(opaque_overhead))
        .and_then(|bytes| bytes.checked_add(WORKSPACE_RESERVE))
        .ok_or(StoreError::InsufficientMigrationSpace)?;
    if fs2::available_space(parent_directory(path))? < required {
        return Err(StoreError::InsufficientMigrationSpace);
    }
    Ok(())
}

pub(crate) fn sync_database_for_replacement(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA synchronous = FULL;
         PRAGMA wal_checkpoint(TRUNCATE);
         PRAGMA journal_mode = DELETE;",
    )?;
    Ok(())
}

pub(crate) fn sync_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn restore_rollback(path: &Path, rollback: &Path) -> Result<()> {
    if !rollback.is_file() {
        return Err(StoreError::ReplacementRecovery);
    }
    let recovery = recovery_path(path)?;
    if recovery.exists() {
        return Err(StoreError::ReplacementRecovery);
    }
    fs::copy(rollback, &recovery)?;
    store_v2::protect_sqlite_files(&recovery)?;
    sync_file(&recovery)?;
    atomic_replace(&recovery, path)?;
    store_v2::sync_directory(parent_directory(path))?;
    Ok(())
}

pub(crate) fn cleanup_obsolete_siblings(temporary: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(temporary, suffix);
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    if let Ok(lock) = store_lock_path(temporary) {
        if lock.exists() {
            fs::remove_file(lock)?;
        }
    }
    let media = media_path(temporary)?;
    if media.exists() {
        fs::remove_dir(&media).map_err(|_| StoreError::ReplacementRecovery)?;
    }
    Ok(())
}

fn migration_path(path: &Path) -> Result<PathBuf> {
    sibling_path(path, ".opaque-v2-migration")
}

fn rollback_path(path: &Path) -> Result<PathBuf> {
    sibling_path(path, ".opaque-v1-rollback")
}

fn recovery_path(path: &Path) -> Result<PathBuf> {
    sibling_path(path, ".opaque-v1-recovery")
}

fn media_path(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or(StoreError::NotAStore)?;
    let mut name = file_name.to_os_string();
    name.push(".media");
    Ok(path.with_file_name(name))
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or(StoreError::NotAStore)?;
    let mut name = file_name.to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(any(unix, windows))]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    atomicwrites::replace_atomic(source, destination)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn atomic_replace(_source: &Path, _destination: &Path) -> Result<()> {
    Err(StoreError::ReplacementRecovery)
}

#[cfg(test)]
static FAILPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
pub(crate) fn set_failpoint(phase: u8) {
    FAILPOINT.store(phase, std::sync::atomic::Ordering::SeqCst);
}

fn failpoint(phase: u8) -> Result<()> {
    #[cfg(test)]
    if FAILPOINT.load(std::sync::atomic::Ordering::SeqCst) == phase {
        FAILPOINT.store(0, std::sync::atomic::Ordering::SeqCst);
        return Err(StoreError::MigrationValidation);
    }
    let _ = phase;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{DeliveryState, Direction};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    static MIGRATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn released_schema_fixtures_are_recognized_exactly() {
        for (schema, receipt) in [
            (SCHEMA_V0_1, false),
            (SCHEMA_V0_2, false),
            (SCHEMA_V0_3, true),
        ] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(schema).unwrap();
            assert_eq!(validate_released_schema(&conn).unwrap(), receipt);
        }
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V0_3).unwrap();
        conn.execute("ALTER TABLE contacts ADD COLUMN leak BLOB", [])
            .unwrap();
        assert!(matches!(
            validate_released_schema(&conn),
            Err(StoreError::UnsupportedLegacySchema)
        ));
    }

    #[test]
    fn every_replacement_phase_restarts_to_one_valid_store() {
        let _guard = MIGRATION_TEST_LOCK.lock().unwrap();
        for phase in 1..=5 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("phase-{phase}.db"));
            let expected = create_legacy_store(&path, SCHEMA_V0_3, phase as u64);
            set_failpoint(phase);
            assert!(matches!(
                Store::open(&path, b"pass"),
                Err(StoreError::MigrationValidation)
            ));
            let store = Store::open(&path, b"pass").unwrap();
            assert_eq!(store.get_identity().unwrap().unwrap().public(), expected.0);
            assert_eq!(store.all_messages().unwrap(), vec![expected.1]);
            assert!(!migration_path(&path).unwrap().exists());
            assert!(!rollback_path(&path).unwrap().exists());
        }
    }

    #[test]
    fn every_prior_public_schema_migrates_with_fresh_database_identity() {
        let _guard = MIGRATION_TEST_LOCK.lock().unwrap();
        for (index, schema) in [SCHEMA_V0_1, SCHEMA_V0_2, SCHEMA_V0_3]
            .into_iter()
            .enumerate()
        {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("released-{index}.db"));
            let expected = create_legacy_store(&path, schema, 100 + index as u64);
            let store = Store::open(&path, b"pass").unwrap();
            assert_ne!(store.metadata.database_id, [0; 32]);
            assert_eq!(store.get_identity().unwrap().unwrap().public(), expected.0);
            assert_eq!(store.all_messages().unwrap(), vec![expected.1]);
            let objects = schema_objects(&store.conn).unwrap();
            assert!(objects.iter().all(|(_, name, _)| {
                matches!(
                    name.as_str(),
                    "store_bootstrap"
                        | "store_metadata"
                        | "store_records"
                        | "store_record_locator"
                        | "store_record_unique"
                        | "store_record_index_a"
                        | "store_record_index_b"
                        | "store_record_index_c"
                        | "store_record_index_d"
                )
            }));
        }
    }

    #[test]
    fn malformed_legacy_rows_fail_before_active_path_replacement() {
        let _guard = MIGRATION_TEST_LOCK.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();

        let typed_path = directory.path().join("wrong-type.db");
        create_legacy_store(&typed_path, SCHEMA_V0_3, 401);
        let typed = Connection::open(&typed_path).unwrap();
        typed
            .execute(
                "INSERT INTO contacts (peer, blob) VALUES ('not-a-key', zeroblob(40))",
                [],
            )
            .unwrap();
        drop(typed);
        assert!(matches!(
            Store::open(&typed_path, b"pass"),
            Err(StoreError::MigrationValidation)
        ));
        assert!(!store_v2::is_v2(&Connection::open(&typed_path).unwrap()).unwrap());
        assert!(!rollback_path(&typed_path).unwrap().exists());

        let oversized_path = directory.path().join("oversized.db");
        create_legacy_store(&oversized_path, SCHEMA_V0_3, 402);
        let oversized = Connection::open(&oversized_path).unwrap();
        oversized
            .execute(
                "INSERT INTO contacts (peer, blob) VALUES (?1, zeroblob(?2))",
                params![[9u8; 32].as_slice(), (MAX_LEGACY_CIPHERTEXT + 1) as i64],
            )
            .unwrap();
        drop(oversized);
        assert!(matches!(
            Store::open(&oversized_path, b"pass"),
            Err(StoreError::MigrationValidation)
        ));
        assert!(!store_v2::is_v2(&Connection::open(&oversized_path).unwrap()).unwrap());
        assert!(!rollback_path(&oversized_path).unwrap().exists());
    }

    #[test]
    fn logical_and_referential_mismatches_do_not_replace_the_legacy_store() {
        let _guard = MIGRATION_TEST_LOCK.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();

        let logical_path = directory.path().join("logical.db");
        let seed = 403u64;
        create_legacy_store(&logical_path, SCHEMA_V0_3, seed);
        let logical = Connection::open(&logical_path).unwrap();
        let mut rng = StdRng::seed_from_u64(seed + 1);
        let contact = ContactRecord {
            peer: [4; 32],
            identity: vec![1],
            name: "mismatch".into(),
            bundle: vec![2],
            hints: Vec::new(),
            verified: false,
        };
        let encoded = postcard::to_allocvec(&contact).unwrap();
        let sealed = StorageKey::from_bytes([seed.wrapping_add(1) as u8; 32])
            .derive(b"KK-store-contacts")
            .seal(b"contact", &encoded, &mut rng);
        logical
            .execute(
                "INSERT INTO contacts (peer, blob) VALUES (?1, ?2)",
                params![[5u8; 32].as_slice(), sealed],
            )
            .unwrap();
        drop(logical);
        assert!(matches!(
            Store::open(&logical_path, b"pass"),
            Err(StoreError::LogicalKeyMismatch)
        ));
        assert!(!store_v2::is_v2(&Connection::open(&logical_path).unwrap()).unwrap());
        assert!(!rollback_path(&logical_path).unwrap().exists());

        let reference_path = directory.path().join("reference.db");
        let seed = 404u64;
        create_legacy_store(&reference_path, SCHEMA_V0_3, seed);
        let reference = Connection::open(&reference_path).unwrap();
        let authority = GroupAuthorityRecord {
            group: [6; 32],
            state_id: [7; 16],
            state_payload: vec![8],
            consumed_requests: Vec::new(),
        };
        let encoded = postcard::to_allocvec(&authority).unwrap();
        let sealed = StorageKey::from_bytes([seed.wrapping_add(1) as u8; 32])
            .derive(b"KK-store-groups")
            .seal(b"group-authority", &encoded, &mut rng);
        reference
            .execute(
                "INSERT INTO group_authority (gid, blob) VALUES (?1, ?2)",
                params![authority.group.as_slice(), sealed],
            )
            .unwrap();
        drop(reference);
        assert!(matches!(
            Store::open(&reference_path, b"pass"),
            Err(StoreError::MigrationValidation)
        ));
        assert!(!store_v2::is_v2(&Connection::open(&reference_path).unwrap()).unwrap());
        assert!(!rollback_path(&reference_path).unwrap().exists());
    }

    fn create_legacy_store(
        path: &Path,
        schema: &str,
        seed: u64,
    ) -> (kult_crypto::IdentityPublic, MessageRecord) {
        let mut rng = StdRng::seed_from_u64(seed);
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(schema).unwrap();
        let salt = [seed as u8; 16];
        let master_bytes = [seed.wrapping_add(1) as u8; 32];
        let master = StorageKey::from_bytes(master_bytes);
        let kek = derive_kek(b"pass", &salt, TEST_KDF).unwrap();
        let wrapped = StorageKey::from_bytes(*kek).seal(WRAP_AD, &master_bytes, &mut rng);
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('salt', ?1)",
            params![salt.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('kdf', ?1)",
            params![postcard::to_allocvec(&(
                TEST_KDF.m_cost_kib,
                TEST_KDF.t_cost,
                TEST_KDF.p_cost,
            ))
            .unwrap()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('wrapped_sk', ?1)",
            params![wrapped],
        )
        .unwrap();

        let identity = Identity::generate(&mut rng);
        let sealed = master.derive(b"KK-store-identity").seal(
            b"identity",
            identity.to_bytes().as_ref(),
            &mut rng,
        );
        conn.execute(
            "INSERT INTO identity (id, blob) VALUES (1, ?1)",
            params![sealed],
        )
        .unwrap();
        let message = MessageRecord {
            id: [seed.wrapping_add(2) as u8; 16],
            peer: [seed.wrapping_add(3) as u8; 32],
            direction: Direction::Inbound,
            state: DeliveryState::Received,
            timestamp: seed,
            body: b"released fixture".to_vec(),
            wire_id: None,
        };
        let encoded = postcard::to_allocvec(&message).unwrap();
        let sealed = master
            .derive(b"KK-store-messages")
            .seal(b"message", &encoded, &mut rng);
        conn.execute("INSERT INTO messages (blob) VALUES (?1)", params![sealed])
            .unwrap();
        let public = identity.public();
        drop(conn);
        (public, message)
    }
}
