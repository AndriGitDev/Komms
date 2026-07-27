//! Bounded local remnant-reduction controls.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{store_v2, Result, Store, StoreError};

/// Largest WAL file this API will synchronously checkpoint (256 MiB).
pub const MAX_MAINTENANCE_WAL_BYTES: u64 = 256 * 1024 * 1024;
/// Largest incremental-vacuum request accepted in one call.
pub const MAX_MAINTENANCE_VACUUM_PAGES: u32 = 4_096;

/// Per-call bounds for local SQLite remnant reduction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageMaintenanceOptions {
    /// Checkpoint and truncate the WAL only when its current file size is no
    /// larger than this bound.
    pub max_wal_checkpoint_bytes: u64,
    /// Maximum freelist pages SQLite may reclaim during this call.
    pub max_incremental_vacuum_pages: u32,
}

impl Default for StorageMaintenanceOptions {
    fn default() -> Self {
        Self {
            max_wal_checkpoint_bytes: 64 * 1024 * 1024,
            max_incremental_vacuum_pages: 1_024,
        }
    }
}

/// Observable result of one bounded maintenance call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageMaintenanceReport {
    /// Whether this SQLite build reports full secure-delete mode enabled.
    pub secure_delete_enabled: bool,
    /// Reclaimable database pages before incremental vacuum.
    pub freelist_pages_before: u64,
    /// Reclaimable database pages after incremental vacuum.
    pub freelist_pages_after: u64,
    /// WAL bytes observed before maintenance.
    pub wal_bytes_before: u64,
    /// WAL bytes observed after maintenance.
    pub wal_bytes_after: u64,
    /// Frames present when a bounded checkpoint was attempted.
    pub wal_frames_before_checkpoint: u64,
    /// Frames copied back to the database by that checkpoint.
    pub wal_frames_checkpointed: u64,
    /// Whether WAL truncation was skipped because the file exceeded the
    /// caller's bound, or could not complete because another reader was active.
    pub wal_checkpoint_deferred: bool,
    /// Always false: SQLite and filesystem maintenance cannot prove forensic
    /// erasure on snapshots, flash media, remapped blocks, or prior copies.
    pub forensic_erasure_guaranteed: bool,
}

impl Store {
    /// Reduce deleted-row and WAL remnants within explicit per-call bounds.
    ///
    /// Logical deletion must happen before this call. This operation enables
    /// full SQLite secure-delete mode, performs a bounded incremental vacuum,
    /// and truncates only a WAL whose observed file size fits the supplied
    /// checkpoint bound. It cannot establish forensic erasure.
    pub fn maintain_deleted_storage(
        &self,
        options: StorageMaintenanceOptions,
    ) -> Result<StorageMaintenanceReport> {
        if options.max_wal_checkpoint_bytes == 0
            || options.max_wal_checkpoint_bytes > MAX_MAINTENANCE_WAL_BYTES
            || options.max_incremental_vacuum_pages > MAX_MAINTENANCE_VACUUM_PAGES
        {
            return Err(StoreError::MaintenanceBounds);
        }

        let wal = sidecar_path(&self.path, "-wal");
        let wal_bytes_before = file_len(&wal)?;
        self.conn.pragma_update(None, "secure_delete", true)?;
        let secure_delete: i64 = self
            .conn
            .pragma_query_value(None, "secure_delete", |row| row.get(0))?;
        let page_size: u64 = self
            .conn
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        let checkpoint_pages = options
            .max_wal_checkpoint_bytes
            .checked_div(page_size.max(1))
            .unwrap_or(1)
            .max(1);
        self.conn.pragma_update(
            None,
            "wal_autocheckpoint",
            u32::try_from(checkpoint_pages).unwrap_or(u32::MAX),
        )?;
        self.conn.pragma_update(
            None,
            "journal_size_limit",
            i64::try_from(options.max_wal_checkpoint_bytes)
                .map_err(|_| StoreError::MaintenanceBounds)?,
        )?;

        let freelist_pages_before = pragma_u64(&self.conn, "freelist_count")?;
        if options.max_incremental_vacuum_pages != 0 {
            self.conn.execute_batch(&format!(
                "PRAGMA incremental_vacuum({});",
                options.max_incremental_vacuum_pages
            ))?;
        }
        let freelist_pages_after = pragma_u64(&self.conn, "freelist_count")?;

        let mut wal_frames_before_checkpoint = 0;
        let mut wal_frames_checkpointed = 0;
        let mut wal_checkpoint_deferred = wal_bytes_before > options.max_wal_checkpoint_bytes;
        if !wal_checkpoint_deferred {
            let (busy, frames, checkpointed): (u32, u64, u64) =
                self.conn
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?;
            wal_frames_before_checkpoint = frames;
            wal_frames_checkpointed = checkpointed;
            wal_checkpoint_deferred = busy != 0;
        }
        store_v2::protect_sqlite_files(&self.path)?;
        let wal_bytes_after = file_len(&wal)?;

        Ok(StorageMaintenanceReport {
            secure_delete_enabled: secure_delete == 1,
            freelist_pages_before,
            freelist_pages_after,
            wal_bytes_before,
            wal_bytes_after,
            wal_frames_before_checkpoint,
            wal_frames_checkpointed,
            wal_checkpoint_deferred,
            forensic_erasure_guaranteed: false,
        })
    }
}

fn pragma_u64(conn: &rusqlite::Connection, pragma: &str) -> Result<u64> {
    let value: i64 = conn.pragma_query_value(None, pragma, |row| row.get(0))?;
    u64::try_from(value).map_err(|_| StoreError::Serialization)
}

fn file_len(path: &Path) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use kult_crypto::KdfProfile;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{DeliveryState, Direction, MessageRecord};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn maintenance_is_bounded_and_never_claims_forensic_erasure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("maintenance.db");
        let mut rng = StdRng::seed_from_u64(0x5ecde1);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        for value in 0..64u8 {
            let mut id = [0; 16];
            id[0] = value;
            let record = MessageRecord {
                id,
                peer: [7; 32],
                direction: Direction::Outbound,
                state: DeliveryState::Queued,
                timestamp: u64::from(value),
                body: vec![value; 8 * 1024],
                wire_id: None,
            };
            store.put_message(&record, &mut rng).unwrap();
            assert!(store
                .delete_message_record(&record.peer, record.direction, &record.id)
                .unwrap());
        }

        let report = store
            .maintain_deleted_storage(StorageMaintenanceOptions::default())
            .unwrap();
        assert!(report.secure_delete_enabled);
        assert!(report.freelist_pages_after <= report.freelist_pages_before);
        assert!(!report.forensic_erasure_guaranteed);
        assert!(
            report.wal_checkpoint_deferred
                || report.wal_bytes_after
                    <= StorageMaintenanceOptions::default().max_wal_checkpoint_bytes
        );
    }

    #[test]
    fn maintenance_rejects_work_above_the_public_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("maintenance-bounds.db");
        let mut rng = StdRng::seed_from_u64(0x5ecde2);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let options = StorageMaintenanceOptions {
            max_wal_checkpoint_bytes: MAX_MAINTENANCE_WAL_BYTES + 1,
            max_incremental_vacuum_pages: 0,
        };
        assert!(matches!(
            store.maintain_deleted_storage(options),
            Err(StoreError::MaintenanceBounds)
        ));
    }
}
