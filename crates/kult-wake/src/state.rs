use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use kult_protocol::WAKE_CAPABILITY_MAX_LIFETIME_SECS;

use crate::{Result, WakeError};

const APPLICATION_ID: u32 = 0x4b57_4b31;
const SCHEMA_VERSION: u32 = 1;
const MAX_PURGE_ROWS_PER_OPERATION: usize = 1024;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS wake_revocations (
    capability_id BLOB PRIMARY KEY NOT NULL CHECK (length(capability_id) = 16),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0)
) STRICT;
CREATE INDEX IF NOT EXISTS wake_revocations_expiry
    ON wake_revocations (expires_at);
CREATE TABLE IF NOT EXISTS wake_replays (
    capability_id BLOB NOT NULL CHECK (length(capability_id) = 16),
    request_nonce BLOB NOT NULL CHECK (length(request_nonce) = 16),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    PRIMARY KEY (capability_id, request_nonce)
) STRICT;
CREATE INDEX IF NOT EXISTS wake_replays_expiry
    ON wake_replays (expires_at);
";

/// Aggregate durable row counts with no capability values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayStateCounts {
    /// Live bounded revocation rows.
    pub revocations: usize,
    /// Live bounded replay rows.
    pub replays: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Authorization {
    Fresh,
    Duplicate,
    Revoked,
    Full,
}

/// Durable bounded replay/revocation store.
///
/// The database contains only random capability ids, random request nonces,
/// and expiry. It never receives native tokens, capabilities, identities, or
/// message data.
pub struct GatewayStateStore {
    connection: Connection,
    max_revocations: usize,
    max_replays: usize,
}

impl GatewayStateStore {
    /// Open or create one owner-local state database.
    pub fn open(path: &Path, max_revocations: usize, max_replays: usize) -> Result<Self> {
        if !path.is_absolute()
            || max_revocations == 0
            || max_replays == 0
            || max_revocations > 1_000_000
            || max_replays > 1_000_000
        {
            return Err(WakeError::Invalid("wake state limits or path are invalid"));
        }
        if path.exists() {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(WakeError::Invalid(
                    "wake state must be a regular non-symlink file",
                ));
            }
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let application_id: u32 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let user_version: u32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if application_id == 0 && user_version == 0 {
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            connection.execute_batch(SCHEMA)?;
        } else if application_id != APPLICATION_ID || user_version != SCHEMA_VERSION {
            return Err(WakeError::Invalid(
                "wake state database format is unsupported",
            ));
        } else {
            connection.execute_batch(SCHEMA)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            connection,
            max_revocations,
            max_replays,
        })
    }

    pub(crate) fn authorize(
        &mut self,
        capability_id: &[u8; 16],
        request_nonce: &[u8; 16],
        expires_at: u64,
        now: u64,
    ) -> Result<Authorization> {
        validate_expiry(expires_at, now)?;
        if capability_id == &[0u8; 16] || request_nonce == &[0u8; 16] {
            return Err(WakeError::Invalid("zero wake state identifier"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired(&transaction, now)?;
        let revoked = transaction
            .query_row(
                "SELECT 1 FROM wake_revocations
                 WHERE capability_id = ?1 AND expires_at > ?2",
                params![capability_id.as_slice(), as_i64(now)?],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if revoked {
            transaction.commit()?;
            return Ok(Authorization::Revoked);
        }
        let duplicate = transaction
            .query_row(
                "SELECT 1 FROM wake_replays
                 WHERE capability_id = ?1 AND request_nonce = ?2 AND expires_at > ?3",
                params![
                    capability_id.as_slice(),
                    request_nonce.as_slice(),
                    as_i64(now)?
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if duplicate {
            transaction.commit()?;
            return Ok(Authorization::Duplicate);
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM wake_replays", [], |row| row.get(0))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= self.max_replays {
            transaction.commit()?;
            return Ok(Authorization::Full);
        }
        transaction.execute(
            "INSERT INTO wake_replays (capability_id, request_nonce, expires_at)
             VALUES (?1, ?2, ?3)",
            params![
                capability_id.as_slice(),
                request_nonce.as_slice(),
                as_i64(expires_at)?
            ],
        )?;
        transaction.commit()?;
        Ok(Authorization::Fresh)
    }

    pub(crate) fn revoke(
        &mut self,
        capability_id: &[u8; 16],
        expires_at: u64,
        now: u64,
    ) -> Result<bool> {
        validate_expiry(expires_at, now)?;
        if capability_id == &[0u8; 16] {
            return Err(WakeError::Invalid("zero wake capability id"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired(&transaction, now)?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM wake_revocations WHERE capability_id = ?1",
                params![capability_id.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            let count: i64 =
                transaction.query_row("SELECT count(*) FROM wake_revocations", [], |row| {
                    row.get(0)
                })?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= self.max_revocations {
                transaction.commit()?;
                return Ok(false);
            }
        }
        transaction.execute(
            "INSERT INTO wake_revocations (capability_id, expires_at)
             VALUES (?1, ?2)
             ON CONFLICT(capability_id) DO UPDATE SET expires_at = max(expires_at, excluded.expires_at)",
            params![capability_id.as_slice(), as_i64(expires_at)?],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Purge expired rows and return only aggregate live counts.
    pub fn counts(&mut self, now: u64) -> Result<GatewayStateCounts> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge_expired(&transaction, now)?;
        let revocations: i64 =
            transaction.query_row("SELECT count(*) FROM wake_revocations", [], |row| {
                row.get(0)
            })?;
        let replays: i64 =
            transaction.query_row("SELECT count(*) FROM wake_replays", [], |row| row.get(0))?;
        transaction.commit()?;
        Ok(GatewayStateCounts {
            revocations: usize::try_from(revocations).unwrap_or(usize::MAX),
            replays: usize::try_from(replays).unwrap_or(usize::MAX),
        })
    }
}

fn purge_expired(transaction: &rusqlite::Transaction<'_>, now: u64) -> Result<()> {
    let now = as_i64(now)?;
    transaction.execute(
        "DELETE FROM wake_replays WHERE rowid IN (
             SELECT rowid FROM wake_replays WHERE expires_at <= ?1
             ORDER BY expires_at LIMIT ?2
         )",
        params![now, MAX_PURGE_ROWS_PER_OPERATION as i64],
    )?;
    transaction.execute(
        "DELETE FROM wake_revocations WHERE rowid IN (
             SELECT rowid FROM wake_revocations WHERE expires_at <= ?1
             ORDER BY expires_at LIMIT ?2
         )",
        params![now, MAX_PURGE_ROWS_PER_OPERATION as i64],
    )?;
    Ok(())
}

fn validate_expiry(expires_at: u64, now: u64) -> Result<()> {
    if expires_at <= now || expires_at.saturating_sub(now) > WAKE_CAPABILITY_MAX_LIFETIME_SECS {
        return Err(WakeError::Invalid("wake state expiry is outside its bound"));
    }
    Ok(())
}

fn as_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| WakeError::Invalid("wake timestamp exceeds SQLite range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn replay_and_revocation_survive_restart_and_expire() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake-state.db");
        {
            let mut store = GatewayStateStore::open(&path, 4, 4).unwrap();
            assert_eq!(
                store
                    .authorize(&[1u8; 16], &[2u8; 16], NOW + 100, NOW)
                    .unwrap(),
                Authorization::Fresh
            );
            assert_eq!(
                store
                    .authorize(&[1u8; 16], &[2u8; 16], NOW + 100, NOW)
                    .unwrap(),
                Authorization::Duplicate
            );
            assert!(store.revoke(&[3u8; 16], NOW + 100, NOW).unwrap());
        }
        {
            let mut store = GatewayStateStore::open(&path, 4, 4).unwrap();
            assert_eq!(
                store
                    .authorize(&[1u8; 16], &[2u8; 16], NOW + 100, NOW)
                    .unwrap(),
                Authorization::Duplicate
            );
            assert_eq!(
                store
                    .authorize(&[3u8; 16], &[4u8; 16], NOW + 100, NOW)
                    .unwrap(),
                Authorization::Revoked
            );
            assert_eq!(store.counts(NOW).unwrap().replays, 1);
            assert_eq!(
                store.counts(NOW + 101).unwrap(),
                GatewayStateCounts::default()
            );
        }
    }

    #[test]
    fn row_caps_fail_closed_without_evicting_live_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake-state.db");
        let mut store = GatewayStateStore::open(&path, 1, 1).unwrap();
        assert_eq!(
            store
                .authorize(&[1u8; 16], &[1u8; 16], NOW + 100, NOW)
                .unwrap(),
            Authorization::Fresh
        );
        assert_eq!(
            store
                .authorize(&[2u8; 16], &[2u8; 16], NOW + 100, NOW)
                .unwrap(),
            Authorization::Full
        );
        assert!(store.revoke(&[3u8; 16], NOW + 100, NOW).unwrap());
        assert!(!store.revoke(&[4u8; 16], NOW + 100, NOW).unwrap());
    }
}
