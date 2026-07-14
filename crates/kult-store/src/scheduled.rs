//! Sealed durable outbox entries that have not reached their send instant.
//!
//! Scheduled plaintext is deliberately separate from the encrypted outbound
//! queue. Ratchet state is advanced only when an entry activates, so a user
//! can safely edit or cancel it beforehand.

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Result, Store, StoreError};

/// A conversation that can receive scheduled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduledConversation {
    /// Pairwise conversation with a stored contact.
    Peer([u8; 32]),
    /// Sender-key group conversation.
    Group([u8; 32]),
}

/// One durable scheduled text message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledMessageRecord {
    /// Stable message id retained when the entry activates.
    pub id: [u8; 16],
    /// Destination conversation.
    pub conversation: ScheduledConversation,
    /// Unix time when the schedule was created.
    pub created_at: u64,
    /// Absolute UTC Unix time before which activation is forbidden.
    pub not_before: u64,
    /// Plaintext body, sealed independently at rest.
    pub body: Vec<u8>,
}

impl Store {
    /// Insert one scheduled message, sealed under the scheduled-outbox key.
    pub fn put_scheduled_message(
        &self,
        record: &ScheduledMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let plain = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_scheduled.seal(b"scheduled-message", &plain, rng);
        self.conn.execute(
            "INSERT INTO scheduled_messages (blob) VALUES (?1)",
            params![sealed],
        )?;
        Ok(())
    }

    /// All scheduled messages in creation order.
    pub fn scheduled_messages(&self) -> Result<Vec<ScheduledMessageRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT blob FROM scheduled_messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_scheduled.open(b"scheduled-message", &row?)?;
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    /// Load one scheduled message by stable id.
    pub fn get_scheduled_message(&self, id: &[u8; 16]) -> Result<Option<ScheduledMessageRecord>> {
        Ok(self
            .scheduled_messages()?
            .into_iter()
            .find(|record| &record.id == id))
    }

    /// Replace the scheduled message with the same id. Returns whether it
    /// existed; callers use this to reject edits after activation.
    pub fn update_scheduled_message(
        &self,
        record: &ScheduledMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM scheduled_messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_scheduled.open(b"scheduled-message", &sealed)?;
            let stored: ScheduledMessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if stored.id == record.id {
                let plain = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
                let sealed = self.k_scheduled.seal(b"scheduled-message", &plain, rng);
                self.conn.execute(
                    "UPDATE scheduled_messages SET blob = ?2 WHERE rowid_ = ?1",
                    params![rowid, sealed],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Delete a scheduled message. Returns whether it still existed.
    pub fn delete_scheduled_message(&self, id: &[u8; 16]) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM scheduled_messages ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_scheduled.open(b"scheduled-message", &sealed)?;
            let stored: ScheduledMessageRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &stored.id == id {
                self.conn.execute(
                    "DELETE FROM scheduled_messages WHERE rowid_ = ?1",
                    params![rowid],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_crypto::KdfProfile;
    use rand::{rngs::StdRng, SeedableRng};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn scheduled_messages_survive_restart_and_support_edit_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scheduled.db");
        let mut rng = StdRng::seed_from_u64(0x5ced);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let mut record = ScheduledMessageRecord {
            id: [1; 16],
            conversation: ScheduledConversation::Peer([2; 32]),
            created_at: 10,
            not_before: 100,
            body: b"before".to_vec(),
        };
        store.put_scheduled_message(&record, &mut rng).unwrap();
        drop(store);

        let store = Store::open(&path, b"pass").unwrap();
        assert_eq!(store.scheduled_messages().unwrap(), vec![record.clone()]);
        record.not_before = 200;
        record.body = b"after".to_vec();
        assert!(store.update_scheduled_message(&record, &mut rng).unwrap());
        assert_eq!(
            store.get_scheduled_message(&record.id).unwrap(),
            Some(record)
        );
        assert!(store.delete_scheduled_message(&[1; 16]).unwrap());
        assert!(!store.delete_scheduled_message(&[1; 16]).unwrap());
        assert!(store.scheduled_messages().unwrap().is_empty());
    }
}
