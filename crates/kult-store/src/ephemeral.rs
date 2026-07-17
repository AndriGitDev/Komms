//! Sealed local expiry markers and durable tombstones (ADR-0021).

use rand_core::CryptoRngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Result, Store, StoreError};

const EPHEMERAL_AD: &[u8] = b"ephemeral-v1";

/// Conversation scope for one ephemeral content id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EphemeralConversation {
    /// Pairwise history keyed by the other identity.
    Pairwise([u8; 32]),
    /// Group history keyed by group id.
    Group([u8; 32]),
}

/// Local deletion behavior authenticated by the content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EphemeralMode {
    /// Remove plaintext at the exact deadline.
    DisappearingText,
    /// Remove the locally decryptable attachment at first successful open or deadline.
    ViewOnceAttachment,
}

/// Durable state of one ephemeral content id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EphemeralState {
    /// Plaintext/decryptable media may still exist locally.
    Active,
    /// First-open consumption completed or began; never make it readable again.
    Consumed,
    /// Exact authenticated deadline elapsed; never make it readable again.
    Expired,
}

/// Sealed marker retained after the associated plaintext and media are deleted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralRecord {
    /// Exact conversation scope.
    pub conversation: EphemeralConversation,
    /// Authenticated author identity.
    pub author: [u8; 32],
    /// Author-minted content id.
    pub content_id: [u8; 16],
    /// Exact authenticated Unix-seconds deadline.
    pub expires_at: u64,
    /// Local deletion behavior.
    pub mode: EphemeralMode,
    /// Current durable state.
    pub state: EphemeralState,
    /// Local attachment transfer ids for active view-once media only.
    /// Group senders may retain one deterministic-chunk entitlement row per peer.
    pub transfer_ids: Vec<[u8; 16]>,
}

impl Store {
    /// Insert or replace one exact sealed ephemeral marker.
    pub fn put_ephemeral_record(
        &self,
        record: &EphemeralRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if record.expires_at == 0
            || (record.mode == EphemeralMode::DisappearingText && !record.transfer_ids.is_empty())
        {
            return Err(StoreError::Serialization);
        }
        let plain = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_ephemeral.seal(EPHEMERAL_AD, &plain, rng);
        if let Some(rowid) =
            self.ephemeral_rowid(&record.conversation, &record.author, &record.content_id)?
        {
            self.conn.execute(
                "UPDATE ephemeral SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        } else {
            self.conn
                .execute("INSERT INTO ephemeral (blob) VALUES (?1)", params![sealed])?;
        }
        Ok(())
    }

    /// Read one exact marker without exposing lookup material in SQLite columns.
    pub fn get_ephemeral_record(
        &self,
        conversation: &EphemeralConversation,
        author: &[u8; 32],
        content_id: &[u8; 16],
    ) -> Result<Option<EphemeralRecord>> {
        Ok(self.ephemeral_records()?.into_iter().find(|record| {
            &record.conversation == conversation
                && &record.author == author
                && &record.content_id == content_id
        }))
    }

    /// Every sealed marker, including durable consumed/expired tombstones.
    pub fn ephemeral_records(&self) -> Result<Vec<EphemeralRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT blob FROM ephemeral ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let plain = self.k_ephemeral.open(EPHEMERAL_AD, &row?)?;
            out.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(out)
    }

    fn ephemeral_rowid(
        &self,
        conversation: &EphemeralConversation,
        author: &[u8; 32],
        content_id: &[u8; 16],
    ) -> Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid_, blob FROM ephemeral ORDER BY rowid_")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, sealed) = row?;
            let plain = self.k_ephemeral.open(EPHEMERAL_AD, &sealed)?;
            let record: EphemeralRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &record.conversation == conversation
                && &record.author == author
                && &record.content_id == content_id
            {
                return Ok(Some(rowid));
            }
        }
        Ok(None)
    }
}
