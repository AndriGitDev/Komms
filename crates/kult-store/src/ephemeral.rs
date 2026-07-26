//! Sealed local expiry markers and durable tombstones (ADR-0021).

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{decode_exact, store_v2, Result, Store, StoreError};

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
        let plain =
            Zeroizing::new(postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::EphemeralRows>(
            &ephemeral_key(&record.conversation, &record.author, &record.content_id)?,
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// Read one exact marker without exposing lookup material in SQLite columns.
    pub fn get_ephemeral_record(
        &self,
        conversation: &EphemeralConversation,
        author: &[u8; 32],
        content_id: &[u8; 16],
    ) -> Result<Option<EphemeralRecord>> {
        let key = ephemeral_key(conversation, author, content_id)?;
        let Some(row) = self.get_equality::<store_v2::EphemeralRows>(&key)? else {
            return Ok(None);
        };
        row.verify_key(&key)?;
        let record: EphemeralRecord = decode_exact(&row.payload)?;
        if record.conversation != *conversation
            || record.author != *author
            || record.content_id != *content_id
        {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Some(record))
    }

    /// Every sealed marker, including durable consumed/expired tombstones.
    pub fn ephemeral_records(&self) -> Result<Vec<EphemeralRecord>> {
        let mut out = Vec::new();
        for row in self.rows::<store_v2::EphemeralRows>()? {
            let record: EphemeralRecord = decode_exact(&row.payload)?;
            row.verify_key(&ephemeral_key(
                &record.conversation,
                &record.author,
                &record.content_id,
            )?)?;
            out.push(record);
        }
        Ok(out)
    }

    pub(crate) fn validate_ephemeral_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::EphemeralRows, _>(|row| {
            let record: EphemeralRecord = decode_exact(&row.payload)?;
            if record.expires_at == 0
                || (record.mode == EphemeralMode::DisappearingText
                    && !record.transfer_ids.is_empty())
            {
                return Err(StoreError::Serialization);
            }
            row.verify_key(&ephemeral_key(
                &record.conversation,
                &record.author,
                &record.content_id,
            )?)?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })
    }
}

fn ephemeral_key(
    conversation: &EphemeralConversation,
    author: &[u8; 32],
    content_id: &[u8; 16],
) -> Result<store_v2::EphemeralKey> {
    let (kind, conversation) = match conversation {
        EphemeralConversation::Pairwise(id) => (0, *id),
        EphemeralConversation::Group(id) => (1, *id),
    };
    store_v2::EphemeralKey::new(kind, conversation, *author, *content_id)
}
