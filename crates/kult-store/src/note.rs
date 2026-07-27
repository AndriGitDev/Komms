//! First-class sealed note-to-self history (B7).
//!
//! Note records live in their own local-only table and key domain. They are
//! never shaped like contact messages and contain no peer, delivery, receipt,
//! queue, or transport fields.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{decode_exact, store_v2, Result, Store, StoreError};

const RECORD_MAGIC_V1: &[u8; 4] = b"KNT1";

/// Reserved conversation identity shared by node, RPC, UniFFI, and every shell.
pub const NOTE_TO_SELF_CONVERSATION_ID: &str = "note_to_self";
/// Maximum UTF-8 bytes in one text note (64 KiB).
pub const MAX_NOTE_TEXT_BYTES: usize = 64 * 1024;

/// One message in the device-local note-to-self conversation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteMessageRecord {
    /// Random author-minted local record id.
    pub id: [u8; 16],
    /// Unix seconds when the note was added.
    pub timestamp: u64,
    /// UTF-8 text, sealed at rest by the store.
    pub body: String,
}

impl NoteMessageRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.body.is_empty() || self.body.len() > MAX_NOTE_TEXT_BYTES {
            Err(StoreError::NoteBounds)
        } else {
            Ok(())
        }
    }
}

impl Store {
    /// Append one independently sealed note-to-self text record.
    pub fn put_note_message(
        &self,
        record: &NoteMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        let encoded = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        let mut versioned = Vec::with_capacity(RECORD_MAGIC_V1.len() + encoded.len());
        versioned.extend_from_slice(RECORD_MAGIC_V1);
        versioned.extend_from_slice(&encoded);
        let versioned = Zeroizing::new(versioned);
        let id = store_v2::ContentKey::new(record.id);
        self.append::<store_v2::NoteRows>(&id, &versioned, store_v2::IndexKeys::note(&id), rng)?;
        Ok(())
    }

    /// Read note-to-self history in stable insertion order.
    pub fn note_messages(&self) -> Result<Vec<NoteMessageRecord>> {
        let mut records = Vec::new();
        for row in self.rows::<store_v2::NoteRows>()? {
            let encoded = row
                .payload
                .strip_prefix(RECORD_MAGIC_V1)
                .ok_or(StoreError::Serialization)?;
            let record: NoteMessageRecord = decode_exact(encoded)?;
            record.validate()?;
            row.verify_key(&store_v2::ContentKey::new(record.id))?;
            records.push(record);
        }
        Ok(records)
    }

    pub(crate) fn validate_note_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::NoteRows, _>(|row| {
            let encoded = row
                .payload
                .strip_prefix(RECORD_MAGIC_V1)
                .ok_or(StoreError::Serialization)?;
            let record: NoteMessageRecord = decode_exact(encoded)?;
            record.validate()?;
            let id = store_v2::ContentKey::new(record.id);
            row.verify_key(&id)?;
            row.verify_indexes(&store_v2::IndexKeys::note(&id))
        })
    }
}
