//! End-to-end encrypted receipts: delivery acknowledgments and fragment
//! NACKs for selective retransmission. A `ReceiptPayload` is postcard-encoded
//! and travels as the *plaintext* of a ratchet message inside an envelope of
//! kind `Receipt` — intermediaries cannot distinguish receipts from messages
//! beyond the padded size bucket.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{ProtocolError, Result};

/// Receipt content (always encrypted end-to-end before transport).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptPayload {
    /// Content ids ([`crate::Envelope::content_id`]) confirmed delivered.
    pub acks: Vec<[u8; 16]>,
    /// Missing fragment indices per in-flight message id, requesting
    /// selective retransmission ([`crate::Reassembler::missing`]).
    pub nacks: Vec<([u8; 4], Vec<u16>)>,
}

impl ReceiptPayload {
    /// Postcard-encode (pad with [`crate::pad`] before encrypting).
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("receipt serialization cannot fail")
    }

    /// Parse a decrypted receipt payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| ProtocolError::Malformed)
    }
}
