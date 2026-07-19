//! The sealed envelope: the only unit transports carry (spec §5).
//!
//! Wire layouts:
//!
//! - v1: `version(1) || kind(1) || delivery token(32) || body`;
//! - v2: `version(1) || kind(1) || delivery token(32) || retention-until(8) || body`.
//!
//! The body is kind-specific and always ciphertext (a ratchet message, an
//! anonymous-boxed handshake flight, or a fragment slice). The only cleartext
//! an intermediary sees is the opaque rotating token.

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Legacy envelope version with no relay-visible retention hint.
pub const ENVELOPE_VERSION_V1: u8 = 1;
/// Envelope version carrying an authenticated-in-content coarse retention hint.
pub const ENVELOPE_VERSION_V2: u8 = 2;

/// Envelope header length: version + kind + token. Callers budgeting for a
/// link MTU subtract this before fragmenting ([`crate::fragment`]).
pub const ENVELOPE_HEADER_LEN: usize = 1 + 1 + 32 + 8;
/// v1 header length retained for old-wire decoding and golden vectors.
pub const ENVELOPE_V1_HEADER_LEN: usize = 1 + 1 + 32;
/// v2 header length.
pub const ENVELOPE_V2_HEADER_LEN: usize = ENVELOPE_HEADER_LEN;

/// What an envelope carries (byte 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeKind {
    /// A ratchet message (encoded `RatchetMessage`).
    Message = 0x01,
    /// A handshake first flight (anonymous-boxed `InitialMessage`).
    Handshake = 0x02,
    /// An end-to-end encrypted receipt (ratchet message whose plaintext is a
    /// [`crate::ReceiptPayload`]).
    Receipt = 0x03,
    /// One fragment of a larger envelope (see [`crate::fragment`]).
    Fragment = 0x04,
    /// Group control (ADR-0012): a pairwise ratchet message whose plaintext
    /// is a [`crate::GroupControlPayload`].
    GroupControl = 0x05,
    /// A sender-key group message (encoded `kult_crypto::GroupMessage`),
    /// encrypted once and fanned out per member.
    GroupMessage = 0x06,
}

impl TryFrom<u8> for EnvelopeKind {
    type Error = ProtocolError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Message),
            0x02 => Ok(Self::Handshake),
            0x03 => Ok(Self::Receipt),
            0x04 => Ok(Self::Fragment),
            0x05 => Ok(Self::GroupControl),
            0x06 => Ok(Self::GroupMessage),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// A sealed envelope. See module docs for the wire layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// What the body is.
    pub kind: EnvelopeKind,
    /// Opaque delivery token (spec §7) — the only routable cleartext.
    pub token: [u8; 32],
    /// Coarse absolute Unix-seconds deletion hint visible to relays in v2.
    /// It is advisory to intermediaries and must be verified against the
    /// authenticated content by an endpoint before that content is accepted.
    pub retention_until: Option<u64>,
    /// Kind-specific ciphertext.
    pub body: Vec<u8>,
}

impl Envelope {
    /// Assemble an envelope.
    pub fn new(kind: EnvelopeKind, token: [u8; 32], body: Vec<u8>) -> Self {
        Self {
            kind,
            token,
            retention_until: None,
            body,
        }
    }

    /// Assemble a v2 envelope with a canonical hour-bucket retention hint.
    pub fn new_retained(
        kind: EnvelopeKind,
        token: [u8; 32],
        retention_until: u64,
        body: Vec<u8>,
    ) -> Result<Self> {
        if retention_until == 0 || !retention_until.is_multiple_of(crate::RETENTION_BUCKET_SECS) {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self {
            kind,
            token,
            retention_until: Some(retention_until),
            body,
        })
    }

    /// Exact encoded header length for this envelope version.
    pub fn header_len(&self) -> usize {
        if self.retention_until.is_some() {
            ENVELOPE_V2_HEADER_LEN
        } else {
            ENVELOPE_V1_HEADER_LEN
        }
    }

    /// Serialize to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_len() + self.body.len());
        out.push(if self.retention_until.is_some() {
            ENVELOPE_VERSION_V2
        } else {
            ENVELOPE_VERSION_V1
        });
        out.push(self.kind as u8);
        out.extend_from_slice(&self.token);
        if let Some(retention_until) = self.retention_until {
            out.extend_from_slice(&retention_until.to_le_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse from the wire format. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < ENVELOPE_V1_HEADER_LEN {
            return Err(ProtocolError::Malformed);
        }
        let kind = EnvelopeKind::try_from(bytes[1])?;
        let mut token = [0u8; 32];
        token.copy_from_slice(&bytes[2..ENVELOPE_V1_HEADER_LEN]);
        let (retention_until, header_len) = match bytes[0] {
            ENVELOPE_VERSION_V1 => (None, ENVELOPE_V1_HEADER_LEN),
            ENVELOPE_VERSION_V2 if bytes.len() >= ENVELOPE_V2_HEADER_LEN => {
                let value = u64::from_le_bytes(
                    bytes[ENVELOPE_V1_HEADER_LEN..ENVELOPE_V2_HEADER_LEN]
                        .try_into()
                        .expect("fixed slice"),
                );
                if value == 0 || value % crate::RETENTION_BUCKET_SECS != 0 {
                    return Err(ProtocolError::Malformed);
                }
                (Some(value), ENVELOPE_V2_HEADER_LEN)
            }
            _ => return Err(ProtocolError::Malformed),
        };
        Ok(Self {
            kind,
            token,
            retention_until,
            body: bytes[header_len..].to_vec(),
        })
    }

    /// Stable content id (first 16 bytes of BLAKE3 of the encoding) — used
    /// for dedup across redundant multipath delivery.
    pub fn content_id(&self) -> [u8; 16] {
        let hash = blake3::hash(&self.encode());
        hash.as_bytes()[..16].try_into().expect("16 <= 32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_remains_byte_exact_and_v2_round_trips() {
        let legacy = Envelope::new(EnvelopeKind::Message, [7; 32], vec![1, 2]);
        let encoded = legacy.encode();
        assert_eq!(encoded.len(), ENVELOPE_V1_HEADER_LEN + 2);
        assert_eq!(encoded[0], ENVELOPE_VERSION_V1);
        assert_eq!(Envelope::decode(&encoded).unwrap(), legacy);

        let retained =
            Envelope::new_retained(EnvelopeKind::Message, [8; 32], 1_800_003_600, vec![3, 4])
                .unwrap();
        let encoded = retained.encode();
        assert_eq!(encoded.len(), ENVELOPE_V2_HEADER_LEN + 2);
        assert_eq!(encoded[0], ENVELOPE_VERSION_V2);
        assert_eq!(Envelope::decode(&encoded).unwrap(), retained);
    }

    #[test]
    fn malformed_versions_and_retention_buckets_fail() {
        assert!(Envelope::new_retained(EnvelopeKind::Message, [0; 32], 1, vec![]).is_err());
        let mut v2 = Envelope::new_retained(EnvelopeKind::Message, [0; 32], 3_600, vec![])
            .unwrap()
            .encode();
        v2[34] = 1;
        assert!(Envelope::decode(&v2).is_err());
        v2[0] = 3;
        assert!(Envelope::decode(&v2).is_err());
    }
}
