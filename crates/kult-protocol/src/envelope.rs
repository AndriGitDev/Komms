//! The sealed envelope: the only unit transports carry (spec §5).
//!
//! Wire layout: `version(1) || kind(1) || delivery token(32) || body`.
//! The body is kind-specific and always ciphertext (a ratchet message, an
//! anonymous-boxed handshake flight, or a fragment slice). The only cleartext
//! an intermediary sees is the opaque rotating token.

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Protocol version carried in byte 0.
pub const ENVELOPE_VERSION: u8 = 1;

/// Envelope header length: version + kind + token. Callers budgeting for a
/// link MTU subtract this before fragmenting ([`crate::fragment`]).
pub const ENVELOPE_HEADER_LEN: usize = 1 + 1 + 32;
const HEADER_LEN: usize = ENVELOPE_HEADER_LEN;

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
    /// Kind-specific ciphertext.
    pub body: Vec<u8>,
}

impl Envelope {
    /// Assemble an envelope.
    pub fn new(kind: EnvelopeKind, token: [u8; 32], body: Vec<u8>) -> Self {
        Self { kind, token, body }
    }

    /// Serialize to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.push(ENVELOPE_VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse from the wire format. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::Malformed);
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(ProtocolError::Malformed);
        }
        let kind = EnvelopeKind::try_from(bytes[1])?;
        let mut token = [0u8; 32];
        token.copy_from_slice(&bytes[2..HEADER_LEN]);
        Ok(Self {
            kind,
            token,
            body: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// Stable content id (first 16 bytes of BLAKE3 of the encoding) — used
    /// for dedup across redundant multipath delivery.
    pub fn content_id(&self) -> [u8; 16] {
        let hash = blake3::hash(&self.encode());
        hash.as_bytes()[..16].try_into().expect("16 <= 32")
    }
}
