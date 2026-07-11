//! Sneakernet bundles (`.kkb`, docs/05-transports.md §5): a bare
//! concatenation of sealed envelopes. The bundle format adds **no metadata**
//! beyond what the envelopes already expose — a courier learns only total
//! size and envelope count.
//!
//! Wire layout: `magic "KKB1" || repeated (len: u32 LE || envelope bytes)`.

use alloc::vec::Vec;

use crate::{Envelope, ProtocolError, Result};

/// Bundle file magic.
pub const BUNDLE_MAGIC: &[u8; 4] = b"KKB1";

/// Per-envelope hard cap inside bundles — matches the largest padded message
/// plus protocol overhead; rejects absurd length prefixes early.
const MAX_ENVELOPE_BYTES: usize = 128 * 1024;

/// Serialize envelopes into a bundle.
pub fn bundle_export(envelopes: &[Envelope]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + envelopes
            .iter()
            .map(|e| 4 + e.body.len() + 34)
            .sum::<usize>(),
    );
    out.extend_from_slice(BUNDLE_MAGIC);
    for env in envelopes {
        let bytes = env.encode();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// Parse a bundle. Strict: bad magic, truncation, oversized entries, or an
/// undecodable envelope reject the whole bundle (couriered files are either
/// intact or worthless — no partial trust).
pub fn bundle_import(bytes: &[u8]) -> Result<Vec<Envelope>> {
    let rest = bytes
        .strip_prefix(BUNDLE_MAGIC.as_slice())
        .ok_or(ProtocolError::Malformed)?;
    let mut envelopes = Vec::new();
    let mut cursor = rest;
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(ProtocolError::Malformed);
        }
        let len = u32::from_le_bytes(cursor[..4].try_into().expect("length checked")) as usize;
        if len > MAX_ENVELOPE_BYTES || cursor.len() < 4 + len {
            return Err(ProtocolError::Malformed);
        }
        envelopes.push(Envelope::decode(&cursor[4..4 + len])?);
        cursor = &cursor[4 + len..];
    }
    Ok(envelopes)
}
