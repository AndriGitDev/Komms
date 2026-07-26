//! Sneakernet bundles (`.kkb`, docs/05-transports.md §5): a bare
//! concatenation of sealed envelopes. The bundle format adds **no metadata**
//! beyond what the envelopes already expose — a courier learns only total
//! size and envelope count.
//!
//! Wire layout: `magic "KKB1" || repeated (len: u32 LE || envelope bytes)`.

use alloc::vec::Vec;

use crate::{Envelope, ProtocolError, Result, MAX_ENVELOPE_BYTES};

/// Bundle file magic.
pub const BUNDLE_MAGIC: &[u8; 4] = b"KKB1";
/// Maximum aggregate bytes admitted for one courier bundle.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum envelopes admitted in one courier bundle.
pub const MAX_BUNDLE_ENVELOPES: usize = 4_096;

/// Serialize bounded envelopes into a bundle.
///
/// Every entry is validated against [`MAX_ENVELOPE_BYTES`] before it is
/// emitted, so this function can never create a bundle that
/// [`bundle_import`] rejects solely for an oversized envelope.
pub fn bundle_export(envelopes: &[Envelope]) -> Result<Vec<u8>> {
    if envelopes.len() > MAX_BUNDLE_ENVELOPES {
        return Err(ProtocolError::TooManyBundleEntries);
    }
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    for env in envelopes {
        let bytes = env.try_encode()?;
        let next_len = out
            .len()
            .checked_add(4)
            .and_then(|len| len.checked_add(bytes.len()))
            .ok_or(ProtocolError::BundleTooLarge)?;
        if next_len > MAX_BUNDLE_BYTES {
            return Err(ProtocolError::BundleTooLarge);
        }
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Parse a bundle. Strict: bad magic, truncation, oversized entries, or an
/// undecodable envelope reject the whole bundle (couriered files are either
/// intact or worthless — no partial trust).
pub fn bundle_import(bytes: &[u8]) -> Result<Vec<Envelope>> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(ProtocolError::BundleTooLarge);
    }
    let rest = bytes
        .strip_prefix(BUNDLE_MAGIC.as_slice())
        .ok_or(ProtocolError::Malformed)?;
    let mut envelopes = Vec::new();
    let mut cursor = rest;
    while !cursor.is_empty() {
        if envelopes.len() >= MAX_BUNDLE_ENVELOPES {
            return Err(ProtocolError::TooManyBundleEntries);
        }
        if cursor.len() < 4 {
            return Err(ProtocolError::Malformed);
        }
        let len = u32::from_le_bytes(cursor[..4].try_into().expect("length checked")) as usize;
        if len > MAX_ENVELOPE_BYTES {
            return Err(ProtocolError::EnvelopeTooLarge);
        }
        if cursor.len() < 4 + len {
            return Err(ProtocolError::Malformed);
        }
        envelopes.push(Envelope::decode(&cursor[4..4 + len])?);
        cursor = &cursor[4 + len..];
    }
    Ok(envelopes)
}
