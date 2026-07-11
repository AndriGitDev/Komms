//! ISO/IEC 7816-4 padding to fixed size buckets (spec §5): every plaintext
//! is padded before encryption so ciphertext lengths quantize to a small set
//! of values, denying observers message-length metadata.

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// The normative bucket sizes. The 192 B bucket exists so a short text plus
/// protocol overhead still fits ≤ 2 LoRa frames after fragmentation.
pub const PAD_BUCKETS: [usize; 6] = [192, 512, 1024, 4096, 16384, 65536];

/// Pad `plaintext` to the smallest bucket that fits it (plus the mandatory
/// `0x80` marker byte). Payloads above the largest bucket must be chunked by
/// the caller (media path).
pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let needed = plaintext.len() + 1; // marker byte always present
    let bucket = PAD_BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= needed)
        .ok_or(ProtocolError::TooLarge)?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(bucket, 0x00);
    Ok(out)
}

/// Remove ISO 7816-4 padding. Rejects anything that is not exactly
/// `data || 0x80 || 0x00*` in a valid bucket size.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if !PAD_BUCKETS.contains(&padded.len()) {
        return Err(ProtocolError::BadPadding);
    }
    // Scan from the end: zeros, then the 0x80 marker. Padding is not secret
    // (it is inside the AEAD), so this need not be constant-time.
    let mut i = padded.len();
    while i > 0 && padded[i - 1] == 0x00 {
        i -= 1;
    }
    if i == 0 || padded[i - 1] != 0x80 {
        return Err(ProtocolError::BadPadding);
    }
    Ok(padded[..i - 1].to_vec())
}
