//! Fragmentation and reassembly for small-MTU links
//! (docs/05-transports.md §4.2, docs/04-cryptography.md §5).
//!
//! Fragment body layout: `msg_id(4) || index(2, LE) || count(2, LE) || slice`.
//! `msg_id` is the first 4 bytes of BLAKE3 of the complete payload — cheap to
//! compute, verified again on completion so mixed-up fragments fail closed.
//! Fragments travel as [`crate::Envelope`]s of kind `Fragment`, carrying the
//! same delivery token as the message they belong to.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Fragment header length in bytes.
pub const FRAG_HEADER_LEN: usize = 4 + 2 + 2;
/// How long an incomplete message is retained (24 h, normative).
pub const REASSEMBLY_WINDOW_SECS: u64 = 24 * 3600;
/// Maximum concurrent partial messages (fail-closed cap).
const MAX_PARTIALS: usize = 256;
/// Maximum reassembled size (matches largest pad bucket + protocol overhead).
const MAX_MESSAGE_BYTES: usize = 128 * 1024;

fn msg_id(payload: &[u8]) -> [u8; 4] {
    blake3::hash(payload).as_bytes()[..4]
        .try_into()
        .expect("4 <= 32")
}

/// Split `payload` into fragment bodies of at most `mtu` bytes each
/// (header included). Returns bodies ready to wrap in `Fragment` envelopes.
pub fn fragment(payload: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>> {
    if mtu <= FRAG_HEADER_LEN {
        return Err(ProtocolError::MtuTooSmall);
    }
    let slice_len = mtu - FRAG_HEADER_LEN;
    let count = payload.len().div_ceil(slice_len).max(1);
    if count > u16::MAX as usize {
        return Err(ProtocolError::TooManyFragments);
    }
    let id = msg_id(payload);
    let mut out = Vec::with_capacity(count);
    for (i, chunk) in payload.chunks(slice_len).enumerate() {
        let mut body = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
        body.extend_from_slice(&id);
        body.extend_from_slice(&(i as u16).to_le_bytes());
        body.extend_from_slice(&(count as u16).to_le_bytes());
        body.extend_from_slice(chunk);
        out.push(body);
    }
    if payload.is_empty() {
        // Degenerate but well-formed: a single empty fragment.
        let mut body = Vec::with_capacity(FRAG_HEADER_LEN);
        body.extend_from_slice(&id);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        out.push(body);
    }
    Ok(out)
}

struct Partial {
    count: u16,
    parts: BTreeMap<u16, Vec<u8>>,
    bytes: usize,
    first_seen: u64,
}

/// Stateful reassembler with the normative 24-hour window, partial caps, and
/// NACK generation for selective retransmission.
#[derive(Default)]
pub struct Reassembler {
    partials: BTreeMap<[u8; 4], Partial>,
}

impl Reassembler {
    /// Create an empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one fragment body. Returns `Ok(Some(payload))` when the
    /// message completes (and verifies), `Ok(None)` while incomplete.
    /// Duplicates are ignored; inconsistent or over-cap input fails closed.
    pub fn insert(&mut self, frag_body: &[u8], now_secs: u64) -> Result<Option<Vec<u8>>> {
        self.purge(now_secs);

        if frag_body.len() < FRAG_HEADER_LEN {
            return Err(ProtocolError::Malformed);
        }
        let id: [u8; 4] = frag_body[..4].try_into().expect("length checked");
        let index = u16::from_le_bytes(frag_body[4..6].try_into().expect("length checked"));
        let count = u16::from_le_bytes(frag_body[6..8].try_into().expect("length checked"));
        let slice = &frag_body[FRAG_HEADER_LEN..];
        if count == 0 || index >= count {
            return Err(ProtocolError::Malformed);
        }

        let partial = match self.partials.get_mut(&id) {
            Some(p) => {
                if p.count != count {
                    // Conflicting metadata for the same id: drop the partial.
                    self.partials.remove(&id);
                    return Err(ProtocolError::IntegrityMismatch);
                }
                p
            }
            None => {
                if self.partials.len() >= MAX_PARTIALS {
                    return Err(ProtocolError::ReassemblyOverflow);
                }
                self.partials.entry(id).or_insert(Partial {
                    count,
                    parts: BTreeMap::new(),
                    bytes: 0,
                    first_seen: now_secs,
                })
            }
        };

        if partial.parts.contains_key(&index) {
            return Ok(None); // duplicate
        }
        if partial.bytes + slice.len() > MAX_MESSAGE_BYTES {
            self.partials.remove(&id);
            return Err(ProtocolError::ReassemblyOverflow);
        }
        partial.bytes += slice.len();
        partial.parts.insert(index, slice.to_vec());

        if partial.parts.len() == usize::from(partial.count) {
            let partial = self.partials.remove(&id).expect("present");
            let mut payload = Vec::with_capacity(partial.bytes);
            for (_, part) in partial.parts {
                payload.extend_from_slice(&part);
            }
            // End-to-end check: id must match the reassembled bytes.
            if msg_id(&payload) != id {
                return Err(ProtocolError::IntegrityMismatch);
            }
            return Ok(Some(payload));
        }
        Ok(None)
    }

    /// Missing fragment indices per in-flight message — the payload for NACK
    /// receipts driving selective retransmission (docs/05-transports.md §4.2).
    pub fn missing(&self, now_secs: u64) -> Vec<([u8; 4], Vec<u16>)> {
        self.partials
            .iter()
            .filter(|(_, p)| now_secs.saturating_sub(p.first_seen) <= REASSEMBLY_WINDOW_SECS)
            .map(|(id, p)| {
                let miss = (0..p.count).filter(|i| !p.parts.contains_key(i)).collect();
                (*id, miss)
            })
            .collect()
    }

    /// Number of in-flight partial messages.
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    fn purge(&mut self, now_secs: u64) {
        self.partials
            .retain(|_, p| now_secs.saturating_sub(p.first_seen) <= REASSEMBLY_WINDOW_SECS);
    }
}
