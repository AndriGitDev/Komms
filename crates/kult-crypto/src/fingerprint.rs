//! Safety-number fingerprints for out-of-band verification.
//! Spec: docs/04-cryptography.md §9; UX: docs/06-identity-trust.md §3.

use alloc::string::String;

use sha2::{Digest, Sha256};

use crate::{util, IdentityPublic, PROTOCOL_VERSION};

/// Iteration count for the fingerprint hash chain (spec §9).
const ITERATIONS: u32 = 5_200;
const FP_INFO: &[u8] = b"KK-fingerprint";

/// A comparable safety number: 60 decimal digits for humans, 32 raw bytes for
/// QR comparison. Symmetric — both parties compute the identical value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SafetyNumber {
    /// 60 decimal digits (12 groups of 5).
    pub digits: String,
    /// Raw comparison value for QR encoding.
    pub qr: [u8; 32],
}

impl SafetyNumber {
    /// The digits grouped 5-at-a-time, space-separated, for display.
    pub fn display_groups(&self) -> String {
        let mut out = String::with_capacity(60 + 11);
        for (i, c) in self.digits.chars().enumerate() {
            if i > 0 && i % 5 == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }
}

/// Compute the safety number between two identities (order-independent).
///
/// `digest = SHA-256^5200(version || IK_min || IK_max)`; the 60 digits are
/// taken from `HKDF(digest, "KK-fingerprint")` expanded to 48 bytes, read as
/// 12 big-endian u32 groups mod 100 000.
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> SafetyNumber {
    let (lo, hi) = if a.ed <= b.ed { (a, b) } else { (b, a) };

    let mut d: [u8; 32] = {
        let mut h = Sha256::new();
        h.update([PROTOCOL_VERSION]);
        h.update(lo.ed);
        h.update(hi.ed);
        h.finalize().into()
    };
    for _ in 1..ITERATIONS {
        let mut h = Sha256::new();
        h.update(d);
        d = h.finalize().into();
    }

    let mut okm = [0u8; 48];
    util::hkdf_expand(None, &d, FP_INFO, &mut okm);

    let mut digits = String::with_capacity(60);
    for chunk in okm.chunks_exact(4) {
        let v = u32::from_be_bytes(chunk.try_into().expect("chunk of 4")) % 100_000;
        // Zero-padded 5-digit group.
        let mut buf = [b'0'; 5];
        let mut v = v;
        for slot in buf.iter_mut().rev() {
            *slot = b'0' + (v % 10) as u8;
            v /= 10;
        }
        digits.push_str(core::str::from_utf8(&buf).expect("ASCII digits"));
    }

    SafetyNumber { digits, qr: d }
}
