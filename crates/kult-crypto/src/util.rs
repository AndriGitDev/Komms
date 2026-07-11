//! Internal helpers: HKDF wrappers, AEAD wrappers, base32, serde shims.

use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// XChaCha20-Poly1305 nonce length (24 bytes; random nonces per spec).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// HKDF-SHA-256 → 32 bytes.
pub fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// HKDF-SHA-256 → arbitrary length (bounded by HKDF's 255*32).
pub fn hkdf_expand(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, out)
        .expect("output length within HKDF-SHA256 bounds");
}

/// AEAD-seal `plaintext` under `key` with a fresh random nonce.
/// Output layout: `nonce(24) || ciphertext+tag`.
pub fn aead_seal(
    key: &[u8; 32],
    ad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open an [`aead_seal`]-format buffer. Errors are deliberately uniform.
pub fn aead_open(key: &[u8; 32], ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::MessageAuthentication);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| CryptoError::MessageAuthentication)
}

/// AEAD-encrypt with an explicit caller-held nonce (ratchet hot path).
pub fn aead_encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

/// Counterpart to [`aead_encrypt_with_nonce`].
pub fn aead_decrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| CryptoError::MessageAuthentication)
}

/// RFC 4648 base32, lowercase, no padding — used for kult addresses.
pub fn base32_lower_nopad(data: &[u8]) -> alloc::string::String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = alloc::string::String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Serde shim for `[u8; 64]` (serde has no built-in impl past 32 bytes).
pub mod bytes64 {
    use core::fmt;
    use serde::{de, Deserializer, Serializer};

    /// Serialize a 64-byte array as a byte string.
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    /// Deserialize a byte string into a 64-byte array, rejecting other lengths.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> core::result::Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> core::result::Result<Self::Value, E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(V)
    }
}
