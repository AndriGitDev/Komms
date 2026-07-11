//! Sealed (encrypted-at-rest) serialization of session state.
//! Spec: docs/04-cryptography.md §8, docs/07-storage.md §2.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ratchet::Session, util, CryptoError, Result};

const SEAL_AD: &[u8] = b"KK-sealed-session-v1";

/// A 32-byte storage key, typically an HKDF-derived per-domain key under the
/// storage master key (`kult-store` owns that hierarchy).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StorageKey([u8; 32]);

impl StorageKey {
    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random storage key.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn seal_session(
    session: &Session,
    key: &StorageKey,
    rng: &mut impl CryptoRngCore,
) -> Vec<u8> {
    let plain = Zeroizing::new(
        postcard::to_allocvec(session).expect("session state serialization cannot fail"),
    );
    util::aead_seal(key.as_bytes(), SEAL_AD, &plain, rng)
}

pub(crate) fn unseal_session(bytes: &[u8], key: &StorageKey) -> Result<Session> {
    let plain = Zeroizing::new(util::aead_open(key.as_bytes(), SEAL_AD, bytes)?);
    postcard::from_bytes(&plain).map_err(|_| CryptoError::Serialization)
}
