//! Argon2id key-encryption-key derivation for at-rest encryption.
//! Spec: docs/04-cryptography.md §8.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// Argon2id cost profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfProfile {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
}

/// Desktop profile: m = 256 MiB, t = 3, p = 4 (spec §8).
pub const KDF_PROFILE_DESKTOP: KdfProfile = KdfProfile {
    m_cost_kib: 256 * 1024,
    t_cost: 3,
    p_cost: 4,
};

/// Mobile profile: m = 64 MiB, t = 3, p = 4 (spec §8).
pub const KDF_PROFILE_MOBILE: KdfProfile = KdfProfile {
    m_cost_kib: 64 * 1024,
    t_cost: 3,
    p_cost: 4,
};

/// Derive the 32-byte key-encryption key from a passphrase and a random
/// 16-byte salt (stored alongside the wrapped master key).
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8; 16],
    profile: KdfProfile,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(profile.m_cost_kib, profile.t_cost, profile.p_cost, Some(32))
        .map_err(|_| CryptoError::KdfParams)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| CryptoError::KdfParams)?;
    Ok(out)
}
