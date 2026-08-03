//! Explicitly opened encrypted account-root recovery authority.
//!
//! This package is intentionally separate from routine backups and device
//! migration. It contains only the stable account root and its public binding;
//! live device, ratchet, rendezvous, wake, and delivery secrets never enter it.

use alloc::{string::String, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    mnemonic_from_entropy, mnemonic_to_entropy, util, CryptoError, Identity, IdentityPublic,
    Result, StorageKey,
};

/// Current encrypted offline recovery package version.
pub const ACCOUNT_RECOVERY_AUTHORITY_VERSION: u16 = 1;
/// Maximum encoded recovery package size.
pub const MAX_ACCOUNT_RECOVERY_AUTHORITY_BYTES: usize = 4096;

const RECOVERY_MAGIC: &[u8; 4] = b"KRA1";
const RECOVERY_KEY_INFO: &[u8] = b"Komms-account-recovery-authority-key-v1";
const RECOVERY_AD_DOMAIN: &[u8] = b"Komms-account-recovery-authority-package-v1";

#[derive(Serialize, Deserialize)]
struct RecoveryEnvelope {
    version: u16,
    account: IdentityPublic,
    sealed_root: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RecoveryPayload {
    root_secret: Vec<u8>,
    account: IdentityPublic,
}

/// Create encrypted offline recovery material and a one-time mnemonic.
///
/// The returned package may be backed up; the mnemonic must be shown through
/// an explicit recovery flow and is not retained by this crate.
pub fn seal_account_recovery_authority(
    root: &Identity,
    rng: &mut impl CryptoRngCore,
) -> Result<(Vec<u8>, Zeroizing<String>)> {
    let account = root.public();
    let mut entropy = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(entropy.as_mut());
    let mnemonic = mnemonic_from_entropy(&entropy);
    let key = recovery_key(&entropy, &account);
    let ad = recovery_ad(ACCOUNT_RECOVERY_AUTHORITY_VERSION, &account);
    let payload = RecoveryPayload {
        root_secret: root.to_bytes().to_vec(),
        account: account.clone(),
    };
    let mut plain =
        Zeroizing::new(postcard::to_allocvec(&payload).map_err(|_| CryptoError::Serialization)?);
    let sealed_root = StorageKey::from_bytes(*key).seal(&ad, &plain, rng);
    plain.zeroize();
    let envelope = RecoveryEnvelope {
        version: ACCOUNT_RECOVERY_AUTHORITY_VERSION,
        account,
        sealed_root,
    };
    let body = postcard::to_allocvec(&envelope).map_err(|_| CryptoError::Serialization)?;
    if body.len() > MAX_ACCOUNT_RECOVERY_AUTHORITY_BYTES {
        return Err(CryptoError::InvalidMessage);
    }
    let mut encoded = Vec::with_capacity(RECOVERY_MAGIC.len() + body.len());
    encoded.extend_from_slice(RECOVERY_MAGIC);
    encoded.extend_from_slice(&body);
    Ok((encoded, mnemonic))
}

/// Open the account root for one explicit recovery operation.
///
/// Callers must apply local attempt throttling before invoking this function
/// and must drop the returned root immediately after signing the recovery
/// transition.
pub fn open_account_recovery_authority(bytes: &[u8], mnemonic: &str) -> Result<Identity> {
    if bytes.len() > RECOVERY_MAGIC.len() + MAX_ACCOUNT_RECOVERY_AUTHORITY_BYTES {
        return Err(CryptoError::InvalidMessage);
    }
    let body = bytes
        .strip_prefix(RECOVERY_MAGIC)
        .ok_or(CryptoError::Serialization)?;
    let (envelope, remainder): (RecoveryEnvelope, &[u8]) =
        postcard::take_from_bytes(body).map_err(|_| CryptoError::Serialization)?;
    if !remainder.is_empty() || envelope.version != ACCOUNT_RECOVERY_AUTHORITY_VERSION {
        return Err(CryptoError::Serialization);
    }
    envelope.account.verify()?;
    let entropy = Zeroizing::new(mnemonic_to_entropy(mnemonic)?);
    let key = recovery_key(&entropy, &envelope.account);
    let ad = recovery_ad(envelope.version, &envelope.account);
    let mut plain = Zeroizing::new(StorageKey::from_bytes(*key).open(&ad, &envelope.sealed_root)?);
    let (mut payload, payload_remainder): (RecoveryPayload, &[u8]) =
        postcard::take_from_bytes(&plain).map_err(|_| CryptoError::Serialization)?;
    if !payload_remainder.is_empty() || payload.root_secret.len() != 64 {
        return Err(CryptoError::Serialization);
    }
    let root_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
        payload
            .root_secret
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?,
    );
    payload.root_secret.zeroize();
    plain.zeroize();
    let root = Identity::from_bytes(&root_bytes);
    if root.public() != envelope.account || payload.account != envelope.account {
        return Err(CryptoError::InvalidKey);
    }
    Ok(root)
}

/// Read and verify the public account binding without opening the root.
pub fn account_recovery_authority_public(bytes: &[u8]) -> Result<IdentityPublic> {
    if bytes.len() > RECOVERY_MAGIC.len() + MAX_ACCOUNT_RECOVERY_AUTHORITY_BYTES {
        return Err(CryptoError::InvalidMessage);
    }
    let body = bytes
        .strip_prefix(RECOVERY_MAGIC)
        .ok_or(CryptoError::Serialization)?;
    let (envelope, remainder): (RecoveryEnvelope, &[u8]) =
        postcard::take_from_bytes(body).map_err(|_| CryptoError::Serialization)?;
    if !remainder.is_empty() || envelope.version != ACCOUNT_RECOVERY_AUTHORITY_VERSION {
        return Err(CryptoError::Serialization);
    }
    envelope.account.verify()?;
    Ok(envelope.account)
}

fn recovery_key(entropy: &[u8; 32], account: &IdentityPublic) -> Zeroizing<[u8; 32]> {
    util::hkdf32(Some(&account.address_digest()), entropy, RECOVERY_KEY_INFO)
}

fn recovery_ad(version: u16, account: &IdentityPublic) -> Vec<u8> {
    let mut ad = Vec::with_capacity(RECOVERY_AD_DOMAIN.len() + 2 + 32 + 32 + 64);
    ad.extend_from_slice(RECOVERY_AD_DOMAIN);
    ad.extend_from_slice(&version.to_le_bytes());
    ad.extend_from_slice(&account.ed);
    ad.extend_from_slice(&account.x);
    ad.extend_from_slice(&account.cross_sig);
    ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn recovery_authority_round_trips_without_device_state() {
        let mut rng = StdRng::seed_from_u64(2610);
        let root = Identity::generate(&mut rng);
        let (package, mnemonic) = seal_account_recovery_authority(&root, &mut rng).unwrap();
        assert_eq!(
            account_recovery_authority_public(&package).unwrap(),
            root.public()
        );
        let opened = open_account_recovery_authority(&package, &mnemonic).unwrap();
        assert_eq!(opened.public(), root.public());
        let root_bytes = root.to_bytes();
        assert!(package
            .windows(root.to_bytes().len())
            .all(|window| window != &root_bytes[..]));
    }

    #[test]
    fn wrong_mnemonic_and_tampering_fail_closed() {
        let mut rng = StdRng::seed_from_u64(2611);
        let root = Identity::generate(&mut rng);
        let other = Identity::generate(&mut rng);
        let (mut package, _) = seal_account_recovery_authority(&root, &mut rng).unwrap();
        let (_, other_mnemonic) = seal_account_recovery_authority(&other, &mut rng).unwrap();
        assert!(open_account_recovery_authority(&package, &other_mnemonic).is_err());
        let last = package.len() - 1;
        package[last] ^= 0x80;
        assert!(open_account_recovery_authority(&package, &other_mnemonic).is_err());
    }
}
