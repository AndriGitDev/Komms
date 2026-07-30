//! ADR-0018 pairwise rendezvous key schedule and record protection.
//!
//! The caller supplies only a transcript-bound exporter created by a verified
//! PQXDH handshake. Provider and recipient separation happen before the hourly
//! slot and payload-key derivations, and the fixed plaintext codec lives in
//! `kult-protocol`.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{util, CryptoError, IdentityPublic, Result};

/// One rendezvous epoch is one Unix hour.
pub const RENDEZVOUS_EPOCH_SECS: u64 = 3_600;
/// Canonical plaintext route-record length.
pub const RENDEZVOUS_RECORD_PLAINTEXT_LEN: usize = 4_096;
/// Nonce plus fixed plaintext and Poly1305 tag.
pub const RENDEZVOUS_SEALED_RECORD_LEN: usize =
    util::NONCE_LEN + RENDEZVOUS_RECORD_PLAINTEXT_LEN + util::TAG_LEN;
/// Maximum server retention after a registration is received.
pub const RENDEZVOUS_MAX_TTL_SECS: u32 = 7_200;
/// Maximum accepted canonical provider-origin length.
pub const MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES: usize = 512;

const LOCATOR_INFO: &[u8] = b"Komms-Rendezvous-Locator-v1";
const PAYLOAD_INFO: &[u8] = b"Komms-Rendezvous-Payload-v1";
const SLOT_INFO: &[u8] = b"Komms-Rendezvous-Slot-v1";
const EPOCH_KEY_INFO: &[u8] = b"Komms-Rendezvous-Epoch-Key-v1";
const RECORD_AD: &[u8] = b"Komms-Rendezvous-Record-v1";

type HmacSha256 = Hmac<Sha256>;

/// Provider- and recipient-separated material for one hourly direction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RendezvousEpochKeys {
    provider_id: [u8; 32],
    slot: [u8; 32],
    epoch: u64,
    payload_key: [u8; 32],
}

impl RendezvousEpochKeys {
    /// Opaque provider id mixed into every derivation and record AD.
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    /// Hourly opaque server slot.
    pub fn slot(&self) -> [u8; 32] {
        self.slot
    }

    /// Unix-hour epoch represented by this material.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Compute the ADR-0018 provider id.
///
/// `canonical_origin` is the already canonicalized HTTPS origin, without a
/// path, query, fragment, user information, or trailing slash. Keeping
/// canonicalization at the configuration boundary lets this no-I/O crate
/// remain `no_std`.
pub fn rendezvous_provider_id(
    canonical_origin: &[u8],
    provider_static_key: &[u8; 32],
) -> Result<[u8; 32]> {
    if canonical_origin.is_empty()
        || canonical_origin.len() > MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES
        || canonical_origin.contains(&0)
    {
        return Err(CryptoError::InvalidKey);
    }
    let mut digest = Sha256::new();
    digest.update(canonical_origin);
    digest.update(provider_static_key);
    Ok(digest.finalize().into())
}

/// Unix-hour epoch for an absolute Unix second.
pub const fn rendezvous_epoch(now: u64) -> u64 {
    now / RENDEZVOUS_EPOCH_SECS
}

/// First Unix second represented by `epoch`.
pub fn rendezvous_epoch_starts_at(epoch: u64) -> Result<u64> {
    epoch
        .checked_mul(RENDEZVOUS_EPOCH_SECS)
        .ok_or(CryptoError::InvalidMessage)
}

/// Derive the provider- and direction-separated slot and payload key.
///
/// The canonical recipient identity is `ed25519(32) || x25519(32)`. Selecting
/// the local recipient derives the publication direction; selecting the peer
/// recipient derives the lookup direction.
pub fn derive_rendezvous_epoch_keys(
    hybrid_service_exporter: &[u8; 32],
    provider_id: &[u8; 32],
    recipient: &IdentityPublic,
    epoch: u64,
) -> Result<RendezvousEpochKeys> {
    recipient.verify()?;
    let mut recipient_identity = [0u8; 64];
    recipient_identity[..32].copy_from_slice(&recipient.ed);
    recipient_identity[32..].copy_from_slice(&recipient.x);

    let mut locator_info = Vec::with_capacity(LOCATOR_INFO.len() + recipient_identity.len());
    locator_info.extend_from_slice(LOCATOR_INFO);
    locator_info.extend_from_slice(&recipient_identity);
    let locator_key = util::hkdf32(Some(provider_id), hybrid_service_exporter, &locator_info);

    let mut payload_info = Vec::with_capacity(PAYLOAD_INFO.len() + recipient_identity.len());
    payload_info.extend_from_slice(PAYLOAD_INFO);
    payload_info.extend_from_slice(&recipient_identity);
    let payload_root = util::hkdf32(Some(provider_id), hybrid_service_exporter, &payload_info);

    let epoch_bytes = epoch.to_be_bytes();
    let mut mac =
        HmacSha256::new_from_slice(locator_key.as_ref()).map_err(|_| CryptoError::InvalidKey)?;
    mac.update(SLOT_INFO);
    mac.update(&epoch_bytes);
    let slot: [u8; 32] = mac.finalize().into_bytes().into();
    let payload_key = util::hkdf32(Some(&epoch_bytes), payload_root.as_ref(), EPOCH_KEY_INFO);

    Ok(RendezvousEpochKeys {
        provider_id: *provider_id,
        slot,
        epoch,
        payload_key: *payload_key,
    })
}

fn record_ad(keys: &RendezvousEpochKeys) -> Vec<u8> {
    let mut ad = Vec::with_capacity(RECORD_AD.len() + 32 + 32 + 8);
    ad.extend_from_slice(RECORD_AD);
    ad.extend_from_slice(&keys.provider_id);
    ad.extend_from_slice(&keys.slot);
    ad.extend_from_slice(&keys.epoch.to_be_bytes());
    ad
}

/// Seal one exact 4,096-byte canonical route record.
pub fn seal_rendezvous_record(
    keys: &RendezvousEpochKeys,
    plaintext: &[u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN],
    rng: &mut impl CryptoRngCore,
) -> [u8; RENDEZVOUS_SEALED_RECORD_LEN] {
    let sealed = util::aead_seal(&keys.payload_key, &record_ad(keys), plaintext, rng);
    let mut out = [0u8; RENDEZVOUS_SEALED_RECORD_LEN];
    out.copy_from_slice(&sealed);
    out
}

/// Authenticate and open one exact fixed-width route record.
pub fn open_rendezvous_record(
    keys: &RendezvousEpochKeys,
    sealed: &[u8],
) -> Result<Zeroizing<[u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN]>> {
    if sealed.len() != RENDEZVOUS_SEALED_RECORD_LEN {
        return Err(CryptoError::InvalidMessage);
    }
    let opened = Zeroizing::new(util::aead_open(
        &keys.payload_key,
        &record_ad(keys),
        sealed,
    )?);
    let mut out = Zeroizing::new([0u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN]);
    out.copy_from_slice(opened.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::Identity;

    #[test]
    fn provider_and_direction_separation_and_roundtrip() {
        let mut rng = StdRng::seed_from_u64(44);
        let recipient_a = Identity::generate(&mut rng).public();
        let recipient_b = Identity::generate(&mut rng).public();
        let exporter = [7u8; 32];
        let provider_a = rendezvous_provider_id(b"https://a.example", &[1u8; 32]).unwrap();
        let provider_b = rendezvous_provider_id(b"https://b.example", &[1u8; 32]).unwrap();

        let a = derive_rendezvous_epoch_keys(&exporter, &provider_a, &recipient_a, 99).unwrap();
        let other_provider =
            derive_rendezvous_epoch_keys(&exporter, &provider_b, &recipient_a, 99).unwrap();
        let other_direction =
            derive_rendezvous_epoch_keys(&exporter, &provider_a, &recipient_b, 99).unwrap();
        let other_epoch =
            derive_rendezvous_epoch_keys(&exporter, &provider_a, &recipient_a, 100).unwrap();
        assert_ne!(a.slot(), other_provider.slot());
        assert_ne!(a.slot(), other_direction.slot());
        assert_ne!(a.slot(), other_epoch.slot());

        let mut plaintext = [0u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN];
        plaintext[..4].copy_from_slice(b"test");
        let sealed = seal_rendezvous_record(&a, &plaintext, &mut rng);
        let opened = open_rendezvous_record(&a, &sealed).unwrap();
        assert_eq!(&*opened, &plaintext);
        assert!(open_rendezvous_record(&other_provider, &sealed).is_err());
        assert!(open_rendezvous_record(&other_direction, &sealed).is_err());
        assert!(open_rendezvous_record(&other_epoch, &sealed).is_err());
    }

    #[test]
    fn provider_origin_is_bounded() {
        assert!(rendezvous_provider_id(b"", &[0u8; 32]).is_err());
        assert!(rendezvous_provider_id(&vec![b'a'; 513], &[0u8; 32]).is_err());
        assert!(rendezvous_provider_id(b"https://bad.example\0x", &[0u8; 32]).is_err());
    }

    #[test]
    fn normative_rendezvous_vector() {
        let recipient = Identity::from_bytes(&[1u8; 64]).public();
        let provider = rendezvous_provider_id(b"https://vector.example", &[2u8; 32]).unwrap();
        let keys = derive_rendezvous_epoch_keys(&[3u8; 32], &provider, &recipient, 42).unwrap();
        let mut plaintext = [0u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN];
        plaintext[..16].copy_from_slice(b"Komms vector v1!");
        let mut rng = StdRng::seed_from_u64(0x1818);
        let sealed = seal_rendezvous_record(&keys, &plaintext, &mut rng);
        assert_eq!(
            provider.as_slice(),
            hex::decode("9935516320b17996593eb230fc34e0937209e308feaaa7ebb91fe370c15118fd")
                .unwrap()
        );
        assert_eq!(
            recipient.ed.as_slice(),
            hex::decode("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
                .unwrap()
        );
        assert_eq!(
            recipient.x.as_slice(),
            hex::decode("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209")
                .unwrap()
        );
        assert_eq!(
            keys.slot().as_slice(),
            hex::decode("b80ca6f4d326fefb8477f342f06c7bb16adbf8056d25ef88c2552bd39ffc87d6")
                .unwrap()
        );
        assert_eq!(
            &sealed[..24],
            hex::decode("0b4b6e38ee282f373c44950b4f4942f2c41253afab011f1b").unwrap()
        );
        assert_eq!(
            Sha256::digest(sealed).as_slice(),
            hex::decode("43424dfcf7f0cf4c190cc88f52e1feff4139c1f252838198415f137082b2723e")
                .unwrap()
        );
        assert_eq!(*open_rendezvous_record(&keys, &sealed).unwrap(), plaintext);
    }
}
