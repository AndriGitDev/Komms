//! Signed, target-specific first-contact admission policy.
//!
//! The descriptor and an optional invitation capability are carried as
//! reserved opaque entries in [`crate::PrekeyBundle::relay_hints`]. The
//! ordinary bundle signature therefore covers them without changing the
//! legacy bundle codec, while routing layers continue to treat the entries as
//! opaque and skip them.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{util, CryptoError, Identity, IdentityPublic, PrekeyBundle, Result};

const DESCRIPTOR_MAGIC: &[u8; 4] = b"KAD1";
const INVITATION_MAGIC: &[u8; 4] = b"KAI1";
const DESCRIPTOR_DOMAIN: &[u8] = b"Komms-admission-descriptor-v1";
const BUNDLE_DIGEST_DOMAIN: &[u8] = b"Komms-admission-bundle-v1";
const INVITATION_DOMAIN: &[u8] = b"Komms-admission-invitation-v1";

/// Current admission descriptor version.
pub const ADMISSION_DESCRIPTOR_VERSION: u8 = 1;
/// Fixed descriptor epoch duration.
pub const ADMISSION_EPOCH_SECS: u64 = 3_600;
/// Lowest public SHA-256 puzzle difficulty accepted by the codec.
pub const MIN_ADMISSION_DIFFICULTY: u8 = 8;
/// Highest public SHA-256 puzzle difficulty accepted by the codec.
pub const MAX_ADMISSION_DIFFICULTY: u8 = 20;
/// Default public SHA-256 puzzle difficulty.
pub const DEFAULT_ADMISSION_DIFFICULTY: u8 = 12;
/// Maximum first-flight sealed ciphertext advertised by any descriptor.
pub const MAX_ADMISSION_FIRST_CIPHERTEXT: usize = 16 * 1024;
/// Default first-flight sealed ciphertext limit.
pub const DEFAULT_ADMISSION_FIRST_CIPHERTEXT: usize = 8 * 1024;
/// Maximum clock skew accepted around the descriptor validity epoch.
pub const MAX_ADMISSION_CLOCK_SKEW_SECS: u32 = 6 * 3_600;
/// Default clock skew accepted around the descriptor validity epoch.
pub const DEFAULT_ADMISSION_CLOCK_SKEW_SECS: u32 = 2 * 3_600;
/// Maximum supported anonymous admission-token issuers.
pub const MAX_ADMISSION_TOKEN_ISSUERS: usize = 4;
/// Maximum encoded descriptor extension size.
pub const MAX_ADMISSION_DESCRIPTOR_BYTES: usize = 512;

/// Admission puzzle advertised by a descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdmissionPuzzleProfile {
    /// SHA-256 digest with a bounded number of required leading zero bits.
    Sha256LeadingZeroBits = 1,
}

/// Recipient-selected public admission policy used when issuing a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// SHA-256 leading-zero difficulty.
    pub difficulty: u8,
    /// Maximum anonymous-boxed first-flight bytes.
    pub max_first_ciphertext: u32,
    /// Allowed skew around the descriptor epoch.
    pub max_clock_skew_secs: u32,
    /// Optional anonymous admission-token issuer fingerprints.
    pub token_issuers: Vec<[u8; 32]>,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            difficulty: DEFAULT_ADMISSION_DIFFICULTY,
            max_first_ciphertext: DEFAULT_ADMISSION_FIRST_CIPHERTEXT as u32,
            max_clock_skew_secs: DEFAULT_ADMISSION_CLOCK_SKEW_SECS,
            token_issuers: Vec::new(),
        }
    }
}

impl AdmissionPolicy {
    fn validate(&self) -> Result<()> {
        if !(MIN_ADMISSION_DIFFICULTY..=MAX_ADMISSION_DIFFICULTY).contains(&self.difficulty)
            || self.max_first_ciphertext == 0
            || usize::try_from(self.max_first_ciphertext)
                .map_or(true, |size| size > MAX_ADMISSION_FIRST_CIPHERTEXT)
            || self.max_clock_skew_secs > MAX_ADMISSION_CLOCK_SKEW_SECS
            || self.token_issuers.len() > MAX_ADMISSION_TOKEN_ISSUERS
            || self.token_issuers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(CryptoError::InvalidBundle);
        }
        Ok(())
    }
}

/// Signed policy bound to one exact prekey bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDescriptor {
    /// Codec and policy version.
    pub version: u8,
    /// SHA-256 digest of the bundle excluding admission extensions/signature.
    pub bundle_digest: [u8; 32],
    /// Fixed-hour epoch in which the descriptor was issued.
    pub validity_epoch: u64,
    /// Last Unix second at which this policy may be used.
    pub expires_at: u64,
    /// Maximum tolerated local clock skew.
    pub max_clock_skew_secs: u32,
    /// Bounded client-puzzle construction.
    pub puzzle_profile: AdmissionPuzzleProfile,
    /// Required SHA-256 leading-zero bits.
    pub difficulty: u8,
    /// Maximum anonymous-boxed first-flight bytes.
    pub max_first_ciphertext: u32,
    /// Commitment to an out-of-band invitation secret, when present.
    pub invitation_commitment: Option<[u8; 32]>,
    /// Sorted fingerprints of optional anonymous token issuers.
    pub token_issuers: Vec<[u8; 32]>,
    /// Recipient-device signature over every preceding field.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl AdmissionDescriptor {
    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.token_issuers.len() * 32);
        out.push(self.version);
        out.extend_from_slice(&self.bundle_digest);
        out.extend_from_slice(&self.validity_epoch.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.max_clock_skew_secs.to_le_bytes());
        out.push(self.puzzle_profile as u8);
        out.push(self.difficulty);
        out.extend_from_slice(&self.max_first_ciphertext.to_le_bytes());
        match self.invitation_commitment {
            Some(commitment) => {
                out.push(1);
                out.extend_from_slice(&commitment);
            }
            None => out.push(0),
        }
        out.push(self.token_issuers.len() as u8);
        for issuer in &self.token_issuers {
            out.extend_from_slice(issuer);
        }
        out
    }

    fn verify(&self, recipient: &IdentityPublic, now: u64) -> Result<()> {
        let policy = AdmissionPolicy {
            difficulty: self.difficulty,
            max_first_ciphertext: self.max_first_ciphertext,
            max_clock_skew_secs: self.max_clock_skew_secs,
            token_issuers: self.token_issuers.clone(),
        };
        policy.validate()?;
        if self.version != ADMISSION_DESCRIPTOR_VERSION
            || self.puzzle_profile != AdmissionPuzzleProfile::Sha256LeadingZeroBits
            || self.expires_at / ADMISSION_EPOCH_SECS < self.validity_epoch
        {
            return Err(CryptoError::InvalidBundle);
        }
        let epoch_start = self
            .validity_epoch
            .checked_mul(ADMISSION_EPOCH_SECS)
            .ok_or(CryptoError::InvalidBundle)?;
        if now != 0
            && (now.saturating_add(u64::from(self.max_clock_skew_secs)) < epoch_start
                || now
                    > self
                        .expires_at
                        .saturating_add(u64::from(self.max_clock_skew_secs)))
        {
            return Err(CryptoError::InvalidBundle);
        }
        recipient.verify_domain(DESCRIPTOR_DOMAIN, &self.canonical(), &self.signature)
    }
}

/// Verified admission material extracted from one exact signed bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmission {
    /// Signed target policy.
    pub descriptor: AdmissionDescriptor,
    /// Out-of-band invitation secret, only in QR/link/file bundles.
    pub invitation: Option<[u8; 32]>,
}

/// Return whether an opaque relay-hint entry is reserved for admission.
pub fn is_admission_extension(bytes: &[u8]) -> bool {
    bytes.starts_with(DESCRIPTOR_MAGIC) || bytes.starts_with(INVITATION_MAGIC)
}

pub(crate) fn is_invitation_extension(bytes: &[u8]) -> bool {
    bytes.starts_with(INVITATION_MAGIC)
}

/// Compute the exact digest descriptors bind.
///
/// Admission extensions and the whole-bundle signature are excluded to avoid
/// a circular construction. Ordinary relay hints remain included.
pub fn admission_bundle_digest(bundle: &PrekeyBundle) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BUNDLE_DIGEST_DOMAIN);
    hash.update(bundle.admission_signing_bytes());
    hash.finalize().into()
}

fn invitation_commitment(
    recipient: &[u8; 32],
    bundle_digest: &[u8; 32],
    validity_epoch: u64,
    expires_at: u64,
    invitation: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(INVITATION_DOMAIN);
    hash.update(recipient);
    hash.update(bundle_digest);
    hash.update(validity_epoch.to_le_bytes());
    hash.update(expires_at.to_le_bytes());
    hash.update(invitation);
    hash.finalize().into()
}

pub(crate) fn attach_admission(
    bundle: &mut PrekeyBundle,
    identity: &Identity,
    now: u64,
    policy: AdmissionPolicy,
    invitation: Option<[u8; 32]>,
) -> Result<()> {
    policy.validate()?;
    if bundle.identity != identity.public() || now > bundle.expires_at {
        return Err(CryptoError::InvalidBundle);
    }
    bundle
        .relay_hints
        .retain(|hint| !is_admission_extension(hint));
    let bundle_digest = admission_bundle_digest(bundle);
    let validity_epoch = now / ADMISSION_EPOCH_SECS;
    let commitment = invitation.as_ref().map(|secret| {
        invitation_commitment(
            &bundle.identity.ed,
            &bundle_digest,
            validity_epoch,
            bundle.expires_at,
            secret,
        )
    });
    let mut descriptor = AdmissionDescriptor {
        version: ADMISSION_DESCRIPTOR_VERSION,
        bundle_digest,
        validity_epoch,
        expires_at: bundle.expires_at,
        max_clock_skew_secs: policy.max_clock_skew_secs,
        puzzle_profile: AdmissionPuzzleProfile::Sha256LeadingZeroBits,
        difficulty: policy.difficulty,
        max_first_ciphertext: policy.max_first_ciphertext,
        invitation_commitment: commitment,
        token_issuers: policy.token_issuers,
        signature: [0u8; 64],
    };
    descriptor.signature = identity.sign_domain(DESCRIPTOR_DOMAIN, &descriptor.canonical());
    let encoded = postcard::to_allocvec(&descriptor).map_err(|_| CryptoError::Serialization)?;
    if encoded.len() > MAX_ADMISSION_DESCRIPTOR_BYTES {
        return Err(CryptoError::InvalidBundle);
    }
    let mut descriptor_hint = Vec::with_capacity(DESCRIPTOR_MAGIC.len() + encoded.len());
    descriptor_hint.extend_from_slice(DESCRIPTOR_MAGIC);
    descriptor_hint.extend_from_slice(&encoded);
    bundle.relay_hints.push(descriptor_hint);
    if let Some(secret) = invitation {
        let mut invitation_hint = Vec::with_capacity(INVITATION_MAGIC.len() + secret.len());
        invitation_hint.extend_from_slice(INVITATION_MAGIC);
        invitation_hint.extend_from_slice(&secret);
        bundle.relay_hints.push(invitation_hint);
    }
    bundle.resign(identity);
    Ok(())
}

pub(crate) fn verify_admission(bundle: &PrekeyBundle, now: u64) -> Result<VerifiedAdmission> {
    let mut descriptor = None;
    let mut invitation = None;
    for hint in &bundle.relay_hints {
        if let Some(encoded) = hint.strip_prefix(DESCRIPTOR_MAGIC) {
            if descriptor.is_some() || encoded.len() > MAX_ADMISSION_DESCRIPTOR_BYTES {
                return Err(CryptoError::InvalidBundle);
            }
            let (decoded, remainder): (AdmissionDescriptor, &[u8]) =
                postcard::take_from_bytes(encoded).map_err(|_| CryptoError::Serialization)?;
            if !remainder.is_empty() {
                return Err(CryptoError::Serialization);
            }
            descriptor = Some(decoded);
        } else if let Some(encoded) = hint.strip_prefix(INVITATION_MAGIC) {
            if invitation.is_some() || encoded.len() != 32 {
                return Err(CryptoError::InvalidBundle);
            }
            invitation = Some(encoded.try_into().map_err(|_| CryptoError::InvalidBundle)?);
        }
    }
    let descriptor = descriptor.ok_or(CryptoError::InvalidBundle)?;
    descriptor.verify(&bundle.identity, now)?;
    if descriptor.bundle_digest != admission_bundle_digest(bundle)
        || descriptor.expires_at != bundle.expires_at
    {
        return Err(CryptoError::InvalidBundle);
    }
    match (descriptor.invitation_commitment, invitation) {
        (Some(expected), Some(secret))
            if expected
                == invitation_commitment(
                    &bundle.identity.ed,
                    &descriptor.bundle_digest,
                    descriptor.validity_epoch,
                    descriptor.expires_at,
                    &secret,
                ) => {}
        (Some(_), None) | (None, None) => {}
        (Some(_), Some(_)) | (None, Some(_)) => return Err(CryptoError::InvalidBundle),
    }
    Ok(VerifiedAdmission {
        descriptor,
        invitation,
    })
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::{OneTimePrekeySecret, PqPrekeySecret, SignedPrekeySecret};

    use super::*;

    fn bundle(now: u64, with_invitation: bool) -> (PrekeyBundle, Identity) {
        let mut rng = StdRng::seed_from_u64(0x0030_0001);
        let identity = Identity::generate(&mut rng);
        let spk = SignedPrekeySecret::generate(&mut rng, 7);
        let pq = PqPrekeySecret::generate(&mut rng, 8);
        let opk = OneTimePrekeySecret::generate(&mut rng, 9);
        let mut bundle = PrekeyBundle::build(
            &identity,
            &spk,
            &pq,
            Some(&opk),
            now + 86_400,
            vec![b"ordinary-route".to_vec()],
        );
        let invitation = with_invitation.then(|| {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            secret
        });
        bundle
            .attach_admission(&identity, now, AdmissionPolicy::default(), invitation)
            .unwrap();
        (bundle, identity)
    }

    #[test]
    fn descriptor_is_signed_bound_and_legacy_codec_compatible() {
        let now = 1_800_000_000;
        let (bundle, _) = bundle(now, false);
        bundle.verify(now).unwrap();
        let admission = bundle.verify_admission(now).unwrap();
        assert_eq!(
            admission.descriptor.bundle_digest,
            admission_bundle_digest(&bundle)
        );
        assert!(admission.invitation.is_none());
        assert_eq!(bundle.transport_hints(), vec![b"ordinary-route".to_vec()]);
        let decoded = PrekeyBundle::decode(&bundle.encode()).unwrap();
        decoded.verify_admission(now).unwrap();
        assert_eq!(decoded.transport_hints(), vec![b"ordinary-route".to_vec()]);
    }

    #[test]
    fn invitation_is_committed_and_tampering_fails_closed() {
        let now = 1_800_000_000;
        let (bundle, identity) = bundle(now, true);
        assert!(bundle.verify_admission(now).unwrap().invitation.is_some());

        let mut tampered = bundle.clone();
        let extension = tampered
            .relay_hints
            .iter_mut()
            .find(|hint| hint.starts_with(INVITATION_MAGIC))
            .unwrap();
        *extension.last_mut().unwrap() ^= 1;
        tampered.resign(&identity);
        assert_eq!(
            tampered.verify_admission(now),
            Err(CryptoError::InvalidBundle)
        );
    }

    #[test]
    fn descriptor_rejects_clock_window_and_policy_escalation() {
        let now = 1_800_000_000;
        let (bundle, identity) = bundle(now, false);
        assert_eq!(
            bundle.verify_admission(now + 100_000),
            Err(CryptoError::InvalidBundle)
        );

        let mut tampered = bundle;
        let hint = tampered
            .relay_hints
            .iter_mut()
            .find(|hint| hint.starts_with(DESCRIPTOR_MAGIC))
            .unwrap();
        let mut descriptor: AdmissionDescriptor =
            postcard::from_bytes(&hint[DESCRIPTOR_MAGIC.len()..]).unwrap();
        descriptor.difficulty = MAX_ADMISSION_DIFFICULTY + 1;
        descriptor.signature = identity.sign_domain(DESCRIPTOR_DOMAIN, &descriptor.canonical());
        hint.truncate(DESCRIPTOR_MAGIC.len());
        hint.extend_from_slice(&postcard::to_allocvec(&descriptor).unwrap());
        tampered.resign(&identity);
        assert_eq!(
            tampered.verify_admission(now),
            Err(CryptoError::InvalidBundle)
        );
    }
}
