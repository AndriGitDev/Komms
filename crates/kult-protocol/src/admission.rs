//! Fixed-header first-contact admission wrapper.
//!
//! A recipient can parse the exact target bundle, validate its signed
//! descriptor, and check the bounded proof before opening the anonymous box
//! or performing ML-KEM decapsulation.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

use crate::{ProtocolError, Result};

const ADMISSION_MAGIC: &[u8; 4] = b"KFA1";
const CONTENT_ID_DOMAIN: &[u8] = b"Komms-admission-content-v1";
const PUZZLE_DOMAIN: &[u8] = b"Komms-admission-puzzle-v1";
const INVITATION_PROOF_DOMAIN: &[u8] = b"Komms-admission-invitation-proof-v1";

/// Current first-contact admission wrapper version.
pub const ADMISSION_ENVELOPE_VERSION: u8 = 1;
/// Fixed bytes before the target bundle and anonymous ciphertext.
pub const ADMISSION_ENVELOPE_HEADER_LEN: usize = 168;
/// Maximum exact target-bundle bytes carried for pre-KEM validation.
pub const MAX_ADMISSION_TARGET_BUNDLE_BYTES: usize = kult_crypto::MAX_PREKEY_BUNDLE_BYTES;
/// Maximum anonymous-boxed first-flight bytes accepted by the wrapper codec.
pub const MAX_ADMISSION_SEALED_FLIGHT_BYTES: usize = kult_crypto::MAX_ADMISSION_FIRST_CIPHERTEXT;
/// Maximum admission wrapper body.
pub const MAX_ADMISSION_ENVELOPE_BYTES: usize = ADMISSION_ENVELOPE_HEADER_LEN
    + MAX_ADMISSION_TARGET_BUNDLE_BYTES
    + MAX_ADMISSION_SEALED_FLIGHT_BYTES;
/// Hard client-work ceiling for one puzzle solution attempt.
pub const MAX_ADMISSION_PUZZLE_ATTEMPTS: u32 = 1 << 22;

/// Admission proof carried in the fixed wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmissionProofKind {
    /// Target-specific SHA-256 leading-zero puzzle.
    Puzzle = 1,
    /// Authenticated out-of-band invitation capability.
    Invitation = 2,
}

impl TryFrom<u8> for AdmissionProofKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Puzzle),
            2 => Ok(Self::Invitation),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Canonical context bound by the admission content id and proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionContext {
    /// Stable target account identity.
    pub target_account: [u8; 32],
    /// Exact ingress physical-device identity.
    pub target_device: [u8; 32],
    /// Digest from the signed target admission descriptor.
    pub bundle_digest: [u8; 32],
    /// Descriptor validity epoch.
    pub validity_epoch: u64,
}

/// Versioned admission wrapper around one anonymous-boxed handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEnvelope {
    /// Target and descriptor binding.
    pub context: AdmissionContext,
    /// Stable id computed without the proof, avoiding a puzzle circularity.
    pub content_id: [u8; 16],
    /// Puzzle or invitation proof type.
    pub proof_kind: AdmissionProofKind,
    /// SHA-256 nonce or invitation secret.
    pub proof: [u8; 32],
    /// Exact signed prekey bundle the descriptor covers.
    pub target_bundle: Vec<u8>,
    /// Anonymous-boxed handshake flight.
    pub sealed_flight: Vec<u8>,
}

impl AdmissionEnvelope {
    /// Assemble a wrapper and derive its stable introduction content id.
    pub fn new(
        context: AdmissionContext,
        proof_kind: AdmissionProofKind,
        proof: [u8; 32],
        target_bundle: Vec<u8>,
        sealed_flight: Vec<u8>,
    ) -> Result<Self> {
        validate_lengths(&context, &target_bundle, &sealed_flight)?;
        let content_id = introduction_content_id(&context, &sealed_flight);
        Ok(Self {
            context,
            content_id,
            proof_kind,
            proof,
            target_bundle,
            sealed_flight,
        })
    }

    /// Strict fixed-header encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_lengths(&self.context, &self.target_bundle, &self.sealed_flight)?;
        if self.content_id != introduction_content_id(&self.context, &self.sealed_flight) {
            return Err(ProtocolError::Malformed);
        }
        let bundle_len =
            u32::try_from(self.target_bundle.len()).map_err(|_| ProtocolError::Malformed)?;
        let sealed_len =
            u32::try_from(self.sealed_flight.len()).map_err(|_| ProtocolError::Malformed)?;
        let mut out = Vec::with_capacity(
            ADMISSION_ENVELOPE_HEADER_LEN + self.target_bundle.len() + self.sealed_flight.len(),
        );
        out.extend_from_slice(ADMISSION_MAGIC);
        out.push(ADMISSION_ENVELOPE_VERSION);
        out.push(self.proof_kind as u8);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.context.target_account);
        out.extend_from_slice(&self.context.target_device);
        out.extend_from_slice(&self.context.bundle_digest);
        out.extend_from_slice(&self.context.validity_epoch.to_le_bytes());
        out.extend_from_slice(&self.content_id);
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&bundle_len.to_le_bytes());
        out.extend_from_slice(&sealed_len.to_le_bytes());
        out.extend_from_slice(&self.target_bundle);
        out.extend_from_slice(&self.sealed_flight);
        Ok(out)
    }

    /// Strict bounded decoding without deserializing an attacker-sized value.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let parsed = parse(bytes)?;
        let context = AdmissionContext {
            target_account: parsed.target_account,
            target_device: parsed.target_device,
            bundle_digest: parsed.bundle_digest,
            validity_epoch: parsed.validity_epoch,
        };
        let expected = introduction_content_id(&context, parsed.sealed_flight);
        if expected != parsed.content_id {
            return Err(ProtocolError::IntegrityMismatch);
        }
        Ok(Self {
            context,
            content_id: parsed.content_id,
            proof_kind: parsed.proof_kind,
            proof: parsed.proof,
            target_bundle: parsed.target_bundle.to_vec(),
            sealed_flight: parsed.sealed_flight.to_vec(),
        })
    }

    /// Identify the fixed admission wrapper without accepting it as valid.
    pub fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(ADMISSION_MAGIC)
    }

    /// Return a verified claimed id without allocating.
    pub(crate) fn verified_content_id(bytes: &[u8]) -> Option<[u8; 16]> {
        let parsed = parse(bytes).ok()?;
        let context = AdmissionContext {
            target_account: parsed.target_account,
            target_device: parsed.target_device,
            bundle_digest: parsed.bundle_digest,
            validity_epoch: parsed.validity_epoch,
        };
        (parsed.content_id == introduction_content_id(&context, parsed.sealed_flight))
            .then_some(parsed.content_id)
    }
}

struct ParsedAdmission<'a> {
    proof_kind: AdmissionProofKind,
    target_account: [u8; 32],
    target_device: [u8; 32],
    bundle_digest: [u8; 32],
    validity_epoch: u64,
    content_id: [u8; 16],
    proof: [u8; 32],
    target_bundle: &'a [u8],
    sealed_flight: &'a [u8],
}

fn parse(bytes: &[u8]) -> Result<ParsedAdmission<'_>> {
    if bytes.len() < ADMISSION_ENVELOPE_HEADER_LEN
        || bytes.len() > MAX_ADMISSION_ENVELOPE_BYTES
        || &bytes[..4] != ADMISSION_MAGIC
        || bytes[4] != ADMISSION_ENVELOPE_VERSION
        || bytes[6..8] != [0u8; 2]
    {
        return Err(ProtocolError::Malformed);
    }
    let proof_kind = AdmissionProofKind::try_from(bytes[5])?;
    let target_account = bytes[8..40].try_into().expect("fixed slice");
    let target_device = bytes[40..72].try_into().expect("fixed slice");
    let bundle_digest = bytes[72..104].try_into().expect("fixed slice");
    let validity_epoch = u64::from_le_bytes(bytes[104..112].try_into().expect("fixed slice"));
    let content_id = bytes[112..128].try_into().expect("fixed slice");
    let proof = bytes[128..160].try_into().expect("fixed slice");
    let bundle_len = usize::try_from(u32::from_le_bytes(
        bytes[160..164].try_into().expect("fixed slice"),
    ))
    .map_err(|_| ProtocolError::Malformed)?;
    let sealed_len = usize::try_from(u32::from_le_bytes(
        bytes[164..168].try_into().expect("fixed slice"),
    ))
    .map_err(|_| ProtocolError::Malformed)?;
    if bundle_len == 0
        || bundle_len > MAX_ADMISSION_TARGET_BUNDLE_BYTES
        || sealed_len == 0
        || sealed_len > MAX_ADMISSION_SEALED_FLIGHT_BYTES
        || ADMISSION_ENVELOPE_HEADER_LEN
            .checked_add(bundle_len)
            .and_then(|size| size.checked_add(sealed_len))
            != Some(bytes.len())
    {
        return Err(ProtocolError::Malformed);
    }
    let split = ADMISSION_ENVELOPE_HEADER_LEN + bundle_len;
    let parsed = ParsedAdmission {
        proof_kind,
        target_account,
        target_device,
        bundle_digest,
        validity_epoch,
        content_id,
        proof,
        target_bundle: &bytes[ADMISSION_ENVELOPE_HEADER_LEN..split],
        sealed_flight: &bytes[split..],
    };
    validate_lengths(
        &AdmissionContext {
            target_account,
            target_device,
            bundle_digest,
            validity_epoch,
        },
        parsed.target_bundle,
        parsed.sealed_flight,
    )?;
    Ok(parsed)
}

fn validate_lengths(
    context: &AdmissionContext,
    target_bundle: &[u8],
    sealed_flight: &[u8],
) -> Result<()> {
    if context.target_account == [0u8; 32]
        || context.target_device == [0u8; 32]
        || context.bundle_digest == [0u8; 32]
        || target_bundle.is_empty()
        || target_bundle.len() > MAX_ADMISSION_TARGET_BUNDLE_BYTES
        || sealed_flight.is_empty()
        || sealed_flight.len() > MAX_ADMISSION_SEALED_FLIGHT_BYTES
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

fn introduction_content_id(context: &AdmissionContext, sealed_flight: &[u8]) -> [u8; 16] {
    let sealed_digest = Sha256::digest(sealed_flight);
    let mut hash = Sha256::new();
    hash.update(CONTENT_ID_DOMAIN);
    hash.update([ADMISSION_ENVELOPE_VERSION]);
    hash.update(context.target_account);
    hash.update(context.target_device);
    hash.update(context.bundle_digest);
    hash.update(context.validity_epoch.to_le_bytes());
    hash.update(sealed_digest);
    hash.finalize()[..16].try_into().expect("16 <= 32")
}

fn puzzle_digest(context: &AdmissionContext, content_id: &[u8; 16], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PUZZLE_DOMAIN);
    hash.update(context.target_account);
    hash.update(context.target_device);
    hash.update(context.bundle_digest);
    hash.update(context.validity_epoch.to_le_bytes());
    hash.update(content_id);
    hash.update(nonce);
    hash.finalize().into()
}

fn has_leading_zero_bits(digest: &[u8; 32], difficulty: u8) -> bool {
    let full = usize::from(difficulty / 8);
    let remainder = difficulty % 8;
    digest[..full].iter().all(|byte| *byte == 0)
        && (remainder == 0 || digest[full] >> (8 - remainder) == 0)
}

/// Verify one target-specific SHA-256 puzzle in constant memory.
pub fn verify_admission_puzzle(
    context: &AdmissionContext,
    content_id: &[u8; 16],
    nonce: &[u8; 32],
    difficulty: u8,
) -> bool {
    if !(kult_crypto::MIN_ADMISSION_DIFFICULTY..=kult_crypto::MAX_ADMISSION_DIFFICULTY)
        .contains(&difficulty)
    {
        return false;
    }
    has_leading_zero_bits(&puzzle_digest(context, content_id, nonce), difficulty)
}

/// Derive the non-revealing proof for one out-of-band invitation secret.
///
/// The bearer secret never appears in the admission envelope. A passive
/// carrier observer sees only a content-id-bound HMAC that cannot authorize a
/// different first flight.
pub fn admission_invitation_proof(
    invitation: &[u8; 32],
    context: &AdmissionContext,
    content_id: &[u8; 16],
) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(invitation).expect("HMAC accepts every 32-byte key");
    mac.update(INVITATION_PROOF_DOMAIN);
    mac.update(&context.target_account);
    mac.update(&context.target_device);
    mac.update(&context.bundle_digest);
    mac.update(&context.validity_epoch.to_le_bytes());
    mac.update(content_id);
    mac.finalize().into_bytes().into()
}

/// Solve one bounded target-specific puzzle.
///
/// The initial nonce is random and then incremented as a little-endian
/// counter. Callers choose a ceiling no larger than
/// [`MAX_ADMISSION_PUZZLE_ATTEMPTS`] so hostile policy cannot create
/// unbounded client work.
pub fn solve_admission_puzzle(
    context: &AdmissionContext,
    content_id: &[u8; 16],
    difficulty: u8,
    max_attempts: u32,
    rng: &mut impl CryptoRngCore,
) -> Result<[u8; 32]> {
    if !(kult_crypto::MIN_ADMISSION_DIFFICULTY..=kult_crypto::MAX_ADMISSION_DIFFICULTY)
        .contains(&difficulty)
        || max_attempts == 0
        || max_attempts > MAX_ADMISSION_PUZZLE_ATTEMPTS
    {
        return Err(ProtocolError::Malformed);
    }
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    for _ in 0..max_attempts {
        if verify_admission_puzzle(context, content_id, &nonce, difficulty) {
            return Ok(nonce);
        }
        for byte in &mut nonce {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }
    Err(ProtocolError::AdmissionWorkExhausted)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn context() -> AdmissionContext {
        AdmissionContext {
            target_account: [1; 32],
            target_device: [2; 32],
            bundle_digest: [3; 32],
            validity_epoch: 500_000,
        }
    }

    #[test]
    fn fixed_wrapper_round_trips_and_content_id_ignores_proof() {
        let mut rng = StdRng::seed_from_u64(0x0030_1001);
        let first = AdmissionEnvelope::new(
            context(),
            AdmissionProofKind::Puzzle,
            [0; 32],
            vec![4; 256],
            vec![5; 512],
        )
        .unwrap();
        let nonce = solve_admission_puzzle(
            &first.context,
            &first.content_id,
            kult_crypto::MIN_ADMISSION_DIFFICULTY,
            MAX_ADMISSION_PUZZLE_ATTEMPTS,
            &mut rng,
        )
        .unwrap();
        let with_proof = AdmissionEnvelope {
            proof: nonce,
            ..first
        };
        let encoded = with_proof.encode().unwrap();
        assert_eq!(AdmissionEnvelope::decode(&encoded).unwrap(), with_proof);
        assert_eq!(
            AdmissionEnvelope::verified_content_id(&encoded),
            Some(with_proof.content_id)
        );
    }

    #[test]
    fn puzzle_is_bound_to_target_bundle_epoch_and_content() {
        let mut rng = StdRng::seed_from_u64(0x0030_1002);
        let envelope = AdmissionEnvelope::new(
            context(),
            AdmissionProofKind::Puzzle,
            [0; 32],
            vec![4; 64],
            vec![5; 64],
        )
        .unwrap();
        let difficulty = kult_crypto::MIN_ADMISSION_DIFFICULTY;
        let nonce = solve_admission_puzzle(
            &envelope.context,
            &envelope.content_id,
            difficulty,
            MAX_ADMISSION_PUZZLE_ATTEMPTS,
            &mut rng,
        )
        .unwrap();
        assert!(verify_admission_puzzle(
            &envelope.context,
            &envelope.content_id,
            &nonce,
            difficulty
        ));
        let mut wrong = envelope.context;
        wrong.target_device[0] ^= 1;
        assert!(!verify_admission_puzzle(
            &wrong,
            &envelope.content_id,
            &nonce,
            difficulty
        ));
    }

    #[test]
    fn malformed_lengths_and_content_id_fail_before_allocation() {
        let envelope = AdmissionEnvelope::new(
            context(),
            AdmissionProofKind::Invitation,
            [9; 32],
            vec![4; 64],
            vec![5; 64],
        )
        .unwrap();
        let mut encoded = envelope.encode().unwrap();
        encoded[112] ^= 1;
        assert_eq!(
            AdmissionEnvelope::decode(&encoded),
            Err(ProtocolError::IntegrityMismatch)
        );
        encoded.truncate(ADMISSION_ENVELOPE_HEADER_LEN);
        assert_eq!(
            AdmissionEnvelope::decode(&encoded),
            Err(ProtocolError::Malformed)
        );
    }
}
