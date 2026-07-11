//! Prekeys and the self-authenticating prekey bundle.
//! Spec: docs/04-cryptography.md §2-3, docs/06-identity-trust.md §2.

use alloc::vec::Vec;

use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{identity::Identity, identity::IdentityPublic, util, CryptoError, Result};

/// Signing domain for X25519 signed prekeys.
const SPK_DOMAIN: &[u8] = b"KommsKult-spk-v1";
/// Signing domain for ML-KEM-768 signed prekeys.
const PQSPK_DOMAIN: &[u8] = b"KommsKult-pqspk-v1";

/// ML-KEM-768 encapsulation-key size in bytes.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
pub const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 decapsulation-key size in bytes.
pub const MLKEM768_DK_LEN: usize = 2400;

/// Medium-term X25519 signed prekey (secret half). Rotated ~weekly by the node.
pub struct SignedPrekeySecret {
    /// Caller-assigned identifier, referenced by handshake messages.
    pub id: u32,
    pub(crate) secret: StaticSecret,
}

impl SignedPrekeySecret {
    /// Generate a signed prekey with the given id.
    pub fn generate(rng: &mut impl CryptoRngCore, id: u32) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self {
            id,
            secret: StaticSecret::from(b),
        }
    }

    /// Public half.
    pub fn public(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    pub(crate) fn dh(&self, their: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            *self
                .secret
                .diffie_hellman(&PublicKey::from(*their))
                .as_bytes(),
        )
    }

    /// Serialize the secret (callers must seal before storing).
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Reconstruct from [`SignedPrekeySecret::to_bytes`].
    pub fn from_bytes(id: u32, bytes: &[u8; 32]) -> Self {
        Self {
            id,
            secret: StaticSecret::from(*bytes),
        }
    }
}

/// Single-use X25519 one-time prekey (secret half).
pub struct OneTimePrekeySecret {
    /// Caller-assigned identifier.
    pub id: u32,
    pub(crate) secret: StaticSecret,
}

impl OneTimePrekeySecret {
    /// Generate a one-time prekey with the given id.
    pub fn generate(rng: &mut impl CryptoRngCore, id: u32) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self {
            id,
            secret: StaticSecret::from(b),
        }
    }

    /// Public half.
    pub fn public(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    pub(crate) fn dh(&self, their: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            *self
                .secret
                .diffie_hellman(&PublicKey::from(*their))
                .as_bytes(),
        )
    }

    /// Serialize the secret (callers must seal before storing).
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Reconstruct from [`OneTimePrekeySecret::to_bytes`].
    pub fn from_bytes(id: u32, bytes: &[u8; 32]) -> Self {
        Self {
            id,
            secret: StaticSecret::from(*bytes),
        }
    }
}

/// Medium-term ML-KEM-768 signed prekey (secret half). Rotated ~weekly.
pub struct PqPrekeySecret {
    /// Caller-assigned identifier.
    pub id: u32,
    dk: Zeroizing<Vec<u8>>,
    ek: Vec<u8>,
}

impl PqPrekeySecret {
    /// Generate an ML-KEM-768 prekey with the given id.
    pub fn generate(rng: &mut impl CryptoRngCore, id: u32) -> Self {
        let (dk, ek) = MlKem768::generate(rng);
        Self {
            id,
            dk: Zeroizing::new(dk.as_bytes().to_vec()),
            ek: ek.as_bytes().to_vec(),
        }
    }

    /// Public (encapsulation) half, [`MLKEM768_EK_LEN`] bytes.
    pub fn public(&self) -> &[u8] {
        &self.ek
    }

    /// Decapsulate a ciphertext to the 32-byte shared secret.
    pub(crate) fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let dk_arr = self.dk[..]
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
        let ct_arr = ct.try_into().map_err(|_| CryptoError::InvalidMessage)?;
        let ss = dk
            .decapsulate(&ct_arr)
            .map_err(|_| CryptoError::InvalidMessage)?;
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&ss);
        Ok(out)
    }

    /// Serialize the secret (callers must seal before storing).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.dk.clone()
    }

    /// Reconstruct from [`PqPrekeySecret::to_bytes`] plus the public half.
    pub fn from_bytes(id: u32, dk: &[u8], ek: &[u8]) -> Result<Self> {
        if dk.len() != MLKEM768_DK_LEN || ek.len() != MLKEM768_EK_LEN {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            id,
            dk: Zeroizing::new(dk.to_vec()),
            ek: ek.to_vec(),
        })
    }
}

/// A self-authenticating prekey bundle, distributable over any channel
/// (DHT record, QR code, mesh broadcast) — every element traces to the
/// identity key by signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// The owner's public identity.
    pub identity: IdentityPublic,
    /// Signed prekey id.
    pub spk_id: u32,
    /// Signed prekey public key.
    pub spk: [u8; 32],
    /// `Sign(IK, spk-domain || spk_id || spk)`.
    #[serde(with = "util::bytes64")]
    pub spk_sig: [u8; 64],
    /// PQ signed prekey id.
    pub pqspk_id: u32,
    /// ML-KEM-768 encapsulation key ([`MLKEM768_EK_LEN`] bytes).
    pub pqspk: Vec<u8>,
    /// `Sign(IK, pqspk-domain || pqspk_id || pqspk)`.
    #[serde(with = "util::bytes64")]
    pub pqspk_sig: [u8; 64],
    /// Optional one-time prekey `(id, public)`.
    pub opk: Option<(u32, [u8; 32])>,
    /// Unix seconds after which the bundle must be rejected.
    pub expires_at: u64,
    /// Opaque relay hints for higher layers (mailbox addresses); not
    /// interpreted by this crate.
    pub relay_hints: Vec<Vec<u8>>,
}

impl PrekeyBundle {
    /// Assemble and sign a bundle from the owner's secrets.
    pub fn build(
        identity: &Identity,
        spk: &SignedPrekeySecret,
        pqspk: &PqPrekeySecret,
        opk: Option<&OneTimePrekeySecret>,
        expires_at: u64,
        relay_hints: Vec<Vec<u8>>,
    ) -> Self {
        let spk_pub = spk.public();
        let mut spk_msg = Vec::with_capacity(4 + 32);
        spk_msg.extend_from_slice(&spk.id.to_le_bytes());
        spk_msg.extend_from_slice(&spk_pub);

        let mut pq_msg = Vec::with_capacity(4 + MLKEM768_EK_LEN);
        pq_msg.extend_from_slice(&pqspk.id.to_le_bytes());
        pq_msg.extend_from_slice(pqspk.public());

        Self {
            identity: identity.public(),
            spk_id: spk.id,
            spk: spk_pub,
            spk_sig: identity.sign_domain(SPK_DOMAIN, &spk_msg),
            pqspk_id: pqspk.id,
            pqspk: pqspk.public().to_vec(),
            pqspk_sig: identity.sign_domain(PQSPK_DOMAIN, &pq_msg),
            opk: opk.map(|k| (k.id, k.public())),
            expires_at,
            relay_hints,
        }
    }

    /// Verify all signatures and structural invariants.
    ///
    /// `now` is Unix seconds; pass `0` to skip the expiry check (e.g. when
    /// re-verifying an archived bundle).
    pub fn verify(&self, now: u64) -> Result<VerifiedBundle> {
        if self.pqspk.len() != MLKEM768_EK_LEN {
            return Err(CryptoError::InvalidBundle);
        }
        if now != 0 && now > self.expires_at {
            return Err(CryptoError::InvalidBundle);
        }
        self.identity.verify()?;

        let mut spk_msg = Vec::with_capacity(4 + 32);
        spk_msg.extend_from_slice(&self.spk_id.to_le_bytes());
        spk_msg.extend_from_slice(&self.spk);
        self.identity
            .verify_domain(SPK_DOMAIN, &spk_msg, &self.spk_sig)?;

        let mut pq_msg = Vec::with_capacity(4 + MLKEM768_EK_LEN);
        pq_msg.extend_from_slice(&self.pqspk_id.to_le_bytes());
        pq_msg.extend_from_slice(&self.pqspk);
        self.identity
            .verify_domain(PQSPK_DOMAIN, &pq_msg, &self.pqspk_sig)?;

        Ok(VerifiedBundle(self.clone()))
    }

    /// Postcard-encode for transport/storage.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("bundle serialization cannot fail")
    }

    /// Decode a postcard-encoded bundle. The result is **unverified**.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| CryptoError::Serialization)
    }
}

/// Proof-of-verification newtype: the only bundle type [`crate::initiate`]
/// accepts, so an unverified bundle cannot reach the handshake by
/// construction.
pub struct VerifiedBundle(pub(crate) PrekeyBundle);

impl VerifiedBundle {
    /// Access the verified bundle contents.
    pub fn bundle(&self) -> &PrekeyBundle {
        &self.0
    }
}
