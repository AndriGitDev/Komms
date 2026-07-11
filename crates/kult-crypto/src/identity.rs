//! Identity keys: separate Ed25519 (signing) and X25519 (agreement) keypairs,
//! cross-signed at creation. Spec: docs/04-cryptography.md §2,
//! docs/06-identity-trust.md §1.

use alloc::string::String;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{util, CryptoError, Result};

/// Domain separator for the cross-signature binding the X25519 key to the
/// Ed25519 identity.
const CROSS_SIGN_DOMAIN: &[u8] = b"KommsKult-cross-sign-v1";

/// A user's full identity: long-term signing and agreement secrets.
///
/// Generated on-device; never leaves the device except inside an encrypted
/// backup produced by higher layers from [`Identity::to_bytes`].
pub struct Identity {
    signing: SigningKey,
    agreement: StaticSecret,
}

impl Identity {
    /// Generate a fresh identity from the supplied CSPRNG.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let signing = SigningKey::generate(rng);
        let mut x = [0u8; 32];
        rng.fill_bytes(&mut x);
        let agreement = StaticSecret::from(x);
        Self { signing, agreement }
    }

    /// The public half, shareable with anyone.
    pub fn public(&self) -> IdentityPublic {
        let x_pub = PublicKey::from(&self.agreement);
        let mut msg = [0u8; CROSS_SIGN_DOMAIN.len() + 32];
        msg[..CROSS_SIGN_DOMAIN.len()].copy_from_slice(CROSS_SIGN_DOMAIN);
        msg[CROSS_SIGN_DOMAIN.len()..].copy_from_slice(x_pub.as_bytes());
        let cross_sig = self.signing.sign(&msg);
        IdentityPublic {
            ed: self.signing.verifying_key().to_bytes(),
            x: *x_pub.as_bytes(),
            cross_sig: cross_sig.to_bytes(),
        }
    }

    /// Sign `msg` under the given domain separator (prekeys, transitions).
    pub(crate) fn sign_domain(&self, domain: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut buf = alloc::vec::Vec::with_capacity(domain.len() + msg.len());
        buf.extend_from_slice(domain);
        buf.extend_from_slice(msg);
        self.signing.sign(&buf).to_bytes()
    }

    /// X25519 agreement with a peer public key.
    pub(crate) fn dh(&self, their: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let shared = self.agreement.diffie_hellman(&PublicKey::from(*their));
        Zeroizing::new(*shared.as_bytes())
    }

    /// Serialize the secret material (64 bytes). Callers **must** seal the
    /// result before it touches storage — see `kult-store` and spec §8.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.agreement.to_bytes());
        out
    }

    /// Reconstruct from [`Identity::to_bytes`] output.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&bytes[..32]);
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[32..]);
        let id = Self {
            signing: SigningKey::from_bytes(&ed),
            agreement: StaticSecret::from(x),
        };
        Zeroizing::new(ed);
        Zeroizing::new(x);
        id
    }
}

/// The public identity: Ed25519 key, X25519 key, and the cross-signature
/// proving both are held by the same party.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    /// Ed25519 verifying key bytes — *the* identity for fingerprint and
    /// address purposes.
    pub ed: [u8; 32],
    /// X25519 agreement public key.
    pub x: [u8; 32],
    /// `Sign(ed, domain || x)`.
    #[serde(with = "util::bytes64")]
    pub cross_sig: [u8; 64],
}

impl IdentityPublic {
    /// Verify internal consistency (cross-signature). Must be called before
    /// trusting the X25519 key as belonging to `ed`.
    pub fn verify(&self) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.ed).map_err(|_| CryptoError::InvalidKey)?;
        let mut msg = [0u8; CROSS_SIGN_DOMAIN.len() + 32];
        msg[..CROSS_SIGN_DOMAIN.len()].copy_from_slice(CROSS_SIGN_DOMAIN);
        msg[CROSS_SIGN_DOMAIN.len()..].copy_from_slice(&self.x);
        let sig = Signature::from_bytes(&self.cross_sig);
        vk.verify(&msg, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Verify a domain-separated signature made by this identity.
    pub(crate) fn verify_domain(&self, domain: &[u8], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.ed).map_err(|_| CryptoError::InvalidKey)?;
        let mut buf = alloc::vec::Vec::with_capacity(domain.len() + msg.len());
        buf.extend_from_slice(domain);
        buf.extend_from_slice(msg);
        vk.verify(&buf, &Signature::from_bytes(sig))
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// The kult address: `kk1` + base32(multihash(identity key material)).
    ///
    /// Multihash prefix `0x12 0x20` = SHA2-256, 32 bytes; digest is over
    /// `ed || x` so the address commits to both public keys.
    pub fn address(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.ed);
        h.update(self.x);
        let digest = h.finalize();
        let mut mh = [0u8; 34];
        mh[0] = 0x12;
        mh[1] = 0x20;
        mh[2..].copy_from_slice(&digest);
        let mut out = String::from("kk1");
        out.push_str(&util::base32_lower_nopad(&mh));
        out
    }
}

impl core::fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityPublic")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}
