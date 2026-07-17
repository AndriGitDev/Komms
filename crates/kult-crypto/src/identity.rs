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
const CROSS_SIGN_DOMAIN: &[u8] = b"Komms-cross-sign-v1";
const GROUP_AUTHORITY_STATE_DOMAIN: &[u8] = b"Komms-group-authority-state-v1";
const GROUP_OWNER_TRANSFER_DOMAIN: &[u8] = b"Komms-group-owner-transfer-v1";
const GROUP_ADMIN_REQUEST_DOMAIN: &[u8] = b"Komms-group-admin-request-v1";
const GROUP_POLL_MODERATION_DOMAIN: &[u8] = b"Komms-group-poll-moderation-v1";
const DEVICE_CERTIFICATE_DOMAIN: &[u8] = b"Komms-device-certificate-v1";
const DEVICE_MANIFEST_DOMAIN: &[u8] = b"Komms-device-manifest-v1";
const DEVICE_LINK_OFFER_DOMAIN: &[u8] = b"Komms-device-link-offer-v1";
const DEVICE_LINK_RESPONSE_DOMAIN: &[u8] = b"Komms-device-link-response-v1";
const DEVICE_SYNC_EVENT_DOMAIN: &[u8] = b"Komms-device-sync-event-v1";

fn verify_peer_domain(
    peer: &[u8; 32],
    domain: &[u8],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(peer).map_err(|_| CryptoError::InvalidKey)?;
    let mut signed = alloc::vec::Vec::with_capacity(domain.len() + message.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(message);
    key.verify(&signed, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Verify a C6 authority-state signature from an exact peer id.
pub fn verify_group_authority_state_signature(
    peer: &[u8; 32],
    canonical_state: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    verify_peer_domain(
        peer,
        GROUP_AUTHORITY_STATE_DOMAIN,
        canonical_state,
        signature,
    )
}

/// Verify a C6 ownership-transfer signature from an exact peer id.
pub fn verify_group_owner_transfer_signature(
    peer: &[u8; 32],
    canonical_transfer: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    verify_peer_domain(
        peer,
        GROUP_OWNER_TRANSFER_DOMAIN,
        canonical_transfer,
        signature,
    )
}

/// Verify a C6 admin-request signature from an exact peer id.
pub fn verify_group_admin_request_signature(
    peer: &[u8; 32],
    canonical_request: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    verify_peer_domain(
        peer,
        GROUP_ADMIN_REQUEST_DOMAIN,
        canonical_request,
        signature,
    )
}

/// Verify a C6 poll-moderation signature from an exact owner id.
pub fn verify_group_poll_moderation_signature(
    peer: &[u8; 32],
    canonical_moderation: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    verify_peer_domain(
        peer,
        GROUP_POLL_MODERATION_DOMAIN,
        canonical_moderation,
        signature,
    )
}

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

    /// Sign one canonical C6 group-authority state.
    ///
    /// The fixed domain prevents a valid authority signature from being
    /// replayed as a prekey, owner transfer, or administrative request.
    pub fn sign_group_authority_state(&self, canonical_state: &[u8]) -> [u8; 64] {
        self.sign_domain(GROUP_AUTHORITY_STATE_DOMAIN, canonical_state)
    }

    /// Sign one canonical C6 ownership-transfer certificate.
    pub fn sign_group_owner_transfer(&self, canonical_transfer: &[u8]) -> [u8; 64] {
        self.sign_domain(GROUP_OWNER_TRANSFER_DOMAIN, canonical_transfer)
    }

    /// Sign one canonical C6 generation-bound administrative request.
    pub fn sign_group_admin_request(&self, canonical_request: &[u8]) -> [u8; 64] {
        self.sign_domain(GROUP_ADMIN_REQUEST_DOMAIN, canonical_request)
    }

    /// Sign one exact generation-bound C6 poll moderation snapshot.
    pub fn sign_group_poll_moderation(&self, canonical_moderation: &[u8]) -> [u8; 64] {
        self.sign_domain(GROUP_POLL_MODERATION_DOMAIN, canonical_moderation)
    }

    /// Sign one canonical C2 device certificate as the stable account root.
    pub fn sign_device_certificate(&self, canonical_certificate: &[u8]) -> [u8; 64] {
        self.sign_domain(DEVICE_CERTIFICATE_DOMAIN, canonical_certificate)
    }

    /// Sign one complete, generation-bound C2 device manifest.
    pub fn sign_device_manifest(&self, canonical_manifest: &[u8]) -> [u8; 64] {
        self.sign_domain(DEVICE_MANIFEST_DOMAIN, canonical_manifest)
    }

    /// Sign the authorizing half of one proximate C2 linking ceremony.
    pub fn sign_device_link_offer(&self, canonical_offer: &[u8]) -> [u8; 64] {
        self.sign_domain(DEVICE_LINK_OFFER_DOMAIN, canonical_offer)
    }

    /// Sign the target half of one proximate C2 linking ceremony.
    pub fn sign_device_link_response(&self, canonical_response: &[u8]) -> [u8; 64] {
        self.sign_domain(DEVICE_LINK_RESPONSE_DOMAIN, canonical_response)
    }

    /// Sign one deterministic C2 state-synchronization mutation.
    pub fn sign_device_sync_event(&self, canonical_event: &[u8]) -> [u8; 64] {
        self.sign_domain(DEVICE_SYNC_EVENT_DOMAIN, canonical_event)
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

    /// Verify a canonical C6 group-authority state signature.
    pub fn verify_group_authority_state(
        &self,
        canonical_state: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(GROUP_AUTHORITY_STATE_DOMAIN, canonical_state, signature)
    }

    /// Verify a canonical C6 ownership-transfer certificate signature.
    pub fn verify_group_owner_transfer(
        &self,
        canonical_transfer: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(GROUP_OWNER_TRANSFER_DOMAIN, canonical_transfer, signature)
    }

    /// Verify a canonical C6 generation-bound administrative request.
    pub fn verify_group_admin_request(
        &self,
        canonical_request: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(GROUP_ADMIN_REQUEST_DOMAIN, canonical_request, signature)
    }

    /// Verify a generation-bound C6 poll moderation snapshot.
    pub fn verify_group_poll_moderation(
        &self,
        canonical_moderation: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(
            GROUP_POLL_MODERATION_DOMAIN,
            canonical_moderation,
            signature,
        )
    }

    /// Verify one canonical C2 device certificate from this account root.
    pub fn verify_device_certificate(
        &self,
        canonical_certificate: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(DEVICE_CERTIFICATE_DOMAIN, canonical_certificate, signature)
    }

    /// Verify one complete, generation-bound C2 device manifest.
    pub fn verify_device_manifest(
        &self,
        canonical_manifest: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(DEVICE_MANIFEST_DOMAIN, canonical_manifest, signature)
    }

    /// Verify the authorizing half of one proximate C2 linking ceremony.
    pub fn verify_device_link_offer(
        &self,
        canonical_offer: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(DEVICE_LINK_OFFER_DOMAIN, canonical_offer, signature)
    }

    /// Verify the target half of one proximate C2 linking ceremony.
    pub fn verify_device_link_response(
        &self,
        canonical_response: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(DEVICE_LINK_RESPONSE_DOMAIN, canonical_response, signature)
    }

    /// Verify one deterministic C2 state-synchronization mutation.
    pub fn verify_device_sync_event(
        &self,
        canonical_event: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify_domain(DEVICE_SYNC_EVENT_DOMAIN, canonical_event, signature)
    }

    /// The 32-byte SHA-256 digest over `ed || x` that the kult address
    /// encodes — also the DHT record key this identity's prekey bundles are
    /// published under (docs/05-transports.md §2, docs/06-identity-trust.md §2).
    pub fn address_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.ed);
        h.update(self.x);
        h.finalize().into()
    }

    /// The kult address: `kk1` + base32(multihash(identity key material)).
    ///
    /// Multihash prefix `0x12 0x20` = SHA2-256, 32 bytes; digest is over
    /// `ed || x` so the address commits to both public keys.
    pub fn address(&self) -> String {
        let mut mh = [0u8; 34];
        mh[0] = 0x12;
        mh[1] = 0x20;
        mh[2..].copy_from_slice(&self.address_digest());
        let mut out = String::from("kk1");
        out.push_str(&util::base32_lower_nopad(&mh));
        out
    }
}

/// Parse a kult address back into the 32-byte digest it encodes.
///
/// Accepts exactly what [`IdentityPublic::address`] produces: the `kk1`
/// prefix, lowercase unpadded base32, multihash `0x12 0x20` (SHA2-256,
/// 32 bytes). Anything else — wrong prefix, bad characters, non-canonical
/// trailing bits, wrong length or hash code — is [`CryptoError::InvalidAddress`].
pub fn parse_address(address: &str) -> Result<[u8; 32]> {
    let encoded = address
        .strip_prefix("kk1")
        .ok_or(CryptoError::InvalidAddress)?;
    let mh = util::base32_lower_nopad_decode(encoded).ok_or(CryptoError::InvalidAddress)?;
    if mh.len() != 34 || mh[0] != 0x12 || mh[1] != 0x20 {
        return Err(CryptoError::InvalidAddress);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&mh[2..]);
    Ok(digest)
}

impl core::fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityPublic")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn group_authority_signatures_are_identity_bound_and_domain_separated() {
        let identity = Identity::generate(&mut OsRng);
        let public = identity.public();
        let state = b"canonical authority state";
        let signature = identity.sign_group_authority_state(state);
        public
            .verify_group_authority_state(state, &signature)
            .unwrap();
        assert!(public
            .verify_group_authority_state(b"different state", &signature)
            .is_err());
        assert!(public
            .verify_group_owner_transfer(state, &signature)
            .is_err());
        assert!(public
            .verify_group_admin_request(state, &signature)
            .is_err());
        assert!(public
            .verify_group_poll_moderation(state, &signature)
            .is_err());
    }
}
