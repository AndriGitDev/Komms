//! Root-free proximate device linking for ADR-0026 authority chains.

use alloc::{string::String, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    util, CryptoError, DeviceAuthorityCertificate, DeviceAuthorityManifest,
    DeviceAuthorityRelation, DeviceAuthoritySignature, DeviceAuthorityTransition, Identity,
    PrekeyBundle, Result, StorageKey, MAX_AUTHORITY_DEVICE_NAME_BYTES,
};

/// Maximum selected synchronized-state bytes admitted by one link.
pub const MAX_AUTHORITY_LINK_TRANSFER_BYTES: usize = 16 * 1024 * 1024;

const OFFER_MAGIC: &[u8; 4] = b"KLO2";
const RESPONSE_MAGIC: &[u8; 4] = b"KLR2";
const APPROVAL_REQUEST_MAGIC: &[u8; 4] = b"KLA2";
const APPROVAL_MAGIC: &[u8; 4] = b"KLS2";
const PREKEY_MAGIC: &[u8; 4] = b"KDP2";
const PAIRING_MAGIC: &[u8; 4] = b"KPB2";
const OFFER_DOMAIN: &[u8] = b"Komms-device-link-offer-v2";
const RESPONSE_DOMAIN: &[u8] = b"Komms-device-link-response-v2";
const PAIRING_DOMAIN: &[u8] = b"Komms-connect-pairing-bundle-v2";
const LINK_INFO: &[u8] = b"Komms-device-link-key-v2";
const LINK_PACKAGE_AD: &[u8] = b"Komms-device-link-package-v2";

/// Recipient-verifiable binding from a stable account to one device prekey.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorityDevicePrekeyBundle {
    /// Exact active candidate-owned device certificate.
    pub certificate: DeviceAuthorityCertificate,
    /// Complete quorum-authorized account proof.
    pub manifest: DeviceAuthorityManifest,
    /// Ordinary self-authenticating PQXDH bundle signed by the device key.
    pub prekey: PrekeyBundle,
}

impl AuthorityDevicePrekeyBundle {
    /// Construct after independently building the device-signed prekey bundle.
    pub fn new(
        certificate: DeviceAuthorityCertificate,
        manifest: DeviceAuthorityManifest,
        prekey: PrekeyBundle,
    ) -> Result<Self> {
        let bundle = Self {
            certificate,
            manifest,
            prekey,
        };
        bundle.verify(0)?;
        Ok(bundle)
    }

    /// Strict versioned encoding for QR and discovery exchange.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify(0)?;
        encode_prefixed(PREKEY_MAGIC, self)
    }

    /// Whether bytes identify this version-two wrapper.
    pub fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(PREKEY_MAGIC)
    }

    /// Strictly decode without accepting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_prefixed(PREKEY_MAGIC, bytes)
    }

    /// Verify authority, active certificate, and device-signed prekeys.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.manifest.verify()?;
        self.certificate.verify()?;
        self.prekey.verify(now)?;
        if self.certificate.account != *self.manifest.account()
            || self.certificate.device != self.prekey.identity
            || self
                .manifest
                .active_certificate(&self.certificate.device_id())
                != Some(&self.certificate)
        {
            return Err(CryptoError::InvalidBundle);
        }
        Ok(())
    }
}

/// Device-signed out-of-band pairing artifact carrying offline introduction
/// authority alongside one current prekey bundle.
///
/// Public DHT records keep the discovery capability outside their ingress
/// prekey bundle. QR, link, paste, and file exchange instead use this wrapper
/// so a recipient-selected mailbox can accept the very first flight while the
/// recipient is offline.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorityPairingBundle {
    /// Exact authority-bound device prekey bundle.
    pub device_bundle: AuthorityDevicePrekeyBundle,
    /// Rotatable Connect discovery capability.
    pub discovery_capability: [u8; 32],
    /// Monotonic capability generation.
    pub discovery_generation: u64,
    /// Active device signature over the complete canonical wrapper.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl AuthorityPairingBundle {
    /// Bind one current Connect capability to an active device prekey.
    pub fn new(
        device_bundle: AuthorityDevicePrekeyBundle,
        discovery_capability: [u8; 32],
        discovery_generation: u64,
        signer: &Identity,
    ) -> Result<Self> {
        let mut bundle = Self {
            device_bundle,
            discovery_capability,
            discovery_generation,
            signature: [0u8; 64],
        };
        if bundle.device_bundle.certificate.device != signer.public() {
            return Err(CryptoError::InvalidBundle);
        }
        bundle.validate_unsigned(0)?;
        bundle.signature = signer.sign_domain(PAIRING_DOMAIN, &bundle.canonical()?);
        Ok(bundle)
    }

    /// Strict versioned encoding for QR, link, paste, and file exchange.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify(0)?;
        encode_prefixed(PAIRING_MAGIC, self)
    }

    /// Whether bytes identify the capability-bearing pairing wrapper.
    pub fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(PAIRING_MAGIC)
    }

    /// Strictly decode without accepting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_prefixed(PAIRING_MAGIC, bytes)
    }

    /// Verify authority, prekey lifetime, capability shape, generation, and
    /// the active physical-device signature over their exact combination.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.validate_unsigned(now)?;
        self.device_bundle.certificate.device.verify_domain(
            PAIRING_DOMAIN,
            &self.canonical()?,
            &self.signature,
        )
    }

    fn validate_unsigned(&self, now: u64) -> Result<()> {
        self.device_bundle.verify(now)?;
        if self.discovery_capability == [0u8; 32] || self.discovery_generation == 0 {
            return Err(CryptoError::InvalidBundle);
        }
        Ok(())
    }

    fn canonical(&self) -> Result<Vec<u8>> {
        let encoded = self.device_bundle.encode()?;
        let mut out = Vec::with_capacity(4 + encoded.len() + 32 + 8);
        out.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(|_| CryptoError::Serialization)?
                .to_le_bytes(),
        );
        out.extend_from_slice(&encoded);
        out.extend_from_slice(&self.discovery_capability);
        out.extend_from_slice(&self.discovery_generation.to_le_bytes());
        Ok(out)
    }
}

/// Device-signed QR offer from one active physical installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeviceLinkOffer {
    /// Random ceremony id.
    pub link_id: [u8; 16],
    /// Absolute local expiry.
    pub expires_at: u64,
    /// Exact accepted authority proof.
    pub manifest: DeviceAuthorityManifest,
    /// Active device that signed the offer.
    pub authorizer: [u8; 32],
    /// Source one-use X25519 public key.
    pub ephemeral: [u8; 32],
    /// Authorizer-device signature over the complete offer.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl AuthorityDeviceLinkOffer {
    /// Strict versioned QR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.manifest.verify()?;
        encode_prefixed(OFFER_MAGIC, self)
    }

    /// Strictly decode and verify one offer at `now`.
    pub fn decode_and_verify(bytes: &[u8], now: u64) -> Result<Self> {
        let offer: Self = decode_prefixed(OFFER_MAGIC, bytes)?;
        offer.verify(now)?;
        Ok(offer)
    }

    /// Verify expiry, authority, active signer, and signature.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.manifest.verify()?;
        if self.link_id == [0u8; 16] || self.ephemeral == [0u8; 32] || now > self.expires_at {
            return Err(CryptoError::InvalidMessage);
        }
        let certificate = self
            .manifest
            .active_certificate(&self.authorizer)
            .ok_or(CryptoError::InvalidSignature)?;
        certificate
            .device
            .verify_domain(OFFER_DOMAIN, &self.canonical(), &self.signature)
    }

    fn canonical(&self) -> Vec<u8> {
        let manifest = self
            .manifest
            .encode()
            .expect("verified authority manifests always encode");
        let mut out = Vec::with_capacity(16 + 8 + 4 + manifest.len() + 32 + 32);
        out.extend_from_slice(&self.link_id);
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        out.extend_from_slice(&manifest);
        out.extend_from_slice(&self.authorizer);
        out.extend_from_slice(&self.ephemeral);
        out
    }
}

/// Candidate-owned response scanned back by an authorizing device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeviceLinkResponse {
    /// Exact offer id being answered.
    pub link_id: [u8; 16],
    /// Fresh candidate-owned immutable certificate.
    pub certificate: DeviceAuthorityCertificate,
    /// Exact proposed UTF-8 device name.
    pub name: String,
    /// Target one-use X25519 public key.
    pub ephemeral: [u8; 32],
    /// Candidate-device signature binding offer and response.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl AuthorityDeviceLinkResponse {
    /// Strict versioned QR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_prefixed(RESPONSE_MAGIC, self)
    }

    /// Strictly decode a response; verification requires its matching offer.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_prefixed(RESPONSE_MAGIC, bytes)
    }

    fn verify_for(&self, offer: &AuthorityDeviceLinkOffer) -> Result<()> {
        self.certificate.verify()?;
        if self.link_id != offer.link_id
            || self.certificate.account != *offer.manifest.account()
            || self.ephemeral == [0u8; 32]
            || self.name.is_empty()
            || self.name.len() > MAX_AUTHORITY_DEVICE_NAME_BYTES
            || offer
                .manifest
                .devices()
                .iter()
                .any(|entry| entry.certificate.device_id() == self.certificate.device_id())
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.certificate.device.verify_domain(
            RESPONSE_DOMAIN,
            &self.canonical(offer),
            &self.signature,
        )
    }

    fn canonical(&self, offer: &AuthorityDeviceLinkOffer) -> Vec<u8> {
        let offer_hash: [u8; 32] = Sha256::digest(offer.canonical()).into();
        let certificate = postcard::to_allocvec(&self.certificate)
            .expect("verified device certificates always serialize");
        let mut out =
            Vec::with_capacity(16 + 32 + 4 + certificate.len() + 4 + self.name.len() + 32);
        out.extend_from_slice(&self.link_id);
        out.extend_from_slice(&offer_hash);
        out.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
        out.extend_from_slice(&certificate);
        out.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out
    }
}

/// Six-digit human comparison code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityDeviceLinkCode(u32);

impl AuthorityDeviceLinkCode {
    /// Zero-padded localized presentation form.
    pub fn digits(self) -> String {
        alloc::format!("{:06}", self.0)
    }
}

/// Source-only one-use QR ceremony state.
pub struct PendingAuthorityDeviceLinkSource {
    offer: AuthorityDeviceLinkOffer,
    ephemeral: StaticSecret,
}

impl PendingAuthorityDeviceLinkSource {
    /// Start a short-lived offer signed by the local active device.
    pub fn begin(
        device: &Identity,
        manifest: &DeviceAuthorityManifest,
        expires_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, AuthorityDeviceLinkOffer)> {
        manifest.verify()?;
        let authorizer = device.public().ed;
        if manifest.active_certificate(&authorizer).is_none() {
            return Err(CryptoError::InvalidKey);
        }
        let mut link_id = [0u8; 16];
        let mut ephemeral_bytes = [0u8; 32];
        fill_nonzero(&mut link_id, rng);
        fill_nonzero(&mut ephemeral_bytes, rng);
        let ephemeral = StaticSecret::from(ephemeral_bytes);
        let mut offer = AuthorityDeviceLinkOffer {
            link_id,
            expires_at,
            manifest: manifest.clone(),
            authorizer,
            ephemeral: *PublicKey::from(&ephemeral).as_bytes(),
            signature: [0u8; 64],
        };
        offer.signature = device.sign_domain(OFFER_DOMAIN, &offer.canonical());
        offer.verify(expires_at)?;
        Ok((
            Self {
                offer: offer.clone(),
                ephemeral,
            },
            offer,
        ))
    }

    /// Verify the response and derive the comparison code.
    pub fn confirmation_code(
        &self,
        response: &AuthorityDeviceLinkResponse,
    ) -> Result<AuthorityDeviceLinkCode> {
        response.verify_for(&self.offer)?;
        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(response.ephemeral));
        Ok(link_material(&self.offer, response, shared.as_bytes()).1)
    }

    /// Build and locally sign the canonical add-device proposal.
    pub fn prepare(
        &self,
        authorizer: &Identity,
        response: &AuthorityDeviceLinkResponse,
        confirmed: bool,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedAuthorityDeviceLink> {
        self.offer.verify(now)?;
        response.verify_for(&self.offer)?;
        if !confirmed || authorizer.public().ed != self.offer.authorizer {
            return Err(CryptoError::InvalidMessage);
        }
        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(response.ephemeral));
        let (link_key, code) = link_material(&self.offer, response, shared.as_bytes());
        let mut proposal = self.offer.manifest.propose_add_device(
            response.certificate.clone(),
            response.name.clone(),
            now.max(response.certificate.issued_at),
            rng,
        )?;
        self.offer
            .manifest
            .sign_transition(&mut proposal, authorizer)?;
        Ok(PreparedAuthorityDeviceLink {
            link_id: self.offer.link_id,
            expires_at: self.offer.expires_at,
            parent: self.offer.manifest.clone(),
            response: response.clone(),
            proposal,
            link_key,
            code,
            authorizer_device: self.offer.authorizer,
        })
    }
}

/// Target-only one-use QR ceremony state.
pub struct PendingAuthorityDeviceLinkTarget {
    offer: AuthorityDeviceLinkOffer,
    response: AuthorityDeviceLinkResponse,
    link_key: Zeroizing<[u8; 32]>,
    code: AuthorityDeviceLinkCode,
}

impl PendingAuthorityDeviceLinkTarget {
    /// Accept an offer with an independently generated physical-device key.
    pub fn accept(
        offer: AuthorityDeviceLinkOffer,
        device: &Identity,
        name: String,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, AuthorityDeviceLinkResponse, AuthorityDeviceLinkCode)> {
        offer.verify(now)?;
        if name.is_empty() || name.len() > MAX_AUTHORITY_DEVICE_NAME_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let certificate =
            DeviceAuthorityCertificate::issue(offer.manifest.account().clone(), device, now, rng)?;
        let mut ephemeral_bytes = [0u8; 32];
        fill_nonzero(&mut ephemeral_bytes, rng);
        let ephemeral = StaticSecret::from(ephemeral_bytes);
        let mut response = AuthorityDeviceLinkResponse {
            link_id: offer.link_id,
            certificate,
            name,
            ephemeral: *PublicKey::from(&ephemeral).as_bytes(),
            signature: [0u8; 64],
        };
        response.signature = device.sign_domain(RESPONSE_DOMAIN, &response.canonical(&offer));
        response.verify_for(&offer)?;
        let shared = ephemeral.diffie_hellman(&PublicKey::from(offer.ephemeral));
        let (link_key, code) = link_material(&offer, &response, shared.as_bytes());
        Ok((
            Self {
                offer,
                response: response.clone(),
                link_key,
                code,
            },
            response,
            code,
        ))
    }

    /// Authenticate and open a completed quorum-approved transfer package.
    pub fn complete(
        &self,
        package: &[u8],
        confirmed: bool,
        now: u64,
    ) -> Result<CompletedAuthorityDeviceLink> {
        self.offer.verify(now)?;
        if !confirmed {
            return Err(CryptoError::InvalidMessage);
        }
        let plain =
            Zeroizing::new(StorageKey::from_bytes(*self.link_key).open(LINK_PACKAGE_AD, package)?);
        if plain.len() > MAX_AUTHORITY_LINK_TRANSFER_BYTES + 1024 * 1024 {
            return Err(CryptoError::InvalidMessage);
        }
        let (payload, remainder): (AuthorityLinkPackagePayload, &[u8]) =
            postcard::take_from_bytes(&plain).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() || payload.sync_payload.len() > MAX_AUTHORITY_LINK_TRANSFER_BYTES {
            return Err(CryptoError::Serialization);
        }
        payload.manifest.verify()?;
        payload.certificate.verify()?;
        if payload.account != *self.offer.manifest.account()
            || payload.manifest.account() != &payload.account
            || !matches!(
                self.offer.manifest.relation(&payload.manifest)?,
                DeviceAuthorityRelation::Descendant
            )
            || payload.certificate != self.response.certificate
            || payload
                .manifest
                .active_certificate(&payload.certificate.device_id())
                != Some(&payload.certificate)
        {
            return Err(CryptoError::InvalidMessage);
        }
        Ok(CompletedAuthorityDeviceLink {
            account: payload.account,
            manifest: payload.manifest,
            certificate: payload.certificate,
            channel_root: Zeroizing::new(payload.channel_root),
            sync_payload: payload.sync_payload,
            code: self.code,
            authorizer_device: self.offer.authorizer,
        })
    }
}

/// Canonical approval request shown to each additional active device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeviceLinkApprovalRequest {
    /// Link ceremony id.
    pub link_id: [u8; 16],
    /// Exact accepted parent state.
    pub parent_state: [u8; 32],
    /// Canonical proposed transition with collected signatures.
    pub proposal: DeviceAuthorityTransition,
}

impl AuthorityDeviceLinkApprovalRequest {
    /// Strict QR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_prefixed(APPROVAL_REQUEST_MAGIC, self)
    }

    /// Strict QR decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_prefixed(APPROVAL_REQUEST_MAGIC, bytes)
    }

    /// Verify against local authority and sign with this active device.
    pub fn approve(
        &self,
        manifest: &DeviceAuthorityManifest,
        device: &Identity,
    ) -> Result<AuthorityDeviceLinkApproval> {
        if self.link_id == [0u8; 16]
            || self.parent_state != manifest.state_id()
            || self.proposal.parent_hash != self.parent_state
        {
            return Err(CryptoError::InvalidMessage);
        }
        let approval = manifest.approve_transition(&self.proposal, device)?;
        Ok(AuthorityDeviceLinkApproval {
            link_id: self.link_id,
            parent_state: self.parent_state,
            proposal_id: self.proposal.proposal_id(),
            approval,
        })
    }
}

/// Detached additional-device approval scanned back by the initiator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDeviceLinkApproval {
    /// Link ceremony id.
    pub link_id: [u8; 16],
    /// Exact parent branch approved.
    pub parent_state: [u8; 32],
    /// Exact canonical proposal approved.
    pub proposal_id: [u8; 32],
    /// One active-parent device signature.
    pub approval: DeviceAuthoritySignature,
}

impl AuthorityDeviceLinkApproval {
    /// Strict QR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_prefixed(APPROVAL_MAGIC, self)
    }

    /// Strict QR decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_prefixed(APPROVAL_MAGIC, bytes)
    }
}

/// Source-held proposal awaiting any additional majority approvals.
pub struct PreparedAuthorityDeviceLink {
    link_id: [u8; 16],
    expires_at: u64,
    parent: DeviceAuthorityManifest,
    response: AuthorityDeviceLinkResponse,
    proposal: DeviceAuthorityTransition,
    link_key: Zeroizing<[u8; 32]>,
    code: AuthorityDeviceLinkCode,
    authorizer_device: [u8; 32],
}

impl PreparedAuthorityDeviceLink {
    /// Strict-majority threshold inherited from the exact parent state.
    pub fn required_approvals(&self) -> usize {
        self.parent.quorum_threshold()
    }

    /// Number of verified approvals currently collected.
    pub fn collected_approvals(&self) -> usize {
        self.proposal.approval_count()
    }

    /// Whether this proposal is ready for target activation.
    pub fn has_quorum(&self) -> Result<bool> {
        self.parent.has_quorum(&self.proposal)
    }

    /// Build the exact request scanned by any additional active devices.
    pub fn approval_request(&self) -> AuthorityDeviceLinkApprovalRequest {
        AuthorityDeviceLinkApprovalRequest {
            link_id: self.link_id,
            parent_state: self.parent.state_id(),
            proposal: self.proposal.clone(),
        }
    }

    /// Merge one detached approval only for this exact ceremony/proposal.
    pub fn merge_approval(&mut self, approval: AuthorityDeviceLinkApproval) -> Result<()> {
        if approval.link_id != self.link_id
            || approval.parent_state != self.parent.state_id()
            || approval.proposal_id != self.proposal.proposal_id()
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.parent
            .merge_approval(&mut self.proposal, approval.approval)
    }

    /// Finalize the authority transition and seal selected state to the target.
    pub fn finalize(
        self,
        now: u64,
        sync_payload: Vec<u8>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ApprovedAuthorityDeviceLink> {
        if now > self.expires_at
            || sync_payload.len() > MAX_AUTHORITY_LINK_TRANSFER_BYTES
            || !self.parent.has_quorum(&self.proposal)?
        {
            return Err(CryptoError::InvalidMessage);
        }
        let manifest = self.parent.append(self.proposal)?;
        let mut channel_root = [0u8; 32];
        rng.fill_bytes(&mut channel_root);
        if channel_root == [0u8; 32] {
            channel_root[0] = 1;
        }
        let package = seal_authority_device_link_recovery_package(
            &manifest,
            &self.response.certificate.device_id(),
            &channel_root,
            &sync_payload,
            &self.link_key,
            rng,
        )?;
        Ok(ApprovedAuthorityDeviceLink {
            package,
            manifest,
            code: self.code,
            target_device: self.response.certificate.device_id(),
            channel_root: Zeroizing::new(channel_root),
            recovery_key: self.link_key,
            authorizer_device: self.authorizer_device,
        })
    }
}

/// Source result after strict-majority authorization.
pub struct ApprovedAuthorityDeviceLink {
    /// AEAD-protected transfer package.
    pub package: Vec<u8>,
    /// New complete authority proof.
    pub manifest: DeviceAuthorityManifest,
    /// Source-side human comparison code.
    pub code: AuthorityDeviceLinkCode,
    /// Exact new target device.
    pub target_device: [u8; 32],
    /// Fresh pairwise sync-channel root.
    pub channel_root: Zeroizing<[u8; 32]>,
    /// Transcript-derived package key for crash-safe resealing.
    pub recovery_key: Zeroizing<[u8; 32]>,
    /// Exact source device that initiated the ceremony.
    pub authorizer_device: [u8; 32],
}

/// Target result after authenticating a root-free transfer package.
pub struct CompletedAuthorityDeviceLink {
    /// Stable public account trust anchor; no account secret is transferred.
    pub account: crate::IdentityPublic,
    /// Complete post-link authority proof.
    pub manifest: DeviceAuthorityManifest,
    /// This target's exact candidate-owned certificate.
    pub certificate: DeviceAuthorityCertificate,
    /// Pairwise sync-channel root.
    pub channel_root: Zeroizing<[u8; 32]>,
    /// Opaque selected state for store import.
    pub sync_payload: Vec<u8>,
    /// Target-side human comparison code.
    pub code: AuthorityDeviceLinkCode,
    /// Exact source device for channel persistence.
    pub authorizer_device: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct AuthorityLinkPackagePayload {
    account: crate::IdentityPublic,
    manifest: DeviceAuthorityManifest,
    certificate: DeviceAuthorityCertificate,
    channel_root: [u8; 32],
    sync_payload: Vec<u8>,
}

/// Rebuild one committed root-free link package after a caller restart.
pub fn seal_authority_device_link_recovery_package(
    manifest: &DeviceAuthorityManifest,
    target_device: &[u8; 32],
    channel_root: &[u8; 32],
    sync_payload: &[u8],
    link_key: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    manifest.verify()?;
    if *target_device == [0u8; 32]
        || *channel_root == [0u8; 32]
        || *link_key == [0u8; 32]
        || sync_payload.len() > MAX_AUTHORITY_LINK_TRANSFER_BYTES
    {
        return Err(CryptoError::InvalidMessage);
    }
    let certificate = manifest
        .active_certificate(target_device)
        .cloned()
        .ok_or(CryptoError::InvalidMessage)?;
    let payload = AuthorityLinkPackagePayload {
        account: manifest.account().clone(),
        manifest: manifest.clone(),
        certificate,
        channel_root: *channel_root,
        sync_payload: sync_payload.to_vec(),
    };
    let plain =
        Zeroizing::new(postcard::to_allocvec(&payload).map_err(|_| CryptoError::Serialization)?);
    Ok(StorageKey::from_bytes(*link_key).seal(LINK_PACKAGE_AD, &plain, rng))
}

fn link_material(
    offer: &AuthorityDeviceLinkOffer,
    response: &AuthorityDeviceLinkResponse,
    shared: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, AuthorityDeviceLinkCode) {
    let mut transcript = Sha256::new();
    transcript.update(offer.canonical());
    transcript.update(response.canonical(offer));
    let transcript: [u8; 32] = transcript.finalize().into();
    let mut input = Zeroizing::new(Vec::with_capacity(64));
    input.extend_from_slice(shared);
    input.extend_from_slice(&transcript);
    let key = util::hkdf32(Some(&transcript), &input, LINK_INFO);
    let raw = u32::from_le_bytes(key[..4].try_into().expect("four-byte prefix"));
    (key, AuthorityDeviceLinkCode(raw % 1_000_000))
}

fn encode_prefixed<T: Serialize>(magic: &[u8; 4], value: &T) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(value).map_err(|_| CryptoError::Serialization)?;
    let mut out = Vec::with_capacity(magic.len() + body.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_prefixed<'a, T: Deserialize<'a>>(magic: &[u8; 4], bytes: &'a [u8]) -> Result<T> {
    let body = bytes
        .strip_prefix(magic)
        .ok_or(CryptoError::Serialization)?;
    let (value, remainder) =
        postcard::take_from_bytes(body).map_err(|_| CryptoError::Serialization)?;
    if !remainder.is_empty() {
        return Err(CryptoError::Serialization);
    }
    Ok(value)
}

fn fill_nonzero<const N: usize>(value: &mut [u8; N], rng: &mut impl CryptoRngCore) {
    loop {
        rng.fill_bytes(value);
        if value.iter().any(|byte| *byte != 0) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn sole_device_link_transfers_no_account_secret() {
        let mut rng = StdRng::seed_from_u64(2620);
        let root = Identity::generate(&mut rng);
        let source = Identity::generate(&mut rng);
        let target = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &source, "Phone".into(), 10, &mut rng).unwrap();
        let root_bytes = root.to_bytes();
        let (pending_source, offer) =
            PendingAuthorityDeviceLinkSource::begin(&source, &manifest, 100, &mut rng).unwrap();
        let (pending_target, response, target_code) =
            PendingAuthorityDeviceLinkTarget::accept(offer, &target, "Laptop".into(), 20, &mut rng)
                .unwrap();
        assert_eq!(
            pending_source.confirmation_code(&response).unwrap(),
            target_code
        );
        let prepared = pending_source
            .prepare(&source, &response, true, 21, &mut rng)
            .unwrap();
        assert!(prepared.has_quorum().unwrap());
        let approved = prepared
            .finalize(22, b"selected history".to_vec(), &mut rng)
            .unwrap();
        let completed = pending_target
            .complete(&approved.package, true, 22)
            .unwrap();
        assert_eq!(completed.account, root.public());
        assert_eq!(completed.certificate.device, target.public());
        assert_eq!(completed.sync_payload, b"selected history");
        assert_eq!(completed.manifest, approved.manifest);
        assert!(approved
            .package
            .windows(root_bytes.len())
            .all(|window| window != &root_bytes[..]));
    }

    #[test]
    fn multi_device_link_requires_exact_additional_approval() {
        let mut rng = StdRng::seed_from_u64(2621);
        let root = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let target = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &first, "Phone".into(), 10, &mut rng).unwrap();
        let certificate =
            DeviceAuthorityCertificate::issue(root.public(), &second, 11, &mut rng).unwrap();
        let mut add = manifest
            .propose_add_device(certificate, "Desktop".into(), 11, &mut rng)
            .unwrap();
        manifest.sign_transition(&mut add, &first).unwrap();
        let manifest = manifest.append(add).unwrap();

        let (pending_source, offer) =
            PendingAuthorityDeviceLinkSource::begin(&first, &manifest, 100, &mut rng).unwrap();
        let (_, response, _) =
            PendingAuthorityDeviceLinkTarget::accept(offer, &target, "Tablet".into(), 20, &mut rng)
                .unwrap();
        let mut prepared = pending_source
            .prepare(&first, &response, true, 21, &mut rng)
            .unwrap();
        assert_eq!(prepared.required_approvals(), 2);
        assert!(!prepared.has_quorum().unwrap());
        let request = AuthorityDeviceLinkApprovalRequest::decode(
            &prepared.approval_request().encode().unwrap(),
        )
        .unwrap();
        let approval = request.approve(&manifest, &second).unwrap();
        prepared.merge_approval(approval).unwrap();
        assert!(prepared.has_quorum().unwrap());
        assert!(prepared.finalize(22, Vec::new(), &mut rng).is_ok());
    }
}
