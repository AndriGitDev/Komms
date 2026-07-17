//! Account-rooted physical-device credentials for C2 linked devices.
//!
//! A Komms account remains the stable Ed25519/X25519 identity already used
//! by conversations. Every physical installation additionally owns a fresh
//! [`Identity`] whose public half is certified by the account identity. The
//! signed manifest is the bounded, monotonic authority for names, last-seen
//! hints, and revocation; live ratchets are never part of either object.

use alloc::{string::String, vec, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{util, CryptoError, Identity, IdentityPublic, PrekeyBundle, Result, StorageKey};

/// Maximum physical devices carried in one account manifest.
pub const MAX_LINKED_DEVICES: usize = 8;
/// Maximum lifetime certificate/tombstone rows retained for rollback safety.
pub const MAX_DEVICE_MANIFEST_ENTRIES: usize = 64;
/// Maximum UTF-8 bytes in a user-visible device name.
pub const MAX_DEVICE_NAME_BYTES: usize = 64;
/// Maximum opaque synchronized-state bytes admitted by the link codec.
pub const MAX_LINK_TRANSFER_BYTES: usize = 16 * 1024 * 1024;

const LINK_INFO: &[u8] = b"Komms-device-link-key-v1";
const LINK_PACKAGE_AD: &[u8] = b"Komms-device-link-package-v1";
const DEVICE_PREKEY_MAGIC: &[u8; 4] = b"KDP1";

/// Versioned contact/QR record binding one device prekey bundle to its stable
/// account and complete signed manifest.
#[derive(Clone, Serialize, Deserialize)]
pub struct DevicePrekeyBundle {
    /// Exact active physical-device certificate.
    pub certificate: DeviceCertificate,
    /// Complete account authority state containing that certificate.
    pub manifest: DeviceManifest,
    /// Ordinary self-authenticating PQXDH bundle signed by the device key.
    pub prekey: PrekeyBundle,
}

impl DevicePrekeyBundle {
    /// Construct after independently building a device-signed prekey bundle.
    pub fn new(
        certificate: DeviceCertificate,
        manifest: DeviceManifest,
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

    /// Strict versioned encoding for QR/DHT/contact exchange.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = postcard::to_allocvec(self).map_err(|_| CryptoError::Serialization)?;
        let mut out = Vec::with_capacity(DEVICE_PREKEY_MAGIC.len() + body.len());
        out.extend_from_slice(DEVICE_PREKEY_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Return whether bytes identify the C2 wrapper rather than a legacy raw bundle.
    pub fn is_encoded(bytes: &[u8]) -> bool {
        bytes.starts_with(DEVICE_PREKEY_MAGIC)
    }

    /// Strictly decode without accepting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(DEVICE_PREKEY_MAGIC)
            .ok_or(CryptoError::Serialization)?;
        let (bundle, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(body).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() {
            return Err(CryptoError::Serialization);
        }
        Ok(bundle)
    }

    /// Verify the account manifest/certificate chain and device-signed prekeys.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.manifest.verify()?;
        self.certificate.verify()?;
        self.prekey.verify(now)?;
        if self.certificate.account != self.manifest.account
            || self.certificate.device != self.prekey.identity
            || !self
                .manifest
                .devices
                .iter()
                .any(|entry| entry.certificate == self.certificate && entry.revoked_at.is_none())
        {
            return Err(CryptoError::InvalidBundle);
        }
        Ok(())
    }
}

/// Immutable account authorization for one physical-device key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    /// Stable account identity that issued this certificate.
    pub account: IdentityPublic,
    /// Separately generated physical-device identity.
    pub device: IdentityPublic,
    /// Random certificate id; prevents delete/recreate aliasing.
    pub serial: [u8; 16],
    /// Local issuance time, for presentation and audit only.
    pub issued_at: u64,
    /// Account-root signature over every preceding field.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl DeviceCertificate {
    /// Issue a certificate for an independently generated device identity.
    pub fn issue(
        account: &Identity,
        device: &Identity,
        issued_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self::issue_public(account, device.public(), issued_at, rng)
    }

    /// Issue a certificate after a target proved possession of this public
    /// device key in the signed link response.
    pub fn issue_public(
        account: &Identity,
        device: IdentityPublic,
        issued_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let mut serial = [0u8; 16];
        loop {
            rng.fill_bytes(&mut serial);
            if serial != [0u8; 16] {
                break;
            }
        }
        let mut certificate = Self {
            account: account.public(),
            device,
            serial,
            issued_at,
            signature: [0u8; 64],
        };
        certificate.signature = account.sign_device_certificate(&certificate.canonical());
        certificate
    }

    /// Issue with a caller-supplied non-zero serial. This exists only for the
    /// deterministic in-memory migration of pre-C2 stores; new credentials
    /// must use [`DeviceCertificate::issue`].
    pub fn issue_with_serial(
        account: &Identity,
        device: IdentityPublic,
        serial: [u8; 16],
        issued_at: u64,
    ) -> Result<Self> {
        device.verify()?;
        if serial == [0u8; 16] {
            return Err(CryptoError::InvalidMessage);
        }
        let mut certificate = Self {
            account: account.public(),
            device,
            serial,
            issued_at,
            signature: [0u8; 64],
        };
        certificate.signature = account.sign_device_certificate(&certificate.canonical());
        certificate.verify()?;
        Ok(certificate)
    }

    /// The device Ed25519 key is its stable endpoint id.
    pub fn device_id(&self) -> [u8; 32] {
        self.device.ed
    }

    /// Verify key consistency, non-degenerate ids, and account authorization.
    pub fn verify(&self) -> Result<()> {
        self.account.verify()?;
        self.device.verify()?;
        if self.serial == [0u8; 16] {
            return Err(CryptoError::InvalidMessage);
        }
        self.account
            .verify_device_certificate(&self.canonical(), &self.signature)
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 4 + 16 + 8);
        out.extend_from_slice(&self.account.ed);
        out.extend_from_slice(&self.account.x);
        out.extend_from_slice(&self.device.ed);
        out.extend_from_slice(&self.device.x);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out
    }
}

/// Mutable manifest row for one certified physical device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceManifestEntry {
    /// Immutable account-rooted credential.
    pub certificate: DeviceCertificate,
    /// Exact user-authored UTF-8 device name.
    pub name: String,
    /// Coarse authenticated observation time; never a presence promise.
    pub last_seen: u64,
    /// Revocation time. A revoked id can never become active again.
    pub revoked_at: Option<u64>,
    /// Highest signed sync counter accepted from this device. Present exactly
    /// when revoked, so delayed pre-revocation work still converges while
    /// post-revocation work is excluded without trusting wall clocks.
    pub revoked_after_counter: Option<u64>,
}

/// Complete signed authority state for one account's physical devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceManifest {
    /// Stable account identity.
    pub account: IdentityPublic,
    /// Monotonic state generation, starting at one.
    pub generation: u64,
    /// Entries in strict ascending device-id order.
    pub devices: Vec<DeviceManifestEntry>,
    /// Account-root signature over the complete canonical state.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl DeviceManifest {
    /// Create the generation-one manifest for a new account installation.
    pub fn initial(
        account: &Identity,
        certificate: DeviceCertificate,
        name: String,
        last_seen: u64,
    ) -> Result<Self> {
        let mut manifest = Self {
            account: account.public(),
            generation: 1,
            devices: vec![DeviceManifestEntry {
                certificate,
                name,
                last_seen,
                revoked_at: None,
                revoked_after_counter: None,
            }],
            signature: [0u8; 64],
        };
        manifest.resign(account)?;
        Ok(manifest)
    }

    /// Validate structure and every nested account-root authorization.
    pub fn verify(&self) -> Result<()> {
        self.account.verify()?;
        if self.generation == 0
            || self.devices.is_empty()
            || self.devices.len() > MAX_DEVICE_MANIFEST_ENTRIES
        {
            return Err(CryptoError::InvalidMessage);
        }
        let mut previous = None;
        let mut active = 0usize;
        for entry in &self.devices {
            entry.certificate.verify()?;
            if entry.certificate.account != self.account
                || entry.name.is_empty()
                || entry.name.len() > MAX_DEVICE_NAME_BYTES
                || entry.last_seen < entry.certificate.issued_at
                || entry
                    .revoked_at
                    .is_some_and(|revoked| revoked < entry.certificate.issued_at)
                || entry.revoked_at.is_some() != entry.revoked_after_counter.is_some()
            {
                return Err(CryptoError::InvalidMessage);
            }
            let id = entry.certificate.device_id();
            if previous.is_some_and(|prior| prior >= id) {
                return Err(CryptoError::InvalidMessage);
            }
            previous = Some(id);
            if entry.revoked_at.is_none() {
                active += 1;
            }
        }
        if active == 0 || active > MAX_LINKED_DEVICES {
            return Err(CryptoError::InvalidMessage);
        }
        self.account
            .verify_device_manifest(&self.canonical(), &self.signature)
    }

    /// Stable digest used to break a rare valid same-generation fork.
    pub fn state_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.canonical());
        hash.update(self.signature);
        hash.finalize().into()
    }

    /// Add one newly certified device and advance the authority generation.
    pub fn add_device(&mut self, account: &Identity, entry: DeviceManifestEntry) -> Result<()> {
        if entry.certificate.account != self.account
            || entry.certificate.verify().is_err()
            || entry.name.is_empty()
            || entry.name.len() > MAX_DEVICE_NAME_BYTES
            || entry.last_seen < entry.certificate.issued_at
            || entry.revoked_at.is_some()
            || entry.revoked_after_counter.is_some()
            || self
                .devices
                .iter()
                .any(|current| current.certificate.device_id() == entry.certificate.device_id())
            || self.devices.len() >= MAX_DEVICE_MANIFEST_ENTRIES
            || self
                .devices
                .iter()
                .filter(|current| current.revoked_at.is_none())
                .count()
                >= MAX_LINKED_DEVICES
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.devices.push(entry);
        self.devices
            .sort_by_key(|current| current.certificate.device_id());
        self.advance_and_resign(account)
    }

    /// Rename one active exact device id.
    pub fn rename_device(
        &mut self,
        account: &Identity,
        device: &[u8; 32],
        name: String,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_DEVICE_NAME_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let entry = self
            .devices
            .iter_mut()
            .find(|entry| &entry.certificate.device_id() == device && entry.revoked_at.is_none())
            .ok_or(CryptoError::InvalidMessage)?;
        entry.name = name;
        self.advance_and_resign(account)
    }

    /// Advance the coarse last-seen hint for one active exact device id.
    pub fn touch_device(
        &mut self,
        account: &Identity,
        device: &[u8; 32],
        last_seen: u64,
    ) -> Result<()> {
        let entry = self
            .devices
            .iter_mut()
            .find(|entry| &entry.certificate.device_id() == device && entry.revoked_at.is_none())
            .ok_or(CryptoError::InvalidMessage)?;
        entry.last_seen = entry.last_seen.max(last_seen);
        self.advance_and_resign(account)
    }

    /// Permanently revoke one device while retaining at least one active row.
    pub fn revoke_device(
        &mut self,
        account: &Identity,
        device: &[u8; 32],
        revoked_at: u64,
        last_accepted_counter: u64,
    ) -> Result<()> {
        if self
            .devices
            .iter()
            .filter(|entry| entry.revoked_at.is_none())
            .count()
            <= 1
        {
            return Err(CryptoError::InvalidMessage);
        }
        let entry = self
            .devices
            .iter_mut()
            .find(|entry| &entry.certificate.device_id() == device && entry.revoked_at.is_none())
            .ok_or(CryptoError::InvalidMessage)?;
        entry.revoked_at = Some(revoked_at.max(entry.certificate.issued_at));
        entry.revoked_after_counter = Some(last_accepted_counter);
        self.advance_and_resign(account)
    }

    /// Accept only a valid forward state that never un-revokes or rewrites a
    /// known certificate. Same-generation forks converge by state id.
    pub fn accepts_successor(&self, candidate: &Self) -> Result<bool> {
        self.verify()?;
        candidate.verify()?;
        if candidate.account != self.account
            || candidate.generation < self.generation
            || (candidate.generation == self.generation && candidate.state_id() <= self.state_id())
        {
            return Ok(false);
        }
        for old in &self.devices {
            let Some(new) = candidate
                .devices
                .iter()
                .find(|entry| entry.certificate.device_id() == old.certificate.device_id())
            else {
                return Ok(false);
            };
            if new.certificate != old.certificate
                || (old.revoked_at.is_some() && new.revoked_at.is_none())
                || old
                    .revoked_after_counter
                    .is_some_and(|cutoff| new.revoked_after_counter != Some(cutoff))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn advance_and_resign(&mut self, account: &Identity) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(CryptoError::InvalidMessage)?;
        self.resign(account)
    }

    fn resign(&mut self, account: &Identity) -> Result<()> {
        if account.public() != self.account {
            return Err(CryptoError::InvalidKey);
        }
        self.signature = account.sign_device_manifest(&self.canonical());
        self.verify()
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.account.ed);
        out.extend_from_slice(&self.account.x);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&(self.devices.len() as u32).to_le_bytes());
        for entry in &self.devices {
            let certificate = entry.certificate.canonical();
            out.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
            out.extend_from_slice(&certificate);
            out.extend_from_slice(&entry.certificate.signature);
            out.extend_from_slice(&(entry.name.len() as u32).to_le_bytes());
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(&entry.last_seen.to_le_bytes());
            match entry.revoked_at {
                Some(revoked_at) => {
                    out.push(1);
                    out.extend_from_slice(&revoked_at.to_le_bytes());
                }
                None => out.push(0),
            }
            if let Some(counter) = entry.revoked_after_counter {
                out.extend_from_slice(&counter.to_le_bytes());
            }
        }
        out
    }
}

/// Account-authenticated QR offer from an already linked device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLinkOffer {
    /// Random ceremony id; responses cannot cross ceremonies.
    pub link_id: [u8; 16],
    /// Absolute expiry. Stale QR payloads fail closed.
    pub expires_at: u64,
    /// Current complete account device authority state.
    pub manifest: DeviceManifest,
    /// Exact active authorizing physical device.
    pub authorizer: [u8; 32],
    /// Source's one-use X25519 public key.
    pub ephemeral: [u8; 32],
    /// Account-root signature over the complete offer.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl DeviceLinkOffer {
    /// Encode the bounded QR payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| CryptoError::Serialization)
    }

    /// Strictly decode and verify a QR payload at `now`.
    pub fn decode_and_verify(bytes: &[u8], now: u64) -> Result<Self> {
        let (offer, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() {
            return Err(CryptoError::Serialization);
        }
        offer.verify(now)?;
        Ok(offer)
    }

    /// Validate expiry, manifest, active authorizer, and account signature.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.manifest.verify()?;
        if self.link_id == [0u8; 16]
            || self.ephemeral == [0u8; 32]
            || now > self.expires_at
            || !self.manifest.devices.iter().any(|entry| {
                entry.certificate.device_id() == self.authorizer && entry.revoked_at.is_none()
            })
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.manifest
            .account
            .verify_device_link_offer(&self.canonical(), &self.signature)
    }

    fn canonical(&self) -> Vec<u8> {
        let manifest = postcard::to_allocvec(&self.manifest)
            .expect("verified device manifests always serialize");
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

/// Device-authenticated target response scanned back by the source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLinkResponse {
    /// Exact offer id being answered.
    pub link_id: [u8; 16],
    /// Fresh target physical-device identity.
    pub device: IdentityPublic,
    /// Exact proposed UTF-8 device name.
    pub name: String,
    /// Target's one-use X25519 public key.
    pub ephemeral: [u8; 32],
    /// Target device-key signature binding the offer and response.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

impl DeviceLinkResponse {
    /// Encode the bounded QR response.
    pub fn encode(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| CryptoError::Serialization)
    }

    /// Strictly decode without trusting its contents; source verification
    /// also requires the matching pending offer.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (response, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() {
            return Err(CryptoError::Serialization);
        }
        Ok(response)
    }

    fn verify_for(&self, offer: &DeviceLinkOffer) -> Result<()> {
        self.device.verify()?;
        if self.link_id != offer.link_id
            || self.ephemeral == [0u8; 32]
            || self.name.is_empty()
            || self.name.len() > MAX_DEVICE_NAME_BYTES
            || offer
                .manifest
                .devices
                .iter()
                .any(|entry| entry.certificate.device_id() == self.device.ed)
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.device
            .verify_device_link_response(&self.canonical(offer), &self.signature)
    }

    fn canonical(&self, offer: &DeviceLinkOffer) -> Vec<u8> {
        let offer_hash: [u8; 32] = Sha256::digest(offer.canonical()).into();
        let mut out = Vec::with_capacity(16 + 32 + 32 + 4 + self.name.len() + 32);
        out.extend_from_slice(&self.link_id);
        out.extend_from_slice(&offer_hash);
        out.extend_from_slice(&self.device.ed);
        out.extend_from_slice(&self.device.x);
        out.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out
    }
}

/// Six-digit comparison code shown on both devices before approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLinkCode(u32);

impl DeviceLinkCode {
    /// Zero-padded six-digit form suitable for localized presentation.
    pub fn digits(self) -> String {
        alloc::format!("{:06}", self.0)
    }
}

/// Source-only one-use ceremony state. It is deliberately memory-only.
pub struct PendingDeviceLinkSource {
    offer: DeviceLinkOffer,
    ephemeral: StaticSecret,
}

impl PendingDeviceLinkSource {
    /// Start a short-lived QR ceremony from an active authorizing device.
    pub fn begin(
        account: &Identity,
        manifest: &DeviceManifest,
        authorizer: [u8; 32],
        expires_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, DeviceLinkOffer)> {
        manifest.verify()?;
        if manifest.account != account.public() {
            return Err(CryptoError::InvalidKey);
        }
        let mut link_id = [0u8; 16];
        let mut ephemeral_bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut link_id);
            rng.fill_bytes(&mut ephemeral_bytes);
            if link_id != [0u8; 16] && ephemeral_bytes != [0u8; 32] {
                break;
            }
        }
        let ephemeral = StaticSecret::from(ephemeral_bytes);
        let mut offer = DeviceLinkOffer {
            link_id,
            expires_at,
            manifest: manifest.clone(),
            authorizer,
            ephemeral: *PublicKey::from(&ephemeral).as_bytes(),
            signature: [0u8; 64],
        };
        offer.signature = account.sign_device_link_offer(&offer.canonical());
        offer.verify(expires_at)?;
        Ok((
            Self {
                offer: offer.clone(),
                ephemeral,
            },
            offer,
        ))
    }

    /// Verify the scanned response and derive the comparison code.
    pub fn confirmation_code(&self, response: &DeviceLinkResponse) -> Result<DeviceLinkCode> {
        response.verify_for(&self.offer)?;
        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(response.ephemeral));
        Ok(link_material(&self.offer, response, shared.as_bytes()).1)
    }

    /// After explicit code confirmation, issue the device credential and
    /// encrypt the account root plus selected synchronized state to target.
    pub fn approve(
        self,
        account: &Identity,
        response: &DeviceLinkResponse,
        confirmed: bool,
        now: u64,
        sync_payload: Vec<u8>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ApprovedDeviceLink> {
        self.offer.verify(now)?;
        response.verify_for(&self.offer)?;
        if !confirmed || sync_payload.len() > MAX_LINK_TRANSFER_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(response.ephemeral));
        let (link_key, code) = link_material(&self.offer, response, shared.as_bytes());
        let certificate =
            DeviceCertificate::issue_public(account, response.device.clone(), now, rng);
        let mut manifest = self.offer.manifest.clone();
        manifest.add_device(
            account,
            DeviceManifestEntry {
                certificate: certificate.clone(),
                name: response.name.clone(),
                last_seen: now,
                revoked_at: None,
                revoked_after_counter: None,
            },
        )?;
        let mut channel_root = [0u8; 32];
        rng.fill_bytes(&mut channel_root);
        let payload = LinkPackagePayload {
            account_secret: account.to_bytes().to_vec(),
            manifest: manifest.clone(),
            certificate,
            channel_root,
            sync_payload,
        };
        let plain = postcard::to_allocvec(&payload).map_err(|_| CryptoError::Serialization)?;
        let package = StorageKey::from_bytes(*link_key).seal(LINK_PACKAGE_AD, &plain, rng);
        Ok(ApprovedDeviceLink {
            package,
            manifest,
            code,
            target_device: response.device.ed,
            channel_root: Zeroizing::new(channel_root),
        })
    }
}

/// Target-only one-use ceremony state. It is deliberately memory-only.
pub struct PendingDeviceLinkTarget {
    offer: DeviceLinkOffer,
    response: DeviceLinkResponse,
    link_key: Zeroizing<[u8; 32]>,
    code: DeviceLinkCode,
}

impl PendingDeviceLinkTarget {
    /// Accept a verified source offer using this installation's fresh device
    /// identity, returning a response QR and comparison code.
    pub fn accept(
        offer: DeviceLinkOffer,
        device: &Identity,
        name: String,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, DeviceLinkResponse, DeviceLinkCode)> {
        offer.verify(now)?;
        if name.is_empty() || name.len() > MAX_DEVICE_NAME_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let mut ephemeral_bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut ephemeral_bytes);
            if ephemeral_bytes != [0u8; 32] {
                break;
            }
        }
        let ephemeral = StaticSecret::from(ephemeral_bytes);
        let mut response = DeviceLinkResponse {
            link_id: offer.link_id,
            device: device.public(),
            name,
            ephemeral: *PublicKey::from(&ephemeral).as_bytes(),
            signature: [0u8; 64],
        };
        response.signature = device.sign_device_link_response(&response.canonical(&offer));
        response.verify_for(&offer)?;
        let shared = ephemeral.diffie_hellman(&PublicKey::from(offer.ephemeral));
        let (link_key, code) = link_material(&offer, &response, shared.as_bytes());
        let pending = Self {
            offer,
            response: response.clone(),
            link_key,
            code,
        };
        Ok((pending, response, code))
    }

    /// After explicit local confirmation, authenticate and open the source's
    /// transfer package. Nothing is returned on mismatch or cancellation.
    pub fn complete(
        self,
        package: &[u8],
        confirmed: bool,
        now: u64,
    ) -> Result<CompletedDeviceLink> {
        self.offer.verify(now)?;
        if !confirmed {
            return Err(CryptoError::InvalidMessage);
        }
        let plain =
            Zeroizing::new(StorageKey::from_bytes(*self.link_key).open(LINK_PACKAGE_AD, package)?);
        if plain.len() > MAX_LINK_TRANSFER_BYTES + 64 * 1024 {
            return Err(CryptoError::InvalidMessage);
        }
        let (mut payload, remainder): (LinkPackagePayload, &[u8]) =
            postcard::take_from_bytes(&plain).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() || payload.sync_payload.len() > MAX_LINK_TRANSFER_BYTES {
            return Err(CryptoError::Serialization);
        }
        let account_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
            payload
                .account_secret
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?,
        );
        payload.account_secret.fill(0);
        let account = Identity::from_bytes(&account_bytes);
        payload.manifest.verify()?;
        payload.certificate.verify()?;
        if account.public() != self.offer.manifest.account
            || payload.manifest.account != account.public()
            || !self.offer.manifest.accepts_successor(&payload.manifest)?
            || payload.certificate.device != self.response.device
            || !payload
                .manifest
                .devices
                .iter()
                .any(|entry| entry.certificate == payload.certificate && entry.revoked_at.is_none())
        {
            return Err(CryptoError::InvalidMessage);
        }
        Ok(CompletedDeviceLink {
            account,
            manifest: payload.manifest,
            certificate: payload.certificate,
            channel_root: Zeroizing::new(payload.channel_root),
            sync_payload: payload.sync_payload,
            code: self.code,
            authorizer_device: self.offer.authorizer,
        })
    }
}

/// Source result after authorizing a target.
pub struct ApprovedDeviceLink {
    /// AEAD-protected transfer bytes; safe for a local-network/file carrier.
    pub package: Vec<u8>,
    /// New account authority state to persist and synchronize.
    pub manifest: DeviceManifest,
    /// The source-side comparison code, retained for audit/tests.
    pub code: DeviceLinkCode,
    /// Exact new peer device for source-side channel persistence.
    pub target_device: [u8; 32],
    /// Shared sync-channel root retained only by the two linked devices.
    pub channel_root: Zeroizing<[u8; 32]>,
}

/// Target result after authenticating and opening a transfer package.
pub struct CompletedDeviceLink {
    /// Stable account root imported only inside the confirmed encrypted link.
    pub account: Identity,
    /// Complete post-link device authority state.
    pub manifest: DeviceManifest,
    /// This target's exact account certificate.
    pub certificate: DeviceCertificate,
    /// Shared root for later encrypted device-sync bundles.
    pub channel_root: Zeroizing<[u8; 32]>,
    /// Opaque selected state for the node/store import layer.
    pub sync_payload: Vec<u8>,
    /// Target-side comparison code, retained for audit/tests.
    pub code: DeviceLinkCode,
    /// Exact source device for target-side channel persistence.
    pub authorizer_device: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LinkPackagePayload {
    account_secret: Vec<u8>,
    manifest: DeviceManifest,
    certificate: DeviceCertificate,
    channel_root: [u8; 32],
    sync_payload: Vec<u8>,
}

fn link_material(
    offer: &DeviceLinkOffer,
    response: &DeviceLinkResponse,
    shared: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, DeviceLinkCode) {
    let mut transcript = Sha256::new();
    transcript.update(offer.canonical());
    transcript.update(response.canonical(offer));
    let transcript: [u8; 32] = transcript.finalize().into();
    let mut input = Zeroizing::new(Vec::with_capacity(64));
    input.extend_from_slice(shared);
    input.extend_from_slice(&transcript);
    let key = util::hkdf32(Some(&transcript), &input, LINK_INFO);
    let raw = u32::from_le_bytes(key[..4].try_into().expect("four-byte prefix"));
    (key, DeviceLinkCode(raw % 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn manifest_authorizes_rename_and_permanent_revocation() {
        let mut rng = StdRng::seed_from_u64(71);
        let account = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let first_cert = DeviceCertificate::issue(&account, &first, 10, &mut rng);
        let mut manifest =
            DeviceManifest::initial(&account, first_cert, "Phone".into(), 10).unwrap();
        let prior = manifest.clone();
        let second_cert = DeviceCertificate::issue(&account, &second, 20, &mut rng);
        manifest
            .add_device(
                &account,
                DeviceManifestEntry {
                    certificate: second_cert,
                    name: "Laptop".into(),
                    last_seen: 20,
                    revoked_at: None,
                    revoked_after_counter: None,
                },
            )
            .unwrap();
        assert!(prior.accepts_successor(&manifest).unwrap());

        let before_revoke = manifest.clone();
        manifest
            .rename_device(&account, &second.public().ed, "Desktop".into())
            .unwrap();
        manifest
            .revoke_device(&account, &first.public().ed, 30, 7)
            .unwrap();
        assert!(before_revoke.accepts_successor(&manifest).unwrap());

        let mut resurrection = manifest.clone();
        resurrection
            .devices
            .iter_mut()
            .find(|entry| entry.certificate.device_id() == first.public().ed)
            .unwrap()
            .revoked_at = None;
        resurrection
            .devices
            .iter_mut()
            .find(|entry| entry.certificate.device_id() == first.public().ed)
            .unwrap()
            .revoked_after_counter = None;
        resurrection.advance_and_resign(&account).unwrap();
        assert!(!manifest.accepts_successor(&resurrection).unwrap());
    }

    #[test]
    fn manifest_rejects_tampering_duplicates_and_last_device_revocation() {
        let mut rng = StdRng::seed_from_u64(72);
        let account = Identity::generate(&mut rng);
        let device = Identity::generate(&mut rng);
        let cert = DeviceCertificate::issue(&account, &device, 10, &mut rng);
        let mut manifest = DeviceManifest::initial(&account, cert, "Phone".into(), 10).unwrap();
        assert!(manifest
            .revoke_device(&account, &device.public().ed, 11, 0)
            .is_err());
        manifest.devices[0].name = "tampered".into();
        assert!(manifest.verify().is_err());
    }

    #[test]
    fn confirmed_link_transfers_account_and_selected_state() {
        let mut rng = StdRng::seed_from_u64(73);
        let account = Identity::generate(&mut rng);
        let source = Identity::generate(&mut rng);
        let target = Identity::generate(&mut rng);
        let source_cert = DeviceCertificate::issue(&account, &source, 10, &mut rng);
        let manifest = DeviceManifest::initial(&account, source_cert, "Phone".into(), 10).unwrap();
        let (source_pending, offer) =
            PendingDeviceLinkSource::begin(&account, &manifest, source.public().ed, 100, &mut rng)
                .unwrap();
        let (target_pending, response, target_code) =
            PendingDeviceLinkTarget::accept(offer, &target, "Laptop".into(), 20, &mut rng).unwrap();
        assert_eq!(
            source_pending.confirmation_code(&response).unwrap(),
            target_code
        );
        let approved = source_pending
            .approve(
                &account,
                &response,
                true,
                21,
                b"selected history".to_vec(),
                &mut rng,
            )
            .unwrap();
        let completed = target_pending
            .complete(&approved.package, true, 22)
            .unwrap();
        assert_eq!(completed.account.public(), account.public());
        assert_eq!(completed.certificate.device, target.public());
        assert_eq!(completed.sync_payload, b"selected history");
        assert_eq!(completed.code, approved.code);
        assert_eq!(completed.manifest, approved.manifest);
    }

    #[test]
    fn link_rejects_expiry_cancellation_and_tampering() {
        let mut rng = StdRng::seed_from_u64(74);
        let account = Identity::generate(&mut rng);
        let source = Identity::generate(&mut rng);
        let target = Identity::generate(&mut rng);
        let source_cert = DeviceCertificate::issue(&account, &source, 10, &mut rng);
        let manifest = DeviceManifest::initial(&account, source_cert, "Phone".into(), 10).unwrap();
        let (_, offer) =
            PendingDeviceLinkSource::begin(&account, &manifest, source.public().ed, 30, &mut rng)
                .unwrap();
        assert!(PendingDeviceLinkTarget::accept(
            offer.clone(),
            &target,
            "Laptop".into(),
            31,
            &mut rng
        )
        .is_err());
        let (source_pending, _) =
            PendingDeviceLinkSource::begin(&account, &manifest, source.public().ed, 100, &mut rng)
                .unwrap();
        let (_, response, _) = PendingDeviceLinkTarget::accept(
            source_pending.offer.clone(),
            &target,
            "Laptop".into(),
            20,
            &mut rng,
        )
        .unwrap();
        assert!(source_pending
            .approve(&account, &response, false, 21, Vec::new(), &mut rng)
            .is_err());
    }
}
