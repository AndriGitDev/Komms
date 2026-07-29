//! Version-two offline-root and quorum-authorized device authority.
//!
//! The stable account key signs only genesis and explicit recovery epoch
//! changes. Ordinary transitions are authorized by a strict majority of the
//! preceding active device set. Every transition carries the complete next
//! state and is bound to its exact parent hash.

use alloc::{string::String, vec, vec::Vec};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{util, CryptoError, Identity, IdentityPublic, Result};

/// Codec and canonical-signature version for offline-root device authority.
pub const DEVICE_AUTHORITY_VERSION: u16 = 2;
/// Maximum transitions retained in one bounded authority proof.
pub const MAX_DEVICE_AUTHORITY_TRANSITIONS: usize = 64;
/// Maximum encoded authority proof accepted from an untrusted peer.
pub const MAX_DEVICE_AUTHORITY_BYTES: usize = 1024 * 1024;
/// Maximum physical devices carried in one current authority state.
pub const MAX_AUTHORITY_DEVICES: usize = 8;
/// Maximum lifetime certificate/tombstone rows retained in one proof.
pub const MAX_AUTHORITY_ENTRIES: usize = 64;
/// Maximum UTF-8 bytes in a user-visible device name.
pub const MAX_AUTHORITY_DEVICE_NAME_BYTES: usize = 64;

const AUTHORITY_MAGIC: &[u8; 4] = b"KDA2";
const CERTIFICATE_DOMAIN: &[u8] = b"Komms-device-authority-certificate-v2";
const TRANSITION_DOMAIN: &[u8] = b"Komms-device-authority-transition-v2";
const ROOT_TRANSITION_DOMAIN: &[u8] = b"Komms-device-authority-root-transition-v2";

/// Immutable candidate-owned credential for one physical device.
///
/// Account authorization comes from the transition that first introduces
/// this certificate. The certificate signature proves possession of the
/// physical device key and therefore never requires the account root online.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorityCertificate {
    /// Stable account trust anchor to which this device is proposed.
    pub account: IdentityPublic,
    /// Independently generated physical-device identity.
    pub device: IdentityPublic,
    /// Random non-zero certificate id.
    pub serial: [u8; 16],
    /// Local issuance time used only for bounded presentation and audit.
    pub issued_at: u64,
    /// Device-key signature over the complete canonical certificate.
    #[serde(with = "util::bytes64")]
    pub device_signature: [u8; 64],
}

impl DeviceAuthorityCertificate {
    /// Create a fresh candidate-owned certificate for `account`.
    pub fn issue(
        account: IdentityPublic,
        device: &Identity,
        issued_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        account.verify()?;
        let mut serial = [0u8; 16];
        fill_nonzero_16(&mut serial, rng);
        Self::issue_with_serial(account, device, serial, issued_at)
    }

    /// Create a deterministic certificate for migration fixtures.
    ///
    /// Production callers must use [`Self::issue`] so serials are random.
    pub fn issue_with_serial(
        account: IdentityPublic,
        device: &Identity,
        serial: [u8; 16],
        issued_at: u64,
    ) -> Result<Self> {
        account.verify()?;
        if serial == [0u8; 16] {
            return Err(CryptoError::InvalidMessage);
        }
        let mut certificate = Self {
            account,
            device: device.public(),
            serial,
            issued_at,
            device_signature: [0u8; 64],
        };
        certificate.device_signature =
            device.sign_domain(CERTIFICATE_DOMAIN, &certificate.canonical());
        certificate.verify()?;
        Ok(certificate)
    }

    /// Exact Ed25519 id of the physical device.
    pub fn device_id(&self) -> [u8; 32] {
        self.device.ed
    }

    /// Verify identity consistency, the non-zero serial, and device possession.
    pub fn verify(&self) -> Result<()> {
        self.account.verify()?;
        self.device.verify()?;
        if self.serial == [0u8; 16] {
            return Err(CryptoError::InvalidMessage);
        }
        self.device.verify_domain(
            CERTIFICATE_DOMAIN,
            &self.canonical(),
            &self.device_signature,
        )
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 * (32 + 32 + 64) + 16 + 8);
        out.extend_from_slice(&DEVICE_AUTHORITY_VERSION.to_le_bytes());
        append_identity(&mut out, &self.account);
        append_identity(&mut out, &self.device);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out
    }
}

/// Complete state row for one immutable physical-device certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorityEntry {
    /// Immutable candidate-owned certificate.
    pub certificate: DeviceAuthorityCertificate,
    /// Exact user-authored UTF-8 device name.
    pub name: String,
    /// Coarse authenticated observation time; never a presence promise.
    pub last_seen: u64,
    /// Revocation time, once set.
    pub revoked_at: Option<u64>,
    /// Highest old-epoch sync counter accepted after ordinary revocation.
    pub revoked_after_counter: Option<u64>,
}

impl DeviceAuthorityEntry {
    /// Whether this exact certificate is currently active.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Declared semantic kind of one complete-state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeviceAuthorityTransitionKind {
    /// Root-authorized first state for a new account.
    Genesis = 1,
    /// Introduce one fresh physical-device certificate.
    AddDevice = 2,
    /// Change exactly one active device's display name.
    RenameDevice = 3,
    /// Advance exactly one active device's coarse last-seen hint.
    ObserveDevice = 4,
    /// Permanently revoke exactly one active device.
    RevokeDevice = 5,
    /// Revoke one credential and introduce one replacement atomically.
    ReplaceDevice = 6,
    /// Root-authorized epoch change with one fresh recovery device.
    Recovery = 7,
}

/// One device signature over a canonical ordinary transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthoritySignature {
    /// Exact active parent device that signed.
    pub signer: [u8; 32],
    /// Domain-separated Ed25519 signature.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

/// Root signature used only for genesis and recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorityRootSignature {
    /// Domain-separated account-root signature.
    #[serde(with = "util::bytes64")]
    pub signature: [u8; 64],
}

/// Authorization proof attached to a transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceAuthorityAuthorization {
    /// Sorted unique strict-majority signatures from the previous active set.
    Devices(Vec<DeviceAuthoritySignature>),
    /// Account-root authorization for genesis or recovery only.
    Root(DeviceAuthorityRootSignature),
}

/// One versioned, parent-bound, complete-state authority transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorityTransition {
    /// Canonical transition version.
    pub version: u16,
    /// Stable account trust anchor.
    pub account: IdentityPublic,
    /// Hash of the exact parent transition, or zero for genesis.
    pub parent_hash: [u8; 32],
    /// Exact parent generation, or zero for genesis.
    pub parent_generation: u64,
    /// Monotonic generation, starting at one.
    pub generation: u64,
    /// Recovery epoch inherited by ordinary descendants.
    pub recovery_epoch: u64,
    /// Random non-zero id preventing replay aliasing.
    pub transition_id: [u8; 16],
    /// Additional random recovery id, present only on recovery.
    pub recovery_id: Option<[u8; 16]>,
    /// Declared state-difference semantics.
    pub kind: DeviceAuthorityTransitionKind,
    /// Complete next state in strict ascending device-id order.
    pub devices: Vec<DeviceAuthorityEntry>,
    /// Exact newly introduced certificates, sorted by device id.
    pub new_certificates: Vec<DeviceAuthorityCertificate>,
    /// Root or strict-majority authorization.
    pub authorization: DeviceAuthorityAuthorization,
}

impl DeviceAuthorityTransition {
    /// Stable proposal digest excluding the growable approval list.
    pub fn proposal_id(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }

    /// Stable digest binding all fields and every accepted signature.
    pub fn transition_hash(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.canonical());
        match &self.authorization {
            DeviceAuthorityAuthorization::Devices(signatures) => {
                hash.update([1]);
                hash.update((signatures.len() as u32).to_le_bytes());
                for signature in signatures {
                    hash.update(signature.signer);
                    hash.update(signature.signature);
                }
            }
            DeviceAuthorityAuthorization::Root(signature) => {
                hash.update([2]);
                hash.update(signature.signature);
            }
        }
        hash.finalize().into()
    }

    /// Number of device approvals currently present.
    pub fn approval_count(&self) -> usize {
        match &self.authorization {
            DeviceAuthorityAuthorization::Devices(signatures) => signatures.len(),
            DeviceAuthorityAuthorization::Root(_) => 0,
        }
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        append_identity(&mut out, &self.account);
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.parent_generation.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.recovery_epoch.to_le_bytes());
        out.extend_from_slice(&self.transition_id);
        match self.recovery_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id);
            }
            None => out.push(0),
        }
        out.push(self.kind as u8);
        out.extend_from_slice(&(self.devices.len() as u32).to_le_bytes());
        for entry in &self.devices {
            append_entry(&mut out, entry);
        }
        out.extend_from_slice(&(self.new_certificates.len() as u32).to_le_bytes());
        for certificate in &self.new_certificates {
            let canonical = certificate.canonical();
            out.extend_from_slice(&(canonical.len() as u32).to_le_bytes());
            out.extend_from_slice(&canonical);
            out.extend_from_slice(&certificate.device_signature);
        }
        out
    }
}

/// Visible relationship between a locally accepted branch and a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceAuthorityRelation {
    /// Both proofs end at the exact same transition.
    Same,
    /// The candidate extends the locally accepted branch in the same epoch.
    Descendant,
    /// A root-authorized higher recovery epoch supersedes local authority.
    RecoverySupersedes,
    /// The candidate is an already accepted ancestor.
    Stale,
    /// The candidate descends from an older recovery epoch.
    OldEpoch,
    /// Two ordinary valid transitions diverge from one accepted parent.
    Fork,
    /// Two different root transitions claim the same recovery epoch.
    RecoveryConflict,
}

/// Bounded append-only proof ending in one complete device authority state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorityManifest {
    transitions: Vec<DeviceAuthorityTransition>,
}

impl DeviceAuthorityManifest {
    /// Create a root-authorized genesis with one fresh physical device.
    pub fn initial(
        root: &Identity,
        device: &Identity,
        name: String,
        issued_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let account = root.public();
        let certificate =
            DeviceAuthorityCertificate::issue(account.clone(), device, issued_at, rng)?;
        let entry = DeviceAuthorityEntry {
            certificate: certificate.clone(),
            name,
            last_seen: issued_at,
            revoked_at: None,
            revoked_after_counter: None,
        };
        let mut transition_id = [0u8; 16];
        fill_nonzero_16(&mut transition_id, rng);
        let mut transition = DeviceAuthorityTransition {
            version: DEVICE_AUTHORITY_VERSION,
            account,
            parent_hash: [0u8; 32],
            parent_generation: 0,
            generation: 1,
            recovery_epoch: 0,
            transition_id,
            recovery_id: None,
            kind: DeviceAuthorityTransitionKind::Genesis,
            devices: vec![entry],
            new_certificates: vec![certificate],
            authorization: DeviceAuthorityAuthorization::Root(DeviceAuthorityRootSignature {
                signature: [0u8; 64],
            }),
        };
        let signature = root.sign_domain(ROOT_TRANSITION_DOMAIN, &transition.canonical());
        transition.authorization =
            DeviceAuthorityAuthorization::Root(DeviceAuthorityRootSignature { signature });
        let manifest = Self {
            transitions: vec![transition],
        };
        manifest.verify()?;
        Ok(manifest)
    }

    /// Strict versioned encoding for storage and untrusted transport.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify()?;
        let body = postcard::to_allocvec(self).map_err(|_| CryptoError::Serialization)?;
        if body.len() > MAX_DEVICE_AUTHORITY_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let mut out = Vec::with_capacity(AUTHORITY_MAGIC.len() + body.len());
        out.extend_from_slice(AUTHORITY_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strictly decode, bound allocation, reject trailing bytes, and verify.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > AUTHORITY_MAGIC.len() + MAX_DEVICE_AUTHORITY_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let body = bytes
            .strip_prefix(AUTHORITY_MAGIC)
            .ok_or(CryptoError::Serialization)?;
        let (manifest, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(body).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() {
            return Err(CryptoError::Serialization);
        }
        manifest.verify()?;
        Ok(manifest)
    }

    /// Verify every transition from genesis through the current state.
    pub fn verify(&self) -> Result<()> {
        if self.transitions.is_empty() || self.transitions.len() > MAX_DEVICE_AUTHORITY_TRANSITIONS
        {
            return Err(CryptoError::InvalidMessage);
        }
        verify_genesis(&self.transitions[0])?;
        for pair in self.transitions.windows(2) {
            verify_transition(&pair[0], &pair[1], true)?;
        }
        Ok(())
    }

    /// Stable account public identity.
    pub fn account(&self) -> &IdentityPublic {
        &self.transitions[0].account
    }

    /// Current complete device state.
    pub fn devices(&self) -> &[DeviceAuthorityEntry] {
        &self
            .transitions
            .last()
            .expect("verified manifests are non-empty")
            .devices
    }

    /// Current manifest generation.
    pub fn generation(&self) -> u64 {
        self.transitions
            .last()
            .expect("verified manifests are non-empty")
            .generation
    }

    /// Greatest accepted recovery epoch in this proof.
    pub fn recovery_epoch(&self) -> u64 {
        self.transitions
            .last()
            .expect("verified manifests are non-empty")
            .recovery_epoch
    }

    /// Genesis or root-recovery transition anchoring the current epoch.
    pub fn recovery_anchor_id(&self) -> [u8; 32] {
        recovery_anchor(self, self.recovery_epoch())
            .expect("verified manifests always contain their epoch anchor")
    }

    /// Stable digest of the current exact transition.
    pub fn state_id(&self) -> [u8; 32] {
        self.transitions
            .last()
            .expect("verified manifests are non-empty")
            .transition_hash()
    }

    /// Exact immutable certificate for one active device.
    pub fn active_certificate(&self, device: &[u8; 32]) -> Option<&DeviceAuthorityCertificate> {
        self.devices()
            .iter()
            .find(|entry| entry.certificate.device_id() == *device && entry.is_active())
            .map(|entry| &entry.certificate)
    }

    /// Strict-majority threshold for the current active set.
    pub fn quorum_threshold(&self) -> usize {
        active_count(self.devices()) / 2 + 1
    }

    /// Propose adding one fresh candidate-owned certificate.
    pub fn propose_add_device(
        &self,
        certificate: DeviceAuthorityCertificate,
        name: String,
        last_seen: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityTransition> {
        self.verify()?;
        if certificate.account != *self.account()
            || self
                .devices()
                .iter()
                .any(|entry| entry.certificate.device_id() == certificate.device_id())
        {
            return Err(CryptoError::InvalidMessage);
        }
        let mut devices = self.devices().to_vec();
        devices.push(DeviceAuthorityEntry {
            certificate: certificate.clone(),
            name,
            last_seen,
            revoked_at: None,
            revoked_after_counter: None,
        });
        devices.sort_by_key(|entry| entry.certificate.device_id());
        self.ordinary_proposal(
            DeviceAuthorityTransitionKind::AddDevice,
            devices,
            vec![certificate],
            rng,
        )
    }

    /// Propose renaming exactly one active device.
    pub fn propose_rename_device(
        &self,
        device: &[u8; 32],
        name: String,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityTransition> {
        self.verify()?;
        let mut devices = self.devices().to_vec();
        let entry = devices
            .iter_mut()
            .find(|entry| entry.certificate.device_id() == *device && entry.is_active())
            .ok_or(CryptoError::InvalidMessage)?;
        entry.name = name;
        self.ordinary_proposal(
            DeviceAuthorityTransitionKind::RenameDevice,
            devices,
            Vec::new(),
            rng,
        )
    }

    /// Propose advancing one active device's coarse observation time.
    pub fn propose_observe_device(
        &self,
        device: &[u8; 32],
        last_seen: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityTransition> {
        self.verify()?;
        let mut devices = self.devices().to_vec();
        let entry = devices
            .iter_mut()
            .find(|entry| entry.certificate.device_id() == *device && entry.is_active())
            .ok_or(CryptoError::InvalidMessage)?;
        if last_seen <= entry.last_seen {
            return Err(CryptoError::InvalidMessage);
        }
        entry.last_seen = last_seen;
        self.ordinary_proposal(
            DeviceAuthorityTransitionKind::ObserveDevice,
            devices,
            Vec::new(),
            rng,
        )
    }

    /// Propose permanently revoking one active device.
    pub fn propose_revoke_device(
        &self,
        device: &[u8; 32],
        revoked_at: u64,
        last_accepted_counter: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityTransition> {
        self.verify()?;
        if active_count(self.devices()) <= 1 {
            return Err(CryptoError::InvalidMessage);
        }
        let mut devices = self.devices().to_vec();
        let entry = devices
            .iter_mut()
            .find(|entry| entry.certificate.device_id() == *device && entry.is_active())
            .ok_or(CryptoError::InvalidMessage)?;
        entry.revoked_at = Some(revoked_at.max(entry.certificate.issued_at));
        entry.revoked_after_counter = Some(last_accepted_counter);
        self.ordinary_proposal(
            DeviceAuthorityTransitionKind::RevokeDevice,
            devices,
            Vec::new(),
            rng,
        )
    }

    /// Add or replace one device approval on an ordinary proposal.
    pub fn sign_transition(
        &self,
        transition: &mut DeviceAuthorityTransition,
        signer: &Identity,
    ) -> Result<()> {
        self.verify()?;
        verify_transition(
            self.transitions
                .last()
                .expect("verified manifests are non-empty"),
            transition,
            false,
        )?;
        let signer_id = signer.public().ed;
        let certificate = self
            .active_certificate(&signer_id)
            .ok_or(CryptoError::InvalidKey)?;
        if certificate.device != signer.public() {
            return Err(CryptoError::InvalidKey);
        }
        let signature = signer.sign_domain(TRANSITION_DOMAIN, &transition.canonical());
        let DeviceAuthorityAuthorization::Devices(signatures) = &mut transition.authorization
        else {
            return Err(CryptoError::InvalidMessage);
        };
        if let Some(existing) = signatures
            .iter_mut()
            .find(|existing| existing.signer == signer_id)
        {
            existing.signature = signature;
        } else {
            signatures.push(DeviceAuthoritySignature {
                signer: signer_id,
                signature,
            });
            signatures.sort_by_key(|approval| approval.signer);
        }
        verify_transition(
            self.transitions
                .last()
                .expect("verified manifests are non-empty"),
            transition,
            false,
        )
    }

    /// Produce one detached approval for an ordinary proposal.
    pub fn approve_transition(
        &self,
        transition: &DeviceAuthorityTransition,
        signer: &Identity,
    ) -> Result<DeviceAuthoritySignature> {
        let mut candidate = transition.clone();
        self.sign_transition(&mut candidate, signer)?;
        let signer_id = signer.public().ed;
        let DeviceAuthorityAuthorization::Devices(signatures) = candidate.authorization else {
            return Err(CryptoError::InvalidMessage);
        };
        signatures
            .into_iter()
            .find(|signature| signature.signer == signer_id)
            .ok_or(CryptoError::InvalidSignature)
    }

    /// Merge one detached approval after verifying its signer and proposal.
    pub fn merge_approval(
        &self,
        transition: &mut DeviceAuthorityTransition,
        approval: DeviceAuthoritySignature,
    ) -> Result<()> {
        self.verify()?;
        let DeviceAuthorityAuthorization::Devices(signatures) = &mut transition.authorization
        else {
            return Err(CryptoError::InvalidMessage);
        };
        if signatures
            .iter()
            .any(|existing| existing.signer == approval.signer)
        {
            return Err(CryptoError::InvalidMessage);
        }
        signatures.push(approval);
        signatures.sort_by_key(|signature| signature.signer);
        verify_transition(
            self.transitions
                .last()
                .expect("verified manifests are non-empty"),
            transition,
            false,
        )
    }

    /// Whether a proposal contains a verified strict majority.
    pub fn has_quorum(&self, transition: &DeviceAuthorityTransition) -> Result<bool> {
        self.verify()?;
        verify_transition(
            self.transitions
                .last()
                .expect("verified manifests are non-empty"),
            transition,
            false,
        )?;
        Ok(transition.approval_count() >= self.quorum_threshold())
    }

    /// Verify and append one fully authorized direct child.
    pub fn append(&self, transition: DeviceAuthorityTransition) -> Result<DeviceAuthorityManifest> {
        self.verify()?;
        if self.transitions.len() >= MAX_DEVICE_AUTHORITY_TRANSITIONS {
            return Err(CryptoError::InvalidMessage);
        }
        verify_transition(
            self.transitions
                .last()
                .expect("verified manifests are non-empty"),
            &transition,
            true,
        )?;
        let mut transitions = self.transitions.clone();
        transitions.push(transition);
        let manifest = Self { transitions };
        manifest.verify()?;
        Ok(manifest)
    }

    /// Open the account root transiently to create a higher recovery epoch.
    ///
    /// Every formerly active certificate is revoked and exactly one fresh
    /// recovery device is introduced. The root is borrowed only for signing.
    pub fn recover(
        &self,
        root: &Identity,
        recovery_device: &Identity,
        name: String,
        recovered_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityManifest> {
        self.verify()?;
        if root.public() != *self.account()
            || self.transitions.len() >= MAX_DEVICE_AUTHORITY_TRANSITIONS
            || self.devices().len() >= MAX_AUTHORITY_ENTRIES
        {
            return Err(CryptoError::InvalidKey);
        }
        let certificate =
            DeviceAuthorityCertificate::issue(root.public(), recovery_device, recovered_at, rng)?;
        if self
            .devices()
            .iter()
            .any(|entry| entry.certificate.device_id() == certificate.device_id())
        {
            return Err(CryptoError::InvalidMessage);
        }
        let mut devices = self.devices().to_vec();
        for entry in &mut devices {
            if entry.is_active() {
                entry.revoked_at = Some(recovered_at.max(entry.certificate.issued_at));
                entry.revoked_after_counter = Some(0);
            }
        }
        devices.push(DeviceAuthorityEntry {
            certificate: certificate.clone(),
            name,
            last_seen: recovered_at,
            revoked_at: None,
            revoked_after_counter: None,
        });
        devices.sort_by_key(|entry| entry.certificate.device_id());
        let mut transition_id = [0u8; 16];
        let mut recovery_id = [0u8; 16];
        fill_nonzero_16(&mut transition_id, rng);
        fill_nonzero_16(&mut recovery_id, rng);
        let parent = self
            .transitions
            .last()
            .expect("verified manifests are non-empty");
        let mut transition = DeviceAuthorityTransition {
            version: DEVICE_AUTHORITY_VERSION,
            account: self.account().clone(),
            parent_hash: parent.transition_hash(),
            parent_generation: parent.generation,
            generation: parent
                .generation
                .checked_add(1)
                .ok_or(CryptoError::InvalidMessage)?,
            recovery_epoch: parent
                .recovery_epoch
                .checked_add(1)
                .ok_or(CryptoError::InvalidMessage)?,
            transition_id,
            recovery_id: Some(recovery_id),
            kind: DeviceAuthorityTransitionKind::Recovery,
            devices,
            new_certificates: vec![certificate],
            authorization: DeviceAuthorityAuthorization::Root(DeviceAuthorityRootSignature {
                signature: [0u8; 64],
            }),
        };
        let signature = root.sign_domain(ROOT_TRANSITION_DOMAIN, &transition.canonical());
        transition.authorization =
            DeviceAuthorityAuthorization::Root(DeviceAuthorityRootSignature { signature });
        self.append(transition)
    }

    /// Compare a verified candidate without selecting forks by ordering.
    pub fn relation(&self, candidate: &Self) -> Result<DeviceAuthorityRelation> {
        self.verify()?;
        candidate.verify()?;
        if self.account() != candidate.account() {
            return Err(CryptoError::InvalidKey);
        }
        if self.state_id() == candidate.state_id() {
            return Ok(DeviceAuthorityRelation::Same);
        }
        let local_epoch = self.recovery_epoch();
        let candidate_epoch = candidate.recovery_epoch();
        if candidate_epoch > local_epoch {
            return Ok(DeviceAuthorityRelation::RecoverySupersedes);
        }
        if candidate_epoch < local_epoch {
            return Ok(DeviceAuthorityRelation::OldEpoch);
        }
        if local_epoch > 0
            && recovery_anchor(self, local_epoch) != recovery_anchor(candidate, candidate_epoch)
        {
            return Ok(DeviceAuthorityRelation::RecoveryConflict);
        }
        let common = common_prefix_len(self, candidate);
        if common == self.transitions.len() {
            return Ok(DeviceAuthorityRelation::Descendant);
        }
        if common == candidate.transitions.len() {
            return Ok(DeviceAuthorityRelation::Stale);
        }
        Ok(DeviceAuthorityRelation::Fork)
    }

    fn ordinary_proposal(
        &self,
        kind: DeviceAuthorityTransitionKind,
        devices: Vec<DeviceAuthorityEntry>,
        new_certificates: Vec<DeviceAuthorityCertificate>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceAuthorityTransition> {
        if matches!(
            kind,
            DeviceAuthorityTransitionKind::Genesis | DeviceAuthorityTransitionKind::Recovery
        ) {
            return Err(CryptoError::InvalidMessage);
        }
        let parent = self
            .transitions
            .last()
            .expect("verified manifests are non-empty");
        let mut transition_id = [0u8; 16];
        fill_nonzero_16(&mut transition_id, rng);
        let transition = DeviceAuthorityTransition {
            version: DEVICE_AUTHORITY_VERSION,
            account: self.account().clone(),
            parent_hash: parent.transition_hash(),
            parent_generation: parent.generation,
            generation: parent
                .generation
                .checked_add(1)
                .ok_or(CryptoError::InvalidMessage)?,
            recovery_epoch: parent.recovery_epoch,
            transition_id,
            recovery_id: None,
            kind,
            devices,
            new_certificates,
            authorization: DeviceAuthorityAuthorization::Devices(Vec::new()),
        };
        verify_transition(parent, &transition, false)?;
        Ok(transition)
    }
}

fn verify_genesis(transition: &DeviceAuthorityTransition) -> Result<()> {
    validate_transition_common(transition)?;
    if transition.parent_hash != [0u8; 32]
        || transition.parent_generation != 0
        || transition.generation != 1
        || transition.recovery_epoch != 0
        || transition.recovery_id.is_some()
        || transition.kind != DeviceAuthorityTransitionKind::Genesis
        || transition.devices.len() != 1
        || transition.new_certificates.len() != 1
        || transition.devices[0].certificate != transition.new_certificates[0]
        || !transition.devices[0].is_active()
    {
        return Err(CryptoError::InvalidMessage);
    }
    let DeviceAuthorityAuthorization::Root(signature) = &transition.authorization else {
        return Err(CryptoError::InvalidMessage);
    };
    transition.account.verify_domain(
        ROOT_TRANSITION_DOMAIN,
        &transition.canonical(),
        &signature.signature,
    )
}

fn verify_transition(
    parent: &DeviceAuthorityTransition,
    candidate: &DeviceAuthorityTransition,
    require_quorum: bool,
) -> Result<()> {
    validate_transition_common(candidate)?;
    if candidate.account != parent.account
        || candidate.parent_hash != parent.transition_hash()
        || candidate.parent_generation != parent.generation
        || candidate.generation != parent.generation.checked_add(1).unwrap_or(0)
    {
        return Err(CryptoError::InvalidMessage);
    }
    validate_parent_continuity(&parent.devices, &candidate.devices)?;
    validate_new_certificates(parent, candidate)?;
    match candidate.kind {
        DeviceAuthorityTransitionKind::Genesis => Err(CryptoError::InvalidMessage),
        DeviceAuthorityTransitionKind::Recovery => {
            if candidate.recovery_epoch != parent.recovery_epoch.checked_add(1).unwrap_or(0)
                || candidate.recovery_id.is_none_or(|id| id == [0u8; 16])
            {
                return Err(CryptoError::InvalidMessage);
            }
            validate_recovery_difference(parent, candidate)?;
            let DeviceAuthorityAuthorization::Root(signature) = &candidate.authorization else {
                return Err(CryptoError::InvalidMessage);
            };
            candidate.account.verify_domain(
                ROOT_TRANSITION_DOMAIN,
                &candidate.canonical(),
                &signature.signature,
            )
        }
        kind => {
            if candidate.recovery_epoch != parent.recovery_epoch || candidate.recovery_id.is_some()
            {
                return Err(CryptoError::InvalidMessage);
            }
            validate_ordinary_difference(kind, &parent.devices, &candidate.devices)?;
            let DeviceAuthorityAuthorization::Devices(signatures) = &candidate.authorization else {
                return Err(CryptoError::InvalidMessage);
            };
            if signatures.len() > active_count(&parent.devices) {
                return Err(CryptoError::InvalidMessage);
            }
            let mut prior = None;
            for signature in signatures {
                if prior.is_some_and(|value| value >= signature.signer) {
                    return Err(CryptoError::InvalidMessage);
                }
                let signer = parent
                    .devices
                    .iter()
                    .find(|entry| {
                        entry.certificate.device_id() == signature.signer && entry.is_active()
                    })
                    .ok_or(CryptoError::InvalidSignature)?;
                signer.certificate.device.verify_domain(
                    TRANSITION_DOMAIN,
                    &candidate.canonical(),
                    &signature.signature,
                )?;
                prior = Some(signature.signer);
            }
            if require_quorum && signatures.len() < active_count(&parent.devices) / 2 + 1 {
                return Err(CryptoError::InvalidSignature);
            }
            Ok(())
        }
    }
}

fn validate_transition_common(transition: &DeviceAuthorityTransition) -> Result<()> {
    transition.account.verify()?;
    if transition.version != DEVICE_AUTHORITY_VERSION
        || transition.transition_id == [0u8; 16]
        || transition.devices.is_empty()
        || transition.devices.len() > MAX_AUTHORITY_ENTRIES
        || transition.new_certificates.len() > MAX_AUTHORITY_DEVICES
    {
        return Err(CryptoError::InvalidMessage);
    }
    validate_state(&transition.account, &transition.devices)?;
    let mut prior = None;
    for certificate in &transition.new_certificates {
        certificate.verify()?;
        if certificate.account != transition.account
            || prior.is_some_and(|value| value >= certificate.device_id())
        {
            return Err(CryptoError::InvalidMessage);
        }
        prior = Some(certificate.device_id());
    }
    Ok(())
}

fn validate_state(account: &IdentityPublic, devices: &[DeviceAuthorityEntry]) -> Result<()> {
    let mut prior = None;
    let mut active = 0usize;
    for entry in devices {
        entry.certificate.verify()?;
        if &entry.certificate.account != account
            || entry.name.is_empty()
            || entry.name.len() > MAX_AUTHORITY_DEVICE_NAME_BYTES
            || entry.last_seen < entry.certificate.issued_at
            || entry
                .revoked_at
                .is_some_and(|value| value < entry.certificate.issued_at)
            || entry.revoked_at.is_some() != entry.revoked_after_counter.is_some()
            || prior.is_some_and(|value| value >= entry.certificate.device_id())
        {
            return Err(CryptoError::InvalidMessage);
        }
        prior = Some(entry.certificate.device_id());
        if entry.is_active() {
            active += 1;
        }
    }
    if active == 0 || active > MAX_AUTHORITY_DEVICES {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(())
}

fn validate_parent_continuity(
    parent: &[DeviceAuthorityEntry],
    candidate: &[DeviceAuthorityEntry],
) -> Result<()> {
    for old in parent {
        let new = candidate
            .iter()
            .find(|entry| entry.certificate.device_id() == old.certificate.device_id())
            .ok_or(CryptoError::InvalidMessage)?;
        if new.certificate != old.certificate
            || (old.revoked_at.is_some() && new.revoked_at != old.revoked_at)
            || (old.revoked_after_counter.is_some()
                && new.revoked_after_counter != old.revoked_after_counter)
            || new.last_seen < old.last_seen
        {
            return Err(CryptoError::InvalidMessage);
        }
    }
    Ok(())
}

fn validate_new_certificates(
    parent: &DeviceAuthorityTransition,
    candidate: &DeviceAuthorityTransition,
) -> Result<()> {
    let introduced = candidate
        .devices
        .iter()
        .filter(|entry| {
            !parent
                .devices
                .iter()
                .any(|old| old.certificate.device_id() == entry.certificate.device_id())
        })
        .map(|entry| entry.certificate.clone())
        .collect::<Vec<_>>();
    if introduced != candidate.new_certificates {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(())
}

fn validate_ordinary_difference(
    kind: DeviceAuthorityTransitionKind,
    parent: &[DeviceAuthorityEntry],
    candidate: &[DeviceAuthorityEntry],
) -> Result<()> {
    let introduced = candidate.len().saturating_sub(parent.len());
    let mut renamed = 0usize;
    let mut observed = 0usize;
    let mut revoked = 0usize;
    for old in parent {
        let new = candidate
            .iter()
            .find(|entry| entry.certificate.device_id() == old.certificate.device_id())
            .ok_or(CryptoError::InvalidMessage)?;
        if new == old {
            continue;
        }
        if old.is_active()
            && new.is_active()
            && new.name != old.name
            && new.last_seen == old.last_seen
        {
            let mut expected = old.clone();
            expected.name = new.name.clone();
            if &expected == new {
                renamed += 1;
                continue;
            }
        }
        if old.is_active()
            && new.is_active()
            && new.name == old.name
            && new.last_seen > old.last_seen
        {
            let mut expected = old.clone();
            expected.last_seen = new.last_seen;
            if &expected == new {
                observed += 1;
                continue;
            }
        }
        if old.is_active()
            && !new.is_active()
            && new.name == old.name
            && new.last_seen == old.last_seen
        {
            let mut expected = old.clone();
            expected.revoked_at = new.revoked_at;
            expected.revoked_after_counter = new.revoked_after_counter;
            if &expected == new {
                revoked += 1;
                continue;
            }
        }
        return Err(CryptoError::InvalidMessage);
    }
    let valid = match kind {
        DeviceAuthorityTransitionKind::AddDevice => {
            introduced == 1 && renamed == 0 && observed == 0 && revoked == 0
        }
        DeviceAuthorityTransitionKind::RenameDevice => {
            introduced == 0 && renamed == 1 && observed == 0 && revoked == 0
        }
        DeviceAuthorityTransitionKind::ObserveDevice => {
            introduced == 0 && renamed == 0 && observed == 1 && revoked == 0
        }
        DeviceAuthorityTransitionKind::RevokeDevice => {
            introduced == 0 && renamed == 0 && observed == 0 && revoked == 1
        }
        DeviceAuthorityTransitionKind::ReplaceDevice => {
            introduced == 1 && renamed == 0 && observed == 0 && revoked == 1
        }
        DeviceAuthorityTransitionKind::Genesis | DeviceAuthorityTransitionKind::Recovery => false,
    };
    if !valid {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(())
}

fn validate_recovery_difference(
    parent: &DeviceAuthorityTransition,
    candidate: &DeviceAuthorityTransition,
) -> Result<()> {
    if candidate.new_certificates.len() != 1
        || candidate.devices.len() != parent.devices.len() + 1
        || active_count(&candidate.devices) != 1
    {
        return Err(CryptoError::InvalidMessage);
    }
    let recovery_device = candidate.new_certificates[0].device_id();
    for old in &parent.devices {
        let new = candidate
            .devices
            .iter()
            .find(|entry| entry.certificate.device_id() == old.certificate.device_id())
            .ok_or(CryptoError::InvalidMessage)?;
        if old.is_active() {
            if new.is_active() || new.name != old.name || new.last_seen != old.last_seen {
                return Err(CryptoError::InvalidMessage);
            }
        } else if new != old {
            return Err(CryptoError::InvalidMessage);
        }
    }
    let fresh = candidate
        .devices
        .iter()
        .find(|entry| entry.certificate.device_id() == recovery_device)
        .ok_or(CryptoError::InvalidMessage)?;
    if !fresh.is_active() {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(())
}

fn active_count(devices: &[DeviceAuthorityEntry]) -> usize {
    devices.iter().filter(|entry| entry.is_active()).count()
}

fn common_prefix_len(left: &DeviceAuthorityManifest, right: &DeviceAuthorityManifest) -> usize {
    left.transitions
        .iter()
        .zip(&right.transitions)
        .take_while(|(left, right)| left.transition_hash() == right.transition_hash())
        .count()
}

fn recovery_anchor(manifest: &DeviceAuthorityManifest, epoch: u64) -> Option<[u8; 32]> {
    if epoch == 0 {
        return manifest
            .transitions
            .first()
            .map(DeviceAuthorityTransition::transition_hash);
    }
    manifest
        .transitions
        .iter()
        .find(|transition| {
            transition.recovery_epoch == epoch
                && transition.kind == DeviceAuthorityTransitionKind::Recovery
        })
        .map(DeviceAuthorityTransition::transition_hash)
}

fn append_identity(out: &mut Vec<u8>, identity: &IdentityPublic) {
    out.extend_from_slice(&identity.ed);
    out.extend_from_slice(&identity.x);
    out.extend_from_slice(&identity.cross_sig);
}

fn append_entry(out: &mut Vec<u8>, entry: &DeviceAuthorityEntry) {
    let certificate = entry.certificate.canonical();
    out.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
    out.extend_from_slice(&certificate);
    out.extend_from_slice(&entry.certificate.device_signature);
    out.extend_from_slice(&(entry.name.len() as u32).to_le_bytes());
    out.extend_from_slice(entry.name.as_bytes());
    out.extend_from_slice(&entry.last_seen.to_le_bytes());
    match entry.revoked_at {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
    match entry.revoked_after_counter {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn fill_nonzero_16(value: &mut [u8; 16], rng: &mut impl CryptoRngCore) {
    loop {
        rng.fill_bytes(value);
        if *value != [0u8; 16] {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn add_device(
        manifest: &DeviceAuthorityManifest,
        signer: &Identity,
        device: &Identity,
        issued_at: u64,
        rng: &mut StdRng,
    ) -> DeviceAuthorityManifest {
        let certificate =
            DeviceAuthorityCertificate::issue(manifest.account().clone(), device, issued_at, rng)
                .unwrap();
        let mut proposal = manifest
            .propose_add_device(
                certificate,
                alloc::format!("Device {issued_at}"),
                issued_at,
                rng,
            )
            .unwrap();
        manifest.sign_transition(&mut proposal, signer).unwrap();
        manifest.append(proposal).unwrap()
    }

    #[test]
    fn genesis_and_codec_bind_the_offline_root() {
        let mut rng = StdRng::seed_from_u64(2601);
        let root = Identity::generate(&mut rng);
        let device = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &device, "Phone".into(), 10, &mut rng).unwrap();
        assert_eq!(manifest.account(), &root.public());
        assert_eq!(manifest.devices()[0].certificate.device, device.public());
        assert_eq!(manifest.quorum_threshold(), 1);
        assert_eq!(
            DeviceAuthorityManifest::decode(&manifest.encode().unwrap()).unwrap(),
            manifest
        );
    }

    #[test]
    fn two_active_devices_require_both_approvals() {
        let mut rng = StdRng::seed_from_u64(2602);
        let root = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let third = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &first, "Phone".into(), 10, &mut rng).unwrap();
        let manifest = add_device(&manifest, &first, &second, 11, &mut rng);
        assert_eq!(manifest.quorum_threshold(), 2);

        let certificate =
            DeviceAuthorityCertificate::issue(root.public(), &third, 12, &mut rng).unwrap();
        let mut proposal = manifest
            .propose_add_device(certificate, "Tablet".into(), 12, &mut rng)
            .unwrap();
        manifest.sign_transition(&mut proposal, &first).unwrap();
        assert!(!manifest.has_quorum(&proposal).unwrap());
        assert!(manifest.append(proposal.clone()).is_err());
        manifest.sign_transition(&mut proposal, &second).unwrap();
        assert!(manifest.has_quorum(&proposal).unwrap());
        assert!(manifest.append(proposal).is_ok());
    }

    #[test]
    fn concurrent_children_are_visible_forks() {
        let mut rng = StdRng::seed_from_u64(2603);
        let root = Identity::generate(&mut rng);
        let device = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &device, "Phone".into(), 10, &mut rng).unwrap();
        let mut first = manifest
            .propose_rename_device(&device.public().ed, "First".into(), &mut rng)
            .unwrap();
        manifest.sign_transition(&mut first, &device).unwrap();
        let first = manifest.append(first).unwrap();
        let mut second = manifest
            .propose_rename_device(&device.public().ed, "Second".into(), &mut rng)
            .unwrap();
        manifest.sign_transition(&mut second, &device).unwrap();
        let second = manifest.append(second).unwrap();
        assert_eq!(
            first.relation(&second).unwrap(),
            DeviceAuthorityRelation::Fork
        );
        assert_eq!(
            second.relation(&first).unwrap(),
            DeviceAuthorityRelation::Fork
        );
    }

    #[test]
    fn revoked_device_cannot_authorize_a_replacement() {
        let mut rng = StdRng::seed_from_u64(2604);
        let root = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let replacement = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &first, "Phone".into(), 10, &mut rng).unwrap();
        let manifest = add_device(&manifest, &first, &second, 11, &mut rng);
        let mut revoke = manifest
            .propose_revoke_device(&first.public().ed, 12, 7, &mut rng)
            .unwrap();
        manifest.sign_transition(&mut revoke, &first).unwrap();
        manifest.sign_transition(&mut revoke, &second).unwrap();
        let manifest = manifest.append(revoke).unwrap();
        let certificate =
            DeviceAuthorityCertificate::issue(root.public(), &replacement, 13, &mut rng).unwrap();
        let mut proposal = manifest
            .propose_add_device(certificate, "Replacement".into(), 13, &mut rng)
            .unwrap();
        assert!(manifest.sign_transition(&mut proposal, &first).is_err());
        manifest.sign_transition(&mut proposal, &second).unwrap();
        assert!(manifest.has_quorum(&proposal).unwrap());
    }

    #[test]
    fn recovery_supersedes_old_epoch_and_conflicts_at_same_epoch() {
        let mut rng = StdRng::seed_from_u64(2605);
        let root = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let recovery_a = Identity::generate(&mut rng);
        let recovery_b = Identity::generate(&mut rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &first, "Phone".into(), 10, &mut rng).unwrap();
        let manifest = add_device(&manifest, &first, &second, 11, &mut rng);

        let recovered_a = manifest
            .recover(&root, &recovery_a, "Recovered".into(), 20, &mut rng)
            .unwrap();
        assert_eq!(
            manifest.relation(&recovered_a).unwrap(),
            DeviceAuthorityRelation::RecoverySupersedes
        );
        assert_eq!(
            recovered_a.relation(&manifest).unwrap(),
            DeviceAuthorityRelation::OldEpoch
        );

        let recovered_b = manifest
            .recover(&root, &recovery_b, "Other recovery".into(), 20, &mut rng)
            .unwrap();
        assert_eq!(
            recovered_a.relation(&recovered_b).unwrap(),
            DeviceAuthorityRelation::RecoveryConflict
        );
    }

    #[test]
    fn replay_and_stale_ancestor_never_advance_authority() {
        let mut rng = StdRng::seed_from_u64(2606);
        let root = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let genesis =
            DeviceAuthorityManifest::initial(&root, &first, "Phone".into(), 10, &mut rng).unwrap();
        let successor = add_device(&genesis, &first, &second, 11, &mut rng);
        assert_eq!(
            successor.relation(&successor).unwrap(),
            DeviceAuthorityRelation::Same
        );
        assert_eq!(
            successor.relation(&genesis).unwrap(),
            DeviceAuthorityRelation::Stale
        );
        assert_eq!(
            genesis.relation(&successor).unwrap(),
            DeviceAuthorityRelation::Descendant
        );
    }
}
