//! Sealed, non-backup ADR-0019 relationship wake state.
//!
//! Rows are bound to one physical-device ratchet session. They contain only
//! opaque fixed-width capabilities, provider descriptors, expiry, and bounded
//! local retry state; backups deliberately omit the complete table.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use kult_crypto::Session;
use kult_protocol::{
    canonical_wake_https_origin, wake_provider_id, WakeCapability, WAKE_CAPABILITY_LEN,
};

use crate::{decode_exact, store_v2, Result, Store, StoreError};

/// Current sealed wake-state version.
pub const WAKE_SERVICE_STATE_VERSION: u8 = 1;
/// Maximum capabilities retained in either direction for one device session.
pub const MAX_WAKE_CAPABILITIES_PER_SESSION: usize = 4;
/// Maximum encoded wake service-state bytes for one device session.
pub const MAX_WAKE_SERVICE_STATE_BYTES: usize = 16 * 1024;
/// Current durable wake-revocation record version.
pub const WAKE_REVOCATION_RECORD_VERSION: u8 = 1;
/// Maximum unacknowledged gateway revocations retained by one installation.
pub const MAX_WAKE_REVOCATION_ROWS: usize = 4_096;
/// Maximum encoded bytes in one sealed gateway-revocation row.
pub const MAX_WAKE_REVOCATION_RECORD_BYTES: usize = 2 * 1024;

/// Relationship direction for one per-contact capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WakeCapabilityDirection {
    /// Capability the contact supplied so this device can wake them.
    Remote = 1,
    /// Capability this device issued and supplied to the contact.
    Issued = 2,
}

/// One sealed provider-scoped capability and bounded local retry state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeStoredCapability {
    /// Relationship direction.
    pub direction: WakeCapabilityDirection,
    /// Canonical gateway HTTPS origin.
    pub origin: String,
    /// Gateway leaf-certificate SHA-256 pin.
    pub static_key: [u8; 32],
    /// Provider-separation id.
    pub provider_id: [u8; 32],
    /// Exact opaque encrypted capability.
    pub capability: Vec<u8>,
    /// Capability expiry as authenticated by the pairwise control.
    pub expires_at: u64,
    /// Whether one next-hop-accepted message is waiting for a wake attempt.
    pub pending: bool,
    /// First coarse time in the current coalesced pending window.
    pub pending_since: u64,
    /// Earliest next local trigger attempt.
    pub next_attempt_at: u64,
    /// Consecutive bounded client failures.
    pub consecutive_failures: u8,
}

impl WakeStoredCapability {
    /// Construct a fresh provider-scoped capability.
    pub fn new(
        direction: WakeCapabilityDirection,
        origin: String,
        static_key: [u8; 32],
        capability: Vec<u8>,
        expires_at: u64,
    ) -> Result<Self> {
        let provider_id =
            wake_provider_id(origin.as_bytes(), &static_key).map_err(StoreError::from)?;
        let value = Self {
            direction,
            origin,
            static_key,
            provider_id,
            capability,
            expires_at,
            pending: false,
            pending_since: 0,
            next_attempt_at: 0,
            consecutive_failures: 0,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decode the exact public capability frame.
    pub fn decoded_capability(&self) -> Result<WakeCapability> {
        WakeCapability::from_bytes(&self.capability).map_err(StoreError::from)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !canonical_wake_https_origin(&self.origin)
            || self.static_key == [0u8; 32]
            || wake_provider_id(self.origin.as_bytes(), &self.static_key)
                .map_err(StoreError::from)?
                != self.provider_id
            || self.capability.len() != WAKE_CAPABILITY_LEN
            || self.expires_at == 0
            || self.consecutive_failures > 16
            || (!self.pending
                && (self.pending_since != 0
                    || self.next_attempt_at != 0
                    || self.consecutive_failures != 0))
            || (self.pending && (self.pending_since == 0 || self.next_attempt_at == 0))
            || self.next_attempt_at > self.expires_at
        {
            return Err(StoreError::RecordBounds);
        }
        self.decoded_capability()?;
        Ok(())
    }

    /// Mark coalesced wake work after an eligible next-hop acceptance.
    pub fn mark_pending(&mut self, now: u64) -> Result<()> {
        if now == 0 || now >= self.expires_at {
            return Err(StoreError::RecordBounds);
        }
        if !self.pending {
            self.pending = true;
            self.pending_since = now;
            self.next_attempt_at = now;
            self.consecutive_failures = 0;
        }
        self.validate()
    }

    /// Clear local work after one generic gateway acknowledgement.
    pub fn mark_attempted(&mut self) {
        self.pending = false;
        self.pending_since = 0;
        self.next_attempt_at = 0;
        self.consecutive_failures = 0;
    }

    /// Pace a bounded local client failure without changing message state.
    pub fn mark_failed(&mut self, now: u64) -> Result<()> {
        if !self.pending || now == 0 || now >= self.expires_at {
            return Err(StoreError::RecordBounds);
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1).min(16);
        let delay = (5u64 << self.consecutive_failures.min(8)).min(15 * 60);
        self.next_attempt_at = now.saturating_add(delay).min(self.expires_at);
        self.validate()
    }
}

impl Drop for WakeStoredCapability {
    fn drop(&mut self) {
        self.origin.zeroize();
        self.capability.zeroize();
    }
}

/// One identity-free, durable gateway revocation retry.
///
/// The equality key is a store-scoped digest of the provider and opaque
/// capability. The row deliberately contains no account, device,
/// conversation, message, or social-label identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeRevocationRecord {
    /// Storage format version.
    pub version: u8,
    /// Store-scoped deterministic equality key.
    pub id: [u8; 32],
    /// Canonical gateway HTTPS origin.
    pub origin: String,
    /// Gateway leaf-certificate SHA-256 pin.
    pub static_key: [u8; 32],
    /// Provider-separation id.
    pub provider_id: [u8; 32],
    /// Exact opaque capability revoked by possession.
    pub capability: Vec<u8>,
    /// Capability expiry after which no gateway state can remain live.
    pub expires_at: u64,
    /// Earliest next bounded retry.
    pub next_attempt_at: u64,
    /// Consecutive bounded client failures.
    pub consecutive_failures: u8,
}

impl WakeRevocationRecord {
    fn from_issued(id: [u8; 32], capability: &WakeStoredCapability) -> Result<Self> {
        if capability.direction != WakeCapabilityDirection::Issued {
            return Err(StoreError::InvalidTransition);
        }
        let record = Self {
            version: WAKE_REVOCATION_RECORD_VERSION,
            id,
            origin: capability.origin.clone(),
            static_key: capability.static_key,
            provider_id: capability.provider_id,
            capability: capability.capability.clone(),
            expires_at: capability.expires_at,
            next_attempt_at: 1,
            consecutive_failures: 0,
        };
        record.validate()?;
        Ok(record)
    }

    /// Decode the exact public capability frame used by the revoke request.
    pub fn decoded_capability(&self) -> Result<WakeCapability> {
        WakeCapability::from_bytes(&self.capability).map_err(StoreError::from)
    }

    /// Pace a failed revoke without changing any message or delivery state.
    pub fn mark_failed(&mut self, now: u64) -> Result<()> {
        if now == 0 || now >= self.expires_at {
            return Err(StoreError::RecordBounds);
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1).min(16);
        let delay = (5u64 << self.consecutive_failures.min(8)).min(15 * 60);
        self.next_attempt_at = now.saturating_add(delay).min(self.expires_at);
        self.validate()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != WAKE_REVOCATION_RECORD_VERSION
            || self.id == [0u8; 32]
            || !canonical_wake_https_origin(&self.origin)
            || self.static_key == [0u8; 32]
            || wake_provider_id(self.origin.as_bytes(), &self.static_key)
                .map_err(StoreError::from)?
                != self.provider_id
            || self.capability.len() != WAKE_CAPABILITY_LEN
            || self.expires_at == 0
            || self.next_attempt_at == 0
            || self.next_attempt_at > self.expires_at
            || self.consecutive_failures > 16
        {
            return Err(StoreError::RecordBounds);
        }
        self.decoded_capability()?;
        let encoded =
            Zeroizing::new(postcard::to_allocvec(self).map_err(|_| StoreError::Serialization)?);
        if encoded.len() > MAX_WAKE_REVOCATION_RECORD_BYTES {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        same_wake_revocation_authority(self, other)
    }
}

impl Drop for WakeRevocationRecord {
    fn drop(&mut self) {
        self.origin.zeroize();
        self.capability.zeroize();
    }
}

/// Complete wake state bound to one verified physical-device session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeServiceState {
    /// Storage format version.
    pub version: u8,
    /// Exact ratchet session id owning the authenticated capability controls.
    pub session_id: [u8; 32],
    /// Greatest accepted complete remote capability generation.
    pub remote_generation: u64,
    /// Same-generation conflict retained fail closed.
    pub remote_conflict_generation: Option<u64>,
    /// Greatest complete local issuance generation.
    pub issued_generation: u64,
    /// Bounded capabilities in both directions.
    pub capabilities: Vec<WakeStoredCapability>,
}

impl WakeServiceState {
    fn fresh(session: &Session) -> Self {
        Self {
            version: WAKE_SERVICE_STATE_VERSION,
            session_id: *session.session_id(),
            remote_generation: 0,
            remote_conflict_generation: None,
            issued_generation: 0,
            capabilities: Vec::new(),
        }
    }

    /// Capabilities supplied by the remote physical device.
    pub fn remote(&self) -> impl Iterator<Item = &WakeStoredCapability> {
        self.capabilities
            .iter()
            .filter(|capability| capability.direction == WakeCapabilityDirection::Remote)
    }

    /// Mutable capabilities supplied by the remote physical device.
    pub fn remote_mut(&mut self) -> impl Iterator<Item = &mut WakeStoredCapability> {
        self.capabilities
            .iter_mut()
            .filter(|capability| capability.direction == WakeCapabilityDirection::Remote)
    }

    /// Capabilities this physical device issued to the remote.
    pub fn issued(&self) -> impl Iterator<Item = &WakeStoredCapability> {
        self.capabilities
            .iter()
            .filter(|capability| capability.direction == WakeCapabilityDirection::Issued)
    }

    /// Atomically replace one complete direction and generation.
    pub fn replace_direction(
        &mut self,
        direction: WakeCapabilityDirection,
        generation: u64,
        mut capabilities: Vec<WakeStoredCapability>,
    ) -> Result<()> {
        if generation == 0
            || capabilities.len() > MAX_WAKE_CAPABILITIES_PER_SESSION
            || capabilities
                .iter()
                .any(|capability| capability.direction != direction)
        {
            return Err(StoreError::RecordBounds);
        }
        capabilities.sort_by_key(|capability| capability.provider_id);
        if capabilities
            .windows(2)
            .any(|pair| pair[0].provider_id == pair[1].provider_id)
        {
            return Err(StoreError::Serialization);
        }
        let current_generation = match direction {
            WakeCapabilityDirection::Remote => self.remote_generation,
            WakeCapabilityDirection::Issued => self.issued_generation,
        };
        if generation < current_generation {
            return Err(StoreError::InvalidTransition);
        }
        if generation == current_generation {
            let current = self
                .capabilities
                .iter()
                .filter(|capability| capability.direction == direction)
                .collect::<Vec<_>>();
            let same_complete_set = current.len() == capabilities.len()
                && current
                    .iter()
                    .zip(&capabilities)
                    .all(|(left, right)| same_authenticated_capability(left, right));
            if same_complete_set {
                return Ok(());
            }
            return match direction {
                WakeCapabilityDirection::Remote => {
                    self.remote_conflict_generation = Some(generation);
                    self.capabilities
                        .retain(|capability| capability.direction != direction);
                    self.validate()
                }
                WakeCapabilityDirection::Issued => Err(StoreError::InvalidTransition),
            };
        }
        self.capabilities
            .retain(|capability| capability.direction != direction);
        self.capabilities.extend(capabilities);
        match direction {
            WakeCapabilityDirection::Remote => {
                self.remote_generation = generation;
                self.remote_conflict_generation = None;
            }
            WakeCapabilityDirection::Issued => self.issued_generation = generation,
        }
        self.capabilities
            .sort_by_key(|capability| (capability.direction as u8, capability.provider_id));
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        if self.version != WAKE_SERVICE_STATE_VERSION
            || self
                .remote_conflict_generation
                .is_some_and(|generation| generation < self.remote_generation || generation == 0)
            || self.capabilities.len() > 2 * MAX_WAKE_CAPABILITIES_PER_SESSION
        {
            return Err(StoreError::Serialization);
        }
        let mut remote_count = 0usize;
        let mut issued_count = 0usize;
        for (index, capability) in self.capabilities.iter().enumerate() {
            capability.validate()?;
            match capability.direction {
                WakeCapabilityDirection::Remote => remote_count += 1,
                WakeCapabilityDirection::Issued => issued_count += 1,
            }
            if self.capabilities[..index].iter().any(|prior| {
                prior.direction == capability.direction
                    && prior.provider_id == capability.provider_id
            }) {
                return Err(StoreError::Serialization);
            }
        }
        if remote_count > MAX_WAKE_CAPABILITIES_PER_SESSION
            || issued_count > MAX_WAKE_CAPABILITIES_PER_SESSION
            || (remote_count > 0 && self.remote_generation == 0)
            || (issued_count > 0 && self.issued_generation == 0)
        {
            return Err(StoreError::RecordBounds);
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(self).map_err(|_| StoreError::Serialization)?);
        if encoded.len() > MAX_WAKE_SERVICE_STATE_BYTES {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

fn same_authenticated_capability(
    left: &WakeStoredCapability,
    right: &WakeStoredCapability,
) -> bool {
    left.direction == right.direction
        && left.origin == right.origin
        && left.static_key == right.static_key
        && left.provider_id == right.provider_id
        && left.capability == right.capability
        && left.expires_at == right.expires_at
}

impl Store {
    pub(crate) fn validate_wake_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::WakeServiceRows, _>(|row| {
            let _ = store_v2::AccountKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let state: WakeServiceState = decode_exact(&row.payload)?;
            state.validate()
        })?;
        let mut count = 0usize;
        self.validate_rows::<store_v2::WakeRevocationRows, _>(|row| {
            count = count.checked_add(1).ok_or(StoreError::RecordBounds)?;
            if count > MAX_WAKE_REVOCATION_ROWS {
                return Err(StoreError::RecordBounds);
            }
            let record: WakeRevocationRecord = decode_exact(&row.payload)?;
            record.validate()?;
            let id = self.wake_revocation_id(&record.provider_id, &record.capability);
            if record.id != id {
                return Err(StoreError::LogicalKeyMismatch);
            }
            row.verify_key(&store_v2::DigestKey::new(id))?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })
    }

    pub(crate) fn synchronize_wake_session(
        &self,
        peer: &[u8; 32],
        session: &Session,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let current = self.get_wake_service_state(peer)?;
        if current
            .as_ref()
            .is_some_and(|state| state.session_id == *session.session_id())
        {
            return Ok(());
        }
        if let Some(current) = current.as_ref() {
            self.enqueue_issued_wake_revocations(current, rng)?;
        }
        self.write_wake_service_state(peer, &WakeServiceState::fresh(session), rng)
    }

    /// Ensure a legacy session has an empty, exact-session wake row.
    ///
    /// Existing matching state is untouched. A changed session id replaces
    /// every prior capability, which prevents restore or re-handshake reuse.
    pub fn ensure_wake_service_state(
        &self,
        peer: &[u8; 32],
        session: &Session,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.synchronize_wake_session(peer, session, rng)
    }

    /// Load one separately sealed, session-bound wake row.
    pub fn get_wake_service_state(&self, peer: &[u8; 32]) -> Result<Option<WakeServiceState>> {
        let state = self
            .get_equality::<store_v2::WakeServiceRows>(&store_v2::AccountKey::new(*peer))?
            .map(|row| decode_exact::<WakeServiceState>(&row.payload))
            .transpose()?;
        if let Some(state) = state.as_ref() {
            state.validate()?;
        }
        Ok(state)
    }

    /// Replace one complete wake row after validating its current session.
    pub fn put_wake_service_state(
        &self,
        peer: &[u8; 32],
        state: &WakeServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        state.validate()?;
        let session = self.get_session_ratchet(peer)?;
        if session
            .as_ref()
            .is_none_or(|session| state.session_id != *session.session_id())
        {
            return Err(StoreError::LogicalKeyMismatch);
        }
        if let Some(current) = self.get_wake_service_state(peer)? {
            self.enqueue_retired_wake_revocations(&current, state, rng)?;
        }
        self.write_wake_service_state(peer, state, rng)
    }

    pub(crate) fn write_wake_service_state(
        &self,
        peer: &[u8; 32],
        state: &WakeServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        state.validate()?;
        let encoded =
            Zeroizing::new(postcard::to_allocvec(state).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::WakeServiceRows>(
            &store_v2::AccountKey::new(*peer),
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    pub(crate) fn delete_wake_service_state(&self, peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::WakeServiceRows>(&store_v2::AccountKey::new(*peer))?;
        Ok(())
    }

    fn wake_revocation_id(&self, provider_id: &[u8; 32], capability: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(31 + provider_id.len() + capability.len());
        input.extend_from_slice(b"Komms-Wake-Revocation-Row-v1");
        input.extend_from_slice(provider_id);
        input.extend_from_slice(capability);
        self.index_root.hmac_sha256(&input)
    }

    pub(crate) fn retired_wake_revocations(
        &self,
        before: &WakeServiceState,
        after: Option<&WakeServiceState>,
    ) -> Result<Vec<WakeRevocationRecord>> {
        let retained = after
            .into_iter()
            .flat_map(WakeServiceState::issued)
            .collect::<Vec<_>>();
        before
            .issued()
            .filter(|capability| {
                !retained
                    .iter()
                    .any(|candidate| same_authenticated_capability(capability, candidate))
            })
            .map(|capability| {
                WakeRevocationRecord::from_issued(
                    self.wake_revocation_id(&capability.provider_id, &capability.capability),
                    capability,
                )
            })
            .collect()
    }

    pub(crate) fn enqueue_issued_wake_revocations(
        &self,
        state: &WakeServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for record in self.retired_wake_revocations(state, None)? {
            self.enqueue_wake_revocation(&record, rng)?;
        }
        Ok(())
    }

    pub(crate) fn enqueue_retired_wake_revocations(
        &self,
        before: &WakeServiceState,
        after: &WakeServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for record in self.retired_wake_revocations(before, Some(after))? {
            self.enqueue_wake_revocation(&record, rng)?;
        }
        Ok(())
    }

    /// Return a bounded stable page of pending gateway revocations.
    pub fn wake_revocations(&self, limit: usize) -> Result<Vec<WakeRevocationRecord>> {
        if limit == 0 || limit > MAX_WAKE_REVOCATION_ROWS {
            return Err(StoreError::RecordBounds);
        }
        self.rows::<store_v2::WakeRevocationRows>()?
            .into_iter()
            .take(limit)
            .map(|row| {
                let record: WakeRevocationRecord = decode_exact(&row.payload)?;
                record.validate()?;
                let id = self.wake_revocation_id(&record.provider_id, &record.capability);
                if id != record.id {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                row.verify_key(&store_v2::DigestKey::new(id))?;
                Ok(record)
            })
            .collect()
    }

    /// Load one exact pending gateway revocation.
    pub fn get_wake_revocation(&self, id: &[u8; 32]) -> Result<Option<WakeRevocationRecord>> {
        self.get_equality::<store_v2::WakeRevocationRows>(&store_v2::DigestKey::new(*id))?
            .map(|row| {
                let record: WakeRevocationRecord = decode_exact(&row.payload)?;
                record.validate()?;
                if record.id != *id
                    || self.wake_revocation_id(&record.provider_id, &record.capability) != *id
                {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(record)
            })
            .transpose()
    }

    fn enqueue_wake_revocation(
        &self,
        record: &WakeRevocationRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        if self.wake_revocation_id(&record.provider_id, &record.capability) != record.id {
            return Err(StoreError::LogicalKeyMismatch);
        }
        if let Some(current) = self.get_wake_revocation(&record.id)? {
            if same_wake_revocation_authority(&current, record) {
                return Ok(());
            }
            return Err(StoreError::LogicalKeyMismatch);
        }
        if self.count_rows::<store_v2::WakeRevocationRows>()? >= MAX_WAKE_REVOCATION_ROWS as u64 {
            return Err(StoreError::RecordBounds);
        }
        self.put_wake_revocation(record, rng)
    }

    pub(crate) fn put_wake_revocation(
        &self,
        record: &WakeRevocationRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        if self.wake_revocation_id(&record.provider_id, &record.capability) != record.id {
            return Err(StoreError::LogicalKeyMismatch);
        }
        if let Some(current) = self.get_wake_revocation(&record.id)? {
            if !same_wake_revocation_authority(&current, record) {
                return Err(StoreError::LogicalKeyMismatch);
            }
        } else if self.count_rows::<store_v2::WakeRevocationRows>()?
            >= MAX_WAKE_REVOCATION_ROWS as u64
        {
            return Err(StoreError::RecordBounds);
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::WakeRevocationRows>(
            &store_v2::DigestKey::new(record.id),
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    pub(crate) fn delete_wake_revocation(&self, id: &[u8; 32]) -> Result<bool> {
        self.delete_equality::<store_v2::WakeRevocationRows>(&store_v2::DigestKey::new(*id))
    }
}

fn same_wake_revocation_authority(
    left: &WakeRevocationRecord,
    right: &WakeRevocationRecord,
) -> bool {
    left.version == right.version
        && left.id == right.id
        && left.origin == right.origin
        && left.static_key == right.static_key
        && left.provider_id == right.provider_id
        && left.capability == right.capability
        && left.expires_at == right.expires_at
}

#[cfg(test)]
mod tests {
    use kult_crypto::{
        initiate, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle,
        SignedPrekeySecret,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const NOW: u64 = 1_800_000_000;

    fn session(rng: &mut StdRng) -> Session {
        let initiator = Identity::generate(rng);
        let responder = Identity::generate(rng);
        let spk = SignedPrekeySecret::generate(rng, 1);
        let pqspk = PqPrekeySecret::generate(rng, 2);
        let opk = OneTimePrekeySecret::generate(rng, 3);
        let bundle =
            PrekeyBundle::build(&responder, &spk, &pqspk, Some(&opk), NOW + 86_400, vec![])
                .verify(NOW)
                .unwrap();
        initiate(&initiator, &bundle, b"first", NOW, rng).unwrap().0
    }

    fn capability(direction: WakeCapabilityDirection, byte: u8) -> WakeStoredCapability {
        WakeStoredCapability::new(
            direction,
            "https://wake.example".to_owned(),
            [7u8; 32],
            WakeCapability::from_parts(
                1,
                [byte; 24],
                &[byte; kult_protocol::WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
            )
            .unwrap()
            .as_bytes()
            .to_vec(),
            NOW + kult_protocol::WAKE_CAPABILITY_MAX_LIFETIME_SECS,
        )
        .unwrap()
    }

    #[test]
    fn wake_state_is_session_bound_persistent_and_retry_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake.db");
        let mut rng = StdRng::seed_from_u64(0x19_01);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let peer = [9u8; 32];
        let first = session(&mut rng);
        store.put_session(&peer, &first, &mut rng).unwrap();
        let mut state = store.get_wake_service_state(&peer).unwrap().unwrap();
        assert_eq!(state.session_id, *first.session_id());
        let mut remote = capability(WakeCapabilityDirection::Remote, 3);
        remote.mark_pending(NOW).unwrap();
        remote.mark_failed(NOW).unwrap();
        state
            .replace_direction(WakeCapabilityDirection::Remote, 1, vec![remote])
            .unwrap();
        state
            .replace_direction(
                WakeCapabilityDirection::Issued,
                1,
                vec![capability(WakeCapabilityDirection::Issued, 4)],
            )
            .unwrap();
        store
            .put_wake_service_state(&peer, &state, &mut rng)
            .unwrap();
        drop(store);

        let reopened = Store::open(&path, b"pass").unwrap();
        let retained = reopened.get_wake_service_state(&peer).unwrap().unwrap();
        assert!(retained.remote().next().unwrap().pending);
        assert_eq!(retained.remote().next().unwrap().consecutive_failures, 1);

        let replacement = session(&mut rng);
        reopened.put_session(&peer, &replacement, &mut rng).unwrap();
        let reset = reopened.get_wake_service_state(&peer).unwrap().unwrap();
        assert_eq!(reset.session_id, *replacement.session_id());
        assert!(reset.capabilities.is_empty());
        let pending = reopened.wake_revocations(MAX_WAKE_REVOCATION_ROWS).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].capability,
            retained.issued().next().unwrap().capability
        );
        reopened.delete_session(&peer).unwrap();
        assert!(reopened.get_wake_service_state(&peer).unwrap().is_none());
        assert_eq!(
            reopened
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn invalid_direction_duplicates_and_unbounded_expiry_fail_closed() {
        let mut state = WakeServiceState {
            version: WAKE_SERVICE_STATE_VERSION,
            session_id: [1u8; 32],
            remote_generation: 0,
            remote_conflict_generation: None,
            issued_generation: 0,
            capabilities: Vec::new(),
        };
        let first = capability(WakeCapabilityDirection::Remote, 5);
        assert!(state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![first.clone(), first]
            )
            .is_err());
        assert!(state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![capability(WakeCapabilityDirection::Issued, 6)]
            )
            .is_err());
    }

    #[test]
    fn remote_same_generation_conflict_is_visible_and_disables_wake() {
        let mut state = WakeServiceState {
            version: WAKE_SERVICE_STATE_VERSION,
            session_id: [1u8; 32],
            remote_generation: 0,
            remote_conflict_generation: None,
            issued_generation: 0,
            capabilities: Vec::new(),
        };
        state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![capability(WakeCapabilityDirection::Remote, 7)],
            )
            .unwrap();
        state
            .remote_mut()
            .next()
            .unwrap()
            .mark_pending(NOW)
            .unwrap();

        // A replay of the same authenticated set is idempotent and must not
        // erase local coalescing/retry state.
        state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![capability(WakeCapabilityDirection::Remote, 7)],
            )
            .unwrap();
        assert!(state.remote().next().unwrap().pending);

        // Two different complete sets at one authenticated generation are a
        // conflict. Retain the fact and remove the usable capability set.
        state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![capability(WakeCapabilityDirection::Remote, 8)],
            )
            .unwrap();
        assert_eq!(state.remote_conflict_generation, Some(1));
        assert_eq!(state.remote().count(), 0);

        // Only a newer authenticated generation resolves the conflict.
        state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                2,
                vec![capability(WakeCapabilityDirection::Remote, 9)],
            )
            .unwrap();
        assert_eq!(state.remote_conflict_generation, None);
        assert_eq!(state.remote_generation, 2);
    }

    #[test]
    fn issued_rotation_is_durable_and_retry_updates_are_exact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake-revocation.db");
        let mut rng = StdRng::seed_from_u64(0x19_04);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let peer = [12u8; 32];
        let session = session(&mut rng);
        store.put_session(&peer, &session, &mut rng).unwrap();
        let mut first = store.get_wake_service_state(&peer).unwrap().unwrap();
        first
            .replace_direction(
                WakeCapabilityDirection::Issued,
                1,
                vec![capability(WakeCapabilityDirection::Issued, 10)],
            )
            .unwrap();
        store
            .put_wake_service_state(&peer, &first, &mut rng)
            .unwrap();

        let mut second = first.clone();
        second
            .replace_direction(
                WakeCapabilityDirection::Issued,
                2,
                vec![capability(WakeCapabilityDirection::Issued, 11)],
            )
            .unwrap();
        store
            .put_wake_service_state(&peer, &second, &mut rng)
            .unwrap();
        let before = store
            .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(before.capability, first.issued().next().unwrap().capability);

        let mut after = before.clone();
        after.mark_failed(NOW).unwrap();
        store
            .commit_plan(
                crate::CommitPlan::WakeRevocation(crate::WakeRevocationPlan {
                    transitions: &[crate::WakeRevocationTransition {
                        before: &before,
                        after: Some(&after),
                    }],
                }),
                &mut rng,
            )
            .unwrap();
        drop(store);

        let reopened = Store::open(&path, b"pass").unwrap();
        assert_eq!(
            reopened.get_wake_revocation(&before.id).unwrap(),
            Some(after.clone())
        );
        reopened
            .commit_plan(
                crate::CommitPlan::WakeRevocation(crate::WakeRevocationPlan {
                    transitions: &[crate::WakeRevocationTransition {
                        before: &after,
                        after: None,
                    }],
                }),
                &mut rng,
            )
            .unwrap();
        assert!(reopened.get_wake_revocation(&before.id).unwrap().is_none());
    }

    #[test]
    fn full_revocation_domain_fails_closed_before_issued_authority_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wake-revocation-bound.db");
        let mut rng = StdRng::seed_from_u64(0x19_05);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let peer = [13u8; 32];
        let session = session(&mut rng);
        store.put_session(&peer, &session, &mut rng).unwrap();
        let mut before = store.get_wake_service_state(&peer).unwrap().unwrap();
        before
            .replace_direction(
                WakeCapabilityDirection::Issued,
                1,
                vec![capability(WakeCapabilityDirection::Issued, 12)],
            )
            .unwrap();
        store
            .put_wake_service_state(&peer, &before, &mut rng)
            .unwrap();

        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        for value in 0..MAX_WAKE_REVOCATION_ROWS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(value as u64 + 1).to_be_bytes());
            store
                .put_equality::<store_v2::WakeRevocationRows>(
                    &store_v2::DigestKey::new(id),
                    b"bounded fixture",
                    store_v2::IndexKeys::none(),
                    &mut rng,
                )
                .unwrap();
        }
        store.conn.execute_batch("COMMIT").unwrap();

        let mut after = before.clone();
        after
            .replace_direction(WakeCapabilityDirection::Issued, 2, Vec::new())
            .unwrap();
        assert!(matches!(
            store.put_wake_service_state(&peer, &after, &mut rng),
            Err(StoreError::RecordBounds)
        ));
        assert_eq!(store.get_wake_service_state(&peer).unwrap(), Some(before));
    }

    #[cfg(feature = "test-failpoints")]
    #[test]
    fn revocation_retry_is_all_or_nothing_across_every_commit_boundary() {
        use crate::{CommitFailpoint, CommitFailure};

        let points = [
            CommitFailpoint::BeforeBegin,
            CommitFailpoint::AfterBegin,
            CommitFailpoint::BeforeStatement(0),
            CommitFailpoint::AfterStatement(0),
            CommitFailpoint::BeforeCommit,
            CommitFailpoint::AfterCommit,
        ];
        for (offset, point) in points.into_iter().enumerate() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("wake-revocation-crash.db");
            let mut rng = StdRng::seed_from_u64(0x19_06 + offset as u64);
            let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
            let peer = [14u8; 32];
            let session = session(&mut rng);
            store.put_session(&peer, &session, &mut rng).unwrap();
            let mut issued = store.get_wake_service_state(&peer).unwrap().unwrap();
            issued
                .replace_direction(
                    WakeCapabilityDirection::Issued,
                    1,
                    vec![capability(WakeCapabilityDirection::Issued, 13)],
                )
                .unwrap();
            store
                .put_wake_service_state(&peer, &issued, &mut rng)
                .unwrap();
            let mut empty = issued.clone();
            empty
                .replace_direction(WakeCapabilityDirection::Issued, 2, Vec::new())
                .unwrap();
            store
                .put_wake_service_state(&peer, &empty, &mut rng)
                .unwrap();
            let before = store
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .pop()
                .unwrap();
            let mut after = before.clone();
            after.mark_failed(NOW).unwrap();

            store.arm_commit_failpoint(point, CommitFailure::Interrupted);
            assert!(store
                .commit_plan(
                    crate::CommitPlan::WakeRevocation(crate::WakeRevocationPlan {
                        transitions: &[crate::WakeRevocationTransition {
                            before: &before,
                            after: Some(&after),
                        }],
                    }),
                    &mut rng,
                )
                .is_err());
            drop(store);

            let reopened = Store::open(&path, b"pass").unwrap();
            let retained = reopened.get_wake_revocation(&before.id).unwrap().unwrap();
            assert_eq!(
                retained,
                if point == CommitFailpoint::AfterCommit {
                    after
                } else {
                    before
                }
            );
        }
    }
}
