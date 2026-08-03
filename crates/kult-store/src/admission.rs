//! Sealed, bounded first-contact request state (ADR-0030).

use kult_crypto::{IdentityPublic, Session};
use serde::{Deserialize, Serialize};

use crate::{
    decode_exact, store_v2, ContactDeviceRecord, ContactRecord, Result, Store, StoreError,
};

/// Current provisional-request record version.
pub const PROVISIONAL_REQUEST_VERSION: u8 = 1;
/// Maximum live first-contact requests in one profile.
pub const MAX_PROVISIONAL_REQUESTS: usize = 32;
/// Maximum aggregate sealed bytes for live provisional requests.
pub const MAX_PROVISIONAL_REQUEST_BYTES: usize = 512 * 1024;
/// Maximum canonical first content retained until consent.
pub const MAX_PROVISIONAL_CONTENT_BYTES: usize = 4 * 1024;
/// Maximum renderable preview bytes exposed by request-list APIs.
pub const MAX_PROVISIONAL_PREVIEW_BYTES: usize = 2 * 1024;
/// Maximum lifetime of a provisional request.
pub const MAX_PROVISIONAL_LIFETIME_SECS: u64 = 7 * 86_400;
/// Maximum short replay tombstones.
pub const MAX_ADMISSION_REPLAY_TOMBSTONES: usize = 4_096;
/// Maximum replay-tombstone lifetime.
pub const MAX_ADMISSION_REPLAY_LIFETIME_SECS: u64 = 30 * 86_400;
/// Maximum sealed local account/device block rules.
pub const MAX_BLOCKED_IDENTITIES: usize = 4_096;
/// Maximum encoded detached provisional ratchet state.
pub const MAX_PROVISIONAL_SESSION_BYTES: usize = 64 * 1024;

/// Coarse carrier class retained without an address, token, or provider label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionTransportClass {
    /// A released record or carrier did not expose a class.
    Unknown,
    /// Interactive direct transport.
    Direct,
    /// Durable store-and-forward mailbox.
    Mailbox,
    /// Bounded low-bandwidth mesh carrier.
    Mesh,
    /// Explicit file/QR/sneakernet import.
    Delayed,
    /// Content-blind bridge admission.
    Bridge,
}

/// One sealed first-contact request, isolated from normal contact/session rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionalRequestRecord {
    /// Record codec version.
    pub version: u8,
    /// Stable introduction content id and UI request id.
    pub request_id: [u8; 16],
    /// Verified stable sender account.
    pub account: [u8; 32],
    /// Verified sender physical device.
    pub device: [u8; 32],
    /// Candidate contact stub, still absent from the normal contact table.
    pub contact: ContactRecord,
    /// Complete candidate certified device set.
    pub devices: Vec<ContactDeviceRecord>,
    /// Detached ratchet state, postcard encoded inside this sealed row.
    pub session: Vec<u8>,
    /// Bounded canonical first content, not normal history before acceptance.
    pub first_content: Vec<u8>,
    /// Bounded UTF-8 request preview.
    pub preview: String,
    /// Symmetric safety-number decimal digits.
    pub safety_number: String,
    /// Full safety-number QR comparison value.
    pub safety_number_qr: [u8; 32],
    /// Local arrival time.
    pub arrived_at: u64,
    /// Absolute local expiry.
    pub expires_at: u64,
    /// Privacy-preserving coarse ingress class.
    pub transport: AdmissionTransportClass,
}

impl ProvisionalRequestRecord {
    /// Validate all row-local bounds and identity relationships.
    pub fn validate(&self) -> Result<()> {
        if self.version != PROVISIONAL_REQUEST_VERSION
            || self.request_id == [0u8; 16]
            || self.account == [0u8; 32]
            || self.device == [0u8; 32]
            || self.contact.peer != self.account
            || !self.contact.name.is_empty()
            || self.contact.verified
            || self.devices.is_empty()
            || self.devices.len() > crate::MAX_PAIRWISE_COMMIT_DEVICES
            || self
                .devices
                .iter()
                .any(|record| record.account != self.account)
            || !self
                .devices
                .iter()
                .any(|record| record.device == self.device)
            || self.session.is_empty()
            || self.session.len() > MAX_PROVISIONAL_SESSION_BYTES
            || self.first_content.len() > MAX_PROVISIONAL_CONTENT_BYTES
            || self.preview.len() > MAX_PROVISIONAL_PREVIEW_BYTES
            || self.safety_number.len() != 30
            || !self.safety_number.bytes().all(|byte| byte.is_ascii_digit())
            || self.safety_number_qr == [0u8; 32]
            || self.expires_at <= self.arrived_at
            || self.expires_at.saturating_sub(self.arrived_at) > MAX_PROVISIONAL_LIFETIME_SECS
        {
            return Err(StoreError::RecordBounds);
        }
        let identity: IdentityPublic = decode_exact(&self.contact.identity)?;
        identity.verify()?;
        if identity.ed != self.account {
            return Err(StoreError::LogicalKeyMismatch);
        }
        let _: Session = decode_exact(&self.session)?;
        for device in &self.devices {
            crate::devices::validate_contact_device(device)?;
        }
        Ok(())
    }
}

/// Short bounded replay absorber retained after Delete or Block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReplayTombstone {
    /// Exact introduction request id.
    pub request_id: [u8; 16],
    /// Verified sender account.
    pub account: [u8; 32],
    /// Verified sender physical device.
    pub device: [u8; 32],
    /// Local rejection time.
    pub rejected_at: u64,
    /// Absolute expiry.
    pub expires_at: u64,
}

impl AdmissionReplayTombstone {
    /// Validate one replay tombstone.
    pub fn validate(&self) -> Result<()> {
        if self.request_id == [0u8; 16]
            || self.account == [0u8; 32]
            || self.device == [0u8; 32]
            || self.expires_at <= self.rejected_at
            || self.expires_at.saturating_sub(self.rejected_at) > MAX_ADMISSION_REPLAY_LIFETIME_SECS
        {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

/// Sealed local block rule; it makes no claim about remote deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedIdentityRecord {
    /// Stable account blocked locally.
    pub account: [u8; 32],
    /// Physical device observed when the rule was created.
    pub device: [u8; 32],
    /// Local creation time.
    pub created_at: u64,
}

impl BlockedIdentityRecord {
    /// Validate one exact block rule.
    pub fn validate(&self) -> Result<()> {
        if self.account == [0u8; 32] || self.device == [0u8; 32] {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

impl Store {
    pub(crate) fn put_provisional_request(
        &self,
        record: &ProvisionalRequestRecord,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        let existing = self.get_provisional_request(&record.account)?;
        if existing.is_none()
            && self.count_rows::<store_v2::ProvisionalRequestRows>()?
                >= MAX_PROVISIONAL_REQUESTS as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        let payload = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        self.put_equality::<store_v2::ProvisionalRequestRows>(
            &store_v2::AccountKey::new(record.account),
            &payload,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        if self.sealed_bytes_on::<store_v2::ProvisionalRequestRows>(&self.conn)?
            > MAX_PROVISIONAL_REQUEST_BYTES as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        Ok(())
    }

    /// Load the live request for one stable sender account.
    pub fn get_provisional_request(
        &self,
        account: &[u8; 32],
    ) -> Result<Option<ProvisionalRequestRecord>> {
        self.get_equality::<store_v2::ProvisionalRequestRows>(&store_v2::AccountKey::new(*account))?
            .map(|row| {
                let record: ProvisionalRequestRecord = decode_exact(&row.payload)?;
                if record.account != *account {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Load one request by its stable opaque request id.
    pub fn provisional_request_by_id(
        &self,
        request_id: &[u8; 16],
    ) -> Result<Option<ProvisionalRequestRecord>> {
        Ok(self
            .provisional_requests()?
            .into_iter()
            .find(|record| &record.request_id == request_id))
    }

    /// List live requests in deterministic arrival/id order.
    pub fn provisional_requests(&self) -> Result<Vec<ProvisionalRequestRecord>> {
        let mut records = self
            .rows::<store_v2::ProvisionalRequestRows>()?
            .into_iter()
            .map(|row| {
                let record: ProvisionalRequestRecord = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::AccountKey::new(record.account))?;
                record.validate()?;
                Ok(record)
            })
            .collect::<Result<Vec<_>>>()?;
        records.sort_by_key(|record| (record.arrived_at, record.request_id));
        Ok(records)
    }

    pub(crate) fn delete_provisional_request(&self, account: &[u8; 32]) -> Result<bool> {
        self.delete_equality::<store_v2::ProvisionalRequestRows>(&store_v2::AccountKey::new(
            *account,
        ))
    }

    pub(crate) fn put_admission_tombstone(
        &self,
        record: &AdmissionReplayTombstone,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        if self.get_admission_tombstone(&record.request_id)?.is_none()
            && self.count_rows::<store_v2::AdmissionReplayRows>()?
                >= MAX_ADMISSION_REPLAY_TOMBSTONES as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        let payload = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        self.put_equality::<store_v2::AdmissionReplayRows>(
            &store_v2::ContentKey::new(record.request_id),
            &payload,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Load one rejected-request replay tombstone.
    pub fn get_admission_tombstone(
        &self,
        request_id: &[u8; 16],
    ) -> Result<Option<AdmissionReplayTombstone>> {
        self.get_equality::<store_v2::AdmissionReplayRows>(&store_v2::ContentKey::new(*request_id))?
            .map(|row| {
                let record: AdmissionReplayTombstone = decode_exact(&row.payload)?;
                if record.request_id != *request_id {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// List bounded replay tombstones.
    pub fn admission_tombstones(&self) -> Result<Vec<AdmissionReplayTombstone>> {
        self.rows::<store_v2::AdmissionReplayRows>()?
            .into_iter()
            .map(|row| {
                let record: AdmissionReplayTombstone = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::ContentKey::new(record.request_id))?;
                record.validate()?;
                Ok(record)
            })
            .collect()
    }

    pub(crate) fn delete_admission_tombstone(&self, request_id: &[u8; 16]) -> Result<bool> {
        self.delete_equality::<store_v2::AdmissionReplayRows>(&store_v2::ContentKey::new(
            *request_id,
        ))
    }

    pub(crate) fn put_blocked_identity(
        &self,
        record: &BlockedIdentityRecord,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<()> {
        record.validate()?;
        let key = store_v2::AccountDeviceKey::new(record.account, record.device);
        if self
            .get_equality::<store_v2::BlockedIdentityRows>(&key)?
            .is_none()
            && self.count_rows::<store_v2::BlockedIdentityRows>()? >= MAX_BLOCKED_IDENTITIES as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        let payload = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
        self.put_equality::<store_v2::BlockedIdentityRows>(
            &key,
            &payload,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Whether any local block rule names this stable account.
    pub fn is_blocked_identity(&self, account: &[u8; 32]) -> Result<bool> {
        Ok(self
            .blocked_identities()?
            .iter()
            .any(|record| &record.account == account))
    }

    /// List local sealed block rules.
    pub fn blocked_identities(&self) -> Result<Vec<BlockedIdentityRecord>> {
        self.rows::<store_v2::BlockedIdentityRows>()?
            .into_iter()
            .map(|row| {
                let record: BlockedIdentityRecord = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::AccountDeviceKey::new(
                    record.account,
                    record.device,
                ))?;
                record.validate()?;
                Ok(record)
            })
            .collect()
    }

    pub(crate) fn validate_admission_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::ProvisionalRequestRows, _>(|row| {
            let record: ProvisionalRequestRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::AccountKey::new(record.account))?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            record.validate()
        })?;
        if self.count_rows::<store_v2::ProvisionalRequestRows>()? > MAX_PROVISIONAL_REQUESTS as u64
            || self.sealed_bytes_on::<store_v2::ProvisionalRequestRows>(&self.conn)?
                > MAX_PROVISIONAL_REQUEST_BYTES as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        self.validate_rows::<store_v2::AdmissionReplayRows, _>(|row| {
            let record: AdmissionReplayTombstone = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::ContentKey::new(record.request_id))?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            record.validate()
        })?;
        if self.count_rows::<store_v2::AdmissionReplayRows>()?
            > MAX_ADMISSION_REPLAY_TOMBSTONES as u64
        {
            return Err(StoreError::AdmissionQuota);
        }
        self.validate_rows::<store_v2::BlockedIdentityRows, _>(|row| {
            let record: BlockedIdentityRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::AccountDeviceKey::new(
                record.account,
                record.device,
            ))?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            record.validate()
        })?;
        if self.count_rows::<store_v2::BlockedIdentityRows>()? > MAX_BLOCKED_IDENTITIES as u64 {
            return Err(StoreError::AdmissionQuota);
        }
        Ok(())
    }
}
