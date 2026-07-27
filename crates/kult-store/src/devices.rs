//! Sealed C2 linked-device authority, channel roots, and sync-event storage.
//!
//! Device ids and sync keys never appear in plaintext SQLite columns. The
//! tables expose only row counts and approximate sealed sizes to a copied
//! database, matching the rest of the store's local-metadata boundary.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{DeviceCertificate, DeviceManifest, Identity, MAX_LINKED_DEVICES};
use kult_protocol::{DeviceSyncEvent, DeviceSyncNamespace};

use crate::{
    decode_exact, store_v2, ContactRecord, DeliveryState, EphemeralRecord, EphemeralState,
    GroupAuthorityRecord, GroupMember, GroupMessageRecord, LocalMetadataRecord, MessageRecord,
    NoteMessageRecord, Result, Store, StoreError, THEME_PREFERENCE_KEY,
};

const DEVICE_SYNC_DIGEST_DOMAIN: &[u8] = b"Komms-Store-Device-Sync-Digest-v2";
/// Maximum authenticated sync-event bytes stored in one row.
pub const MAX_DEVICE_SYNC_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum durable sync events before compaction must make progress.
pub const MAX_DEVICE_SYNC_EVENTS: usize = 100_000;

/// User-controlled initial history transfer selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceTransferSelection {
    /// Import contacts and verification state.
    pub contacts: bool,
    /// Import folders, labels, pins, icons, and the shared appearance choice.
    pub organization: bool,
    /// Import pairwise/group/note history. Media bytes remain device-local.
    pub history: bool,
}

impl Default for DeviceTransferSelection {
    fn default() -> Self {
        Self {
            contacts: true,
            organization: true,
            history: true,
        }
    }
}

/// Chain-free durable group state carried by a device transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTransferGroup {
    /// Stable group id.
    pub id: [u8; 32],
    /// Current signed display name.
    pub name: String,
    /// Legacy creator field retained for compatibility.
    pub creator: [u8; 32],
    /// Current roster.
    pub members: Vec<GroupMember>,
    /// Current group header secret.
    pub secret: [u8; 32],
    /// Current roster/authority generation.
    pub generation: u64,
}

/// Opaque-to-crypto selected state encrypted inside a confirmed link package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTransferSnapshot {
    /// Selected contact records.
    pub contacts: Vec<ContactRecord>,
    /// Per-device contact endpoints for fresh independent sessions.
    pub contact_devices: Vec<ContactDeviceRecord>,
    /// Selected non-ephemeral pairwise history.
    pub messages: Vec<MessageRecord>,
    /// Chain-free group definitions needed by selected group history.
    pub groups: Vec<DeviceTransferGroup>,
    /// Selected non-ephemeral group history without pending wire bodies.
    pub group_messages: Vec<GroupMessageRecord>,
    /// Signed C6 authority state.
    pub group_authorities: Vec<GroupAuthorityRecord>,
    /// Selected syncable organization records; drafts/device settings omitted.
    pub local_metadata: Vec<LocalMetadataRecord>,
    /// Selected note-to-self history.
    pub note_messages: Vec<NoteMessageRecord>,
    /// Terminal expiry/view-once tombstones only.
    pub ephemeral_tombstones: Vec<EphemeralRecord>,
    /// Existing authenticated convergence log.
    pub sync_events: Vec<Vec<u8>>,
}

/// One pairwise root shared only by two linked physical devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceChannelRecord {
    /// Exact other certified physical-device id.
    pub peer_device: [u8; 32],
    /// Link-derived or source-generated 32-byte sync channel root.
    pub root: [u8; 32],
    /// Highest locally emitted encrypted bundle sequence.
    pub send_counter: u64,
    /// Highest contiguous imported bundle sequence.
    pub receive_counter: u64,
}

/// Small durable recovery handle for a committed link package whose caller
/// may not have observed the return value before restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLinkRecoveryRecord {
    /// Exact target physical-device id.
    pub target_device: [u8; 32],
    /// Digest of the signed target response accepted by the source.
    pub response_hash: [u8; 32],
    /// Link-package AEAD key derived from the confirmed ceremony transcript.
    pub link_key: [u8; 32],
    /// Whether a retry includes contacts.
    pub contacts: bool,
    /// Whether a retry includes shared organization state.
    pub organization: bool,
    /// Whether a retry includes history.
    pub history: bool,
}

/// One contact account's independently addressable physical-device endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactDeviceRecord {
    /// Stable contact account id used by conversation history.
    pub account: [u8; 32],
    /// Exact physical-device id used by its ratchet session.
    pub device: [u8; 32],
    /// Account-authenticated user-visible device name, when available.
    pub name: Option<String>,
    /// Encoded account certificate, empty only for a legacy account=device endpoint.
    pub certificate: Vec<u8>,
    /// Latest device-signed raw prekey bundle, possibly empty until announced.
    pub bundle: Vec<u8>,
    /// Opaque endpoint-specific delivery hints.
    pub hints: Vec<Vec<u8>>,
    /// Latest account manifest generation authenticating this endpoint.
    pub manifest_generation: u64,
    /// Deterministic id of that exact signed manifest state for fork ordering.
    pub manifest_state_id: [u8; 32],
    /// Coarse authenticated observation time.
    pub last_seen: u64,
    /// Permanent account-authorized revocation time.
    pub revoked_at: Option<u64>,
    /// Highest device-signed sync counter accepted after revocation.
    pub revoked_after_counter: Option<u64>,
}

/// Honest per-recipient-device delivery state for one account-level message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDeviceDeliveryRecord {
    /// Stable local message id.
    pub message: [u8; 16],
    /// Stable recipient account conversation id.
    pub account: [u8; 32],
    /// Exact physical recipient endpoint.
    pub device: [u8; 32],
    /// Exact encrypted envelope id, absent while no session/bundle can queue it.
    pub wire_id: Option<[u8; 16]>,
    /// Honest queued/sent/delivered/failed ladder for this endpoint.
    pub state: DeliveryState,
}

/// Complete local C2 device state. Account identity remains in the existing
/// identity slot; this record owns the separate physical key and channels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStateRecord {
    /// [`Identity::to_bytes`] for the local physical-device key.
    pub local_device_secret: Vec<u8>,
    /// Exact account authorization for the local physical key.
    pub local_certificate: DeviceCertificate,
    /// Latest accepted complete account authority state.
    pub manifest: DeviceManifest,
    /// Next device-authored operation counter.
    pub sync_counter: u64,
    /// Pairwise channel roots, sorted by peer device id.
    pub channels: Vec<DeviceChannelRecord>,
}

impl DeviceStateRecord {
    pub(crate) fn validate(&self, account: &Identity) -> Result<()> {
        self.manifest.verify()?;
        self.local_certificate.verify()?;
        let device_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
            self.local_device_secret
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Serialization)?,
        );
        let local_device = Identity::from_bytes(&device_bytes);
        let local_id = local_device.public().ed;
        if self.manifest.account != account.public()
            || self.local_certificate.account != account.public()
            || self.local_certificate.device != local_device.public()
            || !self.manifest.devices.iter().any(|entry| {
                entry.certificate == self.local_certificate && entry.revoked_at.is_none()
            })
        {
            return Err(StoreError::Serialization);
        }
        let mut prior = None;
        for channel in &self.channels {
            if channel.peer_device == local_id
                || channel.root == [0u8; 32]
                || prior.is_some_and(|value| value >= channel.peer_device)
                || !self.manifest.devices.iter().any(|entry| {
                    entry.certificate.device_id() == channel.peer_device
                        && entry.revoked_at.is_none()
                })
            {
                return Err(StoreError::Serialization);
            }
            prior = Some(channel.peer_device);
        }
        Ok(())
    }
}

impl Store {
    /// Build a semantic snapshot for one confirmed proximate link. Live
    /// ratchets, prekeys, queues, drafts, media, and active ephemeral
    /// plaintext never enter the result.
    pub fn export_device_transfer(
        &self,
        selection: DeviceTransferSelection,
    ) -> Result<DeviceTransferSnapshot> {
        let mut terminal = self.ephemeral_records()?;
        terminal.retain(|record| record.state != EphemeralState::Active);
        let ephemeral_pairwise = |message: &MessageRecord| {
            terminal.iter().any(|record| {
                record.conversation == crate::EphemeralConversation::Pairwise(message.peer)
                    && record.content_id == message.id
            })
        };
        let ephemeral_group = |message: &GroupMessageRecord| {
            terminal.iter().any(|record| {
                record.conversation == crate::EphemeralConversation::Group(message.group)
                    && record.author == message.sender
                    && record.content_id == message.id
            })
        };
        let local_metadata = if selection.organization {
            self.local_metadata()?
                .into_iter()
                .filter(|record| match record {
                    LocalMetadataRecord::Draft(_) => false,
                    LocalMetadataRecord::UiPreference(preference) => {
                        preference.key == THEME_PREFERENCE_KEY
                    }
                    _ => true,
                })
                .collect()
        } else {
            Vec::new()
        };
        let groups = if selection.history || selection.organization {
            self.groups()?
                .into_iter()
                .map(|group| DeviceTransferGroup {
                    id: group.id,
                    name: group.name,
                    creator: group.creator,
                    members: group.members,
                    secret: group.secret,
                    generation: group.generation,
                })
                .collect()
        } else {
            Vec::new()
        };
        let sync_events = self
            .device_sync_events()?
            .into_iter()
            .map(|encoded| {
                let event = DeviceSyncEvent::decode(&encoded)?;
                let selected = match event.namespace {
                    DeviceSyncNamespace::Contacts | DeviceSyncNamespace::Verification => {
                        selection.contacts
                    }
                    DeviceSyncNamespace::LocalOrganization => selection.organization,
                    DeviceSyncNamespace::ConversationHistory
                    | DeviceSyncNamespace::MessageEdits
                    | DeviceSyncNamespace::GroupPolls => selection.history,
                    DeviceSyncNamespace::Groups => selection.history || selection.organization,
                    DeviceSyncNamespace::ExpiryTombstones => true,
                };
                Ok(selected.then_some(encoded))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(DeviceTransferSnapshot {
            contacts: if selection.contacts {
                self.contacts()?
            } else {
                Vec::new()
            },
            contact_devices: if selection.contacts {
                self.contact_devices()?
            } else {
                Vec::new()
            },
            messages: if selection.history {
                self.all_messages()?
                    .into_iter()
                    .filter(|message| !ephemeral_pairwise(message))
                    .collect()
            } else {
                Vec::new()
            },
            groups,
            group_messages: if selection.history {
                self.all_group_messages()?
                    .into_iter()
                    .filter(|message| !ephemeral_group(message))
                    .map(|mut message| {
                        message.wire_body = None;
                        message
                    })
                    .collect()
            } else {
                Vec::new()
            },
            group_authorities: if selection.history || selection.organization {
                self.group_authorities()?
            } else {
                Vec::new()
            },
            local_metadata,
            note_messages: if selection.history {
                self.note_messages()?
            } else {
                Vec::new()
            },
            ephemeral_tombstones: terminal,
            sync_events,
        })
    }

    /// Atomically replace the complete sealed local linked-device state.
    pub fn put_device_state(
        &self,
        state: &DeviceStateRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let account = self.get_identity()?.ok_or(StoreError::NotAStore)?;
        state.validate(&account)?;
        let plain =
            Zeroizing::new(postcard::to_allocvec(state).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::DeviceStateRows>(
            &store_v2::SingletonKey,
            &plain,
            store_v2::IndexKeys::none(),
            rng,
        )?;
        Ok(())
    }

    /// Insert or replace one sealed contact-device endpoint.
    pub fn put_contact_device(
        &self,
        endpoint: &ContactDeviceRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if endpoint.account == [0u8; 32]
            || endpoint.device == [0u8; 32]
            || (endpoint.certificate.is_empty() && endpoint.account != endpoint.device)
            || (endpoint.manifest_generation == 0) != (endpoint.manifest_state_id == [0u8; 32])
            || endpoint.revoked_at.is_some() != endpoint.revoked_after_counter.is_some()
        {
            return Err(StoreError::Serialization);
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(endpoint).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::ContactDeviceRows>(
            &store_v2::AccountDeviceKey::new(endpoint.account, endpoint.device),
            &encoded,
            store_v2::IndexKeys::contact_device(&store_v2::AccountKey::new(endpoint.account)),
            rng,
        )?;
        Ok(())
    }

    /// Every sealed contact-device endpoint in insertion order.
    pub fn contact_devices(&self) -> Result<Vec<ContactDeviceRecord>> {
        let mut endpoints = Vec::new();
        for row in self.rows::<store_v2::ContactDeviceRows>()? {
            let endpoint: ContactDeviceRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::AccountDeviceKey::new(
                endpoint.account,
                endpoint.device,
            ))?;
            endpoints.push(endpoint);
        }
        Ok(endpoints)
    }

    /// Active endpoints known for one stable contact account.
    pub fn contact_devices_for(&self, account: &[u8; 32]) -> Result<Vec<ContactDeviceRecord>> {
        let mut endpoints = Vec::new();
        for row in self.rows_by_index::<store_v2::ContactDeviceAccountIndex>(
            &store_v2::AccountKey::new(*account),
        )? {
            let endpoint: ContactDeviceRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::AccountDeviceKey::new(
                endpoint.account,
                endpoint.device,
            ))?;
            if endpoint.account != *account {
                return Err(StoreError::LogicalKeyMismatch);
            }
            if endpoint.revoked_at.is_none() {
                endpoints.push(endpoint);
            }
        }
        Ok(endpoints)
    }

    /// Delete one exact sealed contact-device endpoint.
    pub fn delete_contact_device(&self, account: &[u8; 32], device: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::ContactDeviceRows>(&store_v2::AccountDeviceKey::new(
            *account, *device,
        ))?;
        Ok(())
    }

    /// Re-key sealed delivery rows when a legacy account endpoint is bound
    /// to its certified physical-device id.
    pub fn retarget_message_device_deliveries(
        &self,
        account: &[u8; 32],
        old_device: &[u8; 32],
        new_device: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut replacements = Vec::new();
        for row in self.rows_by_index::<store_v2::MessageDeliveryAccountIndex>(
            &store_v2::AccountKey::new(*account),
        )? {
            let mut delivery: MessageDeviceDeliveryRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::MessageDeviceKey::new(
                delivery.message,
                delivery.device,
            ))?;
            if &delivery.account == account && &delivery.device == old_device {
                delivery.device = *new_device;
                replacements.push((row.locator, delivery));
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        for (locator, delivery) in replacements {
            let new_key = store_v2::MessageDeviceKey::new(delivery.message, *new_device);
            let encoded = Zeroizing::new(
                postcard::to_allocvec(&delivery).map_err(|_| StoreError::Serialization)?,
            );
            self.delete_row_on::<store_v2::MessageDeviceDeliveryRows>(&tx, &locator)?;
            self.put_equality_on::<store_v2::MessageDeviceDeliveryRows>(
                &tx,
                &new_key,
                &encoded,
                store_v2::IndexKeys::message_device_delivery(
                    &store_v2::ContentKey::new(delivery.message),
                    &store_v2::AccountKey::new(delivery.account),
                ),
                rng,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert or replace one sealed per-device message delivery row.
    pub fn put_message_device_delivery(
        &self,
        delivery: &MessageDeviceDeliveryRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if delivery.message == [0u8; 16]
            || delivery.account == [0u8; 32]
            || delivery.device == [0u8; 32]
        {
            return Err(StoreError::Serialization);
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(delivery).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::MessageDeviceDeliveryRows>(
            &store_v2::MessageDeviceKey::new(delivery.message, delivery.device),
            &encoded,
            store_v2::IndexKeys::message_device_delivery(
                &store_v2::ContentKey::new(delivery.message),
                &store_v2::AccountKey::new(delivery.account),
            ),
            rng,
        )?;
        Ok(())
    }

    /// Per-device delivery rows for one exact account-level message.
    pub fn message_device_deliveries(
        &self,
        message: &[u8; 16],
    ) -> Result<Vec<MessageDeviceDeliveryRecord>> {
        let mut deliveries = Vec::new();
        for row in self.rows_by_index::<store_v2::MessageDeliveryMessageIndex>(
            &store_v2::ContentKey::new(*message),
        )? {
            let delivery: MessageDeviceDeliveryRecord = decode_exact(&row.payload)?;
            row.verify_key(&store_v2::MessageDeviceKey::new(
                delivery.message,
                delivery.device,
            ))?;
            if delivery.message != *message {
                return Err(StoreError::LogicalKeyMismatch);
            }
            deliveries.push(delivery);
        }
        Ok(deliveries)
    }

    /// Load and validate the complete local linked-device state, if enabled.
    pub fn get_device_state(&self) -> Result<Option<DeviceStateRecord>> {
        let Some(row) = self.get_equality::<store_v2::DeviceStateRows>(&store_v2::SingletonKey)?
        else {
            return Ok(None);
        };
        row.verify_key(&store_v2::SingletonKey)?;
        let state: DeviceStateRecord = decode_exact(&row.payload)?;
        let account = self.get_identity()?.ok_or(StoreError::NotAStore)?;
        state.validate(&account)?;
        Ok(Some(state))
    }

    /// Load one committed link-package recovery handle.
    pub fn get_device_link_recovery(
        &self,
        target_device: &[u8; 32],
    ) -> Result<Option<DeviceLinkRecoveryRecord>> {
        let Some(row) = self.get_equality::<store_v2::DeviceLinkRecoveryRows>(
            &store_v2::AccountKey::new(*target_device),
        )?
        else {
            return Ok(None);
        };
        row.verify_key(&store_v2::AccountKey::new(*target_device))?;
        row.verify_indexes(&store_v2::IndexKeys::none())?;
        let recovery: DeviceLinkRecoveryRecord = decode_exact(&row.payload)?;
        validate_device_link_recovery(&recovery)?;
        if recovery.target_device != *target_device {
            return Err(StoreError::LogicalKeyMismatch);
        }
        Ok(Some(recovery))
    }

    pub(crate) fn put_device_link_recovery(
        &self,
        recovery: &DeviceLinkRecoveryRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        validate_device_link_recovery(recovery)?;
        if self
            .get_device_link_recovery(&recovery.target_device)?
            .is_none()
            && self.count_rows::<store_v2::DeviceLinkRecoveryRows>()? >= MAX_LINKED_DEVICES as u64
        {
            return Err(StoreError::RecordBounds);
        }
        let encoded = postcard::to_allocvec(recovery).map_err(|_| StoreError::Serialization)?;
        self.put_equality::<store_v2::DeviceLinkRecoveryRows>(
            &store_v2::AccountKey::new(recovery.target_device),
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    /// Insert one opaque authenticated sync event if its exact bytes are new.
    /// Returns `true` only for a new durable row.
    pub fn put_device_sync_event(
        &self,
        event: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        if event.is_empty() || event.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
            return Err(StoreError::Serialization);
        }
        let digest = self.device_sync_digest(event);
        if self
            .row_by_unique::<store_v2::DeviceSyncDigestIndex>(&digest)?
            .is_some()
        {
            return Ok(false);
        }
        if self.count_rows::<store_v2::DeviceSyncRows>()? >= MAX_DEVICE_SYNC_EVENTS as u64 {
            return Err(StoreError::Serialization);
        }
        self.append::<store_v2::DeviceSyncRows>(
            &digest,
            event,
            store_v2::IndexKeys::device_sync(&digest),
            rng,
        )?;
        Ok(true)
    }

    /// Return every opaque authenticated sync event in insertion order.
    pub fn device_sync_events(&self) -> Result<Vec<Vec<u8>>> {
        let mut events = Vec::new();
        for row in self.rows::<store_v2::DeviceSyncRows>()? {
            if row.payload.is_empty() || row.payload.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::Serialization);
            }
            row.verify_key(&self.device_sync_digest(&row.payload))?;
            events.push(row.payload.to_vec());
        }
        Ok(events)
    }

    pub(crate) fn delete_device_sync_event(&self, event: &[u8]) -> Result<bool> {
        let digest = self.device_sync_digest(event);
        let Some(row) = self.row_by_unique::<store_v2::DeviceSyncDigestIndex>(&digest)? else {
            return Ok(false);
        };
        row.verify_key(&digest)?;
        if row.payload.as_slice() != event {
            return Err(StoreError::LogicalKeyMismatch);
        }
        self.delete_row::<store_v2::DeviceSyncRows>(&row.locator)
    }

    pub(crate) fn device_sync_digest(&self, event: &[u8]) -> store_v2::DigestKey {
        let mut input = Vec::with_capacity(DEVICE_SYNC_DIGEST_DOMAIN.len() + event.len());
        input.extend_from_slice(DEVICE_SYNC_DIGEST_DOMAIN);
        input.extend_from_slice(event);
        store_v2::DigestKey::new(self.index_root.hmac_sha256(&input))
    }

    pub(crate) fn validate_device_logical_rows(&self) -> Result<()> {
        let account = self.get_identity()?;
        self.validate_rows::<store_v2::DeviceStateRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let state: DeviceStateRecord = decode_exact(&row.payload)?;
            state.validate(account.as_ref().ok_or(StoreError::NotAStore)?)
        })?;
        let device_state = self.get_device_state()?;
        self.validate_rows::<store_v2::DeviceSyncRows, _>(|row| {
            if row.payload.is_empty() || row.payload.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::Serialization);
            }
            let digest = self.device_sync_digest(&row.payload);
            let stored = store_v2::DigestKey::decode(&row.logical_key)?;
            if stored.value() != digest.value() {
                return Err(StoreError::LogicalKeyMismatch);
            }
            row.verify_indexes(&store_v2::IndexKeys::device_sync(&digest))
        })?;
        if self.count_rows::<store_v2::DeviceSyncRows>()? > MAX_DEVICE_SYNC_EVENTS as u64 {
            return Err(StoreError::Serialization);
        }
        self.validate_rows::<store_v2::ContactDeviceRows, _>(|row| {
            let endpoint: ContactDeviceRecord = decode_exact(&row.payload)?;
            validate_contact_device(&endpoint)?;
            let key = store_v2::AccountDeviceKey::decode(&row.logical_key)?;
            if key.account() != &endpoint.account || key.device() != &endpoint.device {
                return Err(StoreError::LogicalKeyMismatch);
            }
            row.verify_indexes(&store_v2::IndexKeys::contact_device(
                &store_v2::AccountKey::new(endpoint.account),
            ))
        })?;
        self.validate_rows::<store_v2::MessageDeviceDeliveryRows, _>(|row| {
            let delivery: MessageDeviceDeliveryRecord = decode_exact(&row.payload)?;
            validate_message_device_delivery(&delivery)?;
            let key = store_v2::MessageDeviceKey::decode(&row.logical_key)?;
            if key.message() != &delivery.message || key.device() != &delivery.device {
                return Err(StoreError::LogicalKeyMismatch);
            }
            row.verify_indexes(&store_v2::IndexKeys::message_device_delivery(
                &store_v2::ContentKey::new(delivery.message),
                &store_v2::AccountKey::new(delivery.account),
            ))
        })?;
        self.validate_rows::<store_v2::DeviceLinkRecoveryRows, _>(|row| {
            let recovery: DeviceLinkRecoveryRecord = decode_exact(&row.payload)?;
            validate_device_link_recovery(&recovery)?;
            row.verify_key(&store_v2::AccountKey::new(recovery.target_device))?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let state = device_state.as_ref().ok_or(StoreError::NotAStore)?;
            if !state.manifest.devices.iter().any(|entry| {
                entry.certificate.device_id() == recovery.target_device
                    && entry.revoked_at.is_none()
            }) || !state
                .channels
                .iter()
                .any(|channel| channel.peer_device == recovery.target_device)
            {
                return Err(StoreError::LogicalKeyMismatch);
            }
            Ok(())
        })?;
        if self.count_rows::<store_v2::DeviceLinkRecoveryRows>()? > MAX_LINKED_DEVICES as u64 {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

pub(crate) fn validate_device_link_recovery(recovery: &DeviceLinkRecoveryRecord) -> Result<()> {
    if recovery.target_device == [0u8; 32]
        || recovery.response_hash == [0u8; 32]
        || recovery.link_key == [0u8; 32]
    {
        return Err(StoreError::Serialization);
    }
    Ok(())
}

pub(crate) fn validate_contact_device(endpoint: &ContactDeviceRecord) -> Result<()> {
    if endpoint.account == [0u8; 32]
        || endpoint.device == [0u8; 32]
        || (endpoint.certificate.is_empty() && endpoint.account != endpoint.device)
        || (endpoint.manifest_generation == 0) != (endpoint.manifest_state_id == [0u8; 32])
        || endpoint.revoked_at.is_some() != endpoint.revoked_after_counter.is_some()
    {
        return Err(StoreError::Serialization);
    }
    Ok(())
}

fn validate_message_device_delivery(delivery: &MessageDeviceDeliveryRecord) -> Result<()> {
    if delivery.message == [0u8; 16]
        || delivery.account == [0u8; 32]
        || delivery.device == [0u8; 32]
    {
        return Err(StoreError::Serialization);
    }
    Ok(())
}
