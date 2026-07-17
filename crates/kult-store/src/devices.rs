//! Sealed C2 linked-device authority, channel roots, and sync-event storage.
//!
//! Device ids and sync keys never appear in plaintext SQLite columns. The
//! tables expose only row counts and approximate sealed sizes to a copied
//! database, matching the rest of the store's local-metadata boundary.

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{DeviceCertificate, DeviceManifest, GroupSenderChain, Identity};

use crate::{
    ContactRecord, DeliveryState, EphemeralRecord, EphemeralState, GroupAuthorityRecord,
    GroupMember, GroupMessageRecord, GroupRecord, LocalMetadataRecord, MessageRecord,
    NoteMessageRecord, PendingAnnounce, Result, Store, StoreError, THEME_PREFERENCE_KEY,
};

const DEVICE_STATE_AD: &[u8] = b"device-state-v1";
const DEVICE_SYNC_AD: &[u8] = b"device-sync-v1";
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
    /// Honest queued/sent/delivered ladder for this endpoint.
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
    fn validate(&self, account: &Identity) -> Result<()> {
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
            sync_events: self.device_sync_events()?,
        })
    }

    /// Import one authenticated link snapshot into a new/pristine target.
    /// Group sending/receiving chains are regenerated rather than copied.
    pub fn import_device_transfer(
        &self,
        snapshot: &DeviceTransferSnapshot,
        me: [u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for contact in &snapshot.contacts {
            self.put_contact(contact, rng)?;
        }
        for endpoint in &snapshot.contact_devices {
            self.put_contact_device(endpoint, rng)?;
        }
        for message in &snapshot.messages {
            self.put_message(message, rng)?;
        }
        for group in &snapshot.groups {
            let chain = GroupSenderChain::generate(rng);
            let (key_id, chain_key, iteration) = chain.snapshot();
            let pending = group
                .members
                .iter()
                .filter(|member| member.peer != me)
                .map(|member| PendingAnnounce {
                    peer: member.peer,
                    key_id,
                    chain_key: *chain_key,
                    iteration,
                    wire_id: None,
                    last_sent: 0,
                })
                .collect();
            self.put_group(
                &GroupRecord {
                    id: group.id,
                    name: group.name.clone(),
                    creator: group.creator,
                    members: group.members.clone(),
                    secret: group.secret,
                    prev_secret: None,
                    generation: group.generation,
                    sender_chain: postcard::to_allocvec(&chain)
                        .map_err(|_| StoreError::Serialization)?,
                    sent_since_rotation: 0,
                    pending,
                },
                rng,
            )?;
        }
        for message in &snapshot.group_messages {
            self.put_group_message(message, rng)?;
        }
        for authority in &snapshot.group_authorities {
            self.put_group_authority(authority, rng)?;
        }
        for record in &snapshot.local_metadata {
            if matches!(record, LocalMetadataRecord::Draft(_)) {
                return Err(StoreError::Serialization);
            }
            self.put_local_metadata(record, rng)?;
        }
        for message in &snapshot.note_messages {
            self.put_note_message(message, rng)?;
        }
        for record in &snapshot.ephemeral_tombstones {
            if record.state == EphemeralState::Active || !record.transfer_ids.is_empty() {
                return Err(StoreError::Serialization);
            }
            self.put_ephemeral_record(record, rng)?;
        }
        for event in &snapshot.sync_events {
            self.put_device_sync_event(event, rng)?;
        }
        Ok(())
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
        let sealed = self.k_devices.seal(DEVICE_STATE_AD, &plain, rng);
        self.conn.execute(
            "INSERT OR REPLACE INTO device_state (id, blob) VALUES (1, ?1)",
            params![sealed],
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
        let encoded = postcard::to_allocvec(endpoint).map_err(|_| StoreError::Serialization)?;
        let sealed = self.k_devices.seal(b"contact-device-v1", &encoded, rng);
        let mut statement = self
            .conn
            .prepare("SELECT rowid_, blob FROM contact_devices ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, stored) = row?;
            let plain = self.k_devices.open(b"contact-device-v1", &stored)?;
            let decoded: ContactDeviceRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if decoded.account == endpoint.account && decoded.device == endpoint.device {
                self.conn.execute(
                    "UPDATE contact_devices SET blob = ?2 WHERE rowid_ = ?1",
                    params![rowid, sealed],
                )?;
                return Ok(());
            }
        }
        drop(statement);
        self.conn.execute(
            "INSERT INTO contact_devices (blob) VALUES (?1)",
            params![sealed],
        )?;
        Ok(())
    }

    /// Every sealed contact-device endpoint in insertion order.
    pub fn contact_devices(&self) -> Result<Vec<ContactDeviceRecord>> {
        let mut statement = self
            .conn
            .prepare("SELECT blob FROM contact_devices ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut endpoints = Vec::new();
        for row in rows {
            let plain = self.k_devices.open(b"contact-device-v1", &row?)?;
            endpoints.push(postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?);
        }
        Ok(endpoints)
    }

    /// Active endpoints known for one stable contact account.
    pub fn contact_devices_for(&self, account: &[u8; 32]) -> Result<Vec<ContactDeviceRecord>> {
        Ok(self
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| &endpoint.account == account && endpoint.revoked_at.is_none())
            .collect())
    }

    /// Delete one exact sealed contact-device endpoint.
    pub fn delete_contact_device(&self, account: &[u8; 32], device: &[u8; 32]) -> Result<()> {
        let mut statement = self
            .conn
            .prepare("SELECT rowid_, blob FROM contact_devices ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut target = None;
        for row in rows {
            let (rowid, stored) = row?;
            let plain = self.k_devices.open(b"contact-device-v1", &stored)?;
            let decoded: ContactDeviceRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &decoded.account == account && &decoded.device == device {
                target = Some(rowid);
                break;
            }
        }
        drop(statement);
        if let Some(rowid) = target {
            self.conn.execute(
                "DELETE FROM contact_devices WHERE rowid_ = ?1",
                params![rowid],
            )?;
        }
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
        let mut statement = self
            .conn
            .prepare("SELECT rowid_, blob FROM message_device_delivery ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut replacements = Vec::new();
        for row in rows {
            let (rowid, stored) = row?;
            let plain = self
                .k_devices
                .open(b"message-device-delivery-v1", &stored)?;
            let mut delivery: MessageDeviceDeliveryRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &delivery.account == account && &delivery.device == old_device {
                delivery.device = *new_device;
                let encoded =
                    postcard::to_allocvec(&delivery).map_err(|_| StoreError::Serialization)?;
                let sealed = self
                    .k_devices
                    .seal(b"message-device-delivery-v1", &encoded, rng);
                replacements.push((rowid, sealed));
            }
        }
        drop(statement);
        for (rowid, sealed) in replacements {
            self.conn.execute(
                "UPDATE message_device_delivery SET blob = ?2 WHERE rowid_ = ?1",
                params![rowid, sealed],
            )?;
        }
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
        let encoded = postcard::to_allocvec(delivery).map_err(|_| StoreError::Serialization)?;
        let sealed = self
            .k_devices
            .seal(b"message-device-delivery-v1", &encoded, rng);
        let mut statement = self
            .conn
            .prepare("SELECT rowid_, blob FROM message_device_delivery ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (rowid, stored) = row?;
            let plain = self
                .k_devices
                .open(b"message-device-delivery-v1", &stored)?;
            let decoded: MessageDeviceDeliveryRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if decoded.message == delivery.message && decoded.device == delivery.device {
                self.conn.execute(
                    "UPDATE message_device_delivery SET blob = ?2 WHERE rowid_ = ?1",
                    params![rowid, sealed],
                )?;
                return Ok(());
            }
        }
        drop(statement);
        self.conn.execute(
            "INSERT INTO message_device_delivery (blob) VALUES (?1)",
            params![sealed],
        )?;
        Ok(())
    }

    /// Per-device delivery rows for one exact account-level message.
    pub fn message_device_deliveries(
        &self,
        message: &[u8; 16],
    ) -> Result<Vec<MessageDeviceDeliveryRecord>> {
        let mut statement = self
            .conn
            .prepare("SELECT blob FROM message_device_delivery ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut deliveries = Vec::new();
        for row in rows {
            let plain = self.k_devices.open(b"message-device-delivery-v1", &row?)?;
            let delivery: MessageDeviceDeliveryRecord =
                postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
            if &delivery.message == message {
                deliveries.push(delivery);
            }
        }
        Ok(deliveries)
    }

    /// Load and validate the complete local linked-device state, if enabled.
    pub fn get_device_state(&self) -> Result<Option<DeviceStateRecord>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT blob FROM device_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let plain = Zeroizing::new(self.k_devices.open(DEVICE_STATE_AD, &sealed)?);
        let state: DeviceStateRecord =
            postcard::from_bytes(&plain).map_err(|_| StoreError::Serialization)?;
        let account = self.get_identity()?.ok_or(StoreError::NotAStore)?;
        state.validate(&account)?;
        Ok(Some(state))
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
        let existing = self.device_sync_events()?;
        if existing.iter().any(|stored| stored == event) {
            return Ok(false);
        }
        if existing.len() >= MAX_DEVICE_SYNC_EVENTS {
            return Err(StoreError::Serialization);
        }
        let sealed = self.k_devices.seal(DEVICE_SYNC_AD, event, rng);
        self.conn.execute(
            "INSERT INTO device_sync (blob) VALUES (?1)",
            params![sealed],
        )?;
        Ok(true)
    }

    /// Return every opaque authenticated sync event in insertion order.
    pub fn device_sync_events(&self) -> Result<Vec<Vec<u8>>> {
        let mut statement = self
            .conn
            .prepare("SELECT blob FROM device_sync ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut events = Vec::new();
        for row in rows {
            let event = self.k_devices.open(DEVICE_SYNC_AD, &row?)?;
            if event.is_empty() || event.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::Serialization);
            }
            events.push(event);
        }
        Ok(events)
    }

    /// Delete every event except the exact supplied set after a verified
    /// compaction snapshot commits. Event bytes remain sealed lookup keys.
    pub fn retain_device_sync_events(&self, retain: &[Vec<u8>]) -> Result<()> {
        let wanted: HashSet<&[u8]> = retain.iter().map(Vec::as_slice).collect();
        let mut statement = self
            .conn
            .prepare("SELECT rowid_, blob FROM device_sync ORDER BY rowid_")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut remove = Vec::new();
        for row in rows {
            let (rowid, sealed) = row?;
            let event = self.k_devices.open(DEVICE_SYNC_AD, &sealed)?;
            if !wanted.contains(event.as_slice()) {
                remove.push(rowid);
            }
        }
        drop(statement);
        for rowid in remove {
            self.conn
                .execute("DELETE FROM device_sync WHERE rowid_ = ?1", params![rowid])?;
        }
        Ok(())
    }
}
