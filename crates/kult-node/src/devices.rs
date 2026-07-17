//! C2 linked-device lifecycle and proximate state transfer.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use kult_crypto::{
    DeviceCertificate, DeviceLinkOffer, DeviceLinkResponse, DeviceManifest,
    PendingDeviceLinkSource, PendingDeviceLinkTarget,
};
use kult_protocol::{
    decode_content, resolve_device_sync_events, DecodedContent, DeviceSyncBundle, DeviceSyncEvent,
    DeviceSyncNamespace,
};
use kult_store::{
    ContactDeviceRecord, ContactRecord, DeviceChannelRecord, DeviceStateRecord,
    DeviceTransferGroup, DeviceTransferSelection, DeviceTransferSnapshot, Direction,
    EphemeralRecord, GroupAuthorityRecord, GroupMessageRecord, LocalMetadataKey,
    LocalMetadataRecord, MessageRecord, NoteMessageRecord, Store, THEME_PREFERENCE_KEY,
};

use crate::{
    DeviceLinkSelection, Event, Identity, LinkedDeviceInfo, MessageDeviceDeliveryInfo, Node,
    NodeError, Result,
};

const LINK_OFFER_LIFETIME_SECS: u64 = 10 * 60;
const DEFAULT_DEVICE_NAME: &str = "This device";

#[derive(Clone, Debug, Serialize, Deserialize)]
enum SyncHistoryValue {
    Pairwise(MessageRecord),
    Group(GroupMessageRecord),
    Note(NoteMessageRecord),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum SyncGroupValue {
    Definition(DeviceTransferGroup),
    Authority(GroupAuthorityRecord),
}

pub(crate) fn initialize_fresh_device(
    store: &Store,
    account: &Identity,
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let device = Identity::generate(rng);
    let certificate = DeviceCertificate::issue(account, &device, 0, rng);
    let manifest =
        DeviceManifest::initial(account, certificate.clone(), DEFAULT_DEVICE_NAME.into(), 0)?;
    store.put_device_state(
        &DeviceStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: certificate,
            manifest,
            sync_counter: 0,
            channels: Vec::new(),
        },
        rng,
    )?;
    Ok(())
}

pub(crate) fn load_or_migrate_device(
    store: &Store,
    account: &Identity,
) -> Result<(Identity, DeviceStateRecord, bool)> {
    if let Some(state) = store.get_device_state()? {
        let bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
            state
                .local_device_secret
                .as_slice()
                .try_into()
                .map_err(|_| NodeError::CorruptState)?,
        );
        return Ok((Identity::from_bytes(&bytes), state, false));
    }

    // A pre-C2 store has only the account key. Treat that exact key as its
    // legacy physical endpoint until the next tick seals the additive C2
    // state. The deterministic serial avoids requiring entropy during open.
    let account_bytes = account.to_bytes();
    let device = Identity::from_bytes(&account_bytes);
    let mut hash = Sha256::new();
    hash.update(b"Komms-legacy-device-serial-v1");
    hash.update(account.public().ed);
    hash.update(account.public().x);
    let digest: [u8; 32] = hash.finalize().into();
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&digest[..16]);
    if serial == [0u8; 16] {
        serial[0] = 1;
    }
    let certificate = DeviceCertificate::issue_with_serial(account, device.public(), serial, 0)?;
    let manifest =
        DeviceManifest::initial(account, certificate.clone(), DEFAULT_DEVICE_NAME.into(), 0)?;
    let state = DeviceStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: certificate,
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
    };
    Ok((device, state, true))
}

impl Node {
    pub(crate) fn validate_contact_device_manifest(&self, manifest: &DeviceManifest) -> Result<()> {
        manifest.verify()?;
        let account = manifest.account.ed;
        let state_id = manifest.state_id();
        let existing: Vec<ContactDeviceRecord> = self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.account == account)
            .collect();
        if let Some(latest) = existing
            .iter()
            .filter(|endpoint| endpoint.manifest_generation > 0)
            .max_by_key(|endpoint| (endpoint.manifest_generation, endpoint.manifest_state_id))
        {
            if (manifest.generation, state_id)
                < (latest.manifest_generation, latest.manifest_state_id)
            {
                return Err(NodeError::InvalidDeviceManifest);
            }
        }
        for old in existing
            .iter()
            .filter(|endpoint| endpoint.manifest_generation > 0)
        {
            let Some(next) = manifest
                .devices
                .iter()
                .find(|entry| entry.certificate.device_id() == old.device)
            else {
                return Err(NodeError::InvalidDeviceManifest);
            };
            let old_certificate: DeviceCertificate =
                postcard::from_bytes(&old.certificate).map_err(|_| NodeError::CorruptState)?;
            if next.certificate != old_certificate
                || (old.revoked_at.is_some()
                    && (next.revoked_at != old.revoked_at
                        || next.revoked_after_counter != old.revoked_after_counter))
            {
                return Err(NodeError::InvalidDeviceManifest);
            }
        }
        Ok(())
    }

    pub(crate) fn apply_contact_device_manifest(
        &mut self,
        manifest: &DeviceManifest,
        advertised_device: [u8; 32],
        advertised_bundle: Vec<u8>,
        advertised_hints: Vec<Vec<u8>>,
        observed_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.validate_contact_device_manifest(manifest)?;
        let account = manifest.account.ed;
        let state_id = manifest.state_id();
        let existing: Vec<ContactDeviceRecord> = self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.account == account)
            .collect();

        // A pre-C2 raw account bundle represented the original installation
        // under the account id. Bind that compatibility route to the unique
        // earliest-issued active certificate when the first manifest arrives.
        let legacy_alias = existing
            .iter()
            .find(|endpoint| endpoint.device == account && endpoint.manifest_generation == 0);
        let mut active_by_issuance: Vec<_> = manifest
            .devices
            .iter()
            .filter(|entry| entry.revoked_at.is_none())
            .collect();
        active_by_issuance
            .sort_by_key(|entry| (entry.certificate.issued_at, entry.certificate.device_id()));
        let legacy_replacement = legacy_alias.and_then(|_| {
            let first = active_by_issuance.first()?;
            let unique_earliest = active_by_issuance
                .get(1)
                .is_none_or(|second| second.certificate.issued_at > first.certificate.issued_at);
            unique_earliest.then_some(first.certificate.device_id())
        });

        for entry in &manifest.devices {
            let device = entry.certificate.device_id();
            let prior = existing
                .iter()
                .find(|endpoint| endpoint.device == device)
                .or_else(|| {
                    (legacy_replacement == Some(device))
                        .then_some(legacy_alias)
                        .flatten()
                });
            let advertised = device == advertised_device;
            let mut bundle = prior.map_or_else(Vec::new, |endpoint| endpoint.bundle.clone());
            let mut hints = prior.map_or_else(Vec::new, |endpoint| endpoint.hints.clone());
            if advertised {
                bundle = advertised_bundle.clone();
                if !advertised_hints.is_empty() || hints.is_empty() {
                    hints = advertised_hints.clone();
                }
            }
            let endpoint = ContactDeviceRecord {
                account,
                device,
                name: Some(entry.name.clone()),
                certificate: postcard::to_allocvec(&entry.certificate)
                    .map_err(|_| NodeError::CorruptState)?,
                bundle,
                hints,
                manifest_generation: manifest.generation,
                manifest_state_id: state_id,
                last_seen: entry
                    .last_seen
                    .max(prior.map_or(0, |endpoint| endpoint.last_seen))
                    .max(if advertised { observed_at } else { 0 }),
                revoked_at: entry.revoked_at,
                revoked_after_counter: entry.revoked_after_counter,
            };
            self.store.put_contact_device(&endpoint, rng)?;
            if endpoint.revoked_at.is_some() {
                self.sessions.remove(&device);
                self.capabilities_advertised.remove(&device);
                self.store.delete_session(&device)?;
                self.store.delete_capabilities(&device)?;
                self.store.queue_remove_peer(&device)?;
            }
        }
        if let (Some(alias), Some(replacement)) = (legacy_alias, legacy_replacement) {
            if let Some(session) = self
                .sessions
                .remove(&alias.device)
                .or(self.store.get_session(&alias.device)?)
            {
                self.store.put_session(&replacement, &session, rng)?;
                self.sessions.insert(replacement, session);
            }
            if let Some(capabilities) = self.store.get_capabilities(&alias.device)? {
                self.store
                    .put_capabilities(&replacement, &capabilities, rng)?;
            }
            if self.capabilities_advertised.remove(&alias.device) {
                self.capabilities_advertised.insert(replacement);
            }
            self.store
                .queue_retarget_peer(&alias.device, &replacement, rng)?;
            self.store.retarget_message_device_deliveries(
                &account,
                &alias.device,
                &replacement,
                rng,
            )?;
            self.groups_retarget_legacy_device_chain(&account, &alias.device, &replacement, rng)?;
            self.store.delete_session(&alias.device)?;
            self.store.delete_capabilities(&alias.device)?;
            self.store.delete_contact_device(&account, &alias.device)?;
        }
        Ok(())
    }

    pub(crate) fn account_for_device(&self, device: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(self
            .store
            .contact_devices()?
            .into_iter()
            .find(|endpoint| &endpoint.device == device)
            .map_or(*device, |endpoint| endpoint.account))
    }

    /// Exact separately authenticated key for this physical installation.
    pub fn device_id(&self) -> [u8; 32] {
        self.device_identity.public().ed
    }

    /// Current complete account-authorized device list, including revoked rows.
    pub fn linked_devices(&self) -> Vec<LinkedDeviceInfo> {
        let current = self.device_id();
        self.device_state
            .manifest
            .devices
            .iter()
            .map(|entry| LinkedDeviceInfo {
                id: entry.certificate.device_id(),
                name: entry.name.clone(),
                last_seen: entry.last_seen,
                revoked_at: entry.revoked_at,
                current: entry.certificate.device_id() == current,
            })
            .collect()
    }

    /// Honest per-device delivery rows for one account-level message.
    pub fn message_device_deliveries(
        &self,
        message: &[u8; 16],
    ) -> Result<Vec<MessageDeviceDeliveryInfo>> {
        let endpoints = self.store.contact_devices()?;
        Ok(self
            .store
            .message_device_deliveries(message)?
            .into_iter()
            .map(|delivery| MessageDeviceDeliveryInfo {
                device: delivery.device,
                name: endpoints
                    .iter()
                    .find(|endpoint| endpoint.device == delivery.device)
                    .and_then(|endpoint| endpoint.name.clone()),
                state: delivery.state,
            })
            .collect())
    }

    /// Rename one active exact physical device and advance signed authority.
    pub fn rename_linked_device(
        &mut self,
        device: &[u8; 32],
        name: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut manifest = self.device_state.manifest.clone();
        manifest
            .rename_device(&self.identity, device, name.to_owned())
            .map_err(|_| NodeError::UnknownLinkedDevice)?;
        self.device_state.manifest = manifest;
        self.store.put_device_state(&self.device_state, rng)?;
        self.events.push_back(Event::DevicesChanged);
        Ok(())
    }

    /// Permanently revoke another physical device and its sync channel.
    pub fn revoke_linked_device(
        &mut self,
        device: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if device == &self.device_id() {
            return Err(NodeError::CannotRevokeCurrentDevice);
        }
        let cutoff = self
            .store
            .device_sync_events()?
            .into_iter()
            .filter_map(|bytes| DeviceSyncEvent::decode(&bytes).ok())
            .filter(|event| &event.author_device == device)
            .map(|event| event.counter)
            .max()
            .unwrap_or(0);
        let mut manifest = self.device_state.manifest.clone();
        manifest
            .revoke_device(&self.identity, device, now, cutoff)
            .map_err(|_| NodeError::UnknownLinkedDevice)?;
        self.device_state.manifest = manifest;
        self.device_state
            .channels
            .retain(|channel| &channel.peer_device != device);
        // Revocation always rotates this installation's sender chains. A
        // revoked copy can retain old ciphertext/key material, but receives
        // no fresh chain snapshots from the surviving channel set.
        for mut group in self.store.groups()? {
            self.rotate_group(&mut group, rng)?;
            self.store.put_group(&group, rng)?;
        }
        self.store.put_device_state(&self.device_state, rng)?;
        self.events.push_back(Event::DevicesChanged);
        Ok(())
    }

    /// Begin a ten-minute account-authenticated QR linking offer.
    pub fn begin_device_link(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        let expires_at = now
            .checked_add(LINK_OFFER_LIFETIME_SECS)
            .ok_or(NodeError::InvalidDeviceLink)?;
        let (pending, offer) = PendingDeviceLinkSource::begin(
            &self.identity,
            &self.device_state.manifest,
            self.device_id(),
            expires_at,
            rng,
        )?;
        self.pending_device_link_source = Some(pending);
        offer.encode().map_err(Into::into)
    }

    /// Accept an offer on a new/pristine target and produce the response QR
    /// plus the six-digit code both people must compare.
    pub fn accept_device_link(
        &mut self,
        offer: &[u8],
        name: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, String)> {
        if !self.device_link_target_is_pristine()? {
            return Err(NodeError::DeviceLinkTargetNotEmpty);
        }
        let offer = DeviceLinkOffer::decode_and_verify(offer, now)?;
        let (pending, response, code) = PendingDeviceLinkTarget::accept(
            offer,
            &self.device_identity,
            name.to_owned(),
            now,
            rng,
        )?;
        self.pending_device_link_target = Some(pending);
        Ok((response.encode()?, code.digits()))
    }

    /// Verify a target response against the pending source offer and return
    /// the source-side six-digit comparison code.
    pub fn device_link_confirmation_code(&self, response: &[u8]) -> Result<String> {
        let pending = self
            .pending_device_link_source
            .as_ref()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        let response = DeviceLinkResponse::decode(response)?;
        Ok(pending.confirmation_code(&response)?.digits())
    }

    /// After explicit comparison approval, issue the target certificate and
    /// encrypt the selected initial state transfer.
    pub fn approve_device_link(
        &mut self,
        response: &[u8],
        selection: DeviceLinkSelection,
        confirmed: bool,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let pending = self
            .pending_device_link_source
            .take()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        let response = DeviceLinkResponse::decode(response)?;
        let snapshot = self.store.export_device_transfer(DeviceTransferSelection {
            contacts: selection.contacts,
            organization: selection.organization,
            history: selection.history,
        })?;
        let snapshot = postcard::to_allocvec(&snapshot).map_err(|_| NodeError::CorruptState)?;
        let approved = pending.approve(&self.identity, &response, confirmed, now, snapshot, rng)?;
        self.device_state.manifest = approved.manifest;
        self.device_state.channels.push(DeviceChannelRecord {
            peer_device: approved.target_device,
            root: *approved.channel_root,
            send_counter: 0,
            receive_counter: 0,
        });
        self.device_state
            .channels
            .sort_by_key(|channel| channel.peer_device);
        self.store.put_device_state(&self.device_state, rng)?;
        self.events.push_back(Event::DevicesChanged);
        Ok(approved.package)
    }

    /// Complete a confirmed target ceremony and atomically switch this
    /// pristine installation to the linked account.
    pub fn complete_device_link(
        &mut self,
        package: &[u8],
        confirmed: bool,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let pending = self
            .pending_device_link_target
            .take()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        if !self.device_link_target_is_pristine()? {
            return Err(NodeError::DeviceLinkTargetNotEmpty);
        }
        let completed = pending.complete(package, confirmed, now)?;
        let (snapshot, remainder): (DeviceTransferSnapshot, &[u8]) =
            postcard::take_from_bytes(&completed.sync_payload)
                .map_err(|_| NodeError::InvalidDeviceLink)?;
        if !remainder.is_empty() || completed.certificate.device != self.device_identity.public() {
            return Err(NodeError::InvalidDeviceLink);
        }
        self.store.put_identity(&completed.account, rng)?;
        self.store
            .import_device_transfer(&snapshot, completed.account.public().ed, rng)?;
        self.identity = completed.account;
        self.device_state = DeviceStateRecord {
            local_device_secret: self.device_identity.to_bytes().to_vec(),
            local_certificate: completed.certificate,
            manifest: completed.manifest,
            sync_counter: 0,
            channels: vec![DeviceChannelRecord {
                peer_device: completed.authorizer_device,
                root: *completed.channel_root,
                send_counter: 0,
                receive_counter: 0,
            }],
        };
        self.store.put_device_state(&self.device_state, rng)?;
        self.sessions.clear();
        self.capabilities_advertised.clear();
        self.events.push_back(Event::DeviceLinkCompleted {
            account: self.identity.public().ed,
            device: self.device_id(),
        });
        self.events.push_back(Event::DevicesChanged);
        Ok(())
    }

    /// Export a complete encrypted convergence log to one active linked peer.
    pub fn export_device_sync(
        &mut self,
        peer_device: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.capture_device_sync_state(rng)?;
        let local = self.device_id();
        let channel = self
            .device_state
            .channels
            .iter_mut()
            .find(|channel| &channel.peer_device == peer_device)
            .ok_or(NodeError::UnknownLinkedDevice)?;
        channel.send_counter = channel
            .send_counter
            .checked_add(1)
            .ok_or(NodeError::InvalidDeviceSync)?;
        let events = self
            .store
            .device_sync_events()?
            .into_iter()
            .map(|event| DeviceSyncEvent::decode(&event))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let bundle = DeviceSyncBundle::seal(
            &channel.root,
            local,
            *peer_device,
            channel.send_counter,
            self.device_state.manifest.clone(),
            events,
            rng,
        )?;
        self.store.put_device_state(&self.device_state, rng)?;
        bundle.encode().map_err(Into::into)
    }

    /// Import one authenticated linked-device convergence bundle. Replays,
    /// rollback manifests, wrong direction, and revoked-author events fail.
    pub fn import_device_sync(
        &mut self,
        encoded: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize> {
        let bundle = DeviceSyncBundle::decode(encoded)?;
        let local = self.device_id();
        let channel_index = self
            .device_state
            .channels
            .iter()
            .position(|channel| channel.peer_device == bundle.sender)
            .ok_or(NodeError::UnknownLinkedDevice)?;
        let channel = &self.device_state.channels[channel_index];
        if bundle.recipient != local || bundle.sequence <= channel.receive_counter {
            return Err(NodeError::InvalidDeviceSync);
        }
        let opened = bundle.open(&channel.root, &local, &bundle.sender)?;
        if opened.manifest != self.device_state.manifest
            && !self
                .device_state
                .manifest
                .accepts_successor(&opened.manifest)?
        {
            return Err(NodeError::InvalidDeviceSync);
        }
        let manifest_changed = opened.manifest != self.device_state.manifest;
        let newly_revoked = self
            .device_state
            .manifest
            .devices
            .iter()
            .filter(|old| old.revoked_at.is_none())
            .any(|old| {
                opened.manifest.devices.iter().any(|new| {
                    new.certificate.device_id() == old.certificate.device_id()
                        && new.revoked_at.is_some()
                })
            });
        let mut inserted = 0usize;
        for event in opened.events {
            let encoded = event.encode()?;
            if self.store.put_device_sync_event(&encoded, rng)? {
                inserted += 1;
            }
        }
        self.device_state.manifest = opened.manifest;
        self.device_state.channels[channel_index].receive_counter = bundle.sequence;
        self.device_state.channels.retain(|channel| {
            self.device_state.manifest.devices.iter().any(|entry| {
                entry.certificate.device_id() == channel.peer_device && entry.revoked_at.is_none()
            })
        });
        if newly_revoked {
            for mut group in self.store.groups()? {
                self.rotate_group(&mut group, rng)?;
                self.store.put_group(&group, rng)?;
            }
        }
        self.store.put_device_state(&self.device_state, rng)?;
        self.apply_resolved_device_sync(rng)?;
        if inserted > 0 || manifest_changed {
            self.events.push_back(Event::DevicesChanged);
        }
        Ok(inserted)
    }

    fn capture_device_sync_state(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        let snapshot = self
            .store
            .export_device_transfer(DeviceTransferSelection::default())?;
        let mut current: BTreeMap<(DeviceSyncNamespace, Vec<u8>), Vec<u8>> = BTreeMap::new();

        for mut contact in snapshot.contacts {
            let peer = contact.peer.to_vec();
            let verified = contact.verified;
            contact.verified = false;
            current.insert(
                (DeviceSyncNamespace::Contacts, peer.clone()),
                postcard::to_allocvec(&contact).map_err(|_| NodeError::CorruptState)?,
            );
            current.insert(
                (DeviceSyncNamespace::Verification, peer),
                vec![u8::from(verified)],
            );
        }
        for endpoint in snapshot.contact_devices {
            let mut key = Vec::with_capacity(65);
            key.push(b'd');
            key.extend_from_slice(&endpoint.account);
            key.extend_from_slice(&endpoint.device);
            current.insert(
                (DeviceSyncNamespace::Contacts, key),
                postcard::to_allocvec(&endpoint).map_err(|_| NodeError::CorruptState)?,
            );
        }
        for record in snapshot.local_metadata {
            if matches!(record, LocalMetadataRecord::Draft(_))
                || matches!(
                    &record,
                    LocalMetadataRecord::UiPreference(preference)
                        if preference.key != THEME_PREFERENCE_KEY
                )
            {
                continue;
            }
            let key = postcard::to_allocvec(&record.key()).map_err(|_| NodeError::CorruptState)?;
            let value = postcard::to_allocvec(&record).map_err(|_| NodeError::CorruptState)?;
            current.insert((DeviceSyncNamespace::LocalOrganization, key), value);
        }
        for message in snapshot.messages {
            let namespace = if matches!(decode_content(&message.body), DecodedContent::Edit { .. })
            {
                DeviceSyncNamespace::MessageEdits
            } else {
                DeviceSyncNamespace::ConversationHistory
            };
            let mut key = Vec::with_capacity(1 + 32 + 1 + 16);
            key.push(b'p');
            key.extend_from_slice(&message.peer);
            key.push(match message.direction {
                Direction::Outbound => 1,
                Direction::Inbound => 2,
            });
            key.extend_from_slice(&message.id);
            current.insert(
                (namespace, key),
                postcard::to_allocvec(&SyncHistoryValue::Pairwise(message))
                    .map_err(|_| NodeError::CorruptState)?,
            );
        }
        for message in snapshot.group_messages {
            let namespace = match decode_content(&message.body) {
                DecodedContent::Edit { .. } => DeviceSyncNamespace::MessageEdits,
                DecodedContent::Poll { .. } => DeviceSyncNamespace::GroupPolls,
                _ => DeviceSyncNamespace::ConversationHistory,
            };
            let mut key = Vec::with_capacity(1 + 32 + 32 + 16);
            key.push(b'g');
            key.extend_from_slice(&message.group);
            key.extend_from_slice(&message.sender);
            key.extend_from_slice(&message.id);
            current.insert(
                (namespace, key),
                postcard::to_allocvec(&SyncHistoryValue::Group(message))
                    .map_err(|_| NodeError::CorruptState)?,
            );
        }
        for message in snapshot.note_messages {
            let mut key = Vec::with_capacity(17);
            key.push(b'n');
            key.extend_from_slice(&message.id);
            current.insert(
                (DeviceSyncNamespace::ConversationHistory, key),
                postcard::to_allocvec(&SyncHistoryValue::Note(message))
                    .map_err(|_| NodeError::CorruptState)?,
            );
        }
        for group in snapshot.groups {
            let mut key = Vec::with_capacity(33);
            key.push(b'd');
            key.extend_from_slice(&group.id);
            current.insert(
                (DeviceSyncNamespace::Groups, key),
                postcard::to_allocvec(&SyncGroupValue::Definition(group))
                    .map_err(|_| NodeError::CorruptState)?,
            );
        }
        for authority in snapshot.group_authorities {
            let mut key = Vec::with_capacity(33);
            key.push(b'a');
            key.extend_from_slice(&authority.group);
            current.insert(
                (DeviceSyncNamespace::Groups, key),
                postcard::to_allocvec(&SyncGroupValue::Authority(authority))
                    .map_err(|_| NodeError::CorruptState)?,
            );
        }
        for tombstone in snapshot.ephemeral_tombstones {
            let key = ephemeral_sync_key(&tombstone)?;
            current.insert(
                (DeviceSyncNamespace::ExpiryTombstones, key),
                postcard::to_allocvec(&tombstone).map_err(|_| NodeError::CorruptState)?,
            );
        }

        let stored = self
            .store
            .device_sync_events()?
            .into_iter()
            .map(|bytes| DeviceSyncEvent::decode(&bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let resolved = resolve_device_sync_events(&self.device_state.manifest, stored);
        let mut lamport = resolved
            .values()
            .map(|event| event.lamport)
            .max()
            .unwrap_or(0);
        let mut mutations = Vec::new();
        for ((namespace, key), value) in &current {
            if resolved
                .get(&(*namespace, key.clone()))
                .is_none_or(|event| event.value.as_ref() != Some(value))
            {
                mutations.push((*namespace, key.clone(), Some(value.clone())));
            }
        }
        for ((namespace, key), event) in &resolved {
            if !current.contains_key(&(*namespace, key.clone())) && event.value.is_some() {
                mutations.push((*namespace, key.clone(), None));
            }
        }
        for (namespace, key, value) in mutations {
            self.device_state.sync_counter = self
                .device_state
                .sync_counter
                .checked_add(1)
                .ok_or(NodeError::InvalidDeviceSync)?;
            lamport = lamport.checked_add(1).ok_or(NodeError::InvalidDeviceSync)?;
            let event = DeviceSyncEvent::sign(
                self.identity.public().ed,
                &self.device_identity,
                self.device_state.sync_counter,
                lamport,
                self.device_state.manifest.generation,
                namespace,
                key,
                value,
            )?;
            self.store.put_device_sync_event(&event.encode()?, rng)?;
        }

        // Retain only converged winners. This bounds replay material while
        // preserving every live value and tombstone needed by a new peer.
        let all = self
            .store
            .device_sync_events()?
            .into_iter()
            .map(|bytes| DeviceSyncEvent::decode(&bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let compacted = resolve_device_sync_events(&self.device_state.manifest, all)
            .into_values()
            .map(|event| event.encode())
            .collect::<core::result::Result<Vec<_>, _>>()?;
        self.store.retain_device_sync_events(&compacted)?;
        self.store.put_device_state(&self.device_state, rng)?;
        Ok(())
    }

    fn apply_resolved_device_sync(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        let events = self
            .store
            .device_sync_events()?
            .into_iter()
            .map(|bytes| DeviceSyncEvent::decode(&bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        for ((namespace, key), event) in
            resolve_device_sync_events(&self.device_state.manifest, events)
        {
            match namespace {
                DeviceSyncNamespace::Contacts => {
                    if key.len() == 32 {
                        let peer: [u8; 32] = key
                            .as_slice()
                            .try_into()
                            .map_err(|_| NodeError::InvalidDeviceSync)?;
                        if let Some(value) = event.value {
                            let mut contact: ContactRecord = decode_exact(&value)?;
                            if contact.peer != peer {
                                return Err(NodeError::InvalidDeviceSync);
                            }
                            let verified = self
                                .store
                                .get_contact(&peer)?
                                .is_some_and(|stored| stored.verified);
                            contact.verified = verified;
                            self.store.put_contact(&contact, rng)?;
                        } else {
                            self.store.delete_contact(&peer)?;
                            self.sessions.remove(&peer);
                        }
                    } else if key.len() == 65 && key[0] == b'd' {
                        let account: [u8; 32] = key[1..33]
                            .try_into()
                            .map_err(|_| NodeError::InvalidDeviceSync)?;
                        let device: [u8; 32] = key[33..65]
                            .try_into()
                            .map_err(|_| NodeError::InvalidDeviceSync)?;
                        if let Some(value) = event.value {
                            let endpoint: ContactDeviceRecord = decode_exact(&value)?;
                            if endpoint.account != account || endpoint.device != device {
                                return Err(NodeError::InvalidDeviceSync);
                            }
                            self.store.put_contact_device(&endpoint, rng)?;
                            if endpoint.revoked_at.is_some() {
                                self.sessions.remove(&device);
                                self.capabilities_advertised.remove(&device);
                                self.store.delete_session(&device)?;
                                self.store.delete_capabilities(&device)?;
                                self.store.queue_remove_peer(&device)?;
                            }
                        } else {
                            self.sessions.remove(&device);
                            self.capabilities_advertised.remove(&device);
                            self.store.delete_session(&device)?;
                            self.store.delete_capabilities(&device)?;
                            self.store.queue_remove_peer(&device)?;
                            self.store.delete_contact_device(&account, &device)?;
                        }
                    } else {
                        return Err(NodeError::InvalidDeviceSync);
                    }
                }
                DeviceSyncNamespace::Verification => {
                    let peer: [u8; 32] = key
                        .as_slice()
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    let verified = event.value.as_deref() == Some(&[1][..]);
                    if let Some(mut contact) = self.store.get_contact(&peer)? {
                        contact.verified = verified;
                        self.store.put_contact(&contact, rng)?;
                    }
                }
                DeviceSyncNamespace::LocalOrganization => {
                    let metadata_key: LocalMetadataKey = decode_exact(&key)?;
                    if let Some(value) = event.value {
                        let record: LocalMetadataRecord = decode_exact(&value)?;
                        if record.key() != metadata_key
                            || matches!(record, LocalMetadataRecord::Draft(_))
                            || matches!(
                                &record,
                                LocalMetadataRecord::UiPreference(preference)
                                    if preference.key != THEME_PREFERENCE_KEY
                            )
                        {
                            return Err(NodeError::InvalidDeviceSync);
                        }
                        self.store.put_local_metadata(&record, rng)?;
                    } else {
                        self.store.delete_local_metadata(&metadata_key)?;
                    }
                }
                DeviceSyncNamespace::ConversationHistory
                | DeviceSyncNamespace::MessageEdits
                | DeviceSyncNamespace::GroupPolls => {
                    self.apply_sync_history(&key, event.value.as_deref(), rng)?;
                }
                DeviceSyncNamespace::Groups => {
                    if let Some(value) = event.value {
                        self.apply_sync_group(&key, &value, rng)?;
                    }
                }
                DeviceSyncNamespace::ExpiryTombstones => {
                    if let Some(value) = event.value {
                        let tombstone: EphemeralRecord = decode_exact(&value)?;
                        if ephemeral_sync_key(&tombstone)? != key
                            || tombstone.state == kult_store::EphemeralState::Active
                            || !tombstone.transfer_ids.is_empty()
                        {
                            return Err(NodeError::InvalidDeviceSync);
                        }
                        self.store.put_ephemeral_record(&tombstone, rng)?;
                        match tombstone.conversation {
                            kult_store::EphemeralConversation::Pairwise(peer) => {
                                self.store.delete_message_record(
                                    &peer,
                                    if tombstone.author == self.identity.public().ed {
                                        Direction::Outbound
                                    } else {
                                        Direction::Inbound
                                    },
                                    &tombstone.content_id,
                                )?;
                            }
                            kult_store::EphemeralConversation::Group(group) => {
                                self.store.delete_group_message_record(
                                    &group,
                                    &tombstone.author,
                                    &tombstone.content_id,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_sync_history(
        &mut self,
        key: &[u8],
        value: Option<&[u8]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(value) = value else {
            match key.first().copied() {
                Some(b'p') if key.len() == 50 => {
                    let peer: [u8; 32] = key[1..33]
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    let direction = match key[33] {
                        1 => Direction::Outbound,
                        2 => Direction::Inbound,
                        _ => return Err(NodeError::InvalidDeviceSync),
                    };
                    let id: [u8; 16] = key[34..]
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    self.store.delete_message_record(&peer, direction, &id)?;
                }
                Some(b'g') if key.len() == 81 => {
                    let group: [u8; 32] = key[1..33]
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    let sender: [u8; 32] = key[33..65]
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    let id: [u8; 16] = key[65..]
                        .try_into()
                        .map_err(|_| NodeError::InvalidDeviceSync)?;
                    self.store
                        .delete_group_message_record(&group, &sender, &id)?;
                }
                _ => {}
            }
            return Ok(());
        };
        match decode_exact::<SyncHistoryValue>(value)? {
            SyncHistoryValue::Pairwise(mut message) => {
                let mut expected = Vec::with_capacity(50);
                expected.push(b'p');
                expected.extend_from_slice(&message.peer);
                expected.push(match message.direction {
                    Direction::Outbound => 1,
                    Direction::Inbound => 2,
                });
                expected.extend_from_slice(&message.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                // A target device never inherits another device's queue/wire
                // promise. History delivery is account-level and immutable.
                message.wire_id = None;
                if !self.store.update_message(&message, rng)? {
                    self.store.put_message(&message, rng)?;
                }
            }
            SyncHistoryValue::Group(mut message) => {
                let mut expected = Vec::with_capacity(81);
                expected.push(b'g');
                expected.extend_from_slice(&message.group);
                expected.extend_from_slice(&message.sender);
                expected.extend_from_slice(&message.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                message.wire_body = None;
                if !self.store.update_group_message(&message, rng)? {
                    self.store.put_group_message(&message, rng)?;
                }
            }
            SyncHistoryValue::Note(message) => {
                let mut expected = Vec::with_capacity(17);
                expected.push(b'n');
                expected.extend_from_slice(&message.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                if !self
                    .store
                    .note_messages()?
                    .iter()
                    .any(|stored| stored.id == message.id)
                {
                    self.store.put_note_message(&message, rng)?;
                }
            }
        }
        Ok(())
    }

    fn apply_sync_group(
        &mut self,
        key: &[u8],
        value: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        match decode_exact::<SyncGroupValue>(value)? {
            SyncGroupValue::Definition(group) => {
                let mut expected = Vec::with_capacity(33);
                expected.push(b'd');
                expected.extend_from_slice(&group.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                if let Some(mut stored) = self.store.get_group(&group.id)? {
                    if group.generation >= stored.generation {
                        stored.name = group.name;
                        stored.creator = group.creator;
                        stored.members = group.members;
                        stored.secret = group.secret;
                        stored.prev_secret = None;
                        stored.generation = group.generation;
                        self.store.put_group(&stored, rng)?;
                    }
                } else {
                    self.store.import_device_transfer(
                        &DeviceTransferSnapshot {
                            contacts: Vec::new(),
                            contact_devices: Vec::new(),
                            messages: Vec::new(),
                            groups: vec![group],
                            group_messages: Vec::new(),
                            group_authorities: Vec::new(),
                            local_metadata: Vec::new(),
                            note_messages: Vec::new(),
                            ephemeral_tombstones: Vec::new(),
                            sync_events: Vec::new(),
                        },
                        self.identity.public().ed,
                        rng,
                    )?;
                }
            }
            SyncGroupValue::Authority(authority) => {
                let mut expected = Vec::with_capacity(33);
                expected.push(b'a');
                expected.extend_from_slice(&authority.group);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                self.store.put_group_authority(&authority, rng)?;
            }
        }
        Ok(())
    }

    fn device_link_target_is_pristine(&self) -> Result<bool> {
        Ok(self.store.contacts()?.is_empty()
            && self.store.groups()?.is_empty()
            && self.store.all_group_messages()?.is_empty()
            && self.store.local_metadata()?.is_empty()
            && self.store.note_messages()?.is_empty()
            && self.store.device_sync_events()?.is_empty()
            && self.store.queue_all()?.is_empty()
            && self.sessions.is_empty())
    }
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let (value, remainder): (T, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| NodeError::InvalidDeviceSync)?;
    if !remainder.is_empty() {
        return Err(NodeError::InvalidDeviceSync);
    }
    Ok(value)
}

fn ephemeral_sync_key(record: &EphemeralRecord) -> Result<Vec<u8>> {
    postcard::to_allocvec(&(record.conversation, record.author, record.content_id))
        .map_err(|_| NodeError::CorruptState)
}
