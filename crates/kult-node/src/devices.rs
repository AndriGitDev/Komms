//! C2 linked-device lifecycle and proximate state transfer.

use std::collections::{BTreeMap, BTreeSet};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use kult_crypto::{
    seal_authority_device_link_recovery_package, AuthorityDeviceLinkApproval,
    AuthorityDeviceLinkApprovalRequest, AuthorityDeviceLinkOffer as DeviceLinkOffer,
    AuthorityDeviceLinkResponse as DeviceLinkResponse, DeviceAuthorityManifest,
    DeviceAuthorityRelation, DeviceAuthorityTransitionKind, GroupSenderChain,
    PendingAuthorityDeviceLinkSource as PendingDeviceLinkSource,
    PendingAuthorityDeviceLinkTarget as PendingDeviceLinkTarget,
};
use kult_protocol::{
    decode_content, resolve_device_sync_events, AuthorityDeviceSyncBundle as DeviceSyncBundle,
    DecodedContent, DeviceSyncEvent, DeviceSyncNamespace,
};
use kult_store::{
    AccountIdentityTransition, AuthorityDeviceControlPlan, AuthorityDeviceLinkPlan,
    CapabilityDelete, CommitPlan, ContactAuthorityConflictRecord, ContactDeviceRecord,
    ContactRecord, DeviceAuthorityConflictKind, DeviceAuthorityConflictRecord,
    DeviceAuthorityStateRecord, DeviceAuthorityStateTransition, DeviceChannelRecord,
    DeviceLinkRecoveryRecord, DeviceLinkRecoveryTransition, DeviceProjection, DeviceProjectionPlan,
    DeviceTransferGroup, DeviceTransferSelection, DeviceTransferSnapshot, Direction,
    EphemeralRecord, EphemeralTransition, GroupAuthorityRecord, GroupAuthorityStateTransition,
    GroupMessageDelete, GroupMessageRecord, GroupOriginAuthentication, GroupRecord, GroupStatePlan,
    GroupStateTransition, GroupTransition, LocalMetadataKey, LocalMetadataRecord, MaintenancePlan,
    MessageDelete, MessageRecord, NoteMessageRecord, PendingAnnounce, QueueDelete, SessionDelete,
    Store, MAX_DEVICE_AUTHORITY_CONFLICTS, MAX_DEVICE_CONTROL_MUTATIONS, THEME_PREFERENCE_KEY,
};

use crate::{
    ContactAuthorityConflictInfo, DeviceAuthorityConflictInfo, DeviceAuthorityConflictType,
    DeviceLinkSelection, Event, Identity, LinkedDeviceInfo, MessageDeviceDeliveryInfo, Node,
    NodeError, Result,
};

const LINK_OFFER_LIFETIME_SECS: u64 = 10 * 60;
const DEFAULT_DEVICE_NAME: &str = "This device";

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn fresh_device_state(
    account: &Identity,
    rng: &mut impl CryptoRngCore,
) -> kult_store::Result<kult_store::DeviceStateRecord> {
    let device = Identity::generate(rng);
    let certificate = kult_crypto::DeviceCertificate::issue(account, &device, 0, rng);
    let manifest = kult_crypto::DeviceManifest::initial(
        account,
        certificate.clone(),
        DEFAULT_DEVICE_NAME.into(),
        0,
    )?;
    Ok(kult_store::DeviceStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: certificate,
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
    })
}

pub(crate) fn fresh_authority_device_state(
    root: &Identity,
    rng: &mut impl CryptoRngCore,
) -> kult_store::Result<(Identity, DeviceAuthorityStateRecord)> {
    let device = Identity::generate(rng);
    let manifest =
        DeviceAuthorityManifest::initial(root, &device, DEFAULT_DEVICE_NAME.into(), 0, rng)?;
    let state = DeviceAuthorityStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: manifest.devices()[0].certificate.clone(),
        accepted_recovery_epoch: manifest.recovery_epoch(),
        accepted_recovery_anchor: manifest.recovery_anchor_id(),
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
        conflicts: Vec::new(),
    };
    Ok((device, state))
}

pub(crate) fn migrate_legacy_authority_device_state(
    root: &Identity,
    legacy: &kult_store::DeviceStateRecord,
    migrated_at: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<(Identity, DeviceAuthorityStateRecord)> {
    if legacy.manifest.devices.len() != 1 || !legacy.channels.is_empty() {
        return Err(NodeError::AuthorityResetRequired);
    }
    let device_bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
        legacy
            .local_device_secret
            .as_slice()
            .try_into()
            .map_err(|_| NodeError::CorruptState)?,
    );
    let device = Identity::from_bytes(&device_bytes);
    let local_id = device.public().ed;
    let old_entry = legacy
        .manifest
        .devices
        .iter()
        .find(|entry| {
            entry.certificate.device_id() == local_id
                && entry.revoked_at.is_none()
                && entry.certificate == legacy.local_certificate
        })
        .ok_or(NodeError::CorruptState)?;
    let manifest =
        DeviceAuthorityManifest::initial(root, &device, old_entry.name.clone(), migrated_at, rng)?;
    let state = DeviceAuthorityStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: manifest.devices()[0].certificate.clone(),
        accepted_recovery_epoch: manifest.recovery_epoch(),
        accepted_recovery_anchor: manifest.recovery_anchor_id(),
        manifest,
        sync_counter: legacy.sync_counter,
        channels: Vec::new(),
        conflicts: Vec::new(),
    };
    Ok((device, state))
}

pub(crate) fn load_authority_device(
    store: &Store,
) -> Result<(Identity, DeviceAuthorityStateRecord)> {
    let state = store
        .get_device_authority_state()?
        .ok_or(NodeError::CorruptState)?;
    let bytes: Zeroizing<[u8; 64]> = Zeroizing::new(
        state
            .local_device_secret
            .as_slice()
            .try_into()
            .map_err(|_| NodeError::CorruptState)?,
    );
    Ok((Identity::from_bytes(&bytes), state))
}

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

fn manifest_contains_certified_device(
    manifest: &DeviceAuthorityManifest,
    account: &[u8; 32],
    device: &[u8; 32],
) -> bool {
    manifest.verify().is_ok()
        && manifest.account().ed == *account
        && manifest
            .devices()
            .iter()
            .any(|entry| entry.certificate.device_id() == *device)
}

fn accepted_contact_authority(
    contacts: &[ContactDeviceRecord],
    account: &[u8; 32],
) -> Option<DeviceAuthorityManifest> {
    let mut accepted: Option<DeviceAuthorityManifest> = None;
    for endpoint in contacts.iter().filter(|endpoint| {
        endpoint.account == *account
            && endpoint.manifest_generation > 0
            && !endpoint.authority.is_empty()
    }) {
        let candidate = DeviceAuthorityManifest::decode(&endpoint.authority).ok()?;
        if !manifest_contains_certified_device(&candidate, account, &endpoint.device) {
            return None;
        }
        accepted = Some(match accepted {
            None => candidate,
            Some(current) => match current.relation(&candidate).ok()? {
                DeviceAuthorityRelation::Same => current,
                DeviceAuthorityRelation::Descendant
                | DeviceAuthorityRelation::RecoverySupersedes => candidate,
                DeviceAuthorityRelation::Stale | DeviceAuthorityRelation::OldEpoch => current,
                DeviceAuthorityRelation::Fork | DeviceAuthorityRelation::RecoveryConflict => {
                    return None;
                }
            },
        });
    }
    accepted
}

fn contact_records_authorize_group_sender(
    contacts: &[ContactDeviceRecord],
    account: &[u8; 32],
    device: &[u8; 32],
) -> bool {
    let Some(authority) = accepted_contact_authority(contacts, account) else {
        return false;
    };
    let Some(entry) = authority
        .devices()
        .iter()
        .find(|entry| entry.certificate.device_id() == *device)
    else {
        return false;
    };
    let Ok(certificate) = postcard::to_allocvec(&entry.certificate) else {
        return false;
    };
    let Ok(encoded_authority) = authority.encode() else {
        return false;
    };
    contacts.iter().any(|endpoint| {
        endpoint.account == *account
            && endpoint.device == *device
            && endpoint.authority == encoded_authority
            && endpoint.certificate == certificate
            && endpoint.manifest_generation == authority.generation()
            && endpoint.manifest_state_id == authority.state_id()
            && endpoint.revoked_at == entry.revoked_at
            && endpoint.revoked_after_counter == entry.revoked_after_counter
    })
}

fn valid_synced_group_origin(
    local_manifest: &DeviceAuthorityManifest,
    contacts: &[ContactDeviceRecord],
    local_account: &[u8; 32],
    message: &GroupMessageRecord,
) -> bool {
    match message.origin {
        GroupOriginAuthentication::LegacyMembership
        | GroupOriginAuthentication::PendingOutboundV1 { .. } => false,
        GroupOriginAuthentication::RecipientV1 {
            sender_device,
            recipient_device,
            chain_key_id,
        } => {
            message.direction == Direction::Inbound
                && message.sender != *local_account
                && chain_key_id != [0u8; 16]
                && manifest_contains_certified_device(
                    local_manifest,
                    local_account,
                    &recipient_device,
                )
                && contact_records_authorize_group_sender(contacts, &message.sender, &sender_device)
        }
        GroupOriginAuthentication::OutboundV1 {
            sender_device,
            chain_key_id,
        } => {
            message.direction == Direction::Outbound
                && message.sender == *local_account
                && chain_key_id != [0u8; 16]
                && manifest_contains_certified_device(local_manifest, local_account, &sender_device)
        }
    }
}

fn synced_group_history_namespace(message: &GroupMessageRecord) -> Option<DeviceSyncNamespace> {
    match decode_content(&message.body) {
        DecodedContent::Edit { .. } => Some(DeviceSyncNamespace::MessageEdits),
        DecodedContent::Poll { .. } => Some(DeviceSyncNamespace::GroupPolls),
        DecodedContent::Ephemeral { .. } => None,
        _ => Some(DeviceSyncNamespace::ConversationHistory),
    }
}

impl Node {
    pub(crate) fn validate_contact_device_manifest(
        &self,
        manifest: &DeviceAuthorityManifest,
    ) -> Result<()> {
        manifest.verify()?;
        let account = manifest.account().ed;
        let existing: Vec<ContactDeviceRecord> = self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.account == account)
            .collect();
        for old in existing
            .iter()
            .filter(|endpoint| !endpoint.authority.is_empty())
        {
            let accepted = DeviceAuthorityManifest::decode(&old.authority)
                .map_err(|_| NodeError::CorruptState)?;
            match accepted.relation(manifest)? {
                DeviceAuthorityRelation::Same
                | DeviceAuthorityRelation::Descendant
                | DeviceAuthorityRelation::RecoverySupersedes => {}
                DeviceAuthorityRelation::Stale => return Err(NodeError::InvalidDeviceManifest),
                DeviceAuthorityRelation::OldEpoch => {
                    return Err(NodeError::OldDeviceAuthorityEpoch)
                }
                DeviceAuthorityRelation::Fork => return Err(NodeError::DeviceAuthorityFork),
                DeviceAuthorityRelation::RecoveryConflict => {
                    return Err(NodeError::DeviceRecoveryConflict)
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_contact_device_manifest_visible(
        &mut self,
        manifest: &DeviceAuthorityManifest,
        observed_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let kind = match self.validate_contact_device_manifest(manifest) {
            Ok(()) => return Ok(()),
            Err(NodeError::DeviceAuthorityFork) => DeviceAuthorityConflictKind::Fork,
            Err(NodeError::DeviceRecoveryConflict) => DeviceAuthorityConflictKind::Recovery,
            Err(error) => return Err(error),
        };
        let account = manifest.account().ed;
        let existing = self.store.contact_devices_for(&account)?;
        let mut accepted_state = None;
        for endpoint in existing
            .iter()
            .filter(|endpoint| !endpoint.authority.is_empty())
        {
            let accepted = DeviceAuthorityManifest::decode(&endpoint.authority)
                .map_err(|_| NodeError::CorruptState)?;
            let relation = accepted.relation(manifest)?;
            if (kind == DeviceAuthorityConflictKind::Fork
                && relation == DeviceAuthorityRelation::Fork)
                || (kind == DeviceAuthorityConflictKind::Recovery
                    && relation == DeviceAuthorityRelation::RecoveryConflict)
            {
                accepted_state = Some(accepted.state_id());
                break;
            }
        }
        let accepted_state = accepted_state.ok_or(NodeError::CorruptState)?;
        let inserted = self.store.record_contact_authority_conflict(
            &ContactAuthorityConflictRecord {
                account,
                kind,
                accepted_state,
                conflicting_state: manifest.state_id(),
                recovery_epoch: manifest.recovery_epoch(),
                observed_at,
            },
            rng,
        )?;
        if inserted {
            self.events.push_back(Event::StateResyncRequired);
        }
        Err(match kind {
            DeviceAuthorityConflictKind::Fork => NodeError::DeviceAuthorityFork,
            DeviceAuthorityConflictKind::Recovery => NodeError::DeviceRecoveryConflict,
        })
    }

    pub(crate) fn apply_contact_device_manifest(
        &mut self,
        manifest: &DeviceAuthorityManifest,
        advertised_device: [u8; 32],
        advertised_bundle: Vec<u8>,
        advertised_hints: Vec<Vec<u8>>,
        observed_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.validate_contact_device_manifest(manifest)?;
        let account = manifest.account().ed;
        let state_id = manifest.state_id();
        let encoded_authority = manifest.encode()?;
        let existing: Vec<ContactDeviceRecord> = self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.account == account)
            .collect();
        let manifest_devices = manifest
            .devices()
            .iter()
            .map(|entry| entry.certificate.device_id())
            .collect::<BTreeSet<_>>();

        // A pre-C2 raw account bundle represented the original installation
        // under the account id. Bind that compatibility route to the unique
        // earliest-issued active certificate when the first manifest arrives.
        let legacy_alias = existing
            .iter()
            .find(|endpoint| endpoint.device == account && endpoint.manifest_generation == 0);
        let mut active_by_issuance: Vec<_> = manifest
            .devices()
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

        let mut next_endpoints = Vec::with_capacity(manifest.devices().len());
        for entry in manifest.devices() {
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
                authority: encoded_authority.clone(),
                bundle,
                hints,
                manifest_generation: manifest.generation(),
                manifest_state_id: state_id,
                last_seen: entry
                    .last_seen
                    .max(prior.map_or(0, |endpoint| endpoint.last_seen))
                    .max(if advertised { observed_at } else { 0 }),
                revoked_at: entry.revoked_at,
                revoked_after_counter: entry.revoked_after_counter,
            };
            next_endpoints.push(endpoint);
        }
        // A recovery made from a stale backup can legitimately supersede a
        // later ordinary descendant whose extra certificates are absent from
        // the recovery proof. Those old-epoch endpoints are excluded by the
        // new complete state even though the recovering user never saw their
        // ids.
        let orphaned = existing
            .iter()
            .filter(|endpoint| {
                endpoint.manifest_generation > 0 && !manifest_devices.contains(&endpoint.device)
            })
            .collect::<Vec<_>>();

        // Once a contact already has versioned device authority, publish the
        // complete next projection and every live-route retirement together.
        // Queue rows are retired first in bounded pages; until the projection
        // commits, the old authority remains the only accepted state.
        if legacy_alias.is_none() {
            let cleanup_devices = next_endpoints
                .iter()
                .filter(|endpoint| endpoint.revoked_at.is_some())
                .map(|endpoint| endpoint.device)
                .chain(orphaned.iter().map(|endpoint| endpoint.device))
                .collect::<BTreeSet<_>>();
            let queue = self
                .store
                .queue_all()?
                .into_iter()
                .filter_map(|(sequence, item)| {
                    cleanup_devices.contains(&item.peer).then_some(QueueDelete {
                        sequence,
                        content_id: item.envelope.content_id(),
                    })
                })
                .collect::<Vec<_>>();
            self.retire_device_projection_queue(&queue, rng)?;

            let mut projections = Vec::new();
            for endpoint in &next_endpoints {
                let before = existing
                    .iter()
                    .find(|stored| stored.device == endpoint.device);
                if before != Some(endpoint) {
                    projections.push(DeviceProjection::ContactDevice {
                        before,
                        after: Some(endpoint),
                    });
                }
            }
            for &before in &orphaned {
                projections.push(DeviceProjection::ContactDevice {
                    before: Some(before),
                    after: None,
                });
            }

            let mut session_rows = Vec::new();
            let mut capability_rows = Vec::new();
            for device in &cleanup_devices {
                if let Some(before) = self.store.get_session(device)? {
                    session_rows.push((*device, before));
                }
                if let Some(before) = self.store.get_capabilities(device)? {
                    capability_rows.push((*device, before));
                }
            }
            let sessions = session_rows
                .iter()
                .map(|(peer_device, before)| SessionDelete {
                    peer_device: *peer_device,
                    before,
                })
                .collect::<Vec<_>>();
            let capabilities = capability_rows
                .iter()
                .map(|(peer_device, before)| CapabilityDelete {
                    peer_device: *peer_device,
                    before,
                })
                .collect::<Vec<_>>();
            if !projections.is_empty() || !sessions.is_empty() || !capabilities.is_empty() {
                let receipt = self.store.commit_plan(
                    CommitPlan::DeviceProjection(DeviceProjectionPlan {
                        projections: &projections,
                        delete_sessions: &sessions,
                        delete_capabilities: &capabilities,
                        delete_queue: &[],
                        presentation_changed: !projections.is_empty(),
                    }),
                    rng,
                )?;
                self.before_memory_replacement()?;
                for device in &cleanup_devices {
                    self.sessions.remove(device);
                    self.capabilities_advertised.remove(device);
                }
                self.after_memory_replacement()?;
                self.accept_commit_receipt(receipt, []);
            }
            return Ok(());
        }

        // Pre-C2 account aliases require the separately delimited compatibility
        // retarget below. New authority states never enter this branch.
        for endpoint in next_endpoints {
            let device = endpoint.device;
            self.store.put_contact_device(&endpoint, rng)?;
            if endpoint.revoked_at.is_some() {
                self.sessions.remove(&device);
                self.capabilities_advertised.remove(&device);
                self.store.delete_session(&device)?;
                self.store.delete_capabilities(&device)?;
                self.store.queue_remove_peer(&device)?;
            }
        }
        for orphaned in orphaned {
            self.sessions.remove(&orphaned.device);
            self.capabilities_advertised.remove(&orphaned.device);
            self.store.delete_session(&orphaned.device)?;
            self.store.delete_capabilities(&orphaned.device)?;
            self.store.queue_remove_peer(&orphaned.device)?;
            self.store
                .delete_contact_device(&account, &orphaned.device)?;
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
            .devices()
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

    /// Unresolved fail-closed authority conflicts retained across restart.
    pub fn device_authority_conflicts(&self) -> Vec<DeviceAuthorityConflictInfo> {
        self.device_state
            .conflicts
            .iter()
            .map(|conflict| DeviceAuthorityConflictInfo {
                kind: match conflict.kind {
                    DeviceAuthorityConflictKind::Fork => DeviceAuthorityConflictType::Fork,
                    DeviceAuthorityConflictKind::Recovery => DeviceAuthorityConflictType::Recovery,
                },
                accepted: conflict.accepted_state,
                conflicting: conflict.conflicting_state,
                recovery_epoch: conflict.recovery_epoch,
                observed_at: conflict.observed_at,
            })
            .collect()
    }

    /// Contact authority forks and recovery conflicts retained across restart.
    pub fn contact_authority_conflicts(&self) -> Result<Vec<ContactAuthorityConflictInfo>> {
        Ok(self
            .store
            .contact_authority_conflicts()?
            .into_iter()
            .map(|conflict| ContactAuthorityConflictInfo {
                account: conflict.account,
                kind: match conflict.kind {
                    DeviceAuthorityConflictKind::Fork => DeviceAuthorityConflictType::Fork,
                    DeviceAuthorityConflictKind::Recovery => DeviceAuthorityConflictType::Recovery,
                },
                accepted: conflict.accepted_state,
                conflicting: conflict.conflicting_state,
                recovery_epoch: conflict.recovery_epoch,
                observed_at: conflict.observed_at,
            })
            .collect())
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
        let before = self.device_state.clone();
        let mut after = before.clone();
        let mut proposal = before
            .manifest
            .propose_rename_device(device, name.to_owned(), rng)
            .map_err(|_| NodeError::UnknownLinkedDevice)?;
        before
            .manifest
            .sign_transition(&mut proposal, &self.device_identity)?;
        if !before.manifest.has_quorum(&proposal)? {
            self.pending_authority_transition = Some(proposal);
            return Err(NodeError::DeviceQuorumRequired);
        }
        after.manifest = before.manifest.append(proposal)?;
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before),
                    after: &after,
                }),
                link_recovery: None,
                groups: &[],
                insert_events: &[],
                delete_events: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, [Event::DevicesChanged]);
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
        let before_state = self.device_state.clone();
        let mut after_state = before_state.clone();
        let mut proposal = before_state
            .manifest
            .propose_revoke_device(device, now, cutoff, rng)
            .map_err(|_| NodeError::UnknownLinkedDevice)?;
        before_state
            .manifest
            .sign_transition(&mut proposal, &self.device_identity)?;
        if !before_state.manifest.has_quorum(&proposal)? {
            self.pending_authority_transition = Some(proposal);
            return Err(NodeError::DeviceQuorumRequired);
        }
        after_state.manifest = before_state.manifest.append(proposal)?;
        after_state
            .channels
            .retain(|channel| &channel.peer_device != device);
        // Revocation always rotates this installation's sender chains. A
        // revoked copy can retain old ciphertext/key material, but receives
        // no fresh chain snapshots from the surviving channel set.
        let before_groups = self.store.groups()?;
        let mut after_groups = before_groups.clone();
        for group in &mut after_groups {
            self.rotate_group(group, rng)?;
        }
        let group_transitions = before_groups
            .iter()
            .zip(&after_groups)
            .map(|(before, after)| GroupTransition { before, after })
            .collect::<Vec<_>>();
        let recovery = self.store.get_device_link_recovery(device)?;
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before_state),
                    after: &after_state,
                }),
                link_recovery: recovery
                    .as_ref()
                    .map(|before| DeviceLinkRecoveryTransition {
                        before: Some(before),
                        after: None,
                    }),
                groups: &group_transitions,
                insert_events: &[],
                delete_events: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after_state;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, [Event::DevicesChanged]);
        Ok(())
    }

    /// Return the exact pending ordinary authority proposal for approval by
    /// another active device.
    pub fn device_authority_approval_request(&self) -> Result<Vec<u8>> {
        let proposal = self
            .pending_authority_transition
            .as_ref()
            .ok_or(NodeError::NoPendingDeviceAuthority)?;
        Ok(AuthorityDeviceLinkApprovalRequest {
            link_id: proposal.transition_id,
            parent_state: self.device_state.manifest.state_id(),
            proposal: proposal.clone(),
        }
        .encode()?)
    }

    /// Verify and approve another active device's exact ordinary authority
    /// proposal. The request is bound to the locally accepted parent branch.
    pub fn approve_device_authority_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let request = AuthorityDeviceLinkApprovalRequest::decode(request)?;
        if request.proposal.kind == DeviceAuthorityTransitionKind::AddDevice {
            return Err(NodeError::InvalidDeviceAuthority);
        }
        let approval = request.approve(&self.device_state.manifest, &self.device_identity)?;
        Ok(approval.encode()?)
    }

    /// Merge one detached approval and atomically apply the proposal once its
    /// previous-active-set strict majority has been reached.
    pub fn accept_device_authority_approval(
        &mut self,
        approval: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let approval = AuthorityDeviceLinkApproval::decode(approval)?;
        let proposal = self
            .pending_authority_transition
            .as_mut()
            .ok_or(NodeError::NoPendingDeviceAuthority)?;
        if approval.link_id != proposal.transition_id
            || approval.parent_state != self.device_state.manifest.state_id()
            || approval.proposal_id != proposal.proposal_id()
        {
            return Err(NodeError::InvalidDeviceAuthority);
        }
        self.device_state
            .manifest
            .merge_approval(proposal, approval.approval)
            .map_err(|_| NodeError::InvalidDeviceAuthority)?;
        if !self.device_state.manifest.has_quorum(proposal)? {
            return Ok(false);
        }
        self.finalize_pending_device_authority(rng)?;
        Ok(true)
    }

    fn finalize_pending_device_authority(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        let proposal = self
            .pending_authority_transition
            .as_ref()
            .ok_or(NodeError::NoPendingDeviceAuthority)?
            .clone();
        if matches!(
            proposal.kind,
            DeviceAuthorityTransitionKind::Genesis
                | DeviceAuthorityTransitionKind::AddDevice
                | DeviceAuthorityTransitionKind::Recovery
        ) {
            return Err(NodeError::InvalidDeviceAuthority);
        }
        let before_state = self.device_state.clone();
        let mut after_state = before_state.clone();
        after_state.manifest = before_state.manifest.append(proposal.clone())?;

        let newly_revoked = before_state.manifest.devices().iter().find_map(|before| {
            let device = before.certificate.device_id();
            let after = proposal
                .devices
                .iter()
                .find(|after| after.certificate.device_id() == device)?;
            (before.revoked_at.is_none() && after.revoked_at.is_some()).then_some(device)
        });
        if let Some(device) = newly_revoked {
            after_state
                .channels
                .retain(|channel| channel.peer_device != device);
        }

        let before_groups = self.store.groups()?;
        let mut after_groups = before_groups.clone();
        if newly_revoked.is_some() {
            for group in &mut after_groups {
                self.rotate_group(group, rng)?;
            }
        }
        let group_transitions = before_groups
            .iter()
            .zip(&after_groups)
            .filter(|(before, after)| before != after)
            .map(|(before, after)| GroupTransition { before, after })
            .collect::<Vec<_>>();
        let recovery = newly_revoked
            .map(|device| self.store.get_device_link_recovery(&device))
            .transpose()?
            .flatten();
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before_state),
                    after: &after_state,
                }),
                link_recovery: recovery
                    .as_ref()
                    .map(|before| DeviceLinkRecoveryTransition {
                        before: Some(before),
                        after: None,
                    }),
                groups: &group_transitions,
                insert_events: &[],
                delete_events: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after_state;
        self.pending_authority_transition = None;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, [Event::DevicesChanged]);
        Ok(())
    }

    /// Begin a ten-minute account-authenticated QR linking offer.
    pub fn begin_device_link(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        let expires_at = now
            .checked_add(LINK_OFFER_LIFETIME_SECS)
            .ok_or(NodeError::InvalidDeviceLink)?;
        let (pending, offer) = PendingDeviceLinkSource::begin(
            &self.device_identity,
            &self.device_state.manifest,
            expires_at,
            rng,
        )?;
        self.pending_device_link_source = Some(pending);
        self.pending_device_link_prepared = None;
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
        encoded_response: &[u8],
        selection: DeviceLinkSelection,
        confirmed: bool,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let response_hash: [u8; 32] = Sha256::digest(encoded_response).into();
        let response = DeviceLinkResponse::decode(encoded_response)?;
        let target_device = response.certificate.device_id();
        if let Some(recovery) = self.store.get_device_link_recovery(&target_device)? {
            if !confirmed || recovery.response_hash != response_hash {
                return Err(NodeError::InvalidDeviceLink);
            }
            self.capture_device_sync_state(rng)?;
            let snapshot = self.store.export_device_transfer(DeviceTransferSelection {
                contacts: recovery.contacts,
                organization: recovery.organization,
                history: recovery.history,
            })?;
            let snapshot = postcard::to_allocvec(&snapshot).map_err(|_| NodeError::CorruptState)?;
            let durable_state = self
                .store
                .get_device_authority_state()?
                .ok_or(NodeError::CorruptState)?;
            let channel = durable_state
                .channels
                .iter()
                .find(|channel| channel.peer_device == recovery.target_device)
                .ok_or(NodeError::CorruptState)?;
            let package = seal_authority_device_link_recovery_package(
                &durable_state.manifest,
                &recovery.target_device,
                &channel.root,
                &snapshot,
                &recovery.link_key,
                rng,
            )?;
            self.device_state = durable_state;
            self.pending_device_link_source = None;
            return Ok(package);
        }
        let prepared = self
            .pending_device_link_source
            .as_ref()
            .ok_or(NodeError::NoPendingDeviceLink)?
            .prepare(&self.device_identity, &response, confirmed, now, rng)?;
        let has_quorum = prepared.has_quorum()?;
        self.pending_device_link_prepared = Some(prepared);
        self.pending_device_link_selection = Some(selection);
        self.pending_device_link_response_hash = Some(response_hash);
        if !has_quorum {
            return Err(NodeError::DeviceQuorumRequired);
        }
        self.finalize_prepared_device_link(now, rng)
    }

    /// Return the canonical proposal another active device must approve.
    pub fn device_link_approval_request(&self) -> Result<Vec<u8>> {
        let prepared = self
            .pending_device_link_prepared
            .as_ref()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        Ok(prepared.approval_request().encode()?)
    }

    /// Verify and sign another active device's exact link proposal.
    pub fn approve_device_link_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let request = AuthorityDeviceLinkApprovalRequest::decode(request)?;
        if request.proposal.kind != DeviceAuthorityTransitionKind::AddDevice {
            return Err(NodeError::InvalidDeviceAuthority);
        }
        let approval = request.approve(&self.device_state.manifest, &self.device_identity)?;
        Ok(approval.encode()?)
    }

    /// Merge an additional-device approval and finalize once quorum is met.
    pub fn accept_device_link_approval(
        &mut self,
        approval: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<Vec<u8>>> {
        let approval = AuthorityDeviceLinkApproval::decode(approval)?;
        let prepared = self
            .pending_device_link_prepared
            .as_mut()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        prepared.merge_approval(approval)?;
        if !prepared.has_quorum()? {
            return Ok(None);
        }
        self.finalize_prepared_device_link(now, rng).map(Some)
    }

    fn finalize_prepared_device_link(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let selection = self
            .pending_device_link_selection
            .ok_or(NodeError::NoPendingDeviceLink)?;
        let response_hash = self
            .pending_device_link_response_hash
            .ok_or(NodeError::NoPendingDeviceLink)?;
        self.capture_device_sync_state(rng)?;
        let snapshot = self.store.export_device_transfer(DeviceTransferSelection {
            contacts: selection.contacts,
            organization: selection.organization,
            history: selection.history,
        })?;
        let snapshot = postcard::to_allocvec(&snapshot).map_err(|_| NodeError::CorruptState)?;
        let prepared = self
            .pending_device_link_prepared
            .take()
            .ok_or(NodeError::NoPendingDeviceLink)?;
        let approved = prepared.finalize(now, snapshot, rng)?;
        let before = self.device_state.clone();
        let mut after = before.clone();
        after.manifest = approved.manifest;
        after.channels.push(DeviceChannelRecord {
            peer_device: approved.target_device,
            root: *approved.channel_root,
            send_counter: 0,
            receive_counter: 0,
        });
        after.channels.sort_by_key(|channel| channel.peer_device);
        let recovery = DeviceLinkRecoveryRecord {
            target_device: approved.target_device,
            response_hash,
            link_key: *approved.recovery_key,
            contacts: selection.contacts,
            organization: selection.organization,
            history: selection.history,
        };
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before),
                    after: &after,
                }),
                link_recovery: Some(DeviceLinkRecoveryTransition {
                    before: None,
                    after: Some(&recovery),
                }),
                groups: &[],
                insert_events: &[],
                delete_events: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after;
        self.pending_device_link_source = None;
        self.pending_device_link_selection = None;
        self.pending_device_link_response_hash = None;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, [Event::DevicesChanged]);
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
            .as_ref()
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
        let before_account = self.account.clone();
        let before_state = self.device_state.clone();
        let after_account = completed.account;
        let after_state = DeviceAuthorityStateRecord {
            local_device_secret: self.device_identity.to_bytes().to_vec(),
            local_certificate: completed.certificate,
            accepted_recovery_epoch: completed.manifest.recovery_epoch(),
            accepted_recovery_anchor: completed.manifest.recovery_anchor_id(),
            manifest: completed.manifest,
            sync_counter: 0,
            channels: vec![DeviceChannelRecord {
                peer_device: completed.authorizer_device,
                root: *completed.channel_root,
                send_counter: 0,
                receive_counter: 0,
            }],
            conflicts: Vec::new(),
        };
        let DeviceTransferSnapshot {
            contacts,
            contact_devices,
            messages,
            groups: transferred_groups,
            group_messages,
            group_authorities,
            local_metadata,
            note_messages,
            ephemeral_tombstones,
            sync_events,
        } = snapshot;
        let mut authenticated_group_messages = Vec::with_capacity(group_messages.len());
        for mut message in group_messages {
            if !valid_synced_group_origin(
                &after_state.manifest,
                &contact_devices,
                &after_account.ed,
                &message,
            ) {
                continue;
            }
            message.wire_body = None;
            for delivery in &mut message.deliveries {
                delivery.wire_id = None;
            }
            authenticated_group_messages.push(message);
        }
        // A linked target receives public contact bundles but no source
        // ratchets. Mark every copied route so its first independent session
        // ignores any one-time prekey the source may already have consumed.
        let mut reset_peers = contact_devices
            .iter()
            .map(|endpoint| endpoint.device)
            .chain(
                contacts
                    .iter()
                    .filter(|contact| {
                        !contact.bundle.is_empty()
                            && !contact_devices
                                .iter()
                                .any(|endpoint| endpoint.account == contact.peer)
                    })
                    .map(|contact| contact.peer),
            )
            .collect::<Vec<_>>();
        reset_peers.sort_unstable();
        reset_peers.dedup();
        let me = after_account.ed;
        let mut groups = Vec::with_capacity(transferred_groups.len());
        for group in transferred_groups {
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
            groups.push(GroupRecord {
                id: group.id,
                name: group.name,
                creator: group.creator,
                members: group.members,
                secret: group.secret,
                prev_secret: None,
                generation: group.generation,
                sender_chain: postcard::to_allocvec(&chain).map_err(|_| NodeError::CorruptState)?,
                sent_since_rotation: 0,
                pending,
            });
        }
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceLink(AuthorityDeviceLinkPlan {
                account: AccountIdentityTransition {
                    before: &before_account,
                    after: &after_account,
                },
                device_state: DeviceAuthorityStateTransition {
                    before: Some(&before_state),
                    after: &after_state,
                },
                contacts: &contacts,
                devices: &contact_devices,
                messages: &messages,
                groups: &groups,
                group_messages: &authenticated_group_messages,
                authorities: &group_authorities,
                local_metadata: &local_metadata,
                notes: &note_messages,
                ephemeral: &ephemeral_tombstones,
                sync_events: &sync_events,
                reset_peers: &reset_peers,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.account = after_account;
        self.device_state = after_state;
        self.pending_device_link_target = None;
        self.sessions.clear();
        self.capabilities_advertised.clear();
        self.after_memory_replacement()?;
        self.accept_commit_receipt(
            receipt,
            [
                Event::DeviceLinkCompleted {
                    account: self.account.ed,
                    device: self.device_id(),
                },
                Event::DevicesChanged,
            ],
        );
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
        let before = self.device_state.clone();
        let mut after = before.clone();
        let channel = after
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
        let encoded = bundle.encode()?;
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before),
                    after: &after,
                }),
                link_recovery: None,
                groups: &[],
                insert_events: &[],
                delete_events: &[],
                presentation_changed: false,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, []);
        Ok(encoded)
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
        let relation = self.device_state.manifest.relation(&opened.manifest)?;
        match relation {
            DeviceAuthorityRelation::Same | DeviceAuthorityRelation::Descendant => {}
            DeviceAuthorityRelation::RecoverySupersedes => {
                // Recovery creates one fresh device and rotates every sync
                // channel. It cannot legitimately arrive over an old channel.
                return Err(NodeError::InvalidDeviceSync);
            }
            DeviceAuthorityRelation::Stale => return Err(NodeError::InvalidDeviceSync),
            DeviceAuthorityRelation::OldEpoch => return Err(NodeError::OldDeviceAuthorityEpoch),
            DeviceAuthorityRelation::Fork | DeviceAuthorityRelation::RecoveryConflict => {
                let accepted = self.device_state.manifest.state_id();
                let conflicting = opened.manifest.state_id();
                let recovery_epoch = opened.manifest.recovery_epoch();
                let kind = if relation == DeviceAuthorityRelation::Fork {
                    DeviceAuthorityConflictKind::Fork
                } else {
                    DeviceAuthorityConflictKind::Recovery
                };
                if !self.device_state.conflicts.iter().any(|record| {
                    record.kind == kind
                        && record.accepted_state == accepted
                        && record.conflicting_state == conflicting
                }) && self.device_state.conflicts.len() < MAX_DEVICE_AUTHORITY_CONFLICTS
                {
                    let before = self.device_state.clone();
                    let mut after = before.clone();
                    after.conflicts.push(DeviceAuthorityConflictRecord {
                        kind,
                        accepted_state: accepted,
                        conflicting_state: conflicting,
                        recovery_epoch,
                        observed_at: 0,
                    });
                    after.conflicts.sort_by_key(|record| {
                        (
                            record.recovery_epoch,
                            record.accepted_state,
                            record.conflicting_state,
                        )
                    });
                    let receipt = self.store.commit_plan(
                        CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                            state: Some(DeviceAuthorityStateTransition {
                                before: Some(&before),
                                after: &after,
                            }),
                            link_recovery: None,
                            groups: &[],
                            insert_events: &[],
                            delete_events: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.device_state = after;
                    self.after_memory_replacement()?;
                    let event = if kind == DeviceAuthorityConflictKind::Fork {
                        Event::DeviceAuthorityFork {
                            accepted,
                            conflicting,
                            recovery_epoch,
                        }
                    } else {
                        Event::DeviceRecoveryConflict {
                            accepted,
                            conflicting,
                            recovery_epoch,
                        }
                    };
                    self.accept_commit_receipt(receipt, [event]);
                }
                return Err(if kind == DeviceAuthorityConflictKind::Fork {
                    NodeError::DeviceAuthorityFork
                } else {
                    NodeError::DeviceRecoveryConflict
                });
            }
        }
        let manifest_changed = relation == DeviceAuthorityRelation::Descendant;
        let newly_revoked = self
            .device_state
            .manifest
            .devices()
            .iter()
            .filter(|old| old.revoked_at.is_none())
            .any(|old| {
                opened.manifest.devices().iter().any(|new| {
                    new.certificate.device_id() == old.certificate.device_id()
                        && new.revoked_at.is_some()
                })
            });
        let existing_events = self
            .store
            .device_sync_events()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut inserts = BTreeSet::new();
        for event in opened.events {
            let bytes = event.encode()?;
            if !existing_events.contains(&bytes) {
                inserts.insert(bytes);
            }
        }
        let insert_events = inserts.into_iter().collect::<Vec<_>>();
        let inserted = insert_events.len();
        let before_state = self.device_state.clone();
        let mut after_state = before_state.clone();
        after_state.manifest = opened.manifest;
        after_state.accepted_recovery_epoch = after_state.manifest.recovery_epoch();
        after_state.accepted_recovery_anchor = after_state.manifest.recovery_anchor_id();
        after_state.channels[channel_index].receive_counter = bundle.sequence;
        after_state.channels.retain(|channel| {
            after_state
                .manifest
                .active_certificate(&channel.peer_device)
                .is_some()
        });
        let before_groups = self.store.groups()?;
        let mut after_groups = before_groups.clone();
        if newly_revoked {
            for group in &mut after_groups {
                self.rotate_group(group, rng)?;
            }
        }
        let group_transitions = before_groups
            .iter()
            .zip(&after_groups)
            .filter(|(before, after)| before != after)
            .map(|(before, after)| GroupTransition { before, after })
            .collect::<Vec<_>>();
        let recovery = self.store.get_device_link_recovery(&bundle.sender)?;
        let receipt = self.store.commit_plan(
            CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                state: Some(DeviceAuthorityStateTransition {
                    before: Some(&before_state),
                    after: &after_state,
                }),
                link_recovery: recovery
                    .as_ref()
                    .map(|before| DeviceLinkRecoveryTransition {
                        before: Some(before),
                        after: None,
                    }),
                groups: &group_transitions,
                insert_events: &insert_events,
                delete_events: &[],
                presentation_changed: manifest_changed || inserted > 0,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after_state;
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, []);
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
        let sync_contact_devices = snapshot.contact_devices.clone();
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
            if !valid_synced_group_origin(
                &self.device_state.manifest,
                &sync_contact_devices,
                &self.account.ed,
                &message,
            ) {
                continue;
            }
            let Some(namespace) = synced_group_history_namespace(&message) else {
                continue;
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

        let stored_encoded = self.store.device_sync_events()?;
        let stored = stored_encoded
            .iter()
            .map(|bytes| DeviceSyncEvent::decode(bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let resolved = resolve_device_sync_events(&self.device_state.manifest, stored);
        let winners = resolved
            .values()
            .map(DeviceSyncEvent::encode)
            .collect::<core::result::Result<BTreeSet<_>, _>>()?;
        let mut redundant = stored_encoded
            .into_iter()
            .filter(|encoded| !winners.contains(encoded))
            .collect::<Vec<_>>();
        while !redundant.is_empty() {
            let take = redundant.len().min(MAX_DEVICE_CONTROL_MUTATIONS);
            let page = redundant.drain(..take).collect::<Vec<_>>();
            self.store.commit_plan(
                CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                    state: None,
                    link_recovery: None,
                    groups: &[],
                    insert_events: &[],
                    delete_events: &page,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }
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
        let page_size = (MAX_DEVICE_CONTROL_MUTATIONS.saturating_sub(1) / 2).max(1);
        for page in mutations.chunks(page_size) {
            let before_state = self.device_state.clone();
            let mut after_state = before_state.clone();
            let mut insert_events = Vec::with_capacity(page.len());
            let mut delete_events = Vec::with_capacity(page.len());
            for (namespace, key, value) in page {
                if let Some(event) = resolved.get(&(*namespace, key.clone())) {
                    delete_events.push(event.encode()?);
                }
                after_state.sync_counter = after_state
                    .sync_counter
                    .checked_add(1)
                    .ok_or(NodeError::InvalidDeviceSync)?;
                lamport = lamport.checked_add(1).ok_or(NodeError::InvalidDeviceSync)?;
                let event = DeviceSyncEvent::sign(
                    self.account.ed,
                    &self.device_identity,
                    after_state.sync_counter,
                    lamport,
                    after_state.manifest.generation(),
                    *namespace,
                    key.clone(),
                    value.clone(),
                )?;
                insert_events.push(event.encode()?);
            }
            let receipt = self.store.commit_plan(
                CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                    state: Some(DeviceAuthorityStateTransition {
                        before: Some(&before_state),
                        after: &after_state,
                    }),
                    link_recovery: None,
                    groups: &[],
                    insert_events: &insert_events,
                    delete_events: &delete_events,
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            self.device_state = after_state;
            self.after_memory_replacement()?;
            self.accept_commit_receipt(receipt, []);
        }

        // Retain only converged winners. This bounds replay material while
        // preserving every live value and tombstone needed by a new peer.
        let all_encoded = self.store.device_sync_events()?;
        let all = all_encoded
            .iter()
            .map(|bytes| DeviceSyncEvent::decode(bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let compacted = resolve_device_sync_events(&self.device_state.manifest, all)
            .into_values()
            .map(|event| event.encode())
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let compacted = compacted.into_iter().collect::<BTreeSet<_>>();
        let mut redundant = all_encoded
            .into_iter()
            .filter(|encoded| !compacted.contains(encoded))
            .collect::<Vec<_>>();
        while !redundant.is_empty() {
            let take = redundant.len().min(MAX_DEVICE_CONTROL_MUTATIONS);
            let page = redundant.drain(..take).collect::<Vec<_>>();
            self.store.commit_plan(
                CommitPlan::AuthorityDeviceControl(AuthorityDeviceControlPlan {
                    state: None,
                    link_recovery: None,
                    groups: &[],
                    insert_events: &[],
                    delete_events: &page,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }
        Ok(())
    }

    fn retire_device_projection_queue(
        &mut self,
        queue: &[QueueDelete],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for page in queue.chunks(kult_store::MAX_MAINTENANCE_TRANSITIONS) {
            let receipt = self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &[],
                    delete_pending: &[],
                    delete_queue: page,
                    update_queue: &[],
                    delete_replay: &[],
                    messages: &[],
                    deliveries: &[],
                    group_messages: &[],
                    groups: &[],
                    ephemeral: &[],
                    delete_messages: &[],
                    delete_group_messages: &[],
                    delete_media: &[],
                    delete_scheduled: &[],
                    delete_sessions: &[],
                    delete_capabilities: &[],
                    clear_reset_markers: &[],
                    delete_controls: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }
        Ok(())
    }

    pub(crate) fn apply_resolved_device_sync(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let events = self
            .store
            .device_sync_events()?
            .into_iter()
            .map(|bytes| DeviceSyncEvent::decode(&bytes))
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let resolved = resolve_device_sync_events(&self.device_state.manifest, events);
        // Definitions own the existence of group state. Project them before
        // authority winners so a newly synchronized group and its authority
        // converge in this invocation rather than requiring another tick.
        for ((namespace, key), event) in &resolved {
            if *namespace == DeviceSyncNamespace::Groups && key.first() == Some(&b'd') {
                self.apply_sync_group(key, event.value.as_deref(), rng)?;
            }
        }
        for ((namespace, key), event) in resolved {
            if namespace == DeviceSyncNamespace::Groups && key.first() == Some(&b'd') {
                continue;
            }
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
                            let before = self.store.get_contact(&peer)?;
                            let verified = before.as_ref().is_some_and(|stored| stored.verified);
                            contact.verified = verified;
                            if before.as_ref() != Some(&contact) {
                                let projection = DeviceProjection::Contact {
                                    before: before.as_ref(),
                                    after: Some(&contact),
                                };
                                let receipt = self.store.commit_plan(
                                    CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                        projections: &[projection],
                                        delete_sessions: &[],
                                        delete_capabilities: &[],
                                        delete_queue: &[],
                                        presentation_changed: true,
                                    }),
                                    rng,
                                )?;
                                self.accept_commit_receipt(receipt, []);
                            }
                        } else {
                            let before = self.store.get_contact(&peer)?;
                            let session = self.store.get_session(&peer)?;
                            let capabilities = self.store.get_capabilities(&peer)?;
                            let queue = self
                                .store
                                .queue_all()?
                                .into_iter()
                                .filter(|(_, item)| item.peer == peer)
                                .map(|(sequence, item)| QueueDelete {
                                    sequence,
                                    content_id: item.envelope.content_id(),
                                })
                                .collect::<Vec<_>>();
                            if before.is_some()
                                || session.is_some()
                                || capabilities.is_some()
                                || !queue.is_empty()
                            {
                                self.retire_device_projection_queue(&queue, rng)?;
                                let projections = before
                                    .as_ref()
                                    .map(|before| {
                                        vec![DeviceProjection::Contact {
                                            before: Some(before),
                                            after: None,
                                        }]
                                    })
                                    .unwrap_or_default();
                                let sessions = session
                                    .as_ref()
                                    .map(|before| {
                                        vec![SessionDelete {
                                            peer_device: peer,
                                            before,
                                        }]
                                    })
                                    .unwrap_or_default();
                                let capability_deletes = capabilities
                                    .as_ref()
                                    .map(|before| {
                                        vec![CapabilityDelete {
                                            peer_device: peer,
                                            before,
                                        }]
                                    })
                                    .unwrap_or_default();
                                if projections.is_empty()
                                    && sessions.is_empty()
                                    && capability_deletes.is_empty()
                                {
                                    continue;
                                }
                                let receipt = self.store.commit_plan(
                                    CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                        projections: &projections,
                                        delete_sessions: &sessions,
                                        delete_capabilities: &capability_deletes,
                                        delete_queue: &[],
                                        presentation_changed: before.is_some(),
                                    }),
                                    rng,
                                )?;
                                self.before_memory_replacement()?;
                                self.sessions.remove(&peer);
                                self.capabilities_advertised.remove(&peer);
                                self.after_memory_replacement()?;
                                self.accept_commit_receipt(receipt, []);
                            }
                        }
                    } else if key.len() == 65 && key[0] == b'd' {
                        let account: [u8; 32] = key[1..33]
                            .try_into()
                            .map_err(|_| NodeError::InvalidDeviceSync)?;
                        let device: [u8; 32] = key[33..65]
                            .try_into()
                            .map_err(|_| NodeError::InvalidDeviceSync)?;
                        let before = self.store.contact_devices()?.into_iter().find(|endpoint| {
                            endpoint.account == account && endpoint.device == device
                        });
                        let after = if let Some(value) = event.value {
                            let endpoint: ContactDeviceRecord = decode_exact(&value)?;
                            if endpoint.account != account || endpoint.device != device {
                                return Err(NodeError::InvalidDeviceSync);
                            }
                            Some(endpoint)
                        } else {
                            None
                        };
                        let retiring = after
                            .as_ref()
                            .is_none_or(|endpoint| endpoint.revoked_at.is_some());
                        let session = if retiring {
                            self.store.get_session(&device)?
                        } else {
                            None
                        };
                        let capabilities = if retiring {
                            self.store.get_capabilities(&device)?
                        } else {
                            None
                        };
                        let queue = if retiring {
                            self.store
                                .queue_all()?
                                .into_iter()
                                .filter(|(_, item)| item.peer == device)
                                .map(|(sequence, item)| QueueDelete {
                                    sequence,
                                    content_id: item.envelope.content_id(),
                                })
                                .collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        };
                        if before.as_ref() != after.as_ref()
                            || session.is_some()
                            || capabilities.is_some()
                            || !queue.is_empty()
                        {
                            self.retire_device_projection_queue(&queue, rng)?;
                            let projections = if before.as_ref() != after.as_ref() {
                                vec![DeviceProjection::ContactDevice {
                                    before: before.as_ref(),
                                    after: after.as_ref(),
                                }]
                            } else {
                                Vec::new()
                            };
                            let sessions = session
                                .as_ref()
                                .map(|before| {
                                    vec![SessionDelete {
                                        peer_device: device,
                                        before,
                                    }]
                                })
                                .unwrap_or_default();
                            let capability_deletes = capabilities
                                .as_ref()
                                .map(|before| {
                                    vec![CapabilityDelete {
                                        peer_device: device,
                                        before,
                                    }]
                                })
                                .unwrap_or_default();
                            if projections.is_empty()
                                && sessions.is_empty()
                                && capability_deletes.is_empty()
                            {
                                continue;
                            }
                            let receipt = self.store.commit_plan(
                                CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                    projections: &projections,
                                    delete_sessions: &sessions,
                                    delete_capabilities: &capability_deletes,
                                    delete_queue: &[],
                                    presentation_changed: before.as_ref() != after.as_ref(),
                                }),
                                rng,
                            )?;
                            if retiring {
                                self.before_memory_replacement()?;
                                self.sessions.remove(&device);
                                self.capabilities_advertised.remove(&device);
                                self.after_memory_replacement()?;
                            }
                            self.accept_commit_receipt(receipt, []);
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
                    if let Some(before) = self.store.get_contact(&peer)? {
                        let mut contact = before.clone();
                        contact.verified = verified;
                        if contact != before {
                            let projection = DeviceProjection::Contact {
                                before: Some(&before),
                                after: Some(&contact),
                            };
                            let receipt = self.store.commit_plan(
                                CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                    projections: &[projection],
                                    delete_sessions: &[],
                                    delete_capabilities: &[],
                                    delete_queue: &[],
                                    presentation_changed: true,
                                }),
                                rng,
                            )?;
                            self.accept_commit_receipt(receipt, []);
                        }
                    }
                }
                DeviceSyncNamespace::LocalOrganization => {
                    let metadata_key: LocalMetadataKey = decode_exact(&key)?;
                    let before = self.store.get_local_metadata(&metadata_key)?;
                    let after = if let Some(value) = event.value {
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
                        Some(record)
                    } else {
                        None
                    };
                    if before.as_ref() != after.as_ref() {
                        let projection = DeviceProjection::LocalMetadata {
                            before: before.as_ref(),
                            after: after.as_ref(),
                        };
                        let receipt = self.store.commit_plan(
                            CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                projections: &[projection],
                                delete_sessions: &[],
                                delete_capabilities: &[],
                                delete_queue: &[],
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.accept_commit_receipt(receipt, []);
                    }
                }
                DeviceSyncNamespace::ConversationHistory
                | DeviceSyncNamespace::MessageEdits
                | DeviceSyncNamespace::GroupPolls => {
                    self.apply_sync_history(namespace, &key, event.value.as_deref(), rng)?;
                }
                DeviceSyncNamespace::Groups => {
                    self.apply_sync_group(&key, event.value.as_deref(), rng)?;
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
                        let before_ephemeral = self.store.get_ephemeral_record(
                            &tombstone.conversation,
                            &tombstone.author,
                            &tombstone.content_id,
                        )?;
                        if before_ephemeral.as_ref().is_some_and(|before| {
                            before != &tombstone
                                && before.state != kult_store::EphemeralState::Active
                        }) {
                            return Err(NodeError::InvalidDeviceSync);
                        }
                        let mut delete_messages = Vec::new();
                        let mut delete_group_messages = Vec::new();
                        match tombstone.conversation {
                            kult_store::EphemeralConversation::Pairwise(peer) => {
                                let direction = if tombstone.author == self.account.ed {
                                    Direction::Outbound
                                } else {
                                    Direction::Inbound
                                };
                                if let Some(message) = self
                                    .store
                                    .messages_with(&peer)?
                                    .into_iter()
                                    .find(|message| {
                                        message.direction == direction
                                            && message.id == tombstone.content_id
                                    })
                                {
                                    delete_messages.push(message);
                                }
                            }
                            kult_store::EphemeralConversation::Group(group) => {
                                if let Some(message) = self
                                    .store
                                    .group_messages(&group)?
                                    .into_iter()
                                    .find(|message| {
                                        message.sender == tombstone.author
                                            && message.id == tombstone.content_id
                                    })
                                {
                                    delete_group_messages.push(message);
                                }
                            }
                        }
                        let ephemeral = (before_ephemeral.as_ref() != Some(&tombstone))
                            .then_some(EphemeralTransition {
                                before: before_ephemeral.as_ref(),
                                after: &tombstone,
                            })
                            .into_iter()
                            .collect::<Vec<_>>();
                        let message_deletes = delete_messages
                            .iter()
                            .map(|before| MessageDelete { before })
                            .collect::<Vec<_>>();
                        let group_message_deletes = delete_group_messages
                            .iter()
                            .map(|before| GroupMessageDelete { before })
                            .collect::<Vec<_>>();
                        if !ephemeral.is_empty()
                            || !message_deletes.is_empty()
                            || !group_message_deletes.is_empty()
                        {
                            let receipt = self.store.commit_plan(
                                CommitPlan::Maintenance(MaintenancePlan {
                                    seen: &[],
                                    delete_pending: &[],
                                    delete_queue: &[],
                                    update_queue: &[],
                                    delete_replay: &[],
                                    messages: &[],
                                    deliveries: &[],
                                    group_messages: &[],
                                    groups: &[],
                                    ephemeral: &ephemeral,
                                    delete_messages: &message_deletes,
                                    delete_group_messages: &group_message_deletes,
                                    delete_media: &[],
                                    delete_scheduled: &[],
                                    delete_sessions: &[],
                                    delete_capabilities: &[],
                                    clear_reset_markers: &[],
                                    delete_controls: &[],
                                    acknowledge_presentation: None,
                                    presentation_changed: true,
                                }),
                                rng,
                            )?;
                            self.accept_commit_receipt(receipt, []);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_sync_history(
        &mut self,
        namespace: DeviceSyncNamespace,
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
                    let before = self
                        .store
                        .messages_with(&peer)?
                        .into_iter()
                        .find(|message| message.direction == direction && message.id == id);
                    if let Some(before) = before {
                        let projection = DeviceProjection::Message {
                            before: Some(&before),
                            after: None,
                        };
                        let receipt = self.store.commit_plan(
                            CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                projections: &[projection],
                                delete_sessions: &[],
                                delete_capabilities: &[],
                                delete_queue: &[],
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.accept_commit_receipt(receipt, []);
                    }
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
                    let before = self
                        .store
                        .group_messages(&group)?
                        .into_iter()
                        .find(|message| message.sender == sender && message.id == id);
                    if let Some(before) = before {
                        let projection = DeviceProjection::GroupMessage {
                            before: Some(&before),
                            after: None,
                        };
                        let receipt = self.store.commit_plan(
                            CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                projections: &[projection],
                                delete_sessions: &[],
                                delete_capabilities: &[],
                                delete_queue: &[],
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.accept_commit_receipt(receipt, []);
                    }
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
                let before = self
                    .store
                    .messages_with(&message.peer)?
                    .into_iter()
                    .find(|stored| {
                        stored.id == message.id && stored.direction == message.direction
                    });
                if before.as_ref() != Some(&message) {
                    let projection = DeviceProjection::Message {
                        before: before.as_ref(),
                        after: Some(&message),
                    };
                    let receipt = self.store.commit_plan(
                        CommitPlan::DeviceProjection(DeviceProjectionPlan {
                            projections: &[projection],
                            delete_sessions: &[],
                            delete_capabilities: &[],
                            delete_queue: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    self.accept_commit_receipt(receipt, []);
                }
            }
            SyncHistoryValue::Group(mut message) => {
                if synced_group_history_namespace(&message) != Some(namespace)
                    || !valid_synced_group_origin(
                        &self.device_state.manifest,
                        &self.store.contact_devices()?,
                        &self.account.ed,
                        &message,
                    )
                {
                    return Ok(());
                }
                let mut expected = Vec::with_capacity(81);
                expected.push(b'g');
                expected.extend_from_slice(&message.group);
                expected.extend_from_slice(&message.sender);
                expected.extend_from_slice(&message.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                message.wire_body = None;
                let before = self
                    .store
                    .group_messages(&message.group)?
                    .into_iter()
                    .find(|stored| stored.id == message.id && stored.sender == message.sender);
                if before.as_ref() != Some(&message) {
                    let projection = DeviceProjection::GroupMessage {
                        before: before.as_ref(),
                        after: Some(&message),
                    };
                    let receipt = self.store.commit_plan(
                        CommitPlan::DeviceProjection(DeviceProjectionPlan {
                            projections: &[projection],
                            delete_sessions: &[],
                            delete_capabilities: &[],
                            delete_queue: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    self.accept_commit_receipt(receipt, []);
                }
            }
            SyncHistoryValue::Note(message) => {
                let mut expected = Vec::with_capacity(17);
                expected.push(b'n');
                expected.extend_from_slice(&message.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                let before = self
                    .store
                    .note_messages()?
                    .iter()
                    .find(|stored| stored.id == message.id)
                    .cloned();
                match before {
                    Some(before) if before != message => {
                        return Err(NodeError::InvalidDeviceSync);
                    }
                    Some(_) => {}
                    None => {
                        let projection = DeviceProjection::Note { after: &message };
                        let receipt = self.store.commit_plan(
                            CommitPlan::DeviceProjection(DeviceProjectionPlan {
                                projections: &[projection],
                                delete_sessions: &[],
                                delete_capabilities: &[],
                                delete_queue: &[],
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.accept_commit_receipt(receipt, []);
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_sync_group(
        &mut self,
        key: &[u8],
        value: Option<&[u8]>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(value) = value else {
            if key.len() != 33 {
                return Err(NodeError::InvalidDeviceSync);
            }
            let group: [u8; 32] = key[1..]
                .try_into()
                .map_err(|_| NodeError::InvalidDeviceSync)?;
            match key[0] {
                b'd' => {
                    let before = self.store.get_group(&group)?;
                    let chain_rows = self.store.group_chains(&group)?;
                    let authority = self.store.get_group_authority(&group)?;
                    if before.is_none() && chain_rows.is_empty() && authority.is_none() {
                        return Ok(());
                    }
                    let groups = before
                        .as_ref()
                        .map(|before| GroupStateTransition {
                            before: Some(before),
                            after: None,
                        })
                        .into_iter()
                        .collect::<Vec<_>>();
                    let chains = chain_rows
                        .iter()
                        .map(|(peer, chain)| kult_store::GroupChainStateTransition {
                            group,
                            peer: *peer,
                            before: Some(chain.as_slice()),
                            after: None,
                        })
                        .collect::<Vec<_>>();
                    let authorities = authority
                        .as_ref()
                        .map(|before| GroupAuthorityStateTransition {
                            before: Some(before),
                            after: None,
                        })
                        .into_iter()
                        .collect::<Vec<_>>();
                    let receipt = self.store.commit_plan(
                        CommitPlan::GroupState(GroupStatePlan {
                            groups: &groups,
                            chains: &chains,
                            contacts: &[],
                            authorities: &authorities,
                            delete_controls: &[],
                            presentation_changed: before.is_some(),
                        }),
                        rng,
                    )?;
                    self.accept_commit_receipt(receipt, []);
                }
                b'a' => {
                    if let Some(before) = self.store.get_group_authority(&group)? {
                        let receipt = self.store.commit_plan(
                            CommitPlan::GroupState(GroupStatePlan {
                                groups: &[],
                                chains: &[],
                                contacts: &[],
                                authorities: &[GroupAuthorityStateTransition {
                                    before: Some(&before),
                                    after: None,
                                }],
                                delete_controls: &[],
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.accept_commit_receipt(receipt, []);
                    }
                }
                _ => return Err(NodeError::InvalidDeviceSync),
            }
            return Ok(());
        };
        match decode_exact::<SyncGroupValue>(value)? {
            SyncGroupValue::Definition(group) => {
                let mut expected = Vec::with_capacity(33);
                expected.push(b'd');
                expected.extend_from_slice(&group.id);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                if let Some(stored) = self.store.get_group(&group.id)? {
                    if group.generation >= stored.generation {
                        let mut after = stored.clone();
                        after.name = group.name;
                        after.creator = group.creator;
                        after.members = group.members;
                        after.secret = group.secret;
                        after.prev_secret = None;
                        after.generation = group.generation;
                        if after != stored {
                            let receipt = self.store.commit_plan(
                                CommitPlan::GroupState(GroupStatePlan {
                                    groups: &[GroupStateTransition {
                                        before: Some(&stored),
                                        after: Some(&after),
                                    }],
                                    chains: &[],
                                    contacts: &[],
                                    authorities: &[],
                                    delete_controls: &[],
                                    presentation_changed: true,
                                }),
                                rng,
                            )?;
                            self.accept_commit_receipt(receipt, []);
                        }
                    }
                } else {
                    let me = self.account.ed;
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
                    let after = GroupRecord {
                        id: group.id,
                        name: group.name,
                        creator: group.creator,
                        members: group.members,
                        secret: group.secret,
                        prev_secret: None,
                        generation: group.generation,
                        sender_chain: postcard::to_allocvec(&chain)
                            .map_err(|_| NodeError::CorruptState)?,
                        sent_since_rotation: 0,
                        pending,
                    };
                    let receipt = self.store.commit_plan(
                        CommitPlan::GroupState(GroupStatePlan {
                            groups: &[GroupStateTransition {
                                before: None,
                                after: Some(&after),
                            }],
                            chains: &[],
                            contacts: &[],
                            authorities: &[],
                            delete_controls: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    self.accept_commit_receipt(receipt, []);
                }
            }
            SyncGroupValue::Authority(authority) => {
                let mut expected = Vec::with_capacity(33);
                expected.push(b'a');
                expected.extend_from_slice(&authority.group);
                if expected != key {
                    return Err(NodeError::InvalidDeviceSync);
                }
                if self.store.get_group(&authority.group)?.is_none() {
                    return Ok(());
                }
                let before = self.store.get_group_authority(&authority.group)?;
                if before.as_ref() != Some(&authority) {
                    let receipt = self.store.commit_plan(
                        CommitPlan::GroupState(GroupStatePlan {
                            groups: &[],
                            chains: &[],
                            contacts: &[],
                            authorities: &[GroupAuthorityStateTransition {
                                before: before.as_ref(),
                                after: Some(&authority),
                            }],
                            delete_controls: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    self.accept_commit_receipt(receipt, []);
                }
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
