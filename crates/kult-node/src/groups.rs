//! Sender-key groups (docs/04-cryptography.md §6, ADR-0012): group
//! management commands, the announce plane, encrypt-once fan-out, and the
//! group receive path. Everything here rides the existing pairwise
//! machinery — announces travel as ratchet-encrypted `GroupControl`
//! envelopes, group ciphertexts fan out under each pair's rotating delivery
//! tokens, and the ordinary encrypted receipts drive both the per-member
//! delivery ladder and announce acknowledgment.

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use kult_crypto::{
    DeviceAuthorityManifest, GroupHeaderKey, GroupMessage, GroupOriginContext, GroupOriginEnvelope,
    GroupReceiverChain, GroupSenderChain, IdentityPublic, Session, GROUP_MESSAGE_VERSION_ORIGIN,
    GROUP_ORIGIN_ENVELOPE_MAGIC,
};
use kult_protocol::{
    decode_content, decode_group_authority, delivery_token, encode_disappearing_text_payload,
    encode_edit, encode_ephemeral, encode_mention, encode_text, epoch_day, pad, retention_bucket,
    unpad, DecodedContent, DecodedGroupAuthority, Edit, Envelope, EnvelopeKind, Ephemeral,
    GroupAnnounce, GroupAuthorityAnnounce, GroupControlPayload, GroupMemberInfo,
    GroupOriginAnnounce, GroupOriginAuthorityAnnounce, MailboxKey, Poll, ReceiptPayload,
    CONTENT_FORMAT_V1, CONTENT_KIND_EDIT, CONTENT_KIND_EPHEMERAL, CONTENT_KIND_MENTION,
    GROUP_ORIGIN_CAPABILITY_FORMAT, GROUP_ORIGIN_CAPABILITY_KIND, MAX_EDIT_TEXT_LEN,
    MAX_EPHEMERAL_LIFETIME_SECS, MAX_GROUP_AUTHORITY_MEMBERS, MAX_GROUP_MEMBER_IDENTITY_LEN,
    MIN_EPHEMERAL_LIFETIME_SECS,
};
use kult_store::{
    ContactDeviceRecord, ContactRecord, ContactTransition, DeferredControlRecord, DeliveryState,
    DeliveryTransition, Direction, EphemeralConversation, EphemeralMode, EphemeralRecord,
    EphemeralState, GroupAuthorityRecord, GroupAuthorityStateTransition, GroupAuthorityTransition,
    GroupChainStateTransition, GroupChainTransition, GroupDelivery, GroupMember,
    GroupMessageRecord, GroupMessageTransition, GroupOriginAuthentication, GroupPendingFanout,
    GroupPendingFanoutRoute, GroupReceivePlan, GroupRecord, GroupSendPlan, GroupStatePlan,
    GroupStateTransition, GroupTransition, MaintenancePlan, MediaDirection, MediaRecord,
    MediaScope, MediaTransferState, MediaTransferTransition, MessageDeviceDeliveryRecord,
    PairwiseSendPlan, PendingAnnounce, PendingDelete, QueueClass, QueueDelete, QueueItem,
    ScheduledMessageRecord, SessionTransition, GROUP_PENDING_FANOUT_MAGIC,
    MAX_MAINTENANCE_TRANSITIONS,
};

use crate::api::{
    GroupInfo, GroupInvitationInfo, GroupMentionCapability, GroupSecurityInfo, GroupSecurityLevel,
    MentionCapabilityIssue, MentionCapabilityIssueReason, MentionSpan, ResolvedGroupMessage,
};
use crate::{
    CommitPlan, Consumed, ContentStatus, Event, Node, NodeError, PreparedDeliveryUpdate, Result,
    MAX_MESSAGE_EDITS,
};

/// Rotate the sending chain after this many messages (PCS via periodic
/// rotation, spec §6).
const GROUP_ROTATE_MSGS: u32 = 1000;

/// End-to-end resend pacing for unacknowledged announces. Transport-level
/// retries handle a flaky link; this covers an envelope lost in transit
/// outright (a member missing one announce is deaf to its sender).
const GROUP_ANNOUNCE_RETRY_SECS: u64 = 900;
const LEGACY_DEVICE_GROUP_CHAINS_V2_MAGIC: &[u8; 4] = b"KGC2";
const LEGACY_DEVICE_GROUP_CHAINS_V3_MAGIC: &[u8; 4] = b"KGC3";
const DEVICE_GROUP_CHAINS_MAGIC: &[u8; 4] = b"KGC4";
const LEGACY_GROUP_SENDER_ORIGIN_MAGIC: &[u8; 4] = b"KGS2";
const GROUP_SENDER_ORIGIN_MAGIC: &[u8; 4] = b"KGS3";
const MAX_DEVICE_GROUP_CHAINS: usize = 64;
const MAX_GROUP_ORIGIN_ROUTES: usize = MAX_GROUP_AUTHORITY_MEMBERS * 8;
/// Maximum live group invitations retained outside normal group state.
pub const MAX_GROUP_INVITATION_REQUESTS: usize = 32;
/// Maximum aggregate decrypted group-control bytes retained for invitations.
pub const MAX_GROUP_INVITATION_BYTES: usize = 512 * 1024;
/// Maximum local lifetime of a group invitation.
pub const MAX_GROUP_INVITATION_LIFETIME_SECS: u64 = 7 * 86_400;
const MAX_GROUP_INVITATION_EXPIRIES_PER_TICK: usize = 16;

#[derive(Serialize, Deserialize)]
struct DeviceGroupReceiverChain {
    device: [u8; 32],
    chain: GroupReceiverChain,
    origin_key: Option<[u8; 32]>,
    recipient_device: [u8; 32],
    origin_generation: u64,
    origin_announce_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct LegacyDeviceGroupReceiverChainV2 {
    device: [u8; 32],
    chain: GroupReceiverChain,
}

#[derive(Serialize, Deserialize)]
struct LegacyDeviceGroupReceiverChainV3 {
    device: [u8; 32],
    chain: GroupReceiverChain,
    origin_key: Option<[u8; 32]>,
    recipient_device: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct OutgoingGroupOrigin {
    recipient_account: [u8; 32],
    recipient_device: [u8; 32],
    key_id: [u8; 16],
    chain_key: [u8; 32],
    iteration: u32,
    origin_key: [u8; 32],
    wire_id: Option<[u8; 16]>,
    last_sent: u64,
    acknowledged: bool,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct GroupSenderState {
    origin_generation: u64,
    chain: GroupSenderChain,
    origins: Vec<OutgoingGroupOrigin>,
}

#[derive(Serialize, Deserialize)]
struct LegacyGroupSenderState {
    chain: GroupSenderChain,
    origins: Vec<OutgoingGroupOrigin>,
}

#[derive(Default)]
struct PreparedGroupCopy {
    queue: Vec<QueueItem>,
    deliveries: Vec<MessageDeviceDeliveryRecord>,
    delivery_updates: Vec<(MessageDeviceDeliveryRecord, MessageDeviceDeliveryRecord)>,
    first_wire: Option<[u8; 16]>,
    all_served: bool,
    completed_routes: Vec<([u8; 32], [u8; 32])>,
}

struct PreparedGroupControl {
    preferred_wire: [u8; 16],
    routes: Vec<PreparedGroupControlRoute>,
    queue: Vec<QueueItem>,
}

struct PreparedGroupControlRoute {
    device: [u8; 32],
    before: Option<Session>,
    after: Session,
    reset: bool,
}

type GroupRouteDevice = ([u8; 32], [u8; 32], bool);
type PreparedGroupReceiverChainUpdate = (Option<zeroize::Zeroizing<Vec<u8>>>, Option<Vec<u8>>);

#[derive(Clone, Copy)]
pub(crate) struct AuthenticatedGroupSender {
    pub(crate) account: [u8; 32],
    pub(crate) device: [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct GroupOriginMaterial {
    pub(crate) key: [u8; 32],
    pub(crate) generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupControlAnnounceContext<'a> {
    pub(crate) origin: Option<GroupOriginMaterial>,
    pub(crate) control: &'a DeferredControlRecord,
    pub(crate) accept_invitation: bool,
}

pub(crate) struct GroupReceiverChainMaterial {
    pub(crate) key_id: [u8; 16],
    pub(crate) chain_key: [u8; 32],
    pub(crate) iteration: u32,
    pub(crate) origin: Option<GroupOriginMaterial>,
}

struct GroupInboundContext {
    peer: [u8; 32],
    envelope_retention: Option<u64>,
    origin: Option<([u8; 16], GroupOriginAuthentication)>,
    now: u64,
}

struct PreparedGroupInbound {
    message: Option<GroupMessageRecord>,
    ephemeral: Option<EphemeralRecord>,
    media_transfers: Vec<kult_store::MediaTransferRecord>,
    media_objects: Vec<kult_store::MediaObjectRecord>,
    events: Vec<Event>,
    attachment_updates: Vec<[u8; 16]>,
}

pub(crate) struct PreparedAuthorityGroupState {
    pub(crate) secret: [u8; 32],
    pub(crate) name: String,
    pub(crate) creator: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) members: Vec<GroupMember>,
    pub(crate) authority_before: Option<GroupAuthorityRecord>,
    pub(crate) authority_after: GroupAuthorityRecord,
}

#[allow(clippy::too_many_arguments)] // fixed authenticated announce context
fn group_origin_announce_digest(
    group: &[u8; 32],
    sender_account: &[u8; 32],
    sender_device: &[u8; 32],
    recipient_account: &[u8; 32],
    recipient_device: &[u8; 32],
    origin_generation: u64,
    key_id: &[u8; 16],
    chain_key: &[u8; 32],
    iteration: u32,
    origin_key: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"Komms-Group-Origin-Announce-v1");
    digest.update(group);
    digest.update(sender_account);
    digest.update(sender_device);
    digest.update(recipient_account);
    digest.update(recipient_device);
    digest.update(origin_generation.to_le_bytes());
    digest.update(key_id);
    digest.update(chain_key);
    digest.update(iteration.to_le_bytes());
    digest.update(origin_key);
    digest.finalize().into()
}

fn decode_device_group_chains(
    bytes: &[u8],
    legacy_device: [u8; 32],
) -> Result<Vec<DeviceGroupReceiverChain>> {
    let (chains, permits_unordered_origin) =
        if let Some(body) = bytes.strip_prefix(DEVICE_GROUP_CHAINS_MAGIC) {
            let (chains, remainder): (Vec<DeviceGroupReceiverChain>, &[u8]) =
                postcard::take_from_bytes(body).map_err(|_| NodeError::CorruptState)?;
            if !remainder.is_empty() {
                return Err(NodeError::CorruptState);
            }
            (chains, false)
        } else if let Some(body) = bytes.strip_prefix(LEGACY_DEVICE_GROUP_CHAINS_V3_MAGIC) {
            let (chains, remainder): (Vec<LegacyDeviceGroupReceiverChainV3>, &[u8]) =
                postcard::take_from_bytes(body).map_err(|_| NodeError::CorruptState)?;
            if !remainder.is_empty() {
                return Err(NodeError::CorruptState);
            }
            (
                chains
                    .into_iter()
                    .map(|entry| DeviceGroupReceiverChain {
                        device: entry.device,
                        chain: entry.chain,
                        origin_key: entry.origin_key,
                        recipient_device: entry.recipient_device,
                        // KGC3 never carried an ordering value or the original
                        // chain-snapshot commitment. A fresh authenticated announce
                        // upgrades it once instead of guessing ordering.
                        origin_generation: 0,
                        origin_announce_digest: [0u8; 32],
                    })
                    .collect(),
                true,
            )
        } else if let Some(body) = bytes.strip_prefix(LEGACY_DEVICE_GROUP_CHAINS_V2_MAGIC) {
            let (chains, remainder): (Vec<LegacyDeviceGroupReceiverChainV2>, &[u8]) =
                postcard::take_from_bytes(body).map_err(|_| NodeError::CorruptState)?;
            if !remainder.is_empty() {
                return Err(NodeError::CorruptState);
            }
            (
                chains
                    .into_iter()
                    .map(|entry| DeviceGroupReceiverChain {
                        device: entry.device,
                        chain: entry.chain,
                        origin_key: None,
                        recipient_device: [0u8; 32],
                        origin_generation: 0,
                        origin_announce_digest: [0u8; 32],
                    })
                    .collect(),
                false,
            )
        } else {
            let chain = postcard::from_bytes(bytes).map_err(|_| NodeError::CorruptState)?;
            (
                vec![DeviceGroupReceiverChain {
                    device: legacy_device,
                    chain,
                    origin_key: None,
                    recipient_device: [0u8; 32],
                    origin_generation: 0,
                    origin_announce_digest: [0u8; 32],
                }],
                false,
            )
        };
    if chains.is_empty()
        || chains.len() > MAX_DEVICE_GROUP_CHAINS
        || chains
            .windows(2)
            .any(|pair| pair[0].device >= pair[1].device)
        || chains.iter().any(|entry| match entry.origin_key {
            Some(key) => {
                key == [0u8; 32]
                    || entry.recipient_device == [0u8; 32]
                    || (entry.origin_generation == 0 && !permits_unordered_origin)
                    || (entry.origin_generation == 0 && entry.origin_announce_digest != [0u8; 32])
                    || (entry.origin_generation != 0 && entry.origin_announce_digest == [0u8; 32])
            }
            None => {
                entry.recipient_device != [0u8; 32]
                    || entry.origin_generation != 0
                    || entry.origin_announce_digest != [0u8; 32]
            }
        })
    {
        return Err(NodeError::CorruptState);
    }
    Ok(chains)
}

fn encode_device_group_chains(chains: &mut Vec<DeviceGroupReceiverChain>) -> Result<Vec<u8>> {
    for entry in chains.iter_mut().filter(|entry| {
        entry.origin_key.is_some()
            && entry.origin_generation == 0
            && entry.origin_announce_digest == [0u8; 32]
    }) {
        // KGC3 carried no monotonic ordering or immutable announce
        // commitment. Once any row is rewritten, retire that unordered
        // capability and require a fresh authenticated announce.
        entry.origin_key.zeroize();
        entry.origin_key = None;
        entry.recipient_device = [0u8; 32];
    }
    chains.sort_by_key(|entry| entry.device);
    chains.dedup_by_key(|entry| entry.device);
    if chains.is_empty()
        || chains.len() > MAX_DEVICE_GROUP_CHAINS
        || chains.iter().any(|entry| match entry.origin_key {
            Some(key) => {
                key == [0u8; 32]
                    || entry.recipient_device == [0u8; 32]
                    || entry.origin_generation == 0
                    || entry.origin_announce_digest == [0u8; 32]
            }
            None => {
                entry.recipient_device != [0u8; 32]
                    || entry.origin_generation != 0
                    || entry.origin_announce_digest != [0u8; 32]
            }
        })
    {
        return Err(NodeError::CorruptState);
    }
    let body = postcard::to_allocvec(chains).map_err(|_| NodeError::CorruptState)?;
    let mut encoded = Vec::with_capacity(DEVICE_GROUP_CHAINS_MAGIC.len() + body.len());
    encoded.extend_from_slice(DEVICE_GROUP_CHAINS_MAGIC);
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

impl Node {
    // ---- commands -----------------------------------------------------------

    fn group_route_devices(&self, members: &[GroupMember]) -> Result<Vec<GroupRouteDevice>> {
        let me = self.account.ed;
        let mut routes = Vec::new();
        for member in members.iter().filter(|member| member.peer != me) {
            let mut endpoints = self
                .store
                .contact_devices_for(&member.peer)?
                .into_iter()
                .filter(|endpoint| endpoint.revoked_at.is_none())
                .collect::<Vec<_>>();
            endpoints.sort_unstable_by_key(|endpoint| endpoint.device);
            endpoints.dedup_by_key(|endpoint| endpoint.device);
            if endpoints.is_empty() {
                routes.push((member.peer, member.peer, false));
                continue;
            }
            for endpoint in endpoints {
                let authorized = DeviceAuthorityManifest::decode(&endpoint.authority)
                    .ok()
                    .filter(|manifest| manifest.verify().is_ok())
                    .is_some_and(|manifest| {
                        manifest.account().ed == member.peer
                            && manifest.active_certificate(&endpoint.device).is_some()
                    });
                routes.push((member.peer, endpoint.device, authorized));
            }
        }
        routes.sort_unstable_by_key(|(account, device, _)| (*account, *device));
        routes.dedup_by_key(|(account, device, _)| (*account, *device));
        if routes.len() > MAX_GROUP_ORIGIN_ROUTES {
            return Err(NodeError::CorruptState);
        }
        Ok(routes)
    }

    fn route_supports_group_origins(&self, device: &[u8; 32]) -> Result<bool> {
        Ok(self.sessions.contains_key(device)
            && self
                .store
                .get_capabilities(device)?
                .is_some_and(|capabilities| {
                    capabilities
                        .supports(GROUP_ORIGIN_CAPABILITY_FORMAT, GROUP_ORIGIN_CAPABILITY_KIND)
                }))
    }

    fn verified_group_sender_account(&self, device: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        for endpoint in self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.device == *device && endpoint.revoked_at.is_none())
        {
            let Ok(manifest) = DeviceAuthorityManifest::decode(&endpoint.authority) else {
                continue;
            };
            if manifest.verify().is_ok()
                && manifest.account().ed == endpoint.account
                && manifest.active_certificate(device).is_some()
            {
                return Ok(Some(endpoint.account));
            }
        }
        Ok(None)
    }

    pub(crate) fn can_initialize_group_origins(&self, members: &[GroupMember]) -> Result<bool> {
        for (_, device, authorized) in self.group_route_devices(members)? {
            if !authorized || !self.route_supports_group_origins(&device)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn new_origin_sender_state(
        &self,
        members: &[GroupMember],
        chain: GroupSenderChain,
        origin_generation: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<GroupSenderState> {
        if origin_generation == 0 {
            return Err(NodeError::CorruptState);
        }
        let (key_id, chain_key, iteration) = chain.snapshot();
        let mut origins = Vec::new();
        for (recipient_account, recipient_device, authorized) in
            self.group_route_devices(members)?
        {
            if !authorized {
                // A manifest gap must block sending, but it must not preserve
                // a capability for a device that is no longer authorized.
                // The visible security state keeps the unresolved route
                // pending until a valid authority chain arrives.
                continue;
            }
            let mut origin_key = [0u8; 32];
            while origin_key == [0u8; 32] {
                rng.fill_bytes(&mut origin_key);
            }
            origins.push(OutgoingGroupOrigin {
                recipient_account,
                recipient_device,
                key_id,
                chain_key: *chain_key,
                iteration,
                origin_key,
                wire_id: None,
                last_sent: 0,
                acknowledged: false,
            });
        }
        let state = GroupSenderState {
            origin_generation,
            chain,
            origins,
        };
        validate_sender_origins(&state)?;
        Ok(state)
    }

    fn group_security_info_for(&self, rec: &GroupRecord) -> Result<GroupSecurityInfo> {
        let sender = decode_sender_state(&rec.sender_chain)?;
        let StoredGroupSenderState::Origin(state) = sender else {
            return Ok(GroupSecurityInfo {
                group: rec.id,
                level: GroupSecurityLevel::UpgradeRequired,
                pending_devices: self
                    .group_route_devices(&rec.members)?
                    .into_iter()
                    .map(|(_, device, _)| device)
                    .collect(),
                legacy_history_rows: self
                    .store
                    .group_messages(&rec.id)?
                    .into_iter()
                    .filter(|message| message.origin.is_legacy_membership())
                    .count(),
            });
        };
        let local_device = self.device_id();
        let mut pending_devices = Vec::new();
        for (account, device, authorized) in self.group_route_devices(&rec.members)? {
            let outgoing_ready = state.origins.iter().any(|origin| {
                origin.recipient_account == account
                    && origin.recipient_device == device
                    && origin.acknowledged
            });
            let incoming_ready = self
                .store
                .get_group_chain(&rec.id, &account)?
                .as_ref()
                .and_then(|blob| decode_device_group_chains(blob, account).ok())
                .is_some_and(|chains| {
                    chains.iter().any(|entry| {
                        entry.device == device
                            && entry.recipient_device == local_device
                            && entry.origin_key.is_some()
                            && entry.origin_generation != 0
                            && entry.origin_announce_digest != [0u8; 32]
                    })
                });
            if !authorized
                || !self.route_supports_group_origins(&device)?
                || !outgoing_ready
                || !incoming_ready
            {
                pending_devices.push(device);
            }
        }
        pending_devices.sort_unstable();
        pending_devices.dedup();
        let level = if pending_devices.is_empty() {
            GroupSecurityLevel::RecipientAuthenticated
        } else {
            GroupSecurityLevel::Upgrading
        };
        Ok(GroupSecurityInfo {
            group: rec.id,
            level,
            pending_devices,
            legacy_history_rows: self
                .store
                .group_messages(&rec.id)?
                .into_iter()
                .filter(|message| message.origin.is_legacy_membership())
                .count(),
        })
    }

    /// Current visible ADR-0029 upgrade state and retained legacy-history
    /// count for one group.
    pub fn group_security_info(&self, group: &[u8; 32]) -> Result<GroupSecurityInfo> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.group_security_info_for(&rec)
    }

    /// Start the visible security upgrade after every exact current device
    /// has authenticated ADR-0029 support over its pairwise session.
    pub fn group_upgrade_security(
        &mut self,
        group: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let before = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        if matches!(
            decode_sender_state(&before.sender_chain)?,
            StoredGroupSenderState::Origin(_)
        ) {
            return Ok(());
        }
        if !self.can_initialize_group_origins(&before.members)? {
            return Err(NodeError::GroupSecurityUpgradeRequired);
        }
        let mut after = before.clone();
        self.rotate_group_origin(&mut after, rng)?;
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&before),
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
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: *group }]);
        Ok(())
    }

    fn has_current_incoming_group_origin(&self, rec: &GroupRecord) -> Result<bool> {
        let local_device = self.device_id();
        let routes = self
            .group_route_devices(&rec.members)?
            .into_iter()
            .filter(|(_, _, authorized)| *authorized)
            .map(|(account, device, _)| (account, device))
            .collect::<HashSet<_>>();
        for member in rec
            .members
            .iter()
            .filter(|member| member.peer != self.account.ed)
        {
            let Some(blob) = self.store.get_group_chain(&rec.id, &member.peer)? else {
                continue;
            };
            if decode_device_group_chains(&blob, member.peer)?
                .into_iter()
                .any(|entry| {
                    routes.contains(&(member.peer, entry.device))
                        && entry.recipient_device == local_device
                        && entry.origin_key.is_some()
                        && entry.origin_generation != 0
                        && entry.origin_announce_digest != [0u8; 32]
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn reconcile_group_origin_sender(
        &mut self,
        rec: &GroupRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<GroupRecord>> {
        let sender = decode_sender_state(&rec.sender_chain)?;
        let should_rotate = match sender {
            StoredGroupSenderState::Legacy(_) => {
                self.has_current_incoming_group_origin(rec)?
                    && self.can_initialize_group_origins(&rec.members)?
            }
            StoredGroupSenderState::Origin(state) => {
                let expected = self
                    .group_route_devices(&rec.members)?
                    .into_iter()
                    .filter(|(_, _, authorized)| *authorized)
                    .map(|(account, device, _)| (account, device))
                    .collect::<Vec<_>>();
                let actual = state
                    .origins
                    .iter()
                    .map(|origin| (origin.recipient_account, origin.recipient_device))
                    .collect::<Vec<_>>();
                expected != actual
            }
        };
        if !should_rotate {
            return Ok(None);
        }
        let mut after = rec.clone();
        self.rotate_group_origin(&mut after, rng)?;
        Ok(Some(after))
    }

    pub(crate) fn require_recipient_authenticated_group(&self, group: &[u8; 32]) -> Result<()> {
        let status = self.group_security_info(group)?;
        if status.level != GroupSecurityLevel::RecipientAuthenticated {
            return Err(NodeError::GroupSecurityUpgradeRequired);
        }
        Ok(())
    }

    fn require_fresh_group_origin_material(&self, group: &[u8; 32]) -> Result<()> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let StoredGroupSenderState::Origin(state) = decode_sender_state(&rec.sender_chain)? else {
            return Err(NodeError::GroupSecurityUpgradeRequired);
        };
        let expected = self.group_route_devices(&rec.members)?;
        for (_, device, authorized) in &expected {
            if !authorized || !self.route_supports_group_origins(device)? {
                return Err(NodeError::GroupSecurityUpgradeRequired);
            }
        }
        let expected = expected
            .into_iter()
            .map(|(account, device, _)| (account, device))
            .collect::<Vec<_>>();
        let actual = state
            .origins
            .iter()
            .map(|origin| (origin.recipient_account, origin.recipient_device))
            .collect::<Vec<_>>();
        if expected != actual {
            return Err(NodeError::GroupSecurityUpgradeRequired);
        }
        Ok(())
    }

    /// Create a group with stored contacts. This node becomes the creator —
    /// the single writer for roster, name, and group secret (ADR-0012).
    /// Announces (invite + sender key in one message) queue on the next
    /// [`Node::tick`]. Returns the group id.
    pub fn create_group(
        &mut self,
        name: &str,
        members: &[[u8; 32]],
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let me = self.account.ed;
        let my_identity =
            postcard::to_allocvec(&self.account.clone()).map_err(|_| NodeError::CorruptState)?;
        let mut roster = vec![GroupMember {
            peer: me,
            identity: my_identity,
        }];
        for peer in members {
            if *peer == me || roster.iter().any(|m| &m.peer == peer) {
                continue;
            }
            let contact = self
                .store
                .get_contact(peer)?
                .ok_or(NodeError::UnknownPeer)?;
            roster.push(GroupMember {
                peer: *peer,
                identity: contact.identity,
            });
            if roster.len() > MAX_GROUP_AUTHORITY_MEMBERS {
                return Err(NodeError::InvalidGroupAuthority);
            }
        }

        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let chain = GroupSenderChain::generate(rng);
        let origin_ready = self.can_initialize_group_origins(&roster)?;
        let (sender_chain, pending) = if origin_ready {
            let state = self.new_origin_sender_state(&roster, chain, 1, rng)?;
            (
                encode_sender_state(&StoredGroupSenderState::Origin(state))?,
                Vec::new(),
            )
        } else {
            (
                encode_chain(&chain)?,
                pending_for(&chain, roster.iter().map(|m| m.peer), &me),
            )
        };
        let group = GroupRecord {
            id,
            name: name.to_owned(),
            creator: me,
            members: roster,
            secret,
            prev_secret: None,
            generation: 1,
            sender_chain,
            sent_since_rotation: 0,
            pending,
        };
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: None,
                    after: Some(&group),
                }],
                chains: &[],
                contacts: &[],
                authorities: &[],
                delete_controls: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: id }]);
        Ok(id)
    }

    /// All stored groups, without their secrets.
    pub fn groups(&self) -> Result<Vec<GroupInfo>> {
        self.store
            .groups()?
            .into_iter()
            .map(|g| {
                let security = self.group_security_info_for(&g)?.level;
                Ok(GroupInfo {
                    id: g.id,
                    name: g.name,
                    creator: g.creator,
                    members: g.members.iter().map(|m| m.peer).collect(),
                    security,
                })
            })
            .collect()
    }

    /// Message history for a group, in insertion order.
    pub fn group_messages(&self, group: &[u8; 32]) -> Result<Vec<GroupMessageRecord>> {
        Ok(self.store.group_messages(group)?)
    }

    /// Group read model with immutable Edit events resolved and hidden from
    /// the ordinary row sequence.
    pub fn resolved_group_messages(&self, group: &[u8; 32]) -> Result<Vec<ResolvedGroupMessage>> {
        Ok(crate::edits::resolve_group(
            self.store.group_messages(group)?,
        ))
    }

    /// Queue a message to a group: persisted `Queued` per member before any
    /// crypto runs, encrypted **once** on this node's sending chain, fanned
    /// out to every member with a live session; members whose session is
    /// still forming keep their honest `Queued` state and are served by the
    /// tick as soon as it exists. Returns the group message record id.
    pub fn group_send(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        // The generic group API is the permanent text/legacy path. A caller
        // must not smuggle an already-encoded Mention around the exact-roster
        // capability and review-token gate below.
        match decode_content(body) {
            DecodedContent::Mention { .. } => return Err(NodeError::InvalidMention),
            DecodedContent::Edit { .. } => return Err(NodeError::InvalidEdit),
            DecodedContent::Ephemeral { .. } => return Err(NodeError::InvalidEphemeral),
            DecodedContent::Poll { .. } => return Err(NodeError::InvalidPoll),
            DecodedContent::GroupAuthority { .. } => return Err(NodeError::InvalidGroupAuthority),
            DecodedContent::CallControl { .. } => return Err(NodeError::InvalidCall),
            _ => {}
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.group_send_with_id(group, body, id, now, now, rng)
    }

    pub(crate) fn group_send_with_id(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_with_id_source(group, body, id, timestamp, now, None, rng)
    }

    pub(crate) fn activate_scheduled_group_message(
        &mut self,
        group: &[u8; 32],
        scheduled: &ScheduledMessageRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_with_id_source(
            group,
            &scheduled.body,
            scheduled.id,
            scheduled.not_before,
            now,
            Some(scheduled),
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn group_send_with_id_source(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        scheduled: Option<&ScheduledMessageRecord>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.account.ed;
        let mut all_members_support_text = true;
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.peer_supports_text(&member.peer)? {
                all_members_support_text = false;
                break;
            }
        }
        let wire_content = if all_members_support_text {
            match core::str::from_utf8(body) {
                Ok(text) => encode_text(id, text)?,
                Err(_) => body.to_vec(),
            }
        } else {
            body.to_vec()
        };
        self.group_send_content_with_id_retention(
            group,
            wire_content,
            id,
            timestamp,
            now,
            None,
            scheduled,
            rng,
        )
    }

    /// Current exact Mention capability intersection and review binding.
    pub fn group_mention_capability(&self, group: &[u8; 32]) -> Result<GroupMentionCapability> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.account.ed;
        let mut members = rec.members.iter().collect::<Vec<_>>();
        members.sort_unstable_by_key(|member| member.peer);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"KK-group-mention-review-v1");
        hasher.update(&rec.id);
        hasher.update(&rec.generation.to_le_bytes());
        hasher.update(&(rec.name.len() as u32).to_le_bytes());
        hasher.update(rec.name.as_bytes());
        let mut issues = Vec::new();
        for member in members {
            let state = if member.peer == me {
                1u8
            } else {
                let endpoints = self.store.contact_devices_for(&member.peer)?;
                let routes = if endpoints.is_empty() {
                    vec![member.peer]
                } else {
                    endpoints
                        .into_iter()
                        .filter(|endpoint| endpoint.revoked_at.is_none())
                        .map(|endpoint| endpoint.device)
                        .collect::<Vec<_>>()
                };
                let mut missing = false;
                let mut unsupported = false;
                for route in routes {
                    match self.store.get_capabilities(&route)? {
                        None => missing = true,
                        Some(capabilities)
                            if capabilities.supports(CONTENT_FORMAT_V1, CONTENT_KIND_MENTION) => {}
                        Some(_) => unsupported = true,
                    }
                }
                if missing {
                    0
                } else if unsupported {
                    2
                } else {
                    1
                }
            };
            hasher.update(&member.peer);
            hasher.update(&[state]);
            hasher.update(&(member.identity.len() as u32).to_le_bytes());
            hasher.update(&member.identity);
            let local_name = self
                .store
                .get_contact(&member.peer)?
                .map(|contact| contact.name)
                .unwrap_or_default();
            hasher.update(&(local_name.len() as u32).to_le_bytes());
            hasher.update(local_name.as_bytes());
            if member.peer != me && state != 1 {
                issues.push(MentionCapabilityIssue {
                    peer: member.peer,
                    reason: if state == 0 {
                        MentionCapabilityIssueReason::Unknown
                    } else {
                        MentionCapabilityIssueReason::Unsupported
                    },
                });
            }
        }
        let mut review_token = [0u8; 16];
        review_token.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(GroupMentionCapability {
            group: rec.id,
            review_token,
            issues,
        })
    }

    /// Queue canonical group Mention content after atomic roster, local
    /// presentation mapping, and authenticated capability revalidation.
    pub fn group_send_mention(
        &mut self,
        group: &[u8; 32],
        text: &str,
        spans: &[MentionSpan],
        review_token: [u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let verdict = self.group_mention_capability(group)?;
        if !bool::from(review_token.ct_eq(&verdict.review_token)) {
            return Err(NodeError::MentionReviewRequired);
        }
        if !verdict.supported() {
            return Err(NodeError::MentionUnsupported);
        }
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        if spans
            .iter()
            .any(|span| !rec.members.iter().any(|member| member.peer == span.target))
        {
            return Err(NodeError::InvalidMention);
        }
        let protocol_spans = spans.iter().copied().map(Into::into).collect::<Vec<_>>();
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let wire_content =
            encode_mention(id, text, &protocol_spans).map_err(|_| NodeError::InvalidMention)?;
        self.group_send_content_with_id(group, wire_content, id, now, now, rng)
    }

    /// Queue an immutable edit for this identity's exact canonical group Text.
    pub fn group_edit_message(
        &mut self,
        group: &[u8; 32],
        target_author: [u8; 32],
        target_content_id: [u8; 16],
        text: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.account.ed;
        if target_author != me
            || text.is_empty()
            || text.len() > MAX_EDIT_TEXT_LEN
            || !rec.members.iter().any(|member| member.peer == me)
        {
            return Err(NodeError::InvalidEdit);
        }
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.peer_supports_kind(&member.peer, CONTENT_KIND_EDIT)? {
                return Err(NodeError::EditUnsupported);
            }
        }
        let records = self.store.group_messages(group)?;
        if !records.iter().any(|record| {
            record.sender == me
                && record.direction == Direction::Outbound
                && record.origin.is_recipient_authenticated()
                && matches!(
                    decode_content(&record.body),
                    DecodedContent::Text { id, .. } if id == target_content_id
                )
        }) {
            return Err(NodeError::InvalidEdit);
        }
        let revisions = records.iter().filter_map(|record| {
            if record.sender != me || record.direction != Direction::Outbound {
                return None;
            }
            match decode_content(&record.body) {
                DecodedContent::Edit { edit, .. }
                    if edit.target_author == me && edit.target_content_id == target_content_id =>
                {
                    Some(edit.revision)
                }
                _ => None,
            }
        });
        let mut count = 0usize;
        let mut revision = 0u64;
        for value in revisions {
            count += 1;
            revision = revision.max(value);
        }
        if count >= MAX_MESSAGE_EDITS {
            return Err(NodeError::EditLimit);
        }
        revision = revision.checked_add(1).ok_or(NodeError::EditLimit)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let wire_content = encode_edit(
            id,
            &Edit {
                target_author: me,
                target_content_id,
                revision,
                text,
            },
        )?;
        self.group_send_content_with_id(group, wire_content, id, now, now, rng)
    }

    /// Queue disappearing UTF-8 only after every current co-member has
    /// authenticated exact ephemeral support.
    pub fn group_send_disappearing_message(
        &mut self,
        group: &[u8; 32],
        text: &str,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if text.is_empty()
            || !(MIN_EPHEMERAL_LIFETIME_SECS..=MAX_EPHEMERAL_LIFETIME_SECS).contains(&lifetime_secs)
        {
            return Err(NodeError::InvalidEphemeral);
        }
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.account.ed;
        if !rec.members.iter().any(|member| member.peer == me) {
            return Err(NodeError::InvalidEphemeral);
        }
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.peer_has_live_device_sessions(&member.peer)?
                || !self.peer_supports_kind(&member.peer, CONTENT_KIND_EPHEMERAL)?
            {
                return Err(NodeError::EphemeralUnsupported);
            }
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(NodeError::InvalidEphemeral)?;
        let retention_until = retention_bucket(expires_at)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let payload = encode_disappearing_text_payload(expires_at, text)?;
        let wire_content = encode_ephemeral(id, &payload)?;
        self.group_send_content_with_id_retention(
            group,
            wire_content,
            id,
            now,
            now,
            Some(retention_until),
            None,
            rng,
        )
    }

    pub(crate) fn group_send_content_with_id(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_content_with_id_retention(
            group,
            wire_content,
            id,
            timestamp,
            now,
            None,
            None,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // canonical group send plus optional relay hint
    fn group_send_content_with_id_retention(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        retention_until: Option<u64>,
        scheduled: Option<&ScheduledMessageRecord>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_content_with_id_effects(
            group,
            wire_content,
            id,
            timestamp,
            now,
            retention_until,
            scheduled,
            None,
            false,
            rng,
        )
    }

    pub(crate) fn group_send_moderated_content_with_id(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_content_with_id_effects(
            group,
            wire_content,
            id,
            timestamp,
            now,
            None,
            None,
            None,
            true,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // authority message and resulting signed state
    pub(crate) fn group_send_authority_content_with_id(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        authority: &PreparedAuthorityGroupState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_content_with_id_effects(
            group,
            wire_content,
            id,
            timestamp,
            now,
            None,
            None,
            Some(authority),
            false,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // canonical group send and exact durable effects
    fn group_send_content_with_id_effects(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        retention_until: Option<u64>,
        scheduled: Option<&ScheduledMessageRecord>,
        authority: Option<&PreparedAuthorityGroupState>,
        allow_unacknowledged_origin: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let before_group = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        if allow_unacknowledged_origin {
            self.require_fresh_group_origin_material(group)?;
        } else {
            self.require_recipient_authenticated_group(group)?;
        }
        let mut after_group = before_group.clone();
        let me = self.account.ed;
        let mut record = GroupMessageRecord {
            id,
            group: *group,
            sender: me,
            direction: Direction::Outbound,
            timestamp,
            body: wire_content.clone(),
            deliveries: after_group
                .members
                .iter()
                .filter(|m| m.peer != me)
                .map(|m| GroupDelivery {
                    peer: m.peer,
                    wire_id: None,
                    state: DeliveryState::Queued,
                })
                .collect(),
            wire_body: None,
            origin: GroupOriginAuthentication::LegacyMembership,
        };

        // A spent chain rotates before it encrypts anything else (PCS).
        if after_group.sent_since_rotation >= GROUP_ROTATE_MSGS {
            self.rotate_group(&mut after_group, rng)?;
        }

        let mut sender_state = decode_sender_state(&after_group.sender_chain)?;
        let origin_chain = matches!(&sender_state, StoredGroupSenderState::Origin(_));
        let chain_key_id = sender_state.chain().key_id();
        let hk = GroupHeaderKey::derive(&after_group.secret);
        let wire = self
            .candidate_group_seal(
                sender_state.chain_mut(),
                &hk,
                group,
                origin_chain.then_some(id),
                &pad(&wire_content)?,
                rng,
            )?
            .encode();
        after_group.sender_chain = encode_sender_state(&sender_state)?;
        if origin_chain {
            record.origin = GroupOriginAuthentication::OutboundV1 {
                sender_device: self.device_id(),
                chain_key_id,
            };
        }
        after_group.sent_since_rotation = after_group
            .sent_since_rotation
            .checked_add(1)
            .ok_or(NodeError::CorruptState)?;
        let mut pending_fanout = if record.deliveries.is_empty() {
            None
        } else {
            Some(self.prepare_group_pending_fanout(
                group,
                &wire,
                &sender_state,
                &record.deliveries,
                id,
                retention_until,
            )?)
        };

        let mut removed_peers = HashSet::new();
        if let Some(authority) = authority {
            if authority.authority_after.group != *group
                || authority.authority_after.state_id != id
                || authority.members.is_empty()
            {
                return Err(NodeError::InvalidGroupAuthority);
            }
            let retained = authority
                .members
                .iter()
                .map(|member| member.peer)
                .collect::<HashSet<_>>();
            removed_peers.extend(
                after_group
                    .members
                    .iter()
                    .filter(|member| !retained.contains(&member.peer))
                    .map(|member| member.peer),
            );
            after_group.prev_secret = Some(after_group.secret);
            after_group.secret = authority.secret;
            after_group.name.clone_from(&authority.name);
            after_group.creator = authority.creator;
            after_group.generation = authority.generation;
            after_group.members.clone_from(&authority.members);
            self.rotate_group(&mut after_group, rng)?;
        }

        let mut queue = Vec::new();
        let mut delivery_rows = Vec::new();
        let mut delivery_pairs = Vec::new();
        let mut completed_routes = HashSet::new();
        for d in record.deliveries.iter_mut() {
            let pending = pending_fanout.as_ref().ok_or(NodeError::CorruptState)?;
            let prepared = self.prepare_group_copy(
                &d.peer,
                pending,
                id,
                QueueClass::Interactive,
                retention_until,
                now,
            )?;
            if prepared.all_served {
                d.wire_id = prepared.first_wire;
            }
            completed_routes.extend(prepared.completed_routes);
            queue.extend(prepared.queue);
            delivery_rows.extend(prepared.deliveries);
            delivery_pairs.extend(prepared.delivery_updates);
        }
        if let Some(mut pending) = pending_fanout.take() {
            pending
                .routes
                .retain(|route| !completed_routes.contains(&(route.account, route.device)));
            if !pending.routes.is_empty() {
                record.wire_body = Some(pending.encode()?);
            }
        }
        let delivery_updates = delivery_pairs
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let ephemeral = match decode_content(&wire_content) {
            DecodedContent::Ephemeral {
                id: content_id,
                ephemeral: Ephemeral::DisappearingText { expires_at, .. },
            } => Some(EphemeralRecord {
                conversation: EphemeralConversation::Group(*group),
                author: me,
                content_id,
                expires_at,
                mode: EphemeralMode::DisappearingText,
                state: EphemeralState::Active,
                transfer_ids: Vec::new(),
            }),
            _ => None,
        };
        let deleted_chain_rows = self
            .store
            .group_chains(group)?
            .into_iter()
            .filter(|(peer, _)| removed_peers.contains(peer))
            .collect::<Vec<_>>();
        let delete_chains = deleted_chain_rows
            .iter()
            .map(|(peer, chain)| GroupChainStateTransition {
                group: *group,
                peer: *peer,
                before: Some(chain.as_slice()),
                after: None,
            })
            .collect::<Vec<_>>();
        let authority_transition = authority.map(|authority| GroupAuthorityTransition {
            before: authority.authority_before.as_ref(),
            after: &authority.authority_after,
        });
        let receipt = self.store.commit_plan(
            CommitPlan::GroupSend(GroupSendPlan {
                group: Some(GroupTransition {
                    before: &before_group,
                    after: &after_group,
                }),
                message: Some(&record),
                message_update: None,
                deliveries: &delivery_rows,
                delivery_updates: &delivery_updates,
                queue: &queue,
                scheduled,
                ephemeral: ephemeral.as_ref(),
                media_transfers: &[],
                delete_chains: &delete_chains,
                authority: authority_transition,
                presentation_changed: true,
            }),
            rng,
        )?;
        let mut events = record
            .deliveries
            .iter()
            .map(|delivery| Event::GroupDeliveryUpdated {
                id,
                peer: delivery.peer,
                state: DeliveryState::Queued,
            })
            .collect::<Vec<_>>();
        if scheduled.is_some() {
            events.push(Event::ScheduledMessageActivated { id });
        }
        if authority.is_some() {
            events.push(Event::GroupUpdated { group: *group });
        }
        self.accept_commit_receipt(receipt, events);
        Ok(id)
    }

    /// Add a stored contact to a group (creator only). Existing members
    /// learn the roster and the new member gets everything through the same
    /// announce shape.
    pub fn group_add(
        &mut self,
        group: &[u8; 32],
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let before = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let mut rec = before.clone();
        let me = self.account.ed;
        if self.store.get_group_authority(group)?.is_some() {
            if rec.members.iter().any(|member| &member.peer == peer) {
                return Ok(());
            }
            let contact = self
                .store
                .get_contact(peer)?
                .ok_or(NodeError::UnknownPeer)?;
            self.group_authority_add_member(
                group,
                GroupMember {
                    peer: *peer,
                    identity: contact.identity,
                },
                now,
                rng,
            )?;
            return Ok(());
        }
        if rec.creator != me {
            return Err(NodeError::NotGroupCreator);
        }
        if rec.members.iter().any(|m| &m.peer == peer) {
            return Ok(()); // already in — idempotent
        }
        if rec.members.len() >= MAX_GROUP_AUTHORITY_MEMBERS {
            return Err(NodeError::InvalidGroupAuthority);
        }
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        rec.members.push(GroupMember {
            peer: *peer,
            identity: contact.identity,
        });
        rec.generation += 1;

        // Roster changes rotate both the sender chain and every recipient
        // origin capability. The newcomer starts at this fresh snapshot.
        self.rotate_group(&mut rec, rng)?;
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&before),
                    after: Some(&rec),
                }],
                chains: &[],
                contacts: &[],
                authorities: &[],
                delete_controls: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: *group }]);
        Ok(())
    }

    /// Remove a member (creator only): fresh group secret, bumped
    /// generation, own chain rotated, announces to every remaining member —
    /// and a removal notice (never the new secret) to the removed one.
    pub fn group_remove(
        &mut self,
        group: &[u8; 32],
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.account.ed;
        if peer == &me {
            return self.group_leave(group, now, rng);
        }
        if self.store.get_group_authority(group)?.is_some() {
            self.group_authority_remove_member(group, *peer, now, rng)?;
            return Ok(());
        }
        let before = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let mut rec = before.clone();
        if rec.creator != me {
            return Err(NodeError::NotGroupCreator);
        }
        if !rec.members.iter().any(|m| &m.peer == peer) {
            return Err(NodeError::UnknownPeer);
        }
        rec.members.retain(|m| &m.peer != peer);
        let chain_before = self.store.get_group_chain(group, peer)?;
        rec.generation += 1;
        rec.prev_secret = Some(rec.secret);
        rng.fill_bytes(&mut rec.secret);
        self.rotate_group(&mut rec, rng)?; // also drops the removed peer's pending entry
        let chain_transitions = chain_before
            .as_ref()
            .map(|chain| GroupChainStateTransition {
                group: *group,
                peer: *peer,
                before: Some(chain.as_slice()),
                after: None,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&before),
                    after: Some(&rec),
                }],
                chains: &chain_transitions,
                contacts: &[],
                authorities: &[],
                delete_controls: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: *group }]);
        // Best effort: keys are already rotated whether or not this lands.
        self.queue_group_control(
            peer,
            &GroupControlPayload::Remove { group: *group },
            now,
            rng,
        )?;
        Ok(())
    }

    /// Leave a group: tell every member (best effort — the survivors rotate
    /// on receipt), then drop the group locally. History stays; it is this
    /// device's data.
    pub fn group_leave(
        &mut self,
        group: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.account.ed;
        let authority = self.store.get_group_authority(group)?;
        if authority.is_some()
            && self.group_authority(group)?.my_role == Some(kult_protocol::GroupRole::Owner)
        {
            return Err(NodeError::LastGroupOwner);
        }
        let chain_rows = self.store.group_chains(group)?;
        let chain_transitions = chain_rows
            .iter()
            .map(|(peer, chain)| GroupChainStateTransition {
                group: *group,
                peer: *peer,
                before: Some(chain.as_slice()),
                after: None,
            })
            .collect::<Vec<_>>();
        let authority_transitions = authority
            .as_ref()
            .map(|authority| GroupAuthorityStateTransition {
                before: Some(authority),
                after: None,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&rec),
                    after: None,
                }],
                chains: &chain_transitions,
                contacts: &[],
                authorities: &authority_transitions,
                delete_controls: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: *group }]);
        for member in &rec.members {
            if member.peer == me {
                continue;
            }
            self.queue_group_control(
                &member.peer,
                &GroupControlPayload::Leave { group: *group },
                now,
                rng,
            )?;
        }
        Ok(())
    }

    // ---- the tick's group upkeep --------------------------------------------

    fn retire_legacy_group_delivery(
        &mut self,
        before: &GroupMessageRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let queued = self
            .store
            .queue_all()?
            .into_iter()
            .filter(|(_, item)| item.group_msg_id == Some(before.id))
            .map(|(sequence, item)| QueueDelete {
                sequence,
                content_id: item.envelope.content_id(),
            })
            .collect::<Vec<_>>();
        for page in queued.chunks(MAX_MAINTENANCE_TRANSITIONS) {
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
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }

        let delivery_pairs = self
            .store
            .message_device_deliveries(&before.id)?
            .into_iter()
            .filter_map(|prior| {
                let mut after = prior.clone();
                after.wire_id = None;
                if matches!(after.state, DeliveryState::Queued | DeliveryState::Sent) {
                    after.state = DeliveryState::Failed;
                }
                (after != prior).then_some((prior, after))
            })
            .collect::<Vec<_>>();
        for page in delivery_pairs.chunks(MAX_MAINTENANCE_TRANSITIONS) {
            let transitions = page
                .iter()
                .map(|(prior, after)| DeliveryTransition {
                    before: prior,
                    after,
                })
                .collect::<Vec<_>>();
            let receipt = self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &[],
                    delete_pending: &[],
                    delete_queue: &[],
                    update_queue: &[],
                    delete_replay: &[],
                    messages: &[],
                    deliveries: &transitions,
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
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }

        let mut after = before.clone();
        after.wire_body = None;
        for delivery in &mut after.deliveries {
            delivery.wire_id = None;
            if matches!(delivery.state, DeliveryState::Queued | DeliveryState::Sent) {
                delivery.state = DeliveryState::Failed;
            }
        }
        if &after != before {
            let transition = GroupMessageTransition {
                before,
                after: &after,
            };
            let receipt = self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &[],
                    delete_pending: &[],
                    delete_queue: &[],
                    update_queue: &[],
                    delete_replay: &[],
                    messages: &[],
                    deliveries: &[],
                    group_messages: &[transition],
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
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: true,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }
        Ok(())
    }

    /// Flush due announces (initiating pairwise sessions where a bundle is
    /// stored or the DHT can produce one) and serve late fan-out: members
    /// whose session appeared after a group message was queued get their
    /// copy of the retained ciphertext now.
    pub(crate) async fn tick_groups(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.account.ed;
        let queued = self.store.queue_all()?;
        let queued_ids: HashSet<[u8; 16]> = queued
            .iter()
            .map(|(_, item)| item.envelope.content_id())
            .collect();
        let queued_group_messages: HashSet<[u8; 16]> = queued
            .iter()
            .filter_map(|(_, item)| item.group_msg_id)
            .collect();

        for mut rec in self.store.groups()? {
            if let Some(after) = self.reconcile_group_origin_sender(&rec, rng)? {
                let before = rec;
                let receipt = self.store.commit_plan(
                    CommitPlan::GroupState(GroupStatePlan {
                        groups: &[GroupStateTransition {
                            before: Some(&before),
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
                rec = after;
                self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: rec.id }]);
            }
            let origin_count = match decode_sender_state(&rec.sender_chain)? {
                StoredGroupSenderState::Origin(state) => state.origins.len(),
                StoredGroupSenderState::Legacy(_) => 0,
            };
            if origin_count != 0
                || matches!(
                    decode_sender_state(&rec.sender_chain)?,
                    StoredGroupSenderState::Origin(_)
                )
            {
                for origin_index in 0..origin_count {
                    let sender = decode_sender_state(&rec.sender_chain)?;
                    let StoredGroupSenderState::Origin(state) = sender else {
                        return Err(NodeError::CorruptState);
                    };
                    let entry = state
                        .origins
                        .get(origin_index)
                        .cloned()
                        .ok_or(NodeError::CorruptState)?;
                    let origin_generation = state.origin_generation;
                    if entry.acknowledged {
                        continue;
                    }
                    let never_tried = entry.last_sent == 0;
                    let resend_due = entry.last_sent != 0
                        && now.saturating_sub(entry.last_sent) >= GROUP_ANNOUNCE_RETRY_SECS
                        && entry.wire_id.is_none_or(|wire| !queued_ids.contains(&wire));
                    if !(never_tried || resend_due) {
                        continue;
                    }
                    self.resolve_group_peer_bundle(&entry.recipient_account, now, rng)
                        .await?;
                    let payload = match self.store.get_group_authority(&rec.id)? {
                        Some(authority) => GroupControlPayload::OriginAuthorityAnnounce(
                            GroupOriginAuthorityAnnounce {
                                announce: GroupAuthorityAnnounce {
                                    group: rec.id,
                                    state_id: authority.state_id,
                                    state_payload: authority.state_payload,
                                    secret: rec.secret,
                                    key_id: entry.key_id,
                                    chain_key: entry.chain_key,
                                    iteration: entry.iteration,
                                },
                                origin_generation,
                                recipient_account: entry.recipient_account,
                                recipient_device: entry.recipient_device,
                                origin_key: entry.origin_key,
                            },
                        ),
                        None => GroupControlPayload::OriginAnnounce(GroupOriginAnnounce {
                            announce: GroupAnnounce {
                                group: rec.id,
                                name: rec.name.clone(),
                                creator: rec.creator,
                                members: if rec.creator == me {
                                    rec.members
                                        .iter()
                                        .map(|member| GroupMemberInfo {
                                            peer: member.peer,
                                            identity: member.identity.clone(),
                                        })
                                        .collect()
                                } else {
                                    Vec::new()
                                },
                                secret: rec.secret,
                                generation: rec.generation,
                                key_id: entry.key_id,
                                chain_key: entry.chain_key,
                                iteration: entry.iteration,
                            },
                            origin_generation,
                            recipient_account: entry.recipient_account,
                            recipient_device: entry.recipient_device,
                            origin_key: entry.origin_key,
                        }),
                    };
                    let before = rec.clone();
                    self.queue_group_origin_announce(
                        &entry.recipient_account,
                        &entry.recipient_device,
                        &payload,
                        &before,
                        &mut rec,
                        origin_index,
                        now,
                        rng,
                    )?;
                }
                continue;
            }
            for pending_index in 0..rec.pending.len() {
                let entry = rec.pending[pending_index].clone();
                // Due when never attempted, or when the retry window passed
                // and the last envelope is out of the queue (a queued one is
                // still the transport scheduler's problem, not ours).
                let never_tried = entry.last_sent == 0;
                let resend_due = entry.last_sent != 0
                    && now.saturating_sub(entry.last_sent) >= GROUP_ANNOUNCE_RETRY_SECS
                    && entry.wire_id.is_none_or(|w| !queued_ids.contains(&w));
                if !(never_tried || resend_due) {
                    continue;
                }
                self.resolve_group_peer_bundle(&entry.peer, now, rng)
                    .await?;
                let announce = match self.store.get_group_authority(&rec.id)? {
                    Some(authority) => {
                        GroupControlPayload::AuthorityAnnounce(GroupAuthorityAnnounce {
                            group: rec.id,
                            state_id: authority.state_id,
                            state_payload: authority.state_payload,
                            secret: rec.secret,
                            key_id: entry.key_id,
                            chain_key: entry.chain_key,
                            iteration: entry.iteration,
                        })
                    }
                    None => GroupControlPayload::Announce(GroupAnnounce {
                        group: rec.id,
                        name: rec.name.clone(),
                        creator: rec.creator,
                        // Roster authority is the creator's alone; anyone else
                        // sends it empty (ignored on receipt either way).
                        members: if rec.creator == me {
                            rec.members
                                .iter()
                                .map(|m| GroupMemberInfo {
                                    peer: m.peer,
                                    identity: m.identity.clone(),
                                })
                                .collect()
                        } else {
                            Vec::new()
                        },
                        secret: rec.secret,
                        generation: rec.generation,
                        key_id: entry.key_id,
                        chain_key: entry.chain_key,
                        iteration: entry.iteration,
                    }),
                };
                let before = rec.clone();
                self.queue_group_announce(
                    &entry.peer,
                    &announce,
                    &before,
                    &mut rec,
                    pending_index,
                    now,
                    rng,
                )?;
            }
        }

        // Late fan-out from retained ciphertexts.
        for before_record in self.store.all_group_messages()? {
            if before_record.origin.is_legacy_membership() {
                let live_delivery = before_record.wire_body.is_some()
                    || before_record.deliveries.iter().any(|delivery| {
                        delivery.wire_id.is_some()
                            || matches!(delivery.state, DeliveryState::Queued | DeliveryState::Sent)
                    })
                    || queued_group_messages.contains(&before_record.id);
                if live_delivery {
                    self.retire_legacy_group_delivery(&before_record, rng)?;
                }
                continue;
            }
            let Some(wire) = before_record.wire_body.clone() else {
                continue;
            };
            let mut pending = self.decode_group_pending_fanout(&before_record, &wire)?;
            let mut record = before_record.clone();
            let mut queue = Vec::new();
            let mut delivery_rows = Vec::new();
            let mut delivery_pairs = Vec::new();
            let mut completed_routes = HashSet::new();

            // A revoked device must never regain an old queued capability.
            // The retained value contains only a tag, so dropping the route
            // also completes local erasure without keeping an origin key.
            for delivery in &record.deliveries {
                let active = self
                    .group_account_route_devices(&delivery.peer)?
                    .into_iter()
                    .collect::<HashSet<_>>();
                pending.routes.retain(|route| {
                    route.account != delivery.peer || active.contains(&route.device)
                });
            }

            for d in record.deliveries.iter_mut() {
                if d.wire_id.is_some() {
                    pending.routes.retain(|route| route.account != d.peer);
                    continue;
                }
                if !pending.routes.iter().any(|route| route.account == d.peer) {
                    d.wire_id = self
                        .store
                        .message_device_deliveries(&record.id)?
                        .into_iter()
                        .find(|delivery| delivery.account == d.peer && delivery.wire_id.is_some())
                        .and_then(|delivery| delivery.wire_id);
                    continue;
                }
                let prepared = self.prepare_group_copy(
                    &d.peer,
                    &pending,
                    record.id,
                    QueueClass::Interactive,
                    ephemeral_retention(&record.body),
                    now,
                )?;
                if prepared.all_served {
                    d.wire_id = prepared.first_wire;
                }
                completed_routes.extend(prepared.completed_routes);
                queue.extend(prepared.queue);
                delivery_rows.extend(prepared.deliveries);
                delivery_pairs.extend(prepared.delivery_updates);
            }
            pending
                .routes
                .retain(|route| !completed_routes.contains(&(route.account, route.device)));
            if pending.routes.is_empty() {
                record.wire_body = None;
            } else {
                record.wire_body = Some(pending.encode()?);
            }
            let changed = record != before_record;
            if changed || !queue.is_empty() {
                let delivery_updates = delivery_pairs
                    .iter()
                    .map(|(before, after)| DeliveryTransition { before, after })
                    .collect::<Vec<_>>();
                let receipt = self.store.commit_plan(
                    CommitPlan::GroupSend(GroupSendPlan {
                        group: None,
                        message: None,
                        message_update: Some(GroupMessageTransition {
                            before: &before_record,
                            after: &record,
                        }),
                        deliveries: &delivery_rows,
                        delivery_updates: &delivery_updates,
                        queue: &queue,
                        scheduled: None,
                        ephemeral: None,
                        media_transfers: &[],
                        delete_chains: &[],
                        authority: None,
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                self.accept_commit_receipt(receipt, []);
            }
        }
        Ok(())
    }

    /// A pairwise session with `peer` was (re-)established from an inbound
    /// handshake: if they co-member any group, make sure an announce is
    /// owed to them — their device may have restored and lost every
    /// receiving chain (ADR-0012). Legacy sender-key entries keep their
    /// existing snapshot and resend it on the fresh session. Origin-
    /// authenticated groups rotate the chain and every recipient capability
    /// because those capabilities are bound to the replaced pairwise session.
    pub(crate) fn prepare_groups_on_session_established(
        &mut self,
        peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<(GroupRecord, GroupRecord)>> {
        let me = self.account.ed;
        if peer == &me {
            return Ok(Vec::new());
        }
        let mut transitions = Vec::new();
        for before in self.store.groups()? {
            let mut rec = before.clone();
            if !rec.members.iter().any(|m| &m.peer == peer) {
                continue;
            }
            if matches!(
                decode_sender_state(&rec.sender_chain)?,
                StoredGroupSenderState::Origin(_)
            ) {
                // A new pairwise session invalidates every capability tied
                // to the previous session. Rotate the chain and all
                // per-recipient origin keys together.
                self.rotate_group_origin(&mut rec, rng)?;
                if rec != before {
                    transitions.push((before, rec));
                }
                continue;
            }
            match rec.pending.iter_mut().find(|p| &p.peer == peer) {
                Some(entry) => {
                    entry.wire_id = None;
                    entry.last_sent = 0;
                }
                None => {
                    let sender = decode_sender_state(&rec.sender_chain)?;
                    let chain = sender.chain();
                    let (key_id, chain_key, iteration) = chain.snapshot();
                    rec.pending.push(PendingAnnounce {
                        peer: *peer,
                        key_id,
                        chain_key: *chain_key,
                        iteration,
                        wire_id: None,
                        last_sent: 0,
                    });
                }
            }
            if rec != before {
                transitions.push((before, rec));
            }
        }
        Ok(transitions)
    }

    pub(crate) fn prepare_group_origin_ack(
        &self,
        before: &GroupRecord,
        peer: &[u8; 32],
        peer_device: &[u8; 32],
        acks: &[[u8; 16]],
    ) -> Result<Option<GroupRecord>> {
        let mut sender = decode_sender_state(&before.sender_chain)?;
        let StoredGroupSenderState::Origin(state) = &mut sender else {
            return Ok(None);
        };
        let mut changed = false;
        for origin in &mut state.origins {
            if origin.recipient_account == *peer
                && origin.recipient_device == *peer_device
                && !origin.acknowledged
                && origin
                    .wire_id
                    .is_some_and(|wire| acks.iter().any(|ack| bool::from(ack.ct_eq(&wire))))
            {
                origin.acknowledged = true;
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        let mut after = before.clone();
        after.sender_chain = encode_sender_state(&sender)?;
        Ok(Some(after))
    }

    /// Bind a pre-C2 account-key receiving chain to the certified physical
    /// endpoint that inherited that compatibility session.
    pub(crate) fn groups_retarget_legacy_device_chain(
        &mut self,
        account: &[u8; 32],
        old_device: &[u8; 32],
        new_device: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for group in self.store.groups()? {
            let Some(blob) = self.store.get_group_chain(&group.id, account)? else {
                continue;
            };
            let mut chains = decode_device_group_chains(&blob, *old_device)?;
            let mut changed = false;
            for entry in &mut chains {
                if &entry.device == old_device {
                    entry.device = *new_device;
                    changed = true;
                }
            }
            if changed {
                let encoded = encode_device_group_chains(&mut chains)?;
                let receipt = self.store.commit_plan(
                    CommitPlan::GroupState(GroupStatePlan {
                        groups: &[],
                        chains: &[GroupChainStateTransition {
                            group: group.id,
                            peer: *account,
                            before: Some(blob.as_slice()),
                            after: Some(&encoded),
                        }],
                        contacts: &[],
                        authorities: &[],
                        delete_controls: &[],
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                self.accept_commit_receipt(receipt, []);
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_group_receiver_chain(
        &self,
        group: &[u8; 32],
        sender: AuthenticatedGroupSender,
        material: GroupReceiverChainMaterial,
    ) -> Result<PreparedGroupReceiverChainUpdate> {
        if material
            .origin
            .is_some_and(|origin| origin.key == [0u8; 32] || origin.generation == 0)
        {
            return Err(NodeError::CorruptState);
        }
        let before = self.store.get_group_chain(group, &sender.account)?;
        let mut chains = match before.as_ref() {
            Some(blob) => decode_device_group_chains(blob, sender.account)?,
            None => Vec::new(),
        };
        let local_device = self.device_id();
        let incoming_digest = material.origin.map(|origin| {
            group_origin_announce_digest(
                group,
                &sender.account,
                &sender.device,
                &self.account.ed,
                &local_device,
                origin.generation,
                &material.key_id,
                &material.chain_key,
                material.iteration,
                &origin.key,
            )
        });
        let replace = match chains.iter().find(|entry| entry.device == sender.device) {
            None => true,
            Some(entry) => match (material.origin, incoming_digest) {
                (None, None) => {
                    entry.origin_key.is_none() && entry.chain.key_id() != material.key_id
                }
                (Some(origin), Some(_)) => {
                    entry.origin_generation == 0 || origin.generation > entry.origin_generation
                }
                _ => return Err(NodeError::CorruptState),
            },
        };
        if !replace {
            return Ok((before, None));
        }
        let chain =
            GroupReceiverChain::new(material.key_id, &material.chain_key, material.iteration);
        let (origin_key, recipient_device, origin_generation, origin_announce_digest) =
            match (material.origin, incoming_digest) {
                (Some(origin), Some(digest)) => {
                    (Some(origin.key), local_device, origin.generation, digest)
                }
                (None, None) => (None, [0u8; 32], 0, [0u8; 32]),
                _ => return Err(NodeError::CorruptState),
            };
        if let Some(entry) = chains
            .iter_mut()
            .find(|entry| entry.device == sender.device)
        {
            entry.chain = chain;
            entry.origin_key = origin_key;
            entry.recipient_device = recipient_device;
            entry.origin_generation = origin_generation;
            entry.origin_announce_digest = origin_announce_digest;
        } else {
            chains.push(DeviceGroupReceiverChain {
                device: sender.device,
                chain,
                origin_key,
                recipient_device,
                origin_generation,
                origin_announce_digest,
            });
        }
        Ok((before, Some(encode_device_group_chains(&mut chains)?)))
    }

    // ---- receive path --------------------------------------------------------

    /// Consume a `GroupMessage` envelope. The delivery token names the
    /// pairwise session it rode under (so foreign traffic never reaches the
    /// group trial-decrypt); the sealed header names the chain. Anything
    /// whose group or chain is not known yet stashes — "announce still in
    /// flight" gets the same cure as "handshake still in flight".
    pub(crate) fn consume_group_message(
        &mut self,
        env: &Envelope,
        pending_sequence: Option<i64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Consumed> {
        let Some(peer_device) = self.match_session(&env.token, now) else {
            return Ok(Consumed::Later);
        };
        let origin_wrapper = match GroupOriginEnvelope::decode(&env.body) {
            Ok(wrapper) => Some(wrapper),
            Err(_) if env.body.starts_with(&GROUP_ORIGIN_ENVELOPE_MAGIC) => {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng)
            }
            Err(_) => None,
        };
        let peer = if origin_wrapper.is_some() {
            let Some(account) = self.verified_group_sender_account(&peer_device)? else {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
            };
            account
        } else {
            self.account_for_device(&peer_device)?
        };
        let message = match origin_wrapper.as_ref() {
            Some(wrapper) => wrapper.shared().clone(),
            None => {
                let Ok(message) = GroupMessage::decode(&env.body) else {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                };
                if message.version() == GROUP_MESSAGE_VERSION_ORIGIN {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                }
                message
            }
        };

        for group in self.store.groups()? {
            if !group.members.iter().any(|member| member.peer == peer) {
                continue;
            }
            let mut opened = None;
            for secret in core::iter::once(group.secret).chain(group.prev_secret) {
                let header = GroupHeaderKey::derive(&secret);
                if let Ok(value) = message.open_header_details(&header) {
                    opened = Some(value);
                    break;
                }
            }
            let Some(header) = opened else {
                continue;
            };
            let Some(before_blob) = self.store.get_group_chain(&group.id, &peer)? else {
                return Ok(Consumed::Later);
            };
            let mut chains = decode_device_group_chains(&before_blob, peer)?;
            let Some(receiver) = chains
                .iter_mut()
                .find(|entry| entry.device == peer_device && entry.chain.key_id() == header.key_id)
            else {
                return Ok(Consumed::Later);
            };
            let origin = if let Some(wrapper) = origin_wrapper.as_ref() {
                let Some(content_id) = header.content_id else {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                };
                let Some(origin_key) = receiver.origin_key else {
                    return Ok(Consumed::Later);
                };
                let recipient_device = self.device_id();
                if receiver.recipient_device != recipient_device
                    || wrapper
                        .verify(
                            &origin_key,
                            &GroupOriginContext {
                                group_id: group.id,
                                sender_account: peer,
                                sender_device: peer_device,
                                recipient_account: self.account.ed,
                                recipient_device,
                                sender_chain_key_id: header.key_id,
                                envelope_content_id: content_id,
                                authenticated_retention: env.retention_until,
                            },
                        )
                        .is_err()
                {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                }
                Some((
                    content_id,
                    GroupOriginAuthentication::RecipientV1 {
                        sender_device: peer_device,
                        recipient_device,
                        chain_key_id: header.key_id,
                    },
                ))
            } else {
                None
            };
            let padded = match self.candidate_group_open(
                &mut receiver.chain,
                &group.id,
                &message,
                header.iteration,
                now,
            )? {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng)
                }
            };
            let Ok(body) = unpad(&padded) else {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
            };
            if !valid_group_origin_plaintext(
                &body,
                origin.as_ref().map(|(content_id, _)| *content_id),
                env.retention_until,
            ) {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
            }
            if origin.is_none() {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
            }
            let after_blob = encode_device_group_chains(&mut chains)?;
            let prepared = self.prepare_group_inbound(
                &group,
                body,
                GroupInboundContext {
                    peer,
                    envelope_retention: env.retention_until,
                    origin,
                    now,
                },
                rng,
            )?;

            let receipt_before = self
                .store
                .get_session(&peer_device)?
                .ok_or(NodeError::CorruptState)?;
            let mut receipt_after = receipt_before.clone();
            let receipt_payload = ReceiptPayload {
                acks: vec![env.content_id()],
                nacks: Vec::new(),
            }
            .encode();
            let receipt_queue = self.prepare_control_queue(
                &mut receipt_after,
                peer_device,
                &receipt_payload,
                now,
                rng,
            )?;
            let source_pending = pending_sequence.map(|sequence| PendingDelete {
                sequence,
                content_id: env.content_id(),
            });
            let presentation_changed = !prepared.events.is_empty()
                || !prepared.attachment_updates.is_empty()
                || prepared.ephemeral.is_some();
            let receipt = self.store.commit_plan(
                CommitPlan::GroupReceive(GroupReceivePlan {
                    chain: GroupChainTransition {
                        group: group.id,
                        peer,
                        before: &before_blob,
                        after: &after_blob,
                    },
                    receipt_session: SessionTransition {
                        peer_device,
                        before: Some(&receipt_before),
                        after: &receipt_after,
                    },
                    message: prepared.message.as_ref(),
                    ephemeral: prepared.ephemeral.as_ref(),
                    media_transfers: &prepared.media_transfers,
                    media_objects: &prepared.media_objects,
                    queue: &[receipt_queue],
                    content_id: env.content_id(),
                    received_at: now,
                    source_pending,
                    presentation_changed,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            self.sessions.insert(peer_device, receipt_after);
            self.after_memory_replacement()?;
            self.accept_commit_receipt(receipt, prepared.events);
            for transfer in prepared.attachment_updates {
                self.emit_attachment_update(&transfer)?;
            }
            return Ok(Consumed::DoneAtomic);
        }
        Ok(Consumed::Later)
    }

    fn prepare_group_inbound(
        &self,
        group: &GroupRecord,
        body: Vec<u8>,
        context: GroupInboundContext,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedGroupInbound> {
        let GroupInboundContext {
            peer,
            envelope_retention,
            origin,
            now,
        } = context;
        let empty = || PreparedGroupInbound {
            message: None,
            ephemeral: None,
            media_transfers: Vec::new(),
            media_objects: Vec::new(),
            events: Vec::new(),
            attachment_updates: Vec::new(),
        };
        let decoded = decode_content(&body);
        let origin_content_id = origin.as_ref().map(|(content_id, _)| *content_id);
        let origin_authentication = origin
            .as_ref()
            .map(|(_, authentication)| *authentication)
            .unwrap_or_default();
        let authenticated_retention = match decoded {
            DecodedContent::Ephemeral { ephemeral, .. } => Some(match ephemeral {
                Ephemeral::DisappearingText {
                    retention_until, ..
                }
                | Ephemeral::ViewOnceAttachment {
                    retention_until, ..
                } => retention_until,
            }),
            _ => None,
        };
        if authenticated_retention != envelope_retention {
            return Ok(empty());
        }
        if let DecodedContent::Text { id, .. }
        | DecodedContent::Attachment { id, .. }
        | DecodedContent::Mention { id, .. }
        | DecodedContent::Edit { id, .. }
        | DecodedContent::Ephemeral { id, .. }
        | DecodedContent::Poll { id, .. }
        | DecodedContent::GroupAuthority { id, .. } = decoded
        {
            let conversation = EphemeralConversation::Group(group.id);
            if self
                .store
                .get_ephemeral_record(&conversation, &peer, &id)?
                .is_some()
                || self.store.group_messages(&group.id)?.iter().any(|record| {
                    record.direction == Direction::Inbound
                        && record.sender == peer
                        && matches!(
                            decode_content(&record.body),
                            DecodedContent::Text { id: stored, .. }
                                | DecodedContent::Attachment { id: stored, .. }
                                | DecodedContent::Mention { id: stored, .. }
                                | DecodedContent::Edit { id: stored, .. }
                                | DecodedContent::Ephemeral { id: stored, .. }
                                | DecodedContent::Poll { id: stored, .. }
                                | DecodedContent::GroupAuthority { id: stored, .. }
                                if stored == id
                        )
                })
            {
                return Ok(empty());
            }
        }

        let me = self.account.ed;
        let decoded_is_edit = matches!(decoded, DecodedContent::Edit { .. });
        let mut ephemeral = None;
        let mut media_transfers = Vec::new();
        let mut media_objects = Vec::new();
        let mut attachment_updates = Vec::new();
        let mut mentions_local_peer = false;
        let (id, event_body, content) = match decoded {
            DecodedContent::LegacyText(text) => {
                let mut id = origin_content_id.unwrap_or([0u8; 16]);
                if id == [0u8; 16] {
                    rng.fill_bytes(&mut id);
                }
                (id, text.as_bytes().to_vec(), ContentStatus::LegacyText)
            }
            DecodedContent::Text { id, text } => {
                (id, text.as_bytes().to_vec(), ContentStatus::Text { id })
            }
            DecodedContent::Attachment { id, manifest } => {
                let (transfer, objects) = self.prepare_group_attachment_offer(
                    crate::attachment::GroupAttachmentOffer {
                        group: group.id,
                        author: peer,
                        entitled_peers: group.members.iter().map(|member| member.peer).collect(),
                    },
                    id,
                    &manifest,
                    now,
                    rng,
                )?;
                let transfer_id = transfer.local_id;
                media_transfers.push(transfer);
                media_objects.extend(objects);
                attachment_updates.push(transfer_id);
                (
                    id,
                    Vec::new(),
                    ContentStatus::Attachment {
                        id,
                        transfer: transfer_id,
                    },
                )
            }
            DecodedContent::Mention { id, mention } => {
                let spans = mention.spans().map(MentionSpan::from).collect::<Vec<_>>();
                mentions_local_peer = spans.iter().any(|span| span.target == me);
                (
                    id,
                    mention.text.as_bytes().to_vec(),
                    ContentStatus::Mention { id, spans },
                )
            }
            DecodedContent::Edit { id, edit } if edit.target_author == peer => (
                id,
                Vec::new(),
                ContentStatus::Edit {
                    id,
                    target_author: edit.target_author,
                    target_content_id: edit.target_content_id,
                    revision: edit.revision,
                },
            ),
            DecodedContent::Edit { id, .. } => (id, Vec::new(), ContentStatus::Malformed),
            DecodedContent::Ephemeral {
                id,
                ephemeral:
                    Ephemeral::DisappearingText {
                        expires_at, text, ..
                    },
            } => {
                let state = if now >= expires_at {
                    EphemeralState::Expired
                } else {
                    EphemeralState::Active
                };
                ephemeral = Some(EphemeralRecord {
                    conversation: EphemeralConversation::Group(group.id),
                    author: peer,
                    content_id: id,
                    expires_at,
                    mode: EphemeralMode::DisappearingText,
                    state,
                    transfer_ids: Vec::new(),
                });
                if state == EphemeralState::Expired {
                    return Ok(PreparedGroupInbound {
                        message: None,
                        ephemeral,
                        media_transfers,
                        media_objects,
                        events: vec![Event::EphemeralRemoved {
                            conversation: EphemeralConversation::Group(group.id),
                            author: peer,
                            content_id: id,
                            reason: state,
                        }],
                        attachment_updates,
                    });
                }
                (
                    id,
                    text.as_bytes().to_vec(),
                    ContentStatus::DisappearingText { id, expires_at },
                )
            }
            DecodedContent::Ephemeral {
                id,
                ephemeral:
                    Ephemeral::ViewOnceAttachment {
                        expires_at,
                        manifest,
                        ..
                    },
            } => {
                if now >= expires_at {
                    ephemeral = Some(EphemeralRecord {
                        conversation: EphemeralConversation::Group(group.id),
                        author: peer,
                        content_id: id,
                        expires_at,
                        mode: EphemeralMode::ViewOnceAttachment,
                        state: EphemeralState::Expired,
                        transfer_ids: Vec::new(),
                    });
                    return Ok(PreparedGroupInbound {
                        message: None,
                        ephemeral,
                        media_transfers,
                        media_objects,
                        events: vec![Event::EphemeralRemoved {
                            conversation: EphemeralConversation::Group(group.id),
                            author: peer,
                            content_id: id,
                            reason: EphemeralState::Expired,
                        }],
                        attachment_updates,
                    });
                }
                let (transfer, objects) = self.prepare_group_attachment_offer(
                    crate::attachment::GroupAttachmentOffer {
                        group: group.id,
                        author: peer,
                        entitled_peers: group.members.iter().map(|member| member.peer).collect(),
                    },
                    id,
                    &manifest,
                    now,
                    rng,
                )?;
                let transfer_id = transfer.local_id;
                media_transfers.push(transfer);
                media_objects.extend(objects);
                attachment_updates.push(transfer_id);
                ephemeral = Some(EphemeralRecord {
                    conversation: EphemeralConversation::Group(group.id),
                    author: peer,
                    content_id: id,
                    expires_at,
                    mode: EphemeralMode::ViewOnceAttachment,
                    state: EphemeralState::Active,
                    transfer_ids: vec![transfer_id],
                });
                (
                    id,
                    Vec::new(),
                    ContentStatus::ViewOnceAttachment {
                        id,
                        transfer: transfer_id,
                        expires_at,
                    },
                )
            }
            DecodedContent::Poll {
                id,
                poll: Poll::Create(create),
            } if create.voters().any(|voter| voter == peer) => (
                id,
                Vec::new(),
                ContentStatus::Poll {
                    id,
                    poll_author: peer,
                    poll_id: id,
                },
            ),
            DecodedContent::Poll {
                id,
                poll: Poll::Vote(vote),
            } => (
                id,
                Vec::new(),
                ContentStatus::Poll {
                    id,
                    poll_author: vote.poll_author,
                    poll_id: vote.poll_id,
                },
            ),
            DecodedContent::Poll {
                id,
                poll: Poll::Close(close),
            } if close.poll_author == peer => (
                id,
                Vec::new(),
                ContentStatus::Poll {
                    id,
                    poll_author: close.poll_author,
                    poll_id: close.poll_id,
                },
            ),
            DecodedContent::Poll {
                id,
                poll: Poll::ModeratedClose(close),
            } => (
                id,
                Vec::new(),
                ContentStatus::Poll {
                    id,
                    poll_author: close.poll_author,
                    poll_id: close.poll_id,
                },
            ),
            DecodedContent::Poll { id, .. } => (id, Vec::new(), ContentStatus::Malformed),
            DecodedContent::GroupAuthority { id, payload } => match decode_group_authority(payload)
            {
                DecodedGroupAuthority::State(state)
                    if state.group == group.id
                        && state.signer == peer
                        && crate::authority::verify_authority_state(&state, None).is_ok() =>
                {
                    (
                        id,
                        Vec::new(),
                        ContentStatus::GroupAuthority {
                            id,
                            generation: state.generation,
                            owner: state.owner,
                        },
                    )
                }
                _ => (id, Vec::new(), ContentStatus::Malformed),
            },
            DecodedContent::CallControl { id, .. } => (id, Vec::new(), ContentStatus::Malformed),
            DecodedContent::Unsupported {
                format_version,
                kind,
            } => {
                let mut id = origin_content_id.unwrap_or([0u8; 16]);
                if id == [0u8; 16] {
                    rng.fill_bytes(&mut id);
                }
                (
                    id,
                    Vec::new(),
                    ContentStatus::Unsupported {
                        format_version,
                        kind,
                    },
                )
            }
            DecodedContent::Malformed => {
                let mut id = origin_content_id.unwrap_or([0u8; 16]);
                if id == [0u8; 16] {
                    rng.fill_bytes(&mut id);
                }
                (id, Vec::new(), ContentStatus::Malformed)
            }
        };

        let message = GroupMessageRecord {
            id,
            group: group.id,
            sender: peer,
            direction: Direction::Inbound,
            timestamp: now,
            body,
            deliveries: Vec::new(),
            wire_body: None,
            origin: origin_authentication,
        };
        let mut events = Vec::new();
        match content {
            ContentStatus::Edit {
                target_content_id, ..
            } => events.push(Event::GroupMessageEdited {
                group: group.id,
                sender: peer,
                target_content_id,
            }),
            ContentStatus::Poll {
                poll_author,
                poll_id,
                ..
            } => events.push(Event::PollUpdated {
                group: group.id,
                poll_author,
                poll_id,
            }),
            ContentStatus::GroupAuthority {
                generation, owner, ..
            } => events.push(Event::GroupAuthorityUpdated {
                group: group.id,
                generation,
                owner,
            }),
            ContentStatus::Malformed if decoded_is_edit => {}
            _ => events.push(Event::GroupMessageReceived {
                group: group.id,
                sender: peer,
                id,
                timestamp: now,
                body: event_body,
                content,
            }),
        }
        if mentions_local_peer {
            events.push(Event::MentionReceived { id });
        }
        Ok(PreparedGroupInbound {
            message: Some(message),
            ephemeral,
            media_transfers,
            media_objects,
            events,
            attachment_updates,
        })
    }

    /// Apply a decrypted `GroupControl` payload from `peer`. Returns whether
    /// it was applied — unapplied controls are **not** acknowledged, so the
    /// sender's paced resend arrives after the missing context (e.g. a
    /// co-member's announce racing the creator's invite).
    fn group_invitation_info_for_control(
        &self,
        control: &DeferredControlRecord,
    ) -> Result<Option<GroupInvitationInfo>> {
        if control.kind != kult_store::DeferredControlKind::GroupControl
            || self.store.is_blocked_identity(&control.peer)?
        {
            return Ok(None);
        }
        let Ok(payload) = GroupControlPayload::decode(&control.body) else {
            return Ok(None);
        };
        let me = self.account.ed;
        let (group, name, creator, member_count, generation, recipient_scoped, signed_authority) =
            match &payload {
                GroupControlPayload::Announce(announce) => {
                    if announce.creator != control.peer
                        || announce.group == [0u8; 32]
                        || announce.name.is_empty()
                        || announce.name.len() > kult_protocol::MAX_GROUP_NAME_LEN
                        || !announce.members.iter().any(|member| member.peer == me)
                        || !announce
                            .members
                            .iter()
                            .any(|member| member.peer == control.peer)
                        || !valid_roster(&announce.members)
                    {
                        return Ok(None);
                    }
                    (
                        announce.group,
                        announce.name.clone(),
                        announce.creator,
                        announce.members.len(),
                        announce.generation,
                        false,
                        false,
                    )
                }
                GroupControlPayload::OriginAnnounce(origin) => {
                    let announce = &origin.announce;
                    if origin.recipient_account != me
                        || origin.recipient_device != self.device_id()
                        || self.verified_group_sender_account(&control.peer_device)?
                            != Some(control.peer)
                        || announce.creator != control.peer
                        || announce.group == [0u8; 32]
                        || announce.name.is_empty()
                        || announce.name.len() > kult_protocol::MAX_GROUP_NAME_LEN
                        || !announce.members.iter().any(|member| member.peer == me)
                        || !announce
                            .members
                            .iter()
                            .any(|member| member.peer == control.peer)
                        || !valid_roster(&announce.members)
                    {
                        return Ok(None);
                    }
                    (
                        announce.group,
                        announce.name.clone(),
                        announce.creator,
                        announce.members.len(),
                        announce.generation,
                        true,
                        false,
                    )
                }
                GroupControlPayload::AuthorityAnnounce(announce) => {
                    let Some(summary) =
                        self.authority_invitation_summary(control.peer, announce)?
                    else {
                        return Ok(None);
                    };
                    (
                        announce.group,
                        summary.name,
                        summary.creator,
                        summary.members,
                        summary.generation,
                        false,
                        true,
                    )
                }
                GroupControlPayload::OriginAuthorityAnnounce(origin) => {
                    if origin.recipient_account != me
                        || origin.recipient_device != self.device_id()
                        || self.verified_group_sender_account(&control.peer_device)?
                            != Some(control.peer)
                    {
                        return Ok(None);
                    }
                    let Some(summary) =
                        self.authority_invitation_summary(control.peer, &origin.announce)?
                    else {
                        return Ok(None);
                    };
                    (
                        origin.announce.group,
                        summary.name,
                        summary.creator,
                        summary.members,
                        summary.generation,
                        true,
                        true,
                    )
                }
                _ => return Ok(None),
            };
        if self.store.get_group(&group)?.is_some() {
            return Ok(None);
        }
        Ok(Some(GroupInvitationInfo {
            id: control.content_id,
            group,
            inviter: control.peer,
            inviter_device: control.peer_device,
            name,
            creator,
            member_count: u32::try_from(member_count).map_err(|_| NodeError::CorruptState)?,
            generation,
            recipient_scoped,
            signed_authority,
            arrived_at: control.received_at,
            expires_at: control
                .received_at
                .saturating_add(MAX_GROUP_INVITATION_LIFETIME_SECS),
        }))
    }

    fn unknown_group_control_group(
        &self,
        control: &DeferredControlRecord,
    ) -> Result<Option<[u8; 32]>> {
        if control.kind != kult_store::DeferredControlKind::GroupControl {
            return Ok(None);
        }
        let Ok(payload) = GroupControlPayload::decode(&control.body) else {
            return Ok(None);
        };
        let group = match &payload {
            GroupControlPayload::Announce(announce) => announce.group,
            GroupControlPayload::AuthorityAnnounce(announce) => announce.group,
            GroupControlPayload::OriginAnnounce(origin) => origin.announce.group,
            GroupControlPayload::OriginAuthorityAnnounce(origin) => origin.announce.group,
            _ => return Ok(None),
        };
        Ok(self.store.get_group(&group)?.is_none().then_some(group))
    }

    /// List authenticated proposals that have not entered normal group state.
    pub fn group_invitations(&self) -> Result<Vec<GroupInvitationInfo>> {
        let mut groups = HashSet::new();
        let mut invitations = Vec::new();
        for control in self
            .store
            .deferred_controls(kult_store::MAX_DEFERRED_CONTROLS)?
        {
            let Some(info) = self.group_invitation_info_for_control(&control)? else {
                continue;
            };
            if groups.insert(info.group) {
                invitations.push(info);
            }
            if invitations.len() == MAX_GROUP_INVITATION_REQUESTS {
                break;
            }
        }
        invitations.sort_by_key(|info| (info.arrived_at, info.id));
        Ok(invitations)
    }

    pub(crate) fn admit_group_control(
        &self,
        control: &DeferredControlRecord,
    ) -> Result<(bool, Option<Event>)> {
        if self.store.is_blocked_identity(&control.peer)? {
            return Ok((false, None));
        }
        let Some(group) = self.unknown_group_control_group(control)? else {
            return Ok((true, None));
        };
        let info = self.group_invitation_info_for_control(control)?;
        let mut count = 0usize;
        let mut bytes = 0usize;
        let mut duplicate_invitation = false;
        for existing in self
            .store
            .deferred_controls(kult_store::MAX_DEFERRED_CONTROLS)?
        {
            if self.unknown_group_control_group(&existing)?.is_none() {
                continue;
            }
            count = count.checked_add(1).ok_or(NodeError::CorruptState)?;
            bytes = bytes
                .checked_add(existing.body.len())
                .ok_or(NodeError::CorruptState)?;
            if info.is_some()
                && self
                    .group_invitation_info_for_control(&existing)?
                    .is_some_and(|candidate| candidate.group == group)
            {
                duplicate_invitation = true;
            }
        }
        if duplicate_invitation
            || count >= MAX_GROUP_INVITATION_REQUESTS
            || bytes
                .checked_add(control.body.len())
                .is_none_or(|total| total > MAX_GROUP_INVITATION_BYTES)
        {
            return Ok((false, None));
        }
        Ok((
            true,
            info.map(|info| Event::GroupInvitationReceived {
                invitation: info.id,
                group: info.group,
                inviter: info.inviter,
            }),
        ))
    }

    /// Explicitly join one authenticated, unexpired invitation.
    pub fn accept_group_invitation(
        &mut self,
        invitation: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let control = self
            .store
            .get_deferred_control(invitation)?
            .ok_or(NodeError::UnknownGroupInvitation)?;
        let info = self
            .group_invitation_info_for_control(&control)?
            .ok_or(NodeError::UnknownGroupInvitation)?;
        if info.expires_at <= now {
            return Err(NodeError::UnknownGroupInvitation);
        }
        let mut established = false;
        let (applied, deleted_atomically) =
            self.apply_group_control(&control, now, rng, &mut established, true)?;
        if !applied || !deleted_atomically {
            return Err(NodeError::UnknownGroupInvitation);
        }
        if info.recipient_scoped {
            let acknowledgement = ReceiptPayload {
                acks: vec![control.content_id],
                nacks: Vec::new(),
            }
            .encode();
            // Membership is already committed. If this best-effort
            // sender-chain acknowledgement cannot be queued, the sender's
            // paced retry remains safe and will be acknowledged after the
            // now-existing group consumes it normally.
            let _ =
                self.commit_pairwise_control_send(&control.peer_device, &acknowledgement, now, rng);
        }
        self.events.push_back(Event::GroupInvitationAccepted {
            invitation: *invitation,
            group: info.group,
        });
        Ok(info.group)
    }

    /// Delete one invitation without creating group, contact, or history state.
    pub fn delete_group_invitation(
        &mut self,
        invitation: &[u8; 16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let control = self
            .store
            .get_deferred_control(invitation)?
            .ok_or(NodeError::UnknownGroupInvitation)?;
        self.group_invitation_info_for_control(&control)?
            .ok_or(NodeError::UnknownGroupInvitation)?;
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
                ephemeral: &[],
                delete_messages: &[],
                delete_group_messages: &[],
                delete_media: &[],
                delete_scheduled: &[],
                delete_sessions: &[],
                delete_capabilities: &[],
                clear_reset_markers: &[],
                delete_controls: &[control],
                wake: &[],
                acknowledge_presentation: None,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(
            receipt,
            [Event::GroupInvitationDeleted {
                invitation: *invitation,
            }],
        );
        Ok(())
    }

    pub(crate) fn sweep_group_invitations(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut expired = Vec::new();
        let mut events = Vec::new();
        for control in self
            .store
            .deferred_controls(kult_store::MAX_DEFERRED_CONTROLS)?
        {
            if self.unknown_group_control_group(&control)?.is_none()
                || control
                    .received_at
                    .saturating_add(MAX_GROUP_INVITATION_LIFETIME_SECS)
                    > now
            {
                continue;
            }
            if let Some(info) = self.group_invitation_info_for_control(&control)? {
                events.push(Event::GroupInvitationExpired {
                    invitation: info.id,
                });
            }
            expired.push(control);
            if expired.len() == MAX_GROUP_INVITATION_EXPIRIES_PER_TICK {
                break;
            }
        }
        if expired.is_empty() {
            return Ok(());
        }
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
                ephemeral: &[],
                delete_messages: &[],
                delete_group_messages: &[],
                delete_media: &[],
                delete_scheduled: &[],
                delete_sessions: &[],
                delete_capabilities: &[],
                clear_reset_markers: &[],
                delete_controls: &expired,
                wake: &[],
                acknowledge_presentation: None,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, events);
        Ok(())
    }

    pub(crate) fn apply_group_control(
        &mut self,
        control: &DeferredControlRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
        accept_invitation: bool,
    ) -> Result<(bool, bool)> {
        let Ok(payload) = GroupControlPayload::decode(&control.body) else {
            return Ok((true, false)); // malformed is terminal
        };
        let peer = control.peer;
        if self.store.is_blocked_identity(&peer)? {
            return Ok((true, false));
        }
        let unknown_group = self.unknown_group_control_group(control)?;
        if unknown_group.is_some()
            && control
                .received_at
                .saturating_add(MAX_GROUP_INVITATION_LIFETIME_SECS)
                <= now
        {
            return Ok((true, false));
        }
        if self.group_invitation_info_for_control(control)?.is_some() && !accept_invitation {
            return Ok((false, false));
        }
        let sender = AuthenticatedGroupSender {
            account: peer,
            device: control.peer_device,
        };
        match &payload {
            GroupControlPayload::Announce(a) => self.apply_group_announce(
                sender,
                a,
                GroupControlAnnounceContext {
                    origin: None,
                    control,
                    accept_invitation,
                },
                rng,
                established,
            ),
            GroupControlPayload::Leave { group } => {
                self.apply_group_leave(peer, group, control, rng)
            }
            GroupControlPayload::Remove { group } => {
                self.apply_group_remove_notice(peer, group, control, rng)
            }
            GroupControlPayload::AuthorityAnnounce(announce) => self.apply_authority_announce(
                sender,
                announce,
                GroupControlAnnounceContext {
                    origin: None,
                    control,
                    accept_invitation,
                },
                rng,
                established,
            ),
            GroupControlPayload::AdminRequest(request) => {
                self.apply_group_admin_request(peer, request, control, now, rng)
            }
            GroupControlPayload::AdminResult(result) => {
                self.apply_group_admin_result(peer, result, control, rng)
            }
            GroupControlPayload::AuthorityRemove {
                group,
                state_id,
                state_payload,
            } => self.apply_authority_remove(peer, group, state_id, state_payload, control, rng),
            GroupControlPayload::OriginAnnounce(origin) => {
                if origin.recipient_account != self.account.ed
                    || origin.recipient_device != self.device_id()
                    || self.verified_group_sender_account(&control.peer_device)? != Some(peer)
                {
                    return Ok((true, false));
                }
                self.apply_group_announce(
                    sender,
                    &origin.announce,
                    GroupControlAnnounceContext {
                        origin: Some(GroupOriginMaterial {
                            key: origin.origin_key,
                            generation: origin.origin_generation,
                        }),
                        control,
                        accept_invitation,
                    },
                    rng,
                    established,
                )
            }
            GroupControlPayload::OriginAuthorityAnnounce(origin) => {
                if origin.recipient_account != self.account.ed
                    || origin.recipient_device != self.device_id()
                    || self.verified_group_sender_account(&control.peer_device)? != Some(peer)
                {
                    return Ok((true, false));
                }
                self.apply_authority_announce(
                    sender,
                    &origin.announce,
                    GroupControlAnnounceContext {
                        origin: Some(GroupOriginMaterial {
                            key: origin.origin_key,
                            generation: origin.origin_generation,
                        }),
                        control,
                        accept_invitation,
                    },
                    rng,
                    established,
                )
            }
        }
    }

    fn apply_group_announce(
        &mut self,
        sender: AuthenticatedGroupSender,
        a: &GroupAnnounce,
        context: GroupControlAnnounceContext<'_>,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<(bool, bool)> {
        let GroupControlAnnounceContext {
            origin,
            control,
            accept_invitation,
        } = context;
        let peer = sender.account;
        let me = self.account.ed;
        let before_group = self.store.get_group(&a.group)?;
        let mut group_changed = false;
        let mut contact_records = Vec::new();
        let mut rec = match before_group.as_ref() {
            None => {
                // An invite: only the claimed creator's announce creates
                // the group, and it must list both of us.
                if a.creator != peer
                    || !a.members.iter().any(|m| m.peer == me)
                    || !a.members.iter().any(|m| m.peer == peer)
                    || !valid_roster(&a.members)
                {
                    return Ok((false, false));
                }
                if !accept_invitation {
                    return Ok((false, false));
                }
                contact_records = self.prepare_roster_stubs(&a.members)?;
                let chain = GroupSenderChain::generate(rng);
                let members: Vec<GroupMember> = a
                    .members
                    .iter()
                    .map(|m| GroupMember {
                        peer: m.peer,
                        identity: m.identity.clone(),
                    })
                    .collect();
                let pending = pending_for(&chain, members.iter().map(|m| m.peer), &me);
                let rec = GroupRecord {
                    id: a.group,
                    name: a.name.clone(),
                    creator: a.creator,
                    members,
                    secret: a.secret,
                    prev_secret: None,
                    generation: a.generation,
                    sender_chain: encode_chain(&chain)?,
                    sent_since_rotation: 0,
                    pending,
                };
                group_changed = true;
                rec
            }
            Some(stored) => {
                let mut rec = stored.clone();
                if peer == rec.creator && a.generation > rec.generation {
                    if !a.members.iter().any(|m| m.peer == me) {
                        // The creator's newer roster omits us: removed.
                        self.commit_group_removal(&rec, control, rng)?;
                        return Ok((true, true));
                    }
                    if !valid_roster(&a.members) {
                        return Ok((true, false));
                    }
                    contact_records = self.prepare_roster_stubs(&a.members)?;
                    rec.members = a
                        .members
                        .iter()
                        .map(|m| GroupMember {
                            peer: m.peer,
                            identity: m.identity.clone(),
                        })
                        .collect();
                    rec.name = a.name.clone();
                    rec.generation = a.generation;
                    if rec.secret != a.secret {
                        rec.prev_secret = Some(rec.secret);
                        rec.secret = a.secret;
                    }
                    // Any roster/generation change rotates sender and origin
                    // capabilities; no prior recipient key survives.
                    self.rotate_group(&mut rec, rng)?;
                    group_changed = true;
                }
                rec
            }
        };

        // The sender-key half: honored from any current member.
        if !rec.members.iter().any(|m| m.peer == peer) {
            return Ok((false, false));
        }
        let (before_chain, after_chain) = self.prepare_group_receiver_chain(
            &rec.id,
            sender,
            GroupReceiverChainMaterial {
                key_id: a.key_id,
                chain_key: a.chain_key,
                iteration: a.iteration,
                origin,
            },
        )?;

        if origin.is_some()
            && matches!(
                decode_sender_state(&rec.sender_chain)?,
                StoredGroupSenderState::Legacy(_)
            )
            && self.can_initialize_group_origins(&rec.members)?
        {
            self.rotate_group_origin(&mut rec, rng)?;
            group_changed = true;
        }

        let group_transitions = (before_group.as_ref() != Some(&rec))
            .then_some(GroupStateTransition {
                before: before_group.as_ref(),
                after: Some(&rec),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let removed_peers = before_group
            .as_ref()
            .map(|before| {
                let retained = rec
                    .members
                    .iter()
                    .map(|member| member.peer)
                    .collect::<HashSet<_>>();
                before
                    .members
                    .iter()
                    .filter(|member| !retained.contains(&member.peer))
                    .map(|member| member.peer)
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let removed_chain_rows = self
            .store
            .group_chains(&rec.id)?
            .into_iter()
            .filter(|(account, _)| removed_peers.contains(account))
            .collect::<Vec<_>>();
        let mut chain_transitions = removed_chain_rows
            .iter()
            .map(|(account, chain)| GroupChainStateTransition {
                group: rec.id,
                peer: *account,
                before: Some(chain.as_slice()),
                after: None,
            })
            .collect::<Vec<_>>();
        if let Some(after_chain) = after_chain.as_ref() {
            chain_transitions.push(GroupChainStateTransition {
                group: rec.id,
                peer,
                before: before_chain.as_ref().map(|chain| chain.as_slice()),
                after: Some(after_chain),
            });
        }
        let contact_transitions = contact_records
            .iter()
            .map(|contact| ContactTransition {
                before: None,
                after: contact,
            })
            .collect::<Vec<_>>();
        let mut events = contact_records
            .iter()
            .map(|contact| Event::ContactAdded { peer: contact.peer })
            .collect::<Vec<_>>();
        if group_changed {
            events.push(Event::GroupUpdated { group: a.group });
        }
        if origin.is_some()
            && group_transitions.is_empty()
            && chain_transitions.is_empty()
            && contact_transitions.is_empty()
        {
            // Exact duplicates are acknowledged below from persisted state;
            // stale or conflicting generations are terminally discarded.
            // Neither case needs an empty durable state transaction.
            return Ok((true, false));
        }
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &group_transitions,
                chains: &chain_transitions,
                contacts: &contact_transitions,
                authorities: &[],
                delete_controls: if origin.is_some() && !accept_invitation {
                    &[]
                } else {
                    core::slice::from_ref(control)
                },
                presentation_changed: !events.is_empty(),
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, events);
        if after_chain.is_some() {
            // Stashed group messages on this chain may decrypt now.
            *established = true;
        }
        Ok((true, origin.is_none() || accept_invitation))
    }

    pub(crate) fn accepted_group_origin_control(
        &self,
        control: &DeferredControlRecord,
    ) -> Result<bool> {
        let Ok(payload) = GroupControlPayload::decode(&control.body) else {
            return Ok(false);
        };
        let (
            group,
            key_id,
            chain_key,
            iteration,
            origin_generation,
            recipient_account,
            recipient_device,
            origin_key,
        ) = match &payload {
            GroupControlPayload::OriginAnnounce(origin) => (
                origin.announce.group,
                origin.announce.key_id,
                origin.announce.chain_key,
                origin.announce.iteration,
                origin.origin_generation,
                origin.recipient_account,
                origin.recipient_device,
                origin.origin_key,
            ),
            GroupControlPayload::OriginAuthorityAnnounce(origin) => (
                origin.announce.group,
                origin.announce.key_id,
                origin.announce.chain_key,
                origin.announce.iteration,
                origin.origin_generation,
                origin.recipient_account,
                origin.recipient_device,
                origin.origin_key,
            ),
            _ => return Ok(false),
        };
        if recipient_account != self.account.ed
            || recipient_device != self.device_id()
            || control.peer_device == [0u8; 32]
        {
            return Ok(false);
        }
        let Some(blob) = self.store.get_group_chain(&group, &control.peer)? else {
            return Ok(false);
        };
        let digest = group_origin_announce_digest(
            &group,
            &control.peer,
            &control.peer_device,
            &recipient_account,
            &recipient_device,
            origin_generation,
            &key_id,
            &chain_key,
            iteration,
            &origin_key,
        );
        Ok(decode_device_group_chains(&blob, control.peer)?
            .iter()
            .any(|entry| {
                entry.device == control.peer_device
                    && entry.chain.key_id() == key_id
                    && entry.recipient_device == recipient_device
                    && entry.origin_key == Some(origin_key)
                    && entry.origin_generation == origin_generation
                    && bool::from(entry.origin_announce_digest.ct_eq(&digest))
            }))
    }

    fn apply_group_leave(
        &mut self,
        peer: [u8; 32],
        group: &[u8; 32],
        control: &DeferredControlRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(bool, bool)> {
        let Some(before) = self.store.get_group(group)? else {
            return Ok((true, false)); // unknown group: terminal no-op
        };
        if !before.members.iter().any(|m| m.peer == peer) {
            return Ok((true, false));
        }
        let mut rec = before.clone();
        rec.members.retain(|m| m.peer != peer);
        let before_chain = self.store.get_group_chain(group, &peer)?;
        let me = self.account.ed;
        if rec.creator == me {
            // Authority: re-key the shrunk roster so the leaver cannot even
            // header-decrypt what follows.
            rec.generation += 1;
            rec.prev_secret = Some(rec.secret);
            rng.fill_bytes(&mut rec.secret);
        }
        // Every remaining member rotates on membership shrink (spec §6).
        self.rotate_group(&mut rec, rng)?;
        let chain_transitions = before_chain
            .as_ref()
            .map(|chain| GroupChainStateTransition {
                group: *group,
                peer,
                before: Some(chain.as_slice()),
                after: None,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&before),
                    after: Some(&rec),
                }],
                chains: &chain_transitions,
                contacts: &[],
                authorities: &[],
                delete_controls: core::slice::from_ref(control),
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: *group }]);
        Ok((true, true))
    }

    fn apply_group_remove_notice(
        &mut self,
        peer: [u8; 32],
        group: &[u8; 32],
        control: &DeferredControlRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(bool, bool)> {
        let Some(rec) = self.store.get_group(group)? else {
            return Ok((true, false));
        };
        if rec.creator != peer {
            return Ok((true, false)); // only the creator removes
        }
        self.commit_group_removal(&rec, control, rng)?;
        Ok((true, true))
    }

    // ---- receipts and delivery ladder ----------------------------------------

    /// A member's envelope copy was handed to a link: `Queued` → `Sent`.
    pub(crate) fn prepare_group_mark_sent(
        &self,
        peer: &[u8; 32],
        peer_device: &[u8; 32],
        group_msg_id: &[u8; 16],
    ) -> Result<PreparedDeliveryUpdate> {
        let mut deliveries = Vec::new();
        for delivery in self.store.message_device_deliveries(group_msg_id)? {
            if delivery.account == *peer
                && delivery.device == *peer_device
                && delivery.state == DeliveryState::Queued
            {
                let mut after = delivery.clone();
                after.state = DeliveryState::Sent;
                deliveries.push((delivery, after));
            }
        }
        let mut group_messages = Vec::new();
        let mut events = Vec::new();
        for record in self.store.all_group_messages()? {
            if &record.id != group_msg_id {
                continue;
            }
            let mut after = record.clone();
            for d in after.deliveries.iter_mut() {
                if &d.peer == peer && d.state == DeliveryState::Queued {
                    d.state = DeliveryState::Sent;
                    events.push(Event::GroupDeliveryUpdated {
                        id: *group_msg_id,
                        peer: *peer,
                        state: DeliveryState::Sent,
                    });
                    group_messages.push((record, after));
                    break;
                }
            }
        }
        Ok(PreparedDeliveryUpdate {
            messages: Vec::new(),
            deliveries,
            group_messages,
            events,
        })
    }

    // ---- internals -------------------------------------------------------

    fn candidate_group_seal(
        &self,
        chain: &mut GroupSenderChain,
        header: &GroupHeaderKey,
        group: &[u8; 32],
        content_id: Option<[u8; 16]>,
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<GroupMessage> {
        let step = self.begin_crypto_step()?;
        let message = match content_id {
            Some(content_id) => chain.seal_origin(header, group, content_id, plaintext, rng),
            None => chain.seal(header, group, plaintext, rng),
        };
        self.finish_crypto_step(step)?;
        Ok(message)
    }

    fn candidate_group_open(
        &self,
        chain: &mut GroupReceiverChain,
        group: &[u8; 32],
        message: &GroupMessage,
        iteration: u32,
        now: u64,
    ) -> Result<std::result::Result<Vec<u8>, kult_crypto::CryptoError>> {
        let step = self.begin_crypto_step()?;
        let plaintext = chain.open(group, message, iteration, now);
        self.finish_crypto_step(step)?;
        Ok(plaintext)
    }

    /// Fresh sending chain, everything reset: announces owed to the whole
    /// roster with the new snapshot.
    pub(crate) fn rotate_group(
        &mut self,
        rec: &mut GroupRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let origin = matches!(
            decode_sender_state(&rec.sender_chain)?,
            StoredGroupSenderState::Origin(_)
        );
        if origin {
            return self.rotate_group_origin(rec, rng);
        }
        let me = self.account.ed;
        let chain = GroupSenderChain::generate(rng);
        rec.pending = pending_for(&chain, rec.members.iter().map(|m| m.peer), &me);
        rec.sender_chain = encode_chain(&chain)?;
        rec.sent_since_rotation = 0;
        Ok(())
    }

    pub(crate) fn rotate_group_origin(
        &mut self,
        rec: &mut GroupRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let origin_generation = match decode_sender_state(&rec.sender_chain)? {
            StoredGroupSenderState::Legacy(_) => 1,
            StoredGroupSenderState::Origin(state) => state
                .origin_generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?,
        };
        let chain = GroupSenderChain::generate(rng);
        let state = self.new_origin_sender_state(&rec.members, chain, origin_generation, rng)?;
        rec.pending.clear();
        rec.sender_chain = encode_sender_state(&StoredGroupSenderState::Origin(state))?;
        rec.sent_since_rotation = 0;
        Ok(())
    }

    pub(crate) fn prepare_roster_stubs(
        &self,
        members: &[GroupMemberInfo],
    ) -> Result<Vec<ContactRecord>> {
        let me = self.account.ed;
        let mut contacts = Vec::new();
        for member in members {
            if member.peer == me
                || member.identity.is_empty()
                || self.store.get_contact(&member.peer)?.is_some()
            {
                continue;
            }
            let identity: IdentityPublic =
                postcard::from_bytes(&member.identity).map_err(|_| NodeError::CorruptState)?;
            if identity.ed != member.peer {
                return Err(NodeError::CorruptState);
            }
            contacts.push(ContactRecord {
                peer: member.peer,
                identity: member.identity.clone(),
                name: String::new(),
                bundle: Vec::new(),
                hints: Vec::new(),
                verified: false,
            });
        }
        Ok(contacts)
    }

    pub(crate) fn commit_group_removal(
        &mut self,
        before: &GroupRecord,
        control: &DeferredControlRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let chain_rows = self.store.group_chains(&before.id)?;
        let chain_transitions = chain_rows
            .iter()
            .map(|(peer, chain)| GroupChainStateTransition {
                group: before.id,
                peer: *peer,
                before: Some(chain.as_slice()),
                after: None,
            })
            .collect::<Vec<_>>();
        let authority = self.store.get_group_authority(&before.id)?;
        let authority_transitions = authority
            .as_ref()
            .map(|authority| GroupAuthorityStateTransition {
                before: Some(authority),
                after: None,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(before),
                    after: None,
                }],
                chains: &chain_transitions,
                contacts: &[],
                authorities: &authority_transitions,
                delete_controls: core::slice::from_ref(control),
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, [Event::GroupUpdated { group: before.id }]);
        Ok(())
    }

    fn group_account_route_devices(&self, peer: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let mut routes: Vec<[u8; 32]> = self
            .store
            .contact_devices_for(peer)?
            .into_iter()
            .map(|endpoint| endpoint.device)
            .collect();
        if routes.is_empty() {
            routes.push(*peer);
        }
        routes.sort_unstable();
        routes.dedup();
        if routes.len() > kult_store::MAX_PAIRWISE_COMMIT_DEVICES {
            return Err(NodeError::CorruptState);
        }
        Ok(routes)
    }

    fn prepare_group_pending_fanout(
        &self,
        group: &[u8; 32],
        wire: &[u8],
        sender: &StoredGroupSenderState,
        deliveries: &[GroupDelivery],
        group_msg_id: [u8; 16],
        retention_until: Option<u64>,
    ) -> Result<GroupPendingFanout> {
        let shared = GroupMessage::decode(wire).map_err(NodeError::from)?;
        let recipients = deliveries
            .iter()
            .map(|delivery| delivery.peer)
            .collect::<HashSet<_>>();
        if recipients.len() != deliveries.len() {
            return Err(NodeError::CorruptState);
        }
        let mut routes = Vec::new();
        match sender {
            StoredGroupSenderState::Legacy(_) => {
                if shared.version() == GROUP_MESSAGE_VERSION_ORIGIN {
                    return Err(NodeError::CorruptState);
                }
                for account in recipients {
                    routes.extend(self.group_account_route_devices(&account)?.into_iter().map(
                        |device| GroupPendingFanoutRoute {
                            account,
                            device,
                            origin_tag: None,
                        },
                    ));
                }
            }
            StoredGroupSenderState::Origin(state) => {
                if shared.version() != GROUP_MESSAGE_VERSION_ORIGIN {
                    return Err(NodeError::CorruptState);
                }
                for origin in &state.origins {
                    if !recipients.contains(&origin.recipient_account)
                        || origin.key_id != state.chain.key_id()
                    {
                        return Err(NodeError::CorruptState);
                    }
                    let wrapper = GroupOriginEnvelope::seal(
                        shared.clone(),
                        &origin.origin_key,
                        &GroupOriginContext {
                            group_id: *group,
                            sender_account: self.account.ed,
                            sender_device: self.device_id(),
                            recipient_account: origin.recipient_account,
                            recipient_device: origin.recipient_device,
                            sender_chain_key_id: origin.key_id,
                            envelope_content_id: group_msg_id,
                            authenticated_retention: retention_until,
                        },
                    )?;
                    routes.push(GroupPendingFanoutRoute {
                        account: origin.recipient_account,
                        device: origin.recipient_device,
                        origin_tag: Some(wrapper.tag()),
                    });
                }
                if recipients
                    .iter()
                    .any(|account| !routes.iter().any(|route| &route.account == account))
                {
                    return Err(NodeError::GroupSecurityUpgradeRequired);
                }
            }
        }
        GroupPendingFanout::new(wire.to_vec(), routes).map_err(NodeError::from)
    }

    fn decode_group_pending_fanout(
        &self,
        record: &GroupMessageRecord,
        encoded: &[u8],
    ) -> Result<GroupPendingFanout> {
        if encoded.starts_with(GROUP_PENDING_FANOUT_MAGIC) {
            let pending = GroupPendingFanout::decode(encoded)?;
            let tagged = pending.routes[0].origin_tag.is_some();
            if tagged != record.origin.is_recipient_authenticated() {
                return Err(NodeError::CorruptState);
            }
            return Ok(pending);
        }
        if record.origin.is_recipient_authenticated() {
            return Err(NodeError::CorruptState);
        }
        let shared = GroupMessage::decode(encoded).map_err(NodeError::from)?;
        if shared.version() == GROUP_MESSAGE_VERSION_ORIGIN {
            return Err(NodeError::CorruptState);
        }
        let mut routes = Vec::new();
        for delivery in &record.deliveries {
            routes.extend(
                self.group_account_route_devices(&delivery.peer)?
                    .into_iter()
                    .map(|device| GroupPendingFanoutRoute {
                        account: delivery.peer,
                        device,
                        origin_tag: None,
                    }),
            );
        }
        GroupPendingFanout::new(encoded.to_vec(), routes).map_err(NodeError::from)
    }

    /// One exact recipient-device copy of a shared group ciphertext, if its
    /// pairwise session exists. Pending tags are fixed when the ciphertext is
    /// created, so later chain/session rotation cannot change its authority.
    #[allow(clippy::too_many_arguments)] // exact fan-out identity, timing, and retention inputs
    fn prepare_group_copy(
        &self,
        peer: &[u8; 32],
        pending: &GroupPendingFanout,
        group_msg_id: [u8; 16],
        class: QueueClass,
        retention_until: Option<u64>,
        now: u64,
    ) -> Result<PreparedGroupCopy> {
        let existing = self.store.message_device_deliveries(&group_msg_id)?;
        let shared = GroupMessage::decode(&pending.shared_ciphertext).map_err(NodeError::from)?;
        let routes = pending
            .routes
            .iter()
            .filter(|route| route.account == *peer)
            .collect::<Vec<_>>();
        if routes.is_empty() {
            return Err(NodeError::CorruptState);
        }
        let mut prepared = PreparedGroupCopy {
            all_served: true,
            ..PreparedGroupCopy::default()
        };
        for route in routes {
            let existing_delivery = existing
                .iter()
                .find(|delivery| delivery.account == *peer && delivery.device == route.device);
            if let Some(wire_id) = existing_delivery.and_then(|delivery| delivery.wire_id) {
                prepared.first_wire.get_or_insert(wire_id);
                prepared.completed_routes.push((*peer, route.device));
                continue;
            }
            let Some(session) = self.sessions.get(&route.device) else {
                prepared.all_served = false;
                continue;
            };
            let token = delivery_token(
                &MailboxKey::from_bytes(*session.mailbox_key()),
                epoch_day(now),
                &route.device,
            );
            let body = match route.origin_tag {
                Some(tag) => GroupOriginEnvelope::from_parts(shared.clone(), tag)?.encode(),
                None if shared.version() != GROUP_MESSAGE_VERSION_ORIGIN => {
                    pending.shared_ciphertext.clone()
                }
                None => return Err(NodeError::CorruptState),
            };
            let envelope = match retention_until {
                Some(deadline) => {
                    Envelope::new_retained(EnvelopeKind::GroupMessage, token, deadline, body)?
                }
                None => Envelope::new(EnvelopeKind::GroupMessage, token, body),
            };
            let wire_id = envelope.content_id();
            prepared.first_wire.get_or_insert(wire_id);
            let after = MessageDeviceDeliveryRecord {
                message: group_msg_id,
                account: *peer,
                device: route.device,
                wire_id: Some(wire_id),
                state: DeliveryState::Queued,
            };
            if let Some(before) = existing_delivery {
                prepared.delivery_updates.push((before.clone(), after));
            } else {
                prepared.deliveries.push(after);
            }
            prepared.queue.push(QueueItem {
                peer: route.device,
                msg_id: None,
                group_msg_id: Some(group_msg_id),
                class,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope,
            });
            prepared.completed_routes.push((*peer, route.device));
        }
        Ok(prepared)
    }

    /// Encrypt one already-persisted Attachment manifest exactly once on the
    /// group's sender chain and queue its pairwise envelope copies as bulk.
    /// The attachment engine calls this only after every intended member has
    /// authenticated support and a fresh non-airtime route.
    pub(crate) fn queue_group_attachment_manifest(
        &mut self,
        group: &[u8; 32],
        content_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let before_group = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let mut after_group = before_group.clone();
        let before_record = self
            .store
            .group_messages(group)?
            .into_iter()
            .find(|record| record.direction == Direction::Outbound && &record.id == content_id)
            .ok_or(NodeError::UnknownAttachment)?;
        if before_record.origin
            != (GroupOriginAuthentication::PendingOutboundV1 {
                sender_device: self.device_id(),
            })
        {
            return Err(NodeError::CorruptState);
        }
        if before_record
            .deliveries
            .iter()
            .any(|delivery| delivery.wire_id.is_some())
        {
            return Ok(false);
        }
        for delivery in &before_record.deliveries {
            if !self.peer_has_live_device_sessions(&delivery.peer)? {
                return Ok(false);
            }
        }
        if after_group.sent_since_rotation >= GROUP_ROTATE_MSGS {
            self.rotate_group(&mut after_group, rng)?;
        }
        let mut sender_state = decode_sender_state(&after_group.sender_chain)?;
        let origin_chain = matches!(&sender_state, StoredGroupSenderState::Origin(_));
        let chain_key_id = sender_state.chain().key_id();
        let hk = GroupHeaderKey::derive(&after_group.secret);
        let wire = self
            .candidate_group_seal(
                sender_state.chain_mut(),
                &hk,
                group,
                origin_chain.then_some(before_record.id),
                &pad(&before_record.body)?,
                rng,
            )?
            .encode();
        after_group.sender_chain = encode_sender_state(&sender_state)?;
        after_group.sent_since_rotation = after_group
            .sent_since_rotation
            .checked_add(1)
            .ok_or(NodeError::CorruptState)?;
        let mut after_record = before_record.clone();
        after_record.origin = if origin_chain {
            GroupOriginAuthentication::OutboundV1 {
                sender_device: self.device_id(),
                chain_key_id,
            }
        } else {
            GroupOriginAuthentication::LegacyMembership
        };
        let pending_fanout = self.prepare_group_pending_fanout(
            group,
            &wire,
            &sender_state,
            &after_record.deliveries,
            after_record.id,
            ephemeral_retention(&after_record.body),
        )?;
        let mut queue = Vec::new();
        let mut delivery_rows = Vec::new();
        let mut delivery_pairs = Vec::new();
        for delivery in after_record.deliveries.iter_mut() {
            let prepared = self.prepare_group_copy(
                &delivery.peer,
                &pending_fanout,
                after_record.id,
                QueueClass::Bulk,
                ephemeral_retention(&after_record.body),
                now,
            )?;
            if !prepared.all_served || prepared.first_wire.is_none() {
                return Ok(false);
            }
            delivery.wire_id = prepared.first_wire;
            queue.extend(prepared.queue);
            delivery_rows.extend(prepared.deliveries);
            delivery_pairs.extend(prepared.delivery_updates);
        }
        after_record.wire_body = None;
        let delivery_updates = delivery_pairs
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let media_pairs = self
            .store
            .media_transfers()?
            .into_iter()
            .filter_map(|record| match record {
                MediaRecord::Available(before)
                    if before.scope == MediaScope::Group
                        && before.direction == MediaDirection::Outbound
                        && before.scope_id == *group
                        && before.manifest_content_id == *content_id
                        && before.state == MediaTransferState::Queued =>
                {
                    let mut after = before.clone();
                    after.state = MediaTransferState::Transferring;
                    after.updated_at = now;
                    Some((before, after))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let media_transfers = media_pairs
            .iter()
            .map(|(before, after)| MediaTransferTransition { before, after })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupSend(GroupSendPlan {
                group: Some(GroupTransition {
                    before: &before_group,
                    after: &after_group,
                }),
                message: None,
                message_update: Some(GroupMessageTransition {
                    before: &before_record,
                    after: &after_record,
                }),
                deliveries: &delivery_rows,
                delivery_updates: &delivery_updates,
                queue: &queue,
                scheduled: None,
                ephemeral: None,
                media_transfers: &media_transfers,
                delete_chains: &[],
                authority: None,
                presentation_changed: !media_transfers.is_empty(),
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, []);
        for (_, transfer) in media_pairs {
            self.emit_attachment_update(&transfer.local_id)?;
        }
        Ok(true)
    }

    /// Encrypt and queue one control payload to a peer over the pairwise
    /// session, initiating one from the stored bundle if none exists
    /// (announces to strangers ride right behind the handshake, like a
    /// first message does). `None` means the peer is unreachable *for now* —
    /// no bundle and no session; the announce plane's pacing retries.
    pub(crate) fn queue_group_control(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<[u8; 16]>> {
        let Some(prepared) = self.prepare_group_control(peer, payload, now, rng)? else {
            return Ok(None);
        };
        let preferred_wire = prepared.preferred_wire;
        self.commit_prepared_group_control(prepared, None, &[], &[], rng)?;
        Ok(Some(preferred_wire))
    }

    #[allow(clippy::too_many_arguments)] // encrypted response and exact authority consequence
    pub(crate) fn queue_group_control_with_authority_response(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        authority_before: &GroupAuthorityRecord,
        authority_after: &GroupAuthorityRecord,
        control: &DeferredControlRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(prepared) = self.prepare_group_control(peer, payload, now, rng)? else {
            return Ok(false);
        };
        self.commit_prepared_group_control(
            prepared,
            None,
            &[GroupAuthorityStateTransition {
                before: Some(authority_before),
                after: Some(authority_after),
            }],
            core::slice::from_ref(control),
            rng,
        )?;
        Ok(true)
    }

    pub(crate) fn queue_group_control_with_control_ack(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        control: &DeferredControlRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(prepared) = self.prepare_group_control(peer, payload, now, rng)? else {
            return Ok(false);
        };
        self.commit_prepared_group_control(
            prepared,
            None,
            &[],
            core::slice::from_ref(control),
            rng,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)] // exact pending owner and pairwise crypto inputs
    fn queue_group_announce(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        before_group: &GroupRecord,
        after_group: &mut GroupRecord,
        pending_index: usize,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<[u8; 16]>> {
        let prepared = self.prepare_group_control(peer, payload, now, rng)?;
        let preferred_wire = prepared.as_ref().map(|prepared| prepared.preferred_wire);
        let pending = after_group
            .pending
            .get_mut(pending_index)
            .filter(|pending| pending.peer == *peer)
            .ok_or(NodeError::CorruptState)?;
        pending.wire_id = preferred_wire;
        pending.last_sent = now.max(pending.last_sent.saturating_add(1));

        if let Some(prepared) = prepared {
            self.commit_prepared_group_control(
                prepared,
                Some(GroupTransition {
                    before: before_group,
                    after: after_group,
                }),
                &[],
                &[],
                rng,
            )?;
        } else {
            let receipt = self.store.commit_plan(
                CommitPlan::GroupState(GroupStatePlan {
                    groups: &[GroupStateTransition {
                        before: Some(before_group),
                        after: Some(after_group),
                    }],
                    chains: &[],
                    contacts: &[],
                    authorities: &[],
                    delete_controls: &[],
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }
        Ok(preferred_wire)
    }

    #[allow(clippy::too_many_arguments)] // exact recipient capability and durable group update
    fn queue_group_origin_announce(
        &mut self,
        peer: &[u8; 32],
        device: &[u8; 32],
        payload: &GroupControlPayload,
        before_group: &GroupRecord,
        after_group: &mut GroupRecord,
        origin_index: usize,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<[u8; 16]>> {
        let prepared = self.prepare_group_control_to_device(peer, device, payload, now, rng)?;
        let preferred_wire = prepared.as_ref().map(|prepared| prepared.preferred_wire);
        let mut sender = decode_sender_state(&after_group.sender_chain)?;
        let StoredGroupSenderState::Origin(state) = &mut sender else {
            return Err(NodeError::CorruptState);
        };
        let origin = state
            .origins
            .get_mut(origin_index)
            .filter(|origin| {
                origin.recipient_account == *peer && origin.recipient_device == *device
            })
            .ok_or(NodeError::CorruptState)?;
        origin.wire_id = preferred_wire;
        origin.last_sent = now.max(origin.last_sent.saturating_add(1));
        origin.acknowledged = false;
        after_group.sender_chain = encode_sender_state(&sender)?;

        if let Some(prepared) = prepared {
            self.commit_prepared_group_control(
                prepared,
                Some(GroupTransition {
                    before: before_group,
                    after: after_group,
                }),
                &[],
                &[],
                rng,
            )?;
        } else {
            let receipt = self.store.commit_plan(
                CommitPlan::GroupState(GroupStatePlan {
                    groups: &[GroupStateTransition {
                        before: Some(before_group),
                        after: Some(after_group),
                    }],
                    chains: &[],
                    contacts: &[],
                    authorities: &[],
                    delete_controls: &[],
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }
        Ok(preferred_wire)
    }

    fn prepare_group_control(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<PreparedGroupControl>> {
        let Some(contact) = self.store.get_contact(peer)? else {
            return Ok(None);
        };
        let mut routes = self.store.contact_devices_for(peer)?;
        if routes.is_empty() {
            routes.push(ContactDeviceRecord {
                account: *peer,
                device: *peer,
                name: None,
                certificate: Vec::new(),
                authority: Vec::new(),
                bundle: contact.bundle,
                hints: contact.hints,
                introduction_capability: None,
                introduction_generation: 0,
                manifest_generation: 0,
                manifest_state_id: [0u8; 32],
                last_seen: 0,
                revoked_at: None,
                revoked_after_counter: None,
            });
        }
        routes.sort_by(|left, right| {
            right
                .last_seen
                .cmp(&left.last_seen)
                .then_with(|| left.device.cmp(&right.device))
        });
        routes.dedup_by_key(|route| route.device);
        if routes.len() > kult_store::MAX_PAIRWISE_COMMIT_DEVICES {
            return Err(NodeError::CorruptState);
        }

        let bytes = zeroize::Zeroizing::new(payload.encode());
        let padded = pad(&bytes)?;
        let mut preferred_wire = None;
        let mut prepared = Vec::new();
        let mut queue = Vec::new();
        for route in routes {
            let device = route.device;
            let (before, mut after, handshake) =
                if let Some(before) = self.sessions.get(&device).cloned() {
                    (Some(before.clone()), before, None)
                } else {
                    if route.bundle.is_empty() {
                        continue;
                    }
                    let Ok((after, flight)) =
                        self.prepare_session(peer, &device, &route.bundle, &pad(&[])?, now, rng)
                    else {
                        continue; // e.g. the bundle expired — paced retry
                    };
                    (None, after, Some(flight))
                };
            let reset = handshake.is_some();
            if let Some(flight) = handshake {
                queue.push(QueueItem {
                    peer: device,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Normal,
                    created_at: now,
                    attempts: 0,
                    next_attempt_at: now,
                    envelope: flight,
                });
            }
            let msg = self.candidate_encrypt(&mut after, rng, now, &padded)?;
            let token = delivery_token(
                &MailboxKey::from_bytes(*after.mailbox_key()),
                epoch_day(now),
                &device,
            );
            let envelope = Envelope::new(EnvelopeKind::GroupControl, token, msg.encode());
            preferred_wire.get_or_insert_with(|| envelope.content_id());
            queue.push(QueueItem {
                peer: device,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope,
            });
            prepared.push(PreparedGroupControlRoute {
                device,
                before,
                after,
                reset,
            });
        }
        if prepared.is_empty() {
            return Ok(None);
        }
        Ok(Some(PreparedGroupControl {
            preferred_wire: preferred_wire.expect("prepared route has a control ciphertext"),
            routes: prepared,
            queue,
        }))
    }

    fn prepare_group_control_to_device(
        &mut self,
        peer: &[u8; 32],
        device: &[u8; 32],
        payload: &GroupControlPayload,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<PreparedGroupControl>> {
        let Some(contact) = self.store.get_contact(peer)? else {
            return Ok(None);
        };
        let endpoint = self
            .store
            .contact_devices_for(peer)?
            .into_iter()
            .find(|endpoint| endpoint.device == *device && endpoint.revoked_at.is_none())
            .or_else(|| {
                (*device == *peer).then_some(ContactDeviceRecord {
                    account: *peer,
                    device: *device,
                    name: None,
                    certificate: Vec::new(),
                    authority: Vec::new(),
                    bundle: contact.bundle,
                    hints: contact.hints,
                    introduction_capability: None,
                    introduction_generation: 0,
                    manifest_generation: 0,
                    manifest_state_id: [0u8; 32],
                    last_seen: 0,
                    revoked_at: None,
                    revoked_after_counter: None,
                })
            });
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        let (before, mut after, handshake) =
            if let Some(before) = self.sessions.get(device).cloned() {
                (Some(before.clone()), before, None)
            } else {
                if endpoint.bundle.is_empty() {
                    return Ok(None);
                }
                let Ok((after, flight)) =
                    self.prepare_session(peer, device, &endpoint.bundle, &pad(&[])?, now, rng)
                else {
                    return Ok(None);
                };
                (None, after, Some(flight))
            };
        let reset = handshake.is_some();
        let mut queue = Vec::new();
        if let Some(flight) = handshake {
            queue.push(QueueItem {
                peer: *device,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope: flight,
            });
        }
        let bytes = zeroize::Zeroizing::new(payload.encode());
        let padded = pad(&bytes)?;
        let message = self.candidate_encrypt(&mut after, rng, now, &padded)?;
        let token = delivery_token(
            &MailboxKey::from_bytes(*after.mailbox_key()),
            epoch_day(now),
            device,
        );
        let envelope = Envelope::new(EnvelopeKind::GroupControl, token, message.encode());
        let preferred_wire = envelope.content_id();
        queue.push(QueueItem {
            peer: *device,
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: now,
            attempts: 0,
            next_attempt_at: now,
            envelope,
        });
        Ok(Some(PreparedGroupControl {
            preferred_wire,
            routes: vec![PreparedGroupControlRoute {
                device: *device,
                before,
                after,
                reset,
            }],
            queue,
        }))
    }

    fn commit_prepared_group_control(
        &mut self,
        prepared: PreparedGroupControl,
        group: Option<GroupTransition<'_>>,
        authorities: &[GroupAuthorityStateTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transitions = prepared
            .routes
            .iter()
            .map(|route| SessionTransition {
                peer_device: route.device,
                before: route.before.as_ref(),
                after: &route.after,
            })
            .collect::<Vec<_>>();
        let clear_capabilities = prepared
            .routes
            .iter()
            .filter_map(|route| route.reset.then_some(route.device))
            .collect::<Vec<_>>();
        let groups = group.into_iter().collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::PairwiseSend(PairwiseSendPlan {
                sessions: &transitions,
                message: None,
                message_update: None,
                deliveries: &[],
                delivery_updates: &[],
                queue: &prepared.queue,
                groups: &groups,
                authorities,
                scheduled: None,
                clear_capabilities: &clear_capabilities,
                clear_reset_markers: &[],
                ephemeral: None,
                media_transfers: &[],
                media_objects: &[],
                delete_controls,
                wake: &[],
                presentation_changed: false,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        for route in prepared.routes {
            self.sessions.insert(route.device, route.after);
            if route.reset {
                self.capabilities_advertised.remove(&route.device);
                self.discovery_advertised.remove(&route.device);
            }
        }
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, []);
        Ok(())
    }

    /// Roster members met only through an announce have identity but no
    /// bundle; where a discovery plane exists, their published prekey
    /// record makes them reachable (paced by the announce retry window).
    async fn resolve_group_peer_bundle(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if self.peer_has_session_or_bundle(peer)? || self.discoveries.is_empty() {
            return Ok(());
        }
        let Some(before) = self.store.get_contact(peer)? else {
            return Ok(());
        };
        if !before.bundle.is_empty() {
            return Ok(());
        }
        let Ok(identity) = postcard::from_bytes::<IdentityPublic>(&before.identity) else {
            return Ok(());
        };
        let Some(bundle) = self
            .lookup_legacy_bundle(identity.address_digest(), now)
            .await
        else {
            return Ok(());
        };
        let mut contact = before.clone();
        contact.hints = bundle.prekey.transport_hints();
        contact.bundle = bundle.prekey.encode();
        let receipt = self.store.commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[],
                chains: &[],
                contacts: &[ContactTransition {
                    before: Some(&before),
                    after: &contact,
                }],
                authorities: &[],
                delete_controls: &[],
                presentation_changed: false,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, []);
        Ok(())
    }
}

pub(crate) fn encode_chain(chain: &GroupSenderChain) -> Result<Vec<u8>> {
    postcard::to_allocvec(chain).map_err(|_| NodeError::CorruptState)
}

enum StoredGroupSenderState {
    Legacy(GroupSenderChain),
    Origin(GroupSenderState),
}

impl StoredGroupSenderState {
    fn chain(&self) -> &GroupSenderChain {
        match self {
            Self::Legacy(chain) => chain,
            Self::Origin(state) => &state.chain,
        }
    }

    fn chain_mut(&mut self) -> &mut GroupSenderChain {
        match self {
            Self::Legacy(chain) => chain,
            Self::Origin(state) => &mut state.chain,
        }
    }
}

fn encode_sender_state(state: &StoredGroupSenderState) -> Result<Vec<u8>> {
    match state {
        StoredGroupSenderState::Legacy(chain) => encode_chain(chain),
        StoredGroupSenderState::Origin(state) => {
            validate_sender_origins(state)?;
            let body = postcard::to_allocvec(state).map_err(|_| NodeError::CorruptState)?;
            let mut encoded = Vec::with_capacity(GROUP_SENDER_ORIGIN_MAGIC.len() + body.len());
            encoded.extend_from_slice(GROUP_SENDER_ORIGIN_MAGIC);
            encoded.extend_from_slice(&body);
            Ok(encoded)
        }
    }
}

fn decode_sender_state(blob: &[u8]) -> Result<StoredGroupSenderState> {
    if let Some(body) = blob.strip_prefix(GROUP_SENDER_ORIGIN_MAGIC) {
        let (state, remainder): (GroupSenderState, &[u8]) =
            postcard::take_from_bytes(body).map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty() {
            return Err(NodeError::CorruptState);
        }
        validate_sender_origins(&state)?;
        Ok(StoredGroupSenderState::Origin(state))
    } else if let Some(body) = blob.strip_prefix(LEGACY_GROUP_SENDER_ORIGIN_MAGIC) {
        let (legacy, remainder): (LegacyGroupSenderState, &[u8]) =
            postcard::take_from_bytes(body).map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty() {
            return Err(NodeError::CorruptState);
        }
        let state = GroupSenderState {
            origin_generation: 1,
            chain: legacy.chain,
            origins: legacy.origins,
        };
        validate_sender_origins(&state)?;
        Ok(StoredGroupSenderState::Origin(state))
    } else {
        let (chain, remainder): (GroupSenderChain, &[u8]) =
            postcard::take_from_bytes(blob).map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty() {
            return Err(NodeError::CorruptState);
        }
        Ok(StoredGroupSenderState::Legacy(chain))
    }
}

fn validate_sender_origins(state: &GroupSenderState) -> Result<()> {
    if state.origin_generation == 0
        || state.origins.len() > MAX_GROUP_ORIGIN_ROUTES
        || state.origins.windows(2).any(|pair| {
            (pair[0].recipient_account, pair[0].recipient_device)
                >= (pair[1].recipient_account, pair[1].recipient_device)
        })
        || state.origins.iter().any(|origin| {
            origin.recipient_account == [0u8; 32]
                || origin.recipient_device == [0u8; 32]
                || origin.origin_key == [0u8; 32]
                || origin.chain_key == [0u8; 32]
                || origin.key_id != state.chain.key_id()
                || origin.acknowledged && origin.wire_id.is_none()
        })
    {
        return Err(NodeError::CorruptState);
    }
    Ok(())
}

fn ephemeral_retention(body: &[u8]) -> Option<u64> {
    match decode_content(body) {
        DecodedContent::Ephemeral {
            ephemeral:
                Ephemeral::DisappearingText {
                    retention_until, ..
                }
                | Ephemeral::ViewOnceAttachment {
                    retention_until, ..
                },
            ..
        } => Some(retention_until),
        _ => None,
    }
}

fn valid_group_origin_plaintext(
    body: &[u8],
    origin_content_id: Option<[u8; 16]>,
    envelope_retention: Option<u64>,
) -> bool {
    if ephemeral_retention(body) != envelope_retention {
        return false;
    }
    let Some(expected) = origin_content_id else {
        return true;
    };
    if expected == [0u8; 16] {
        return false;
    }
    match decode_content(body) {
        DecodedContent::Text { id, .. }
        | DecodedContent::Attachment { id, .. }
        | DecodedContent::Mention { id, .. }
        | DecodedContent::Edit { id, .. }
        | DecodedContent::Ephemeral { id, .. }
        | DecodedContent::Poll { id, .. }
        | DecodedContent::GroupAuthority { id, .. }
        | DecodedContent::CallControl { id, .. } => id == expected,
        DecodedContent::LegacyText(_)
        | DecodedContent::Unsupported { .. }
        | DecodedContent::Malformed => true,
    }
}

fn valid_roster(members: &[GroupMemberInfo]) -> bool {
    let peers = members
        .iter()
        .map(|member| member.peer)
        .collect::<HashSet<_>>();
    !members.is_empty()
        && members.len() <= MAX_GROUP_AUTHORITY_MEMBERS
        && peers.len() == members.len()
        && members.iter().all(|member| {
            !member.identity.is_empty()
                && member.identity.len() <= MAX_GROUP_MEMBER_IDENTITY_LEN
                && postcard::from_bytes::<IdentityPublic>(&member.identity)
                    .is_ok_and(|identity| identity.ed == member.peer)
        })
}

/// Announce entries for every roster member but `me`, snapshotting `chain`
/// at its current state (the entitlement point).
pub(crate) fn pending_for(
    chain: &GroupSenderChain,
    members: impl Iterator<Item = [u8; 32]>,
    me: &[u8; 32],
) -> Vec<PendingAnnounce> {
    let (key_id, chain_key, iteration) = chain.snapshot();
    members
        .filter(|p| p != me)
        .map(|peer| PendingAnnounce {
            peer,
            key_id,
            chain_key: *chain_key,
            iteration,
            wire_id: None,
            last_sent: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use kult_crypto::KdfProfile;
    use kult_protocol::{
        CapabilityControl, FormatCapabilities, CONTENT_KIND_EDIT, CONTENT_KIND_TEXT,
    };

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn origin_state_codecs_migrate_released_and_premerge_rows_explicitly() {
        let mut rng = StdRng::seed_from_u64(0x0029_c0de);
        let sender = GroupSenderChain::generate(&mut rng);
        let (key_id, chain_key, iteration) = sender.snapshot();
        let receiver = GroupReceiverChain::new(key_id, &chain_key, iteration);

        let v2 = vec![LegacyDeviceGroupReceiverChainV2 {
            device: [1; 32],
            chain: receiver.clone(),
        }];
        let mut v2_blob = LEGACY_DEVICE_GROUP_CHAINS_V2_MAGIC.to_vec();
        v2_blob.extend_from_slice(&postcard::to_allocvec(&v2).unwrap());
        let mut decoded = decode_device_group_chains(&v2_blob, [9; 32]).unwrap();
        assert_eq!(decoded[0].chain.key_id(), key_id);
        assert!(decoded[0].origin_key.is_none());
        let current = encode_device_group_chains(&mut decoded).unwrap();
        assert!(current.starts_with(DEVICE_GROUP_CHAINS_MAGIC));
        assert!(decode_device_group_chains(&current, [9; 32]).is_ok());

        let v3 = vec![LegacyDeviceGroupReceiverChainV3 {
            device: [1; 32],
            chain: receiver,
            origin_key: Some([2; 32]),
            recipient_device: [3; 32],
        }];
        let mut v3_blob = LEGACY_DEVICE_GROUP_CHAINS_V3_MAGIC.to_vec();
        v3_blob.extend_from_slice(&postcard::to_allocvec(&v3).unwrap());
        let mut decoded = decode_device_group_chains(&v3_blob, [9; 32]).unwrap();
        assert_eq!(decoded[0].origin_generation, 0);
        let current = encode_device_group_chains(&mut decoded).unwrap();
        let decoded = decode_device_group_chains(&current, [9; 32]).unwrap();
        assert!(
            decoded[0].origin_key.is_none(),
            "unordered KGC3 origin material requires a fresh announce"
        );

        let legacy_sender = LegacyGroupSenderState {
            chain: sender,
            origins: vec![OutgoingGroupOrigin {
                recipient_account: [4; 32],
                recipient_device: [5; 32],
                key_id,
                chain_key: *chain_key,
                iteration,
                origin_key: [6; 32],
                wire_id: None,
                last_sent: 0,
                acknowledged: false,
            }],
        };
        let mut sender_blob = LEGACY_GROUP_SENDER_ORIGIN_MAGIC.to_vec();
        sender_blob.extend_from_slice(&postcard::to_allocvec(&legacy_sender).unwrap());
        let StoredGroupSenderState::Origin(migrated) = decode_sender_state(&sender_blob).unwrap()
        else {
            panic!("KGS2 must decode as origin state");
        };
        assert_eq!(migrated.origin_generation, 1);
        let current = encode_sender_state(&StoredGroupSenderState::Origin(migrated)).unwrap();
        assert!(current.starts_with(GROUP_SENDER_ORIGIN_MAGIC));
    }

    #[test]
    fn receiver_origin_generation_ignores_stale_and_same_generation_conflicts() {
        let mut rng = StdRng::seed_from_u64(0x0029_6e6e);
        let directory = tempfile::tempdir().unwrap();
        let alice =
            Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
        let bob = Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
        let group = [7u8; 32];
        let peer = bob.peer_id();
        let device = bob.device_id();

        let (_, accepted) = alice
            .prepare_group_receiver_chain(
                &group,
                AuthenticatedGroupSender {
                    account: peer,
                    device,
                },
                GroupReceiverChainMaterial {
                    key_id: [1; 16],
                    chain_key: [2; 32],
                    iteration: 0,
                    origin: Some(GroupOriginMaterial {
                        key: [3; 32],
                        generation: 2,
                    }),
                },
            )
            .unwrap();
        let accepted = accepted.unwrap();
        alice
            .store
            .put_group_chain(&group, &peer, &accepted, &mut rng)
            .unwrap();

        let (_, duplicate) = alice
            .prepare_group_receiver_chain(
                &group,
                AuthenticatedGroupSender {
                    account: peer,
                    device,
                },
                GroupReceiverChainMaterial {
                    key_id: [1; 16],
                    chain_key: [2; 32],
                    iteration: 0,
                    origin: Some(GroupOriginMaterial {
                        key: [3; 32],
                        generation: 2,
                    }),
                },
            )
            .unwrap();
        assert!(duplicate.is_none());

        let (_, conflict) = alice
            .prepare_group_receiver_chain(
                &group,
                AuthenticatedGroupSender {
                    account: peer,
                    device,
                },
                GroupReceiverChainMaterial {
                    key_id: [4; 16],
                    chain_key: [5; 32],
                    iteration: 0,
                    origin: Some(GroupOriginMaterial {
                        key: [6; 32],
                        generation: 2,
                    }),
                },
            )
            .unwrap();
        assert!(conflict.is_none());

        let (_, stale) = alice
            .prepare_group_receiver_chain(
                &group,
                AuthenticatedGroupSender {
                    account: peer,
                    device,
                },
                GroupReceiverChainMaterial {
                    key_id: [7; 16],
                    chain_key: [8; 32],
                    iteration: 0,
                    origin: Some(GroupOriginMaterial {
                        key: [9; 32],
                        generation: 1,
                    }),
                },
            )
            .unwrap();
        assert!(stale.is_none());
        assert_eq!(
            alice
                .store
                .get_group_chain(&group, &peer)
                .unwrap()
                .unwrap()
                .as_slice(),
            accepted.as_slice()
        );

        let (_, fresh) = alice
            .prepare_group_receiver_chain(
                &group,
                AuthenticatedGroupSender {
                    account: peer,
                    device,
                },
                GroupReceiverChainMaterial {
                    key_id: [10; 16],
                    chain_key: [11; 32],
                    iteration: 0,
                    origin: Some(GroupOriginMaterial {
                        key: [12; 32],
                        generation: 3,
                    }),
                },
            )
            .unwrap();
        assert!(fresh.is_some());
    }

    #[test]
    fn group_edit_requires_every_current_member_capability() {
        let mut rng = StdRng::seed_from_u64(0x00c3_0004);
        let directory = tempfile::tempdir().unwrap();
        let mut alice =
            Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
        let mut bob =
            Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(1_800_000_000, &mut rng).unwrap();
        let bob_device = bob.device_id();
        let bob_peer = alice
            .add_contact("bob", &bob_bundle, &[], 1_800_000_000, &mut rng)
            .unwrap();
        alice
            .send_message(&bob_peer, b"establish session", 1_800_000_000, &mut rng)
            .unwrap();
        let group = alice
            .create_group("old client", &[bob_peer], &mut rng)
            .unwrap();
        let alice_peer = alice.account.ed;

        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "unsupported",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::EditUnsupported)
        ));

        let text_only = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_device, &text_only, &mut rng)
            .unwrap();
        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "old client",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::EditUnsupported)
        ));

        let edit_capable = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT, CONTENT_KIND_EDIT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_device, &edit_capable, &mut rng)
            .unwrap();
        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "missing target",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::InvalidEdit)
        ));
    }

    #[test]
    fn mention_intersection_fails_closed_on_downgrade_and_missing_snapshot() {
        let mut rng = StdRng::seed_from_u64(0xB17);
        let directory = tempfile::tempdir().unwrap();
        let mut alice =
            Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
        let mut bob =
            Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(1_800_000_000, &mut rng).unwrap();
        let bob_device = bob.device_id();
        let bob_peer = alice
            .add_contact("same name", &bob_bundle, &[], 1_800_000_000, &mut rng)
            .unwrap();
        let group = alice
            .create_group("capabilities", &[bob_peer], &mut rng)
            .unwrap();

        let supported_snapshot = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT, CONTENT_KIND_MENTION],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_device, &supported_snapshot, &mut rng)
            .unwrap();
        let supported = alice.group_mention_capability(&group).unwrap();
        assert!(supported.supported());

        let span = [MentionSpan {
            start: 0,
            end: 2,
            target: bob_peer,
        }];
        let mut renamed_contact = alice.store.get_contact(&bob_peer).unwrap().unwrap();
        renamed_contact.name = "\u{2067}同名\u{2069}".to_owned();
        alice.store.put_contact(&renamed_contact, &mut rng).unwrap();
        let renamed = alice.group_mention_capability(&group).unwrap();
        assert!(renamed.supported());
        assert_ne!(supported.review_token, renamed.review_token);
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                supported.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionReviewRequired)
        ));

        let downgraded_snapshot = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_device, &downgraded_snapshot, &mut rng)
            .unwrap();
        let downgraded = alice.group_mention_capability(&group).unwrap();
        assert_eq!(
            downgraded.issues,
            vec![MentionCapabilityIssue {
                peer: bob_peer,
                reason: MentionCapabilityIssueReason::Unsupported,
            }]
        );
        assert_ne!(renamed.review_token, downgraded.review_token);
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                renamed.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionReviewRequired)
        ));
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                downgraded.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionUnsupported)
        ));

        alice.store.delete_capabilities(&bob_device).unwrap();
        let missing = alice.group_mention_capability(&group).unwrap();
        assert_eq!(
            missing.issues,
            vec![MentionCapabilityIssue {
                peer: bob_peer,
                reason: MentionCapabilityIssueReason::Unknown,
            }]
        );
        assert_ne!(downgraded.review_token, missing.review_token);
    }
}
