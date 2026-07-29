//! Bounded typed transactions for protocol-state transitions (ADR-0028).

use std::collections::{HashMap, HashSet};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::{
    GroupMessage, GroupOriginEnvelope, GroupSenderChain, Identity, IdentityPublic, Session,
    GROUP_MESSAGE_VERSION_LEGACY,
};
use kult_protocol::{
    CapabilityControl, DeviceSyncEvent, Envelope, EnvelopeKind, MAX_DEVICE_SYNC_BUNDLE_EVENTS,
    MAX_GROUP_ADMIN_REQUESTS, MAX_GROUP_AUTHORITY_MEMBERS, MAX_GROUP_MEMBER_IDENTITY_LEN,
    MAX_GROUP_NAME_LEN,
};

use crate::{
    decode_exact, direction_code, store_v2, ContactDeviceRecord, ContactRecord, DeliveryState,
    DeviceAuthorityStateRecord, DeviceLinkRecoveryRecord, DeviceStateRecord, Direction,
    EphemeralRecord, EphemeralState, GroupAuthorityRecord, GroupMessageRecord,
    GroupOriginAuthentication, GroupPendingFanout, GroupRecord, LocalMetadataRecord,
    MediaObjectRecord, MediaRecord, MediaTransferRecord, MessageDeviceDeliveryRecord,
    MessageRecord, NoteMessageRecord, QueueItem, Result, ScheduledMessageRecord, Store, StoreError,
    MAX_DEVICE_SYNC_EVENT_BYTES,
};

/// Maximum logical durable mutations accepted by one typed commit plan.
pub const MAX_COMMIT_MUTATIONS: usize = 512;
/// Maximum physical devices in one pairwise fan-out.
pub const MAX_PAIRWISE_COMMIT_DEVICES: usize = 8;
/// Maximum queue rows created by one protocol transition.
pub const MAX_COMMIT_QUEUE_ROWS: usize = 128;
/// Maximum queue rows in a stable-v1 group fan-out (64 accounts × 8 devices).
pub const MAX_GROUP_COMMIT_QUEUE_ROWS: usize = 512;
/// Maximum durable mutations in one bounded group fan-out transaction.
pub const MAX_GROUP_COMMIT_MUTATIONS: usize = 2_048;
/// Maximum rows created while staging one bounded attachment manifest.
pub const MAX_ATTACHMENT_STAGE_MUTATIONS: usize = 256;
/// Maximum exact rows changed by one group roster or authority transition.
pub const MAX_GROUP_STATE_MUTATIONS: usize = 256;
/// Maximum exact maintenance transitions applied in one transaction.
pub const MAX_MAINTENANCE_TRANSITIONS: usize = 256;
/// Maximum authenticated control records retained for post-commit work.
pub const MAX_DEFERRED_CONTROLS: usize = 512;
/// Maximum exact changes in one linked-device authority or convergence transition.
pub const MAX_DEVICE_CONTROL_MUTATIONS: usize = 8_192;
/// Maximum durable groups in one profile.
///
/// This leaves room for a full device-sync bundle, device authority, and
/// link-recovery retirement while rotating every local group sender chain in
/// the same revocation transaction.
pub const MAX_PROFILE_GROUPS: usize =
    MAX_DEVICE_CONTROL_MUTATIONS - MAX_DEVICE_SYNC_BUNDLE_EVENTS - 2;
/// Maximum selected records imported by one confirmed pristine-device link.
pub const MAX_DEVICE_LINK_MUTATIONS: usize = 8_192;
/// Maximum exact durable changes projected from one accepted sync winner.
pub const MAX_DEVICE_PROJECTION_MUTATIONS: usize = 512;

fn validate_outbound_group_origin(origin: GroupOriginAuthentication) -> Result<()> {
    match origin {
        GroupOriginAuthentication::LegacyMembership => Ok(()),
        GroupOriginAuthentication::OutboundV1 {
            sender_device,
            chain_key_id,
        } if sender_device != [0u8; 32] && chain_key_id != [0u8; 16] => Ok(()),
        GroupOriginAuthentication::RecipientV1 { .. }
        | GroupOriginAuthentication::PendingOutboundV1 { .. }
        | GroupOriginAuthentication::OutboundV1 { .. } => Err(StoreError::InvalidTransition),
    }
}

fn validate_inbound_group_origin(origin: GroupOriginAuthentication) -> Result<()> {
    match origin {
        GroupOriginAuthentication::RecipientV1 {
            sender_device,
            recipient_device,
            chain_key_id,
        } if sender_device != [0u8; 32]
            && recipient_device != [0u8; 32]
            && chain_key_id != [0u8; 16] =>
        {
            Ok(())
        }
        _ => Err(StoreError::InvalidTransition),
    }
}

fn pending_group_shared(origin: GroupOriginAuthentication, encoded: &[u8]) -> Result<Vec<u8>> {
    if let Ok(pending) = GroupPendingFanout::decode(encoded) {
        let tagged = pending.routes[0].origin_tag.is_some();
        if tagged != matches!(origin, GroupOriginAuthentication::OutboundV1 { .. }) {
            return Err(StoreError::InvalidTransition);
        }
        return Ok(pending.shared_ciphertext);
    }
    if origin != GroupOriginAuthentication::LegacyMembership {
        return Err(StoreError::InvalidTransition);
    }
    let message = GroupMessage::decode(encoded).map_err(|_| StoreError::InvalidTransition)?;
    if message.version() != GROUP_MESSAGE_VERSION_LEGACY {
        return Err(StoreError::InvalidTransition);
    }
    Ok(encoded.to_vec())
}

fn queued_group_shared(origin: GroupOriginAuthentication, encoded: &[u8]) -> Result<Vec<u8>> {
    match origin {
        GroupOriginAuthentication::LegacyMembership => {
            let message =
                GroupMessage::decode(encoded).map_err(|_| StoreError::InvalidTransition)?;
            if message.version() != GROUP_MESSAGE_VERSION_LEGACY {
                return Err(StoreError::InvalidTransition);
            }
            Ok(encoded.to_vec())
        }
        GroupOriginAuthentication::OutboundV1 { .. } => {
            let envelope =
                GroupOriginEnvelope::decode(encoded).map_err(|_| StoreError::InvalidTransition)?;
            Ok(envelope.shared().encode())
        }
        GroupOriginAuthentication::RecipientV1 { .. }
        | GroupOriginAuthentication::PendingOutboundV1 { .. } => Err(StoreError::InvalidTransition),
    }
}

/// Complete cryptographic bootstrap of one previously unpublished profile.
#[cfg(any(test, feature = "legacy-test-fixtures"))]
pub struct ProfileBootstrapPlan<'a> {
    /// Fresh account identity.
    pub identity: &'a Identity,
    /// Fresh local physical-device authority state.
    pub device_state: &'a DeviceStateRecord,
    /// Fresh encoded prekey vault.
    pub prekeys: &'a [u8],
}

/// Complete ADR-0026 bootstrap with no account private key in the live store.
pub struct AuthorityProfileBootstrapPlan<'a> {
    /// Stable public account trust anchor.
    pub account: &'a IdentityPublic,
    /// Fresh local quorum-authorized physical-device state.
    pub device_state: &'a DeviceAuthorityStateRecord,
    /// Fresh encoded prekey vault.
    pub prekeys: &'a [u8],
}

/// Exact in-place conversion of a single-device Alpha profile to ADR-0026.
///
/// The legacy account root and device state are replaced in one SQLite
/// transaction. Conversation state and the independently keyed physical
/// device remain unchanged.
pub struct AuthorityMigrationPlan<'a> {
    /// Exact legacy account root expected before the transaction.
    pub legacy_identity: &'a Identity,
    /// Exact legacy single-device authority state expected before the transaction.
    pub legacy_device_state: &'a DeviceStateRecord,
    /// Public account trust anchor retained after the root is removed.
    pub account: &'a IdentityPublic,
    /// Root-authorized generation-one authority state for the same device key.
    pub device_state: &'a DeviceAuthorityStateRecord,
}

/// Kind of authenticated pairwise control retained for idempotent follow-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferredControlKind {
    /// Attachment bulk request, chunk, or terminal response.
    AttachmentBulk,
    /// Pairwise-ratchet-protected group control.
    GroupControl,
}

/// Immutable accepted control state whose external work occurs after commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredControlRecord {
    /// Envelope content id and durable equality key.
    pub content_id: [u8; 16],
    /// Stable account identity that authenticated the control.
    pub peer: [u8; 32],
    /// Exact physical session route that authenticated the control.
    pub peer_device: [u8; 32],
    /// Typed follow-up behavior.
    pub kind: DeferredControlKind,
    /// Exact decrypted authenticated control bytes.
    pub body: Vec<u8>,
    /// Local acceptance time.
    pub received_at: u64,
}

/// A durable session replacement tied to its exact prior value.
pub struct SessionTransition<'a> {
    /// Exact physical-device route.
    pub peer_device: [u8; 32],
    /// Durable session expected before the transaction, or `None` for a new route.
    pub before: Option<&'a Session>,
    /// Candidate session produced without mutating live runtime state.
    pub after: &'a Session,
}

/// One deferred-inbox row that may be removed only with its named envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingDelete {
    /// Stable pending row sequence.
    pub sequence: i64,
    /// Exact envelope content id expected in that row.
    pub content_id: [u8; 16],
}

/// One outbound row that may be removed only with its named envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueDelete {
    /// Stable outbound row sequence.
    pub sequence: i64,
    /// Exact envelope content id expected in that row.
    pub content_id: [u8; 16],
}

/// An exact in-place outbound queue update.
pub struct QueueTransition<'a> {
    /// Stable outbound row sequence.
    pub sequence: i64,
    /// Exact durable value expected before the transaction.
    pub before: &'a QueueItem,
    /// Replacement scheduling or delivery value.
    pub after: &'a QueueItem,
}

/// An exact pairwise history update.
pub struct MessageTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MessageRecord,
    /// Replacement value with the same immutable identity.
    pub after: &'a MessageRecord,
}

/// One pairwise history row removed only after a tombstone is committed.
pub struct MessageDelete<'a> {
    /// Exact durable value expected before deletion.
    pub before: &'a MessageRecord,
}

/// One group history row removed only after a tombstone is committed.
pub struct GroupMessageDelete<'a> {
    /// Exact durable value expected before deletion.
    pub before: &'a GroupMessageRecord,
}

/// An exact per-device delivery-state update.
pub struct DeliveryTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MessageDeviceDeliveryRecord,
    /// Replacement delivery value with the same identity.
    pub after: &'a MessageDeviceDeliveryRecord,
}

/// An exact group-state update.
pub struct GroupTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a GroupRecord,
    /// Replacement value with the same group id.
    pub after: &'a GroupRecord,
}

/// An exact group-history update.
pub struct GroupMessageTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a GroupMessageRecord,
    /// Replacement value with the same immutable identity.
    pub after: &'a GroupMessageRecord,
}

/// An exact sealed group receiver-chain replacement.
pub struct GroupChainTransition<'a> {
    /// Exact group conversation.
    pub group: [u8; 32],
    /// Account whose sender chain this receiver state follows.
    pub peer: [u8; 32],
    /// Exact durable chain expected before the transaction.
    pub before: &'a [u8],
    /// Candidate chain produced without mutating durable or live state.
    pub after: &'a [u8],
}

/// A new or exact replacement signed group-authority record.
pub struct GroupAuthorityTransition<'a> {
    /// Existing authority state, or `None` for the first signed generation.
    pub before: Option<&'a GroupAuthorityRecord>,
    /// Resulting signed authority state.
    pub after: &'a GroupAuthorityRecord,
}

/// New, exact replacement, or exact removal of one signed group-authority record.
pub struct GroupAuthorityStateTransition<'a> {
    /// Existing authority state, or `None` when creating it.
    pub before: Option<&'a GroupAuthorityRecord>,
    /// Resulting authority state, or `None` when removing it with the group.
    pub after: Option<&'a GroupAuthorityRecord>,
}

/// New, exact replacement, or exact removal of one group record.
pub struct GroupStateTransition<'a> {
    /// Existing group, or `None` when creating it.
    pub before: Option<&'a GroupRecord>,
    /// Resulting group, or `None` when removing it.
    pub after: Option<&'a GroupRecord>,
}

/// New, exact replacement, or exact removal of one group receiver-chain blob.
pub struct GroupChainStateTransition<'a> {
    /// Group whose receiver-chain map changes.
    pub group: [u8; 32],
    /// Account whose device-chain aggregate changes.
    pub peer: [u8; 32],
    /// Exact existing blob, or `None` when creating it.
    pub before: Option<&'a [u8]>,
    /// Resulting blob, or `None` when removing it.
    pub after: Option<&'a [u8]>,
}

/// New or exact replacement contact stub adopted from authenticated group state.
pub struct ContactTransition<'a> {
    /// Existing contact, or `None` for a newly authenticated roster stub.
    pub before: Option<&'a ContactRecord>,
    /// Resulting contact row.
    pub after: &'a ContactRecord,
}

/// An exact ephemeral marker update.
pub struct EphemeralTransition<'a> {
    /// Existing marker, or `None` when the transition creates it.
    pub before: Option<&'a EphemeralRecord>,
    /// Resulting active marker or tombstone.
    pub after: &'a EphemeralRecord,
}

/// Exact media rows removed after their semantic tombstone is durable.
pub struct MediaDelete<'a> {
    /// Transfer id whose metadata is removed.
    pub transfer_id: [u8; 16],
    /// Exact local object ids removed before the transfer row.
    pub object_ids: &'a [[u8; 16]],
}

/// An exact attachment-transfer metadata replacement.
pub struct MediaTransferTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MediaTransferRecord,
    /// Replacement value with the same local transfer identity.
    pub after: &'a MediaTransferRecord,
}

/// An exact attachment-object metadata replacement.
pub struct MediaObjectTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MediaObjectRecord,
    /// Replacement value with the same local object identity.
    pub after: &'a MediaObjectRecord,
}

/// One exact contact endpoint removed by an authenticated manifest transition.
pub struct ContactDeviceDelete<'a> {
    /// Exact durable endpoint expected before deletion.
    pub before: &'a ContactDeviceRecord,
}

/// Exact account-identity replacement during a confirmed device link.
#[cfg(any(test, feature = "legacy-test-fixtures"))]
pub struct IdentityTransition<'a> {
    /// Identity currently stored on the pristine target.
    pub before: &'a Identity,
    /// Account identity authenticated by the completed link package.
    pub after: &'a Identity,
}

/// Exact public-account replacement during a confirmed root-free device link.
pub struct AccountIdentityTransition<'a> {
    /// Public account currently stored on the pristine target.
    pub before: &'a IdentityPublic,
    /// Public account authenticated by the completed link package.
    pub after: &'a IdentityPublic,
}

/// New or exact replacement of the complete local linked-device state.
pub struct DeviceStateTransition<'a> {
    /// Existing state, or `None` while atomically initializing a new profile.
    pub before: Option<&'a DeviceStateRecord>,
    /// Detached candidate state.
    pub after: &'a DeviceStateRecord,
}

/// Exact replacement of live ADR-0026 device authority state.
pub struct DeviceAuthorityStateTransition<'a> {
    /// Existing state, or `None` while atomically initializing.
    pub before: Option<&'a DeviceAuthorityStateRecord>,
    /// Detached candidate state.
    pub after: &'a DeviceAuthorityStateRecord,
}

/// Creation, exact replacement, or acknowledgement of a recoverable link package.
pub struct DeviceLinkRecoveryTransition<'a> {
    /// Current recovery handle, or `None` before link approval.
    pub before: Option<&'a DeviceLinkRecoveryRecord>,
    /// Resulting recovery handle, or `None` after authenticated target activity.
    pub after: Option<&'a DeviceLinkRecoveryRecord>,
}

/// Exact ratchet session retired by an authenticated device transition.
pub struct SessionDelete<'a> {
    /// Exact physical-device route.
    pub peer_device: [u8; 32],
    /// Durable session expected before deletion.
    pub before: &'a Session,
}

/// Exact session-bound capability snapshot retired with its device route.
pub struct CapabilityDelete<'a> {
    /// Exact physical-device route.
    pub peer_device: [u8; 32],
    /// Durable capability state expected before deletion.
    pub before: &'a CapabilityControl,
}

/// One exact, idempotent projection of an accepted linked-device sync winner.
pub enum DeviceProjection<'a> {
    /// Contact creation, replacement, or deletion.
    Contact {
        /// Exact current value.
        before: Option<&'a ContactRecord>,
        /// Desired value.
        after: Option<&'a ContactRecord>,
    },
    /// Physical contact-device creation, replacement, or deletion.
    ContactDevice {
        /// Exact current value.
        before: Option<&'a ContactDeviceRecord>,
        /// Desired value.
        after: Option<&'a ContactDeviceRecord>,
    },
    /// Pairwise history creation, replacement, or deletion.
    Message {
        /// Exact current value.
        before: Option<&'a MessageRecord>,
        /// Desired value.
        after: Option<&'a MessageRecord>,
    },
    /// Group history creation, replacement, or deletion.
    GroupMessage {
        /// Exact current value.
        before: Option<&'a GroupMessageRecord>,
        /// Desired value.
        after: Option<&'a GroupMessageRecord>,
    },
    /// Local organization creation, replacement, or deletion.
    LocalMetadata {
        /// Exact current value.
        before: Option<&'a LocalMetadataRecord>,
        /// Desired value.
        after: Option<&'a LocalMetadataRecord>,
    },
    /// A new immutable note-to-self record.
    Note {
        /// New record, which must not already exist.
        after: &'a NoteMessageRecord,
    },
}

/// One bounded linked-device authority, counter, convergence-log, or rotation transition.
pub struct DeviceControlPlan<'a> {
    /// Optional complete local authority/counter replacement.
    pub state: Option<DeviceStateTransition<'a>>,
    /// Optional committed link-package recovery outbox transition.
    pub link_recovery: Option<DeviceLinkRecoveryTransition<'a>>,
    /// Sender-chain rotations owned by a device revocation.
    pub groups: &'a [GroupTransition<'a>],
    /// New authenticated convergence events.
    pub insert_events: &'a [Vec<u8>],
    /// Exact redundant convergence events removed during bounded compaction.
    pub delete_events: &'a [Vec<u8>],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded ADR-0026 authority, counter, convergence, or rotation transition.
pub struct AuthorityDeviceControlPlan<'a> {
    /// Optional complete live authority/counter replacement.
    pub state: Option<DeviceAuthorityStateTransition<'a>>,
    /// Optional committed link-package recovery outbox transition.
    pub link_recovery: Option<DeviceLinkRecoveryTransition<'a>>,
    /// Sender-chain rotations owned by revocation or recovery.
    pub groups: &'a [GroupTransition<'a>],
    /// New authenticated convergence events.
    pub insert_events: &'a [Vec<u8>],
    /// Exact redundant convergence events removed during compaction.
    pub delete_events: &'a [Vec<u8>],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete bounded import performed by one confirmed link onto a pristine target.
#[cfg(any(test, feature = "legacy-test-fixtures"))]
pub struct DeviceLinkPlan<'a> {
    /// Authenticated account replacement.
    pub identity: IdentityTransition<'a>,
    /// Complete target-device authority and channel state.
    pub device_state: DeviceStateTransition<'a>,
    /// Selected contact records.
    pub contacts: &'a [ContactRecord],
    /// Selected contact-device endpoints.
    pub devices: &'a [ContactDeviceRecord],
    /// Selected pairwise history.
    pub messages: &'a [MessageRecord],
    /// Regenerated local group records.
    pub groups: &'a [GroupRecord],
    /// Selected group history.
    pub group_messages: &'a [GroupMessageRecord],
    /// Selected signed group authority.
    pub authorities: &'a [GroupAuthorityRecord],
    /// Selected local organization state.
    pub local_metadata: &'a [LocalMetadataRecord],
    /// Selected note-to-self history.
    pub notes: &'a [NoteMessageRecord],
    /// Terminal ephemeral tombstones.
    pub ephemeral: &'a [EphemeralRecord],
    /// Authenticated convergence events.
    pub sync_events: &'a [Vec<u8>],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete bounded root-free import onto a pristine ADR-0026 target.
pub struct AuthorityDeviceLinkPlan<'a> {
    /// Authenticated public-account replacement.
    pub account: AccountIdentityTransition<'a>,
    /// Complete target-device authority and channel state.
    pub device_state: DeviceAuthorityStateTransition<'a>,
    /// Selected contact records.
    pub contacts: &'a [ContactRecord],
    /// Selected contact-device endpoints.
    pub devices: &'a [ContactDeviceRecord],
    /// Selected pairwise history.
    pub messages: &'a [MessageRecord],
    /// Regenerated local group records.
    pub groups: &'a [GroupRecord],
    /// Selected group history.
    pub group_messages: &'a [GroupMessageRecord],
    /// Selected signed group authority.
    pub authorities: &'a [GroupAuthorityRecord],
    /// Selected local organization state.
    pub local_metadata: &'a [LocalMetadataRecord],
    /// Selected note-to-self history.
    pub notes: &'a [NoteMessageRecord],
    /// Terminal ephemeral tombstones.
    pub ephemeral: &'a [EphemeralRecord],
    /// Authenticated convergence events.
    pub sync_events: &'a [Vec<u8>],
    /// Physical contact routes whose copied public one-time prekeys must be
    /// ignored when the target creates fresh ratchets.
    pub reset_peers: &'a [[u8; 32]],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded projection from already-durable device-sync control state.
pub struct DeviceProjectionPlan<'a> {
    /// Exact row projections owned by one resolved sync event.
    pub projections: &'a [DeviceProjection<'a>],
    /// Exact ratchet sessions retired by a revoked endpoint.
    pub delete_sessions: &'a [SessionDelete<'a>],
    /// Exact capability snapshots retired with those sessions.
    pub delete_capabilities: &'a [CapabilityDelete<'a>],
    /// Exact queued ciphertext rows invalidated by the endpoint transition.
    pub delete_queue: &'a [QueueDelete],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of one pairwise send.
pub struct PairwiseSendPlan<'a> {
    /// Every detached sending-session candidate advanced by the fan-out.
    pub sessions: &'a [SessionTransition<'a>],
    /// Immutable local history, absent for protocol control traffic.
    pub message: Option<&'a MessageRecord>,
    /// Exact history update when a previously unavailable device becomes usable.
    pub message_update: Option<MessageTransition<'a>>,
    /// Honest per-device delivery rows created with new history.
    pub deliveries: &'a [MessageDeviceDeliveryRecord],
    /// Exact delivery updates for a previously retained history row.
    pub delivery_updates: &'a [DeliveryTransition<'a>],
    /// Every ciphertext produced by the candidate sessions.
    pub queue: &'a [QueueItem],
    /// Exact pending-announcement ownership updates for group controls.
    pub groups: &'a [GroupTransition<'a>],
    /// Exact authority bookkeeping owned by an encrypted group-control response.
    pub authorities: &'a [GroupAuthorityStateTransition<'a>],
    /// Exact scheduled record consumed by activation, when applicable.
    pub scheduled: Option<&'a ScheduledMessageRecord>,
    /// Session-bound capability snapshots invalidated by new handshakes.
    pub clear_capabilities: &'a [[u8; 32]],
    /// Exact restore markers consumed by successful reset handshakes.
    pub clear_reset_markers: &'a [[u8; 32]],
    /// Optional local ephemeral marker created with history.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Attachment transfer rows activated by this exact manifest send.
    pub media_transfers: &'a [MediaTransferTransition<'a>],
    /// Attachment object progress owned by an encrypted bulk control.
    pub media_objects: &'a [MediaObjectTransition<'a>],
    /// Accepted controls consumed by the resulting encrypted response.
    pub delete_controls: &'a [DeferredControlRecord],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of one sender-key group send or late fan-out.
pub struct GroupSendPlan<'a> {
    /// Sender-chain/group-state replacement when this transition encrypts.
    /// Late fan-out of an already retained ciphertext leaves this `None`.
    pub group: Option<GroupTransition<'a>>,
    /// Immutable outbound group history created by this send.
    pub message: Option<&'a GroupMessageRecord>,
    /// Exact retained-history replacement for attachment activation or late fan-out.
    pub message_update: Option<GroupMessageTransition<'a>>,
    /// Honest per-device delivery rows created with ciphertext copies.
    pub deliveries: &'a [MessageDeviceDeliveryRecord],
    /// Exact placeholder or delivery-row replacements.
    pub delivery_updates: &'a [DeliveryTransition<'a>],
    /// Every recipient-scoped envelope that owns the produced group ciphertext.
    pub queue: &'a [QueueItem],
    /// Exact scheduled record consumed by activation, when applicable.
    pub scheduled: Option<&'a ScheduledMessageRecord>,
    /// Optional local ephemeral marker created with history.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Attachment transfer rows activated by this exact manifest send.
    pub media_transfers: &'a [MediaTransferTransition<'a>],
    /// Receiver chains removed by the roster transition carried by this send.
    pub delete_chains: &'a [GroupChainStateTransition<'a>],
    /// Optional signed authority state committed with its immutable announcement.
    pub authority: Option<GroupAuthorityTransition<'a>>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of one sender-key group receive.
pub struct GroupReceivePlan<'a> {
    /// Detached group receiver-chain candidate.
    pub chain: GroupChainTransition<'a>,
    /// Detached pairwise sending-session candidate used by the receipt.
    pub receipt_session: SessionTransition<'a>,
    /// Accepted immutable group history, if this content creates one.
    pub message: Option<&'a GroupMessageRecord>,
    /// Optional local ephemeral marker or tombstone.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Attachment-offer transfer metadata created by accepted content.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Attachment-offer object metadata created by accepted content.
    pub media_objects: &'a [MediaObjectRecord],
    /// Encrypted receipt produced by the detached pairwise candidate.
    pub queue: &'a [QueueItem],
    /// Authenticated group envelope content id used for replay absorption.
    pub content_id: [u8; 16],
    /// Local receive time retained with duplicate-receipt routing.
    pub received_at: u64,
    /// Exact deferred source row, when this input came from the durable inbox.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete local metadata stage for one outbound attachment manifest.
///
/// Chunk files are committed through the media store's file-first chunk
/// protocol after this plan succeeds. The manifest is not eligible for
/// encryption until every staged object is complete.
pub struct AttachmentStagePlan<'a> {
    /// Pairwise history created by this stage.
    pub message: Option<&'a MessageRecord>,
    /// Group history created by this stage.
    pub group_message: Option<&'a GroupMessageRecord>,
    /// New transfer rows owned by the manifest history.
    pub media_transfers: &'a [MediaTransferRecord],
    /// New object rows owned by those transfers.
    pub media_objects: &'a [MediaObjectRecord],
    /// Optional view-once marker created with the manifest.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded attachment lifecycle or progress transition.
pub struct AttachmentStatePlan<'a> {
    /// Exact transfer-level replacements.
    pub media_transfers: &'a [MediaTransferTransition<'a>],
    /// Exact object-level replacements.
    pub media_objects: &'a [MediaObjectTransition<'a>],
    /// Accepted authenticated controls consumed by the transition.
    pub delete_controls: &'a [DeferredControlRecord],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded group membership, announcement, authority, or deferred-control transition.
pub struct GroupStatePlan<'a> {
    /// Group creations, replacements, or removals.
    pub groups: &'a [GroupStateTransition<'a>],
    /// Receiver-chain creations, replacements, or removals.
    pub chains: &'a [GroupChainStateTransition<'a>],
    /// Contact stubs authenticated by the accepted roster.
    pub contacts: &'a [ContactTransition<'a>],
    /// Signed authority state creations or replacements.
    pub authorities: &'a [GroupAuthorityStateTransition<'a>],
    /// Accepted controls consumed by this exact state transition.
    pub delete_controls: &'a [DeferredControlRecord],
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of one pairwise message/control receive.
pub struct PairwiseReceivePlan<'a> {
    /// Detached receiving candidate, including an optional receipt send step.
    pub session: SessionTransition<'a>,
    /// Accepted immutable history row, if this content creates one.
    pub message: Option<&'a MessageRecord>,
    /// Optional local ephemeral marker or tombstone.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Attachment offer transfer metadata created by accepted content.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Attachment offer object metadata created by accepted content.
    pub media_objects: &'a [MediaObjectRecord],
    /// Authenticated capability snapshot carried as pairwise control.
    pub capabilities: Option<&'a CapabilityControl>,
    /// Outbound receipt/control ciphertext produced by the same candidate.
    pub queue: &'a [QueueItem],
    /// Authenticated envelope content id used for replay absorption.
    pub content_id: [u8; 16],
    /// Local receive time retained with an optional duplicate-receipt route.
    pub received_at: u64,
    /// Whether duplicate delivery should replay a receipt to this route.
    pub receipt_replay: bool,
    /// Exact deferred source row, when this input came from the durable inbox.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Exact prekey-vault replacement performed by issuance or an inbound handshake.
pub struct PrekeyTransition<'a> {
    /// Encoded durable vault expected before the transaction, or `None`
    /// while completing a recovered profile.
    pub before: Option<&'a [u8]>,
    /// Encoded candidate vault after one-time-prekey issuance or consumption.
    pub after: &'a [u8],
}

/// One newly issued prekey bundle and the vault state that owns its OPK.
pub struct PrekeyPublishPlan<'a> {
    /// Exact vault replacement that makes the returned bundle usable.
    pub prekeys: PrekeyTransition<'a>,
}

/// Complete durable consequences of accepting one inbound handshake.
pub struct HandshakeReceivePlan<'a> {
    /// Optional one-time-prekey consumption.
    pub prekeys: Option<PrekeyTransition<'a>>,
    /// Newly established detached session.
    pub session: SessionTransition<'a>,
    /// Contact stub or authenticated contact update.
    pub contact: &'a ContactRecord,
    /// Authenticated physical-device endpoint updates.
    pub devices: &'a [ContactDeviceRecord],
    /// Superseded legacy endpoint rows removed by the same manifest.
    pub delete_devices: &'a [ContactDeviceDelete<'a>],
    /// Superseded or revoked sessions removed by the same manifest.
    pub delete_sessions: &'a [[u8; 32]],
    /// Session-bound capability rows removed by the same manifest.
    pub delete_capabilities: &'a [[u8; 32]],
    /// Exact queued envelopes invalidated by revoked/superseded sessions.
    pub delete_queue: &'a [QueueDelete],
    /// Group announce state changed by session establishment.
    pub groups: &'a [GroupTransition<'a>],
    /// Optional accepted anonymous first-flight history.
    pub message: Option<&'a MessageRecord>,
    /// Optional first-flight ephemeral state.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Optional first-flight attachment transfer rows.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Optional first-flight attachment object rows.
    pub media_objects: &'a [MediaObjectRecord],
    /// Encrypted receipt generated from the newly established candidate.
    pub queue: &'a [QueueItem],
    /// Handshake envelope content id.
    pub content_id: [u8; 16],
    /// Local receive time retained with duplicate-receipt routing.
    pub received_at: u64,
    /// Whether the accepted first flight needs duplicate receipt replay.
    pub receipt_replay: bool,
    /// Exact deferred source row, when applicable.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of an encrypted receipt/control receive.
pub struct ReceiptReceivePlan<'a> {
    /// Detached session after receive and any response encryption.
    pub session: SessionTransition<'a>,
    /// Exact outbound envelopes acknowledged by the receipt.
    pub delete_queue: &'a [QueueDelete],
    /// Selective retransmissions or control responses created by this receipt.
    pub queue: &'a [QueueItem],
    /// Pairwise aggregate message-state changes.
    pub messages: &'a [MessageTransition<'a>],
    /// Per-device delivery-state changes.
    pub deliveries: &'a [DeliveryTransition<'a>],
    /// Group aggregate delivery changes.
    pub group_messages: &'a [GroupMessageTransition<'a>],
    /// Group pending-announce changes retired by acknowledgements.
    pub groups: &'a [GroupTransition<'a>],
    /// Attachment transfer metadata changes.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Attachment object metadata changes.
    pub media_objects: &'a [MediaObjectRecord],
    /// Authenticated capability snapshot carried by this control.
    pub capabilities: Option<&'a CapabilityControl>,
    /// Immutable control work retained before filesystem or group callbacks.
    pub deferred_control: Option<&'a DeferredControlRecord>,
    /// Receipt envelope content id.
    pub content_id: [u8; 16],
    /// Exact deferred source row, when applicable.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded expiry, retry, rejection, or acknowledgement transaction.
pub struct MaintenancePlan<'a> {
    /// Terminal envelope ids recorded as seen with their exact pending removal.
    pub seen: &'a [[u8; 16]],
    /// Exact deferred rows removed by terminal handling.
    pub delete_pending: &'a [PendingDelete],
    /// Exact outbound rows removed by expiry or terminal delivery.
    pub delete_queue: &'a [QueueDelete],
    /// Exact outbound scheduling updates.
    pub update_queue: &'a [QueueTransition<'a>],
    /// Duplicate-receipt routes removed after their bounded replay window.
    pub delete_replay: &'a [[u8; 16]],
    /// Pairwise aggregate delivery updates.
    pub messages: &'a [MessageTransition<'a>],
    /// Per-device delivery updates.
    pub deliveries: &'a [DeliveryTransition<'a>],
    /// Group aggregate delivery updates.
    pub group_messages: &'a [GroupMessageTransition<'a>],
    /// Group state updates such as bounded pending announce expiry.
    pub groups: &'a [GroupTransition<'a>],
    /// Ephemeral active-state to tombstone transitions.
    pub ephemeral: &'a [EphemeralTransition<'a>],
    /// Pairwise plaintext rows removed after a tombstone.
    pub delete_messages: &'a [MessageDelete<'a>],
    /// Group plaintext rows removed after a tombstone.
    pub delete_group_messages: &'a [GroupMessageDelete<'a>],
    /// Media metadata removed after a tombstone.
    pub delete_media: &'a [MediaDelete<'a>],
    /// Exact scheduled records removed by terminal cancellation.
    pub delete_scheduled: &'a [ScheduledMessageRecord],
    /// Exact stale ratchet sessions retired by bounded repair.
    pub delete_sessions: &'a [[u8; 32]],
    /// Exact session-bound capability snapshots retired with those sessions.
    pub delete_capabilities: &'a [[u8; 32]],
    /// Exact restore markers consumed by bounded reset upkeep.
    pub clear_reset_markers: &'a [[u8; 32]],
    /// Exact accepted controls acknowledged after idempotent follow-up.
    pub delete_controls: &'a [DeferredControlRecord],
    /// Exact presentation marker acknowledged after event delivery.
    pub acknowledge_presentation: Option<[u8; 16]>,
    /// Whether this maintenance transition itself changes presentation.
    pub presentation_changed: bool,
}

/// The only protocol-state transaction variants exposed by the store.
pub enum CommitPlan<'a> {
    /// Initial account, device, and prekey publication.
    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    ProfileBootstrap(ProfileBootstrapPlan<'a>),
    /// Initial offline-root account, device, and prekey publication.
    AuthorityProfileBootstrap(AuthorityProfileBootstrapPlan<'a>),
    /// Explicit single-device Alpha conversion that removes the live account root.
    AuthorityMigration(AuthorityMigrationPlan<'a>),
    /// Prekey bundle issuance.
    PrekeyPublish(PrekeyPublishPlan<'a>),
    /// Pairwise send.
    PairwiseSend(PairwiseSendPlan<'a>),
    /// Pairwise receive.
    PairwiseReceive(PairwiseReceivePlan<'a>),
    /// Sender-key group send or late fan-out.
    GroupSend(GroupSendPlan<'a>),
    /// Sender-key group receive.
    GroupReceive(GroupReceivePlan<'a>),
    /// Local outbound attachment metadata stage.
    AttachmentStage(AttachmentStagePlan<'a>),
    /// Attachment lifecycle, progress, or deferred-control transition.
    AttachmentState(AttachmentStatePlan<'a>),
    /// Group membership, authority, chain, or deferred-control transition.
    GroupState(GroupStatePlan<'a>),
    /// Linked-device authority, channel counter, convergence-log, or rotation transition.
    DeviceControl(DeviceControlPlan<'a>),
    /// Offline-root linked-device authority and related atomic state.
    AuthorityDeviceControl(AuthorityDeviceControlPlan<'a>),
    /// Confirmed bounded link import onto a pristine target.
    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    DeviceLink(DeviceLinkPlan<'a>),
    /// Confirmed root-free link import onto a pristine target.
    AuthorityDeviceLink(AuthorityDeviceLinkPlan<'a>),
    /// One idempotent projection from already-durable device-sync state.
    DeviceProjection(DeviceProjectionPlan<'a>),
    /// Handshake receive.
    HandshakeReceive(HandshakeReceivePlan<'a>),
    /// Receipt or authenticated pairwise control receive.
    ReceiptReceive(ReceiptReceivePlan<'a>),
    /// Bounded maintenance.
    Maintenance(MaintenancePlan<'a>),
}

/// Stable identities returned only after a successful commit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedRecordIds {
    /// Pairwise message ids created or updated.
    pub messages: Vec<[u8; 16]>,
    /// Newly appended outbound row sequences.
    pub queue_sequences: Vec<i64>,
}

/// Proof returned after SQLite accepted the complete typed transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Random identifier for this complete transition.
    pub transaction_id: [u8; 16],
    /// Stable record identities produced by the transaction.
    pub records: CommittedRecordIds,
    /// Marker that must be acknowledged after presentation delivery.
    pub presentation_marker: Option<[u8; 16]>,
    /// Number of bounded logical write statements applied.
    pub statement_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PresentationMarker {
    transaction_id: [u8; 16],
}

/// Deterministic store commit injection location used by crash-matrix tests.
#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFailpoint {
    /// Immediately before `BEGIN IMMEDIATE`.
    BeforeBegin,
    /// Immediately after `BEGIN IMMEDIATE`.
    AfterBegin,
    /// Before the numbered logical write statement, starting at zero.
    BeforeStatement(usize),
    /// After the numbered logical write statement, starting at zero.
    AfterStatement(usize),
    /// Immediately before `COMMIT`.
    BeforeCommit,
    /// Immediately after a successful `COMMIT`.
    AfterCommit,
}

/// Failure class produced by an armed deterministic store failpoint.
#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFailure {
    /// Process-interruption equivalent.
    Interrupted,
    /// Disk-full equivalent.
    DiskFull,
    /// Constraint-failure equivalent.
    Constraint,
    /// Duplicate-index equivalent.
    Duplicate,
}

#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy)]
pub(crate) struct ArmedCommitFailpoint {
    pub(crate) point: CommitFailpoint,
    pub(crate) failure: CommitFailure,
}

impl Store {
    /// Apply one bounded typed protocol transition using `BEGIN IMMEDIATE`.
    pub fn commit_plan(
        &self,
        plan: CommitPlan<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<CommitReceipt> {
        self.validate_commit_plan(&plan)?;
        let presentation_changed = match &plan {
            #[cfg(any(test, feature = "legacy-test-fixtures"))]
            CommitPlan::ProfileBootstrap(_) => false,
            CommitPlan::AuthorityProfileBootstrap(_) => false,
            CommitPlan::AuthorityMigration(_) => false,
            CommitPlan::PrekeyPublish(_) => false,
            CommitPlan::PairwiseSend(plan) => plan.presentation_changed,
            CommitPlan::PairwiseReceive(plan) => plan.presentation_changed,
            CommitPlan::GroupSend(plan) => plan.presentation_changed,
            CommitPlan::GroupReceive(plan) => plan.presentation_changed,
            CommitPlan::AttachmentStage(plan) => plan.presentation_changed,
            CommitPlan::AttachmentState(plan) => plan.presentation_changed,
            CommitPlan::GroupState(plan) => plan.presentation_changed,
            CommitPlan::DeviceControl(plan) => plan.presentation_changed,
            CommitPlan::AuthorityDeviceControl(plan) => plan.presentation_changed,
            #[cfg(any(test, feature = "legacy-test-fixtures"))]
            CommitPlan::DeviceLink(plan) => plan.presentation_changed,
            CommitPlan::AuthorityDeviceLink(plan) => plan.presentation_changed,
            CommitPlan::DeviceProjection(plan) => plan.presentation_changed,
            CommitPlan::HandshakeReceive(plan) => plan.presentation_changed,
            CommitPlan::ReceiptReceive(plan) => plan.presentation_changed,
            CommitPlan::Maintenance(plan) => plan.presentation_changed,
        };
        let mut transaction_id = [0u8; 16];
        rng.fill_bytes(&mut transaction_id);
        if transaction_id == [0u8; 16] {
            transaction_id[0] = 1;
        }

        self.check_commit_failpoint(CommitPoint::BeforeBegin)?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let mut writer = CommitWriter {
            store: self,
            rng,
            statement: 0,
            records: CommittedRecordIds::default(),
        };
        let result = (|| {
            writer
                .store
                .check_commit_failpoint(CommitPoint::AfterBegin)?;
            match plan {
                #[cfg(any(test, feature = "legacy-test-fixtures"))]
                CommitPlan::ProfileBootstrap(plan) => writer.profile_bootstrap(&plan)?,
                CommitPlan::AuthorityProfileBootstrap(plan) => {
                    writer.authority_profile_bootstrap(&plan)?
                }
                CommitPlan::AuthorityMigration(plan) => writer.authority_migration(&plan)?,
                CommitPlan::PrekeyPublish(plan) => writer.prekey_publish(&plan)?,
                CommitPlan::PairwiseSend(plan) => writer.pairwise_send(&plan)?,
                CommitPlan::PairwiseReceive(plan) => writer.pairwise_receive(&plan)?,
                CommitPlan::GroupSend(plan) => writer.group_send(&plan)?,
                CommitPlan::GroupReceive(plan) => writer.group_receive(&plan)?,
                CommitPlan::AttachmentStage(plan) => writer.attachment_stage(&plan)?,
                CommitPlan::AttachmentState(plan) => writer.attachment_state(&plan)?,
                CommitPlan::GroupState(plan) => writer.group_state(&plan)?,
                CommitPlan::DeviceControl(plan) => writer.device_control(&plan)?,
                CommitPlan::AuthorityDeviceControl(plan) => {
                    writer.authority_device_control(&plan)?
                }
                #[cfg(any(test, feature = "legacy-test-fixtures"))]
                CommitPlan::DeviceLink(plan) => writer.device_link(&plan)?,
                CommitPlan::AuthorityDeviceLink(plan) => writer.authority_device_link(&plan)?,
                CommitPlan::DeviceProjection(plan) => writer.device_projection(&plan)?,
                CommitPlan::HandshakeReceive(plan) => writer.handshake_receive(&plan)?,
                CommitPlan::ReceiptReceive(plan) => writer.receipt_receive(&plan)?,
                CommitPlan::Maintenance(plan) => writer.maintenance(&plan)?,
            }
            if presentation_changed {
                writer.write(|store, rng| {
                    let marker = postcard::to_allocvec(&PresentationMarker { transaction_id })
                        .map_err(|_| StoreError::Serialization)?;
                    store.put_equality::<store_v2::PresentationMarkerRows>(
                        &store_v2::SingletonKey,
                        &marker,
                        store_v2::IndexKeys::none(),
                        rng,
                    )
                })?;
            }
            writer
                .store
                .check_commit_failpoint(CommitPoint::BeforeCommit)?;
            writer.store.conn.execute_batch("COMMIT")?;
            writer
                .store
                .check_commit_failpoint(CommitPoint::AfterCommit)?;
            Ok(CommitReceipt {
                transaction_id,
                records: writer.records,
                presentation_marker: presentation_changed.then_some(transaction_id),
                statement_count: writer.statement,
            })
        })();
        if result.is_err() && !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        result
    }

    /// Return the unacknowledged deterministic presentation-resync marker.
    pub fn presentation_resync_marker(&self) -> Result<Option<[u8; 16]>> {
        self.get_equality::<store_v2::PresentationMarkerRows>(&store_v2::SingletonKey)?
            .map(|row| {
                row.verify_key(&store_v2::SingletonKey)?;
                let marker: PresentationMarker = decode_exact(&row.payload)?;
                if marker.transaction_id == [0u8; 16] {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(marker.transaction_id)
            })
            .transpose()
    }

    /// Validate the bounded presentation marker during store open.
    pub(crate) fn validate_presentation_marker(&self) -> Result<()> {
        self.validate_rows::<store_v2::PresentationMarkerRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let marker: PresentationMarker = decode_exact(&row.payload)?;
            if marker.transaction_id == [0u8; 16] {
                return Err(StoreError::LogicalKeyMismatch);
            }
            Ok(())
        })
    }

    /// Arm one deterministic transaction failure for the next matching point.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn arm_commit_failpoint(&self, point: CommitFailpoint, failure: CommitFailure) {
        self.commit_failpoint
            .replace(Some(ArmedCommitFailpoint { point, failure }));
    }

    /// Remove any armed deterministic transaction failure.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn clear_commit_failpoint(&self) {
        self.commit_failpoint.replace(None);
    }

    fn validate_commit_plan(&self, plan: &CommitPlan<'_>) -> Result<()> {
        match plan {
            #[cfg(any(test, feature = "legacy-test-fixtures"))]
            CommitPlan::ProfileBootstrap(plan) => self.validate_profile_bootstrap(plan),
            CommitPlan::AuthorityProfileBootstrap(plan) => {
                self.validate_authority_profile_bootstrap(plan)
            }
            CommitPlan::AuthorityMigration(plan) => self.validate_authority_migration(plan),
            CommitPlan::PrekeyPublish(plan) => self.validate_prekey_publish(plan),
            CommitPlan::PairwiseSend(plan) => self.validate_pairwise_send(plan),
            CommitPlan::PairwiseReceive(plan) => self.validate_pairwise_receive(plan),
            CommitPlan::GroupSend(plan) => self.validate_group_send(plan),
            CommitPlan::GroupReceive(plan) => self.validate_group_receive(plan),
            CommitPlan::AttachmentStage(plan) => self.validate_attachment_stage(plan),
            CommitPlan::AttachmentState(plan) => self.validate_attachment_state(plan),
            CommitPlan::GroupState(plan) => self.validate_group_state(plan),
            CommitPlan::DeviceControl(plan) => self.validate_device_control(plan),
            CommitPlan::AuthorityDeviceControl(plan) => {
                self.validate_authority_device_control(plan)
            }
            #[cfg(any(test, feature = "legacy-test-fixtures"))]
            CommitPlan::DeviceLink(plan) => self.validate_device_link(plan),
            CommitPlan::AuthorityDeviceLink(plan) => self.validate_authority_device_link(plan),
            CommitPlan::DeviceProjection(plan) => self.validate_device_projection(plan),
            CommitPlan::HandshakeReceive(plan) => self.validate_handshake_receive(plan),
            CommitPlan::ReceiptReceive(plan) => self.validate_receipt_receive(plan),
            CommitPlan::Maintenance(plan) => self.validate_maintenance(plan),
        }
    }

    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    fn validate_profile_bootstrap(&self, plan: &ProfileBootstrapPlan<'_>) -> Result<()> {
        if plan.prekeys.is_empty()
            || self.get_identity()?.is_some()
            || self.get_device_state()?.is_some()
            || self.get_prekeys()?.is_some()
        {
            return Err(StoreError::InvalidTransition);
        }
        plan.identity.public().verify()?;
        plan.device_state.validate(plan.identity)
    }

    fn validate_authority_profile_bootstrap(
        &self,
        plan: &AuthorityProfileBootstrapPlan<'_>,
    ) -> Result<()> {
        if plan.prekeys.is_empty()
            || self.get_identity()?.is_some()
            || self.get_account_identity()?.is_some()
            || self.get_device_state()?.is_some()
            || self.get_device_authority_state()?.is_some()
            || self.get_prekeys()?.is_some()
        {
            return Err(StoreError::InvalidTransition);
        }
        plan.account.verify()?;
        plan.device_state.validate(plan.account)
    }

    fn validate_authority_migration(&self, plan: &AuthorityMigrationPlan<'_>) -> Result<()> {
        let current_identity = self.get_identity()?.ok_or(StoreError::InvalidTransition)?;
        if !identity_eq(&current_identity, plan.legacy_identity)
            || self.get_account_identity()?.is_some()
            || self.get_device_state()?.as_ref() != Some(plan.legacy_device_state)
            || self.get_device_authority_state()?.is_some()
            || self.get_prekeys()?.is_none()
            || plan.account != &plan.legacy_identity.public()
            || plan.legacy_device_state.manifest.devices.len() != 1
            || !plan.legacy_device_state.channels.is_empty()
        {
            return Err(StoreError::InvalidTransition);
        }
        plan.account.verify()?;
        plan.device_state.validate(plan.account)?;
        if plan.device_state.local_device_secret != plan.legacy_device_state.local_device_secret
            || plan.device_state.sync_counter != plan.legacy_device_state.sync_counter
            || !plan.device_state.channels.is_empty()
            || plan.device_state.manifest.generation() != 1
            || plan.device_state.manifest.recovery_epoch() != 0
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_prekey_publish(&self, plan: &PrekeyPublishPlan<'_>) -> Result<()> {
        if plan.prekeys.before.is_some_and(<[u8]>::is_empty)
            || plan.prekeys.after.is_empty()
            || plan.prekeys.before == Some(plan.prekeys.after)
            || self.get_prekeys()?.as_ref().map(|value| value.as_slice()) != plan.prekeys.before
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_pairwise_send(&self, plan: &PairwiseSendPlan<'_>) -> Result<()> {
        if plan.sessions.is_empty()
            || plan.sessions.len() > MAX_PAIRWISE_COMMIT_DEVICES
            || plan.queue.is_empty()
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || mutation_count([
                plan.sessions.len(),
                usize::from(plan.message.is_some()),
                usize::from(plan.message_update.is_some()),
                plan.deliveries.len(),
                plan.delivery_updates.len(),
                plan.queue.len(),
                plan.groups.len(),
                plan.authorities.len(),
                usize::from(plan.scheduled.is_some()),
                plan.clear_capabilities.len(),
                plan.clear_reset_markers.len(),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                plan.delete_controls.len(),
            ])? > MAX_COMMIT_MUTATIONS
            || plan.groups.len() > MAX_GROUP_AUTHORITY_MEMBERS
            || plan.authorities.len() > MAX_GROUP_AUTHORITY_MEMBERS
        {
            return Err(StoreError::InvalidTransition);
        }
        let routes = plan
            .sessions
            .iter()
            .map(|transition| transition.peer_device)
            .collect::<HashSet<_>>();
        let queue_ids = plan
            .queue
            .iter()
            .map(|item| item.envelope.content_id())
            .collect::<HashSet<_>>();
        if routes.len() != plan.sessions.len()
            || queue_ids.len() != plan.queue.len()
            || plan.queue.iter().any(|item| !routes.contains(&item.peer))
            || plan.queue.iter().any(|item| item.group_msg_id.is_some())
            || routes
                .iter()
                .any(|route| !plan.queue.iter().any(|item| item.peer == *route))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.sessions {
            self.validate_session_transition(transition)?;
        }
        for transition in plan.groups {
            self.validate_group_transition(transition)?;
            validate_group_control_transition(transition, plan.queue)?;
        }
        let authority_ids = plan
            .authorities
            .iter()
            .filter_map(|transition| transition.after.map(|authority| authority.group))
            .collect::<HashSet<_>>();
        if authority_ids.len() != plan.authorities.len()
            || (!plan.authorities.is_empty()
                && !plan
                    .queue
                    .iter()
                    .any(|item| item.envelope.kind == EnvelopeKind::GroupControl))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.authorities {
            let (Some(before), Some(after)) = (transition.before, transition.after) else {
                return Err(StoreError::InvalidTransition);
            };
            if before.group != after.group
                || before.state_id != after.state_id
                || before.state_payload != after.state_payload
                || before.consumed_requests == after.consumed_requests
                || self.get_group_authority(&before.group)?.as_ref() != Some(before)
                || !valid_group_authority_record(after)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        if plan.message.is_some() && plan.message_update.is_some() {
            return Err(StoreError::InvalidTransition);
        }
        let history_id = if let Some(message) = plan.message {
            if message.direction != Direction::Outbound
                || message.state != DeliveryState::Queued
                || self
                    .messages_with(&message.peer)?
                    .iter()
                    .any(|existing| existing.id == message.id)
                || plan
                    .queue
                    .iter()
                    .any(|item| item.msg_id != Some(message.id))
                || plan.deliveries.iter().any(|delivery| {
                    delivery.message != message.id || delivery.account != message.peer
                })
            {
                return Err(StoreError::InvalidTransition);
            }
            Some(message.id)
        } else if let Some(transition) = &plan.message_update {
            self.validate_message_transition(transition)?;
            if transition.after.direction != Direction::Outbound
                || plan
                    .queue
                    .iter()
                    .any(|item| item.msg_id != Some(transition.after.id))
            {
                return Err(StoreError::InvalidTransition);
            }
            Some(transition.after.id)
        } else {
            None
        };
        if history_id.is_none()
            && (!plan.deliveries.is_empty()
                || !plan.delivery_updates.is_empty()
                || plan.queue.iter().any(|item| item.msg_id.is_some()))
        {
            return Err(StoreError::InvalidTransition);
        }
        if history_id.is_some() && !plan.groups.is_empty() {
            return Err(StoreError::InvalidTransition);
        }
        if plan.deliveries.iter().any(|delivery| {
            Some(delivery.message) != history_id || delivery.state != DeliveryState::Queued
        }) {
            return Err(StoreError::InvalidTransition);
        }
        if plan
            .delivery_updates
            .iter()
            .any(|transition| Some(transition.after.message) != history_id)
        {
            return Err(StoreError::InvalidTransition);
        }
        let mut delivery_routes = HashSet::new();
        if plan
            .deliveries
            .iter()
            .map(|delivery| delivery.device)
            .chain(
                plan.delivery_updates
                    .iter()
                    .map(|transition| transition.after.device),
            )
            .any(|device| !delivery_routes.insert(device))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.delivery_updates {
            self.validate_delivery_transition(transition)?;
        }
        if let Some(history_id) = history_id {
            let history_peer = plan.message.map_or_else(
                || {
                    plan.message_update
                        .as_ref()
                        .expect("history exists")
                        .after
                        .peer
                },
                |message| message.peer,
            );
            let existing_queue = self.queue_all()?;
            for delivery in plan.deliveries.iter().chain(
                plan.delivery_updates
                    .iter()
                    .map(|transition| transition.after),
            ) {
                if delivery.account != history_peer || delivery.state != DeliveryState::Queued {
                    return Err(StoreError::InvalidTransition);
                }
                if let Some(wire_id) = delivery.wire_id {
                    let owned = plan.queue.iter().any(|item| {
                        item.peer == delivery.device
                            && item.msg_id == Some(history_id)
                            && item.envelope.content_id() == wire_id
                    }) || existing_queue.iter().any(|(_, item)| {
                        item.peer == delivery.device
                            && item.msg_id == Some(history_id)
                            && item.envelope.content_id() == wire_id
                    });
                    if !owned {
                        return Err(StoreError::InvalidTransition);
                    }
                }
            }
            for item in plan.queue {
                let wire_id = item.envelope.content_id();
                let owners = plan
                    .deliveries
                    .iter()
                    .filter(|delivery| {
                        delivery.message == history_id
                            && delivery.account == history_peer
                            && delivery.device == item.peer
                            && delivery.wire_id == Some(wire_id)
                            && delivery.state == DeliveryState::Queued
                    })
                    .count()
                    + plan
                        .delivery_updates
                        .iter()
                        .filter(|transition| {
                            transition.after.message == history_id
                                && transition.after.account == history_peer
                                && transition.after.device == item.peer
                                && transition.after.wire_id == Some(wire_id)
                                && transition.after.state == DeliveryState::Queued
                        })
                        .count();
                if owners != 1 {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        if let Some(scheduled) = plan.scheduled {
            if self.get_scheduled_message(&scheduled.id)?.as_ref() != Some(scheduled)
                || plan
                    .message
                    .is_none_or(|message| message.id != scheduled.id)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        if let Some(ephemeral) = plan.ephemeral {
            if Some(ephemeral.content_id) != history_id
                || ephemeral.conversation
                    != crate::EphemeralConversation::Pairwise(plan.message.map_or_else(
                        || {
                            plan.message_update
                                .as_ref()
                                .expect("history exists")
                                .after
                                .peer
                        },
                        |message| message.peer,
                    ))
                || self
                    .get_ephemeral_record(
                        &ephemeral.conversation,
                        &ephemeral.author,
                        &ephemeral.content_id,
                    )?
                    .is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.media_transfers {
            self.validate_media_transfer_transition(transition)?;
            if history_id
                .is_some_and(|history_id| transition.after.manifest_content_id != history_id)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.media_objects {
            self.validate_media_object_transition(transition)?;
        }
        for control in plan.delete_controls {
            if self.get_deferred_control(&control.content_id)?.as_ref() != Some(control) {
                return Err(StoreError::InvalidTransition);
            }
        }
        let reset_markers = self.reset_markers()?.into_iter().collect::<HashSet<_>>();
        if plan
            .clear_reset_markers
            .iter()
            .any(|marker| !reset_markers.contains(marker))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_pairwise_receive(&self, plan: &PairwiseReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.content_id == [0u8; 16]
            || plan.message.is_some_and(|message| {
                message.direction != Direction::Inbound
                    || message.state != DeliveryState::Received
                    || message.wire_id.is_some()
            })
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
                    || item.envelope.kind != EnvelopeKind::Receipt
            })
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || mutation_count([
                1,
                usize::from(plan.message.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                usize::from(plan.capabilities.is_some()),
                plan.queue.len(),
                1,
                usize::from(plan.receipt_replay),
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(message) = plan.message {
            self.validate_new_message(message)?;
        }
        self.validate_pending(plan.source_pending)?;
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        let accepted_state = plan.message.is_some()
            || plan.ephemeral.is_some()
            || !plan.media_transfers.is_empty()
            || !plan.media_objects.is_empty()
            || plan.capabilities.is_some();
        if (plan.receipt_replay && plan.queue.is_empty())
            || (accepted_state && (!plan.receipt_replay || plan.queue.is_empty()))
            || (self.is_seen(&plan.content_id)?
                && (accepted_state || !plan.receipt_replay || plan.queue.is_empty()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_send(&self, plan: &GroupSendPlan<'_>) -> Result<()> {
        if plan.message.is_some() == plan.message_update.is_some()
            || plan.queue.len() > MAX_GROUP_COMMIT_QUEUE_ROWS
            || mutation_count([
                usize::from(plan.group.is_some()),
                usize::from(plan.message.is_some()),
                usize::from(plan.message_update.is_some()),
                plan.deliveries.len(),
                plan.delivery_updates.len(),
                plan.queue.len(),
                usize::from(plan.scheduled.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.delete_chains.len(),
                usize::from(plan.authority.is_some()),
            ])? > MAX_GROUP_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }

        let (message_id, group_id, message_after, retained_wire) =
            if let Some(message) = plan.message {
                self.validate_new_group_message(message)?;
                if message.direction != Direction::Outbound {
                    return Err(StoreError::InvalidTransition);
                }
                (message.id, message.group, message, None)
            } else {
                let transition = plan
                    .message_update
                    .as_ref()
                    .ok_or(StoreError::InvalidTransition)?;
                self.validate_group_message_transition(transition)?;
                if transition.after.direction != Direction::Outbound {
                    return Err(StoreError::InvalidTransition);
                }
                (
                    transition.after.id,
                    transition.after.group,
                    transition.after,
                    transition.before.wire_body.as_deref(),
                )
            };

        if let Some(group) = &plan.group {
            self.validate_group_transition(group)?;
            if group.after.id != group_id || group.before.sender_chain == group.after.sender_chain {
                return Err(StoreError::InvalidTransition);
            }
        } else if retained_wire.is_none() || plan.message.is_some() {
            // A plan without a sender-chain transition may only fan out an
            // already durable ciphertext retained by the exact prior row.
            return Err(StoreError::InvalidTransition);
        }
        let stored_distribution_group = if plan.group.is_none() {
            self.get_group(&group_id)?
        } else {
            None
        };
        let distribution_group = plan
            .group
            .as_ref()
            .map(|group| group.before)
            .or(stored_distribution_group.as_ref())
            .ok_or(StoreError::InvalidTransition)?;
        let eligible_accounts = distribution_group
            .members
            .iter()
            .filter(|member| member.peer != message_after.sender)
            .map(|member| member.peer)
            .collect::<HashSet<_>>();
        let history_accounts = message_after
            .deliveries
            .iter()
            .map(|delivery| delivery.peer)
            .collect::<HashSet<_>>();
        if history_accounts.len() != message_after.deliveries.len()
            || history_accounts != eligible_accounts
            || plan.queue.len()
                > eligible_accounts
                    .len()
                    .saturating_mul(MAX_PAIRWISE_COMMIT_DEVICES)
        {
            return Err(StoreError::InvalidTransition);
        }
        validate_outbound_group_origin(message_after.origin)?;
        if plan.group.is_some()
            && !eligible_accounts.is_empty()
            && plan.queue.is_empty()
            && message_after.wire_body.is_none()
        {
            return Err(StoreError::InvalidTransition);
        }
        if eligible_accounts.is_empty()
            && (!plan.queue.is_empty() || message_after.wire_body.is_some())
        {
            return Err(StoreError::InvalidTransition);
        }

        let mut shared_wire = None;
        if plan.queue.iter().any(|item| {
            item.msg_id.is_some()
                || item.group_msg_id != Some(message_id)
                || item.envelope.kind != EnvelopeKind::GroupMessage
        }) {
            return Err(StoreError::InvalidTransition);
        }
        for item in plan.queue {
            let shared = queued_group_shared(message_after.origin, &item.envelope.body)?;
            if shared_wire
                .as_ref()
                .is_some_and(|canonical| canonical != &shared)
            {
                return Err(StoreError::InvalidTransition);
            }
            shared_wire.get_or_insert(shared);
        }
        if plan.queue.first().is_some_and(|first| {
            plan.queue
                .iter()
                .any(|item| item.envelope.retention_until != first.envelope.retention_until)
        }) {
            return Err(StoreError::InvalidTransition);
        }
        for pending in [message_after.wire_body.as_deref(), retained_wire]
            .into_iter()
            .flatten()
        {
            let shared = pending_group_shared(message_after.origin, pending)?;
            if shared_wire
                .as_ref()
                .is_some_and(|canonical| canonical != &shared)
            {
                return Err(StoreError::InvalidTransition);
            }
            shared_wire.get_or_insert(shared);
        }
        if !eligible_accounts.is_empty() && shared_wire.is_none() {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(encoded) = message_after.wire_body.as_deref() {
            if let Ok(pending) = GroupPendingFanout::decode(encoded) {
                if pending.routes.iter().any(|route| {
                    !eligible_accounts.contains(&route.account)
                        || message_after.deliveries.iter().any(|delivery| {
                            delivery.peer == route.account && delivery.wire_id.is_some()
                        })
                        || plan.queue.iter().any(|item| item.peer == route.device)
                }) {
                    return Err(StoreError::InvalidTransition);
                }
                let mut counts = HashMap::new();
                for route in pending.routes {
                    let count = counts.entry(route.account).or_insert(0usize);
                    *count = count.saturating_add(1);
                    if *count > MAX_PAIRWISE_COMMIT_DEVICES {
                        return Err(StoreError::InvalidTransition);
                    }
                }
            }
        }

        let queue_ids = plan
            .queue
            .iter()
            .map(|item| item.envelope.content_id())
            .collect::<HashSet<_>>();
        if queue_ids.len() != plan.queue.len() {
            return Err(StoreError::InvalidTransition);
        }
        let existing_queue = self.queue_all()?;
        let existing_deliveries = self.message_device_deliveries(&message_id)?;
        let mut account_device_counts = HashMap::new();
        for delivery in &existing_deliveries {
            let count = account_device_counts
                .entry(delivery.account)
                .or_insert(0usize);
            *count = count.saturating_add(1);
        }
        if account_device_counts
            .values()
            .any(|count| *count > MAX_PAIRWISE_COMMIT_DEVICES)
        {
            return Err(StoreError::InvalidTransition);
        }
        let mut devices = HashSet::new();
        for delivery in plan.deliveries {
            let count = account_device_counts
                .entry(delivery.account)
                .or_insert(0usize);
            *count = count.saturating_add(1);
            if delivery.message != message_id
                || delivery.state != DeliveryState::Queued
                || !eligible_accounts.contains(&delivery.account)
                || *count > MAX_PAIRWISE_COMMIT_DEVICES
                || !devices.insert(delivery.device)
                || existing_deliveries
                    .iter()
                    .any(|existing| existing.device == delivery.device)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.delivery_updates {
            self.validate_delivery_transition(transition)?;
            if transition.after.message != message_id
                || transition.after.state != DeliveryState::Queued
                || transition.before.account != transition.after.account
                || !eligible_accounts.contains(&transition.after.account)
                || !devices.insert(transition.after.device)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for item in plan.queue {
            let wire_id = item.envelope.content_id();
            let owners = plan
                .deliveries
                .iter()
                .filter(|delivery| {
                    delivery.message == message_id
                        && delivery.device == item.peer
                        && delivery.wire_id == Some(wire_id)
                })
                .count()
                + plan
                    .delivery_updates
                    .iter()
                    .filter(|transition| {
                        transition.after.message == message_id
                            && transition.after.device == item.peer
                            && transition.after.wire_id == Some(wire_id)
                    })
                    .count();
            if owners != 1 {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delivery in plan.deliveries.iter().chain(
            plan.delivery_updates
                .iter()
                .map(|transition| transition.after),
        ) {
            if let Some(wire_id) = delivery.wire_id {
                let owned = plan.queue.iter().any(|item| {
                    item.peer == delivery.device
                        && item.group_msg_id == Some(message_id)
                        && item.envelope.content_id() == wire_id
                }) || existing_queue.iter().any(|(_, item)| {
                    item.peer == delivery.device
                        && item.group_msg_id == Some(message_id)
                        && item.envelope.content_id() == wire_id
                });
                if !owned {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }

        if message_after
            .deliveries
            .iter()
            .any(|delivery| delivery.peer == message_after.sender)
        {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(scheduled) = plan.scheduled {
            if self.get_scheduled_message(&scheduled.id)?.as_ref() != Some(scheduled)
                || scheduled.id != message_id
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        if let Some(ephemeral) = plan.ephemeral {
            if ephemeral.content_id != message_id
                || ephemeral.conversation != crate::EphemeralConversation::Group(group_id)
                || self
                    .get_ephemeral_record(
                        &ephemeral.conversation,
                        &ephemeral.author,
                        &ephemeral.content_id,
                    )?
                    .is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.media_transfers {
            self.validate_media_transfer_transition(transition)?;
            if transition.after.manifest_content_id != message_id {
                return Err(StoreError::InvalidTransition);
            }
        }
        let deleted_chain_ids = plan
            .delete_chains
            .iter()
            .map(|transition| (transition.group, transition.peer))
            .collect::<HashSet<_>>();
        if deleted_chain_ids.len() != plan.delete_chains.len() {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.delete_chains {
            let current = self.get_group_chain(&transition.group, &transition.peer)?;
            if transition.after.is_some()
                || transition.before.is_none()
                || current.as_ref().map(|chain| chain.as_slice()) != transition.before
                || transition.group != group_id
                || plan.group.as_ref().is_none_or(|group| {
                    group
                        .after
                        .members
                        .iter()
                        .any(|member| member.peer == transition.peer)
                })
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        if let Some(authority) = &plan.authority {
            self.validate_group_authority_transition(authority)?;
            if authority.after.group != group_id || authority.after.state_id != message_id {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_group_receive(&self, plan: &GroupReceivePlan<'_>) -> Result<()> {
        self.validate_group_chain_transition(&plan.chain)?;
        self.validate_session_transition(&plan.receipt_session)?;
        if plan.content_id == [0u8; 16]
            || self.is_seen(&plan.content_id)?
            || plan.queue.is_empty()
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan.queue.iter().any(|item| {
                item.peer != plan.receipt_session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
                    || item.envelope.kind != EnvelopeKind::Receipt
            })
            || mutation_count([
                1,
                1,
                usize::from(plan.message.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                plan.queue.len(),
                1,
                1,
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(message) = plan.message {
            self.validate_new_group_message(message)?;
            if message.direction != Direction::Inbound
                || message.group != plan.chain.group
                || message.sender != plan.chain.peer
                || !message.deliveries.is_empty()
                || message.wire_body.is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
            validate_inbound_group_origin(message.origin)?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            if ephemeral.conversation != crate::EphemeralConversation::Group(plan.chain.group)
                || ephemeral.author != plan.chain.peer
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        self.validate_pending(plan.source_pending)
    }

    fn validate_attachment_stage(&self, plan: &AttachmentStagePlan<'_>) -> Result<()> {
        if plan.message.is_some() == plan.group_message.is_some()
            || plan.media_transfers.is_empty()
            || plan.media_objects.is_empty()
            || mutation_count([
                usize::from(plan.message.is_some()),
                usize::from(plan.group_message.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                usize::from(plan.ephemeral.is_some()),
            ])? > MAX_ATTACHMENT_STAGE_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;

        let (content_id, author, conversation, peers) = if let Some(message) = plan.message {
            self.validate_new_message(message)?;
            if message.direction != Direction::Outbound
                || message.state != DeliveryState::Queued
                || message.wire_id.is_some()
                || message.body.is_empty()
                || plan.media_transfers.len() != 1
            {
                return Err(StoreError::InvalidTransition);
            }
            (
                message.id,
                None,
                crate::EphemeralConversation::Pairwise(message.peer),
                HashSet::from([message.peer]),
            )
        } else {
            let message = plan.group_message.ok_or(StoreError::InvalidTransition)?;
            self.validate_new_group_message(message)?;
            let peers = message
                .deliveries
                .iter()
                .map(|delivery| delivery.peer)
                .collect::<HashSet<_>>();
            if message.direction != Direction::Outbound
                || message.wire_body.is_some()
                || message.body.is_empty()
                || !matches!(
                    message.origin,
                    GroupOriginAuthentication::PendingOutboundV1 { sender_device }
                        if sender_device != [0u8; 32]
                )
                || peers.len() != message.deliveries.len()
                || peers.len() != plan.media_transfers.len()
                || message.deliveries.iter().any(|delivery| {
                    delivery.peer == message.sender
                        || delivery.wire_id.is_some()
                        || delivery.state != DeliveryState::Queued
                })
            {
                return Err(StoreError::InvalidTransition);
            }
            (
                message.id,
                Some(message.sender),
                crate::EphemeralConversation::Group(message.group),
                peers,
            )
        };

        let transfer_ids = plan
            .media_transfers
            .iter()
            .map(|transfer| transfer.local_id)
            .collect::<HashSet<_>>();
        if plan.media_transfers.iter().any(|transfer| {
            transfer.direction != crate::MediaDirection::Outbound
                || transfer.manifest_content_id != content_id
                || transfer.state != crate::MediaTransferState::Queued
                || !peers.contains(&transfer.peer)
                || author.is_some_and(|sender| {
                    transfer.scope != crate::MediaScope::Group
                        || transfer.scope_id
                            != plan.group_message.expect("group stage selected").group
                        || transfer.manifest_author != sender
                })
                || author.is_none() && transfer.scope != crate::MediaScope::Pairwise
        }) || plan.media_objects.iter().any(|object| {
            !transfer_ids.contains(&object.transfer_id)
                || object.state != crate::MediaTransferState::Queued
        }) {
            return Err(StoreError::InvalidTransition);
        }

        if let Some(ephemeral) = plan.ephemeral {
            let ephemeral_transfers = ephemeral
                .transfer_ids
                .iter()
                .copied()
                .collect::<HashSet<_>>();
            if ephemeral.content_id != content_id
                || ephemeral.conversation != conversation
                || ephemeral.state != EphemeralState::Active
                || ephemeral_transfers != transfer_ids
                || self
                    .get_ephemeral_record(
                        &ephemeral.conversation,
                        &ephemeral.author,
                        &ephemeral.content_id,
                    )?
                    .is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_attachment_state(&self, plan: &AttachmentStatePlan<'_>) -> Result<()> {
        let count = mutation_count([
            plan.media_transfers.len(),
            plan.media_objects.len(),
            plan.delete_controls.len(),
        ])?;
        if count == 0 || count > MAX_MAINTENANCE_TRANSITIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        let transfer_ids = plan
            .media_transfers
            .iter()
            .map(|transition| transition.after.local_id)
            .collect::<HashSet<_>>();
        let object_ids = plan
            .media_objects
            .iter()
            .map(|transition| transition.after.local_id)
            .collect::<HashSet<_>>();
        let control_ids = plan
            .delete_controls
            .iter()
            .map(|control| control.content_id)
            .collect::<HashSet<_>>();
        if transfer_ids.len() != plan.media_transfers.len()
            || object_ids.len() != plan.media_objects.len()
            || control_ids.len() != plan.delete_controls.len()
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.media_transfers {
            self.validate_media_transfer_transition(transition)?;
        }
        for transition in plan.media_objects {
            self.validate_media_object_transition(transition)?;
        }
        for control in plan.delete_controls {
            if self.get_deferred_control(&control.content_id)?.as_ref() != Some(control) {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_group_state(&self, plan: &GroupStatePlan<'_>) -> Result<()> {
        let count = mutation_count([
            plan.groups.len(),
            plan.chains.len(),
            plan.contacts.len(),
            plan.authorities.len(),
            plan.delete_controls.len(),
        ])?;
        if count == 0 || count > MAX_GROUP_STATE_MUTATIONS {
            return Err(StoreError::MaintenanceBounds);
        }

        let mut group_ids = HashSet::new();
        for transition in plan.groups {
            let id = match (transition.before, transition.after) {
                (None, None) => return Err(StoreError::InvalidTransition),
                (None, Some(after)) => after.id,
                (Some(before), None) => before.id,
                (Some(before), Some(after)) => {
                    if before == after || before.id != after.id {
                        return Err(StoreError::InvalidTransition);
                    }
                    before.id
                }
            };
            if !group_ids.insert(id)
                || self.get_group(&id)?.as_ref() != transition.before
                || transition
                    .after
                    .is_some_and(|group| !valid_group_record(group))
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        let current_groups = self.count_rows::<store_v2::GroupRows>()?;
        let additions = plan
            .groups
            .iter()
            .filter(|transition| transition.before.is_none() && transition.after.is_some())
            .count() as u64;
        let removals = plan
            .groups
            .iter()
            .filter(|transition| transition.before.is_some() && transition.after.is_none())
            .count() as u64;
        let resulting_groups = current_groups
            .checked_add(additions)
            .and_then(|count| count.checked_sub(removals))
            .ok_or(StoreError::InvalidTransition)?;
        if resulting_groups > MAX_PROFILE_GROUPS as u64 {
            return Err(StoreError::GroupLimit);
        }

        let mut chain_ids = HashSet::new();
        for transition in plan.chains {
            let current = self.get_group_chain(&transition.group, &transition.peer)?;
            if !chain_ids.insert((transition.group, transition.peer))
                || (transition.before.is_none() && transition.after.is_none())
                || transition.before == transition.after
                || transition.before.is_some_and(<[u8]>::is_empty)
                || transition.after.is_some_and(<[u8]>::is_empty)
                || current.as_ref().map(|value| value.as_slice()) != transition.before
            {
                return Err(StoreError::InvalidTransition);
            }
        }

        let mut contact_ids = HashSet::new();
        for transition in plan.contacts {
            if !contact_ids.insert(transition.after.peer)
                || transition.before == Some(transition.after)
                || transition
                    .before
                    .is_some_and(|before| before.peer != transition.after.peer)
                || transition.after.identity.is_empty()
                || transition.after.identity.len() > MAX_GROUP_MEMBER_IDENTITY_LEN
                || self.get_contact(&transition.after.peer)?.as_ref() != transition.before
            {
                return Err(StoreError::InvalidTransition);
            }
        }

        let mut authority_ids = HashSet::new();
        for transition in plan.authorities {
            let group = match (transition.before, transition.after) {
                (None, None) => return Err(StoreError::InvalidTransition),
                (None, Some(after)) => after.group,
                (Some(before), None) => before.group,
                (Some(before), Some(after)) => {
                    if before == after || before.group != after.group {
                        return Err(StoreError::InvalidTransition);
                    }
                    before.group
                }
            };
            if !authority_ids.insert(group)
                || self.get_group_authority(&group)?.as_ref() != transition.before
                || transition
                    .after
                    .is_some_and(|authority| !valid_group_authority_record(authority))
            {
                return Err(StoreError::InvalidTransition);
            }
        }

        let control_ids = plan
            .delete_controls
            .iter()
            .map(|control| control.content_id)
            .collect::<HashSet<_>>();
        if control_ids.len() != plan.delete_controls.len() {
            return Err(StoreError::InvalidTransition);
        }
        for control in plan.delete_controls {
            if self.get_deferred_control(&control.content_id)?.as_ref() != Some(control) {
                return Err(StoreError::InvalidTransition);
            }
        }

        for transition in plan.groups {
            let id = transition
                .before
                .or(transition.after)
                .expect("validated group transition")
                .id;
            let current_chains = self.group_chains(&id)?;
            if let Some(final_group) = transition.after {
                for (peer, _) in current_chains {
                    let removed = plan.chains.iter().any(|chain| {
                        chain.group == id && chain.peer == peer && chain.after.is_none()
                    });
                    if !removed && !final_group.members.iter().any(|member| member.peer == peer) {
                        return Err(StoreError::InvalidTransition);
                    }
                }
            } else {
                let deleted_chains = plan
                    .chains
                    .iter()
                    .filter(|chain| chain.group == id && chain.after.is_none())
                    .map(|chain| chain.peer)
                    .collect::<HashSet<_>>();
                if deleted_chains.len() != current_chains.len()
                    || current_chains
                        .iter()
                        .any(|(peer, _)| !deleted_chains.contains(peer))
                    || plan
                        .chains
                        .iter()
                        .any(|chain| chain.group == id && chain.after.is_some())
                {
                    return Err(StoreError::InvalidTransition);
                }
                let current_authority = self.get_group_authority(&id)?;
                let delete_authority = plan.authorities.iter().find(|authority| {
                    authority.before.is_some_and(|before| before.group == id)
                        && authority.after.is_none()
                });
                if current_authority.is_some() != delete_authority.is_some() {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }

        for transition in plan.chains {
            if transition.after.is_some() {
                let planned_group = plan.groups.iter().find_map(|candidate| {
                    candidate.after.filter(|group| group.id == transition.group)
                });
                let current_group;
                let group = if let Some(group) = planned_group {
                    group
                } else {
                    current_group = self.get_group(&transition.group)?;
                    current_group
                        .as_ref()
                        .ok_or(StoreError::InvalidTransition)?
                };
                if !group
                    .members
                    .iter()
                    .any(|member| member.peer == transition.peer)
                {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        for transition in plan.authorities {
            if let Some(authority) = transition.after {
                let group_exists = plan.groups.iter().any(|candidate| {
                    candidate
                        .after
                        .is_some_and(|group| group.id == authority.group)
                }) || (plan.groups.iter().all(|candidate| {
                    candidate
                        .before
                        .is_none_or(|group| group.id != authority.group)
                }) && self.get_group(&authority.group)?.is_some());
                if !group_exists {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        Ok(())
    }

    fn validate_device_control(&self, plan: &DeviceControlPlan<'_>) -> Result<()> {
        let count = mutation_count([
            usize::from(plan.state.is_some()),
            usize::from(plan.link_recovery.is_some()),
            plan.groups.len(),
            plan.insert_events.len(),
            plan.delete_events.len(),
        ])?;
        if count == 0 || count > MAX_DEVICE_CONTROL_MUTATIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        if let Some(state) = &plan.state {
            let current = self.get_device_state()?;
            if current.as_ref() != state.before || state.before == Some(state.after) {
                return Err(StoreError::InvalidTransition);
            }
            let identity = self.get_identity()?.ok_or(StoreError::InvalidTransition)?;
            state.after.validate(&identity)?;
        }
        let mut group_ids = HashSet::new();
        for transition in plan.groups {
            if !group_ids.insert(transition.after.id) {
                return Err(StoreError::InvalidTransition);
            }
            self.validate_group_transition(transition)?;
        }

        let current_events = self.device_sync_events()?;
        let current = current_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        let inserts = plan
            .insert_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        let deletes = plan
            .delete_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        if inserts.len() != plan.insert_events.len()
            || deletes.len() != plan.delete_events.len()
            || inserts
                .iter()
                .any(|event| current.contains(event) || deletes.contains(event))
            || deletes.iter().any(|event| !current.contains(event))
        {
            return Err(StoreError::InvalidTransition);
        }
        let manifest = if let Some(state) = &plan.state {
            &state.after.manifest
        } else {
            &self
                .get_device_state()?
                .ok_or(StoreError::InvalidTransition)?
                .manifest
        };
        if let Some(transition) = &plan.link_recovery {
            let target = transition
                .before
                .map(|record| record.target_device)
                .or_else(|| transition.after.map(|record| record.target_device))
                .ok_or(StoreError::InvalidTransition)?;
            if transition.before == transition.after
                || transition
                    .before
                    .is_some_and(|record| record.target_device != target)
                || transition
                    .after
                    .is_some_and(|record| record.target_device != target)
                || self.get_device_link_recovery(&target)?.as_ref() != transition.before
            {
                return Err(StoreError::InvalidTransition);
            }
            if let Some(recovery) = transition.after {
                crate::devices::validate_device_link_recovery(recovery)?;
                let channel_exists = if let Some(state) = &plan.state {
                    state
                        .after
                        .channels
                        .iter()
                        .any(|channel| channel.peer_device == target)
                } else {
                    self.get_device_state()?.is_some_and(|state| {
                        state
                            .channels
                            .iter()
                            .any(|channel| channel.peer_device == target)
                    })
                };
                if !manifest.devices.iter().any(|entry| {
                    entry.certificate.device_id() == target && entry.revoked_at.is_none()
                }) || !channel_exists
                {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        for encoded in plan.insert_events {
            if encoded.is_empty() || encoded.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::RecordBounds);
            }
            DeviceSyncEvent::decode(encoded)?.verify(manifest)?;
        }
        Ok(())
    }

    fn validate_authority_device_control(
        &self,
        plan: &AuthorityDeviceControlPlan<'_>,
    ) -> Result<()> {
        let count = mutation_count([
            usize::from(plan.state.is_some()),
            usize::from(plan.link_recovery.is_some()),
            plan.groups.len(),
            plan.insert_events.len(),
            plan.delete_events.len(),
        ])?;
        if count == 0 || count > MAX_DEVICE_CONTROL_MUTATIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        if let Some(state) = &plan.state {
            let current = self.get_device_authority_state()?;
            if current.as_ref() != state.before || state.before == Some(state.after) {
                return Err(StoreError::InvalidTransition);
            }
            let account = self
                .get_account_identity()?
                .ok_or(StoreError::InvalidTransition)?;
            state.after.validate(&account)?;
        }
        let mut group_ids = HashSet::new();
        for transition in plan.groups {
            if !group_ids.insert(transition.after.id) {
                return Err(StoreError::InvalidTransition);
            }
            self.validate_group_transition(transition)?;
        }

        let current_events = self.device_sync_events()?;
        let current = current_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        let inserts = plan
            .insert_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        let deletes = plan
            .delete_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        if inserts.len() != plan.insert_events.len()
            || deletes.len() != plan.delete_events.len()
            || inserts
                .iter()
                .any(|event| current.contains(event) || deletes.contains(event))
            || deletes.iter().any(|event| !current.contains(event))
        {
            return Err(StoreError::InvalidTransition);
        }
        let manifest = if let Some(state) = &plan.state {
            &state.after.manifest
        } else {
            &self
                .get_device_authority_state()?
                .ok_or(StoreError::InvalidTransition)?
                .manifest
        };
        if let Some(transition) = &plan.link_recovery {
            let target = transition
                .before
                .map(|record| record.target_device)
                .or_else(|| transition.after.map(|record| record.target_device))
                .ok_or(StoreError::InvalidTransition)?;
            if transition.before == transition.after
                || transition
                    .before
                    .is_some_and(|record| record.target_device != target)
                || transition
                    .after
                    .is_some_and(|record| record.target_device != target)
                || self.get_device_link_recovery(&target)?.as_ref() != transition.before
            {
                return Err(StoreError::InvalidTransition);
            }
            if let Some(recovery) = transition.after {
                crate::devices::validate_device_link_recovery(recovery)?;
                let channel_exists = if let Some(state) = &plan.state {
                    state
                        .after
                        .channels
                        .iter()
                        .any(|channel| channel.peer_device == target)
                } else {
                    self.get_device_authority_state()?.is_some_and(|state| {
                        state
                            .channels
                            .iter()
                            .any(|channel| channel.peer_device == target)
                    })
                };
                if manifest.active_certificate(&target).is_none() || !channel_exists {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        for encoded in plan.insert_events {
            if encoded.is_empty() || encoded.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::RecordBounds);
            }
            DeviceSyncEvent::decode(encoded)?.verify(manifest)?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    fn validate_device_link(&self, plan: &DeviceLinkPlan<'_>) -> Result<()> {
        let count = mutation_count([
            2,
            plan.contacts.len(),
            plan.devices.len(),
            plan.messages.len(),
            plan.groups.len(),
            plan.group_messages.len(),
            plan.authorities.len(),
            plan.local_metadata.len(),
            plan.notes.len(),
            plan.ephemeral.len(),
            plan.sync_events.len(),
        ])?;
        if plan.groups.len() > MAX_PROFILE_GROUPS {
            return Err(StoreError::GroupLimit);
        }
        if count > MAX_DEVICE_LINK_MUTATIONS
            || identity_eq(plan.identity.before, plan.identity.after)
            || self
                .get_identity()?
                .as_ref()
                .is_none_or(|current| !identity_eq(current, plan.identity.before))
            || self.get_device_state()?.as_ref() != plan.device_state.before
            || plan.device_state.before == Some(plan.device_state.after)
        {
            return Err(StoreError::InvalidTransition);
        }
        plan.device_state.after.validate(plan.identity.after)?;

        let pristine_tables = [
            self.count_rows::<store_v2::SessionRows>()?,
            self.count_rows::<store_v2::CapabilityRows>()?,
            self.count_rows::<store_v2::MessageRows>()?,
            self.count_rows::<store_v2::ContactRows>()?,
            self.count_rows::<store_v2::QueueRows>()?,
            self.count_rows::<store_v2::SeenRows>()?,
            self.count_rows::<store_v2::ReceiptReplayRows>()?,
            self.count_rows::<store_v2::PendingRows>()?,
            self.count_rows::<store_v2::GroupRows>()?,
            self.count_rows::<store_v2::GroupAuthorityRows>()?,
            self.count_rows::<store_v2::GroupChainRows>()?,
            self.count_rows::<store_v2::GroupMessageRows>()?,
            self.count_rows::<store_v2::ResetRows>()?,
            self.count_rows::<store_v2::MediaTransferRows>()?,
            self.count_rows::<store_v2::MediaObjectRows>()?,
            self.count_rows::<store_v2::LocalMetadataRows>()?,
            self.count_rows::<store_v2::NoteRows>()?,
            self.count_rows::<store_v2::ScheduledRows>()?,
            self.count_rows::<store_v2::EphemeralRows>()?,
            self.count_rows::<store_v2::DeviceSyncRows>()?,
            self.count_rows::<store_v2::ContactDeviceRows>()?,
            self.count_rows::<store_v2::MessageDeviceDeliveryRows>()?,
            self.count_rows::<store_v2::PresentationMarkerRows>()?,
            self.count_rows::<store_v2::DeferredControlRows>()?,
            self.count_rows::<store_v2::DeviceLinkRecoveryRows>()?,
        ];
        if self.get_prekeys()?.is_none() || pristine_tables.into_iter().any(|count| count != 0) {
            return Err(StoreError::InvalidTransition);
        }

        let contact_ids = plan
            .contacts
            .iter()
            .map(|record| record.peer)
            .collect::<HashSet<_>>();
        let device_ids = plan
            .devices
            .iter()
            .map(|record| (record.account, record.device))
            .collect::<HashSet<_>>();
        let message_ids = plan
            .messages
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let group_ids = plan
            .groups
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let group_message_ids = plan
            .group_messages
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let authority_ids = plan
            .authorities
            .iter()
            .map(|record| record.group)
            .collect::<HashSet<_>>();
        let note_ids = plan
            .notes
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        if contact_ids.len() != plan.contacts.len()
            || device_ids.len() != plan.devices.len()
            || message_ids.len() != plan.messages.len()
            || group_ids.len() != plan.groups.len()
            || group_message_ids.len() != plan.group_messages.len()
            || authority_ids.len() != plan.authorities.len()
            || note_ids.len() != plan.notes.len()
            || plan
                .devices
                .iter()
                .any(|record| !contact_ids.contains(&record.account))
            || plan.groups.iter().any(|record| !valid_group_record(record))
            || plan
                .group_messages
                .iter()
                .any(|record| !group_ids.contains(&record.group))
            || plan.authorities.iter().any(|record| {
                !group_ids.contains(&record.group) || !valid_group_authority_record(record)
            })
            || plan.ephemeral.iter().any(|record| {
                record.state == EphemeralState::Active || !record.transfer_ids.is_empty()
            })
        {
            return Err(StoreError::InvalidTransition);
        }
        for record in plan.devices {
            crate::devices::validate_contact_device(record)?;
        }
        for record in plan.local_metadata {
            record.validate()?;
        }
        for record in plan.notes {
            record.validate()?;
        }
        let event_ids = plan
            .sync_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        if event_ids.len() != plan.sync_events.len() {
            return Err(StoreError::InvalidTransition);
        }
        for encoded in plan.sync_events {
            if encoded.is_empty() || encoded.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::RecordBounds);
            }
            DeviceSyncEvent::decode(encoded)?.verify(&plan.device_state.after.manifest)?;
        }
        Ok(())
    }

    fn validate_authority_device_link(&self, plan: &AuthorityDeviceLinkPlan<'_>) -> Result<()> {
        let count = mutation_count([
            2,
            plan.contacts.len(),
            plan.devices.len(),
            plan.messages.len(),
            plan.groups.len(),
            plan.group_messages.len(),
            plan.authorities.len(),
            plan.local_metadata.len(),
            plan.notes.len(),
            plan.ephemeral.len(),
            plan.sync_events.len(),
            plan.reset_peers.len(),
        ])?;
        if plan.groups.len() > MAX_PROFILE_GROUPS {
            return Err(StoreError::GroupLimit);
        }
        if count > MAX_DEVICE_LINK_MUTATIONS
            || plan.account.before == plan.account.after
            || self.get_account_identity()?.as_ref() != Some(plan.account.before)
            || self.get_device_authority_state()?.as_ref() != plan.device_state.before
            || plan.device_state.before == Some(plan.device_state.after)
        {
            return Err(StoreError::InvalidTransition);
        }
        plan.account.after.verify()?;
        plan.device_state.after.validate(plan.account.after)?;

        let pristine_tables = [
            self.count_rows::<store_v2::SessionRows>()?,
            self.count_rows::<store_v2::CapabilityRows>()?,
            self.count_rows::<store_v2::MessageRows>()?,
            self.count_rows::<store_v2::ContactRows>()?,
            self.count_rows::<store_v2::QueueRows>()?,
            self.count_rows::<store_v2::SeenRows>()?,
            self.count_rows::<store_v2::ReceiptReplayRows>()?,
            self.count_rows::<store_v2::PendingRows>()?,
            self.count_rows::<store_v2::GroupRows>()?,
            self.count_rows::<store_v2::GroupAuthorityRows>()?,
            self.count_rows::<store_v2::GroupChainRows>()?,
            self.count_rows::<store_v2::GroupMessageRows>()?,
            self.count_rows::<store_v2::ResetRows>()?,
            self.count_rows::<store_v2::MediaTransferRows>()?,
            self.count_rows::<store_v2::MediaObjectRows>()?,
            self.count_rows::<store_v2::LocalMetadataRows>()?,
            self.count_rows::<store_v2::NoteRows>()?,
            self.count_rows::<store_v2::ScheduledRows>()?,
            self.count_rows::<store_v2::EphemeralRows>()?,
            self.count_rows::<store_v2::DeviceSyncRows>()?,
            self.count_rows::<store_v2::ContactDeviceRows>()?,
            self.count_rows::<store_v2::MessageDeviceDeliveryRows>()?,
            self.count_rows::<store_v2::PresentationMarkerRows>()?,
            self.count_rows::<store_v2::DeferredControlRows>()?,
            self.count_rows::<store_v2::DeviceLinkRecoveryRows>()?,
        ];
        if self.get_prekeys()?.is_none() || pristine_tables.into_iter().any(|count| count != 0) {
            return Err(StoreError::InvalidTransition);
        }

        let contact_ids = plan
            .contacts
            .iter()
            .map(|record| record.peer)
            .collect::<HashSet<_>>();
        let device_ids = plan
            .devices
            .iter()
            .map(|record| (record.account, record.device))
            .collect::<HashSet<_>>();
        let message_ids = plan
            .messages
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let group_ids = plan
            .groups
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let group_message_ids = plan
            .group_messages
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let authority_ids = plan
            .authorities
            .iter()
            .map(|record| record.group)
            .collect::<HashSet<_>>();
        let note_ids = plan
            .notes
            .iter()
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        if contact_ids.len() != plan.contacts.len()
            || device_ids.len() != plan.devices.len()
            || message_ids.len() != plan.messages.len()
            || group_ids.len() != plan.groups.len()
            || group_message_ids.len() != plan.group_messages.len()
            || authority_ids.len() != plan.authorities.len()
            || note_ids.len() != plan.notes.len()
            || plan
                .devices
                .iter()
                .any(|record| !contact_ids.contains(&record.account))
            || plan.groups.iter().any(|record| !valid_group_record(record))
            || plan
                .group_messages
                .iter()
                .any(|record| !group_ids.contains(&record.group))
            || plan.authorities.iter().any(|record| {
                !group_ids.contains(&record.group) || !valid_group_authority_record(record)
            })
            || plan.ephemeral.iter().any(|record| {
                record.state == EphemeralState::Active || !record.transfer_ids.is_empty()
            })
        {
            return Err(StoreError::InvalidTransition);
        }
        for record in plan.devices {
            crate::devices::validate_contact_device(record)?;
        }
        for record in plan.local_metadata {
            record.validate()?;
        }
        for record in plan.notes {
            record.validate()?;
        }
        let event_ids = plan
            .sync_events
            .iter()
            .map(Vec::as_slice)
            .collect::<HashSet<_>>();
        if event_ids.len() != plan.sync_events.len() {
            return Err(StoreError::InvalidTransition);
        }
        for encoded in plan.sync_events {
            if encoded.is_empty() || encoded.len() > MAX_DEVICE_SYNC_EVENT_BYTES {
                return Err(StoreError::RecordBounds);
            }
            DeviceSyncEvent::decode(encoded)?.verify(&plan.device_state.after.manifest)?;
        }
        let reset_peers = plan.reset_peers.iter().copied().collect::<HashSet<_>>();
        if reset_peers.len() != plan.reset_peers.len()
            || plan.reset_peers.iter().any(|peer| {
                !plan.devices.iter().any(|device| device.device == *peer)
                    && !plan.contacts.iter().any(|contact| contact.peer == *peer)
            })
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_device_projection(&self, plan: &DeviceProjectionPlan<'_>) -> Result<()> {
        let count = mutation_count([
            plan.projections.len(),
            plan.delete_sessions.len(),
            plan.delete_capabilities.len(),
            plan.delete_queue.len(),
        ])?;
        if count == 0 || count > MAX_DEVICE_PROJECTION_MUTATIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        let mut keys = HashSet::new();
        for projection in plan.projections {
            match projection {
                DeviceProjection::Contact { before, after } => {
                    let peer = before
                        .map(|record| record.peer)
                        .or_else(|| after.map(|record| record.peer))
                        .ok_or(StoreError::InvalidTransition)?;
                    if before == after
                        || before.is_some_and(|record| record.peer != peer)
                        || after.is_some_and(|record| record.peer != peer)
                        || !keys.insert((0u8, peer.to_vec()))
                        || self.get_contact(&peer)?.as_ref() != *before
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                }
                DeviceProjection::ContactDevice { before, after } => {
                    let key = before
                        .map(|record| (record.account, record.device))
                        .or_else(|| after.map(|record| (record.account, record.device)))
                        .ok_or(StoreError::InvalidTransition)?;
                    let current = self
                        .contact_devices()?
                        .into_iter()
                        .find(|record| (record.account, record.device) == key);
                    if before == after
                        || before.is_some_and(|record| (record.account, record.device) != key)
                        || after.is_some_and(|record| (record.account, record.device) != key)
                        || !keys.insert((1u8, [key.0.as_slice(), key.1.as_slice()].concat()))
                        || current.as_ref() != *before
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                    if let Some(record) = after {
                        crate::devices::validate_contact_device(record)?;
                    }
                }
                DeviceProjection::Message { before, after } => {
                    let record = (*before).or(*after).ok_or(StoreError::InvalidTransition)?;
                    let key = (record.peer, record.direction, record.id);
                    let current = self
                        .messages_with(&record.peer)?
                        .into_iter()
                        .find(|candidate| {
                            (candidate.peer, candidate.direction, candidate.id) == key
                        });
                    if before == after
                        || before.is_some_and(|candidate| {
                            (candidate.peer, candidate.direction, candidate.id) != key
                        })
                        || after.is_some_and(|candidate| {
                            (candidate.peer, candidate.direction, candidate.id) != key
                        })
                        || !keys.insert((
                            2u8,
                            [key.0.as_slice(), &[direction_code(key.1)], key.2.as_slice()].concat(),
                        ))
                        || current.as_ref() != *before
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                }
                DeviceProjection::GroupMessage { before, after } => {
                    let record = (*before).or(*after).ok_or(StoreError::InvalidTransition)?;
                    let key = (record.group, record.sender, record.id);
                    let current = self
                        .group_messages(&record.group)?
                        .into_iter()
                        .find(|candidate| (candidate.group, candidate.sender, candidate.id) == key);
                    if before == after
                        || before.is_some_and(|candidate| {
                            (candidate.group, candidate.sender, candidate.id) != key
                        })
                        || after.is_some_and(|candidate| {
                            (candidate.group, candidate.sender, candidate.id) != key
                        })
                        || !keys.insert((
                            3u8,
                            [key.0.as_slice(), key.1.as_slice(), key.2.as_slice()].concat(),
                        ))
                        || current.as_ref() != *before
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                }
                DeviceProjection::LocalMetadata { before, after } => {
                    let key = before
                        .map(|record| record.key())
                        .or_else(|| after.map(LocalMetadataRecord::key))
                        .ok_or(StoreError::InvalidTransition)?;
                    if before == after
                        || before.is_some_and(|record| record.key() != key)
                        || after.is_some_and(|record| record.key() != key)
                        || !keys.insert((
                            4u8,
                            postcard::to_allocvec(&key).map_err(|_| StoreError::Serialization)?,
                        ))
                        || self.get_local_metadata(&key)?.as_ref() != *before
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                    if let Some(record) = after {
                        record.validate()?;
                    }
                }
                DeviceProjection::Note { after } => {
                    if !keys.insert((5u8, after.id.to_vec()))
                        || self
                            .note_messages()?
                            .iter()
                            .any(|record| record.id == after.id)
                    {
                        return Err(StoreError::InvalidTransition);
                    }
                    after.validate()?;
                }
            }
        }
        let mut sessions = HashSet::new();
        for delete in plan.delete_sessions {
            if !sessions.insert(delete.peer_device)
                || !session_eq(
                    self.get_session(&delete.peer_device)?.as_ref(),
                    Some(delete.before),
                )?
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        let mut capabilities = HashSet::new();
        for delete in plan.delete_capabilities {
            if !capabilities.insert(delete.peer_device)
                || self
                    .get_capabilities(&delete.peer_device)?
                    .as_ref()
                    .map(CapabilityControl::encode)
                    .transpose()?
                    .as_deref()
                    != Some(delete.before.encode()?.as_slice())
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        let queue_ids = plan
            .delete_queue
            .iter()
            .map(|delete| delete.sequence)
            .collect::<HashSet<_>>();
        if queue_ids.len() != plan.delete_queue.len() {
            return Err(StoreError::InvalidTransition);
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
        }
        Ok(())
    }

    fn validate_handshake_receive(&self, plan: &HandshakeReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.content_id == [0u8; 16]
            || plan.devices.is_empty()
            || plan.devices.len() > MAX_PAIRWISE_COMMIT_DEVICES
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan.delete_queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan
                .devices
                .iter()
                .any(|device| device.account != plan.contact.peer)
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
                    || item.envelope.kind != EnvelopeKind::Receipt
            })
            || mutation_count([
                usize::from(plan.prekeys.is_some()),
                1,
                1,
                plan.devices.len(),
                plan.delete_devices.len(),
                plan.delete_sessions.len(),
                plan.delete_capabilities.len(),
                plan.delete_queue.len(),
                plan.groups.len(),
                usize::from(plan.message.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                plan.queue.len(),
                1,
                usize::from(plan.receipt_replay),
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        let device_ids = plan
            .devices
            .iter()
            .map(|device| device.device)
            .collect::<HashSet<_>>();
        if device_ids.len() != plan.devices.len()
            || plan
                .delete_devices
                .iter()
                .any(|delete| device_ids.contains(&delete.before.device))
        {
            return Err(StoreError::InvalidTransition);
        }
        for delete in plan.delete_devices {
            if self
                .contact_devices_for(&delete.before.account)?
                .into_iter()
                .find(|endpoint| endpoint.device == delete.before.device)
                .as_ref()
                != Some(delete.before)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for peer in plan.delete_sessions {
            if peer == &plan.session.peer_device || self.get_session(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
        }
        if let Some(prekeys) = &plan.prekeys {
            let current = self.get_prekeys()?;
            if prekeys.before.is_none()
                || prekeys.before == Some(prekeys.after)
                || current.as_ref().map(|value| value.as_slice()) != prekeys.before
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for group in plan.groups {
            self.validate_group_transition(group)?;
        }
        if let Some(message) = plan.message {
            if message.peer != plan.contact.peer {
                return Err(StoreError::InvalidTransition);
            }
            self.validate_new_message(message)?;
        }
        self.validate_pending(plan.source_pending)?;
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        let accepted_state = plan.message.is_some()
            || plan.ephemeral.is_some()
            || !plan.media_transfers.is_empty()
            || !plan.media_objects.is_empty();
        if self.is_seen(&plan.content_id)?
            || (plan.receipt_replay && plan.queue.is_empty())
            || (accepted_state && (!plan.receipt_replay || plan.queue.is_empty()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_receipt_receive(&self, plan: &ReceiptReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan.content_id == [0u8; 16]
            || self.is_seen(&plan.content_id)?
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
            })
            || mutation_count([
                1,
                plan.delete_queue.len(),
                plan.queue.len(),
                plan.messages.len(),
                plan.deliveries.len(),
                plan.group_messages.len(),
                plan.groups.len(),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                usize::from(plan.capabilities.is_some()),
                usize::from(plan.deferred_control.is_some()),
                1,
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
            if self
                .store_queue_row(delete.sequence)?
                .is_none_or(|item| item.peer != plan.session.peer_device)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.messages {
            self.validate_message_transition(transition)?;
        }
        for transition in plan.deliveries {
            self.validate_delivery_transition(transition)?;
        }
        for transition in plan.group_messages {
            self.validate_group_message_transition(transition)?;
        }
        for transition in plan.groups {
            self.validate_group_transition(transition)?;
        }
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        if let Some(control) = plan.deferred_control {
            if control.content_id != plan.content_id
                || control.peer_device != plan.session.peer_device
                || control.body.is_empty()
                || self.get_deferred_control(&control.content_id)?.is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        self.validate_pending(plan.source_pending)
    }

    fn validate_maintenance(&self, plan: &MaintenancePlan<'_>) -> Result<()> {
        let count = mutation_count([
            plan.seen.len(),
            plan.delete_pending.len(),
            plan.delete_queue.len(),
            plan.update_queue.len(),
            plan.delete_replay.len(),
            plan.messages.len(),
            plan.deliveries.len(),
            plan.group_messages.len(),
            plan.groups.len(),
            plan.ephemeral.len(),
            plan.delete_messages.len(),
            plan.delete_group_messages.len(),
            plan.delete_media
                .iter()
                .map(|delete| delete.object_ids.len() + 1)
                .sum(),
            plan.delete_scheduled.len(),
            plan.delete_sessions.len(),
            plan.delete_capabilities.len(),
            plan.clear_reset_markers.len(),
            plan.delete_controls.len(),
            usize::from(plan.acknowledge_presentation.is_some()),
        ])?;
        if count == 0 || count > MAX_MAINTENANCE_TRANSITIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        for delete in plan.delete_pending {
            self.validate_pending(Some(*delete))?;
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
        }
        for transition in plan.update_queue {
            let current = self
                .store_queue_row(transition.sequence)?
                .ok_or(StoreError::InvalidTransition)?;
            if current != *transition.before
                || transition.before.envelope.content_id() != transition.after.envelope.content_id()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.messages {
            self.validate_message_transition(transition)?;
        }
        for transition in plan.deliveries {
            self.validate_delivery_transition(transition)?;
        }
        for transition in plan.group_messages {
            self.validate_group_message_transition(transition)?;
        }
        for transition in plan.groups {
            self.validate_group_transition(transition)?;
        }
        for transition in plan.ephemeral {
            let current = self.get_ephemeral_record(
                &transition.after.conversation,
                &transition.after.author,
                &transition.after.content_id,
            )?;
            if current.as_ref() != transition.before
                || transition
                    .before
                    .is_some_and(|before| before.state != EphemeralState::Active)
                || transition.after.state == EphemeralState::Active
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_messages {
            let current = self
                .messages_with(&delete.before.peer)?
                .into_iter()
                .find(|message| message.id == delete.before.id);
            if current.as_ref() != Some(delete.before) {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_group_messages {
            if self
                .group_messages(&delete.before.group)?
                .into_iter()
                .find(|message| {
                    message.id == delete.before.id && message.sender == delete.before.sender
                })
                .as_ref()
                != Some(delete.before)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_media {
            let transfer = self
                .get_media_transfer(&delete.transfer_id)?
                .ok_or(StoreError::InvalidTransition)?;
            if !matches!(transfer, crate::MediaRecord::Available(_)) {
                return Err(StoreError::InvalidTransition);
            }
            let current_objects = self
                .media_objects_for_transfer(&delete.transfer_id)?
                .into_iter()
                .map(|object| object.local_id)
                .collect::<HashSet<_>>();
            if current_objects.len() != delete.object_ids.len()
                || delete
                    .object_ids
                    .iter()
                    .any(|object| !current_objects.contains(object))
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for scheduled in plan.delete_scheduled {
            if self.get_scheduled_message(&scheduled.id)?.as_ref() != Some(scheduled) {
                return Err(StoreError::InvalidTransition);
            }
        }
        let delete_sessions = plan.delete_sessions.iter().copied().collect::<HashSet<_>>();
        if delete_sessions.len() != plan.delete_sessions.len() {
            return Err(StoreError::InvalidTransition);
        }
        for peer in plan.delete_sessions {
            if self.get_session(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        let delete_capabilities = plan
            .delete_capabilities
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        if delete_capabilities.len() != plan.delete_capabilities.len() {
            return Err(StoreError::InvalidTransition);
        }
        for peer in plan.delete_capabilities {
            if self.get_capabilities(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        let reset_markers = self.reset_markers()?.into_iter().collect::<HashSet<_>>();
        if plan
            .clear_reset_markers
            .iter()
            .any(|marker| !reset_markers.contains(marker))
        {
            return Err(StoreError::InvalidTransition);
        }
        for control in plan.delete_controls {
            if self.get_deferred_control(&control.content_id)?.as_ref() != Some(control) {
                return Err(StoreError::InvalidTransition);
            }
        }
        if let Some(marker) = plan.acknowledge_presentation {
            if self.presentation_resync_marker()? != Some(marker) {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_session_transition(&self, transition: &SessionTransition<'_>) -> Result<()> {
        let current = self.get_session(&transition.peer_device)?;
        if !session_eq(current.as_ref(), transition.before)?
            || session_eq(Some(transition.after), transition.before)?
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_pending(&self, pending: Option<PendingDelete>) -> Result<()> {
        let Some(pending) = pending else {
            return Ok(());
        };
        let row = self
            .row_by_rowid::<store_v2::PendingRows>(pending.sequence)?
            .ok_or(StoreError::InvalidTransition)?;
        let (encoded, _): (Vec<u8>, u64) = decode_exact(&row.payload)?;
        if Envelope::decode(&encoded)?.content_id() != pending.content_id {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_queue_delete(&self, delete: QueueDelete) -> Result<()> {
        let item = self
            .store_queue_row(delete.sequence)?
            .ok_or(StoreError::InvalidTransition)?;
        if item.envelope.content_id() != delete.content_id {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn store_queue_row(&self, sequence: i64) -> Result<Option<QueueItem>> {
        self.row_by_rowid::<store_v2::QueueRows>(sequence)?
            .map(|row| Self::decode_queue_item(&row.payload))
            .transpose()
    }

    fn validate_message_transition(&self, transition: &MessageTransition<'_>) -> Result<()> {
        if transition.before.id != transition.after.id
            || transition.before.peer != transition.after.peer
            || transition.before.direction != transition.after.direction
            || self
                .messages_with(&transition.before.peer)?
                .into_iter()
                .find(|message| message.id == transition.before.id)
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_new_message(&self, message: &MessageRecord) -> Result<()> {
        if self
            .messages_with(&message.peer)?
            .into_iter()
            .any(|existing| existing.id == message.id && existing.direction == message.direction)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_delivery_transition(&self, transition: &DeliveryTransition<'_>) -> Result<()> {
        if transition.before.message != transition.after.message
            || transition.before.account != transition.after.account
            || transition.before.device != transition.after.device
            || self
                .message_device_deliveries(&transition.before.message)?
                .into_iter()
                .find(|delivery| delivery.device == transition.before.device)
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_transition(&self, transition: &GroupTransition<'_>) -> Result<()> {
        if transition.before.id != transition.after.id
            || !valid_group_record(transition.after)
            || self.get_group(&transition.before.id)?.as_ref() != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_chain_transition(&self, transition: &GroupChainTransition<'_>) -> Result<()> {
        let current = self.get_group_chain(&transition.group, &transition.peer)?;
        if transition.before.is_empty()
            || transition.after.is_empty()
            || transition.before == transition.after
            || current.as_ref().map(|value| value.as_slice()) != Some(transition.before)
            || self.get_group(&transition.group)?.is_none_or(|group| {
                !group
                    .members
                    .iter()
                    .any(|member| member.peer == transition.peer)
            })
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_authority_transition(
        &self,
        transition: &GroupAuthorityTransition<'_>,
    ) -> Result<()> {
        if !valid_group_authority_record(transition.after)
            || transition
                .before
                .is_some_and(|before| before.group != transition.after.group)
            || self.get_group_authority(&transition.after.group)?.as_ref() != transition.before
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_message_transition(
        &self,
        transition: &GroupMessageTransition<'_>,
    ) -> Result<()> {
        if transition.before.id != transition.after.id
            || transition.before.group != transition.after.group
            || transition.before.sender != transition.after.sender
            || transition.before.direction != transition.after.direction
            || self
                .group_messages(&transition.before.group)?
                .into_iter()
                .find(|message| {
                    message.id == transition.before.id && message.sender == transition.before.sender
                })
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_new_group_message(&self, message: &GroupMessageRecord) -> Result<()> {
        if self
            .group_messages(&message.group)?
            .into_iter()
            .any(|existing| existing.id == message.id)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_new_media(
        &self,
        transfers: &[MediaTransferRecord],
        objects: &[MediaObjectRecord],
    ) -> Result<()> {
        let transfer_ids = transfers
            .iter()
            .map(|transfer| transfer.local_id)
            .collect::<HashSet<_>>();
        let object_ids = objects
            .iter()
            .map(|object| object.local_id)
            .collect::<HashSet<_>>();
        if transfer_ids.len() != transfers.len()
            || object_ids.len() != objects.len()
            || objects
                .iter()
                .any(|object| !transfer_ids.contains(&object.transfer_id))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transfer in transfers {
            if self.get_media_transfer(&transfer.local_id)?.is_some() {
                return Err(StoreError::InvalidTransition);
            }
        }
        for object in objects {
            if self.get_media_object(&object.local_id)?.is_some() {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_media_transfer_transition(
        &self,
        transition: &MediaTransferTransition<'_>,
    ) -> Result<()> {
        if transition.before.local_id != transition.after.local_id
            || transition.before == transition.after
            || self.get_media_transfer(&transition.before.local_id)?
                != Some(MediaRecord::Available(transition.before.clone()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_media_object_transition(
        &self,
        transition: &MediaObjectTransition<'_>,
    ) -> Result<()> {
        if transition.before.local_id != transition.after.local_id
            || transition.before.transfer_id != transition.after.transfer_id
            || transition.before == transition.after
            || self.get_media_object(&transition.before.local_id)?
                != Some(MediaRecord::Available(transition.before.clone()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    /// Read one accepted deferred control by its envelope id.
    pub fn get_deferred_control(
        &self,
        content_id: &[u8; 16],
    ) -> Result<Option<DeferredControlRecord>> {
        let key = store_v2::ContentKey::new(*content_id);
        self.get_equality::<store_v2::DeferredControlRows>(&key)?
            .map(|row| {
                row.verify_key(&key)?;
                let control: DeferredControlRecord = decode_exact(&row.payload)?;
                if control.content_id != *content_id {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(control)
            })
            .transpose()
    }

    /// Return a bounded page of accepted controls in stable row order.
    pub fn deferred_controls(&self, limit: usize) -> Result<Vec<DeferredControlRecord>> {
        if limit == 0 || limit > MAX_DEFERRED_CONTROLS {
            return Err(StoreError::RecordBounds);
        }
        self.rows::<store_v2::DeferredControlRows>()?
            .into_iter()
            .take(limit)
            .map(|row| {
                let control: DeferredControlRecord = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::ContentKey::new(control.content_id))?;
                Ok(control)
            })
            .collect()
    }

    pub(crate) fn validate_deferred_controls(&self) -> Result<()> {
        self.validate_rows::<store_v2::DeferredControlRows, _>(|row| {
            let control: DeferredControlRecord = decode_exact(&row.payload)?;
            if control.content_id == [0u8; 16]
                || control.body.is_empty()
                || control.body.len() > store_v2::MAX_RECORD_BYTES
            {
                return Err(StoreError::RecordBounds);
            }
            row.verify_key(&store_v2::ContentKey::new(control.content_id))?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })
    }

    fn check_commit_failpoint(&self, point: CommitPoint) -> Result<()> {
        #[cfg(feature = "test-failpoints")]
        {
            let armed = *self.commit_failpoint.borrow();
            if armed.is_some_and(|armed| armed.point == point.into_public()) {
                self.commit_failpoint.replace(None);
                return Err(match armed.expect("checked above").failure {
                    CommitFailure::Interrupted => {
                        StoreError::Io(std::io::Error::from(std::io::ErrorKind::Interrupted))
                    }
                    CommitFailure::DiskFull => {
                        StoreError::Io(std::io::Error::from(std::io::ErrorKind::StorageFull))
                    }
                    CommitFailure::Constraint => StoreError::InvalidTransition,
                    CommitFailure::Duplicate => StoreError::DuplicateIndex,
                });
            }
        }
        #[cfg(not(feature = "test-failpoints"))]
        match point {
            CommitPoint::BeforeStatement(index) | CommitPoint::AfterStatement(index) => {
                let _ = index;
            }
            _ => {}
        }
        Ok(())
    }
}

struct CommitWriter<'a, R> {
    store: &'a Store,
    rng: &'a mut R,
    statement: usize,
    records: CommittedRecordIds,
}

impl<R: CryptoRngCore> CommitWriter<'_, R> {
    fn write<T>(&mut self, operation: impl FnOnce(&Store, &mut R) -> Result<T>) -> Result<T> {
        self.store
            .check_commit_failpoint(CommitPoint::BeforeStatement(self.statement))?;
        let value = operation(self.store, self.rng)?;
        self.store
            .check_commit_failpoint(CommitPoint::AfterStatement(self.statement))?;
        self.statement += 1;
        Ok(value)
    }

    fn session(&mut self, transition: &SessionTransition<'_>) -> Result<()> {
        self.write(|store, rng| {
            let payload = Zeroizing::new(
                postcard::to_allocvec(transition.after).map_err(|_| StoreError::Serialization)?,
            );
            store.put_equality::<store_v2::SessionRows>(
                &store_v2::AccountKey::new(transition.peer_device),
                &payload,
                store_v2::IndexKeys::none(),
                rng,
            )
        })
    }

    fn group_chain(&mut self, transition: &GroupChainTransition<'_>) -> Result<()> {
        self.write(|store, rng| {
            store.put_group_chain(&transition.group, &transition.peer, transition.after, rng)
        })
    }

    fn queue(&mut self, items: &[QueueItem]) -> Result<()> {
        for item in items {
            let sequence = self.write(|store, rng| store.queue_push(item, rng))?;
            self.records.queue_sequences.push(sequence);
        }
        Ok(())
    }

    fn pending(&mut self, pending: Option<PendingDelete>) -> Result<()> {
        if let Some(pending) = pending {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::PendingRows>(pending.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    fn profile_bootstrap(&mut self, plan: &ProfileBootstrapPlan<'_>) -> Result<()> {
        self.write(|store, rng| store.put_identity(plan.identity, rng))?;
        self.write(|store, rng| store.put_device_state(plan.device_state, rng))?;
        self.write(|store, rng| store.put_prekeys(plan.prekeys, rng))
    }

    fn authority_profile_bootstrap(
        &mut self,
        plan: &AuthorityProfileBootstrapPlan<'_>,
    ) -> Result<()> {
        self.write(|store, rng| store.put_account_identity(plan.account, rng))?;
        self.write(|store, rng| store.put_device_authority_state(plan.device_state, rng))?;
        self.write(|store, rng| store.put_prekeys(plan.prekeys, rng))
    }

    fn authority_migration(&mut self, plan: &AuthorityMigrationPlan<'_>) -> Result<()> {
        self.write(|store, rng| store.put_account_identity(plan.account, rng))?;
        self.write(|store, rng| store.put_device_authority_state(plan.device_state, rng))
    }

    fn prekey_publish(&mut self, plan: &PrekeyPublishPlan<'_>) -> Result<()> {
        self.write(|store, rng| store.put_prekeys(plan.prekeys.after, rng))
    }

    fn pairwise_send(&mut self, plan: &PairwiseSendPlan<'_>) -> Result<()> {
        for transition in plan.sessions {
            self.session(transition)?;
        }
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(transition) = &plan.message_update {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for delivery in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(delivery, rng))?;
        }
        for transition in plan.delivery_updates {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        self.queue(plan.queue)?;
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for transition in plan.authorities {
            self.write(|store, rng| {
                store.put_group_authority(
                    transition.after.expect("validated authority replacement"),
                    rng,
                )
            })?;
        }
        if let Some(scheduled) = plan.scheduled {
            self.write(|store, _| {
                if store.delete_scheduled_message(&scheduled.id)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.clear_capabilities {
            self.write(|store, _| store.delete_capabilities(peer))?;
        }
        for marker in plan.clear_reset_markers {
            self.write(|store, _| store.clear_reset_marker(marker))?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transition in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transition.after, rng))?;
        }
        for transition in plan.media_objects {
            self.write(|store, rng| store.put_media_object(transition.after, rng))?;
        }
        for control in plan.delete_controls {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn pairwise_receive(&mut self, plan: &PairwiseReceivePlan<'_>) -> Result<()> {
        self.session(&plan.session)?;
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        if let Some(capabilities) = plan.capabilities {
            let peer = plan.session.peer_device;
            self.write(|store, rng| store.put_capabilities(&peer, capabilities, rng))?;
        }
        self.queue(plan.queue)?;
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        if plan.receipt_replay {
            let peer = plan.session.peer_device;
            self.write(|store, rng| {
                store.put_receipt_replay(&plan.content_id, &peer, plan.received_at, rng)
            })?;
        }
        self.pending(plan.source_pending)
    }

    fn group_send(&mut self, plan: &GroupSendPlan<'_>) -> Result<()> {
        if let Some(group) = &plan.group {
            self.write(|store, rng| store.put_group(group.after, rng))?;
        }
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_group_message(message, rng))?;
        }
        if let Some(transition) = &plan.message_update {
            self.write(|store, rng| {
                if store.update_group_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delivery in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(delivery, rng))?;
        }
        for transition in plan.delivery_updates {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        self.queue(plan.queue)?;
        if let Some(scheduled) = plan.scheduled {
            self.write(|store, _| {
                if store.delete_scheduled_message(&scheduled.id)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transition in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transition.after, rng))?;
        }
        for transition in plan.delete_chains {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::GroupChainRows>(
                    &store_v2::GroupMemberKey::new(transition.group, transition.peer),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        if let Some(authority) = &plan.authority {
            self.write(|store, rng| store.put_group_authority(authority.after, rng))?;
        }
        Ok(())
    }

    fn group_receive(&mut self, plan: &GroupReceivePlan<'_>) -> Result<()> {
        self.group_chain(&plan.chain)?;
        self.session(&plan.receipt_session)?;
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_group_message(message, rng))?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        self.queue(plan.queue)?;
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        let peer = plan.receipt_session.peer_device;
        self.write(|store, rng| {
            store.put_receipt_replay(&plan.content_id, &peer, plan.received_at, rng)
        })?;
        self.pending(plan.source_pending)
    }

    fn attachment_stage(&mut self, plan: &AttachmentStagePlan<'_>) -> Result<()> {
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(message) = plan.group_message {
            self.write(|store, rng| store.put_group_message(message, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        Ok(())
    }

    fn attachment_state(&mut self, plan: &AttachmentStatePlan<'_>) -> Result<()> {
        for transition in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transition.after, rng))?;
        }
        for transition in plan.media_objects {
            self.write(|store, rng| store.put_media_object(transition.after, rng))?;
        }
        for control in plan.delete_controls {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn group_state(&mut self, plan: &GroupStatePlan<'_>) -> Result<()> {
        for transition in plan.contacts {
            self.write(|store, rng| store.put_contact(transition.after, rng))?;
        }
        for transition in plan.groups {
            if let Some(group) = transition.after {
                self.write(|store, rng| store.put_group(group, rng))?;
            } else {
                let group = transition.before.expect("validated group deletion").id;
                self.write(|store, _| {
                    if store
                        .delete_equality::<store_v2::GroupRows>(&store_v2::GroupKey::new(group))?
                    {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
        }
        for transition in plan.chains {
            if let Some(chain) = transition.after {
                self.write(|store, rng| {
                    store.put_group_chain(&transition.group, &transition.peer, chain, rng)
                })?;
            } else {
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::GroupChainRows>(
                        &store_v2::GroupMemberKey::new(transition.group, transition.peer),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
        }
        for transition in plan.authorities {
            if let Some(authority) = transition.after {
                self.write(|store, rng| store.put_group_authority(authority, rng))?;
            } else {
                let group = transition
                    .before
                    .expect("validated authority deletion")
                    .group;
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::GroupAuthorityRows>(
                        &store_v2::GroupKey::new(group),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
        }
        for control in plan.delete_controls {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn device_control(&mut self, plan: &DeviceControlPlan<'_>) -> Result<()> {
        if let Some(state) = &plan.state {
            self.write(|store, rng| store.put_device_state(state.after, rng))?;
        }
        if let Some(recovery) = &plan.link_recovery {
            if let Some(after) = recovery.after {
                self.write(|store, rng| store.put_device_link_recovery(after, rng))?;
            } else {
                let target = recovery
                    .before
                    .expect("validated recovery deletion")
                    .target_device;
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::DeviceLinkRecoveryRows>(
                        &store_v2::AccountKey::new(target),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for encoded in plan.delete_events {
            self.write(|store, _| {
                if store.delete_device_sync_event(encoded)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for encoded in plan.insert_events {
            self.write(|store, rng| {
                if store.put_device_sync_event(encoded, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn authority_device_control(&mut self, plan: &AuthorityDeviceControlPlan<'_>) -> Result<()> {
        if let Some(state) = &plan.state {
            self.write(|store, rng| store.put_device_authority_state(state.after, rng))?;
        }
        if let Some(recovery) = &plan.link_recovery {
            if let Some(after) = recovery.after {
                self.write(|store, rng| store.put_device_link_recovery(after, rng))?;
            } else {
                let target = recovery
                    .before
                    .expect("validated recovery deletion")
                    .target_device;
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::DeviceLinkRecoveryRows>(
                        &store_v2::AccountKey::new(target),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for encoded in plan.delete_events {
            self.write(|store, _| {
                if store.delete_device_sync_event(encoded)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for encoded in plan.insert_events {
            self.write(|store, rng| {
                if store.put_device_sync_event(encoded, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-test-fixtures"))]
    fn device_link(&mut self, plan: &DeviceLinkPlan<'_>) -> Result<()> {
        self.write(|store, rng| store.put_identity(plan.identity.after, rng))?;
        self.write(|store, rng| store.put_device_state(plan.device_state.after, rng))?;
        for contact in plan.contacts {
            self.write(|store, rng| store.put_contact(contact, rng))?;
        }
        for device in plan.devices {
            self.write(|store, rng| store.put_contact_device(device, rng))?;
        }
        for message in plan.messages {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        for group in plan.groups {
            self.write(|store, rng| store.put_group(group, rng))?;
        }
        for message in plan.group_messages {
            self.write(|store, rng| store.put_group_message(message, rng))?;
        }
        for authority in plan.authorities {
            self.write(|store, rng| store.put_group_authority(authority, rng))?;
        }
        for record in plan.local_metadata {
            self.write(|store, rng| store.put_local_metadata(record, rng))?;
        }
        for note in plan.notes {
            self.write(|store, rng| store.put_note_message(note, rng))?;
        }
        for record in plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(record, rng))?;
        }
        for encoded in plan.sync_events {
            self.write(|store, rng| {
                if store.put_device_sync_event(encoded, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn authority_device_link(&mut self, plan: &AuthorityDeviceLinkPlan<'_>) -> Result<()> {
        self.write(|store, rng| store.put_account_identity(plan.account.after, rng))?;
        self.write(|store, rng| store.put_device_authority_state(plan.device_state.after, rng))?;
        for contact in plan.contacts {
            self.write(|store, rng| store.put_contact(contact, rng))?;
        }
        for device in plan.devices {
            self.write(|store, rng| store.put_contact_device(device, rng))?;
        }
        for message in plan.messages {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        for group in plan.groups {
            self.write(|store, rng| store.put_group(group, rng))?;
        }
        for message in plan.group_messages {
            self.write(|store, rng| store.put_group_message(message, rng))?;
        }
        for authority in plan.authorities {
            self.write(|store, rng| store.put_group_authority(authority, rng))?;
        }
        for record in plan.local_metadata {
            self.write(|store, rng| store.put_local_metadata(record, rng))?;
        }
        for note in plan.notes {
            self.write(|store, rng| store.put_note_message(note, rng))?;
        }
        for record in plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(record, rng))?;
        }
        for encoded in plan.sync_events {
            self.write(|store, rng| {
                if store.put_device_sync_event(encoded, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.reset_peers {
            self.write(|store, rng| store.put_reset_marker_with_rng(peer, rng))?;
        }
        Ok(())
    }

    fn device_projection(&mut self, plan: &DeviceProjectionPlan<'_>) -> Result<()> {
        for projection in plan.projections {
            match projection {
                DeviceProjection::Contact { before, after } => {
                    if let Some(record) = after {
                        self.write(|store, rng| store.put_contact(record, rng))?;
                    } else {
                        let peer = before.expect("validated contact deletion").peer;
                        self.write(|store, _| {
                            if store.delete_contact(&peer)? {
                                Ok(())
                            } else {
                                Err(StoreError::InvalidTransition)
                            }
                        })?;
                    }
                }
                DeviceProjection::ContactDevice { before, after } => {
                    if let Some(record) = after {
                        self.write(|store, rng| store.put_contact_device(record, rng))?;
                    } else {
                        let record = before.expect("validated device deletion");
                        self.write(|store, _| {
                            store.delete_contact_device(&record.account, &record.device)
                        })?;
                    }
                }
                DeviceProjection::Message { before, after } => {
                    if let Some(record) = after {
                        if before.is_some() {
                            self.write(|store, rng| {
                                if store.update_message(record, rng)? {
                                    Ok(())
                                } else {
                                    Err(StoreError::InvalidTransition)
                                }
                            })?;
                        } else {
                            self.write(|store, rng| store.put_message(record, rng))?;
                        }
                        self.records.messages.push(record.id);
                    } else {
                        let record = before.expect("validated message deletion");
                        self.write(|store, _| {
                            if store.delete_message_record(
                                &record.peer,
                                record.direction,
                                &record.id,
                            )? {
                                Ok(())
                            } else {
                                Err(StoreError::InvalidTransition)
                            }
                        })?;
                    }
                }
                DeviceProjection::GroupMessage { before, after } => {
                    if let Some(record) = after {
                        if before.is_some() {
                            self.write(|store, rng| {
                                if store.update_group_message(record, rng)? {
                                    Ok(())
                                } else {
                                    Err(StoreError::InvalidTransition)
                                }
                            })?;
                        } else {
                            self.write(|store, rng| store.put_group_message(record, rng))?;
                        }
                    } else {
                        let record = before.expect("validated group-message deletion");
                        self.write(|store, _| {
                            if store.delete_group_message_record(
                                &record.group,
                                &record.sender,
                                &record.id,
                            )? {
                                Ok(())
                            } else {
                                Err(StoreError::InvalidTransition)
                            }
                        })?;
                    }
                }
                DeviceProjection::LocalMetadata { before, after } => {
                    if let Some(record) = after {
                        self.write(|store, rng| store.put_local_metadata(record, rng))?;
                    } else {
                        let key = before.expect("validated metadata deletion").key();
                        self.write(|store, _| {
                            if store.delete_local_metadata(&key)? {
                                Ok(())
                            } else {
                                Err(StoreError::InvalidTransition)
                            }
                        })?;
                    }
                }
                DeviceProjection::Note { after } => {
                    self.write(|store, rng| store.put_note_message(after, rng))?;
                }
            }
        }
        for delete in plan.delete_sessions {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::SessionRows>(&store_v2::AccountKey::new(
                    delete.peer_device,
                ))? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_capabilities {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::CapabilityRows>(&store_v2::AccountKey::new(
                    delete.peer_device,
                ))? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn handshake_receive(&mut self, plan: &HandshakeReceivePlan<'_>) -> Result<()> {
        if let Some(prekeys) = &plan.prekeys {
            self.write(|store, rng| store.put_prekeys(prekeys.after, rng))?;
        }
        self.session(&plan.session)?;
        self.write(|store, rng| store.put_contact(plan.contact, rng))?;
        for device in plan.devices {
            self.write(|store, rng| store.put_contact_device(device, rng))?;
        }
        for delete in plan.delete_devices {
            self.write(|store, _| {
                store.delete_contact_device(&delete.before.account, &delete.before.device)
            })?;
        }
        for peer in plan.delete_sessions {
            self.write(|store, _| store.delete_session(peer))?;
        }
        for peer in plan.delete_capabilities {
            self.write(|store, _| store.delete_capabilities(peer))?;
        }
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for group in plan.groups {
            self.write(|store, rng| store.put_group(group.after, rng))?;
        }
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        self.queue(plan.queue)?;
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        if plan.receipt_replay {
            let peer = plan.session.peer_device;
            self.write(|store, rng| {
                store.put_receipt_replay(&plan.content_id, &peer, plan.received_at, rng)
            })?;
        }
        self.pending(plan.source_pending)
    }

    fn receipt_receive(&mut self, plan: &ReceiptReceivePlan<'_>) -> Result<()> {
        self.session(&plan.session)?;
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        self.queue(plan.queue)?;
        for transition in plan.messages {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for transition in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        for transition in plan.group_messages {
            self.write(|store, rng| {
                if store.update_group_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        if let Some(capabilities) = plan.capabilities {
            let peer = plan.session.peer_device;
            self.write(|store, rng| store.put_capabilities(&peer, capabilities, rng))?;
        }
        if let Some(control) = plan.deferred_control {
            self.write(|store, rng| {
                let encoded =
                    postcard::to_allocvec(control).map_err(|_| StoreError::Serialization)?;
                store.put_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                    &encoded,
                    store_v2::IndexKeys::none(),
                    rng,
                )
            })?;
        }
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        self.pending(plan.source_pending)
    }

    fn maintenance(&mut self, plan: &MaintenancePlan<'_>) -> Result<()> {
        for content_id in plan.seen {
            self.write(|store, rng| {
                store.put_equality::<store_v2::SeenRows>(
                    &store_v2::ContentKey::new(*content_id),
                    content_id,
                    store_v2::IndexKeys::none(),
                    rng,
                )
            })?;
        }
        for pending in plan.delete_pending {
            self.pending(Some(*pending))?;
        }
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.update_queue {
            self.write(|store, rng| {
                store.queue_update(transition.sequence, transition.after, rng)
            })?;
        }
        for content_id in plan.delete_replay {
            self.write(|store, _| {
                store.delete_equality::<store_v2::ReceiptReplayRows>(
                    &store_v2::ContentKey::new(*content_id),
                )?;
                Ok(())
            })?;
        }
        for transition in plan.messages {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for transition in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        for transition in plan.group_messages {
            self.write(|store, rng| {
                if store.update_group_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for transition in plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(transition.after, rng))?;
        }
        for delete in plan.delete_messages {
            self.write(|store, _| {
                if store.delete_message_record(
                    &delete.before.peer,
                    delete.before.direction,
                    &delete.before.id,
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_group_messages {
            self.write(|store, _| {
                if store.delete_group_message_record(
                    &delete.before.group,
                    &delete.before.sender,
                    &delete.before.id,
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_media {
            for object_id in delete.object_ids {
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::MediaObjectRows>(
                        &store_v2::LocalIdKey::new(*object_id),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
            self.write(|store, _| {
                if store.delete_equality::<store_v2::MediaTransferRows>(
                    &store_v2::LocalIdKey::new(delete.transfer_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for scheduled in plan.delete_scheduled {
            self.write(|store, _| {
                if store.delete_scheduled_message(&scheduled.id)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.delete_sessions {
            self.write(|store, _| {
                if store
                    .delete_equality::<store_v2::SessionRows>(&store_v2::AccountKey::new(*peer))?
                {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.delete_capabilities {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::CapabilityRows>(&store_v2::AccountKey::new(
                    *peer,
                ))? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for marker in plan.clear_reset_markers {
            self.write(|store, _| store.clear_reset_marker(marker))?;
        }
        for control in plan.delete_controls {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        if let Some(marker) = plan.acknowledge_presentation {
            self.write(|store, _| {
                if store.presentation_resync_marker()? != Some(marker) {
                    return Err(StoreError::InvalidTransition);
                }
                if store
                    .delete_equality::<store_v2::PresentationMarkerRows>(&store_v2::SingletonKey)?
                {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CommitPoint {
    BeforeBegin,
    AfterBegin,
    BeforeStatement(usize),
    AfterStatement(usize),
    BeforeCommit,
    AfterCommit,
}

#[cfg(feature = "test-failpoints")]
impl CommitPoint {
    fn into_public(self) -> CommitFailpoint {
        match self {
            Self::BeforeBegin => CommitFailpoint::BeforeBegin,
            Self::AfterBegin => CommitFailpoint::AfterBegin,
            Self::BeforeStatement(index) => CommitFailpoint::BeforeStatement(index),
            Self::AfterStatement(index) => CommitFailpoint::AfterStatement(index),
            Self::BeforeCommit => CommitFailpoint::BeforeCommit,
            Self::AfterCommit => CommitFailpoint::AfterCommit,
        }
    }
}

fn session_eq(left: Option<&Session>, right: Option<&Session>) -> Result<bool> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => {
            let left = postcard::to_allocvec(left).map_err(|_| StoreError::Serialization)?;
            let right = postcard::to_allocvec(right).map_err(|_| StoreError::Serialization)?;
            Ok(left == right)
        }
        _ => Ok(false),
    }
}

fn identity_eq(left: &Identity, right: &Identity) -> bool {
    left.to_bytes().as_slice() == right.to_bytes().as_slice()
}

fn valid_group_record(group: &GroupRecord) -> bool {
    let member_ids = group
        .members
        .iter()
        .map(|member| member.peer)
        .collect::<HashSet<_>>();
    let pending_ids = group
        .pending
        .iter()
        .map(|pending| pending.peer)
        .collect::<HashSet<_>>();
    group.id != [0u8; 32]
        && !group.name.is_empty()
        && group.name.len() <= MAX_GROUP_NAME_LEN
        && !group.members.is_empty()
        && group.members.len() <= MAX_GROUP_AUTHORITY_MEMBERS
        && member_ids.len() == group.members.len()
        && group.members.iter().all(|member| {
            !member.identity.is_empty() && member.identity.len() <= MAX_GROUP_MEMBER_IDENTITY_LEN
        })
        && group.secret != [0u8; 32]
        && !group.sender_chain.is_empty()
        && group.pending.len() <= MAX_GROUP_AUTHORITY_MEMBERS
        && pending_ids.len() == group.pending.len()
        && group
            .pending
            .iter()
            .all(|pending| member_ids.contains(&pending.peer))
}

fn valid_group_authority_record(authority: &GroupAuthorityRecord) -> bool {
    let consumed = authority
        .consumed_requests
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    authority.group != [0u8; 32]
        && authority.state_id != [0u8; 16]
        && !authority.state_payload.is_empty()
        && authority.consumed_requests.len() <= MAX_GROUP_ADMIN_REQUESTS
        && consumed.len() == authority.consumed_requests.len()
}

const LEGACY_GROUP_SENDER_ORIGIN_MAGIC: &[u8; 4] = b"KGS2";
const GROUP_SENDER_ORIGIN_MAGIC: &[u8; 4] = b"KGS3";

#[derive(Deserialize)]
struct ValidatedOutgoingGroupOrigin {
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

#[derive(Deserialize)]
struct ValidatedGroupSenderState {
    origin_generation: u64,
    chain: GroupSenderChain,
    origins: Vec<ValidatedOutgoingGroupOrigin>,
}

#[derive(Deserialize)]
struct LegacyValidatedGroupSenderState {
    chain: GroupSenderChain,
    origins: Vec<ValidatedOutgoingGroupOrigin>,
}

fn decode_validated_group_sender_state(encoded: &[u8]) -> Result<ValidatedGroupSenderState> {
    let state = if let Some(body) = encoded.strip_prefix(GROUP_SENDER_ORIGIN_MAGIC) {
        decode_exact(body)?
    } else if let Some(body) = encoded.strip_prefix(LEGACY_GROUP_SENDER_ORIGIN_MAGIC) {
        let legacy: LegacyValidatedGroupSenderState = decode_exact(body)?;
        ValidatedGroupSenderState {
            origin_generation: 1,
            chain: legacy.chain,
            origins: legacy.origins,
        }
    } else {
        return Err(StoreError::InvalidTransition);
    };
    if state.origin_generation == 0
        || state.origins.is_empty()
        || state.origins.len() > MAX_GROUP_COMMIT_QUEUE_ROWS
        || state.origins.windows(2).any(|pair| {
            (pair[0].recipient_account, pair[0].recipient_device)
                >= (pair[1].recipient_account, pair[1].recipient_device)
        })
        || state.origins.iter().any(|origin| {
            origin.recipient_account == [0u8; 32]
                || origin.recipient_device == [0u8; 32]
                || origin.key_id != state.chain.key_id()
                || origin.chain_key == [0u8; 32]
                || origin.origin_key == [0u8; 32]
                || origin.acknowledged && origin.wire_id.is_none()
        })
    {
        return Err(StoreError::InvalidTransition);
    }
    Ok(state)
}

fn validate_group_origin_control_transition(
    before: &GroupRecord,
    after: &GroupRecord,
    queue: &[QueueItem],
) -> Result<()> {
    let prior = decode_validated_group_sender_state(&before.sender_chain)?;
    let candidate = decode_validated_group_sender_state(&after.sender_chain)?;
    if postcard::to_allocvec(&prior.chain).map_err(|_| StoreError::Serialization)?
        != postcard::to_allocvec(&candidate.chain).map_err(|_| StoreError::Serialization)?
        || prior.origin_generation != candidate.origin_generation
        || prior.origins.len() != candidate.origins.len()
        || !before.pending.is_empty()
        || !after.pending.is_empty()
    {
        return Err(StoreError::InvalidTransition);
    }
    let mut changed = 0usize;
    for (old, new) in prior.origins.iter().zip(&candidate.origins) {
        if old.recipient_account != new.recipient_account
            || old.recipient_device != new.recipient_device
            || old.key_id != new.key_id
            || old.chain_key != new.chain_key
            || old.iteration != new.iteration
            || old.origin_key != new.origin_key
        {
            return Err(StoreError::InvalidTransition);
        }
        if old.wire_id == new.wire_id
            && old.last_sent == new.last_sent
            && old.acknowledged == new.acknowledged
        {
            continue;
        }
        changed += 1;
        if new.last_sent <= old.last_sent
            || new.acknowledged
            || new.wire_id.is_none_or(|wire_id| {
                !queue.iter().any(|item| {
                    item.peer == new.recipient_device
                        && item.envelope.kind == EnvelopeKind::GroupControl
                        && item.envelope.content_id() == wire_id
                })
            })
        {
            return Err(StoreError::InvalidTransition);
        }
    }
    if changed != 1 {
        return Err(StoreError::InvalidTransition);
    }
    Ok(())
}

fn validate_group_control_transition(
    transition: &GroupTransition<'_>,
    queue: &[QueueItem],
) -> Result<()> {
    let before = transition.before;
    let after = transition.after;
    if before.name != after.name
        || before.creator != after.creator
        || before.members != after.members
        || before.secret != after.secret
        || before.prev_secret != after.prev_secret
        || before.generation != after.generation
        || before.sent_since_rotation != after.sent_since_rotation
        || before.pending.len() != after.pending.len()
    {
        return Err(StoreError::InvalidTransition);
    }
    if before.sender_chain != after.sender_chain {
        return validate_group_origin_control_transition(before, after, queue);
    }
    let mut changed = 0usize;
    for (prior, candidate) in before.pending.iter().zip(&after.pending) {
        if prior.peer != candidate.peer
            || prior.key_id != candidate.key_id
            || prior.chain_key != candidate.chain_key
            || prior.iteration != candidate.iteration
        {
            return Err(StoreError::InvalidTransition);
        }
        if prior.wire_id == candidate.wire_id && prior.last_sent == candidate.last_sent {
            continue;
        }
        changed += 1;
        if candidate.last_sent == 0
            || candidate.wire_id.is_none_or(|wire_id| {
                !queue.iter().any(|item| {
                    item.envelope.kind == EnvelopeKind::GroupControl
                        && item.envelope.content_id() == wire_id
                })
            })
        {
            return Err(StoreError::InvalidTransition);
        }
    }
    if changed != 1 {
        return Err(StoreError::InvalidTransition);
    }
    Ok(())
}

fn mutation_count<const N: usize>(counts: [usize; N]) -> Result<usize> {
    counts.into_iter().try_fold(0usize, |sum, count| {
        sum.checked_add(count).ok_or(StoreError::RecordBounds)
    })
}
