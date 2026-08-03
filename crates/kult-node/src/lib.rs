//! Komms runtime (docs/03-architecture.md §2): composes the crypto core,
//! protocol layer, encrypted store and transports into one event-driven node.
//!
//! Responsibilities, and nothing else:
//!
//! - **Session lifecycle** — initiating handshakes from stored prekey
//!   bundles, answering inbound handshakes from the local prekey vault,
//!   persisting ratchet state after every step.
//! - **Delivery engine** — every outbound message is persisted `Queued`
//!   before any crypto runs, advances to `Sent` only when a transport
//!   actually accepted the envelope, and to `Delivered` only on an
//!   end-to-end encrypted receipt. Nothing is ever faked.
//! - **Transport scheduler** — ranks the registered carriers per recipient
//!   by (reachability, latency class, cost class) and falls through the
//!   ranking on failure; failed items retry with exponential backoff. The
//!   queue flushes in priority order (text > receipts > handshakes,
//!   docs/05-transports.md §4.2 rule 3), and payloads over 4 KiB are held
//!   off airtime-budgeted (LoRa) links with honest feedback instead of
//!   silently hogging the mesh.
//! - **Dedup & reassembly** — inbound envelopes are deduplicated by content
//!   id (multipath duplicates are normal), fragments reassembled, and
//!   envelopes that arrive before the session that can read them (courier
//!   reordering) are stashed persistently and retried — never lost, never
//!   double-processed. Partials stuck missing fragments are NACKed back to
//!   the sender, which retransmits exactly the missing indices (selective
//!   retransmission, §4.2 rule 2) — airtime is the scarcest resource in
//!   the system.
//!
//! Driving the node: applications call commands ([`Node::send_message`],
//! [`Node::add_contact`], … or the [`Command`] enum) and then pump
//! [`Node::tick`] — one receive/flush cycle — collecting [`Event`]s.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "test-failpoints")]
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::future::{join_all, select, Either};
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use kult_crypto::{
    derive_rendezvous_epoch_keys, initiate, open_account_recovery_authority, open_anonymous,
    open_rendezvous_record, rendezvous_epoch, respond, safety_number,
    seal_account_recovery_authority, seal_anonymous, seal_rendezvous_record, AdmissionPolicy,
    AuthorityDevicePrekeyBundle as DevicePrekeyBundle, AuthorityPairingBundle, ConnectCode,
    DeviceAuthorityCertificate, DiscoveryIngressBundle, DiscoveryRecord, DiscoveryRoute,
    DiscoveryRouteKind, Identity, IdentityPublic, InitialMessage, KdfProfile,
    PendingAuthorityDeviceLinkSource, PendingAuthorityDeviceLinkTarget, PrekeyBundle,
    PreparedAuthorityDeviceLink, RatchetMessage, SafetyNumber, Session,
    DISCOVERY_LOOKUP_EPOCH_ADJACENCY, DISCOVERY_PUBLISH_EPOCH_AHEAD,
    DISCOVERY_PUBLISH_EPOCH_BEHIND, DISCOVERY_RECORD_SIZE, MAX_DISCOVERY_CANDIDATES,
    MAX_DISCOVERY_ROUTES, RENDEZVOUS_MAX_TTL_SECS,
};
use kult_protocol::{
    admission_invitation_proof, decode_content, delivery_token, encode_disappearing_text_payload,
    encode_edit, encode_ephemeral, encode_text, epoch_day, fragment, intro_token,
    is_capability_control, is_discovery_upgrade_control, is_rendezvous_provider_control,
    is_wake_capability_control, pad, retention_bucket, solve_admission_puzzle, unpad,
    verify_admission_puzzle, AdmissionContext, AdmissionEnvelope, AdmissionProofKind,
    CapabilityControl, DecodedContent, DiscoveryUpgradeControl, Edit, Envelope, EnvelopeKind,
    Ephemeral, FormatCapabilities, MailboxKey, Reassembler, ReceiptPayload,
    RendezvousLookupRequest, RendezvousProviderControl, RendezvousProviderDescriptor,
    RendezvousRegisterRequest, RendezvousRoute, RendezvousRouteRecord, WakeCapabilityControl,
    WakeCapabilityDescriptor, WakeEnvironment, WakePlatform, WakeProfile, WakeRegisterRequest,
    WakeTriggerRequest, CONTENT_FORMAT_V1, CONTENT_KIND_ATTACHMENT, CONTENT_KIND_CALL_CONTROL,
    CONTENT_KIND_EDIT, CONTENT_KIND_EPHEMERAL, CONTENT_KIND_GROUP_AUTHORITY, CONTENT_KIND_MENTION,
    CONTENT_KIND_POLL, CONTENT_KIND_TEXT, ENVELOPE_HEADER_LEN, MAX_ADMISSION_PUZZLE_ATTEMPTS,
    MAX_EDIT_TEXT_LEN, MAX_EPHEMERAL_LIFETIME_SECS, MIN_EPHEMERAL_LIFETIME_SECS,
    REASSEMBLY_WINDOW_SECS, WAKE_CAPABILITY_MAX_LIFETIME_SECS,
};
use kult_store::{
    AdmissionAcceptPlan, AdmissionDiscardPlan, AdmissionReplayTombstone, AdmissionStagePlan,
    AdmissionSweepPlan, AdmissionTransportClass, AttachmentStatePlan, AuthorityDeviceControlPlan,
    AuthorityMigrationPlan, BlockedIdentityRecord, CommitPlan, CommitReceipt, ContactDeviceDelete,
    ContactDeviceRecord, ContactDeviceTransition, ContactRecord, ConversationId,
    ConversationMetadata, DeferredControlKind, DeferredControlRecord, DeliveryState,
    DeliveryTransition, DeviceAuthorityStateRecord, DeviceAuthorityStateTransition, Direction,
    DiscoveryCapabilityState, EphemeralConversation, EphemeralMode, EphemeralRecord,
    EphemeralState, EphemeralTransition, GroupMessageDelete, GroupMessageRecord,
    GroupMessageTransition, GroupRecord, GroupTransition, HandshakeReceivePlan, LocalMetadataKey,
    LocalMetadataRecord, MaintenancePlan, MediaDelete, MediaObjectRecord, MediaObjectTransition,
    MediaTransferRecord, MediaTransferTransition, MessageDelete, MessageDeviceDeliveryRecord,
    MessageRecord, MessageTransition, NoteMessageRecord, PairwiseReceivePlan, PairwiseSendPlan,
    PendingDelete, PendingStagePlan, PrekeyPublishPlan, PrekeyTransition, ProvisionalRequestRecord,
    QueueClass, QueueDelete, QueueItem, QueueTransition, ReceiptReceivePlan, RendezvousLocalConfig,
    RendezvousProviderState, RendezvousServiceTransition, RendezvousStoredRoute,
    ScheduledConversation as StoreScheduledConversation, ScheduledMessageRecord, SessionTransition,
    Store, WakeCapabilityDirection, WakeRevocationPlan, WakeRevocationRecord,
    WakeRevocationTransition, WakeServiceState, WakeServiceTransition, WakeStoredCapability,
    MAX_ADMISSION_REPLAY_LIFETIME_SECS, MAX_ADMISSION_REPLAY_TOMBSTONES,
    MAX_MAINTENANCE_TRANSITIONS, MAX_PROVISIONAL_CONTENT_BYTES, MAX_PROVISIONAL_LIFETIME_SECS,
    MAX_PROVISIONAL_PREVIEW_BYTES, MAX_WAKE_REVOCATION_ROWS, PROVISIONAL_REQUEST_VERSION,
};
use kult_transport::{
    rendezvous_record_route, rendezvous_route_hint, CostClass, DeliveryHint, Discovery,
    DiscoveryNamespace, IngressClass, Reachability, ReceivedEnvelope, RendezvousClient,
    RendezvousProvider, SendReceipt, Transport, WakeClient, WakeProvider, MAX_RENDEZVOUS_PROVIDERS,
    MAX_WAKE_PROVIDERS,
};

mod api;
#[cfg(all(test, feature = "test-failpoints"))]
mod atomic_tests;
mod attachment;
mod authority;
mod calls;
mod carrier;
mod contact_names;
mod devices;
mod edits;
mod error;
mod file_presentation;
mod folders;
mod groups;
mod icons;
mod incognito_keyboard;
mod labels;
mod pins;
mod polls;
mod screen_security;
mod text_formatting;
mod theme;
mod vault;

pub use api::{
    AttachmentConversation, AttachmentDirection, AttachmentInfo, AttachmentMetadata,
    AttachmentObjectInfo, CallAudioFrame, CallAvailability, CallDirection, CallEndReason, CallInfo,
    CallPhase, CallUnavailableReason, CarrierCapability, CarrierCapabilitySnapshot, Command,
    ContactAuthorityConflictInfo, ContentStatus, CustomIconCrop, CustomIconInfo, CustomIconUsage,
    DeviceAuthorityConflictInfo, DeviceAuthorityConflictType, DeviceLinkSelection, EditVersionInfo,
    Event, FolderConversationInfo, FolderConversationList, FolderInfo, FolderSelection,
    GroupAuthorityInfo, GroupInfo, GroupInvitationInfo, GroupMemberRoleInfo,
    GroupMentionCapability, GroupSecurityInfo, GroupSecurityLevel, LabelConversationInfo,
    LabelFilterInfo, LabelInfo, LabelMatchMode, LinkedDeviceInfo, MentionCapabilityIssue,
    MentionCapabilityIssueReason, MentionSpan, MessageDeviceDeliveryInfo, MessageRequestInfo,
    PinConversationInfo, PinConversationList, PinInfo, PollInfo, PollOptionInfo, PollVoteInfo,
    ResolvedGroupMessage, ResolvedMessage, ScheduledConversation, ScheduledMessageInfo,
    StaleFolderInfo, StaleFolderReason as NodeStaleFolderReason, StaleLabelInfo,
    StaleLabelReason as NodeStaleLabelReason,
};
pub use calls::{CALL_OFFER_LIFETIME_SECS, MAX_CALL_OFFER_LIFETIME_SECS};
pub use contact_names::{ContactNameAssessment, ContactNameWarning, MAX_CONTACT_NAME_BYTES};
pub use edits::MAX_MESSAGE_EDITS;
pub use error::NodeError;
pub use file_presentation::{
    classify_attachment_file, AttachmentFileKind, AttachmentFilePresentation,
    AttachmentFileWarning, AttachmentOpenPolicy,
};
pub use groups::{
    MAX_GROUP_INVITATION_BYTES, MAX_GROUP_INVITATION_LIFETIME_SECS, MAX_GROUP_INVITATION_REQUESTS,
};
pub use incognito_keyboard::{
    incognito_keyboard_policy, IncognitoKeyboardLevel, IncognitoKeyboardPlatform,
    IncognitoKeyboardPolicy, INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
};
pub use kult_protocol::GroupRole;
pub use kult_store::{
    AuthorityResetHistoryRecord, ConversationId as LabelConversationId, CustomIconTarget,
    ThemePreference, CUSTOM_ICON_BUNDLED_GLYPHS, CUSTOM_ICON_DIMENSION, CUSTOM_ICON_MEDIA_TYPE,
    FOLDER_ID_RETRY_LIMIT, LABEL_COLORS, MAX_CUSTOM_ICONS, MAX_CUSTOM_ICON_BYTES,
    MAX_CUSTOM_ICON_TOTAL_BYTES, MAX_FOLDERS, MAX_FOLDER_ASSIGNMENTS, MAX_LABELS,
    MAX_LABELS_PER_CONVERSATION, MAX_LABEL_ASSIGNMENTS, MAX_LOCAL_METADATA_STRING_BYTES, MAX_PINS,
    NOTE_TO_SELF_CONVERSATION_ID, THEME_PREFERENCES, THEME_PREFERENCE_KEY, THEME_SEMANTIC_ROLES,
};
#[cfg(feature = "test-failpoints")]
#[doc(hidden)]
pub use kult_store::{CommitFailpoint, CommitFailure};
pub use polls::MAX_POLL_VOTE_REVISIONS;
pub use screen_security::{
    screen_security_policy, ScreenSecurityLevel, ScreenSecurityPlatform, ScreenSecurityPolicy,
};
pub use text_formatting::{
    format_text, FormattedText, FormattedTextBlock, FormattedTextRun, TextFormatBlockKind,
    TextFormatHighlight, TextFormatStyle, MAX_FORMAT_BLOCKS, MAX_FORMAT_HIGHLIGHTS,
    MAX_FORMAT_INLINE_DEPTH, MAX_FORMAT_LIST_DEPTH, MAX_FORMAT_RUNS, MAX_FORMAT_SOURCE_BYTES,
};

use vault::PrekeyVault;

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NodeError>;

/// Deterministic process-interruption checkpoints for transition crash tests.
#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionFailpoint {
    /// Before the numbered candidate cryptographic operation.
    BeforeCryptoStep(usize),
    /// After the numbered candidate cryptographic operation.
    AfterCryptoStep(usize),
    /// After commit and before live candidate state replaces memory.
    BeforeMemoryReplacement,
    /// Immediately after live candidate state replaces memory.
    AfterMemoryReplacement,
    /// Before queued presentation events leave the node.
    BeforeEventDelivery,
    /// Immediately after queued presentation events leave the node.
    AfterEventDelivery,
}

/// Associated data for anonymous-boxed handshake flights (fixed across the
/// protocol; also used by the M2 acceptance tests).
const HS_AD: &[u8] = b"KK-handshake-v1";
const LEGACY_DEVICE_INITIAL_MAGIC: &[u8; 4] = b"KDI1";
const DEVICE_INITIAL_MAGIC: &[u8; 4] = b"KDI2";
const ACCOUNT_INITIAL_MAGIC: &[u8; 4] = b"KAI1";

/// Prekey bundles expire after 30 days (docs/06-identity-trust.md).
const BUNDLE_TTL_SECS: u64 = 30 * 86_400;
/// Maximum separately configured DHT paths queried for one bounded lookup.
const MAX_DISCOVERY_PLANES: usize = 8;
/// Maximum fixed rendezvous HTTP operations started by one heartbeat.
const MAX_RENDEZVOUS_OPERATIONS_PER_TICK: usize = 16;
/// First registration attempts are staggered across five minutes.
const RENDEZVOUS_INITIAL_JITTER_SECS: u64 = 300;
/// Confirmed registrations refresh once per hour.
const RENDEZVOUS_REGISTER_REFRESH_SECS: u64 = 3_600;
/// Active routes refresh when fewer than fifteen minutes remain.
const RENDEZVOUS_NEAR_EXPIRY_SECS: u64 = 900;
/// Minimum transport backoff.
const RENDEZVOUS_BACKOFF_MIN_SECS: u64 = 5;
/// Maximum transport backoff before the circuit breaker.
const RENDEZVOUS_BACKOFF_MAX_SECS: u64 = 900;
/// Consecutive failures that open the provider circuit.
const RENDEZVOUS_CIRCUIT_FAILURES: u8 = 5;
/// Open-circuit interval.
const RENDEZVOUS_CIRCUIT_OPEN_SECS: u64 = 1_800;
/// Maximum authenticated legacy re-handshakes started per heartbeat.
const MAX_RENDEZVOUS_REHANDSHAKES_PER_TICK: usize = 4;
/// One heartbeat never waits longer than this for the optional provider
/// plane, regardless of the number of configured providers.
const RENDEZVOUS_MAINTENANCE_BUDGET: Duration = Duration::from_secs(5);
/// Maximum gateway trigger or revoke operations started by one heartbeat.
const MAX_WAKE_GATEWAY_OPERATIONS_PER_TICK: usize = 8;
/// Revoke work cannot consume every gateway slot and starve ordinary wakes.
const MAX_WAKE_REVOCATIONS_PER_TICK: usize = 4;
/// Maximum durable revocation retry rows changed by one heartbeat.
const MAX_WAKE_REVOCATION_CHANGES_PER_TICK: usize = 32;
/// All gateway trigger and revoke work shares one bounded heartbeat deadline.
const WAKE_MAINTENANCE_BUDGET: Duration = Duration::from_secs(5);
/// Maximum contact-device capability sets minted by one platform callback.
const MAX_WAKE_REGISTRATION_RELATIONSHIPS_PER_CALL: usize = 8;
/// All registration work owned by one platform callback shares this deadline.
const WAKE_REGISTRATION_BUDGET: Duration = Duration::from_secs(20);
/// Maximum platform-owned background collection duration accepted by core.
pub const MAX_WAKE_COLLECTION_DURATION: Duration = Duration::from_secs(25);
/// Smaller receive domain used for a native-wake collection pass.
const MAX_WAKE_PENDING_WORK_PER_TICK: usize = 32;
/// Maximum encoded envelope bytes admitted to one native-wake collection pass.
const MAX_WAKE_COLLECTION_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RendezvousOperationKind {
    Register,
    Lookup,
}

/// Public-route policy applied while creating ADR-0031 records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// Disclosed replaceable defaults; public records contain mailboxes only.
    #[default]
    Standard,
    /// Metadata-hiding ingress; public records contain mailboxes only.
    Private,
    /// User-operated mode, with a separately confirmed direct-route switch.
    Sovereign,
}

/// Explicit publication policy for one discovery maintenance pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscoveryPublicationPolicy {
    /// Current operating mode.
    pub mode: DiscoveryMode,
    /// Advanced Sovereign-only acknowledgement that Connect-code holders can
    /// poll any included direct route.
    pub publish_direct_routes: bool,
}

/// Bounded result of one native-token capability registration pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeWakeRegistrationResult {
    /// Contact-device capability sets replaced atomically in this pass.
    pub updated: usize,
    /// More relationships remain for a later platform-scheduled pass.
    pub remaining: bool,
}

/// Borrowed platform destination and provider set for one bounded registration
/// pass.
pub struct NativeWakeDestinationRegistration<'a> {
    /// Native notification provider family.
    pub platform: WakePlatform,
    /// Provider sandbox or production environment.
    pub environment: WakeEnvironment,
    /// Fixed generic payload profile requested for this destination.
    pub profile: WakeProfile,
    /// Opaque APNs or FCM destination token kept only for this call.
    pub provider_token: &'a [u8],
    /// Exact application topic or package identifier.
    pub app_topic: &'a [u8],
    /// Complete eligible gateway set for the current operating mode.
    pub providers: &'a [WakeProvider],
    /// Current Unix time in seconds.
    pub now: u64,
}

impl DiscoveryPublicationPolicy {
    fn permits_direct_routes(self) -> bool {
        self.mode == DiscoveryMode::Sovereign && self.publish_direct_routes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum DeviceHandshakeIntent {
    Establish,
    Replace { prior_session_id: [u8; 32] },
    Reset,
    Legacy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandshakeSessionDecision {
    KeepPrior,
    AcceptInbound,
    Reject,
}

fn decide_inbound_session(
    local_device: [u8; 32],
    peer_device: [u8; 32],
    prior_session_id: Option<&[u8; 32]>,
    intent: DeviceHandshakeIntent,
) -> HandshakeSessionDecision {
    match (prior_session_id, intent) {
        (None, DeviceHandshakeIntent::Replace { .. }) => HandshakeSessionDecision::Reject,
        (Some(prior), DeviceHandshakeIntent::Replace { prior_session_id })
            if prior != &prior_session_id =>
        {
            HandshakeSessionDecision::Reject
        }
        (Some(_), DeviceHandshakeIntent::Establish) if local_device < peer_device => {
            HandshakeSessionDecision::KeepPrior
        }
        _ => HandshakeSessionDecision::AcceptInbound,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceInitialFlight {
    initial: Vec<u8>,
    return_bundle: Vec<u8>,
    intent: DeviceHandshakeIntent,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyDeviceInitialFlight {
    initial: Vec<u8>,
    return_bundle: Vec<u8>,
}

fn encode_device_initial(flight: &DeviceInitialFlight) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(flight).map_err(|_| NodeError::CorruptState)?;
    let mut out = Vec::with_capacity(DEVICE_INITIAL_MAGIC.len() + body.len());
    out.extend_from_slice(DEVICE_INITIAL_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_device_initial(bytes: &[u8]) -> Option<DeviceInitialFlight> {
    if let Some(body) = bytes.strip_prefix(DEVICE_INITIAL_MAGIC) {
        let (flight, remainder): (DeviceInitialFlight, &[u8]) =
            postcard::take_from_bytes(body).ok()?;
        return remainder.is_empty().then_some(flight);
    }
    let body = bytes.strip_prefix(LEGACY_DEVICE_INITIAL_MAGIC)?;
    let (flight, remainder): (LegacyDeviceInitialFlight, &[u8]) =
        postcard::take_from_bytes(body).ok()?;
    remainder.is_empty().then_some(DeviceInitialFlight {
        initial: flight.initial,
        return_bundle: flight.return_bundle,
        intent: DeviceHandshakeIntent::Legacy,
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountInitialFlight {
    initial: Vec<u8>,
    return_bundle: Vec<u8>,
}

fn decode_account_initial(bytes: &[u8]) -> Option<AccountInitialFlight> {
    let body = bytes.strip_prefix(ACCOUNT_INITIAL_MAGIC)?;
    let (flight, remainder): (AccountInitialFlight, &[u8]) =
        postcard::take_from_bytes(body).ok()?;
    remainder.is_empty().then_some(flight)
}

/// How many past daily epochs of delivery tokens the receiver recognizes.
/// Sneakernet latency is human-scale; a courier bundle a month old must
/// still route (docs/05-transports.md §5).
const TOKEN_LOOKBACK_EPOCHS: u64 = 35;
/// Future epochs tolerated (sender clock ahead of ours).
const TOKEN_LOOKAHEAD_EPOCHS: u64 = 2;

/// Future epochs of tokens handed to mailbox relays at check-in — how long
/// this node may stay offline while senders' deposits still match a
/// registered filter.
const MAILBOX_AHEAD_EPOCHS: u64 = 35;

/// Retention for inbound envelopes that cannot be consumed yet (arrived
/// before their session). Matches the bundle TTL: after a month the
/// handshake that would unlock them can no longer arrive either.
const PENDING_TTL_SECS: u64 = 30 * 86_400;

/// Retry backoff: base delay, doubling per attempt, capped.
const RETRY_BASE_SECS: u64 = 30;
const RETRY_CAP_SECS: u64 = 3_600;
/// A reached next hop can refuse transient local capacity. Retry that
/// distinct condition soon enough to benefit from the receiver's next
/// bounded drain, while exponentially capping a persistently refusing hop.
const CAPACITY_RETRY_BASE_SECS: u64 = 1;
const CAPACITY_RETRY_CAP_SECS: u64 = 30;
/// After several foreground attempts, an unreachable delivery moves to a
/// low-frequency lane so old work cannot make the unlocked app feel stuck.
const PASSIVE_AFTER_ATTEMPTS: u32 = 3;
const PASSIVE_RETRY_MIN_SECS: u64 = 15 * 60;
/// Ordinary outbound messages stop consuming queue and network resources
/// after this durable end-to-end delivery window.
const DELIVERY_EXPIRY_SECS: u64 = 30 * 86_400;
const DELIVERY_SWEEP_INTERVAL_SECS: u64 = 3_600;
/// One heartbeat must return to the receive inbox promptly even when an old
/// direct route, attachment, or discovery lookup is stalled. Transport work
/// is idempotent and remains durably queued, so yielding is always safe.
const FLUSH_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Ordinary encrypted content above this size never rides an
/// airtime-budgeted (LoRa) link: it is held for a faster carrier with honest
/// feedback instead of silently hogging the mesh.
const AIRTIME_CEILING_BYTES: usize = 4 * 1024;
/// A PQ first flight is security control traffic rather than user media. Give
/// the authority-wrapped handshake one still-small, explicit allowance so a
/// QR-paired contact can establish over the mesh-only golden path.
const AIRTIME_HANDSHAKE_CEILING_BYTES: usize = 8 * 1024;

fn airtime_ceiling(envelope: &Envelope) -> usize {
    if envelope.kind == EnvelopeKind::Handshake {
        AIRTIME_HANDSHAKE_CEILING_BYTES
    } else {
        AIRTIME_CEILING_BYTES
    }
}

/// How long a partial message may sit incomplete before the receiver NACKs
/// its missing fragment indices (selective retransmission,
/// docs/05-transports.md §4.2 rule 2) — long enough that in-flight
/// fragments on a seconds-class link get their chance to arrive.
const NACK_AFTER_SECS: u64 = 60;
/// Minimum spacing between NACKs for the same partial. NACKs cost airtime
/// too, and a duplicate retransmission costs even more.
const NACK_INTERVAL_SECS: u64 = 900;

/// Cap on remembered sent-fragment sets (the sender side of selective
/// retransmission). Oldest entries evict first; an evicted message can no
/// longer be selectively repaired, only fully resent.
const MAX_FRAG_CACHE: usize = 256;

// ---- bridging (docs/05-transports.md §4.2 rule 5, ADR-0009) ----------------

/// How long a transit envelope may wait for a sink before it is dropped.
/// Sized like the other store-and-forward windows: human-scale, but transit
/// lives in memory — the end-to-end retry machinery, not the bridge, is the
/// source of reliability.
const TRANSIT_TTL_SECS: u64 = 3 * 86_400;

/// Caps on the transit queue. Third parties fill it, so both axes bound it;
/// an envelope refused here is simply not bridged — the sealed traffic's own
/// retries may find another path or a later slot.
const MAX_TRANSIT_ITEMS: usize = 256;
const MAX_TRANSIT_BYTES: usize = 512 * 1024;

/// Remembered transit content ids (dedup across multipath echoes and
/// multi-bridge loops). Oldest forgotten first.
const MAX_TRANSIT_SEEN: usize = 4096;

/// Mesh→internet transit: how many deposit rounds before an envelope no
/// relay recognizes is dropped. Mesh-internal chatter matches no internet
/// registration ever; this bounds what such traffic can cost.
const TRANSIT_DEPOSIT_ATTEMPTS: u32 = 8;

/// Base retry delay for refused transit deposits, doubling per attempt. A
/// gentler schedule than the delivery engine's own queue: a refusal is one
/// tiny request on a metered link, and the common transient cause — the
/// recipient's *fresh* session tokens missing their first mailbox check-in
/// by seconds — clears quickly.
const TRANSIT_DEPOSIT_RETRY_BASE_SECS: u64 = 5;

/// Internet→mesh transit: total floods per envelope, and the base spacing
/// between them (doubling each round). Receipts are end-to-end and opaque
/// to the bridge, so there is no feedback channel — bounded blind
/// repetition stands in for retransmission (ADR-0009).
const TRANSIT_MESH_FLOODS: u32 = 3;
const TRANSIT_REFLOOD_BASE_SECS: u64 = 300;

/// Internet→mesh transit envelopes flooded per tick, so a deep transit
/// backlog never starves the bridge's own outbound queue of airtime (which
/// always flushes first).
const TRANSIT_MESH_PER_TICK: usize = 4;

/// Missing fragment indices per in-flight message id — the NACK half of a
/// receipt (the shape of [`ReceiptPayload::nacks`]).
type FragNacks = Vec<([u8; 4], Vec<u16>)>;
/// Bound one receipt's selective-retransmission work independently of the
/// reassembler's aggregate partial-message cap.
const MAX_NACK_PARTIALS_PER_TICK: usize = 32;
/// Missing indices carried in one tick across all partial messages.
const MAX_NACK_INDICES_PER_TICK: usize = 4_096;
const MAX_DEFERRED_CONTROLS_PER_TICK: usize = 16;
const MAX_MAINTENANCE_MESSAGES_PER_TICK: usize = 8;
const MAX_MAINTENANCE_QUEUE_ROWS_PER_TICK: usize = 32;
const MAX_MAINTENANCE_REPLAY_ROWS_PER_TICK: usize = 16;
const MAX_EPHEMERAL_EXPIRIES_PER_TICK: usize = 4;
const MAX_PENDING_WORK_PER_TICK: usize = 64;
const MAX_PENDING_DEVICE_DELIVERIES_PER_TICK: usize = 8;
const MAX_RESET_MARKERS_PER_TICK: usize = 8;
/// Maximum signed admission descriptors/puzzles verified in one heartbeat.
const MAX_ADMISSION_PUZZLES_PER_TICK: usize = 8;
/// Maximum ML-KEM decapsulations spent on first-contact candidates per heartbeat.
const MAX_ADMISSION_KEMS_PER_TICK: usize = 4;
/// Maximum request-inbox presentation changes emitted per heartbeat.
const MAX_ADMISSION_NOTIFICATIONS_PER_TICK: usize = 4;
/// Maximum expired request/tombstone rows retired per heartbeat.
const MAX_ADMISSION_EXPIRIES_PER_TICK: usize = 16;
const ADMISSION_CARRIER_CLASS_COUNT: usize = 6;
/// Per-carrier candidate ceilings in enum order: unknown, direct, mailbox,
/// mesh, delayed, and bridge.
const MAX_ADMISSION_CANDIDATES_PER_CARRIER: [usize; ADMISSION_CARRIER_CLASS_COUNT] =
    [4, 4, 2, 2, 2, 2];
/// Wall-clock slice for all first-contact proof and KEM work in one heartbeat.
const MAX_ADMISSION_TIME_PER_TICK: Duration = Duration::from_millis(100);

/// Receiver-side bookkeeping for one in-flight partial message: enough to
/// address the NACK requesting its missing fragments (via the delivery
/// token) and to pace repeats.
struct PartialMeta {
    token: [u8; 32],
    first_seen: u64,
    last_nack: Option<u64>,
}

/// Sender-side copy of one fragmented envelope's fragment bodies, kept so a
/// NACK can trigger retransmission of exactly the missing indices instead of
/// re-flooding the whole message (docs/05-transports.md §4.2 rule 2).
struct SentFragments {
    peer: [u8; 32],
    token: [u8; 32],
    retention_until: Option<u64>,
    bodies: Vec<Vec<u8>>,
    sent_at: u64,
}

struct PreparedPairwiseRoute {
    route: [u8; 32],
    before: Option<Session>,
    after: Session,
    envelope: Envelope,
    resets_capabilities: bool,
}

pub(crate) struct CommittedPairwiseEnvelope {
    pub(crate) sequence: i64,
}

struct PreparedInbound {
    message: Option<MessageRecord>,
    ephemeral: Option<EphemeralRecord>,
    media_transfers: Vec<MediaTransferRecord>,
    media_objects: Vec<MediaObjectRecord>,
    events: Vec<Event>,
    attachment_updates: Vec<[u8; 16]>,
}

struct PreparedReceipt {
    delete_queue: Vec<QueueDelete>,
    queue: Vec<QueueItem>,
    messages: Vec<(MessageRecord, MessageRecord)>,
    deliveries: Vec<(MessageDeviceDeliveryRecord, MessageDeviceDeliveryRecord)>,
    group_messages: Vec<(GroupMessageRecord, GroupMessageRecord)>,
    groups: Vec<(GroupRecord, GroupRecord)>,
    events: Vec<Event>,
}

#[derive(Default)]
pub(crate) struct PreparedDeliveryUpdate {
    pub(crate) messages: Vec<(MessageRecord, MessageRecord)>,
    pub(crate) deliveries: Vec<(MessageDeviceDeliveryRecord, MessageDeviceDeliveryRecord)>,
    pub(crate) group_messages: Vec<(GroupMessageRecord, GroupMessageRecord)>,
    pub(crate) events: Vec<Event>,
}

struct PreparedWakeUpdate {
    peer_device: [u8; 32],
    before: WakeServiceState,
    after: WakeServiceState,
}

enum Consumed {
    /// Fully handled (or permanently unprocessable) — never seen again.
    Done,
    /// Fully handled by a transaction that also acknowledged its named
    /// deferred-inbox source row, when one existed.
    DoneAtomic,
    /// Permanently rejected and atomically retired. Interactive carriers
    /// return the same bounded refusal for every such candidate.
    RejectedAtomic,
    /// Cannot be processed *yet* (no matching session) — stash and retry.
    Later,
}

#[derive(Clone, Copy)]
struct ConsumeOrigin {
    depth: u8,
    pending_sequence: Option<i64>,
    transport: AdmissionTransportClass,
}

/// One third-party envelope in transit across the bridge (ADR-0009).
struct TransitItem {
    envelope: Envelope,
    /// Which side it arrived on — transit never returns to the carrier
    /// class it came from (split horizon).
    from_mesh: bool,
    first_seen: u64,
    attempts: u32,
    next_ok: u64,
}

/// Bridging state (docs/05-transports.md §4.2 rule 5, ADR-0009): the
/// bounded transit queue plus the internet-side deposit targets. The bridge
/// handles nothing but sealed envelopes and rotating tokens — the same view
/// any relay already has.
struct Bridge {
    /// Internet-side sinks for mesh-heard transit: mailbox relays to offer
    /// deposits to (the node's own mailbox service reachable among them).
    relays: Vec<DeliveryHint>,
    queue: VecDeque<TransitItem>,
    queue_bytes: usize,
    /// Content ids ever admitted — multipath echoes and multi-bridge loops
    /// die here. Insertion-ordered so the oldest forgets first.
    seen: HashSet<[u8; 16]>,
    seen_order: VecDeque<[u8; 16]>,
}

impl Bridge {
    fn new(relays: Vec<DeliveryHint>) -> Self {
        Self {
            relays,
            queue: VecDeque::new(),
            queue_bytes: 0,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }

    /// Admit one foreign envelope, if it is new and fits every cap.
    fn admit(&mut self, envelope: &Envelope, from_mesh: bool, now: u64) {
        if envelope
            .retention_until
            .is_some_and(|deadline| deadline <= now)
        {
            return;
        }
        let encoded_len = envelope.header_len() + envelope.body.len();
        // Anything over its bounded airtime class could neither ride the
        // mesh nor have come off it whole — never transit (§4.2 rule 3).
        if encoded_len > airtime_ceiling(envelope) {
            return;
        }
        let id = envelope.content_id();
        if self.seen.contains(&id) {
            return;
        }
        if self.queue.len() >= MAX_TRANSIT_ITEMS
            || self.queue_bytes + encoded_len > MAX_TRANSIT_BYTES
        {
            return; // full: not remembered, so a later copy may still get in
        }
        self.seen.insert(id);
        self.seen_order.push_back(id);
        while self.seen_order.len() > MAX_TRANSIT_SEEN {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.queue_bytes += encoded_len;
        self.queue.push_back(TransitItem {
            envelope: envelope.clone(),
            from_mesh,
            first_seen: now,
            attempts: 0,
            next_ok: now,
        });
    }
}

/// One-time account authority retained only until the explicit offline-file
/// export completes.
struct PendingAccountRecoveryMaterial {
    package: Vec<u8>,
    mnemonic: zeroize::Zeroizing<String>,
}

/// Prepared copied-root Alpha reset that the user must review and confirm
/// before the live profile is replaced.
pub struct AuthorityResetPreparation {
    /// Fresh public account that will replace the irrevocable former account.
    pub new_account: IdentityPublic,
    /// Human-readable address derived from `new_account`.
    pub new_address: String,
    /// One-time 24-word phrase opening the separately written recovery file.
    pub mnemonic: zeroize::Zeroizing<String>,
}

const RECOVERY_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const MAX_RECOVERY_ATTEMPTS_PER_WINDOW: usize = 5;
const MAX_RECOVERY_ATTEMPT_KEYS: usize = 64;

struct RecoveryAttemptState {
    failures: VecDeque<Instant>,
    last_seen: Instant,
}

static RECOVERY_ATTEMPTS: OnceLock<Mutex<HashMap<[u8; 32], RecoveryAttemptState>>> =
    OnceLock::new();

fn open_account_recovery_authority_throttled(package: &[u8], mnemonic: &str) -> Result<Identity> {
    let key: [u8; 32] = Sha256::digest(package).into();
    let now = Instant::now();
    {
        let attempts = RECOVERY_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut attempts = attempts.lock().map_err(|_| NodeError::CorruptState)?;
        attempts.retain(|_, state| now.duration_since(state.last_seen) < RECOVERY_ATTEMPT_WINDOW);
        if !attempts.contains_key(&key) && attempts.len() >= MAX_RECOVERY_ATTEMPT_KEYS {
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, state)| state.last_seen)
                .map(|(key, _)| *key)
            {
                attempts.remove(&oldest);
            }
        }
        let state = attempts.entry(key).or_insert_with(|| RecoveryAttemptState {
            failures: VecDeque::new(),
            last_seen: now,
        });
        while state
            .failures
            .front()
            .is_some_and(|failure| now.duration_since(*failure) >= RECOVERY_ATTEMPT_WINDOW)
        {
            state.failures.pop_front();
        }
        if state.failures.len() >= MAX_RECOVERY_ATTEMPTS_PER_WINDOW {
            return Err(NodeError::RecoveryAttemptLimited);
        }
        state.failures.push_back(now);
        state.last_seen = now;
    }

    let opened = open_account_recovery_authority(package, mnemonic);
    if opened.is_ok() {
        RECOVERY_ATTEMPTS
            .get()
            .expect("attempt map initialized")
            .lock()
            .map_err(|_| NodeError::CorruptState)?
            .remove(&key);
    }
    opened.map_err(Into::into)
}

fn write_new_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let io_error = |error| NodeError::Store(kult_store::StoreError::Io(error));
    atomicwrites::AtomicFile::new(path, atomicwrites::DisallowOverwrite)
        .write_with_options(|file| file.write_all(bytes), options)
        .map_err(std::io::Error::from)
        .map_err(io_error)
}

/// The Komms runtime: one public account, one device key, and one store.
pub struct Node {
    store: Store,
    /// Stable public account trust anchor used for conversations and safety numbers.
    account: IdentityPublic,
    /// Separately authenticated key unique to this physical installation.
    device_identity: Identity,
    device_state: DeviceAuthorityStateRecord,
    pending_device_link_source: Option<PendingAuthorityDeviceLinkSource>,
    pending_device_link_target: Option<PendingAuthorityDeviceLinkTarget>,
    pending_device_link_prepared: Option<PreparedAuthorityDeviceLink>,
    pending_device_link_selection: Option<DeviceLinkSelection>,
    pending_device_link_response_hash: Option<[u8; 32]>,
    pending_authority_transition: Option<kult_crypto::DeviceAuthorityTransition>,
    pending_recovery_material: Option<PendingAccountRecoveryMaterial>,
    vault: PrekeyVault,
    /// Current signed return routes included in anonymous first flights.
    own_hints: Vec<DeliveryHint>,
    /// Whether `own_hints` is a complete locally supplied route set rather
    /// than the empty, unknown state immediately after construction/restart.
    own_hints_authoritative: bool,
    transports: Vec<Arc<dyn Transport>>,
    discoveries: Vec<Arc<dyn Discovery>>,
    sessions: HashMap<[u8; 32], kult_crypto::Session>,
    capabilities_advertised: HashSet<[u8; 32]>,
    discovery_advertised: HashSet<[u8; 32]>,
    discovery_published_material: Option<[u8; 32]>,
    rendezvous_client: Option<Arc<dyn RendezvousClient>>,
    rendezvous_providers: Vec<RendezvousProvider>,
    rendezvous_provider_generation: u64,
    rendezvous_advertised: HashSet<[u8; 32]>,
    rendezvous_refresh_requested: HashSet<[u8; 32]>,
    rendezvous_active_conversations: HashSet<[u8; 32]>,
    rendezvous_rehandshake_requested: HashSet<[u8; 32]>,
    rendezvous_inflight: HashSet<([u8; 32], [u8; 32], RendezvousOperationKind)>,
    wake_client: Option<Arc<dyn WakeClient>>,
    wake_registration_cursor: usize,
    wake_collection_deadline: Option<Instant>,
    media_reconciled: bool,
    attachment_request_at: HashMap<[u8; 16], u64>,
    attachment_request_target: HashMap<[u8; 16], usize>,
    carrier_capabilities: HashMap<[u8; 32], CarrierCapabilitySnapshot>,
    calls: HashMap<[u8; 16], calls::ActiveCall>,
    call_queue_deadlines: HashMap<i64, u64>,
    reassembler: Reassembler,
    frag_meta: HashMap<[u8; 4], PartialMeta>,
    frag_cache: HashMap<[u8; 4], SentFragments>,
    held_notified: HashSet<i64>,
    next_delivery_sweep: u64,
    bridge: Option<Bridge>,
    events: VecDeque<Event>,
    presentation_marker: Option<[u8; 16]>,
    delivered_presentation_marker: Option<[u8; 16]>,
    admission_puzzles_remaining: usize,
    admission_kems_remaining: usize,
    admission_notifications_remaining: usize,
    admission_carrier_remaining: [usize; ADMISSION_CARRIER_CLASS_COUNT],
    admission_deadline: Option<Instant>,
    #[cfg(feature = "test-failpoints")]
    transition_failpoint: RefCell<Option<TransitionFailpoint>>,
    #[cfg(feature = "test-failpoints")]
    transition_failpoint_fired: Cell<bool>,
    #[cfg(feature = "test-failpoints")]
    crypto_step: Cell<usize>,
}

impl Node {
    // ---- lifecycle ---------------------------------------------------------

    /// Arm one process-interruption checkpoint and reset crypto numbering.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn arm_transition_failpoint(&self, point: TransitionFailpoint) {
        self.transition_failpoint.replace(Some(point));
        self.transition_failpoint_fired.set(false);
        self.crypto_step.set(0);
    }

    /// Arm one store transaction checkpoint.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn arm_commit_failpoint(&self, point: CommitFailpoint, failure: CommitFailure) {
        self.store.arm_commit_failpoint(point, failure);
    }

    /// Whether the currently armed process-interruption checkpoint fired.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn transition_failpoint_fired(&self) -> bool {
        self.transition_failpoint_fired.get()
    }

    #[cfg(feature = "test-failpoints")]
    fn check_transition_failpoint(&self, point: TransitionFailpoint) -> Result<()> {
        if *self.transition_failpoint.borrow() == Some(point) {
            self.transition_failpoint.replace(None);
            self.transition_failpoint_fired.set(true);
            return Err(NodeError::Store(kult_store::StoreError::Io(
                std::io::Error::from(std::io::ErrorKind::Interrupted),
            )));
        }
        Ok(())
    }

    fn begin_crypto_step(&self) -> Result<usize> {
        #[cfg(feature = "test-failpoints")]
        {
            let step = self.crypto_step.get();
            self.check_transition_failpoint(TransitionFailpoint::BeforeCryptoStep(step))?;
            self.crypto_step.set(step + 1);
            Ok(step)
        }
        #[cfg(not(feature = "test-failpoints"))]
        {
            Ok(0)
        }
    }

    fn finish_crypto_step(&self, step: usize) -> Result<()> {
        #[cfg(feature = "test-failpoints")]
        {
            self.check_transition_failpoint(TransitionFailpoint::AfterCryptoStep(step))
        }
        #[cfg(not(feature = "test-failpoints"))]
        {
            let _ = step;
            Ok(())
        }
    }

    pub(crate) fn candidate_encrypt(
        &self,
        session: &mut Session,
        rng: &mut impl CryptoRngCore,
        now: u64,
        plaintext: &[u8],
    ) -> Result<RatchetMessage> {
        let step = self.begin_crypto_step()?;
        let message = session.encrypt(rng, now, plaintext, &[]);
        self.finish_crypto_step(step)?;
        Ok(message)
    }

    fn candidate_decrypt(
        &self,
        session: &mut Session,
        rng: &mut impl CryptoRngCore,
        now: u64,
        message: &RatchetMessage,
    ) -> Result<std::result::Result<Vec<u8>, kult_crypto::CryptoError>> {
        let step = self.begin_crypto_step()?;
        let plaintext = session.decrypt(rng, now, message, &[]);
        self.finish_crypto_step(step)?;
        Ok(plaintext)
    }

    fn before_memory_replacement(&self) -> Result<()> {
        #[cfg(feature = "test-failpoints")]
        {
            self.check_transition_failpoint(TransitionFailpoint::BeforeMemoryReplacement)
        }
        #[cfg(not(feature = "test-failpoints"))]
        {
            Ok(())
        }
    }

    fn after_memory_replacement(&self) -> Result<()> {
        #[cfg(feature = "test-failpoints")]
        {
            self.check_transition_failpoint(TransitionFailpoint::AfterMemoryReplacement)
        }
        #[cfg(not(feature = "test-failpoints"))]
        {
            Ok(())
        }
    }

    /// Create a brand-new node and retain its one-time recovery export.
    pub fn create(
        path: &std::path::Path,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let root = Identity::generate(rng);
        let account = root.public();
        let (device_identity, device_state) = devices::fresh_authority_device_state(&root, rng)?;
        let (package, mnemonic) = seal_account_recovery_authority(&root, rng)?;
        let vault = PrekeyVault::generate(rng);
        let encoded_vault = vault.encode();
        let store = Store::create_authority_profile(
            path,
            passphrase,
            profile,
            &account,
            &device_state,
            &encoded_vault,
            rng,
        )?;
        Self::assemble(
            store,
            account,
            device_identity,
            device_state,
            vault,
            Some(PendingAccountRecoveryMaterial { package, mnemonic }),
        )
    }

    /// Open an existing node.
    pub fn open(path: &std::path::Path, passphrase: &[u8]) -> Result<Self> {
        let store = Store::open(path, passphrase)?;
        if store.contains_legacy_account_root()? {
            let copied = store.get_device_state()?.is_some_and(|state| {
                state.manifest.devices.len() > 1 || !state.channels.is_empty()
            });
            return Err(if copied {
                NodeError::AuthorityResetRequired
            } else {
                NodeError::AuthorityMigrationRequired
            });
        }
        let account = store
            .get_account_identity()?
            .ok_or(NodeError::CorruptState)?;
        let (device_identity, mut device_state) = devices::load_authority_device(&store)?;
        if device_state.discovery.capability == [0u8; 32] {
            let mut rng = OsRng;
            let code = ConnectCode::generate(&account, &mut rng)?;
            device_state.discovery = DiscoveryCapabilityState {
                capability: code.capability(),
                generation: 1,
                legacy_v1_enabled: true,
            };
            store.put_device_authority_state(&device_state, &mut rng)?;
        }
        let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
        let vault = PrekeyVault::decode(&vault_blob)?;
        Self::assemble(store, account, device_identity, device_state, vault, None)
    }

    /// Prepare an honest single-device Alpha migration by writing a new
    /// encrypted offline authority while leaving the live store untouched.
    ///
    /// The caller must show and confirm the returned phrase before invoking
    /// [`Self::complete_authority_migration`]. A crash or cancellation before
    /// completion therefore leaves the original profile openable by this
    /// preparation flow and permits a fresh export to another new path.
    pub fn prepare_authority_migration(
        path: &std::path::Path,
        passphrase: &[u8],
        recovery_path: &std::path::Path,
        rng: &mut impl CryptoRngCore,
    ) -> Result<zeroize::Zeroizing<String>> {
        let store = Store::open(path, passphrase)?;
        let root = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        let legacy_state = store.get_device_state()?.ok_or(NodeError::CorruptState)?;
        if legacy_state.manifest.devices.len() != 1 || !legacy_state.channels.is_empty() {
            return Err(NodeError::AuthorityResetRequired);
        }
        let (package, mnemonic) = seal_account_recovery_authority(&root, rng)?;
        write_new_private_file(recovery_path, &package)?;
        Ok(mnemonic)
    }

    /// Finish a prepared single-device Alpha migration atomically.
    ///
    /// The separately exported authority and its confirmed phrase must open
    /// the exact root still present in the legacy store. The transaction then
    /// replaces that root with its public trust anchor and a root-authorized
    /// generation-one manifest for the same physical-device key. Conversation
    /// state, petnames, verification, ratchets, and prekeys remain local and
    /// unchanged because no account root was ever distributed.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_authority_migration(
        path: &std::path::Path,
        passphrase: &[u8],
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        migrated_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let store = Store::open(path, passphrase)?;
        let opened_root =
            open_account_recovery_authority_throttled(recovery_package, recovery_mnemonic)?;
        let Some(legacy_root) = store.get_identity()? else {
            let account = store
                .get_account_identity()?
                .ok_or(NodeError::CorruptState)?;
            if opened_root.public() != account {
                return Err(NodeError::RecoveryAuthorityRequired);
            }
            let (device_identity, device_state) = devices::load_authority_device(&store)?;
            let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
            let vault = PrekeyVault::decode(&vault_blob)?;
            drop(opened_root);
            return Self::assemble(store, account, device_identity, device_state, vault, None);
        };
        let legacy_state = store.get_device_state()?.ok_or(NodeError::CorruptState)?;
        if legacy_state.manifest.devices.len() != 1 || !legacy_state.channels.is_empty() {
            return Err(NodeError::AuthorityResetRequired);
        }
        if opened_root.public() != legacy_root.public() {
            return Err(NodeError::RecoveryAuthorityRequired);
        }
        let account = legacy_root.public();
        let (device_identity, device_state) = devices::migrate_legacy_authority_device_state(
            &opened_root,
            &legacy_state,
            migrated_at,
            rng,
        )?;
        let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
        let vault = PrekeyVault::decode(&vault_blob)?;
        store.commit_plan(
            CommitPlan::AuthorityMigration(AuthorityMigrationPlan {
                legacy_identity: &legacy_root,
                legacy_device_state: &legacy_state,
                account: &account,
                device_state: &device_state,
            }),
            rng,
        )?;
        if store.contains_legacy_account_root()?
            || store.get_account_identity()?.as_ref() != Some(&account)
            || store.get_device_authority_state()?.as_ref() != Some(&device_state)
        {
            return Err(NodeError::CorruptState);
        }
        drop(opened_root);
        drop(legacy_root);
        Self::assemble(store, account, device_identity, device_state, vault, None)
    }

    /// Prepare an explicit copied-root Alpha reset without mutating the live
    /// database.
    ///
    /// A completely new account root is written to `recovery_path` with
    /// owner-only permissions. The caller must show the new address, explain
    /// that every safety number changes, and confirm the returned phrase
    /// before invoking [`Self::complete_authority_reset`]. This conservative
    /// path is also available for a single-device profile when the user knows
    /// that a legacy KKR7 backup or another root copy exists even though the
    /// live store contains no linked-device evidence.
    pub fn prepare_authority_reset(
        path: &std::path::Path,
        passphrase: &[u8],
        recovery_path: &std::path::Path,
        rng: &mut impl CryptoRngCore,
    ) -> Result<AuthorityResetPreparation> {
        let store = Store::open(path, passphrase)?;
        let former_root = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        store.get_device_state()?.ok_or(NodeError::CorruptState)?;
        let new_root = Identity::generate(rng);
        if new_root.public() == former_root.public() {
            return Err(NodeError::CorruptState);
        }
        let new_account = new_root.public();
        let new_address = new_account.address();
        let (package, mnemonic) = seal_account_recovery_authority(&new_root, rng)?;
        write_new_private_file(recovery_path, &package)?;
        Ok(AuthorityResetPreparation {
            new_account,
            new_address,
            mnemonic,
        })
    }

    /// Prepare a fresh root-free identity for recovering only the safe local
    /// archive projection from a copied-root `KKR1` through `KKR7` backup.
    ///
    /// There is no live store to inspect in this flow. The caller must show
    /// the new address and explain that the backup's former identity and all
    /// of its safety numbers are permanently abandoned before calling
    /// [`Self::restore_legacy_backup_with_authority_reset`].
    pub fn prepare_legacy_backup_authority_reset(
        recovery_path: &std::path::Path,
        rng: &mut impl CryptoRngCore,
    ) -> Result<AuthorityResetPreparation> {
        let new_root = Identity::generate(rng);
        let new_account = new_root.public();
        let new_address = new_account.address();
        let (package, mnemonic) = seal_account_recovery_authority(&new_root, rng)?;
        write_new_private_file(recovery_path, &package)?;
        Ok(AuthorityResetPreparation {
            new_account,
            new_address,
            mnemonic,
        })
    }

    /// Complete a copied-root Alpha reset with one atomic database replacement.
    ///
    /// The confirmed recovery file becomes the offline authority for a fresh
    /// account. Only local petnames, non-ephemeral pairwise history,
    /// note-to-self history, and eligible local organization are copied.
    /// Contacts lose all routes and verification; groups, sessions, delivery
    /// work, device state, media, and service capabilities are not transferred.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_authority_reset(
        path: &std::path::Path,
        passphrase: &[u8],
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        reset_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let store = Store::open(path, passphrase)?;
        let new_root =
            open_account_recovery_authority_throttled(recovery_package, recovery_mnemonic)?;
        let new_account = new_root.public();
        if store.get_identity()?.is_none() {
            let account = store
                .get_account_identity()?
                .ok_or(NodeError::CorruptState)?;
            let reset = store
                .authority_reset_history()?
                .ok_or(NodeError::RecoveryAuthorityRequired)?;
            if account != new_account || reset.new_account != account.ed {
                return Err(NodeError::RecoveryAuthorityRequired);
            }
            let (device_identity, device_state) = devices::load_authority_device(&store)?;
            let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
            let vault = PrekeyVault::decode(&vault_blob)?;
            drop(new_root);
            return Self::assemble(store, account, device_identity, device_state, vault, None);
        }
        store.get_device_state()?.ok_or(NodeError::CorruptState)?;
        let former_account = store
            .get_identity()?
            .ok_or(NodeError::CorruptState)?
            .public();
        if former_account == new_account {
            return Err(NodeError::AuthorityResetRequired);
        }

        let (device_identity, device_state) =
            devices::fresh_authority_device_state(&new_root, rng)?;
        let vault = PrekeyVault::generate(rng);
        let encoded_vault = vault.encode();
        let (store, reset) = store.replace_copied_root_profile(
            passphrase,
            &new_account,
            &device_state,
            &encoded_vault,
            reset_at,
            rng,
        )?;
        if reset.former_account != former_account.ed
            || reset.new_account != new_account.ed
            || store.contains_legacy_account_root()?
        {
            return Err(NodeError::CorruptState);
        }
        drop(new_root);
        Self::assemble(
            store,
            new_account,
            device_identity,
            device_state,
            vault,
            None,
        )
    }

    /// Recover a legacy backup as a visible new-identity local archive.
    ///
    /// The copied account root is authenticated and decoded only in memory
    /// by the store migration. The published database contains a fresh KDA2
    /// account/device profile, cleared contact trust and routes, and only the
    /// accurately labelled local history/petname projection.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_legacy_backup_with_authority_reset(
        path: &std::path::Path,
        backup: &[u8],
        backup_mnemonic: &str,
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        reset_at: u64,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let new_root =
            open_account_recovery_authority_throttled(recovery_package, recovery_mnemonic)?;
        let new_account = new_root.public();
        let (device_identity, device_state) =
            devices::fresh_authority_device_state(&new_root, rng)?;
        let vault = PrekeyVault::generate(rng);
        let encoded_vault = vault.encode();
        let (store, reset) = Store::restore_legacy_backup_as_authority_reset(
            path,
            backup,
            backup_mnemonic,
            passphrase,
            profile,
            &new_account,
            &device_state,
            &encoded_vault,
            reset_at,
            rng,
        )?;
        if reset.new_account != new_account.ed
            || store.contains_legacy_account_root()?
            || store.get_account_identity()?.as_ref() != Some(&new_account)
        {
            return Err(NodeError::CorruptState);
        }
        drop(new_root);
        Self::assemble(
            store,
            new_account,
            device_identity,
            device_state,
            vault,
            None,
        )
    }

    /// Restore a node from an encrypted backup file onto a **new** store at
    /// `path` (docs/07-storage.md §4): the exported identity resumes with
    /// contacts and history intact, prekeys are minted fresh (the old
    /// device's one-time prekeys must never be honored twice), and every
    /// peer that had a live session at export time re-handshakes on the
    /// first [`Node::tick`] — ratchet state is deliberately not portable.
    pub fn restore(
        path: &std::path::Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let _ = (path, backup, mnemonic, passphrase, profile, rng);
        Err(NodeError::RecoveryAuthorityRequired)
    }

    /// Restore a root-free backup by explicitly opening the separately held
    /// offline account authority for one recovery-epoch transition.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_with_recovery_authority(
        path: &std::path::Path,
        backup: &[u8],
        backup_mnemonic: &str,
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        recovered_at: u64,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let root = open_account_recovery_authority_throttled(recovery_package, recovery_mnemonic)?;
        let account = root.public();
        let (store, device_identity, device_state, vault) =
            Store::restore_authority_backup_with_initializer(
                path,
                backup,
                backup_mnemonic,
                &root,
                recovered_at,
                passphrase,
                profile,
                rng,
                |store, rng| {
                    let vault = PrekeyVault::generate(rng);
                    let encoded = vault.encode();
                    store.commit_plan(
                        CommitPlan::PrekeyPublish(PrekeyPublishPlan {
                            prekeys: PrekeyTransition {
                                before: None,
                                after: &encoded,
                            },
                        }),
                        rng,
                    )?;
                    Ok(vault)
                },
            )?;
        drop(root);
        Self::assemble(store, account, device_identity, device_state, vault, None)
    }

    /// Export this node's encrypted backup (docs/07-storage.md §4):
    /// identity + contacts + history + session-reset markers, sealed under
    /// a freshly minted 24-word mnemonic. Returns the file bytes and the
    /// mnemonic — show it to the user once; it is not stored anywhere.
    /// Ratchet sessions and prekey secrets are deliberately excluded;
    /// restoring re-handshakes instead ([`Node::restore`]).
    pub fn export_backup(
        &self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
        Ok(self.store.export_authority_backup(now, rng)?)
    }

    fn assemble(
        store: Store,
        account: IdentityPublic,
        device_identity: Identity,
        device_state: DeviceAuthorityStateRecord,
        vault: PrekeyVault,
        pending_recovery_material: Option<PendingAccountRecoveryMaterial>,
    ) -> Result<Self> {
        // Call controls are transient and their in-memory state and secrets
        // deliberately do not survive a process restart. The first bounded
        // flush retires any sealed realtime rows through Maintenance.
        let mut sessions = HashMap::new();
        let contact_devices = store.contact_devices()?;
        for endpoint in &contact_devices {
            if endpoint.revoked_at.is_none() {
                if let Some(session) = store.get_session(&endpoint.device)? {
                    sessions.insert(endpoint.device, session);
                }
            }
        }
        for contact in store.contacts()? {
            if !contact_devices
                .iter()
                .any(|endpoint| endpoint.device == contact.peer)
                && !sessions.contains_key(&contact.peer)
            {
                if let Some(session) = store.get_session(&contact.peer)? {
                    sessions.insert(contact.peer, session);
                }
            }
        }
        for (peer_device, session) in &sessions {
            store.ensure_wake_service_state(peer_device, session, &mut OsRng)?;
        }
        let (rendezvous_providers, rendezvous_provider_generation) =
            if let Some(config) = store.get_rendezvous_local_config()? {
                let mut providers = Vec::with_capacity(config.providers.len());
                for configured in &config.providers {
                    let provider =
                        RendezvousProvider::new(configured.origin.clone(), configured.static_key)
                            .map_err(|_| NodeError::CorruptState)?;
                    if provider.provider_id() != configured.provider_id {
                        return Err(NodeError::CorruptState);
                    }
                    providers.push(provider);
                }
                (providers, config.generation)
            } else {
                (Vec::new(), 0)
            };
        let presentation_marker = store.presentation_resync_marker()?;
        let mut events = VecDeque::new();
        if presentation_marker.is_some() {
            events.push_back(Event::StateResyncRequired);
        }
        for peer_device in sessions.keys().copied() {
            let Some(state) = store.get_rendezvous_service_state(&peer_device)? else {
                continue;
            };
            let peer = contact_devices
                .iter()
                .find(|endpoint| endpoint.device == peer_device)
                .map_or(peer_device, |endpoint| endpoint.account);
            if state.remote_provider_conflict_generation.is_some() {
                events.push_back(Event::RendezvousConflict {
                    peer,
                    device: peer_device,
                    provider: [0u8; 32],
                });
            }
            for provider in state
                .providers
                .iter()
                .filter(|provider| provider.conflict_generation.is_some())
            {
                events.push_back(Event::RendezvousConflict {
                    peer,
                    device: peer_device,
                    provider: provider.provider_id,
                });
            }
        }
        for peer_device in sessions.keys().copied() {
            let Some(state) = store.get_wake_service_state(&peer_device)? else {
                continue;
            };
            let Some(generation) = state.remote_conflict_generation else {
                continue;
            };
            let peer = contact_devices
                .iter()
                .find(|endpoint| endpoint.device == peer_device)
                .map_or(peer_device, |endpoint| endpoint.account);
            events.push_back(Event::WakeConflict {
                peer,
                device: peer_device,
                generation,
            });
        }
        Ok(Self {
            store,
            account,
            device_identity,
            device_state,
            pending_device_link_source: None,
            pending_device_link_target: None,
            pending_device_link_prepared: None,
            pending_device_link_selection: None,
            pending_device_link_response_hash: None,
            pending_authority_transition: None,
            pending_recovery_material,
            vault,
            own_hints: Vec::new(),
            own_hints_authoritative: false,
            transports: Vec::new(),
            discoveries: Vec::new(),
            sessions,
            capabilities_advertised: HashSet::new(),
            discovery_advertised: HashSet::new(),
            discovery_published_material: None,
            rendezvous_client: None,
            rendezvous_providers,
            rendezvous_provider_generation,
            rendezvous_advertised: HashSet::new(),
            rendezvous_refresh_requested: HashSet::new(),
            rendezvous_active_conversations: HashSet::new(),
            rendezvous_rehandshake_requested: HashSet::new(),
            rendezvous_inflight: HashSet::new(),
            wake_client: None,
            wake_registration_cursor: 0,
            wake_collection_deadline: None,
            media_reconciled: false,
            attachment_request_at: HashMap::new(),
            attachment_request_target: HashMap::new(),
            carrier_capabilities: HashMap::new(),
            calls: HashMap::new(),
            call_queue_deadlines: HashMap::new(),
            reassembler: Reassembler::new(),
            frag_meta: HashMap::new(),
            frag_cache: HashMap::new(),
            held_notified: HashSet::new(),
            next_delivery_sweep: 0,
            bridge: None,
            events,
            presentation_marker,
            delivered_presentation_marker: None,
            admission_puzzles_remaining: MAX_ADMISSION_PUZZLES_PER_TICK,
            admission_kems_remaining: MAX_ADMISSION_KEMS_PER_TICK,
            admission_notifications_remaining: MAX_ADMISSION_NOTIFICATIONS_PER_TICK,
            admission_carrier_remaining: MAX_ADMISSION_CANDIDATES_PER_CARRIER,
            admission_deadline: None,
            #[cfg(feature = "test-failpoints")]
            transition_failpoint: RefCell::new(None),
            #[cfg(feature = "test-failpoints")]
            transition_failpoint_fired: Cell::new(false),
            #[cfg(feature = "test-failpoints")]
            crypto_step: Cell::new(0),
        })
    }

    /// Register a transport. Order does not matter — the scheduler ranks by
    /// link profile per delivery, not registration order.
    pub fn add_transport(&mut self, transport: Arc<dyn Transport>) {
        self.transports.push(transport);
    }

    /// Register a discovery plane (a DHT) for prekey-bundle publication and
    /// lookup. Registering none is fine — bundles then travel out-of-band
    /// only (QR, file), exactly as in M2.
    pub fn add_discovery(&mut self, discovery: Arc<dyn Discovery>) {
        if self.discoveries.len() < MAX_DISCOVERY_PLANES {
            self.discoveries.push(discovery);
        }
    }

    /// Configure recipient-selected post-pairing rendezvous providers.
    ///
    /// `generation` is a caller-persisted monotonic provider-set generation.
    /// An empty set is an authenticated disable. Sovereign mode always
    /// disables this optional plane; Standard or Private select the concrete
    /// direct/anonymized [`RendezvousClient`] supplied by the embedding shell.
    pub fn configure_rendezvous(
        &mut self,
        mode: DiscoveryMode,
        client: Option<Arc<dyn RendezvousClient>>,
        mut providers: Vec<RendezvousProvider>,
        generation: u64,
    ) -> Result<()> {
        providers.sort_by(|left, right| {
            (left.origin(), left.static_key()).cmp(&(right.origin(), right.static_key()))
        });
        if generation == 0
            || providers.len() > MAX_RENDEZVOUS_PROVIDERS
            || providers
                .windows(2)
                .any(|pair| pair[0].provider_id() == pair[1].provider_id())
            || (!providers.is_empty() && client.is_none())
            || (mode == DiscoveryMode::Sovereign && (!providers.is_empty() || client.is_some()))
            || generation < self.rendezvous_provider_generation
        {
            return Err(NodeError::RendezvousUnavailable);
        }
        if generation == self.rendezvous_provider_generation
            && providers != self.rendezvous_providers
        {
            return Err(NodeError::RendezvousConflict);
        }
        let persisted = RendezvousLocalConfig::new(
            generation,
            providers
                .iter()
                .map(|provider| (provider.origin().to_owned(), provider.static_key()))
                .collect(),
        )?;
        match self.store.get_rendezvous_local_config()? {
            Some(current) if generation < current.generation => {
                return Err(NodeError::RendezvousUnavailable);
            }
            Some(current) if generation == current.generation && current != persisted => {
                return Err(NodeError::RendezvousConflict);
            }
            Some(current) if current == persisted => {}
            _ => self
                .store
                .put_rendezvous_local_config(&persisted, &mut OsRng)?,
        }
        self.rendezvous_client = client;
        self.rendezvous_providers = providers;
        self.rendezvous_provider_generation = generation;
        self.rendezvous_advertised.clear();
        self.rendezvous_refresh_requested
            .extend(self.sessions.keys().copied());
        self.mark_rendezvous_publication_dirty(&mut OsRng)?;
        Ok(())
    }

    /// Reconcile the complete local rendezvous set using an internal
    /// monotonic generation.
    ///
    /// Shell settings do not own protocol generations. A provider-set change
    /// advances the sealed generation exactly once; a restart or a
    /// Standard↔Private ingress change over the same set reuses it. Sovereign
    /// mode persists an authenticated empty set.
    pub fn reconcile_rendezvous(
        &mut self,
        mode: DiscoveryMode,
        client: Option<Arc<dyn RendezvousClient>>,
        mut providers: Vec<RendezvousProvider>,
    ) -> Result<()> {
        providers.sort_by(|left, right| {
            (left.origin(), left.static_key()).cmp(&(right.origin(), right.static_key()))
        });
        let generation = if providers == self.rendezvous_providers {
            self.rendezvous_provider_generation.max(1)
        } else {
            self.rendezvous_provider_generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?
                .max(1)
        };
        self.configure_rendezvous(mode, client, providers, generation)
    }

    /// Configure the optional native-wake client for the current operating
    /// mode. Sovereign mode has no wake provider and rejects a supplied
    /// client; disabling the client leaves ordinary delivery untouched.
    pub fn configure_wake(
        &mut self,
        mode: DiscoveryMode,
        client: Option<Arc<dyn WakeClient>>,
    ) -> Result<()> {
        if mode == DiscoveryMode::Sovereign && client.is_some() {
            return Err(NodeError::WakeUnavailable);
        }
        self.wake_client = client;
        Ok(())
    }

    /// Remove issued capabilities for gateways that are no longer eligible.
    ///
    /// This runs when a node starts with a new mode or provider set. It never
    /// removes remote capabilities supplied by contacts, and gateway failure
    /// cannot disturb ordinary delivery.
    pub fn reconcile_wake_providers(
        &mut self,
        providers: &[WakeProvider],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize> {
        if now == 0 || providers.len() > MAX_WAKE_PROVIDERS {
            return Err(NodeError::WakeUnavailable);
        }
        let allowed = providers
            .iter()
            .map(WakeProvider::provider_id)
            .collect::<HashSet<_>>();
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        let mut updated = 0usize;
        for peer_device in devices {
            let state = self
                .store
                .get_wake_service_state(&peer_device)?
                .ok_or(NodeError::CorruptState)?;
            let issued_count = state.issued().count();
            if issued_count == 0 {
                continue;
            }
            let capabilities = state
                .issued()
                .filter(|capability| {
                    allowed.contains(&capability.provider_id) && capability.expires_at > now
                })
                .map(|capability| {
                    Ok(WakeCapabilityDescriptor {
                        origin: capability.origin.clone(),
                        static_key: capability.static_key,
                        expires_at: capability.expires_at,
                        capability: capability.decoded_capability()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if capabilities.len() == issued_count {
                continue;
            }
            let generation = state
                .issued_generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?;
            self.publish_wake_capabilities(peer_device, generation, capabilities, now, rng)?;
            updated = updated.saturating_add(1);
        }
        Ok(updated)
    }

    /// Mint and publish fresh per-contact capabilities for one native token.
    ///
    /// Provider registration is bounded by relationship count and wall-clock
    /// budget. A relationship changes only after every configured gateway
    /// returned a valid fresh capability; refusal or outage preserves its
    /// prior complete capability set. The cursor rotates across later calls
    /// so a large contact set cannot monopolize one platform callback.
    pub async fn register_native_wake_destination(
        &mut self,
        registration: NativeWakeDestinationRegistration<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<NativeWakeRegistrationResult> {
        let NativeWakeDestinationRegistration {
            platform,
            environment,
            profile,
            provider_token,
            app_topic,
            providers,
            now,
        } = registration;
        let Some(client) = self.wake_client.clone() else {
            return Err(NodeError::WakeUnavailable);
        };
        if now == 0 || providers.is_empty() || providers.len() > MAX_WAKE_PROVIDERS {
            return Err(NodeError::WakeUnavailable);
        }
        let mut provider_ids = providers
            .iter()
            .map(WakeProvider::provider_id)
            .collect::<Vec<_>>();
        provider_ids.sort_unstable();
        if provider_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(NodeError::WakeUnavailable);
        }
        let mut validation = WakeRegisterRequest {
            platform,
            environment,
            profile,
            provider_token: provider_token.to_vec(),
            app_topic: app_topic.to_vec(),
            request_nonce: [1u8; 16],
        };
        let validated = validation.encode();
        validation.provider_token.fill(0);
        validated?;

        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        if devices.is_empty() {
            self.wake_registration_cursor = 0;
            return Ok(NativeWakeRegistrationResult::default());
        }
        if self.wake_registration_cursor >= devices.len() {
            self.wake_registration_cursor = 0;
        }
        let start = self.wake_registration_cursor;
        let end = start
            .saturating_add(MAX_WAKE_REGISTRATION_RELATIONSHIPS_PER_CALL)
            .min(devices.len());
        let deadline = Instant::now() + WAKE_REGISTRATION_BUDGET;
        let mut attempted = 0usize;
        let mut updated = 0usize;

        for peer_device in devices[start..end].iter().copied() {
            if Instant::now() >= deadline {
                break;
            }
            attempted = attempted.saturating_add(1);
            let mut descriptors = Vec::with_capacity(providers.len());
            for provider in providers {
                let mut request_nonce = [0u8; 16];
                rng.fill_bytes(&mut request_nonce);
                if request_nonce == [0u8; 16] {
                    request_nonce[15] = 1;
                }
                let mut request = WakeRegisterRequest {
                    platform,
                    environment,
                    profile,
                    provider_token: provider_token.to_vec(),
                    app_topic: app_topic.to_vec(),
                    request_nonce,
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                let outcome = if remaining.is_zero() {
                    None
                } else {
                    before_timeout(remaining, client.register(provider, &request)).await
                };
                request.provider_token.fill(0);
                let Some(Ok(response)) = outcome else {
                    descriptors.clear();
                    break;
                };
                let Some(capability) = response.capability else {
                    descriptors.clear();
                    break;
                };
                if !response.accepted
                    || response.expires_at <= now
                    || response.expires_at > now.saturating_add(WAKE_CAPABILITY_MAX_LIFETIME_SECS)
                {
                    descriptors.clear();
                    break;
                }
                descriptors.push(WakeCapabilityDescriptor {
                    origin: provider.origin().to_owned(),
                    static_key: provider.static_key(),
                    expires_at: response.expires_at,
                    capability,
                });
            }
            if descriptors.len() != providers.len() {
                continue;
            }
            let state = self
                .store
                .get_wake_service_state(&peer_device)?
                .ok_or(NodeError::CorruptState)?;
            let generation = state
                .issued_generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?;
            self.publish_wake_capabilities(peer_device, generation, descriptors, now, rng)?;
            updated = updated.saturating_add(1);
        }

        let next = start.saturating_add(attempted);
        let remaining = next < devices.len();
        self.wake_registration_cursor = if remaining { next } else { 0 };
        Ok(NativeWakeRegistrationResult { updated, remaining })
    }

    /// Revoke every capability this installation issued to current contacts.
    ///
    /// Empty complete generations travel over the existing authenticated
    /// pairwise sessions. Durable gateway revocations are queued by the same
    /// atomic transition; remote capabilities and message delivery state are
    /// untouched.
    pub fn revoke_native_wake_capabilities(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize> {
        if now == 0 {
            return Err(NodeError::WakeUnavailable);
        }
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        let mut updated = 0usize;
        for peer_device in devices {
            let Some(state) = self.store.get_wake_service_state(&peer_device)? else {
                continue;
            };
            if state.issued().next().is_none() {
                continue;
            }
            let generation = state
                .issued_generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?;
            self.publish_wake_capabilities(peer_device, generation, Vec::new(), now, rng)?;
            updated = updated.saturating_add(1);
        }
        self.wake_registration_cursor = 0;
        Ok(updated)
    }

    /// Replace the complete capability generation this installation issued
    /// to one authenticated remote physical device.
    ///
    /// Capabilities must already have been minted for this exact relationship
    /// by the configured gateway. The resulting complete set (including an
    /// empty revocation set) is encrypted through the pairwise ratchet and
    /// committed atomically with the local issued-state generation.
    pub fn publish_wake_capabilities(
        &mut self,
        peer_device: [u8; 32],
        generation: u64,
        mut capabilities: Vec<WakeCapabilityDescriptor>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if now == 0 || (!capabilities.is_empty() && self.wake_client.is_none()) {
            return Err(NodeError::WakeUnavailable);
        }
        let recipient_account = self.account_for_device(&peer_device)?;
        let endpoint = self
            .store
            .contact_devices_for(&recipient_account)?
            .into_iter()
            .find(|endpoint| endpoint.device == peer_device)
            .ok_or(NodeError::UnknownPeer)?;
        if endpoint.revoked_at.is_some() {
            return Err(NodeError::UnknownPeer);
        }
        capabilities.sort_by(|left, right| {
            (left.origin.as_bytes(), left.static_key)
                .cmp(&(right.origin.as_bytes(), right.static_key))
        });
        let mut stored = Vec::with_capacity(capabilities.len());
        for capability in &capabilities {
            let provider = WakeProvider::new(capability.origin.clone(), capability.static_key)?;
            if provider.provider_id()
                != kult_protocol::wake_provider_id(
                    capability.origin.as_bytes(),
                    &capability.static_key,
                )?
                || capability.expires_at <= now
                || capability.expires_at > now.saturating_add(WAKE_CAPABILITY_MAX_LIFETIME_SECS)
            {
                return Err(NodeError::WakeUnavailable);
            }
            stored.push(WakeStoredCapability::new(
                WakeCapabilityDirection::Issued,
                capability.origin.clone(),
                capability.static_key,
                capability.capability.as_bytes().to_vec(),
                capability.expires_at,
            )?);
        }
        let control = WakeCapabilityControl {
            sender_account: self.account.ed,
            sender_device: self.device_id(),
            recipient_account,
            recipient_device: peer_device,
            authority_generation: self.device_state.manifest.generation(),
            generation,
            capabilities,
        };
        let payload = control.encode()?;
        let before_state = self
            .store
            .get_wake_service_state(&peer_device)?
            .ok_or(NodeError::CorruptState)?;
        let mut after_state = before_state.clone();
        after_state
            .replace_direction(WakeCapabilityDirection::Issued, generation, stored)
            .map_err(|error| {
                if matches!(error, kult_store::StoreError::InvalidTransition) {
                    NodeError::WakeConflict
                } else {
                    NodeError::Store(error)
                }
            })?;
        if before_state == after_state {
            return Ok(());
        }
        let before_session = self
            .sessions
            .get(&peer_device)
            .cloned()
            .ok_or(NodeError::NoSession)?;
        if before_state.session_id != *before_session.session_id() {
            return Err(NodeError::CorruptState);
        }
        let mut after_session = before_session.clone();
        let queue =
            self.prepare_control_queue(&mut after_session, peer_device, &payload, now, rng)?;
        let receipt = self.store.commit_plan(
            CommitPlan::PairwiseSend(PairwiseSendPlan {
                sessions: &[SessionTransition {
                    peer_device,
                    before: Some(&before_session),
                    after: &after_session,
                }],
                message: None,
                message_update: None,
                deliveries: &[],
                delivery_updates: &[],
                queue: &[queue],
                groups: &[],
                authorities: &[],
                scheduled: None,
                clear_capabilities: &[],
                clear_reset_markers: &[],
                ephemeral: None,
                media_transfers: &[],
                media_objects: &[],
                delete_controls: &[],
                wake: &[WakeServiceTransition {
                    peer_device,
                    before: &before_state,
                    after: &after_state,
                }],
                presentation_changed: false,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.sessions.insert(peer_device, after_session);
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, []);
        Ok(())
    }

    /// Coalesce an active-conversation or call-setup route refresh.
    pub fn request_rendezvous_refresh(&mut self, peer: &[u8; 32]) -> Result<()> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        let endpoints = self.store.contact_devices_for(peer)?;
        if endpoints.is_empty() {
            self.rendezvous_refresh_requested.insert(*peer);
        } else {
            self.rendezvous_refresh_requested.extend(
                endpoints
                    .into_iter()
                    .filter(|endpoint| endpoint.revoked_at.is_none())
                    .map(|endpoint| endpoint.device),
            );
        }
        Ok(())
    }

    /// Mark or clear one foreground pairwise conversation.
    ///
    /// This is runtime-only presentation state. While active, the ordinary
    /// rendezvous retry/expiry schedule may refresh the contact's physical
    /// endpoints. Clearing it stops that trigger without deleting routes or
    /// changing message state.
    pub fn set_rendezvous_conversation_active(
        &mut self,
        peer: &[u8; 32],
        active: bool,
    ) -> Result<()> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if active {
            self.request_rendezvous_refresh(peer)?;
            self.rendezvous_active_conversations.insert(*peer);
        } else {
            self.rendezvous_active_conversations.remove(peer);
        }
        Ok(())
    }

    /// Enable, reconfigure, or (`None`) disable internet↔mesh bridging
    /// (docs/05-transports.md §4.2 rule 5, ADR-0009). While enabled, sealed
    /// envelopes heard on airtime-class carriers whose delivery tokens this
    /// node does not recognize are offered as mailbox deposits to `relays`
    /// (a relay accepts exactly when the recipient registered that token
    /// there), and third-party envelopes surfaced by carriers via
    /// `recv_transit` are flooded on broadcast (mesh) carriers — after this
    /// node's own traffic, bounded in every axis. Off by default: bridging
    /// spends the operator's airtime and bandwidth on strangers' sealed
    /// traffic, so it is a deliberate choice.
    pub fn set_bridge(&mut self, relays: Option<Vec<DeliveryHint>>) {
        match relays {
            Some(relays) => match &mut self.bridge {
                Some(bridge) => bridge.relays = relays,
                None => self.bridge = Some(Bridge::new(relays)),
            },
            None => self.bridge = None,
        }
    }

    /// Third-party envelopes currently queued for bridging (0 when bridging
    /// is off) — observability for daemon status, nothing more.
    pub fn transit_queued(&self) -> usize {
        self.bridge.as_ref().map_or(0, |b| b.queue.len())
    }

    // ---- identity ----------------------------------------------------------

    /// This node's peer id (Ed25519 identity key bytes) — what contacts key
    /// conversations by.
    pub fn peer_id(&self) -> [u8; 32] {
        self.account.ed
    }

    /// This node's public identity.
    pub fn public(&self) -> IdentityPublic {
        self.account.clone()
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.account.address()
    }

    /// This account's ordinary share artifact: stable fingerprint plus a
    /// sealed random reachability capability.
    pub fn connect_code(&self) -> Result<String> {
        Ok(ConnectCode::new(&self.account, self.device_state.discovery.capability)?.encode())
    }

    /// Whether the visible mailbox-only Alpha address bridge remains enabled.
    pub fn legacy_discovery_enabled(&self) -> bool {
        self.device_state.discovery.legacy_v1_enabled
    }

    /// Whether the public discovery material changed since the last complete
    /// Standard-mode publication.
    ///
    /// The digest covers only public inputs: authority, ingress prekeys,
    /// admission policy, capability state, and policy-filtered routes. It
    /// deliberately excludes OPKs and every live/session secret.
    pub fn discovery_publication_needed(&self, hints: &[DeliveryHint]) -> Result<bool> {
        self.discovery_publication_needed_with_policy(hints, DiscoveryPublicationPolicy::default())
    }

    /// Whether public discovery material changed under an explicit operating
    /// mode and Sovereign direct-route policy.
    pub fn discovery_publication_needed_with_policy(
        &self,
        hints: &[DeliveryHint],
        policy: DiscoveryPublicationPolicy,
    ) -> Result<bool> {
        Ok(self.discovery_published_material
            != Some(self.discovery_material_digest(hints, policy)?))
    }

    /// Rotate reachability independently of account identity and safety
    /// numbers. Existing sessions and local history remain unchanged.
    pub fn rotate_connect_code(&mut self, rng: &mut impl CryptoRngCore) -> Result<String> {
        let before = self.device_state.clone();
        let code = ConnectCode::generate(&self.account, rng)?;
        let mut after = before.clone();
        after.discovery = DiscoveryCapabilityState {
            capability: code.capability(),
            generation: before
                .discovery
                .generation
                .checked_add(1)
                .ok_or(NodeError::CorruptState)?,
            // A deliberate capability rotation must not leave stable-identity
            // discovery as a bypass around that revocation.
            legacy_v1_enabled: false,
        };
        self.store.commit_plan(
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
        self.discovery_advertised.clear();
        self.after_memory_replacement()?;
        Ok(code.encode())
    }

    /// Permanently retire the time-bounded stable-address publication bridge
    /// without changing the current Connect code.
    pub fn retire_legacy_discovery(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        if !self.device_state.discovery.legacy_v1_enabled {
            return Ok(());
        }
        let before = self.device_state.clone();
        let mut after = before.clone();
        after.discovery.legacy_v1_enabled = false;
        after.discovery.generation = after
            .discovery
            .generation
            .checked_add(1)
            .ok_or(NodeError::CorruptState)?;
        self.store.commit_plan(
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
        self.discovery_advertised.clear();
        self.after_memory_replacement()
    }

    /// The safety number for out-of-band verification with a contact
    /// (docs/04-cryptography.md §9).
    pub fn safety_number_with(&self, peer: &[u8; 32]) -> Result<SafetyNumber> {
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        let their: IdentityPublic =
            postcard::from_bytes(&contact.identity).map_err(|_| NodeError::CorruptState)?;
        Ok(safety_number(&self.account, &their))
    }

    /// Local-only record describing a copied-root Alpha reset and contacts
    /// whose new safety numbers still require comparison.
    pub fn authority_reset_history(&self) -> Result<Option<AuthorityResetHistoryRecord>> {
        Ok(self.store.authority_reset_history()?)
    }

    /// Write the one-time encrypted offline account authority to a new
    /// caller-selected file and return the separate 24-word opening phrase.
    ///
    /// The destination is created with owner-only permissions on Unix and is
    /// never overwritten. A failed write leaves the in-memory material
    /// available for a retry; a successful write consumes it permanently.
    pub fn export_account_recovery_authority(
        &mut self,
        path: &std::path::Path,
    ) -> Result<zeroize::Zeroizing<String>> {
        let material = self
            .pending_recovery_material
            .as_ref()
            .ok_or(NodeError::RecoveryAuthorityUnavailable)?;
        write_new_private_file(path, &material.package)?;
        let mnemonic = material.mnemonic.clone();
        self.pending_recovery_material = None;
        Ok(mnemonic)
    }

    /// Export a fresh signed prekey and Connect-capability bundle for
    /// out-of-band sharing (QR, file, dictation). Each call mints a new
    /// one-time prekey, so hand each prospective contact their own bundle.
    pub fn handshake_bundle(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        self.handshake_bundle_inner(&[], false, now, rng)
    }

    /// Export a fresh signed prekey bundle carrying this node's current
    /// delivery routes.
    ///
    /// QR pairing must be sufficient to send the first message even without
    /// an internet DHT bootstrap. mDNS discovers libp2p peers, but Komms
    /// identities are intentionally separate from libp2p peer ids; these
    /// signed hints bind the two without weakening that separation.
    pub fn handshake_bundle_with_hints(
        &mut self,
        hints: &[DeliveryHint],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.handshake_bundle_inner(hints, true, now, rng)
    }

    fn handshake_bundle_inner(
        &mut self,
        hints: &[DeliveryHint],
        hints_authoritative: bool,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let before_vault = self.vault.encode();
        let mut candidate_vault = self.vault.clone();
        let step = self.begin_crypto_step()?;
        let opk = candidate_vault.fresh_opk(rng);
        self.finish_crypto_step(step)?;
        let mut bundle = PrekeyBundle::build(
            &self.device_identity,
            &candidate_vault.spk(),
            &candidate_vault.pqspk()?,
            Some(&opk),
            now + BUNDLE_TTL_SECS,
            encode_hints(hints),
        );
        let mut invitation = [0u8; 32];
        rng.fill_bytes(&mut invitation);
        bundle.attach_admission(
            &self.device_identity,
            now,
            AdmissionPolicy::default(),
            Some(invitation),
        )?;
        let invitation_digest = bundle.verify_admission(now)?.descriptor.bundle_digest;
        candidate_vault.add_invitation(invitation_digest, invitation, bundle.expires_at, now);
        let device_bundle = DevicePrekeyBundle::new(
            self.device_state.local_certificate.clone(),
            self.device_state.manifest.clone(),
            bundle,
        )?;
        let encoded = AuthorityPairingBundle::new(
            device_bundle,
            self.device_state.discovery.capability,
            self.device_state.discovery.generation,
            &self.device_identity,
        )?
        .encode()?;
        let after_vault = candidate_vault.encode();
        self.store.commit_plan(
            CommitPlan::PrekeyPublish(PrekeyPublishPlan {
                prekeys: PrekeyTransition {
                    before: Some(&before_vault),
                    after: &after_vault,
                },
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.vault = candidate_vault;
        if hints_authoritative {
            self.own_hints = hints.to_vec();
            self.own_hints_authoritative = true;
            self.discovery_advertised.clear();
        }
        self.after_memory_replacement()?;
        if hints_authoritative {
            self.mark_rendezvous_publication_dirty(rng)?;
        }
        Ok(encoded)
    }

    // ---- capability-scoped discovery (ADR-0031) ----------------------------

    /// Publish the Standard-mode six-record capability window.
    ///
    /// Only recipient-selected mailbox hints enter public records. Direct,
    /// LAN, mesh, and spool routes remain pairing- or relationship-scoped.
    pub async fn publish_bundle(&mut self, hints: &[DeliveryHint], now: u64) -> Result<()> {
        self.publish_bundle_with_policy(hints, DiscoveryPublicationPolicy::default(), now)
            .await
    }

    /// Publish the exact ADR-0031 epoch window under an explicit mode policy.
    ///
    /// A direct route is accepted only when both Sovereign mode and the
    /// separate warning acknowledgement are present. Records contain no
    /// one-time prekeys and are stored with their encoded validity expiry.
    pub async fn publish_bundle_with_policy(
        &mut self,
        hints: &[DeliveryHint],
        policy: DiscoveryPublicationPolicy,
        now: u64,
    ) -> Result<()> {
        if self.discoveries.is_empty() {
            return Err(NodeError::NoDiscovery);
        }
        let routes = discovery_routes(hints, policy)?;
        let code = ConnectCode::new(&self.account, self.device_state.discovery.capability)?;
        let before = self.device_state.clone();
        let mut after = before.clone();
        after.discovery.generation = after
            .discovery
            .generation
            .checked_add(1)
            .ok_or(NodeError::CorruptState)?;
        let mut rng = OsRng;
        self.store.commit_plan(
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
            &mut rng,
        )?;
        self.before_memory_replacement()?;
        self.device_state = after;
        self.own_hints = hints.to_vec();
        self.own_hints_authoritative = true;
        self.discovery_advertised.clear();
        self.after_memory_replacement()?;
        self.mark_rendezvous_publication_dirty(&mut rng)?;

        let current_epoch = kult_crypto::discovery_epoch(now);
        let first_epoch = current_epoch.saturating_sub(DISCOVERY_PUBLISH_EPOCH_BEHIND);
        let last_epoch = current_epoch
            .checked_add(DISCOVERY_PUBLISH_EPOCH_AHEAD)
            .ok_or(NodeError::CorruptState)?;
        let mut records = Vec::with_capacity(
            usize::try_from(last_epoch - first_epoch + 1).map_err(|_| NodeError::CorruptState)?,
        );
        for epoch in first_epoch..=last_epoch {
            let valid_from = kult_crypto::discovery_epoch_valid_from(epoch);
            let expires_at = kult_crypto::discovery_epoch_valid_until(epoch)?;
            let mut prekey = PrekeyBundle::build(
                &self.device_identity,
                &self.vault.spk(),
                &self.vault.pqspk()?,
                None,
                expires_at,
                Vec::new(),
            );
            prekey.attach_admission(
                &self.device_identity,
                valid_from,
                AdmissionPolicy::default(),
                None,
            )?;
            let ingress = DiscoveryIngressBundle {
                certificate: self.device_state.local_certificate.clone(),
                prekey,
            };
            let value = kult_crypto::seal_discovery_record(
                &code,
                epoch,
                self.device_state.discovery.generation,
                now.min(expires_at),
                self.account.clone(),
                self.device_state.manifest.clone(),
                vec![ingress],
                routes.clone(),
                &self.device_identity,
                &mut rng,
            )?;
            records.push((
                epoch,
                kult_crypto::discovery_locator(&code.capability(), epoch),
                expires_at,
                value,
            ));
        }

        let mut published = false;
        for discovery in &self.discoveries {
            let complete = join_all(records.iter().map(|(_, locator, expires_at, value)| {
                discovery.publish(
                    DiscoveryNamespace::ConnectV2,
                    *locator,
                    value.clone(),
                    *expires_at,
                )
            }))
            .await
            .into_iter()
            .all(|result| result.is_ok());
            published |= complete;
        }

        if self.device_state.discovery.legacy_v1_enabled {
            let mailbox_hints = hints
                .iter()
                .filter(|hint| matches!(hint, DeliveryHint::Relay(_)))
                .cloned()
                .collect::<Vec<_>>();
            let mut legacy = PrekeyBundle::build(
                &self.device_identity,
                &self.vault.spk(),
                &self.vault.pqspk()?,
                None,
                now.saturating_add(BUNDLE_TTL_SECS),
                encode_hints(&mailbox_hints),
            );
            legacy.attach_admission(
                &self.device_identity,
                now,
                AdmissionPolicy::default(),
                None,
            )?;
            let value = DevicePrekeyBundle::new(
                self.device_state.local_certificate.clone(),
                self.device_state.manifest.clone(),
                legacy,
            )?
            .encode()?;
            for discovery in &self.discoveries {
                let _ = discovery
                    .publish(
                        DiscoveryNamespace::LegacyPrekeyV1,
                        self.account.address_digest(),
                        value.clone(),
                        now.saturating_add(BUNDLE_TTL_SECS),
                    )
                    .await;
            }
        }
        if published {
            self.discovery_published_material =
                Some(self.discovery_material_digest(hints, policy)?);
            Ok(())
        } else {
            Err(NodeError::NoDiscovery)
        }
    }

    fn discovery_material_digest(
        &self,
        hints: &[DeliveryHint],
        policy: DiscoveryPublicationPolicy,
    ) -> Result<[u8; 32]> {
        let routes = discovery_routes(hints, policy)?;
        let manifest = self.device_state.manifest.encode()?;
        let spk = self.vault.spk();
        let pqspk = self.vault.pqspk()?;
        let admission = AdmissionPolicy::default();
        let mut digest = Sha256::new();
        digest.update(b"Komms-Discovery-Publication-Material-v2");
        digest.update(self.account.address_digest());
        digest.update(self.device_id());
        digest.update(self.device_state.discovery.capability);
        digest.update([u8::from(self.device_state.discovery.legacy_v1_enabled)]);
        digest.update((manifest.len() as u64).to_be_bytes());
        digest.update(&manifest);
        digest.update(spk.id.to_be_bytes());
        digest.update(spk.public());
        digest.update(pqspk.id.to_be_bytes());
        digest.update((pqspk.public().len() as u64).to_be_bytes());
        digest.update(pqspk.public());
        digest.update([admission.difficulty]);
        digest.update(admission.max_first_ciphertext.to_be_bytes());
        digest.update(admission.max_clock_skew_secs.to_be_bytes());
        digest.update((admission.token_issuers.len() as u64).to_be_bytes());
        digest.update([match policy.mode {
            DiscoveryMode::Standard => 1,
            DiscoveryMode::Private => 2,
            DiscoveryMode::Sovereign => 3,
        }]);
        digest.update([u8::from(policy.publish_direct_routes)]);
        digest.update((routes.len() as u64).to_be_bytes());
        for route in routes {
            digest.update([route.kind as u8]);
            digest.update((route.value.len() as u64).to_be_bytes());
            digest.update(route.value);
        }
        Ok(digest.finalize().into())
    }

    /// Add a contact from a Connect code or a legacy Alpha account address.
    ///
    /// Connect lookups query exactly the local weekly epoch and one adjacent
    /// epoch on either side. Every retained candidate is exact-size, opened
    /// under the bearer capability, and fully authority/prekey verified
    /// before any contact or session state changes.
    pub async fn add_contact_by_address(
        &mut self,
        name: &str,
        address: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        if self.discoveries.is_empty() {
            return Err(NodeError::NoDiscovery);
        }
        if address.starts_with(kult_crypto::CONNECT_CODE_PREFIX) {
            let code = ConnectCode::parse(address)?;
            let record = self
                .lookup_connect_record(&code, now)
                .await?
                .ok_or(NodeError::BundleNotFound)?;
            let ingress = record
                .ingress
                .iter()
                .max_by(|left, right| {
                    left.prekey
                        .expires_at
                        .cmp(&right.prekey.expires_at)
                        .then_with(|| {
                            right
                                .certificate
                                .device_id()
                                .cmp(&left.certificate.device_id())
                        })
                })
                .ok_or(NodeError::BundleNotFound)?;
            let bundle = DevicePrekeyBundle::new(
                ingress.certificate.clone(),
                record.authority.clone(),
                ingress.prekey.clone(),
            )?
            .encode()?;
            let mut hints = Vec::with_capacity(record.routes.len());
            for route in &record.routes {
                let hint = decode_discovery_route(route)?;
                if !hints.contains(&hint) {
                    hints.push(hint);
                }
            }
            return self.add_contact_with_discovery_capability(
                name,
                &bundle,
                &hints,
                devices::ContactDiscoveryProjection {
                    capability: Some(code.capability()),
                    generation: record.generation,
                },
                now,
                rng,
            );
        }
        let digest = kult_crypto::parse_address(address)?;
        let bundle = self
            .lookup_legacy_bundle(digest, now)
            .await
            .ok_or(NodeError::BundleNotFound)?;
        let hints = decode_hints(&bundle.prekey.transport_hints());
        self.add_contact(name, &bundle.encode()?, &hints, now, rng)
    }

    async fn lookup_connect_record(
        &self,
        code: &ConnectCode,
        now: u64,
    ) -> Result<Option<DiscoveryRecord>> {
        let current = kult_crypto::discovery_epoch(now);
        let first = current.saturating_sub(DISCOVERY_LOOKUP_EPOCH_ADJACENCY);
        let last = current
            .checked_add(DISCOVERY_LOOKUP_EPOCH_ADJACENCY)
            .ok_or(NodeError::CorruptState)?;
        let mut requests = Vec::new();
        for epoch in first..=last {
            let locator = kult_crypto::discovery_locator(&code.capability(), epoch);
            for discovery in &self.discoveries {
                let discovery = Arc::clone(discovery);
                requests.push(async move {
                    (
                        epoch,
                        discovery
                            .lookup(DiscoveryNamespace::ConnectV2, locator)
                            .await,
                    )
                });
            }
        }
        let mut by_epoch: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
        for (epoch, result) in join_all(requests).await {
            if let Ok(mut values) = result {
                let bytes = values
                    .iter()
                    .try_fold(0usize, |total, value| total.checked_add(value.len()));
                if values.len() > MAX_DISCOVERY_CANDIDATES
                    || bytes.is_none_or(|bytes| {
                        bytes > MAX_DISCOVERY_CANDIDATES.saturating_mul(DISCOVERY_RECORD_SIZE)
                    })
                {
                    continue;
                }
                // One provider can contribute at most the protocol's exact
                // candidate bound. Discard wrong-shape values before they
                // consume the expensive authenticated-open budget.
                values.retain(|value| value.len() == DISCOVERY_RECORD_SIZE);
                values.sort_by_key(|value| <[u8; 32]>::from(Sha256::digest(value)));
                values.dedup();
                values.truncate(MAX_DISCOVERY_CANDIDATES);
                by_epoch.entry(epoch).or_default().extend(values);
            }
        }
        let mut verified: Vec<DiscoveryRecord> = Vec::new();
        for (epoch, mut candidates) in by_epoch {
            candidates.sort_by_key(|value| <[u8; 32]>::from(Sha256::digest(value)));
            candidates.dedup();
            candidates.truncate(MAX_DISCOVERY_CANDIDATES);
            let mut retained_bytes = 0usize;
            let byte_limit = MAX_DISCOVERY_CANDIDATES.saturating_mul(DISCOVERY_RECORD_SIZE);
            for candidate in candidates {
                retained_bytes = retained_bytes.saturating_add(candidate.len());
                if retained_bytes > byte_limit {
                    break;
                }
                let Ok(record) = kult_crypto::open_discovery_record(code, epoch, &candidate, now)
                else {
                    continue;
                };
                for accepted in &verified {
                    match accepted.authority.relation(&record.authority)? {
                        kult_crypto::DeviceAuthorityRelation::Fork => {
                            return Err(NodeError::DeviceAuthorityFork);
                        }
                        kult_crypto::DeviceAuthorityRelation::RecoveryConflict => {
                            return Err(NodeError::DeviceRecoveryConflict);
                        }
                        _ => {}
                    }
                }
                verified.push(record);
            }
        }
        let mut best: Option<DiscoveryRecord> = None;
        for candidate in verified {
            let replace = best.as_ref().is_none_or(|current| {
                candidate.authority.generation() > current.authority.generation()
                    || (candidate.authority.generation() == current.authority.generation()
                        && (candidate.issued_at > current.issued_at
                            || (candidate.issued_at == current.issued_at
                                && candidate.digest() < current.digest())))
            });
            if replace {
                best = Some(candidate);
            }
        }
        Ok(best)
    }

    /// Fetch and verify the mailbox-only Alpha compatibility record.
    async fn lookup_legacy_bundle(&self, digest: [u8; 32], now: u64) -> Option<DevicePrekeyBundle> {
        let mut best: Option<DevicePrekeyBundle> = None;
        for discovery in &self.discoveries {
            let Ok(candidates) = discovery
                .lookup(DiscoveryNamespace::LegacyPrekeyV1, digest)
                .await
            else {
                continue;
            };
            for bytes in candidates {
                let Ok(bundle) = DevicePrekeyBundle::decode(&bytes) else {
                    continue;
                };
                if bundle.verify(now).is_err()
                    || bundle.manifest.account().address_digest() != digest
                {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|b| bundle.prekey.expires_at > b.prekey.expires_at)
                {
                    best = Some(bundle);
                }
            }
        }
        best
    }

    /// The "accept mail for these" filter set (docs/04-cryptography.md §7)
    /// this node hands its chosen mailbox relays via
    /// [`kult_transport::Libp2pTransport::mailbox_checkin`]: introduction
    /// tokens (so first-contact handshakes can be deposited) plus every
    /// session's delivery tokens, over a window reaching
    /// `TOKEN_LOOKBACK_EPOCHS` back (deposits may be old) and
    /// `MAILBOX_AHEAD_EPOCHS` forward (deposits keep landing while this node
    /// is offline). Every token is scoped to this node as recipient
    /// (ADR-0007), so a check-in can only ever drain mail addressed to us.
    pub fn mailbox_tokens(&self, now: u64) -> Vec<[u8; 32]> {
        let me = self.account.ed;
        let device = self.device_id();
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + MAILBOX_AHEAD_EPOCHS;
        let mut tokens = Vec::new();
        for epoch in lo..=hi {
            tokens.push(kult_crypto::discovery_introduction_token(
                &self.device_state.discovery.capability,
                &device,
                epoch,
            ));
            if self.device_state.discovery.legacy_v1_enabled {
                tokens.push(intro_token(&me, epoch));
                if device != me {
                    tokens.push(intro_token(&device, epoch));
                }
            }
            for session in self.sessions.values() {
                tokens.push(delivery_token(
                    &MailboxKey::from_bytes(*session.mailbox_key()),
                    epoch,
                    &me,
                ));
                if device != me {
                    tokens.push(delivery_token(
                        &MailboxKey::from_bytes(*session.mailbox_key()),
                        epoch,
                        &device,
                    ));
                }
            }
        }
        tokens
    }

    // ---- contacts ----------------------------------------------------------

    /// Add (or replace) a contact from their encoded prekey bundle. The
    /// bundle is signature-verified before anything is stored. Returns the
    /// contact's peer id.
    pub fn add_contact(
        &mut self,
        name: &str,
        bundle_bytes: &[u8],
        hints: &[DeliveryHint],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        self.add_contact_with_discovery_capability(
            name,
            bundle_bytes,
            hints,
            devices::ContactDiscoveryProjection::default(),
            now,
            rng,
        )
    }

    fn add_contact_with_discovery_capability(
        &mut self,
        name: &str,
        bundle_bytes: &[u8],
        hints: &[DeliveryHint],
        supplied_discovery: devices::ContactDiscoveryProjection,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let mut owned_device_bundle = None;
        let discovery = if AuthorityPairingBundle::is_encoded(bundle_bytes) {
            let pairing = AuthorityPairingBundle::decode(bundle_bytes)?;
            pairing.verify(now)?;
            if supplied_discovery.capability.is_some()
                && (supplied_discovery.capability != Some(pairing.discovery_capability)
                    || supplied_discovery.generation != pairing.discovery_generation)
            {
                return Err(NodeError::Crypto(kult_crypto::CryptoError::InvalidBundle));
            }
            owned_device_bundle = Some(pairing.device_bundle.encode()?);
            devices::ContactDiscoveryProjection {
                capability: Some(pairing.discovery_capability),
                generation: pairing.discovery_generation,
            }
        } else {
            supplied_discovery
        };
        let bundle_bytes = owned_device_bundle.as_deref().unwrap_or(bundle_bytes);
        let introduction_capability = discovery.capability;
        let introduction_generation = discovery.generation;
        let name = contact_names::normalize_contact_name(name)?;
        let (peer, identity, stored_bundle, mut endpoint, manifest, advertised_hints) =
            if DevicePrekeyBundle::is_encoded(bundle_bytes) {
                let device_bundle = DevicePrekeyBundle::decode(bundle_bytes)?;
                device_bundle.verify(now)?;
                let advertised_hints = decode_hints(&device_bundle.prekey.transport_hints());
                let peer = device_bundle.manifest.account().ed;
                let identity = postcard::to_allocvec(device_bundle.manifest.account())
                    .map_err(|_| NodeError::CorruptState)?;
                let authority = device_bundle.manifest.encode()?;
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device: device_bundle.certificate.device_id(),
                    name: device_bundle
                        .manifest
                        .devices()
                        .iter()
                        .find(|entry| entry.certificate == device_bundle.certificate)
                        .map(|entry| entry.name.clone()),
                    certificate: postcard::to_allocvec(&device_bundle.certificate)
                        .map_err(|_| NodeError::CorruptState)?,
                    authority,
                    bundle: device_bundle.prekey.encode(),
                    hints: Vec::new(),
                    introduction_capability,
                    introduction_generation,
                    manifest_generation: device_bundle.manifest.generation(),
                    manifest_state_id: device_bundle.manifest.state_id(),
                    last_seen: now,
                    revoked_at: None,
                    revoked_after_counter: None,
                };
                (
                    peer,
                    identity,
                    Vec::new(),
                    endpoint,
                    Some(device_bundle.manifest),
                    advertised_hints,
                )
            } else {
                let verified = PrekeyBundle::decode(bundle_bytes)?.verify(now)?;
                let advertised_hints = decode_hints(&verified.bundle().transport_hints());
                let peer = verified.bundle().identity.ed;
                let identity = postcard::to_allocvec(&verified.bundle().identity)
                    .map_err(|_| NodeError::CorruptState)?;
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device: peer,
                    name: None,
                    certificate: Vec::new(),
                    authority: Vec::new(),
                    bundle: bundle_bytes.to_vec(),
                    hints: Vec::new(),
                    introduction_capability,
                    introduction_generation,
                    manifest_generation: 0,
                    manifest_state_id: [0u8; 32],
                    last_seen: now,
                    revoked_at: None,
                    revoked_after_counter: None,
                };
                (
                    peer,
                    identity,
                    bundle_bytes.to_vec(),
                    endpoint,
                    None,
                    advertised_hints,
                )
            };
        // Explicit user-supplied routes take priority, while authenticated
        // routes carried by the bundle make QR pairing sufficient on a LAN.
        let mut effective_hints = hints.to_vec();
        for advertised in advertised_hints {
            if !effective_hints.contains(&advertised) {
                effective_hints.push(advertised);
            }
        }
        endpoint.hints = encode_hints(&effective_hints);
        let endpoint_bundle_changed = self
            .store
            .contact_devices()?
            .into_iter()
            .find(|stored| stored.device == endpoint.device)
            .is_some_and(|stored| stored.bundle != endpoint.bundle);
        let endpoint_device = endpoint.device;
        if let Some(manifest) = manifest.as_ref() {
            // A rollback/fork-losing manifest must not mutate even the
            // account-level petname, verification bit, or delivery hints.
            self.validate_contact_device_manifest_visible(manifest, now, rng)?;
        }
        self.store.put_contact(
            &ContactRecord {
                peer,
                identity,
                name,
                bundle: stored_bundle,
                hints: encode_hints(&effective_hints),
                verified: false,
            },
            rng,
        )?;
        if let Some(manifest) = manifest {
            self.apply_contact_device_manifest(
                &manifest,
                devices::ContactDeviceAdvertisement {
                    device: endpoint.device,
                    bundle: endpoint.bundle,
                    hints: endpoint.hints,
                    discovery,
                },
                now,
                rng,
            )?;
        } else {
            self.store.put_contact_device(&endpoint, rng)?;
        }
        if endpoint_bundle_changed {
            self.reset_unconfirmed_session(&peer, &endpoint_device, rng)?;
        }
        Ok(peer)
    }

    /// A newly scanned bundle for an existing endpoint is an explicit repair
    /// opportunity. If messages are still awaiting a receipt, their current
    /// ratchet may have been created from an older one-time prekey bundle that
    /// the recipient never accepted. Drop only that unconfirmed session and
    /// make its pending deliveries eligible for fresh first-flight encryption
    /// on the next tick. Delivered history and other linked devices are left
    /// untouched.
    fn reset_unconfirmed_session(
        &mut self,
        account: &[u8; 32],
        device: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut affected = HashSet::new();
        let mut message_candidates = Vec::new();
        let mut delivery_candidates = Vec::new();
        let mut events = Vec::new();
        for message_before in self.store.messages_with(account)? {
            if message_before.direction != Direction::Outbound
                || matches!(
                    message_before.state,
                    DeliveryState::Delivered | DeliveryState::Failed
                )
            {
                continue;
            }
            let mut deliveries = self.store.message_device_deliveries(&message_before.id)?;
            let mut reset = false;
            for delivery in &mut deliveries {
                if delivery.device == *device
                    && delivery.state != DeliveryState::Delivered
                    && (delivery.state != DeliveryState::Queued || delivery.wire_id.is_some())
                {
                    let before = delivery.clone();
                    delivery.state = DeliveryState::Queued;
                    delivery.wire_id = None;
                    delivery_candidates.push((before, delivery.clone()));
                    reset = true;
                }
            }
            if !reset {
                continue;
            }
            affected.insert(message_before.id);
            let mut message_after = message_before.clone();
            message_after.state = if deliveries
                .iter()
                .any(|delivery| delivery.state == DeliveryState::Delivered)
            {
                DeliveryState::Delivered
            } else if deliveries
                .iter()
                .any(|delivery| delivery.state == DeliveryState::Sent)
            {
                DeliveryState::Sent
            } else {
                DeliveryState::Queued
            };
            message_after.wire_id = deliveries.iter().find_map(|delivery| delivery.wire_id);
            events.push(Event::DeliveryUpdated {
                id: message_after.id,
                state: message_after.state,
            });
            if message_after != message_before {
                message_candidates.push((message_before, message_after));
            }
        }
        if affected.is_empty() {
            return Ok(());
        }

        let delete_queue = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(sequence, item)| {
                (item.peer == *device && item.msg_id.is_some_and(|id| affected.contains(&id)))
                    .then_some(QueueDelete {
                        sequence,
                        content_id: item.envelope.content_id(),
                    })
            })
            .collect::<Vec<_>>();
        let delete_sessions = self
            .store
            .get_session(device)?
            .is_some()
            .then_some(*device)
            .into_iter()
            .collect::<Vec<_>>();
        let delete_capabilities = self
            .store
            .get_capabilities(device)?
            .is_some()
            .then_some(*device)
            .into_iter()
            .collect::<Vec<_>>();
        let messages = message_candidates
            .iter()
            .map(|(before, after)| MessageTransition { before, after })
            .collect::<Vec<_>>();
        let deliveries = delivery_candidates
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[],
                delete_pending: &[],
                delete_queue: &delete_queue,
                update_queue: &[],
                delete_replay: &[],
                messages: &messages,
                deliveries: &deliveries,
                group_messages: &[],
                groups: &[],
                ephemeral: &[],
                delete_messages: &[],
                delete_group_messages: &[],
                delete_media: &[],
                delete_scheduled: &[],
                delete_sessions: &delete_sessions,
                delete_capabilities: &delete_capabilities,
                clear_reset_markers: &[],
                delete_controls: &[],
                wake: &[],
                acknowledge_presentation: None,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.sessions.remove(device);
        self.capabilities_advertised.remove(device);
        self.discovery_advertised.remove(device);
        self.rendezvous_advertised.remove(device);
        self.rendezvous_refresh_requested.remove(device);
        self.rendezvous_rehandshake_requested.remove(device);
        self.after_memory_replacement()?;
        let deleted = delete_queue
            .iter()
            .map(|delete| delete.sequence)
            .collect::<HashSet<_>>();
        self.held_notified
            .retain(|sequence| !deleted.contains(sequence));
        self.call_queue_deadlines
            .retain(|sequence, _| !deleted.contains(sequence));
        self.accept_commit_receipt(receipt, events);
        Ok(())
    }

    /// Validate and assess one proposed private local petname without mutation.
    pub fn assess_contact_name(
        &self,
        peer: &[u8; 32],
        proposed_name: &str,
    ) -> Result<ContactNameAssessment> {
        if self.store.get_contact(peer)?.is_none() {
            return Err(NodeError::UnknownPeer);
        }
        contact_names::assess_contact_name(peer, proposed_name, &self.store.contacts()?)
    }

    /// Rename one stored contact locally by exact peer identity.
    ///
    /// Duplicate names remain valid. Any deterministic spoofing or duplicate
    /// warning must be explicitly acknowledged by the caller before the sealed
    /// contact blob is replaced. No envelope, capability, receipt, or transport
    /// work is created.
    pub fn rename_contact(
        &mut self,
        peer: &[u8; 32],
        proposed_name: &str,
        accept_warnings: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ContactNameAssessment> {
        let assessment = self.assess_contact_name(peer, proposed_name)?;
        if !assessment.warnings.is_empty() && !accept_warnings {
            return Err(NodeError::ContactNameReviewRequired);
        }
        let mut contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if contact.name != assessment.normalized_name {
            contact.name.clone_from(&assessment.normalized_name);
            self.store.put_contact(&contact, rng)?;
            self.events.push_back(Event::ContactRenamed {
                peer: *peer,
                name: assessment.normalized_name.clone(),
            });
        }
        Ok(assessment)
    }

    /// Replace a contact's delivery hints.
    pub fn set_hints(
        &mut self,
        peer: &[u8; 32],
        hints: &[DeliveryHint],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        contact.hints = encode_hints(hints);
        self.store.put_contact(&contact, rng)?;
        // Preserve the original account-scoped API. A legacy alias and a sole
        // active physical endpoint both unambiguously inherit the replacement;
        // with several devices, fill only endpoints that have no exact route so
        // one device's address never overwrites another's advertised address.
        let endpoints = self.store.contact_devices_for(peer)?;
        let sole_endpoint = endpoints.len() == 1;
        for mut endpoint in endpoints {
            if sole_endpoint || endpoint.device == *peer || endpoint.hints.is_empty() {
                endpoint.hints.clone_from(&contact.hints);
                self.store.put_contact_device(&endpoint, rng)?;
            }
        }
        Ok(())
    }

    /// Record that safety numbers were verified out-of-band.
    pub fn mark_verified(&mut self, peer: &[u8; 32], rng: &mut impl CryptoRngCore) -> Result<()> {
        if self.store.authority_reset_reverification_required(peer)? {
            if !self.store.confirm_authority_reset_contact(peer, rng)? {
                return Err(NodeError::CorruptState);
            }
            return Ok(());
        }
        let mut contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        contact.verified = true;
        self.store.put_contact(&contact, rng)?;
        Ok(())
    }

    /// All stored contacts.
    pub fn contacts(&self) -> Result<Vec<ContactRecord>> {
        Ok(self.store.contacts()?)
    }

    /// Bounded sealed first-contact requests in deterministic arrival order.
    pub fn message_requests(&self) -> Result<Vec<MessageRequestInfo>> {
        Ok(self
            .store
            .provisional_requests()?
            .into_iter()
            .map(|request| MessageRequestInfo {
                id: request.request_id,
                account: request.account,
                device: request.device,
                preview: request.preview,
                safety_number: request
                    .safety_number
                    .as_bytes()
                    .chunks(5)
                    .map(|chunk| core::str::from_utf8(chunk).expect("validated digits"))
                    .collect::<Vec<_>>()
                    .join(" "),
                arrived_at: request.arrived_at,
                expires_at: request.expires_at,
                transport: request.transport,
            })
            .collect())
    }

    /// Explicitly accept and atomically promote one message request.
    pub fn accept_message_request(
        &mut self,
        request_id: &[u8; 16],
        name: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let request = self
            .store
            .provisional_request_by_id(request_id)?
            .ok_or(NodeError::UnknownMessageRequest)?;
        if now > request.expires_at {
            return Err(NodeError::UnknownMessageRequest);
        }
        let name = contact_names::normalize_contact_name(name)?;
        let (session_before, remainder): (Session, &[u8]) =
            postcard::take_from_bytes(&request.session).map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty() {
            return Err(NodeError::CorruptState);
        }
        let mut session_after = session_before.clone();
        let acceptance = ReceiptPayload {
            acks: vec![request.request_id],
            nacks: Vec::new(),
        }
        .encode();
        let receipt_queue =
            self.prepare_control_queue(&mut session_after, request.device, &acceptance, now, rng)?;
        let prepared = if request.first_content.is_empty() {
            None
        } else {
            let prepared = self.prepare_inbound(
                request.account,
                request.first_content.clone(),
                None,
                now,
                rng,
            )?;
            if prepared.message.is_none()
                || prepared.ephemeral.is_some()
                || !prepared.media_transfers.is_empty()
                || !prepared.media_objects.is_empty()
            {
                return Err(NodeError::CorruptState);
            }
            Some(prepared)
        };
        let mut contact = request.contact.clone();
        contact.name = name;
        let receipt = self.store.commit_plan(
            CommitPlan::AdmissionAccept(AdmissionAcceptPlan {
                request: &request,
                session_before: &session_before,
                session: SessionTransition {
                    peer_device: request.device,
                    before: None,
                    after: &session_after,
                },
                contact: &contact,
                devices: &request.devices,
                groups: &[],
                message: prepared
                    .as_ref()
                    .and_then(|prepared| prepared.message.as_ref()),
                queue: core::slice::from_ref(&receipt_queue),
                accepted_at: now,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.sessions.insert(request.device, session_after);
        self.capabilities_advertised.remove(&request.device);
        self.discovery_advertised.remove(&request.device);
        self.rendezvous_advertised.remove(&request.device);
        self.rendezvous_refresh_requested.insert(request.device);
        self.after_memory_replacement()?;
        let mut events = vec![
            Event::MessageRequestAccepted {
                request: request.request_id,
                peer: request.account,
            },
            Event::ContactAdded {
                peer: request.account,
            },
            Event::SessionEstablished {
                peer: request.account,
            },
        ];
        if let Some(prepared) = prepared {
            events.extend(prepared.events);
        }
        self.accept_commit_receipt(receipt, events);
        Ok(request.account)
    }

    /// Explicitly delete one request, retaining only its bounded replay tombstone.
    pub fn delete_message_request(
        &mut self,
        request_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.discard_message_request(request_id, now, false, rng)
    }

    /// Block one verified request sender locally and remove provisional state.
    pub fn block_message_request(
        &mut self,
        request_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.discard_message_request(request_id, now, true, rng)
    }

    fn discard_message_request(
        &mut self,
        request_id: &[u8; 16],
        now: u64,
        block: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let request = self
            .store
            .provisional_request_by_id(request_id)?
            .ok_or(NodeError::UnknownMessageRequest)?;
        let tombstone = AdmissionReplayTombstone {
            request_id: request.request_id,
            account: request.account,
            device: request.device,
            rejected_at: now,
            expires_at: now.saturating_add(
                MAX_PROVISIONAL_LIFETIME_SECS.min(MAX_ADMISSION_REPLAY_LIFETIME_SECS),
            ),
        };
        let tombstones = self.store.admission_tombstones()?;
        let retire_tombstone = (tombstones.len() >= MAX_ADMISSION_REPLAY_TOMBSTONES).then(|| {
            tombstones
                .iter()
                .min_by_key(|record| (record.expires_at, record.rejected_at, record.request_id))
                .expect("non-empty at fixed limit")
        });
        let block_record = block.then_some(BlockedIdentityRecord {
            account: request.account,
            device: request.device,
            created_at: now,
        });
        let receipt = self.store.commit_plan(
            CommitPlan::AdmissionDiscard(AdmissionDiscardPlan {
                request: &request,
                tombstone: &tombstone,
                retire_tombstone,
                block: block_record.as_ref(),
                presentation_changed: true,
            }),
            rng,
        )?;
        self.capabilities_advertised.remove(&request.device);
        self.discovery_advertised.remove(&request.device);
        self.rendezvous_advertised.remove(&request.device);
        self.rendezvous_refresh_requested.insert(request.device);
        self.accept_commit_receipt(
            receipt,
            [if block {
                Event::MessageRequestBlocked {
                    request: request.request_id,
                }
            } else {
                Event::MessageRequestDeleted {
                    request: request.request_id,
                }
            }],
        );
        Ok(())
    }

    /// Message history with a peer, in insertion order.
    pub fn messages_with(&self, peer: &[u8; 32]) -> Result<Vec<MessageRecord>> {
        Ok(self.store.messages_with(peer)?)
    }

    /// Pairwise message read model with immutable edits resolved and edit
    /// events removed from the ordinary row sequence.
    pub fn resolved_messages_with(&self, peer: &[u8; 32]) -> Result<Vec<ResolvedMessage>> {
        Ok(edits::resolve_pairwise(
            self.store.messages_with(peer)?,
            self.account.ed,
        ))
    }

    /// Text history in the one reserved device-local note-to-self
    /// conversation, in insertion order.
    pub fn note_to_self_messages(&self) -> Result<Vec<NoteMessageRecord>> {
        let mut messages = self.store.note_messages()?;
        messages.sort_by_key(|message| (message.timestamp, message.id));
        Ok(messages)
    }

    /// Number of envelopes waiting in the outbound queue.
    pub fn queued(&self) -> Result<usize> {
        let mut queued = 0usize;
        for (_, item) in self.store.queue_all()? {
            let message = item.msg_id.or(item.group_msg_id);
            let Some(message) = message else {
                queued += 1;
                continue;
            };
            let deliveries = self.store.message_device_deliveries(&message)?;
            if deliveries.is_empty()
                || deliveries.iter().any(|delivery| {
                    delivery.device == item.peer && delivery.state == DeliveryState::Queued
                })
            {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// Messages waiting for an absolute UTC activation instant.
    pub fn scheduled_messages(&self) -> Result<Vec<ScheduledMessageInfo>> {
        Ok(self
            .store
            .scheduled_messages()?
            .into_iter()
            .map(scheduled_info)
            .collect())
    }

    // ---- commands ----------------------------------------------------------

    /// Execute one [`Command`] — the single serializable entry point the FFI
    /// layer wraps. Effects surface as [`Event`]s on the next [`Node::tick`].
    pub fn execute(&mut self, cmd: Command, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        match cmd {
            Command::Send { peer, body } => {
                self.send_message(&peer, &body, now, rng)?;
            }
            Command::SendDisappearing {
                peer,
                body,
                lifetime_secs,
            } => {
                self.send_disappearing_message(&peer, &body, lifetime_secs, now, rng)?;
            }
            Command::Schedule {
                peer,
                body,
                not_before,
            } => {
                self.schedule_message(&peer, &body, not_before, now, rng)?;
            }
            Command::GroupSchedule {
                group,
                body,
                not_before,
            } => {
                self.schedule_group_message(&group, &body, not_before, now, rng)?;
            }
            Command::ScheduledEdit {
                id,
                body,
                not_before,
            } => self.edit_scheduled_message(&id, &body, not_before, now, rng)?,
            Command::ScheduledCancel { id } => self.cancel_scheduled_message(&id)?,
            Command::NoteToSelfSend { body } => {
                self.note_to_self_send(&body, now, rng)?;
            }
            Command::AddContact {
                name,
                bundle,
                hints,
            } => {
                self.add_contact(&name, &bundle, &hints, now, rng)?;
            }
            Command::MessageRequestAccept { request, name } => {
                self.accept_message_request(&request, &name, now, rng)?;
            }
            Command::MessageRequestDelete { request } => {
                self.delete_message_request(&request, now, rng)?;
            }
            Command::MessageRequestBlock { request } => {
                self.block_message_request(&request, now, rng)?;
            }
            Command::GroupInvitationAccept { invitation } => {
                self.accept_group_invitation(&invitation, now, rng)?;
            }
            Command::GroupInvitationDelete { invitation } => {
                self.delete_group_invitation(&invitation, rng)?;
            }
            Command::RenameContact {
                peer,
                name,
                accept_warnings,
            } => {
                self.rename_contact(&peer, &name, accept_warnings, rng)?;
            }
            Command::SetHints { peer, hints } => self.set_hints(&peer, &hints, rng)?,
            Command::MarkVerified { peer } => self.mark_verified(&peer, rng)?,
            Command::GroupCreate { name, members } => {
                self.create_group(&name, &members, rng)?;
            }
            Command::GroupSend { group, body } => {
                self.group_send(&group, &body, now, rng)?;
            }
            Command::GroupSendDisappearing {
                group,
                body,
                lifetime_secs,
            } => {
                self.group_send_disappearing_message(&group, &body, lifetime_secs, now, rng)?;
            }
            Command::GroupMentionSend {
                group,
                text,
                spans,
                review_token,
            } => {
                self.group_send_mention(&group, &text, &spans, review_token, now, rng)?;
            }
            Command::GroupAdd { group, peer } => self.group_add(&group, &peer, now, rng)?,
            Command::GroupRemove { group, peer } => self.group_remove(&group, &peer, now, rng)?,
            Command::GroupLeave { group } => self.group_leave(&group, now, rng)?,
            Command::AttachmentAccept { transfer } => {
                self.accept_attachment(&transfer, now, rng)?
            }
            Command::AttachmentReject { transfer } => {
                self.reject_attachment(&transfer, now, rng)?
            }
            Command::AttachmentCancel { transfer } => {
                self.cancel_attachment(&transfer, now, rng)?
            }
            Command::AttachmentPause { transfer } => self.pause_attachment(&transfer, now, rng)?,
            Command::AttachmentResume { transfer } => {
                self.resume_attachment(&transfer, now, rng)?
            }
        }
        Ok(())
    }

    /// Queue a message to a contact. Persists the record as `Queued` before
    /// any crypto runs (nothing is lost on crash), establishes the session
    /// from the stored prekey bundle if this is the first message, and
    /// enqueues the sealed envelope for the next flush. Returns the message
    /// record id.
    pub fn send_message(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
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
        self.send_message_with_id(peer, body, id, now, now, rng)
    }

    /// Queue one immutable edit of this identity's exact canonical pairwise
    /// Text event. The original and every edit remain sealed in history.
    pub fn edit_message(
        &mut self,
        peer: &[u8; 32],
        target_author: [u8; 32],
        target_content_id: [u8; 16],
        text: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let me = self.account.ed;
        if target_author != me || text.is_empty() || text.len() > MAX_EDIT_TEXT_LEN {
            return Err(NodeError::InvalidEdit);
        }
        if !self.peer_has_live_device_sessions(peer)?
            || !self.peer_supports_kind(peer, CONTENT_KIND_EDIT)?
        {
            return Err(NodeError::EditUnsupported);
        }
        let records = self.store.messages_with(peer)?;
        if !records.iter().any(|record| {
            record.direction == Direction::Outbound
                && matches!(
                    decode_content(&record.body),
                    DecodedContent::Text { id, .. } if id == target_content_id
                )
        }) {
            return Err(NodeError::InvalidEdit);
        }
        let mut revisions = records.iter().filter_map(|record| {
            if record.direction != Direction::Outbound {
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
        for value in revisions.by_ref() {
            count += 1;
            revision = revision.max(value);
        }
        if count >= MAX_MESSAGE_EDITS {
            return Err(NodeError::EditLimit);
        }
        revision = revision.checked_add(1).ok_or(NodeError::EditLimit)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let wire = encode_edit(
            id,
            &Edit {
                target_author: me,
                target_content_id,
                revision,
                text,
            },
        )?;
        self.send_message_with_id(peer, &wire, id, now, now, rng)
    }

    /// Queue UTF-8 that is removed from local history at an exact deadline.
    /// The peer must have authenticated support and a live session: an
    /// unnegotiated anonymous first flight is deliberately never ephemeral.
    pub fn send_disappearing_message(
        &mut self,
        peer: &[u8; 32],
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
        if !self.peer_has_live_device_sessions(peer)?
            || !self.peer_supports_kind(peer, CONTENT_KIND_EPHEMERAL)?
        {
            return Err(NodeError::EphemeralUnsupported);
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(NodeError::InvalidEphemeral)?;
        let retention_until = retention_bucket(expires_at)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let payload = encode_disappearing_text_payload(expires_at, text)?;
        let wire = encode_ephemeral(id, &payload)?;
        self.send_message_with_id_retention(
            peer,
            &wire,
            id,
            now,
            now,
            Some(retention_until),
            None,
            rng,
        )
    }

    fn send_message_with_id(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_message_with_id_retention(peer, body, id, timestamp, now, None, None, rng)
    }

    #[allow(clippy::too_many_arguments)] // canonical pair send plus retention/schedule sources
    fn send_message_with_id_retention(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        retention_until: Option<u64>,
        scheduled: Option<&ScheduledMessageRecord>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        // Mention is permanently group-only. Reject a canonical frame before
        // it can enter pairwise history, padding, encryption, or the queue.
        match decode_content(body) {
            DecodedContent::Mention { .. } => return Err(NodeError::InvalidMention),
            DecodedContent::Poll { .. } => return Err(NodeError::InvalidPoll),
            DecodedContent::GroupAuthority { .. } => return Err(NodeError::InvalidGroupAuthority),
            DecodedContent::CallControl { .. } => return Err(NodeError::InvalidCall),
            _ => {}
        }
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if self.store.authority_reset_reverification_required(peer)? {
            return Err(NodeError::ContactReverificationRequired);
        }
        let endpoints = self.store.contact_devices_for(peer)?;
        let mut routes = endpoints;
        if routes.is_empty() {
            routes.push(ContactDeviceRecord {
                account: *peer,
                device: *peer,
                name: None,
                certificate: Vec::new(),
                authority: Vec::new(),
                bundle: contact.bundle.clone(),
                hints: contact.hints.clone(),
                introduction_capability: None,
                introduction_generation: 0,
                manifest_generation: 0,
                manifest_state_id: [0u8; 32],
                last_seen: now,
                revoked_at: None,
                revoked_after_counter: None,
            });
        }
        routes.sort_by_key(|endpoint| endpoint.device);
        routes.dedup_by_key(|endpoint| endpoint.device);
        if routes.len() > kult_store::MAX_PAIRWISE_COMMIT_DEVICES {
            return Err(NodeError::CorruptState);
        }
        if !routes.iter().any(|endpoint| {
            self.sessions.contains_key(&endpoint.device)
                || (!endpoint.bundle.is_empty()
                    && PrekeyBundle::decode(&endpoint.bundle)
                        .and_then(|bundle| bundle.verify(now))
                        .is_ok())
        }) {
            return Err(NodeError::NoSession);
        }

        // The anonymous first flight is always legacy text. Once a live
        // session has authenticated v1 Text support, reuse the record id as
        // the framed content id and retain those exact bytes in history.
        let wire_body = if core::str::from_utf8(body).is_ok() && self.peer_supports_text(peer)? {
            encode_text(id, core::str::from_utf8(body).expect("checked above"))?
        } else {
            body.to_vec()
        };
        let mut record = MessageRecord {
            id,
            peer: *peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp,
            body: wire_body.clone(),
            wire_id: None,
        };
        let padded = pad(&wire_body)?;
        let mut prepared = Vec::new();
        let mut deliveries = Vec::with_capacity(routes.len());
        for endpoint in &routes {
            let route = endpoint.device;
            let route_state = if let Some(before) = self.sessions.get(&route).cloned() {
                let mut after = before.clone();
                let msg = self.candidate_encrypt(&mut after, rng, now, &padded)?;
                let token = delivery_token(
                    &MailboxKey::from_bytes(*after.mailbox_key()),
                    epoch_day(now),
                    &route,
                );
                let envelope = match retention_until {
                    Some(deadline) => Envelope::new_retained(
                        EnvelopeKind::Message,
                        token,
                        deadline,
                        msg.encode(),
                    )?,
                    None => Envelope::new(EnvelopeKind::Message, token, msg.encode()),
                };
                Some(PreparedPairwiseRoute {
                    route,
                    before: Some(before),
                    after,
                    envelope,
                    resets_capabilities: false,
                })
            } else if retention_until.is_some()
                || endpoint.bundle.is_empty()
                || PrekeyBundle::decode(&endpoint.bundle)
                    .and_then(|bundle| bundle.verify(now))
                    .is_err()
            {
                None
            } else {
                let (after, envelope) =
                    self.prepare_session(peer, &route, &endpoint.bundle, &padded, now, rng)?;
                Some(PreparedPairwiseRoute {
                    route,
                    before: None,
                    after,
                    envelope,
                    resets_capabilities: true,
                })
            };
            let wire_id = route_state
                .as_ref()
                .map(|prepared| prepared.envelope.content_id());
            if record.wire_id.is_none() {
                record.wire_id = wire_id;
            }
            deliveries.push(MessageDeviceDeliveryRecord {
                message: id,
                account: *peer,
                device: route,
                wire_id,
                state: DeliveryState::Queued,
            });
            if let Some(route_state) = route_state {
                prepared.push(route_state);
            }
        }
        if prepared.is_empty() {
            return Err(if retention_until.is_some() {
                NodeError::EphemeralUnsupported
            } else {
                NodeError::NoSession
            });
        }
        let queue = prepared
            .iter()
            .map(|prepared| QueueItem {
                peer: prepared.route,
                msg_id: Some(id),
                group_msg_id: None,
                class: QueueClass::Interactive,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope: prepared.envelope.clone(),
            })
            .collect::<Vec<_>>();
        let transitions = prepared
            .iter()
            .map(|prepared| SessionTransition {
                peer_device: prepared.route,
                before: prepared.before.as_ref(),
                after: &prepared.after,
            })
            .collect::<Vec<_>>();
        let clear_capabilities = prepared
            .iter()
            .filter(|prepared| prepared.resets_capabilities)
            .map(|prepared| prepared.route)
            .collect::<Vec<_>>();
        let prepared_routes = prepared
            .iter()
            .map(|prepared| prepared.route)
            .collect::<HashSet<_>>();
        let clear_reset_markers = self
            .store
            .reset_markers()?
            .into_iter()
            .filter(|marker| marker == peer || prepared_routes.contains(marker))
            .collect::<Vec<_>>();
        let ephemeral = match decode_content(&wire_body) {
            DecodedContent::Ephemeral {
                id: content_id,
                ephemeral: Ephemeral::DisappearingText { expires_at, .. },
            } => Some(EphemeralRecord {
                conversation: EphemeralConversation::Pairwise(*peer),
                author: self.account.ed,
                content_id,
                expires_at,
                mode: EphemeralMode::DisappearingText,
                state: EphemeralState::Active,
                transfer_ids: Vec::new(),
            }),
            _ => None,
        };
        let receipt = self.store.commit_plan(
            CommitPlan::PairwiseSend(PairwiseSendPlan {
                sessions: &transitions,
                message: Some(&record),
                message_update: None,
                deliveries: &deliveries,
                delivery_updates: &[],
                queue: &queue,
                groups: &[],
                authorities: &[],
                scheduled,
                clear_capabilities: &clear_capabilities,
                clear_reset_markers: &clear_reset_markers,
                ephemeral: ephemeral.as_ref(),
                media_transfers: &[],
                media_objects: &[],
                delete_controls: &[],
                wake: &[],
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        for route in prepared {
            self.sessions.insert(route.route, route.after);
            if route.resets_capabilities {
                self.capabilities_advertised.remove(&route.route);
                self.discovery_advertised.remove(&route.route);
                self.rendezvous_advertised.remove(&route.route);
                self.rendezvous_refresh_requested.insert(route.route);
            }
        }
        self.after_memory_replacement()?;
        let mut events = vec![Event::DeliveryUpdated {
            id,
            state: DeliveryState::Queued,
        }];
        if scheduled.is_some() {
            events.push(Event::ScheduledMessageActivated { id });
        }
        self.accept_commit_receipt(receipt, events);
        Ok(id)
    }

    /// Persist pairwise text until `not_before` UTC. No ratchet, envelope,
    /// queue, or transport state is touched before activation.
    pub fn schedule_message(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if !self.peer_has_session_or_bundle(peer)? {
            return Err(NodeError::NoSession);
        }
        self.schedule(
            StoreScheduledConversation::Peer(*peer),
            body,
            not_before,
            now,
            rng,
        )
    }

    /// Persist group text until `not_before` UTC without advancing the
    /// sender chain or creating member copies early.
    pub fn schedule_group_message(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.schedule(
            StoreScheduledConversation::Group(*group),
            body,
            not_before,
            now,
            rng,
        )
    }

    fn schedule(
        &mut self,
        conversation: StoreScheduledConversation,
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if not_before <= now || core::str::from_utf8(body).is_err() || pad(body).is_err() {
            return Err(NodeError::InvalidSchedule);
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.store.put_scheduled_message(
            &ScheduledMessageRecord {
                id,
                conversation,
                created_at: now,
                not_before,
                body: body.to_vec(),
            },
            rng,
        )?;
        self.events.push_back(Event::ScheduledMessageUpdated { id });
        Ok(id)
    }

    /// Replace a scheduled message's body and UTC instant. Once activation
    /// begins the scheduled row is gone and edits fail explicitly.
    pub fn edit_scheduled_message(
        &mut self,
        id: &[u8; 16],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if not_before <= now || core::str::from_utf8(body).is_err() || pad(body).is_err() {
            return Err(NodeError::InvalidSchedule);
        }
        let mut record = self
            .store
            .get_scheduled_message(id)?
            .ok_or(NodeError::UnknownScheduledMessage)?;
        record.body = body.to_vec();
        record.not_before = not_before;
        if !self.store.update_scheduled_message(&record, rng)? {
            return Err(NodeError::UnknownScheduledMessage);
        }
        self.events
            .push_back(Event::ScheduledMessageUpdated { id: *id });
        Ok(())
    }

    /// Cancel a scheduled message before its activation instant.
    pub fn cancel_scheduled_message(&mut self, id: &[u8; 16]) -> Result<()> {
        if !self.store.delete_scheduled_message(id)? {
            return Err(NodeError::UnknownScheduledMessage);
        }
        self.events
            .push_back(Event::ScheduledMessageCancelled { id: *id });
        Ok(())
    }

    /// Append UTF-8 text to the one reserved local note-to-self
    /// conversation. This path creates no contact, session, envelope,
    /// receipt, delivery state, queue item, or transport work.
    pub fn note_to_self_send(
        &mut self,
        body: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if self
            .store
            .get_local_metadata(&LocalMetadataKey::Conversation(ConversationId::NoteToSelf))?
            .is_none()
        {
            self.store.put_local_metadata(
                &LocalMetadataRecord::Conversation(ConversationMetadata {
                    conversation: ConversationId::NoteToSelf,
                    created_at: now,
                }),
                rng,
            )?;
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let record = NoteMessageRecord {
            id,
            timestamp: now,
            body: body.to_owned(),
        };
        self.store.put_note_message(&record, rng)?;
        self.events.push_back(Event::NoteToSelfMessageAdded {
            id,
            timestamp: now,
            body: body.to_owned(),
        });
        Ok(id)
    }

    /// Events emitted since the last drain (also returned by [`Node::tick`]).
    pub fn drain_events(&mut self) -> Vec<Event> {
        #[cfg(feature = "test-failpoints")]
        if self
            .check_transition_failpoint(TransitionFailpoint::BeforeEventDelivery)
            .is_err()
        {
            return Vec::new();
        }
        let events = self.events.drain(..).collect::<Vec<_>>();
        if !events.is_empty() {
            self.delivered_presentation_marker = self.presentation_marker;
        }
        #[cfg(feature = "test-failpoints")]
        let _ = self.check_transition_failpoint(TransitionFailpoint::AfterEventDelivery);
        events
    }

    fn accept_commit_receipt(
        &mut self,
        receipt: CommitReceipt,
        events: impl IntoIterator<Item = Event>,
    ) {
        if let Some(marker) = receipt.presentation_marker {
            self.presentation_marker = Some(marker);
        }
        self.events.extend(events);
    }

    fn acknowledge_presentation(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        let Some(delivered) = self.delivered_presentation_marker.take() else {
            return Ok(());
        };
        match self.store.presentation_resync_marker()? {
            Some(current) if current == delivered => {
                self.store.commit_plan(
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
                        delete_controls: &[],
                        wake: &[],
                        acknowledge_presentation: Some(delivered),
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                if self.presentation_marker == Some(delivered) {
                    self.presentation_marker = None;
                }
            }
            Some(current) => {
                self.presentation_marker = Some(current);
            }
            None => {
                self.presentation_marker = None;
            }
        }
        Ok(())
    }

    // ---- the heartbeat -----------------------------------------------------

    /// Run one platform-deadline-bounded native-wake collection pass.
    ///
    /// Only immediate non-airtime carriers are drained. Accepted envelopes
    /// use the ordinary deduplication, ratchet, persistence, and receipt
    /// paths, but this pass never flushes messages, floods a mesh, exports
    /// sneakernet work, activates attachments, or starts calls.
    pub async fn wake_tick(
        &mut self,
        now: u64,
        platform_budget: Duration,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Event>> {
        if platform_budget.is_zero() || self.wake_collection_deadline.is_some() {
            return Err(NodeError::WakeUnavailable);
        }
        self.wake_collection_deadline =
            Some(Instant::now() + platform_budget.min(MAX_WAKE_COLLECTION_DURATION));
        let result = self.tick(now, rng).await;
        self.wake_collection_deadline = None;
        result
    }

    /// Run one ordinary receive, maintenance, and outbound flush cycle.
    pub async fn tick(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<Event>> {
        let wake_collection = self.wake_collection_deadline.is_some();
        self.admission_puzzles_remaining =
            usize::from(!wake_collection) * MAX_ADMISSION_PUZZLES_PER_TICK;
        self.admission_kems_remaining = usize::from(!wake_collection) * MAX_ADMISSION_KEMS_PER_TICK;
        self.admission_notifications_remaining =
            usize::from(!wake_collection) * MAX_ADMISSION_NOTIFICATIONS_PER_TICK;
        self.admission_carrier_remaining = if wake_collection {
            [0; ADMISSION_CARRIER_CLASS_COUNT]
        } else {
            MAX_ADMISSION_CANDIDATES_PER_CARRIER
        };
        self.admission_deadline = None;
        if !wake_collection {
            self.acknowledge_presentation(rng)?;
            self.apply_resolved_device_sync(rng)?;
            self.sweep_admission(now, rng)?;
            if !self.media_reconciled {
                let batch = self
                    .store
                    .prepare_media_reconciliation(MAX_MAINTENANCE_TRANSITIONS)?;
                if batch.transitions.is_empty() {
                    self.store
                        .finish_media_reconciliation(batch.unknown_records)?;
                    self.media_reconciled = batch.complete;
                } else {
                    let object_transitions = batch
                        .transitions
                        .iter()
                        .map(|(before, after)| MediaObjectTransition { before, after })
                        .collect::<Vec<_>>();
                    let receipt = self.store.commit_plan(
                        CommitPlan::AttachmentState(AttachmentStatePlan {
                            media_transfers: &[],
                            media_objects: &object_transitions,
                            delete_controls: &[],
                            presentation_changed: true,
                        }),
                        rng,
                    )?;
                    let transfers = batch
                        .transitions
                        .iter()
                        .map(|(_, after)| after.transfer_id)
                        .collect::<HashSet<_>>();
                    self.accept_commit_receipt(receipt, []);
                    for transfer in transfers {
                        self.emit_attachment_update(&transfer)?;
                    }
                    if batch.complete {
                        self.store
                            .finish_media_reconciliation(batch.unknown_records)?;
                        self.media_reconciled = true;
                    }
                }
            }
            self.apply_deferred_controls(now, rng)?;
            // Expiry is core-owned and runs before any queue activation, receive,
            // attachment request, or transport flush. A restart and a clock jump
            // therefore cannot revive or transmit already-expired plaintext.
            self.sweep_ephemeral(now, rng)?;
            if now >= self.next_delivery_sweep {
                self.sweep_failed_deliveries(now, rng)?;
                self.next_delivery_sweep = now.saturating_add(DELIVERY_SWEEP_INTERVAL_SECS);
            }
            self.sweep_calls(now, rng)?;
            // 0. Session-reset markers (a restore happened): queue fresh
            //    handshakes so re-keyed traffic flows without waiting for the
            //    user to send first.
            self.rekey_reset_peers(now, rng)?;
            // A legacy pairwise session can authenticate the provider upgrade but
            // cannot safely synthesize a transcript exporter. Exactly one side,
            // selected by physical-device id ordering, starts a fresh verified
            // PQXDH exchange and replaces the session plus optional service state
            // in one commit.
            self.process_rendezvous_rehandshakes(now, rng)?;
            // A manifest can advertise an active endpoint before its prekey bundle
            // or session arrives. Ordinary sends retain an honest per-device
            // `Queued` row; once that route becomes usable, materialize the exact
            // pending copy instead of leaving the placeholder stuck forever.
            self.queue_pending_pairwise_device_deliveries(now, rng)?;

            // Absolute UTC scheduling is enforced in core before encryption:
            // clock rollback keeps entries held, clock advance activates them on
            // this tick, and a restart simply reloads the same sealed records.
            self.activate_scheduled_messages(now, rng)?;

            // Loaded and newly-created sessions advertise on the first tick.
            // Controls use the durable queue and are terminal like receipts.
            self.advertise_capabilities(now, rng)?;
            self.advertise_discovery_upgrades(now, rng)?;
            self.advertise_rendezvous_providers(now, rng)?;
            self.maintain_rendezvous(now, rng).await?;
            self.admission_deadline = Some(Instant::now() + MAX_ADMISSION_TIME_PER_TICK);
        }

        // 1. Gather: previously-stashed envelopes first, then fresh arrivals.
        //    Every complete fresh envelope is staged under a stable pending
        //    row before parsing or cryptographic work. Top-level fragments are
        //    the bounded exception: no ratchet state advances while assembling
        //    them, and the completed inner envelope is staged before it can be
        //    deferred. Refused assembly therefore leaves every fragment unseen
        //    and carrier retry remains lossless.
        //    When bridging, fresh arrivals with tokens this node does not
        //    recognize also enter the transit queue (ADR-0009): mesh-heard
        //    foreignness heads for the internet, carrier-surfaced transit
        //    (bridge mailbox deposits) heads for the mesh. Every arrival
        //    still joins the normal receive path — "foreign" and "ours, but
        //    the unlocking handshake hasn't arrived yet" are indistinguishable
        //    by design, and downstream dedup absorbs the overlap.
        let mut work: Vec<(Option<i64>, Envelope, u64, AdmissionTransportClass)> = Vec::new();
        let mut gathered = HashSet::new();
        let mut durable_gathered = HashSet::new();
        let mut redundant_pending = Vec::new();
        let work_limit = if wake_collection {
            MAX_WAKE_PENDING_WORK_PER_TICK
        } else {
            MAX_PENDING_WORK_PER_TICK
        };
        let mut work_bytes = 0usize;
        for (sequence, envelope, first_seen, transport) in self
            .store
            .pending_all_with_transport()?
            .into_iter()
            .take(work_limit)
        {
            let encoded_len = envelope.try_encode()?.len();
            if wake_collection
                && work_bytes
                    .checked_add(encoded_len)
                    .is_none_or(|bytes| bytes > MAX_WAKE_COLLECTION_BYTES)
            {
                break;
            }
            if gathered.insert(envelope.content_id()) {
                durable_gathered.insert(envelope.content_id());
                work_bytes += encoded_len;
                work.push((Some(sequence), envelope, first_seen, transport));
            } else {
                durable_gathered.insert(envelope.content_id());
                redundant_pending.push(PendingDelete {
                    sequence,
                    content_id: envelope.content_id(),
                });
            }
        }
        if !redundant_pending.is_empty() {
            self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &[],
                    delete_pending: &redundant_pending,
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
                    delete_controls: &[],
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }
        let mut bridge_seen = HashSet::new();
        let mut fresh_fragments = 0usize;
        let transports = self.transports.clone();
        for transport in &transports {
            let profile = transport.profile();
            let airtime = profile.cost == CostClass::Airtime;
            if wake_collection
                && (airtime || profile.latency == kult_transport::LatencyClass::HumanScale)
            {
                continue;
            }
            let envelopes_result = if let Some(deadline) = self.wake_collection_deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let Some(result) = before_timeout(remaining, transport.recv_staged()).await else {
                    break;
                };
                result
            } else {
                transport.recv_staged().await
            };
            // A dead link must not stall the others; its envelopes will
            // arrive via retry or another path.
            if let Ok(envelopes) = envelopes_result {
                for ReceivedEnvelope {
                    envelope,
                    receipt,
                    ingress,
                } in envelopes
                {
                    let encoded_len = envelope.try_encode()?.len();
                    let content_id = envelope.content_id();
                    let transport_class = admission_transport(ingress);
                    if airtime
                        && !wake_collection
                        && self.bridge.is_some()
                        && !self.token_is_mine(&envelope.token, now)
                        && bridge_seen.insert((true, content_id))
                    {
                        if let Some(bridge) = &mut self.bridge {
                            bridge.admit(&envelope, true, now);
                        }
                    }
                    if !gathered.insert(content_id) {
                        if let Some(receipt) = receipt {
                            // ADR-0030 makes duplicate introductions a
                            // uniform refusal even when their original copy
                            // was staged successfully. Do not let generic
                            // multipath dedup reveal whether a request row
                            // exists or has spare capacity.
                            let duplicate_admission = ingress == IngressClass::Direct
                                && envelope.kind == EnvelopeKind::Handshake
                                && AdmissionEnvelope::is_encoded(&envelope.body);
                            let accepted = !duplicate_admission
                                && (durable_gathered.contains(&content_id)
                                    || self.store.is_seen(&content_id)?);
                            let _ = transport.settle_recv(receipt, accepted).await;
                        }
                        continue;
                    }
                    if envelope.kind == EnvelopeKind::Fragment {
                        if let Some(receipt) = receipt {
                            let _ = transport.settle_recv(receipt, false).await;
                        }
                        if fresh_fragments < work_limit
                            && (!wake_collection
                                || work_bytes
                                    .checked_add(encoded_len)
                                    .is_some_and(|bytes| bytes <= MAX_WAKE_COLLECTION_BYTES))
                        {
                            fresh_fragments += 1;
                            work_bytes += encoded_len;
                            work.push((None, envelope, now, transport_class));
                        }
                        continue;
                    }
                    if receipt.is_some()
                        && ingress == IngressClass::Direct
                        && envelope.kind == EnvelopeKind::Handshake
                        && AdmissionEnvelope::is_encoded(&envelope.body)
                    {
                        if wake_collection {
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, false).await;
                            }
                            continue;
                        }
                        // Seen introductions are duplicates or permanent
                        // failures. Both receive the same bounded refusal and
                        // neither is allowed back into the KEM path.
                        if self.store.is_seen(&content_id)? {
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, false).await;
                            }
                            continue;
                        }
                        let mut established = false;
                        let outcome = self.consume(
                            &envelope,
                            ConsumeOrigin {
                                depth: 0,
                                pending_sequence: None,
                                transport: transport_class,
                            },
                            now,
                            rng,
                            &mut established,
                        );
                        let accepted = match outcome {
                            Ok(Consumed::Done | Consumed::DoneAtomic) => true,
                            Ok(Consumed::RejectedAtomic | Consumed::Later) => false,
                            Err(error) => {
                                if let Some(receipt) = receipt {
                                    let _ = transport.settle_recv(receipt, false).await;
                                }
                                return Err(error);
                            }
                        };
                        if self.store.is_seen(&content_id)? {
                            durable_gathered.insert(content_id);
                        }
                        if let Some(receipt) = receipt {
                            let _ = transport.settle_recv(receipt, accepted).await;
                        }
                        continue;
                    }
                    if wake_collection
                        && work_bytes
                            .checked_add(encoded_len)
                            .is_none_or(|bytes| bytes > MAX_WAKE_COLLECTION_BYTES)
                    {
                        if let Some(receipt) = receipt {
                            let _ = transport.settle_recv(receipt, false).await;
                        }
                        continue;
                    }
                    match self.store.commit_plan(
                        CommitPlan::PendingStage(PendingStagePlan {
                            envelope: &envelope,
                            first_seen: now,
                            transport: transport_class,
                        }),
                        rng,
                    ) {
                        Ok(committed) if work.len() < work_limit => {
                            let sequence = committed
                                .records
                                .pending_sequences
                                .first()
                                .copied()
                                .ok_or(NodeError::CorruptState)?;
                            durable_gathered.insert(content_id);
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, true).await;
                            }
                            work_bytes += encoded_len;
                            work.push((Some(sequence), envelope, now, transport_class));
                        }
                        Ok(committed) => {
                            if committed.records.pending_sequences.len() != 1 {
                                return Err(NodeError::CorruptState);
                            }
                            durable_gathered.insert(content_id);
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, true).await;
                            }
                        }
                        Err(kult_store::StoreError::PendingQuota) => {
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, false).await;
                            }
                        }
                        Err(error) => {
                            if let Some(receipt) = receipt {
                                let _ = transport.settle_recv(receipt, false).await;
                            }
                            return Err(error.into());
                        }
                    }
                }
            }
            if !wake_collection && self.bridge.is_some() {
                if let Ok(envelopes) = transport.recv_transit().await {
                    for envelope in envelopes {
                        let content_id = envelope.content_id();
                        if !self.token_is_mine(&envelope.token, now)
                            && bridge_seen.insert((false, content_id))
                        {
                            if let Some(bridge) = &mut self.bridge {
                                bridge.admit(&envelope, false, now);
                            }
                        }
                        if !gathered.insert(content_id) {
                            continue;
                        }
                        if envelope.kind == EnvelopeKind::Fragment {
                            if fresh_fragments < work_limit {
                                fresh_fragments += 1;
                                work.push((None, envelope, now, AdmissionTransportClass::Bridge));
                            }
                            continue;
                        }
                        match self.store.pending_push_with_transport(
                            &envelope,
                            now,
                            AdmissionTransportClass::Bridge,
                            rng,
                        ) {
                            Ok(sequence) if work.len() < work_limit => {
                                work.push((
                                    Some(sequence),
                                    envelope,
                                    now,
                                    AdmissionTransportClass::Bridge,
                                ));
                            }
                            Ok(_) | Err(kult_store::StoreError::PendingQuota) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
        }

        let mut expired_seen = Vec::new();
        let mut expired_pending = Vec::new();
        work.retain(|(pending_sequence, env, first_seen, _)| {
            let expired = now.saturating_sub(*first_seen) > PENDING_TTL_SECS
                || env.retention_until.is_some_and(|deadline| deadline <= now);
            if expired {
                let content_id = env.content_id();
                expired_seen.push(content_id);
                if let Some(sequence) = pending_sequence {
                    expired_pending.push(PendingDelete {
                        sequence: *sequence,
                        content_id,
                    });
                }
            }
            !expired
        });
        if !expired_seen.is_empty() {
            self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &expired_seen,
                    delete_pending: &expired_pending,
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
                    delete_controls: &[],
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }

        // 2. Consume, re-running over the stash whenever a new session was
        //    established (a handshake later in the batch can unlock messages
        //    earlier in it). Each pass consumes at least one envelope, so
        //    this terminates.
        let mut pending_acks: Vec<PendingDelete> = Vec::new();
        loop {
            let mut stash = Vec::new();
            let mut established = false;
            for (pending_sequence, env, first_seen, transport) in work {
                if self
                    .wake_collection_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    break;
                }
                match self.consume(
                    &env,
                    ConsumeOrigin {
                        depth: 0,
                        pending_sequence,
                        transport,
                    },
                    now,
                    rng,
                    &mut established,
                )? {
                    Consumed::Done => {
                        if let Some(sequence) = pending_sequence {
                            // Keep the row until receipts and other durable
                            // consequences of this receive pass are queued.
                            // Any intervening error can then safely replay it
                            // through the seen-envelope path.
                            pending_acks.push(PendingDelete {
                                sequence,
                                content_id: env.content_id(),
                            });
                        }
                    }
                    Consumed::DoneAtomic => {}
                    Consumed::RejectedAtomic => {}
                    Consumed::Later => {
                        let sequence = match pending_sequence {
                            Some(sequence) => sequence,
                            None => match self
                                .store
                                .pending_push_with_transport(&env, first_seen, transport, rng)
                            {
                                Ok(sequence) => sequence,
                                Err(kult_store::StoreError::PendingQuota) => {
                                    // Interim overload containment. The
                                    // interactive admission protocol in
                                    // ADR-0030 must move this refusal before
                                    // the carrier's accepted response.
                                    continue;
                                }
                                Err(error) => return Err(error.into()),
                            },
                        };
                        stash.push((Some(sequence), env, first_seen, transport));
                    }
                }
            }
            if !stash.is_empty()
                && (established || (!wake_collection && self.apply_deferred_controls(now, rng)?))
            {
                work = stash;
                continue;
            }
            // Every entry in `stash` is already durable. Leaving it in place
            // is the retry action; no delete/reinsert cycle or new sequence
            // number is needed.
            break;
        }

        if !wake_collection {
            // Accepted authenticated controls are durable before their follow-up
            // work runs. A second bounded pass lets same-tick attachment windows
            // advance without coupling filesystem or group work to ratchet commit.
            self.apply_deferred_controls(now, rng)?;

            // 2b. Group upkeep (ADR-0012): flush due announces (initiating
            //     pairwise sessions where possible) and serve late fan-out to
            //     members whose session appeared after a group send.
            self.tick_groups(now, rng).await?;

            // 2c. Publish one authoritative, expiring carrier verdict per peer.
            //     Attachment activation consumes this exact snapshot rather than
            //     independently inferring capacity from a route.
            self.refresh_carrier_capabilities(now, rng).await?;

            // 2d. Attachment offers and resumable missing-range requests activate
            //     only under a fresh F4 bulk-capable verdict.
            self.activate_attachment_transfers(now, rng).await?;

            // 3. NACK the missing fragment indices of stale
            //    partials (selective retransmission, docs/05-transports.md §4.2
            //    rule 2). Accepted messages already own their encrypted receipt
            //    and duplicate-replay route inside the receive commit plan.
            let mut nacks_by_peer: BTreeMap<[u8; 32], FragNacks> = BTreeMap::new();
            for (id, missing) in self.stale_partials(now) {
                // The fragment's delivery token names the session to ask.
                // Handshake fragments never match one — correctly so: with no
                // session there is nothing to encrypt a receipt under.
                let Some(token) = self.frag_meta.get(&id).map(|m| m.token) else {
                    continue;
                };
                let Some(peer) = self.match_session(&token, now) else {
                    continue;
                };
                if let Some(meta) = self.frag_meta.get_mut(&id) {
                    meta.last_nack = Some(now);
                }
                nacks_by_peer.entry(peer).or_default().push((id, missing));
            }
            for peer in nacks_by_peer.keys().copied().collect::<Vec<_>>() {
                let nacks = nacks_by_peer.remove(&peer).unwrap_or_default();
                self.queue_receipt(&peer, Vec::new(), nacks, now, rng)?;
            }
        }
        if !pending_acks.is_empty() {
            self.store.commit_plan(
                CommitPlan::Maintenance(MaintenancePlan {
                    seen: &[],
                    delete_pending: &pending_acks,
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
                    delete_controls: &[],
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }

        // 4. Flush the outbound queue, then — only with whatever airtime and
        //    attention is left — third-party transit (ADR-0009).
        if wake_collection {
            for (_, item) in self
                .store
                .queue_all()?
                .into_iter()
                .take(MAX_RENDEZVOUS_OPERATIONS_PER_TICK)
            {
                self.rendezvous_refresh_requested.insert(item.peer);
            }
            if let Some(deadline) = self.wake_collection_deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    if let Some(result) =
                        before_timeout(remaining, self.maintain_rendezvous(now, rng)).await
                    {
                        result?;
                    }
                }
            }
            return Ok(self.drain_events());
        }
        self.flush(now, rng).await?;
        self.maintain_wake(now, rng).await?;
        self.flush_transit(now).await;

        Ok(self.drain_events())
    }

    /// Retire outbound work that has gone a full month without an encrypted
    /// end-to-end receipt. History is retained with an explicit terminal
    /// state, while sealed envelopes and per-device copies stop consuming
    /// queue, discovery, and transport resources.
    fn sweep_failed_deliveries(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let cutoff = now.saturating_sub(DELIVERY_EXPIRY_SECS);
        let delete_replay = self
            .store
            .expired_receipt_replay_ids(cutoff, MAX_MAINTENANCE_REPLAY_ROWS_PER_TICK)?;
        let queue_snapshot = self.store.queue_all()?;
        let mut message_pairs = Vec::new();
        let mut delivery_pairs = Vec::new();
        let mut group_message_pairs = Vec::new();
        let mut delete_queue = Vec::new();
        let mut events = Vec::new();
        let mut selected_messages = HashSet::new();
        for contact in self.store.contacts()? {
            for before_message in self.store.messages_with(&contact.peer)? {
                if selected_messages.len() == MAX_MAINTENANCE_MESSAGES_PER_TICK {
                    break;
                }
                if before_message.direction != Direction::Outbound
                    || before_message.timestamp > cutoff
                {
                    continue;
                }
                selected_messages.insert(before_message.id);
                let deliveries = self.store.message_device_deliveries(&before_message.id)?;
                let delivered = deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Delivered);
                for before_delivery in deliveries {
                    if !matches!(
                        before_delivery.state,
                        DeliveryState::Delivered | DeliveryState::Failed
                    ) {
                        let mut after_delivery = before_delivery.clone();
                        after_delivery.state = DeliveryState::Failed;
                        delivery_pairs.push((before_delivery, after_delivery));
                    }
                }
                if !delivered
                    && !matches!(
                        before_message.state,
                        DeliveryState::Delivered | DeliveryState::Failed
                    )
                {
                    let mut after_message = before_message.clone();
                    after_message.state = DeliveryState::Failed;
                    events.push(Event::DeliveryUpdated {
                        id: before_message.id,
                        state: DeliveryState::Failed,
                    });
                    message_pairs.push((before_message, after_message));
                }
            }
            if selected_messages.len() == MAX_MAINTENANCE_MESSAGES_PER_TICK {
                break;
            }
        }

        for before_message in self.store.all_group_messages()? {
            if selected_messages.len() == MAX_MAINTENANCE_MESSAGES_PER_TICK {
                break;
            }
            if before_message.direction != Direction::Outbound || before_message.timestamp > cutoff
            {
                continue;
            }
            selected_messages.insert(before_message.id);
            let mut after_message = before_message.clone();
            let mut changed = false;
            for delivery in &mut after_message.deliveries {
                if !matches!(
                    delivery.state,
                    DeliveryState::Delivered | DeliveryState::Failed
                ) {
                    delivery.state = DeliveryState::Failed;
                    changed = true;
                    events.push(Event::GroupDeliveryUpdated {
                        id: before_message.id,
                        peer: delivery.peer,
                        state: DeliveryState::Failed,
                    });
                }
            }
            for before_delivery in self.store.message_device_deliveries(&before_message.id)? {
                if !matches!(
                    before_delivery.state,
                    DeliveryState::Delivered | DeliveryState::Failed
                ) {
                    let mut after_delivery = before_delivery.clone();
                    after_delivery.state = DeliveryState::Failed;
                    delivery_pairs.push((before_delivery, after_delivery));
                }
            }
            if changed {
                after_message.wire_body = None;
                group_message_pairs.push((before_message, after_message));
            }
        }

        for (sequence, item) in queue_snapshot {
            let selected_history = item
                .msg_id
                .or(item.group_msg_id)
                .is_some_and(|id| selected_messages.contains(&id));
            let expired_control = item.msg_id.is_none()
                && item.group_msg_id.is_none()
                && item.created_at != 0
                && item.created_at <= cutoff;
            if (selected_history || expired_control)
                && delete_queue.len() < MAX_MAINTENANCE_QUEUE_ROWS_PER_TICK
            {
                delete_queue.push(QueueDelete {
                    sequence,
                    content_id: item.envelope.content_id(),
                });
            }
        }
        let message_transitions = message_pairs
            .iter()
            .map(|(before, after)| MessageTransition { before, after })
            .collect::<Vec<_>>();
        let delivery_transitions = delivery_pairs
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let group_message_transitions = group_message_pairs
            .iter()
            .map(|(before, after)| GroupMessageTransition { before, after })
            .collect::<Vec<_>>();
        if delete_replay.is_empty()
            && delete_queue.is_empty()
            && message_transitions.is_empty()
            && delivery_transitions.is_empty()
            && group_message_transitions.is_empty()
        {
            return Ok(());
        }
        let receipt = self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[],
                delete_pending: &[],
                delete_queue: &delete_queue,
                update_queue: &[],
                delete_replay: &delete_replay,
                messages: &message_transitions,
                deliveries: &delivery_transitions,
                group_messages: &group_message_transitions,
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
                presentation_changed: !events.is_empty(),
            }),
            rng,
        )?;
        let deleted = delete_queue
            .iter()
            .map(|delete| delete.sequence)
            .collect::<HashSet<_>>();
        self.held_notified
            .retain(|sequence| !deleted.contains(sequence));
        self.call_queue_deadlines
            .retain(|sequence, _| !deleted.contains(sequence));
        self.accept_commit_receipt(receipt, events);
        Ok(())
    }

    fn prepare_session(
        &self,
        account: &[u8; 32],
        device: &[u8; 32],
        bundle_bytes: &[u8],
        padded: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Session, Envelope)> {
        let target_bundle = PrekeyBundle::decode(bundle_bytes)?;
        let admission = target_bundle.verify_admission(now).ok();
        let mut bundle = target_bundle.verify(now)?;
        let reset_markers = self.store.reset_markers()?;
        let resetting = reset_markers.contains(account) || reset_markers.contains(device);
        let prior_session = self.store.get_session(device)?;
        let intent = if resetting {
            DeviceHandshakeIntent::Reset
        } else if let Some(prior) = prior_session.as_ref() {
            DeviceHandshakeIntent::Replace {
                prior_session_id: *prior.session_id(),
            }
        } else {
            DeviceHandshakeIntent::Establish
        };
        if resetting {
            bundle = bundle.without_opk();
        }
        let step = self.begin_crypto_step()?;
        let initiated = initiate(&self.device_identity, &bundle, padded, now, rng);
        self.finish_crypto_step(step)?;
        let (session, init) = initiated?;
        let mut return_prekey = PrekeyBundle::build(
            &self.device_identity,
            &self.vault.spk(),
            &self.vault.pqspk()?,
            None,
            now + BUNDLE_TTL_SECS,
            encode_hints(&self.own_hints),
        );
        return_prekey.attach_admission(
            &self.device_identity,
            now,
            AdmissionPolicy::default(),
            None,
        )?;
        let return_bundle = DevicePrekeyBundle::new(
            self.device_state.local_certificate.clone(),
            self.device_state.manifest.clone(),
            return_prekey,
        )?
        .encode()?;
        let initial_bytes = encode_device_initial(&DeviceInitialFlight {
            initial: init.encode(),
            return_bundle,
            intent,
        })?;
        let step = self.begin_crypto_step()?;
        let sealed = seal_anonymous(&bundle.bundle().identity, HS_AD, &initial_bytes, rng);
        self.finish_crypto_step(step)?;
        let body = if let Some(admission) = admission {
            if sealed.len()
                > usize::try_from(admission.descriptor.max_first_ciphertext)
                    .map_err(|_| NodeError::CorruptState)?
            {
                return Err(NodeError::Protocol(kult_protocol::ProtocolError::TooLarge));
            }
            let context = AdmissionContext {
                target_account: *account,
                target_device: *device,
                bundle_digest: admission.descriptor.bundle_digest,
                validity_epoch: admission.descriptor.validity_epoch,
            };
            let use_invitation = admission.invitation.filter(|_| !resetting);
            let mut wrapped = AdmissionEnvelope::new(
                context,
                if use_invitation.is_some() {
                    AdmissionProofKind::Invitation
                } else {
                    AdmissionProofKind::Puzzle
                },
                [0u8; 32],
                target_bundle.without_invitation_capability().encode(),
                sealed,
            )?;
            wrapped.proof = if let Some(invitation) = use_invitation {
                admission_invitation_proof(&invitation, &wrapped.context, &wrapped.content_id)
            } else {
                solve_admission_puzzle(
                    &wrapped.context,
                    &wrapped.content_id,
                    admission.descriptor.difficulty,
                    MAX_ADMISSION_PUZZLE_ATTEMPTS,
                    rng,
                )?
            };
            wrapped.encode()?
        } else {
            // Existing Alpha contacts may still complete an authenticated
            // legacy re-handshake. Unknown legacy senders are rejected before
            // ML-KEM by the receiver and must exchange a current invitation.
            sealed
        };
        let introduction_capability = self
            .store
            .contact_devices_for(account)?
            .into_iter()
            .find(|endpoint| endpoint.device == *device)
            .and_then(|endpoint| endpoint.introduction_capability);
        let token = introduction_capability.map_or_else(
            || intro_token(device, epoch_day(now)),
            |capability| {
                kult_crypto::discovery_introduction_token(&capability, device, epoch_day(now))
            },
        );
        Ok((session, Envelope::new(EnvelopeKind::Handshake, token, body)))
    }

    fn sweep_admission(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let requests = self
            .store
            .provisional_requests()?
            .into_iter()
            .filter(|request| request.expires_at <= now)
            .take(MAX_ADMISSION_EXPIRIES_PER_TICK)
            .collect::<Vec<_>>();
        let remaining = MAX_ADMISSION_EXPIRIES_PER_TICK.saturating_sub(requests.len());
        let tombstones = self
            .store
            .admission_tombstones()?
            .into_iter()
            .filter(|record| record.expires_at <= now)
            .take(remaining)
            .collect::<Vec<_>>();
        if requests.is_empty() && tombstones.is_empty() {
            return Ok(());
        }
        let receipt = self.store.commit_plan(
            CommitPlan::AdmissionSweep(AdmissionSweepPlan {
                requests: &requests,
                tombstones: &tombstones,
                now,
                presentation_changed: !requests.is_empty(),
            }),
            rng,
        )?;
        let mut events = Vec::new();
        for request in &requests {
            if self.admission_notifications_remaining == 0 {
                break;
            }
            self.admission_notifications_remaining -= 1;
            events.push(Event::MessageRequestExpired {
                request: request.request_id,
            });
        }
        self.accept_commit_receipt(receipt, events);
        Ok(())
    }

    fn sweep_ephemeral(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let due: Vec<EphemeralRecord> = self
            .store
            .ephemeral_records()?
            .into_iter()
            .filter(|record| record.state == EphemeralState::Active && now >= record.expires_at)
            .take(MAX_EPHEMERAL_EXPIRIES_PER_TICK)
            .collect();
        if due.is_empty() {
            return Ok(());
        }
        let me = self.account.ed;
        let queue = self.store.queue_all()?;
        let mut tombstones = Vec::new();
        let mut pairwise_deletes = Vec::new();
        let mut group_deletes = Vec::new();
        let mut media_rows = Vec::new();
        let mut queue_deletes = Vec::new();
        let mut events = Vec::new();
        let mut transfer_ids = Vec::new();
        for before in due {
            let mut after = before.clone();
            after.state = EphemeralState::Expired;
            match before.conversation {
                EphemeralConversation::Pairwise(peer) => {
                    let direction = if before.author == me {
                        Direction::Outbound
                    } else {
                        Direction::Inbound
                    };
                    if let Some(message) =
                        self.store
                            .messages_with(&peer)?
                            .into_iter()
                            .find(|message| {
                                message.id == before.content_id && message.direction == direction
                            })
                    {
                        pairwise_deletes.push(message);
                    }
                    if direction == Direction::Outbound {
                        for (sequence, item) in &queue {
                            if item.msg_id == Some(before.content_id) {
                                queue_deletes.push(QueueDelete {
                                    sequence: *sequence,
                                    content_id: item.envelope.content_id(),
                                });
                            }
                        }
                    }
                }
                EphemeralConversation::Group(group) => {
                    if let Some(message) =
                        self.store
                            .group_messages(&group)?
                            .into_iter()
                            .find(|message| {
                                message.id == before.content_id && message.sender == before.author
                            })
                    {
                        group_deletes.push(message);
                    }
                    if before.author == me {
                        for (sequence, item) in &queue {
                            if item.group_msg_id == Some(before.content_id) {
                                queue_deletes.push(QueueDelete {
                                    sequence: *sequence,
                                    content_id: item.envelope.content_id(),
                                });
                            }
                        }
                    }
                }
            }
            for transfer in &before.transfer_ids {
                if self.store.get_media_transfer(transfer)?.is_some() {
                    let objects = self
                        .store
                        .media_objects_for_transfer(transfer)?
                        .into_iter()
                        .map(|object| object.local_id)
                        .collect::<Vec<_>>();
                    media_rows.push((*transfer, objects));
                }
                transfer_ids.push(*transfer);
            }
            events.push(Event::EphemeralRemoved {
                conversation: before.conversation,
                author: before.author,
                content_id: before.content_id,
                reason: EphemeralState::Expired,
            });
            tombstones.push((before, after));
        }
        queue_deletes.sort_by_key(|delete| delete.sequence);
        queue_deletes.dedup_by_key(|delete| delete.sequence);
        let ephemeral = tombstones
            .iter()
            .map(|(before, after)| EphemeralTransition {
                before: Some(before),
                after,
            })
            .collect::<Vec<_>>();
        let delete_messages = pairwise_deletes
            .iter()
            .map(|before| MessageDelete { before })
            .collect::<Vec<_>>();
        let delete_group_messages = group_deletes
            .iter()
            .map(|before| GroupMessageDelete { before })
            .collect::<Vec<_>>();
        let delete_media = media_rows
            .iter()
            .map(|(transfer_id, object_ids)| MediaDelete {
                transfer_id: *transfer_id,
                object_ids,
            })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[],
                delete_pending: &[],
                delete_queue: &queue_deletes,
                update_queue: &[],
                delete_replay: &[],
                messages: &[],
                deliveries: &[],
                group_messages: &[],
                groups: &[],
                ephemeral: &ephemeral,
                delete_messages: &delete_messages,
                delete_group_messages: &delete_group_messages,
                delete_media: &delete_media,
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
        for transfer in transfer_ids {
            self.attachment_request_at.remove(&transfer);
            self.attachment_request_target.remove(&transfer);
        }
        self.store.collect_media_garbage()?;
        self.accept_commit_receipt(receipt, events);
        Ok(())
    }

    fn activate_scheduled_messages(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for scheduled in self.store.scheduled_messages()? {
            if now < scheduled.not_before {
                continue;
            }
            let activation = (|| -> Result<bool> {
                match scheduled.conversation {
                    StoreScheduledConversation::Peer(peer) => {
                        // Validate a first-flight bundle before the ordinary
                        // send path persists its queued history record. An
                        // expired bundle keeps the editable scheduled record
                        // intact without stalling unrelated node work.
                        if !self.sessions.contains_key(&peer) {
                            let contact = self
                                .store
                                .get_contact(&peer)?
                                .ok_or(NodeError::UnknownPeer)?;
                            let endpoints = self.store.contact_devices_for(&peer)?;
                            if endpoints.is_empty() {
                                if contact.bundle.is_empty() {
                                    return Err(NodeError::NoSession);
                                }
                                PrekeyBundle::decode(&contact.bundle)?.verify(now)?;
                            } else {
                                let mut usable = false;
                                for endpoint in endpoints {
                                    if self.sessions.contains_key(&endpoint.device)
                                        || (!endpoint.bundle.is_empty()
                                            && PrekeyBundle::decode(&endpoint.bundle)
                                                .and_then(|bundle| bundle.verify(now))
                                                .is_ok())
                                    {
                                        usable = true;
                                    }
                                }
                                if !usable {
                                    return Err(NodeError::NoSession);
                                }
                            }
                        }
                        self.send_message_with_id_retention(
                            &peer,
                            &scheduled.body,
                            scheduled.id,
                            scheduled.not_before,
                            now,
                            None,
                            Some(&scheduled),
                            rng,
                        )?;
                        Ok(true)
                    }
                    StoreScheduledConversation::Group(group) => {
                        self.activate_scheduled_group_message(&group, &scheduled, now, rng)?;
                        Ok(true)
                    }
                }
            })();
            match activation {
                Ok(true) => {}
                Ok(false) => unreachable!("scheduled activation reports committed success"),
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// Queue a fresh handshake to every session-reset-marked peer
    /// (docs/07-storage.md §4). A restored device's ratchets are gone;
    /// waiting for the user to send first would leave inbound traffic dead
    /// until then, so the reset markers the backup carried are turned into
    /// proactive re-handshakes — empty first flights the receiver
    /// recognizes as session maintenance, not messages. One attempt per
    /// marker: peers whose bundle is missing or expired fall back to the
    /// send-path auto-handshake once the user has a fresh bundle for them.
    fn rekey_reset_peers(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        for marker in self
            .store
            .reset_markers()?
            .into_iter()
            .take(MAX_RESET_MARKERS_PER_TICK)
        {
            let all_endpoints = self.store.contact_devices()?;
            let physical = all_endpoints
                .iter()
                .find(|endpoint| endpoint.device == marker && endpoint.revoked_at.is_none());
            let account = physical.map_or(marker, |endpoint| endpoint.account);
            let mut routes = if physical.is_some() {
                physical.cloned().into_iter().collect::<Vec<_>>()
            } else {
                self.store.contact_devices_for(&account)?
            };
            if routes.is_empty() {
                let contact = self.store.get_contact(&account)?;
                if let Some(contact) = contact.filter(|contact| !contact.bundle.is_empty()) {
                    routes.push(ContactDeviceRecord {
                        account,
                        device: account,
                        name: None,
                        certificate: Vec::new(),
                        authority: Vec::new(),
                        bundle: contact.bundle,
                        hints: contact.hints,
                        introduction_capability: None,
                        introduction_generation: 0,
                        manifest_generation: 0,
                        manifest_state_id: [0u8; 32],
                        last_seen: now,
                        revoked_at: None,
                        revoked_after_counter: None,
                    });
                }
            }

            let mut prepared = Vec::new();
            let mut queue = Vec::new();
            for endpoint in routes {
                if self.sessions.contains_key(&endpoint.device) || endpoint.bundle.is_empty() {
                    continue;
                }
                let Ok((after, envelope)) = self.prepare_session(
                    &account,
                    &endpoint.device,
                    &endpoint.bundle,
                    &pad(&[])?,
                    now,
                    rng,
                ) else {
                    continue; // e.g. the archived bundle has expired
                };
                queue.push(QueueItem {
                    peer: endpoint.device,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Normal,
                    created_at: now,
                    attempts: 0,
                    next_attempt_at: now,
                    envelope: envelope.clone(),
                });
                prepared.push(PreparedPairwiseRoute {
                    route: endpoint.device,
                    before: None,
                    after,
                    envelope,
                    resets_capabilities: true,
                });
            }
            if prepared.is_empty() {
                self.store.commit_plan(
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
                        clear_reset_markers: &[marker],
                        delete_controls: &[],
                        wake: &[],
                        acknowledge_presentation: None,
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                continue;
            }
            let transitions = prepared
                .iter()
                .map(|route| SessionTransition {
                    peer_device: route.route,
                    before: None,
                    after: &route.after,
                })
                .collect::<Vec<_>>();
            let clear_capabilities = prepared.iter().map(|route| route.route).collect::<Vec<_>>();
            self.store.commit_plan(
                CommitPlan::PairwiseSend(PairwiseSendPlan {
                    sessions: &transitions,
                    message: None,
                    message_update: None,
                    deliveries: &[],
                    delivery_updates: &[],
                    queue: &queue,
                    groups: &[],
                    authorities: &[],
                    scheduled: None,
                    clear_capabilities: &clear_capabilities,
                    clear_reset_markers: &[marker],
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    delete_controls: &[],
                    wake: &[],
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            for route in prepared {
                self.sessions.insert(route.route, route.after);
                self.capabilities_advertised.remove(&route.route);
                self.discovery_advertised.remove(&route.route);
                self.rendezvous_advertised.remove(&route.route);
                self.rendezvous_refresh_requested.insert(route.route);
            }
            self.after_memory_replacement()?;
        }
        Ok(())
    }

    fn process_rendezvous_rehandshakes(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut due = self
            .rendezvous_rehandshake_requested
            .iter()
            .copied()
            .collect::<Vec<_>>();
        due.sort_unstable();
        due.truncate(MAX_RENDEZVOUS_REHANDSHAKES_PER_TICK);
        for peer_device in due {
            let Some(before) = self.store.get_session(&peer_device)? else {
                self.rendezvous_rehandshake_requested.remove(&peer_device);
                continue;
            };
            if before.hybrid_service_exporter().is_some() {
                self.rendezvous_rehandshake_requested.remove(&peer_device);
                continue;
            }
            let Some(endpoint) = self.store.contact_devices()?.into_iter().find(|endpoint| {
                endpoint.device == peer_device
                    && endpoint.revoked_at.is_none()
                    && !endpoint.bundle.is_empty()
            }) else {
                continue;
            };
            let Ok((after, envelope)) = self.prepare_session(
                &endpoint.account,
                &peer_device,
                &endpoint.bundle,
                &pad(&[])?,
                now,
                rng,
            ) else {
                continue;
            };
            let queue = QueueItem {
                peer: peer_device,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope,
            };
            self.store.commit_plan(
                CommitPlan::PairwiseSend(PairwiseSendPlan {
                    sessions: &[SessionTransition {
                        peer_device,
                        before: Some(&before),
                        after: &after,
                    }],
                    message: None,
                    message_update: None,
                    deliveries: &[],
                    delivery_updates: &[],
                    queue: &[queue],
                    groups: &[],
                    authorities: &[],
                    scheduled: None,
                    clear_capabilities: &[peer_device],
                    clear_reset_markers: &[],
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    delete_controls: &[],
                    wake: &[],
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            self.sessions.insert(peer_device, after);
            self.capabilities_advertised.remove(&peer_device);
            self.discovery_advertised.remove(&peer_device);
            self.rendezvous_advertised.remove(&peer_device);
            self.rendezvous_refresh_requested.insert(peer_device);
            self.rendezvous_rehandshake_requested.remove(&peer_device);
            self.after_memory_replacement()?;
        }
        Ok(())
    }

    fn queue_pending_pairwise_device_deliveries(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let endpoints: HashMap<[u8; 32], ContactDeviceRecord> = self
            .store
            .contact_devices()?
            .into_iter()
            .filter(|endpoint| endpoint.revoked_at.is_none())
            .map(|endpoint| (endpoint.device, endpoint))
            .collect();
        let mut queued: HashMap<([u8; 16], [u8; 32]), [u8; 16]> = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(_, item)| {
                item.msg_id
                    .map(|message| ((message, item.peer), item.envelope.content_id()))
            })
            .collect();
        let active_ephemeral: HashSet<[u8; 16]> = self
            .store
            .ephemeral_records()?
            .into_iter()
            .filter(|record| record.state == EphemeralState::Active)
            .map(|record| record.content_id)
            .collect();
        let mut transitions_left = MAX_PENDING_DEVICE_DELIVERIES_PER_TICK;

        for contact in self.store.contacts()? {
            for message in self.store.messages_with(&contact.peer)? {
                if transitions_left == 0 {
                    return Ok(());
                }
                if message.direction != Direction::Outbound
                    || active_ephemeral.contains(&message.id)
                {
                    continue;
                }
                let message_before = message;
                let mut message_after = message_before.clone();
                let mut prepared = Vec::new();
                let mut queue = Vec::new();
                let mut delivery_pairs = Vec::new();
                for delivery in self.store.message_device_deliveries(&message_before.id)? {
                    if transitions_left == 0 {
                        break;
                    }
                    if delivery.account != contact.peer
                        || delivery.state != DeliveryState::Queued
                        || delivery.wire_id.is_some()
                    {
                        continue;
                    }
                    let route = delivery.device;
                    let mut delivery_after = delivery.clone();
                    if let Some(wire_id) = queued.get(&(message_before.id, route)).copied() {
                        delivery_after.wire_id = Some(wire_id);
                        if message_after.wire_id.is_none() {
                            message_after.wire_id = Some(wire_id);
                        }
                        delivery_pairs.push((delivery, delivery_after));
                        transitions_left -= 1;
                        continue;
                    }

                    let padded = pad(&message_before.body)?;
                    let route_state = if let Some(before) = self.sessions.get(&route).cloned() {
                        let mut after = before.clone();
                        let ratchet = self.candidate_encrypt(&mut after, rng, now, &padded)?;
                        let token = delivery_token(
                            &MailboxKey::from_bytes(*after.mailbox_key()),
                            epoch_day(now),
                            &route,
                        );
                        PreparedPairwiseRoute {
                            route,
                            before: Some(before),
                            after,
                            envelope: Envelope::new(EnvelopeKind::Message, token, ratchet.encode()),
                            resets_capabilities: false,
                        }
                    } else {
                        let Some(endpoint) = endpoints.get(&route) else {
                            continue;
                        };
                        if endpoint.bundle.is_empty()
                            || PrekeyBundle::decode(&endpoint.bundle)
                                .and_then(|bundle| bundle.verify(now))
                                .is_err()
                        {
                            continue;
                        }
                        let (after, envelope) = self.prepare_session(
                            &contact.peer,
                            &route,
                            &endpoint.bundle,
                            &padded,
                            now,
                            rng,
                        )?;
                        PreparedPairwiseRoute {
                            route,
                            before: None,
                            after,
                            envelope,
                            resets_capabilities: true,
                        }
                    };
                    let wire_id = route_state.envelope.content_id();
                    let class = if matches!(
                        decode_content(&message_before.body),
                        DecodedContent::Attachment { .. }
                    ) {
                        QueueClass::Bulk
                    } else {
                        QueueClass::Interactive
                    };
                    queue.push(QueueItem {
                        peer: route,
                        msg_id: Some(message_before.id),
                        group_msg_id: None,
                        class,
                        created_at: message_before.timestamp,
                        attempts: 0,
                        next_attempt_at: now,
                        envelope: route_state.envelope.clone(),
                    });
                    queued.insert((message_before.id, route), wire_id);
                    delivery_after.wire_id = Some(wire_id);
                    delivery_pairs.push((delivery, delivery_after));
                    if message_after.wire_id.is_none() {
                        message_after.wire_id = Some(wire_id);
                    }
                    prepared.push(route_state);
                    transitions_left -= 1;
                }
                if delivery_pairs.is_empty() {
                    continue;
                }
                let delivery_updates = delivery_pairs
                    .iter()
                    .map(|(before, after)| DeliveryTransition { before, after })
                    .collect::<Vec<_>>();
                let message_update =
                    (message_after != message_before).then_some(MessageTransition {
                        before: &message_before,
                        after: &message_after,
                    });
                if prepared.is_empty() {
                    self.store.commit_plan(
                        CommitPlan::Maintenance(MaintenancePlan {
                            seen: &[],
                            delete_pending: &[],
                            delete_queue: &[],
                            update_queue: &[],
                            delete_replay: &[],
                            messages: message_update.as_slice(),
                            deliveries: &delivery_updates,
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
                    continue;
                }
                let session_transitions = prepared
                    .iter()
                    .map(|route| SessionTransition {
                        peer_device: route.route,
                        before: route.before.as_ref(),
                        after: &route.after,
                    })
                    .collect::<Vec<_>>();
                let clear_capabilities = prepared
                    .iter()
                    .filter(|route| route.resets_capabilities)
                    .map(|route| route.route)
                    .collect::<Vec<_>>();
                self.store.commit_plan(
                    CommitPlan::PairwiseSend(PairwiseSendPlan {
                        sessions: &session_transitions,
                        message: None,
                        message_update: Some(MessageTransition {
                            before: &message_before,
                            after: &message_after,
                        }),
                        deliveries: &[],
                        delivery_updates: &delivery_updates,
                        queue: &queue,
                        groups: &[],
                        authorities: &[],
                        scheduled: None,
                        clear_capabilities: &clear_capabilities,
                        clear_reset_markers: &[],
                        ephemeral: None,
                        media_transfers: &[],
                        media_objects: &[],
                        delete_controls: &[],
                        wake: &[],
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                self.before_memory_replacement()?;
                for route in prepared {
                    self.sessions.insert(route.route, route.after);
                    if route.resets_capabilities {
                        self.capabilities_advertised.remove(&route.route);
                        self.discovery_advertised.remove(&route.route);
                        self.rendezvous_advertised.remove(&route.route);
                        self.rendezvous_refresh_requested.insert(route.route);
                    }
                }
                self.after_memory_replacement()?;
            }
        }
        Ok(())
    }

    // ---- receive path ------------------------------------------------------

    fn apply_deferred_controls(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<bool> {
        self.sweep_group_invitations(now, rng)?;
        let mut made_progress = false;
        for control in self
            .store
            .deferred_controls(MAX_DEFERRED_CONTROLS_PER_TICK)?
        {
            let (applied, deleted_atomically) = match control.kind {
                DeferredControlKind::AttachmentBulk => {
                    let acknowledged = self.apply_attachment_bulk(
                        control.peer,
                        control.peer_device,
                        &control.body,
                        now,
                        &control,
                        rng,
                    )?;
                    (true, acknowledged)
                }
                DeferredControlKind::GroupControl => {
                    let mut established = false;
                    self.apply_group_control(&control, now, rng, &mut established, false)?
                }
            };
            if !applied {
                continue;
            }
            made_progress = true;
            if deleted_atomically {
                continue;
            }
            if control.kind == DeferredControlKind::GroupControl
                && self.accepted_group_origin_control(&control)?
            {
                let acknowledgement = ReceiptPayload {
                    acks: vec![control.content_id],
                    nacks: Vec::new(),
                }
                .encode();
                if !self.commit_pairwise_control_send(
                    &control.peer_device,
                    &acknowledgement,
                    now,
                    rng,
                )? {
                    continue;
                }
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
                    delete_controls: &[control],
                    wake: &[],
                    acknowledge_presentation: None,
                    presentation_changed: true,
                }),
                rng,
            )?;
            self.accept_commit_receipt(receipt, []);
        }
        Ok(made_progress)
    }

    fn pending_delete(
        pending_sequence: Option<i64>,
        content_id: [u8; 16],
    ) -> Option<PendingDelete> {
        pending_sequence.map(|sequence| PendingDelete {
            sequence,
            content_id,
        })
    }

    fn prepare_control_queue(
        &self,
        session: &mut Session,
        peer: [u8; 32],
        payload: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<QueueItem> {
        let message = self.candidate_encrypt(session, rng, now, &pad(payload)?)?;
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            &peer,
        );
        Ok(QueueItem {
            peer,
            msg_id: None,
            group_msg_id: None,
            class: QueueClass::Normal,
            created_at: now,
            attempts: 0,
            next_attempt_at: now,
            envelope: Envelope::new(EnvelopeKind::Receipt, token, message.encode()),
        })
    }

    fn commit_terminal_input(
        &mut self,
        content_id: [u8; 16],
        pending_sequence: Option<i64>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Consumed> {
        let pending = Self::pending_delete(pending_sequence, content_id);
        self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[content_id],
                delete_pending: pending.as_slice(),
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
                delete_controls: &[],
                wake: &[],
                acknowledge_presentation: None,
                presentation_changed: false,
            }),
            rng,
        )?;
        Ok(Consumed::RejectedAtomic)
    }

    fn consume(
        &mut self,
        env: &Envelope,
        origin: ConsumeOrigin,
        now: u64,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<Consumed> {
        // Multipath duplicates of anything already consumed are dropped here.
        let content_id = env.content_id();
        if self.store.is_seen(&content_id)? {
            if let Some(peer) = self.store.receipt_replay_peer(&content_id)? {
                if let Some(before) = self.store.get_session(&peer)? {
                    let mut after = before.clone();
                    let receipt = ReceiptPayload {
                        acks: vec![content_id],
                        nacks: Vec::new(),
                    }
                    .encode();
                    let queue = self.prepare_control_queue(&mut after, peer, &receipt, now, rng)?;
                    let source_pending = Self::pending_delete(origin.pending_sequence, content_id);
                    self.store.commit_plan(
                        CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                            session: SessionTransition {
                                peer_device: peer,
                                before: Some(&before),
                                after: &after,
                            },
                            message: None,
                            ephemeral: None,
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            queue: &[queue],
                            content_id,
                            received_at: now,
                            receipt_replay: true,
                            source_pending,
                            presentation_changed: false,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer, after);
                    self.after_memory_replacement()?;
                    return Ok(Consumed::DoneAtomic);
                }
            }
            if origin.pending_sequence.is_some() {
                return self.commit_terminal_input(content_id, origin.pending_sequence, rng);
            }
            return Ok(Consumed::Done);
        }
        match env.kind {
            EnvelopeKind::Fragment => {
                // Fragments never nest (we only fragment whole envelopes);
                // treat nested ones as malformed.
                if origin.depth > 0 {
                    return self.commit_terminal_input(
                        env.content_id(),
                        origin.pending_sequence,
                        rng,
                    );
                }
                // Remember which delivery token this partial rides under so
                // the NACK for its missing pieces (selective retransmission,
                // docs/05-transports.md §4.2 rule 2) knows which session to
                // ask — resolvable lazily, once that session exists.
                if env.body.len() >= 4 {
                    let id: [u8; 4] = env.body[..4].try_into().expect("length checked");
                    self.frag_meta.entry(id).or_insert(PartialMeta {
                        token: env.token,
                        first_seen: now,
                        last_nack: None,
                    });
                }
                let completed = self.reassembler.insert(&env.body, now);
                // Top-level fragments are deliberately not persisted in the
                // seen set. A completed inner envelope may still be refused
                // by the bounded deferred inbox; retaining retryability of
                // the full fragment set is then the only lossless outcome.
                // Reassembly and inner-envelope dedup remain independently
                // bounded, so exact fragment retries are safe.
                if let Ok(Some(payload)) = completed {
                    if let Ok(inner) = Envelope::decode(&payload) {
                        if let Consumed::Later = self.consume(
                            &inner,
                            ConsumeOrigin {
                                depth: 1,
                                pending_sequence: None,
                                transport: origin.transport,
                            },
                            now,
                            rng,
                            established,
                        )? {
                            // Reassembled before its session exists — stash
                            // the inner envelope for later ticks.
                            match self.store.pending_push_with_transport(
                                &inner,
                                now,
                                origin.transport,
                                rng,
                            ) {
                                Ok(_) | Err(kult_store::StoreError::PendingQuota) => {}
                                Err(error) => return Err(error.into()),
                            }
                        }
                    }
                }
                Ok(Consumed::Done)
            }
            EnvelopeKind::Handshake => self.consume_handshake(
                env,
                origin.pending_sequence,
                origin.transport,
                now,
                rng,
                established,
            ),
            EnvelopeKind::Message | EnvelopeKind::Receipt | EnvelopeKind::GroupControl => {
                self.consume_ratchet(env, origin.pending_sequence, now, rng, established)
            }
            EnvelopeKind::GroupMessage => {
                self.consume_group_message(env, origin.pending_sequence, now, rng)
            }
        }
    }

    fn reserve_admission_candidate(&mut self, transport: AdmissionTransportClass) -> bool {
        if self
            .admission_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return false;
        }
        let index = admission_transport_index(transport);
        let Some(remaining) = self.admission_carrier_remaining.get_mut(index) else {
            return false;
        };
        if *remaining == 0 {
            return false;
        }
        *remaining -= 1;
        true
    }

    fn consume_handshake(
        &mut self,
        env: &Envelope,
        pending_sequence: Option<i64>,
        transport: AdmissionTransportClass,
        now: u64,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<Consumed> {
        // Every failure below is permanent for this envelope (it cannot
        // become decryptable later), so it is marked seen and dropped —
        // parsers never panic, dropped flights never wedge the queue.
        let content_id = env.content_id();
        let mut admission_bundle_digest = None;
        let mut invitation_admission = false;
        let admission = if AdmissionEnvelope::is_encoded(&env.body) {
            if !self.reserve_admission_candidate(transport) {
                return Ok(Consumed::Later);
            }
            if self.admission_puzzles_remaining == 0 {
                return Ok(Consumed::Later);
            }
            self.admission_puzzles_remaining -= 1;
            let Ok(admission) = AdmissionEnvelope::decode(&env.body) else {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            };
            let Ok(target_bundle) = PrekeyBundle::decode(&admission.target_bundle) else {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            };
            let Ok(target_policy) = target_bundle.verify_admission(now) else {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            };
            if admission.context.target_account != self.account.ed
                || admission.context.target_device != self.device_id()
                || target_bundle.identity != self.device_identity.public()
                || admission.context.bundle_digest != target_policy.descriptor.bundle_digest
                || admission.context.validity_epoch != target_policy.descriptor.validity_epoch
                || admission.sealed_flight.len()
                    > usize::try_from(target_policy.descriptor.max_first_ciphertext)
                        .map_err(|_| NodeError::CorruptState)?
            {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            let proof_valid = match admission.proof_kind {
                AdmissionProofKind::Puzzle => verify_admission_puzzle(
                    &admission.context,
                    &admission.content_id,
                    &admission.proof,
                    target_policy.descriptor.difficulty,
                ),
                AdmissionProofKind::Invitation => self
                    .vault
                    .invitation(&admission.context.bundle_digest, now)
                    .map(|invitation| {
                        admission_invitation_proof(
                            &invitation,
                            &admission.context,
                            &admission.content_id,
                        )
                    })
                    .is_some_and(|expected| bool::from(expected.ct_eq(&admission.proof))),
            };
            if !proof_valid {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            let current_pq = self.vault.pqspk()?;
            if target_bundle.spk_id != self.vault.spk_id
                || target_bundle.spk != self.vault.spk().public()
                || target_bundle.pqspk_id != self.vault.pqspk_id
                || target_bundle.pqspk.as_slice() != current_pq.public()
            {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            admission_bundle_digest = Some(admission.context.bundle_digest);
            invitation_admission = admission.proof_kind == AdmissionProofKind::Invitation;
            Some(admission)
        } else {
            None
        };
        let sealed_flight = admission.as_ref().map_or(env.body.as_slice(), |admission| {
            admission.sealed_flight.as_slice()
        });
        let step = self.begin_crypto_step()?;
        let device_open = open_anonymous(&self.device_identity, HS_AD, sealed_flight);
        self.finish_crypto_step(step)?;
        let (recipient, init_bytes) = if let Ok(bytes) = device_open {
            (&self.device_identity, bytes)
        } else {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        };
        let (raw_initial, sender_bundle, sender_account_bundle, handshake_intent) =
            if let Some(flight) = decode_device_initial(&init_bytes) {
                let Ok(bundle) = DevicePrekeyBundle::decode(&flight.return_bundle) else {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                };
                if bundle.verify(now).is_err() {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                }
                (flight.initial, Some(bundle), None, flight.intent)
            } else if let Some(flight) = decode_account_initial(&init_bytes) {
                let Ok(bundle) = PrekeyBundle::decode(&flight.return_bundle) else {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                };
                if bundle.verify(now).is_err() {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                }
                (
                    flight.initial,
                    None,
                    Some(bundle),
                    DeviceHandshakeIntent::Legacy,
                )
            } else {
                (init_bytes, None, None, DeviceHandshakeIntent::Legacy)
            };
        let Ok(init) = InitialMessage::decode(&raw_initial) else {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        };
        if sender_bundle
            .as_ref()
            .is_some_and(|bundle| bundle.prekey.identity != init.initiator)
            || sender_account_bundle
                .as_ref()
                .is_some_and(|bundle| bundle.identity != init.initiator)
        {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        }
        let peer_device = init.initiator.ed;
        let (peer, account_identity) = sender_bundle.as_ref().map_or_else(
            || (peer_device, init.initiator.clone()),
            |bundle| {
                (
                    bundle.manifest.account().ed,
                    bundle.manifest.account().clone(),
                )
            },
        );
        let existing_contact = self.store.get_contact(&peer)?;
        let was_new_contact = existing_contact.is_none();
        if (admission.is_none() && was_new_contact) || self.store.is_blocked_identity(&peer)? {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        }
        if was_new_contact {
            let existing_request = self.store.get_provisional_request(&peer)?;
            if existing_request.is_none()
                && self.store.provisional_requests()?.len() >= kult_store::MAX_PROVISIONAL_REQUESTS
            {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            if self.admission_kems_remaining == 0 {
                return Ok(Consumed::Later);
            }
            self.admission_kems_remaining -= 1;
        }
        if init.spk_id != self.vault.spk_id || init.pqspk_id != self.vault.pqspk_id {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        }
        let opk = match init.opk_id {
            Some(id) => match self.vault.opk(id) {
                Some(opk) => Some(opk),
                None => {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                }
            },
            None => None,
        };
        let spk = self.vault.spk();
        let pqspk = self.vault.pqspk()?;
        let step = self.begin_crypto_step()?;
        let responded = respond(recipient, &spk, &pqspk, opk.as_ref(), &init, now, rng);
        self.finish_crypto_step(step)?;
        let Ok((mut session, first_payload)) = responded else {
            return self.commit_terminal_input(content_id, pending_sequence, rng);
        };

        let before_vault = self.vault.encode();
        let mut candidate_vault = self.vault.clone();
        if let Some(id) = init.opk_id {
            candidate_vault.remove_opk(id);
        }
        if invitation_admission {
            if let Some(digest) = admission_bundle_digest {
                candidate_vault.remove_invitation(&digest);
            }
        }
        let after_vault = candidate_vault.encode();
        let identity =
            postcard::to_allocvec(&account_identity).map_err(|_| NodeError::CorruptState)?;
        let account_return_bundle = sender_account_bundle
            .as_ref()
            .map_or_else(Vec::new, PrekeyBundle::encode);
        let account_return_hints = sender_account_bundle
            .as_ref()
            .map_or_else(Vec::new, PrekeyBundle::transport_hints);
        let contact = if let Some(mut contact) = existing_contact {
            if sender_account_bundle.is_some() {
                contact.identity = identity;
                contact.bundle.clone_from(&account_return_bundle);
                contact.hints.clone_from(&account_return_hints);
            }
            contact
        } else {
            ContactRecord {
                peer,
                identity,
                name: String::new(),
                bundle: account_return_bundle.clone(),
                hints: account_return_hints.clone(),
                verified: false,
            }
        };

        let existing_endpoints = self.store.contact_devices_for(&peer)?;
        let mut endpoints = Vec::new();
        let mut delete_endpoint_records = Vec::new();
        let mut cleanup_devices = Vec::new();
        if let Some(bundle) = sender_bundle.as_ref() {
            self.validate_contact_device_manifest_visible(&bundle.manifest, now, rng)?;
            let state_id = bundle.manifest.state_id();
            let legacy_alias = existing_endpoints
                .iter()
                .find(|endpoint| endpoint.device == peer && endpoint.manifest_generation == 0);
            let mut active_by_issuance = bundle
                .manifest
                .devices()
                .iter()
                .filter(|entry| entry.revoked_at.is_none())
                .collect::<Vec<_>>();
            active_by_issuance
                .sort_by_key(|entry| (entry.certificate.issued_at, entry.certificate.device_id()));
            let legacy_replacement = legacy_alias.and_then(|_| {
                let first = active_by_issuance.first()?;
                let unique_earliest = active_by_issuance.get(1).is_none_or(|second| {
                    second.certificate.issued_at > first.certificate.issued_at
                });
                unique_earliest.then_some(first.certificate.device_id())
            });
            let encoded_authority = bundle.manifest.encode()?;
            for entry in bundle.manifest.devices() {
                let device = entry.certificate.device_id();
                let prior = existing_endpoints
                    .iter()
                    .find(|endpoint| endpoint.device == device)
                    .or_else(|| {
                        (legacy_replacement == Some(device))
                            .then_some(legacy_alias)
                            .flatten()
                    });
                let advertised = device == peer_device;
                let mut endpoint_bundle =
                    prior.map_or_else(Vec::new, |endpoint| endpoint.bundle.clone());
                let mut hints = prior.map_or_else(Vec::new, |endpoint| endpoint.hints.clone());
                if advertised {
                    endpoint_bundle = bundle.prekey.encode();
                    let advertised_hints = bundle.prekey.transport_hints();
                    if !advertised_hints.is_empty() || hints.is_empty() {
                        hints = advertised_hints;
                    }
                }
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device,
                    name: Some(entry.name.clone()),
                    certificate: postcard::to_allocvec(&entry.certificate)
                        .map_err(|_| NodeError::CorruptState)?,
                    authority: encoded_authority.clone(),
                    bundle: endpoint_bundle,
                    hints,
                    introduction_capability: prior
                        .and_then(|endpoint| endpoint.introduction_capability),
                    introduction_generation: prior
                        .map_or(0, |endpoint| endpoint.introduction_generation),
                    manifest_generation: bundle.manifest.generation(),
                    manifest_state_id: state_id,
                    last_seen: entry
                        .last_seen
                        .max(prior.map_or(0, |endpoint| endpoint.last_seen))
                        .max(if advertised { now } else { 0 }),
                    revoked_at: entry.revoked_at,
                    revoked_after_counter: entry.revoked_after_counter,
                };
                if endpoint.revoked_at.is_some() && endpoint.device != peer_device {
                    cleanup_devices.push(endpoint.device);
                }
                endpoints.push(endpoint);
            }
            let manifest_devices = endpoints
                .iter()
                .map(|endpoint| endpoint.device)
                .collect::<HashSet<_>>();
            for orphaned in existing_endpoints.iter().filter(|endpoint| {
                endpoint.manifest_generation > 0 && !manifest_devices.contains(&endpoint.device)
            }) {
                delete_endpoint_records.push(orphaned.clone());
                cleanup_devices.push(orphaned.device);
            }
            for legacy in existing_endpoints.iter().filter(|endpoint| {
                endpoint.manifest_generation == 0
                    && !manifest_devices.contains(&endpoint.device)
                    && endpoint.device != peer_device
            }) {
                delete_endpoint_records.push(legacy.clone());
                cleanup_devices.push(legacy.device);
            }
        } else {
            let prior = existing_endpoints
                .iter()
                .find(|endpoint| endpoint.device == peer_device);
            let mut endpoint = ContactDeviceRecord {
                account: peer,
                device: peer_device,
                name: None,
                certificate: Vec::new(),
                authority: Vec::new(),
                bundle: account_return_bundle,
                hints: account_return_hints,
                introduction_capability: prior
                    .as_ref()
                    .and_then(|endpoint| endpoint.introduction_capability),
                introduction_generation: prior
                    .as_ref()
                    .map_or(0, |endpoint| endpoint.introduction_generation),
                manifest_generation: 0,
                manifest_state_id: [0u8; 32],
                last_seen: now,
                revoked_at: None,
                revoked_after_counter: None,
            };
            if let Some(prior) = prior {
                if endpoint.bundle.is_empty() {
                    endpoint.bundle.clone_from(&prior.bundle);
                }
                if endpoint.hints.is_empty() {
                    endpoint.hints.clone_from(&prior.hints);
                }
                if endpoint.certificate.is_empty() {
                    endpoint.certificate.clone_from(&prior.certificate);
                }
                if endpoint.authority.is_empty() {
                    endpoint.authority.clone_from(&prior.authority);
                }
                if endpoint.name.is_none() {
                    endpoint.name.clone_from(&prior.name);
                }
                endpoint.last_seen = endpoint.last_seen.max(prior.last_seen);
            }
            endpoints.push(endpoint);
        }

        if was_new_contact {
            if !existing_endpoints.is_empty() {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            let Ok(first_content) = unpad(&first_payload) else {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            };
            if first_content.len() > MAX_PROVISIONAL_CONTENT_BYTES {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            let preview = if first_content.is_empty() {
                String::new()
            } else {
                match decode_content(&first_content) {
                    DecodedContent::LegacyText(text) | DecodedContent::Text { text, .. } => {
                        bounded_request_preview(text)
                    }
                    _ => {
                        return self.commit_terminal_input(content_id, pending_sequence, rng);
                    }
                }
            };
            let safety = safety_number(&self.account, &account_identity);
            let session_bytes =
                postcard::to_allocvec(&session).map_err(|_| NodeError::CorruptState)?;
            let request = ProvisionalRequestRecord {
                version: PROVISIONAL_REQUEST_VERSION,
                request_id: content_id,
                account: peer,
                device: peer_device,
                contact,
                devices: endpoints,
                session: session_bytes,
                first_content,
                preview,
                safety_number: safety.digits,
                safety_number_qr: safety.qr,
                arrived_at: now,
                expires_at: now.saturating_add(MAX_PROVISIONAL_LIFETIME_SECS),
                transport,
            };
            let before = self.store.get_provisional_request(&peer)?;
            if before.as_ref().is_some_and(|prior| {
                (request.arrived_at, request.request_id) <= (prior.arrived_at, prior.request_id)
            }) {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            let vault_changed = init.opk_id.is_some() || invitation_admission;
            let prekeys = vault_changed.then_some(PrekeyTransition {
                before: Some(before_vault.as_ref()),
                after: after_vault.as_ref(),
            });
            let source_pending = Self::pending_delete(pending_sequence, content_id);
            let staged = self.store.commit_plan(
                CommitPlan::AdmissionStage(AdmissionStagePlan {
                    prekeys,
                    before: before.as_ref(),
                    after: &request,
                    content_id,
                    source_pending,
                    presentation_changed: true,
                }),
                rng,
            );
            let receipt = match staged {
                Ok(receipt) => receipt,
                Err(kult_store::StoreError::AdmissionQuota) => {
                    return self.commit_terminal_input(content_id, pending_sequence, rng);
                }
                Err(error) => return Err(error.into()),
            };
            self.before_memory_replacement()?;
            if vault_changed {
                self.vault = candidate_vault;
            }
            self.after_memory_replacement()?;
            let events = if self.admission_notifications_remaining == 0 {
                Vec::new()
            } else {
                self.admission_notifications_remaining -= 1;
                vec![Event::MessageRequestReceived {
                    request: content_id,
                }]
            };
            self.accept_commit_receipt(receipt, events);
            return Ok(Consumed::DoneAtomic);
        }

        let prior_session = self.store.get_session(&peer_device)?;
        let keep_prior_session = match decide_inbound_session(
            self.device_id(),
            peer_device,
            prior_session.as_ref().map(Session::session_id),
            handshake_intent,
        ) {
            HandshakeSessionDecision::Reject => {
                return self.commit_terminal_input(content_id, pending_sequence, rng);
            }
            HandshakeSessionDecision::KeepPrior => true,
            HandshakeSessionDecision::AcceptInbound => false,
        };
        if keep_prior_session {
            session = prior_session
                .as_ref()
                .ok_or(NodeError::CorruptState)?
                .clone();
        }

        cleanup_devices.sort_unstable();
        cleanup_devices.dedup();
        let mut delete_sessions = Vec::new();
        for device in &cleanup_devices {
            if self.store.get_session(device)?.is_some() {
                delete_sessions.push(*device);
            }
        }
        let mut delete_capabilities = cleanup_devices.clone();
        if !keep_prior_session {
            delete_capabilities.push(peer_device);
        }
        delete_capabilities.sort_unstable();
        delete_capabilities.dedup();
        let replacing_prior_session = prior_session.is_some() && !keep_prior_session;
        let mut reset_message_candidates = Vec::new();
        let mut reset_delivery_candidates = Vec::new();
        let mut retired_group_message_candidates = Vec::new();
        let mut retired_group_delivery_candidates = Vec::new();
        let mut reset_events = Vec::new();
        if replacing_prior_session {
            for message_before in self.store.messages_with(&peer)? {
                if message_before.direction != Direction::Outbound {
                    continue;
                }
                let mut deliveries = self.store.message_device_deliveries(&message_before.id)?;
                let mut changed = false;
                for delivery in &mut deliveries {
                    if delivery.device != peer_device
                        || matches!(
                            delivery.state,
                            DeliveryState::Delivered | DeliveryState::Failed
                        )
                        || (delivery.state == DeliveryState::Queued && delivery.wire_id.is_none())
                    {
                        continue;
                    }
                    let before = delivery.clone();
                    delivery.state = DeliveryState::Queued;
                    delivery.wire_id = None;
                    reset_delivery_candidates.push((before, delivery.clone()));
                    changed = true;
                }
                if !changed {
                    continue;
                }
                let mut message_after = message_before.clone();
                message_after.state = if deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Delivered)
                {
                    DeliveryState::Delivered
                } else if deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Sent)
                {
                    DeliveryState::Sent
                } else if deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Queued)
                {
                    DeliveryState::Queued
                } else {
                    DeliveryState::Failed
                };
                message_after.wire_id = deliveries.iter().find_map(|delivery| delivery.wire_id);
                if message_after != message_before {
                    reset_events.push(Event::DeliveryUpdated {
                        id: message_after.id,
                        state: message_after.state,
                    });
                    reset_message_candidates.push((message_before, message_after));
                }
            }
            for message_before in self.store.all_group_messages()? {
                if message_before.direction != Direction::Outbound {
                    continue;
                }
                let mut deliveries = self.store.message_device_deliveries(&message_before.id)?;
                let mut changed = false;
                for delivery in &mut deliveries {
                    if delivery.account != peer
                        || delivery.device != peer_device
                        || matches!(
                            delivery.state,
                            DeliveryState::Delivered | DeliveryState::Failed
                        )
                    {
                        continue;
                    }
                    let before = delivery.clone();
                    delivery.state = DeliveryState::Failed;
                    delivery.wire_id = None;
                    retired_group_delivery_candidates.push((before, delivery.clone()));
                    changed = true;
                }
                if !changed {
                    continue;
                }
                let account_deliveries = deliveries
                    .iter()
                    .filter(|delivery| delivery.account == peer)
                    .collect::<Vec<_>>();
                let mut message_after = message_before.clone();
                let account = message_after
                    .deliveries
                    .iter_mut()
                    .find(|delivery| delivery.peer == peer)
                    .ok_or(NodeError::CorruptState)?;
                account.state = if account_deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Delivered)
                {
                    DeliveryState::Delivered
                } else if account_deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Sent)
                {
                    DeliveryState::Sent
                } else if account_deliveries
                    .iter()
                    .any(|delivery| delivery.state == DeliveryState::Queued)
                {
                    DeliveryState::Queued
                } else {
                    DeliveryState::Failed
                };
                account.wire_id = account_deliveries
                    .iter()
                    .find_map(|delivery| delivery.wire_id);
                let account_state = account.state;
                if message_after != message_before {
                    reset_events.push(Event::GroupDeliveryUpdated {
                        id: message_after.id,
                        peer,
                        state: account_state,
                    });
                    retired_group_message_candidates.push((message_before, message_after));
                }
            }
        }
        let reset_messages = reset_message_candidates
            .iter()
            .map(|(before, after)| MessageTransition { before, after })
            .collect::<Vec<_>>();
        let reset_deliveries = reset_delivery_candidates
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let retire_group_messages = retired_group_message_candidates
            .iter()
            .map(|(before, after)| GroupMessageTransition { before, after })
            .collect::<Vec<_>>();
        let retire_group_deliveries = retired_group_delivery_candidates
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let cleanup_set = cleanup_devices.iter().copied().collect::<HashSet<_>>();
        let delete_queue = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(sequence, item)| {
                (cleanup_set.contains(&item.peer)
                    || (replacing_prior_session && item.peer == peer_device))
                    .then_some(QueueDelete {
                        sequence,
                        content_id: item.envelope.content_id(),
                    })
            })
            .collect::<Vec<_>>();
        if delete_queue.len() > kult_store::MAX_COMMIT_QUEUE_ROWS
            || reset_messages.len() > kult_store::MAX_COMMIT_QUEUE_ROWS
            || reset_deliveries.len() > kult_store::MAX_COMMIT_QUEUE_ROWS
            || retire_group_messages.len() > kult_store::MAX_COMMIT_QUEUE_ROWS
            || retire_group_deliveries.len() > kult_store::MAX_COMMIT_QUEUE_ROWS
        {
            return Ok(Consumed::Later);
        }
        let group_candidates = if keep_prior_session {
            Vec::new()
        } else {
            self.prepare_groups_on_session_established(&peer, rng)?
        };
        let group_transitions = group_candidates
            .iter()
            .map(|(before, after)| GroupTransition { before, after })
            .collect::<Vec<_>>();

        let prepared_inbound = match unpad(&first_payload) {
            Ok(body)
                if !body.is_empty()
                    && !matches!(decode_content(&body), DecodedContent::CallControl { .. }) =>
            {
                Some(self.prepare_inbound(peer, body, None, now, rng)?)
            }
            _ => None,
        };
        let needs_receipt = prepared_inbound.is_some() || keep_prior_session;
        let receipt_queue = if needs_receipt {
            let payload = ReceiptPayload {
                acks: vec![content_id],
                nacks: Vec::new(),
            }
            .encode();
            Some(self.prepare_control_queue(&mut session, peer_device, &payload, now, rng)?)
        } else {
            None
        };
        let delete_devices = delete_endpoint_records
            .iter()
            .map(|before| ContactDeviceDelete { before })
            .collect::<Vec<_>>();
        let source_pending = Self::pending_delete(pending_sequence, content_id);
        let mut events = Vec::new();
        if !keep_prior_session {
            events.push(Event::SessionEstablished { peer });
        }
        events.extend(reset_events);
        if let Some(prepared) = prepared_inbound.as_ref() {
            events.extend(prepared.events.clone());
        }
        let vault_changed = init.opk_id.is_some() || invitation_admission;
        let prekeys = vault_changed.then_some(PrekeyTransition {
            before: Some(before_vault.as_ref()),
            after: after_vault.as_ref(),
        });
        let inbound_media_transfers = prepared_inbound
            .as_ref()
            .map_or(0, |prepared| prepared.media_transfers.len());
        let inbound_media_objects = prepared_inbound
            .as_ref()
            .map_or(0, |prepared| prepared.media_objects.len());
        let mutation_count = [
            usize::from(prekeys.is_some()),
            1,
            1,
            endpoints.len(),
            delete_devices.len(),
            delete_sessions.len(),
            delete_capabilities.len(),
            delete_queue.len(),
            reset_messages.len(),
            reset_deliveries.len(),
            retire_group_messages.len(),
            retire_group_deliveries.len(),
            group_transitions.len(),
            usize::from(
                prepared_inbound
                    .as_ref()
                    .and_then(|prepared| prepared.message.as_ref())
                    .is_some(),
            ),
            usize::from(
                prepared_inbound
                    .as_ref()
                    .and_then(|prepared| prepared.ephemeral.as_ref())
                    .is_some(),
            ),
            inbound_media_transfers,
            inbound_media_objects,
            usize::from(receipt_queue.is_some()),
            1,
            usize::from(needs_receipt),
            usize::from(source_pending.is_some()),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(NodeError::CorruptState)?;
        if mutation_count > kult_store::MAX_COMMIT_MUTATIONS {
            return Ok(Consumed::Later);
        }
        let receipt = self.store.commit_plan(
            CommitPlan::HandshakeReceive(HandshakeReceivePlan {
                prekeys,
                session: SessionTransition {
                    peer_device,
                    before: prior_session.as_ref(),
                    after: &session,
                },
                contact: &contact,
                devices: &endpoints,
                delete_devices: &delete_devices,
                delete_sessions: &delete_sessions,
                delete_capabilities: &delete_capabilities,
                delete_queue: &delete_queue,
                reset_messages: &reset_messages,
                reset_deliveries: &reset_deliveries,
                retire_group_messages: &retire_group_messages,
                retire_group_deliveries: &retire_group_deliveries,
                groups: &group_transitions,
                message: prepared_inbound
                    .as_ref()
                    .and_then(|prepared| prepared.message.as_ref()),
                ephemeral: prepared_inbound
                    .as_ref()
                    .and_then(|prepared| prepared.ephemeral.as_ref()),
                media_transfers: prepared_inbound
                    .as_ref()
                    .map_or(&[], |prepared| prepared.media_transfers.as_slice()),
                media_objects: prepared_inbound
                    .as_ref()
                    .map_or(&[], |prepared| prepared.media_objects.as_slice()),
                queue: receipt_queue.as_slice(),
                content_id,
                received_at: now,
                receipt_replay: needs_receipt,
                source_pending,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        if vault_changed {
            self.vault = candidate_vault;
        }
        for device in cleanup_devices {
            self.sessions.remove(&device);
            self.capabilities_advertised.remove(&device);
            self.discovery_advertised.remove(&device);
            self.rendezvous_advertised.remove(&device);
            self.rendezvous_refresh_requested.remove(&device);
            self.rendezvous_rehandshake_requested.remove(&device);
        }
        if !keep_prior_session {
            self.capabilities_advertised.remove(&peer_device);
            self.discovery_advertised.remove(&peer_device);
            self.rendezvous_advertised.remove(&peer_device);
            self.rendezvous_refresh_requested.insert(peer_device);
            self.rendezvous_rehandshake_requested.remove(&peer_device);
        }
        self.sessions.insert(peer_device, session);
        *established |= !keep_prior_session;
        self.after_memory_replacement()?;
        let deleted = delete_queue
            .iter()
            .map(|delete| delete.sequence)
            .collect::<HashSet<_>>();
        self.held_notified
            .retain(|sequence| !deleted.contains(sequence));
        self.call_queue_deadlines
            .retain(|sequence, _| !deleted.contains(sequence));
        self.accept_commit_receipt(receipt, events);
        if let Some(prepared) = prepared_inbound {
            for transfer in prepared.attachment_updates {
                self.emit_attachment_update(&transfer)?;
            }
        }
        Ok(Consumed::DoneAtomic)
    }

    fn consume_ratchet(
        &mut self,
        env: &Envelope,
        pending_sequence: Option<i64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
        _established: &mut bool,
    ) -> Result<Consumed> {
        let Some(peer_device) = self.match_session(&env.token, now) else {
            return Ok(Consumed::Later);
        };
        let peer = self.account_for_device(&peer_device)?;
        let Ok(msg) = RatchetMessage::decode(&env.body) else {
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        };
        let Some(before) = self.store.get_session(&peer_device)? else {
            return Err(NodeError::CorruptState);
        };
        let mut after = before.clone();
        let Ok(plaintext) = self.candidate_decrypt(&mut after, rng, now, &msg)? else {
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        };
        let Ok(body) = unpad(&plaintext) else {
            let source_pending = Self::pending_delete(pending_sequence, env.content_id());
            self.store.commit_plan(
                CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                    session: SessionTransition {
                        peer_device,
                        before: Some(&before),
                        after: &after,
                    },
                    message: None,
                    ephemeral: None,
                    media_transfers: &[],
                    media_objects: &[],
                    capabilities: None,
                    queue: &[],
                    content_id: env.content_id(),
                    received_at: now,
                    receipt_replay: false,
                    source_pending,
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            self.sessions.insert(peer_device, after);
            self.after_memory_replacement()?;
            return Ok(Consumed::DoneAtomic);
        };

        match env.kind {
            EnvelopeKind::Message => {
                if let DecodedContent::CallControl { control, .. } = decode_content(&body) {
                    if self.wake_collection_deadline.is_some() {
                        return Ok(Consumed::Later);
                    }
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    self.store.commit_plan(
                        CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            message: None,
                            ephemeral: None,
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            queue: &[],
                            content_id: env.content_id(),
                            received_at: now,
                            receipt_replay: false,
                            source_pending,
                            presentation_changed: env.retention_until.is_none(),
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                    if env.retention_until.is_none() {
                        self.apply_call_control(peer, peer_device, control, now, rng)?;
                    }
                    Ok(Consumed::DoneAtomic)
                } else {
                    let prepared =
                        self.prepare_inbound(peer, body, env.retention_until, now, rng)?;
                    let receipt_payload = ReceiptPayload {
                        acks: vec![env.content_id()],
                        nacks: Vec::new(),
                    }
                    .encode();
                    let receipt_queue = self.prepare_control_queue(
                        &mut after,
                        peer_device,
                        &receipt_payload,
                        now,
                        rng,
                    )?;
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    let presentation_changed = !prepared.events.is_empty()
                        || !prepared.attachment_updates.is_empty()
                        || prepared.ephemeral.is_some();
                    let receipt = self.store.commit_plan(
                        CommitPlan::PairwiseReceive(PairwiseReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            message: prepared.message.as_ref(),
                            ephemeral: prepared.ephemeral.as_ref(),
                            media_transfers: &prepared.media_transfers,
                            media_objects: &prepared.media_objects,
                            capabilities: None,
                            queue: &[receipt_queue],
                            content_id: env.content_id(),
                            received_at: now,
                            receipt_replay: true,
                            source_pending,
                            presentation_changed,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                    self.accept_commit_receipt(receipt, prepared.events);
                    for transfer in prepared.attachment_updates {
                        self.emit_attachment_update(&transfer)?;
                    }
                    Ok(Consumed::DoneAtomic)
                }
            }
            EnvelopeKind::Receipt => {
                if kult_protocol::is_attachment_bulk_record(&body) {
                    let control = DeferredControlRecord {
                        content_id: env.content_id(),
                        peer,
                        peer_device,
                        kind: DeferredControlKind::AttachmentBulk,
                        body,
                        received_at: now,
                    };
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &[],
                            queue: &[],
                            messages: &[],
                            deliveries: &[],
                            group_messages: &[],
                            groups: &[],
                            contact_devices: &[],
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous: None,
                            wake: None,
                            deferred_control: Some(&control),
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: false,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                } else if is_wake_capability_control(&body) {
                    let Ok(control) = WakeCapabilityControl::decode(&body) else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if control.sender_account != peer
                        || control.sender_device != peer_device
                        || control.recipient_account != self.account.ed
                        || control.recipient_device != self.device_id()
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let endpoints = self.store.contact_devices_for(&peer)?;
                    let Some(sender) = endpoints
                        .iter()
                        .find(|endpoint| endpoint.device == peer_device)
                    else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if sender.revoked_at.is_some()
                        || sender.manifest_generation != control.authority_generation
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let incoming = control
                        .capabilities
                        .iter()
                        .map(|capability| {
                            let provider = WakeProvider::new(
                                capability.origin.clone(),
                                capability.static_key,
                            )?;
                            if provider.provider_id()
                                != kult_protocol::wake_provider_id(
                                    capability.origin.as_bytes(),
                                    &capability.static_key,
                                )
                                .map_err(kult_transport::TransportError::Protocol)?
                                || capability.expires_at <= now
                                || capability.expires_at
                                    > now.saturating_add(WAKE_CAPABILITY_MAX_LIFETIME_SECS)
                            {
                                return Err(kult_transport::TransportError::UnsupportedHint);
                            }
                            WakeStoredCapability::new(
                                WakeCapabilityDirection::Remote,
                                capability.origin.clone(),
                                capability.static_key,
                                capability.capability.as_bytes().to_vec(),
                                capability.expires_at,
                            )
                            .map_err(|_| kult_transport::TransportError::UnsupportedHint)
                        })
                        .collect::<kult_transport::Result<Vec<_>>>();
                    let Ok(incoming) = incoming else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    let before_state = self
                        .store
                        .get_wake_service_state(&peer_device)?
                        .ok_or(NodeError::CorruptState)?;
                    if before_state.session_id != *before.session_id() {
                        return Err(NodeError::CorruptState);
                    }
                    let mut after_state = before_state.clone();
                    if after_state
                        .replace_direction(
                            WakeCapabilityDirection::Remote,
                            control.generation,
                            incoming,
                        )
                        .is_err()
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let conflict = after_state.remote_conflict_generation
                        == Some(control.generation)
                        && before_state != after_state;
                    let wake = (before_state != after_state).then_some(WakeServiceTransition {
                        peer_device,
                        before: &before_state,
                        after: &after_state,
                    });
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    let committed = self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &[],
                            queue: &[],
                            messages: &[],
                            deliveries: &[],
                            group_messages: &[],
                            groups: &[],
                            contact_devices: &[],
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous: None,
                            wake,
                            deferred_control: None,
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: conflict,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                    let events = conflict.then_some(Event::WakeConflict {
                        peer,
                        device: peer_device,
                        generation: control.generation,
                    });
                    self.accept_commit_receipt(committed, events);
                } else if is_rendezvous_provider_control(&body) {
                    let Ok(control) = RendezvousProviderControl::decode(&body) else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if control.account != peer || control.device != peer_device {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let endpoints = self.store.contact_devices_for(&peer)?;
                    let Some(sender) = endpoints
                        .iter()
                        .find(|endpoint| endpoint.device == peer_device)
                    else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if sender.revoked_at.is_some()
                        || sender.manifest_generation != control.authority_generation
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let incoming = control
                        .providers
                        .iter()
                        .map(|provider| {
                            RendezvousProvider::new(provider.origin.clone(), provider.static_key)
                        })
                        .collect::<kult_transport::Result<Vec<_>>>();
                    let Ok(incoming) = incoming else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };

                    let service_before = self.store.get_rendezvous_service_state(&peer_device)?;
                    let mut service_after = service_before.clone();
                    let mut provider_set_conflict = false;
                    if let Some(candidate) = service_after.as_mut() {
                        let mut current = candidate
                            .providers
                            .iter()
                            .filter(|provider| provider.lookup_enabled)
                            .map(|provider| {
                                (
                                    provider.provider_id,
                                    provider.origin.clone(),
                                    provider.static_key,
                                )
                            })
                            .collect::<Vec<_>>();
                        current.sort();
                        let mut proposed = incoming
                            .iter()
                            .map(|provider| {
                                (
                                    provider.provider_id(),
                                    provider.origin().to_owned(),
                                    provider.static_key(),
                                )
                            })
                            .collect::<Vec<_>>();
                        proposed.sort();
                        if control.generation < candidate.remote_provider_generation {
                            return self.commit_terminal_input(
                                env.content_id(),
                                pending_sequence,
                                rng,
                            );
                        }
                        if candidate
                            .remote_provider_conflict_generation
                            .is_some_and(|generation| control.generation <= generation)
                        {
                            return self.commit_terminal_input(
                                env.content_id(),
                                pending_sequence,
                                rng,
                            );
                        }
                        if control.generation == candidate.remote_provider_generation
                            && current != proposed
                        {
                            candidate.remote_provider_conflict_generation =
                                Some(control.generation);
                            for provider in &mut candidate.providers {
                                if provider.lookup_enabled {
                                    provider.lookup_enabled = false;
                                    provider.routes.clear();
                                    provider.routes_expires_at = 0;
                                }
                            }
                            provider_set_conflict = true;
                        }
                        if control.generation > candidate.remote_provider_generation {
                            candidate.remote_provider_generation = control.generation;
                            candidate.remote_provider_conflict_generation = None;
                            for provider in &mut candidate.providers {
                                provider.lookup_enabled = false;
                            }
                            for provider in &incoming {
                                candidate
                                    .provider_mut(
                                        provider.provider_id(),
                                        provider.origin().to_owned(),
                                        provider.static_key(),
                                    )?
                                    .lookup_enabled = true;
                            }
                            candidate.providers.retain(|provider| {
                                provider.publish_enabled || provider.lookup_enabled
                            });
                            candidate
                                .providers
                                .sort_by_key(|provider| provider.provider_id);
                        }
                    }

                    if provider_set_conflict {
                        let Some(before_state) = service_before.as_ref() else {
                            return Err(NodeError::CorruptState);
                        };
                        let Some(after_state) = service_after.as_ref() else {
                            return Err(NodeError::CorruptState);
                        };
                        let source_pending =
                            Self::pending_delete(pending_sequence, env.content_id());
                        let committed = self.store.commit_plan(
                            CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                                session: SessionTransition {
                                    peer_device,
                                    before: Some(&before),
                                    after: &after,
                                },
                                delete_queue: &[],
                                queue: &[],
                                messages: &[],
                                deliveries: &[],
                                group_messages: &[],
                                groups: &[],
                                contact_devices: &[],
                                media_transfers: &[],
                                media_objects: &[],
                                capabilities: None,
                                rendezvous: Some(RendezvousServiceTransition {
                                    peer_device,
                                    before: before_state,
                                    after: after_state,
                                }),
                                wake: None,
                                deferred_control: None,
                                content_id: env.content_id(),
                                source_pending,
                                presentation_changed: true,
                            }),
                            rng,
                        )?;
                        self.before_memory_replacement()?;
                        self.sessions.insert(peer_device, after);
                        self.rendezvous_refresh_requested.remove(&peer_device);
                        self.after_memory_replacement()?;
                        self.accept_commit_receipt(
                            committed,
                            [Event::RendezvousConflict {
                                peer,
                                device: peer_device,
                                provider: [0u8; 32],
                            }],
                        );
                        return Ok(Consumed::DoneAtomic);
                    }

                    let local_control = self.local_rendezvous_provider_control()?;
                    let advertise = local_control.is_some()
                        && !self.rendezvous_advertised.contains(&peer_device);
                    let response = local_control
                        .filter(|_| advertise)
                        .map(|control| {
                            self.prepare_control_queue(
                                &mut after,
                                peer_device,
                                &control.encode()?,
                                now,
                                rng,
                            )
                        })
                        .transpose()?;
                    let rendezvous = match (service_before.as_ref(), service_after.as_ref()) {
                        (Some(before_state), Some(after_state)) if before_state != after_state => {
                            Some(RendezvousServiceTransition {
                                peer_device,
                                before: before_state,
                                after: after_state,
                            })
                        }
                        _ => None,
                    };
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &[],
                            queue: response.as_slice(),
                            messages: &[],
                            deliveries: &[],
                            group_messages: &[],
                            groups: &[],
                            contact_devices: &[],
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous,
                            wake: None,
                            deferred_control: None,
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: false,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    if advertise {
                        self.rendezvous_advertised.insert(peer_device);
                    }
                    if service_before.is_none() && self.device_id() < peer_device {
                        self.rendezvous_rehandshake_requested.insert(peer_device);
                    }
                    if service_before != service_after {
                        self.rendezvous_refresh_requested.insert(peer_device);
                    }
                    self.after_memory_replacement()?;
                } else if is_discovery_upgrade_control(&body) {
                    let Ok(control) = DiscoveryUpgradeControl::decode(&body) else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if control.account != peer
                        || validate_discovery_upgrade_routes(&control.routes).is_err()
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let endpoints = self.store.contact_devices_for(&peer)?;
                    let Some(sender) = endpoints
                        .iter()
                        .find(|endpoint| endpoint.device == peer_device)
                    else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    };
                    if sender.revoked_at.is_some()
                        || sender.manifest_generation != control.authority_generation
                    {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                    let accepted_generation = endpoints
                        .iter()
                        .filter(|endpoint| endpoint.revoked_at.is_none())
                        .map(|endpoint| endpoint.introduction_generation)
                        .max()
                        .unwrap_or_default();
                    let conflicting = endpoints.iter().any(|endpoint| {
                        endpoint.revoked_at.is_none()
                            && endpoint.introduction_generation == control.generation
                            && endpoint
                                .introduction_capability
                                .is_some_and(|capability| capability != control.capability)
                    });
                    if control.generation < accepted_generation || conflicting {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }

                    let mut changed = Vec::new();
                    for before_endpoint in &endpoints {
                        if before_endpoint.revoked_at.is_some() {
                            continue;
                        }
                        let mut after_endpoint = before_endpoint.clone();
                        after_endpoint.introduction_capability = Some(control.capability);
                        after_endpoint.introduction_generation = control.generation;
                        if after_endpoint.device == peer_device && control.routes_complete {
                            after_endpoint.hints.clone_from(&control.routes);
                        }
                        if after_endpoint != *before_endpoint {
                            changed.push((before_endpoint.clone(), after_endpoint));
                        }
                    }
                    let transitions = changed
                        .iter()
                        .map(
                            |(before_endpoint, after_endpoint)| ContactDeviceTransition {
                                before: before_endpoint,
                                after: after_endpoint,
                            },
                        )
                        .collect::<Vec<_>>();
                    let advertise = !self.discovery_advertised.contains(&peer_device);
                    let response = advertise
                        .then(|| {
                            self.prepare_control_queue(
                                &mut after,
                                peer_device,
                                &self.local_discovery_upgrade()?.encode()?,
                                now,
                                rng,
                            )
                        })
                        .transpose()?;
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &[],
                            queue: response.as_slice(),
                            messages: &[],
                            deliveries: &[],
                            group_messages: &[],
                            groups: &[],
                            contact_devices: &transitions,
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous: None,
                            wake: None,
                            deferred_control: None,
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: !transitions.is_empty(),
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    if advertise {
                        self.discovery_advertised.insert(peer_device);
                    }
                    self.after_memory_replacement()?;
                } else if is_capability_control(&body) {
                    if let Ok(capabilities) = CapabilityControl::decode(&body) {
                        let advertise = !self.capabilities_advertised.contains(&peer_device);
                        let response = advertise
                            .then(|| {
                                self.prepare_control_queue(
                                    &mut after,
                                    peer_device,
                                    &Self::local_capabilities().encode()?,
                                    now,
                                    rng,
                                )
                            })
                            .transpose()?;
                        let source_pending =
                            Self::pending_delete(pending_sequence, env.content_id());
                        self.store.commit_plan(
                            CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                                session: SessionTransition {
                                    peer_device,
                                    before: Some(&before),
                                    after: &after,
                                },
                                delete_queue: &[],
                                queue: response.as_slice(),
                                messages: &[],
                                deliveries: &[],
                                group_messages: &[],
                                groups: &[],
                                contact_devices: &[],
                                media_transfers: &[],
                                media_objects: &[],
                                capabilities: Some(&capabilities),
                                rendezvous: None,
                                wake: None,
                                deferred_control: None,
                                content_id: env.content_id(),
                                source_pending,
                                presentation_changed: false,
                            }),
                            rng,
                        )?;
                        self.before_memory_replacement()?;
                        self.sessions.insert(peer_device, after);
                        if advertise {
                            self.capabilities_advertised.insert(peer_device);
                        }
                        self.after_memory_replacement()?;
                    } else {
                        return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                    }
                } else if let Ok(receipt) = ReceiptPayload::decode(&body) {
                    let prepared = self.prepare_receipt(&peer_device, &receipt, now)?;
                    let message_transitions = prepared
                        .messages
                        .iter()
                        .map(|(before, after)| MessageTransition { before, after })
                        .collect::<Vec<_>>();
                    let delivery_transitions = prepared
                        .deliveries
                        .iter()
                        .map(|(before, after)| kult_store::DeliveryTransition { before, after })
                        .collect::<Vec<_>>();
                    let group_message_transitions = prepared
                        .group_messages
                        .iter()
                        .map(|(before, after)| GroupMessageTransition { before, after })
                        .collect::<Vec<_>>();
                    let group_transitions = prepared
                        .groups
                        .iter()
                        .map(|(before, after)| GroupTransition { before, after })
                        .collect::<Vec<_>>();
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    let committed = self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &prepared.delete_queue,
                            queue: &prepared.queue,
                            messages: &message_transitions,
                            deliveries: &delivery_transitions,
                            group_messages: &group_message_transitions,
                            groups: &group_transitions,
                            contact_devices: &[],
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous: None,
                            wake: None,
                            deferred_control: None,
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: !prepared.events.is_empty(),
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                    let deleted = prepared
                        .delete_queue
                        .iter()
                        .map(|delete| delete.sequence)
                        .collect::<HashSet<_>>();
                    self.held_notified
                        .retain(|sequence| !deleted.contains(sequence));
                    self.call_queue_deadlines
                        .retain(|sequence, _| !deleted.contains(sequence));
                    self.accept_commit_receipt(committed, prepared.events);
                } else {
                    let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                    self.store.commit_plan(
                        CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                            session: SessionTransition {
                                peer_device,
                                before: Some(&before),
                                after: &after,
                            },
                            delete_queue: &[],
                            queue: &[],
                            messages: &[],
                            deliveries: &[],
                            group_messages: &[],
                            groups: &[],
                            contact_devices: &[],
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
                            rendezvous: None,
                            wake: None,
                            deferred_control: None,
                            content_id: env.content_id(),
                            source_pending,
                            presentation_changed: false,
                        }),
                        rng,
                    )?;
                    self.before_memory_replacement()?;
                    self.sessions.insert(peer_device, after);
                    self.after_memory_replacement()?;
                }
                Ok(Consumed::DoneAtomic)
            }
            EnvelopeKind::GroupControl => {
                let control = DeferredControlRecord {
                    content_id: env.content_id(),
                    peer,
                    peer_device,
                    kind: DeferredControlKind::GroupControl,
                    body,
                    received_at: now,
                };
                let (retain_control, invitation_event) = self.admit_group_control(&control)?;
                let source_pending = Self::pending_delete(pending_sequence, env.content_id());
                let receipt = self.store.commit_plan(
                    CommitPlan::ReceiptReceive(ReceiptReceivePlan {
                        session: SessionTransition {
                            peer_device,
                            before: Some(&before),
                            after: &after,
                        },
                        delete_queue: &[],
                        queue: &[],
                        messages: &[],
                        deliveries: &[],
                        group_messages: &[],
                        groups: &[],
                        contact_devices: &[],
                        media_transfers: &[],
                        media_objects: &[],
                        capabilities: None,
                        rendezvous: None,
                        wake: None,
                        deferred_control: retain_control.then_some(&control),
                        content_id: env.content_id(),
                        source_pending,
                        presentation_changed: invitation_event.is_some(),
                    }),
                    rng,
                )?;
                self.before_memory_replacement()?;
                self.sessions.insert(peer_device, after);
                self.after_memory_replacement()?;
                self.accept_commit_receipt(receipt, invitation_event);
                Ok(Consumed::DoneAtomic)
            }
            _ => unreachable!("consume() routes only Message/Receipt/GroupControl here"),
        }
    }

    fn prepare_inbound(
        &self,
        peer: [u8; 32],
        body: Vec<u8>,
        envelope_retention: Option<u64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedInbound> {
        let empty = || PreparedInbound {
            message: None,
            ephemeral: None,
            media_transfers: Vec::new(),
            media_objects: Vec::new(),
            events: Vec::new(),
            attachment_updates: Vec::new(),
        };
        let decoded = decode_content(&body);
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
        if envelope_retention != authenticated_retention {
            return Ok(empty());
        }
        let decoded_is_edit = matches!(decoded, DecodedContent::Edit { .. });
        if let DecodedContent::Text { id, .. }
        | DecodedContent::Attachment { id, .. }
        | DecodedContent::Mention { id, .. }
        | DecodedContent::Edit { id, .. }
        | DecodedContent::Ephemeral { id, .. }
        | DecodedContent::Poll { id, .. }
        | DecodedContent::GroupAuthority { id, .. } = decoded
        {
            let conversation = EphemeralConversation::Pairwise(peer);
            if self
                .store
                .get_ephemeral_record(&conversation, &peer, &id)?
                .is_some()
            {
                return Ok(empty());
            }
            let duplicate = self.store.messages_with(&peer)?.iter().any(|record| {
                record.direction == Direction::Inbound
                    && matches!(
                        decode_content(&record.body),
                        DecodedContent::Text { id: stored_id, .. }
                            | DecodedContent::Attachment { id: stored_id, .. }
                            | DecodedContent::Mention { id: stored_id, .. }
                            | DecodedContent::Edit { id: stored_id, .. }
                            | DecodedContent::Ephemeral { id: stored_id, .. }
                            | DecodedContent::Poll { id: stored_id, .. }
                            | DecodedContent::GroupAuthority { id: stored_id, .. }
                            if stored_id == id
                    )
            });
            if duplicate {
                return Ok(empty());
            }
        }

        let mut ephemeral = None;
        let mut media_transfers = Vec::new();
        let mut media_objects = Vec::new();
        let mut events = Vec::new();
        let mut attachment_updates = Vec::new();
        let (id, event_body, content, retain_message) = match decoded {
            DecodedContent::LegacyText(text) => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (
                    id,
                    text.as_bytes().to_vec(),
                    ContentStatus::LegacyText,
                    true,
                )
            }
            DecodedContent::Text { id, text } => (
                id,
                text.as_bytes().to_vec(),
                ContentStatus::Text { id },
                true,
            ),
            DecodedContent::Attachment { id, manifest } => {
                let (transfer, objects) =
                    self.prepare_pairwise_attachment_offer(peer, id, &manifest, now, rng)?;
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
                    true,
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
                true,
            ),
            DecodedContent::Edit { id, .. } => (id, Vec::new(), ContentStatus::Malformed, true),
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
                    conversation: EphemeralConversation::Pairwise(peer),
                    author: peer,
                    content_id: id,
                    expires_at,
                    mode: EphemeralMode::DisappearingText,
                    state,
                    transfer_ids: Vec::new(),
                });
                if state == EphemeralState::Expired {
                    events.push(Event::EphemeralRemoved {
                        conversation: EphemeralConversation::Pairwise(peer),
                        author: peer,
                        content_id: id,
                        reason: state,
                    });
                    (id, Vec::new(), ContentStatus::Malformed, false)
                } else {
                    (
                        id,
                        text.as_bytes().to_vec(),
                        ContentStatus::DisappearingText { id, expires_at },
                        true,
                    )
                }
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
                        conversation: EphemeralConversation::Pairwise(peer),
                        author: peer,
                        content_id: id,
                        expires_at,
                        mode: EphemeralMode::ViewOnceAttachment,
                        state: EphemeralState::Expired,
                        transfer_ids: Vec::new(),
                    });
                    events.push(Event::EphemeralRemoved {
                        conversation: EphemeralConversation::Pairwise(peer),
                        author: peer,
                        content_id: id,
                        reason: EphemeralState::Expired,
                    });
                    (id, Vec::new(), ContentStatus::Malformed, false)
                } else {
                    let (transfer, objects) =
                        self.prepare_pairwise_attachment_offer(peer, id, &manifest, now, rng)?;
                    let transfer_id = transfer.local_id;
                    media_transfers.push(transfer);
                    media_objects.extend(objects);
                    ephemeral = Some(EphemeralRecord {
                        conversation: EphemeralConversation::Pairwise(peer),
                        author: peer,
                        content_id: id,
                        expires_at,
                        mode: EphemeralMode::ViewOnceAttachment,
                        state: EphemeralState::Active,
                        transfer_ids: vec![transfer_id],
                    });
                    attachment_updates.push(transfer_id);
                    (
                        id,
                        Vec::new(),
                        ContentStatus::ViewOnceAttachment {
                            id,
                            transfer: transfer_id,
                            expires_at,
                        },
                        true,
                    )
                }
            }
            DecodedContent::Mention { .. }
            | DecodedContent::Poll { .. }
            | DecodedContent::GroupAuthority { .. } => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (id, Vec::new(), ContentStatus::Malformed, true)
            }
            DecodedContent::CallControl { .. } => return Ok(empty()),
            DecodedContent::Unsupported {
                format_version,
                kind,
            } => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (
                    id,
                    Vec::new(),
                    ContentStatus::Unsupported {
                        format_version,
                        kind,
                    },
                    true,
                )
            }
            DecodedContent::Malformed => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (id, Vec::new(), ContentStatus::Malformed, true)
            }
        };
        let message = retain_message.then_some(MessageRecord {
            id,
            peer,
            direction: Direction::Inbound,
            state: DeliveryState::Received,
            timestamp: now,
            body,
            wire_id: None,
        });
        if message.is_some() {
            match content {
                ContentStatus::Edit {
                    target_content_id, ..
                } => events.push(Event::MessageEdited {
                    peer,
                    target_content_id,
                }),
                ContentStatus::Malformed if decoded_is_edit => {}
                _ => events.push(Event::MessageReceived {
                    peer,
                    id,
                    timestamp: now,
                    body: event_body,
                    content,
                }),
            }
        }
        Ok(PreparedInbound {
            message,
            ephemeral,
            media_transfers,
            media_objects,
            events,
            attachment_updates,
        })
    }

    fn peer_supports_kind(&self, peer: &[u8; 32], kind: u16) -> Result<bool> {
        let endpoints = self.store.contact_devices_for(peer)?;
        if endpoints.is_empty() {
            return Ok(self.sessions.contains_key(peer)
                && self
                    .store
                    .get_capabilities(peer)?
                    .is_some_and(|capabilities| capabilities.supports(CONTENT_FORMAT_V1, kind)));
        }
        for endpoint in endpoints {
            if !self.sessions.contains_key(&endpoint.device)
                || !self
                    .store
                    .get_capabilities(&endpoint.device)?
                    .is_some_and(|capabilities| capabilities.supports(CONTENT_FORMAT_V1, kind))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn peer_has_live_device_sessions(&self, peer: &[u8; 32]) -> Result<bool> {
        let endpoints = self.store.contact_devices_for(peer)?;
        if endpoints.is_empty() {
            return Ok(self.sessions.contains_key(peer));
        }
        Ok(endpoints
            .iter()
            .all(|endpoint| self.sessions.contains_key(&endpoint.device)))
    }

    fn peer_has_session_or_bundle(&self, peer: &[u8; 32]) -> Result<bool> {
        let endpoints = self.store.contact_devices_for(peer)?;
        if endpoints.is_empty() {
            return Ok(self.sessions.contains_key(peer)
                || self
                    .store
                    .get_contact(peer)?
                    .is_some_and(|contact| !contact.bundle.is_empty()));
        }
        Ok(endpoints.iter().any(|endpoint| {
            self.sessions.contains_key(&endpoint.device) || !endpoint.bundle.is_empty()
        }))
    }

    fn peer_supports_text(&self, peer: &[u8; 32]) -> Result<bool> {
        self.peer_supports_kind(peer, CONTENT_KIND_TEXT)
    }

    fn local_capabilities() -> CapabilityControl {
        CapabilityControl {
            formats: vec![
                FormatCapabilities {
                    format_version: CONTENT_FORMAT_V1,
                    kinds: vec![
                        CONTENT_KIND_TEXT,
                        CONTENT_KIND_ATTACHMENT,
                        CONTENT_KIND_MENTION,
                        CONTENT_KIND_EDIT,
                        CONTENT_KIND_EPHEMERAL,
                        CONTENT_KIND_POLL,
                        CONTENT_KIND_GROUP_AUTHORITY,
                        CONTENT_KIND_CALL_CONTROL,
                    ],
                },
                FormatCapabilities {
                    format_version: kult_protocol::GROUP_ORIGIN_CAPABILITY_FORMAT,
                    kinds: vec![kult_protocol::GROUP_ORIGIN_CAPABILITY_KIND],
                },
            ],
        }
    }

    fn advertise_capabilities(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let due: Vec<[u8; 32]> = self
            .sessions
            .keys()
            .filter(|peer| !self.capabilities_advertised.contains(*peer))
            .copied()
            .collect();
        for peer in due {
            self.queue_capabilities(&peer, now, rng)?;
        }
        Ok(())
    }

    fn queue_capabilities(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if !self.commit_pairwise_control_send(
            peer,
            &Self::local_capabilities().encode()?,
            now,
            rng,
        )? {
            return Ok(());
        }
        self.capabilities_advertised.insert(*peer);
        Ok(())
    }

    fn local_discovery_upgrade(&self) -> Result<DiscoveryUpgradeControl> {
        let mut routes = if self.own_hints_authoritative {
            encode_hints(&self.own_hints)
        } else {
            Vec::new()
        };
        routes.sort();
        routes.dedup();
        let control = DiscoveryUpgradeControl {
            account: self.account.ed,
            capability: self.device_state.discovery.capability,
            generation: self.device_state.discovery.generation,
            authority_generation: self.device_state.manifest.generation(),
            routes_complete: self.own_hints_authoritative,
            routes,
        };
        // Encoding is the single canonical bound check used by both
        // proactive advertisements and transactional responses.
        control.encode()?;
        Ok(control)
    }

    fn local_rendezvous_provider_control(&self) -> Result<Option<RendezvousProviderControl>> {
        if self.rendezvous_provider_generation == 0 {
            return Ok(None);
        }
        let mut providers = self
            .rendezvous_providers
            .iter()
            .map(|provider| RendezvousProviderDescriptor {
                origin: provider.origin().to_owned(),
                static_key: provider.static_key(),
            })
            .collect::<Vec<_>>();
        providers.sort();
        let control = RendezvousProviderControl {
            account: self.account.ed,
            device: self.device_id(),
            authority_generation: self.device_state.manifest.generation(),
            generation: self.rendezvous_provider_generation,
            providers,
        };
        control.encode()?;
        Ok(Some(control))
    }

    fn advertise_rendezvous_providers(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(payload) = self
            .local_rendezvous_provider_control()?
            .map(|control| control.encode())
            .transpose()?
        else {
            return Ok(());
        };
        let due = self
            .sessions
            .keys()
            .filter(|peer| !self.rendezvous_advertised.contains(*peer))
            .copied()
            .collect::<Vec<_>>();
        for peer in due {
            if self.commit_pairwise_control_send(&peer, &payload, now, rng)? {
                self.rendezvous_advertised.insert(peer);
            }
        }
        Ok(())
    }

    fn synchronize_rendezvous_provider_roles(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let configured = self.rendezvous_providers.clone();
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        for peer_device in devices {
            let Some(before) = self.store.get_rendezvous_service_state(&peer_device)? else {
                continue;
            };
            let mut after = before.clone();
            let configured_ids = configured
                .iter()
                .map(RendezvousProvider::provider_id)
                .collect::<HashSet<_>>();
            for state in &mut after.providers {
                if state.publish_enabled && !configured_ids.contains(&state.provider_id) {
                    state.publish_enabled = false;
                    state.withdrawal_pending = state.publish_generation > 0;
                    state.next_register_at = now;
                }
            }
            for provider in &configured {
                let state = after.provider_mut(
                    provider.provider_id(),
                    provider.origin().to_owned(),
                    provider.static_key(),
                )?;
                state.publish_enabled = true;
                state.withdrawal_pending = false;
                if state.next_register_at == 0 {
                    state.next_register_at = now.saturating_add(rendezvous_jitter(rng));
                }
            }
            after.providers.retain(|provider| {
                provider.publish_enabled || provider.lookup_enabled || provider.withdrawal_pending
            });
            after.providers.sort_by_key(|provider| provider.provider_id);
            if after != before {
                self.store
                    .put_rendezvous_service_state(&peer_device, &after, rng)?;
            }
        }
        Ok(())
    }

    fn mark_rendezvous_publication_dirty(&mut self, rng: &mut impl CryptoRngCore) -> Result<()> {
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        for peer_device in devices {
            let Some(mut state) = self.store.get_rendezvous_service_state(&peer_device)? else {
                continue;
            };
            let before = state.clone();
            for provider in &mut state.providers {
                if provider.publish_enabled || provider.withdrawal_pending {
                    provider.next_register_at = 0;
                    provider.circuit_open_until = 0;
                    provider.consecutive_failures = 0;
                }
            }
            if state != before {
                self.store
                    .put_rendezvous_service_state(&peer_device, &state, rng)?;
            }
        }
        Ok(())
    }

    async fn maintain_rendezvous(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        self.synchronize_rendezvous_provider_roles(now, rng)?;
        let Some(client) = self.rendezvous_client.clone() else {
            return Ok(());
        };
        let deadline = Instant::now() + RENDEZVOUS_MAINTENANCE_BUDGET;
        let mut operations_left = MAX_RENDEZVOUS_OPERATIONS_PER_TICK;

        let mut registrations = Vec::new();
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        for peer_device in &devices {
            let Some(state) = self.store.get_rendezvous_service_state(peer_device)? else {
                continue;
            };
            for provider in &state.providers {
                if (provider.publish_enabled || provider.withdrawal_pending)
                    && provider.next_register_at <= now
                    && provider.circuit_open_until <= now
                    && (!provider.publish_enabled || self.own_hints_authoritative)
                {
                    let Ok(provider) =
                        RendezvousProvider::new(provider.origin.clone(), provider.static_key)
                    else {
                        continue;
                    };
                    registrations.push((*peer_device, provider));
                }
            }
        }
        registrations.sort_by_key(|(device, provider)| (*device, provider.provider_id()));
        for (peer_device, provider) in registrations {
            if operations_left < 3 || Instant::now() >= deadline {
                break;
            }
            self.maintain_rendezvous_registration(
                &client,
                peer_device,
                &provider,
                now,
                deadline,
                &mut operations_left,
                rng,
            )
            .await?;
        }

        let mut requested = self.rendezvous_refresh_requested.clone();
        for (_, item) in self.store.queue_all()? {
            if !self.has_fresh_relationship_route(&item.peer, now)? {
                requested.insert(item.peer);
            }
        }
        requested.extend(self.active_conversation_rendezvous_devices()?);
        requested.extend(self.active_rendezvous_devices()?);
        let mut lookups = requested.into_iter().collect::<Vec<_>>();
        lookups.sort_unstable();
        for peer_device in lookups {
            if operations_left < 3 || Instant::now() >= deadline {
                break;
            }
            let Some(state) = self.store.get_rendezvous_service_state(&peer_device)? else {
                self.rendezvous_refresh_requested.remove(&peer_device);
                continue;
            };
            let peer_identity = match self.rendezvous_peer_identity(&peer_device) {
                Ok(identity) => identity,
                Err(_) => {
                    self.rendezvous_refresh_requested.remove(&peer_device);
                    continue;
                }
            };
            let explicitly_requested = self.rendezvous_refresh_requested.contains(&peer_device);
            let mut providers = state
                .providers
                .iter()
                .filter(|provider| {
                    provider.lookup_enabled
                        && (explicitly_requested || provider.next_lookup_at <= now)
                        && provider.circuit_open_until <= now
                })
                .filter_map(|provider| {
                    RendezvousProvider::new(provider.origin.clone(), provider.static_key).ok()
                })
                .collect::<Vec<_>>();
            providers.sort_by_key(RendezvousProvider::provider_id);
            for provider in providers {
                if operations_left < 3 || Instant::now() >= deadline {
                    break;
                }
                self.maintain_rendezvous_lookup(
                    &client,
                    peer_device,
                    &peer_identity,
                    &provider,
                    explicitly_requested,
                    now,
                    deadline,
                    &mut operations_left,
                    rng,
                )
                .await?;
            }
            self.rendezvous_refresh_requested.remove(&peer_device);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // fixed provider operation context
    async fn maintain_rendezvous_registration(
        &mut self,
        client: &Arc<dyn RendezvousClient>,
        peer_device: [u8; 32],
        provider: &RendezvousProvider,
        now: u64,
        deadline: Instant,
        operations_left: &mut usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let operation = (
            peer_device,
            provider.provider_id(),
            RendezvousOperationKind::Register,
        );
        if !self.rendezvous_inflight.insert(operation) {
            return Ok(());
        }
        let result = self
            .try_rendezvous_registration(
                client,
                peer_device,
                provider,
                now,
                deadline,
                operations_left,
                rng,
            )
            .await;
        self.rendezvous_inflight.remove(&operation);
        result
    }

    #[allow(clippy::too_many_arguments)] // fixed provider operation context
    async fn try_rendezvous_registration(
        &mut self,
        client: &Arc<dyn RendezvousClient>,
        peer_device: [u8; 32],
        provider: &RendezvousProvider,
        now: u64,
        deadline: Instant,
        operations_left: &mut usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(mut state) = self.store.get_rendezvous_service_state(&peer_device)? else {
            return Ok(());
        };
        let Some(provider_state) = state
            .providers
            .iter_mut()
            .find(|state| state.provider_id == provider.provider_id())
        else {
            return Ok(());
        };
        if provider_state.next_register_at > now
            || provider_state.circuit_open_until > now
            || (!provider_state.publish_enabled && !provider_state.withdrawal_pending)
        {
            return Ok(());
        }
        let withdrawal = !provider_state.publish_enabled && provider_state.withdrawal_pending;
        let generation = provider_state
            .publish_generation
            .checked_add(1)
            .ok_or(NodeError::RendezvousUnavailable)?
            .max(self.rendezvous_provider_generation.max(1));
        provider_state.publish_generation = generation;
        // The reserved generation remains due until success/failure below is
        // durably recorded. A process interruption therefore skips, rather
        // than reuses, a generation.
        self.store
            .put_rendezvous_service_state(&peer_device, &state, rng)?;

        let mut routes = if withdrawal {
            Vec::new()
        } else {
            self.own_hints
                .iter()
                .filter_map(|hint| rendezvous_record_route(hint).ok())
                .collect::<Vec<_>>()
        };
        routes.sort();
        routes.dedup();
        routes.truncate(kult_protocol::MAX_RENDEZVOUS_ROUTES);
        let exporter = state.hybrid_service_exporter;
        let local_recipient = self.device_identity.public();
        let current_epoch = rendezvous_epoch(now);
        let expires_at = now.saturating_add(u64::from(RENDEZVOUS_MAX_TTL_SECS));

        let attempted = async {
            let mut current_record = None;
            for epoch in [current_epoch, current_epoch.saturating_add(1)] {
                if *operations_left == 0 || Instant::now() >= deadline {
                    return Ok::<bool, NodeError>(false);
                }
                let keys = derive_rendezvous_epoch_keys(
                    &exporter,
                    &provider.provider_id(),
                    &local_recipient,
                    epoch,
                )?;
                let record = RendezvousRouteRecord {
                    epoch,
                    generation,
                    issued_at: now,
                    expires_at,
                    routes: routes.clone(),
                };
                let plaintext = record.encode()?;
                let request = RendezvousRegisterRequest {
                    slot: keys.slot(),
                    epoch,
                    ttl_seconds: RENDEZVOUS_MAX_TTL_SECS,
                    sealed_record: seal_rendezvous_record(&keys, &plaintext, rng),
                };
                *operations_left -= 1;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero()
                    || !matches!(
                        before_timeout(remaining, client.register(provider, &request)).await,
                        Some(Ok(_))
                    )
                {
                    return Ok(false);
                }
                if epoch == current_epoch {
                    current_record = Some((keys, record));
                }
            }

            // A fixed acknowledgement only confirms that the service handled
            // a body. Registration is successful solely when the endpoint can
            // retrieve and authenticate its exact current record.
            let Some((keys, expected)) = current_record else {
                return Ok(false);
            };
            if *operations_left == 0 || Instant::now() >= deadline {
                return Ok(false);
            }
            let request = RendezvousLookupRequest {
                slot: keys.slot(),
                epoch: current_epoch,
            };
            *operations_left -= 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(Ok(sealed)) =
                before_timeout(remaining, client.lookup(provider, &request)).await
            else {
                return Ok(false);
            };
            let plaintext = open_rendezvous_record(&keys, &sealed)?;
            let observed = RendezvousRouteRecord::decode(plaintext.as_ref())?;
            observed.validate_acceptance(current_epoch, now, 0, generation)?;
            Ok(observed == expected)
        }
        .await
        .unwrap_or(false);

        let Some(mut state) = self.store.get_rendezvous_service_state(&peer_device)? else {
            return Ok(());
        };
        if let Some(provider_state) = state
            .providers
            .iter_mut()
            .find(|state| state.provider_id == provider.provider_id())
        {
            if attempted {
                provider_state.registration_confirmed_at = now;
                provider_state.consecutive_failures = 0;
                provider_state.circuit_open_until = 0;
                provider_state.withdrawal_pending = false;
                provider_state.next_register_at = if provider_state.publish_enabled {
                    now.saturating_add(RENDEZVOUS_REGISTER_REFRESH_SECS)
                        .saturating_add(rendezvous_jitter(rng))
                } else {
                    0
                };
            } else {
                note_rendezvous_failure(provider_state, RendezvousOperationKind::Register, now);
            }
        }
        state.providers.retain(|provider| {
            provider.publish_enabled || provider.lookup_enabled || provider.withdrawal_pending
        });
        self.store
            .put_rendezvous_service_state(&peer_device, &state, rng)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // fixed provider operation context
    async fn maintain_rendezvous_lookup(
        &mut self,
        client: &Arc<dyn RendezvousClient>,
        peer_device: [u8; 32],
        peer_identity: &IdentityPublic,
        provider: &RendezvousProvider,
        force: bool,
        now: u64,
        deadline: Instant,
        operations_left: &mut usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let operation = (
            peer_device,
            provider.provider_id(),
            RendezvousOperationKind::Lookup,
        );
        if !self.rendezvous_inflight.insert(operation) {
            return Ok(());
        }
        let result = self
            .try_rendezvous_lookup(
                client,
                peer_device,
                peer_identity,
                provider,
                force,
                now,
                deadline,
                operations_left,
                rng,
            )
            .await;
        self.rendezvous_inflight.remove(&operation);
        result
    }

    #[allow(clippy::too_many_arguments)] // fixed provider operation context
    async fn try_rendezvous_lookup(
        &mut self,
        client: &Arc<dyn RendezvousClient>,
        peer_device: [u8; 32],
        peer_identity: &IdentityPublic,
        provider: &RendezvousProvider,
        force: bool,
        now: u64,
        deadline: Instant,
        operations_left: &mut usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(state) = self.store.get_rendezvous_service_state(&peer_device)? else {
            return Ok(());
        };
        let Some(provider_state) = state
            .providers
            .iter()
            .find(|state| state.provider_id == provider.provider_id())
        else {
            return Ok(());
        };
        if !provider_state.lookup_enabled
            || (!force && provider_state.next_lookup_at > now)
            || provider_state.circuit_open_until > now
        {
            return Ok(());
        }
        let exporter = state.hybrid_service_exporter;
        let clock_floor = provider_state.clock_floor;
        let accepted_generation = provider_state.accepted_generation;
        let conflict_floor = provider_state.conflict_generation;
        let accepted_routes_expires_at = provider_state.routes_expires_at;
        let accepted_routes = provider_state.routes.clone();
        let current_epoch = rendezvous_epoch(now);
        let Some(previous_epoch) = current_epoch.checked_sub(1) else {
            return Ok(());
        };
        let Some(next_epoch) = current_epoch.checked_add(1) else {
            return Ok(());
        };
        let mut candidates = Vec::new();
        for epoch in [previous_epoch, current_epoch, next_epoch] {
            if *operations_left == 0 || Instant::now() >= deadline {
                break;
            }
            let Ok(keys) = derive_rendezvous_epoch_keys(
                &exporter,
                &provider.provider_id(),
                peer_identity,
                epoch,
            ) else {
                continue;
            };
            let request = RendezvousLookupRequest {
                slot: keys.slot(),
                epoch,
            };
            *operations_left -= 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(Ok(sealed)) =
                before_timeout(remaining, client.lookup(provider, &request)).await
            else {
                continue;
            };
            let Ok(plaintext) = open_rendezvous_record(&keys, &sealed) else {
                continue;
            };
            let Ok(record) = RendezvousRouteRecord::decode(plaintext.as_ref()) else {
                continue;
            };
            if record
                .validate_acceptance(epoch, now, clock_floor, accepted_generation)
                .is_err()
            {
                continue;
            }
            let mut stored = Vec::with_capacity(record.routes.len());
            let mut valid_routes = true;
            for route in &record.routes {
                if rendezvous_route_hint(route).is_err() {
                    valid_routes = false;
                    break;
                }
                match RendezvousStoredRoute::new(route.kind, route.value.as_bytes()) {
                    Ok(route) => stored.push(route),
                    Err(_) => {
                        valid_routes = false;
                        break;
                    }
                }
            }
            if valid_routes {
                candidates.push((record, stored));
            }
        }

        if let Some(floor) = conflict_floor {
            candidates.retain(|(record, _)| record.generation > floor);
        }
        let mut conflict_generation = candidates
            .iter()
            .filter(|(record, stored)| {
                record.generation == accepted_generation
                    && accepted_generation != 0
                    && if accepted_routes.is_empty() {
                        !stored.is_empty()
                    } else {
                        stored != &accepted_routes
                            || record.expires_at != accepted_routes_expires_at
                    }
            })
            .map(|(record, _)| record.generation)
            .max();
        for left in 0..candidates.len() {
            for right in left + 1..candidates.len() {
                let left_record = &candidates[left].0;
                let right_record = &candidates[right].0;
                if left_record.generation == right_record.generation
                    && (left_record.expires_at != right_record.expires_at
                        || left_record.routes != right_record.routes)
                {
                    conflict_generation =
                        Some(conflict_generation.unwrap_or(0).max(left_record.generation));
                }
            }
        }
        let selected = if conflict_generation.is_some() {
            None
        } else {
            candidates
                .into_iter()
                .max_by_key(|(record, _)| (record.generation, record.issued_at, record.epoch))
        };

        let Some(mut state) = self.store.get_rendezvous_service_state(&peer_device)? else {
            return Ok(());
        };
        if let Some(provider_state) = state
            .providers
            .iter_mut()
            .find(|state| state.provider_id == provider.provider_id())
        {
            if let Some(generation) = conflict_generation {
                provider_state.conflict_generation = Some(
                    provider_state
                        .conflict_generation
                        .unwrap_or(0)
                        .max(generation),
                );
                provider_state.routes.clear();
                provider_state.routes_expires_at = 0;
                note_rendezvous_failure(provider_state, RendezvousOperationKind::Lookup, now);
            } else if let Some((record, stored)) = selected {
                provider_state.accepted_generation = record.generation;
                provider_state.conflict_generation = None;
                provider_state.clock_floor = provider_state.clock_floor.max(now);
                provider_state.routes_expires_at = if stored.is_empty() {
                    0
                } else {
                    record.expires_at
                };
                provider_state.routes = stored;
                provider_state.consecutive_failures = 0;
                provider_state.circuit_open_until = 0;
                provider_state.next_lookup_at = if provider_state.routes_expires_at == 0 {
                    now.saturating_add(RENDEZVOUS_REGISTER_REFRESH_SECS)
                        .saturating_add(rendezvous_jitter(rng))
                } else {
                    provider_state
                        .routes_expires_at
                        .saturating_sub(RENDEZVOUS_NEAR_EXPIRY_SECS)
                        .max(now.saturating_add(RENDEZVOUS_BACKOFF_MIN_SECS))
                };
            } else {
                if provider_state.routes_expires_at <= now {
                    provider_state.routes.clear();
                    provider_state.routes_expires_at = 0;
                }
                note_rendezvous_failure(provider_state, RendezvousOperationKind::Lookup, now);
            }
        }
        self.store
            .put_rendezvous_service_state(&peer_device, &state, rng)?;
        if conflict_generation.is_some() {
            self.events.push_back(Event::RendezvousConflict {
                peer: self.account_for_device(&peer_device)?,
                device: peer_device,
                provider: provider.provider_id(),
            });
        }
        Ok(())
    }

    fn rendezvous_peer_identity(&self, peer_device: &[u8; 32]) -> Result<IdentityPublic> {
        let endpoint = self
            .store
            .contact_devices()?
            .into_iter()
            .find(|endpoint| {
                endpoint.device == *peer_device
                    && endpoint.revoked_at.is_none()
                    && !endpoint.certificate.is_empty()
            })
            .ok_or(NodeError::RendezvousUnavailable)?;
        let (certificate, remainder): (DeviceAuthorityCertificate, &[u8]) =
            postcard::take_from_bytes(&endpoint.certificate)
                .map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty()
            || certificate.verify().is_err()
            || certificate.account.ed != endpoint.account
            || certificate.device_id() != endpoint.device
        {
            return Err(NodeError::CorruptState);
        }
        Ok(certificate.device)
    }

    fn has_fresh_relationship_route(&self, peer_device: &[u8; 32], now: u64) -> Result<bool> {
        if !self.base_hints_for(peer_device)?.is_empty() {
            return Ok(true);
        }
        Ok(self
            .store
            .get_rendezvous_service_state(peer_device)?
            .is_some_and(|state| {
                state.providers.iter().any(|provider| {
                    provider.lookup_enabled
                        && provider.routes_expires_at > now
                        && !provider.routes.is_empty()
                })
            }))
    }

    fn active_conversation_rendezvous_devices(&self) -> Result<Vec<[u8; 32]>> {
        let mut devices = Vec::new();
        for peer in &self.rendezvous_active_conversations {
            let endpoints = self.store.contact_devices_for(peer)?;
            if endpoints.is_empty() {
                if self.store.get_contact(peer)?.is_some() {
                    devices.push(*peer);
                }
            } else {
                devices.extend(
                    endpoints
                        .into_iter()
                        .filter(|endpoint| endpoint.revoked_at.is_none())
                        .map(|endpoint| endpoint.device),
                );
            }
        }
        devices.sort_unstable();
        devices.dedup();
        Ok(devices)
    }

    fn advertise_discovery_upgrades(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let due = self
            .sessions
            .keys()
            .filter(|peer| !self.discovery_advertised.contains(*peer))
            .copied()
            .collect::<Vec<_>>();
        if due.is_empty() {
            return Ok(());
        }
        let payload = self.local_discovery_upgrade()?.encode()?;
        for peer in due {
            if self.commit_pairwise_control_send(&peer, &payload, now, rng)? {
                self.discovery_advertised.insert(peer);
            }
        }
        Ok(())
    }

    fn commit_pairwise_control_send(
        &mut self,
        peer: &[u8; 32],
        payload: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        if !self.sessions.contains_key(peer) {
            return Ok(false);
        }
        self.commit_pairwise_envelopes(
            &[*peer],
            &pad(payload)?,
            EnvelopeKind::Receipt,
            QueueClass::Normal,
            None,
            now,
            rng,
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)] // bounded sealed-control fan-out inputs
    pub(crate) fn commit_pairwise_envelopes(
        &mut self,
        devices: &[[u8; 32]],
        padded: &[u8],
        kind: EnvelopeKind,
        class: QueueClass,
        retention_until: Option<u64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<CommittedPairwiseEnvelope>> {
        self.commit_pairwise_envelopes_with_effects(
            devices,
            padded,
            kind,
            class,
            retention_until,
            &[],
            &[],
            &[],
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // exact crypto and durable consequence boundary
    pub(crate) fn commit_pairwise_envelopes_with_effects(
        &mut self,
        devices: &[[u8; 32]],
        padded: &[u8],
        kind: EnvelopeKind,
        class: QueueClass,
        retention_until: Option<u64>,
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<CommittedPairwiseEnvelope>> {
        self.commit_pairwise_payloads_with_effects(
            devices,
            &[padded],
            kind,
            class,
            retention_until,
            media_transfers,
            media_objects,
            delete_controls,
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // exact crypto and durable consequence boundary
    pub(crate) fn commit_pairwise_payloads_with_effects(
        &mut self,
        devices: &[[u8; 32]],
        padded_payloads: &[&[u8]],
        kind: EnvelopeKind,
        class: QueueClass,
        retention_until: Option<u64>,
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<CommittedPairwiseEnvelope>> {
        let mut routes = devices.to_vec();
        routes.sort_unstable();
        routes.dedup();
        if routes.is_empty()
            || routes.len() > kult_store::MAX_PAIRWISE_COMMIT_DEVICES
            || padded_payloads.is_empty()
        {
            return Err(NodeError::NoSession);
        }
        let mut prepared = Vec::with_capacity(routes.len());
        let mut queue = Vec::with_capacity(routes.len().saturating_mul(padded_payloads.len()));
        for device in routes {
            let before = self
                .sessions
                .get(&device)
                .cloned()
                .ok_or(NodeError::NoSession)?;
            let mut after = before.clone();
            let mut final_envelope = None;
            for padded in padded_payloads {
                let message = self.candidate_encrypt(&mut after, rng, now, padded)?;
                let token = delivery_token(
                    &MailboxKey::from_bytes(*after.mailbox_key()),
                    epoch_day(now),
                    &device,
                );
                let envelope = match retention_until {
                    Some(deadline) => {
                        Envelope::new_retained(kind, token, deadline, message.encode())?
                    }
                    None => Envelope::new(kind, token, message.encode()),
                };
                queue.push(QueueItem {
                    peer: device,
                    msg_id: None,
                    group_msg_id: None,
                    class,
                    created_at: now,
                    attempts: 0,
                    next_attempt_at: now,
                    envelope: envelope.clone(),
                });
                final_envelope = Some(envelope);
            }
            prepared.push(PreparedPairwiseRoute {
                route: device,
                before: Some(before),
                after,
                envelope: final_envelope.expect("payloads are non-empty"),
                resets_capabilities: false,
            });
        }
        let transitions = prepared
            .iter()
            .map(|route| SessionTransition {
                peer_device: route.route,
                before: route.before.as_ref(),
                after: &route.after,
            })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::PairwiseSend(PairwiseSendPlan {
                sessions: &transitions,
                message: None,
                message_update: None,
                deliveries: &[],
                delivery_updates: &[],
                queue: &queue,
                groups: &[],
                authorities: &[],
                scheduled: None,
                clear_capabilities: &[],
                clear_reset_markers: &[],
                ephemeral: None,
                media_transfers,
                media_objects,
                delete_controls,
                wake: &[],
                presentation_changed: !media_transfers.is_empty() || !media_objects.is_empty(),
            }),
            rng,
        )?;
        let committed = receipt
            .records
            .queue_sequences
            .iter()
            .map(|sequence| CommittedPairwiseEnvelope {
                sequence: *sequence,
            })
            .collect::<Vec<_>>();
        self.before_memory_replacement()?;
        for route in prepared {
            self.sessions.insert(route.route, route.after);
        }
        self.after_memory_replacement()?;
        self.accept_commit_receipt(receipt, []);
        Ok(committed)
    }

    fn prepare_receipt(
        &self,
        peer_device: &[u8; 32],
        receipt: &ReceiptPayload,
        now: u64,
    ) -> Result<PreparedReceipt> {
        let peer = self.account_for_device(peer_device)?;
        let acked = |wire_id: &[u8; 16]| {
            receipt
                .acks
                .iter()
                .any(|ack| bool::from(ack.ct_eq(wire_id)))
        };
        let delete_queue = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(sequence, item)| {
                let content_id = item.envelope.content_id();
                (item.peer == *peer_device && acked(&content_id)).then_some(QueueDelete {
                    sequence,
                    content_id,
                })
            })
            .collect::<Vec<_>>();
        let mut queue = Vec::new();
        // Selective retransmission (docs/05-transports.md §4.2 rule 2):
        // re-queue exactly the missing fragment indices, never the whole
        // message — and only if the NACK comes from the peer the fragments
        // were addressed to, so no one else can elicit retransmissions.
        // A stale NACK crossing a retransmission in flight re-queues
        // duplicates; the receiver's content-id dedup absorbs them.
        for (id, indices) in &receipt.nacks {
            let Some(cached) = self.frag_cache.get(id) else {
                continue; // expired or evicted — the full-message retry path remains
            };
            if !bool::from(cached.peer.ct_eq(peer_device)) {
                continue;
            }
            for &i in indices {
                let Some(body) = cached.bodies.get(usize::from(i)) else {
                    continue;
                };
                let envelope = match cached.retention_until {
                    Some(deadline) if deadline > now => Envelope::new_retained(
                        EnvelopeKind::Fragment,
                        cached.token,
                        deadline,
                        body.clone(),
                    )?,
                    Some(_) => continue,
                    None => Envelope::new(EnvelopeKind::Fragment, cached.token, body.clone()),
                };
                if queue.len() == kult_store::MAX_COMMIT_QUEUE_ROWS {
                    break;
                }
                queue.push(QueueItem {
                    peer: *peer_device,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Normal,
                    created_at: now,
                    attempts: 0,
                    next_attempt_at: now,
                    envelope,
                });
            }
        }

        let mut messages = Vec::new();
        let mut deliveries = Vec::new();
        let mut group_messages = Vec::new();
        let mut groups = Vec::new();
        let mut events = Vec::new();
        let records = self.store.messages_with(&peer)?;
        for record in records {
            let mut device_acked = false;
            for before_delivery in self.store.message_device_deliveries(&record.id)? {
                if before_delivery.device == *peer_device
                    && before_delivery.wire_id.as_ref().is_some_and(acked)
                    && before_delivery.state != DeliveryState::Delivered
                {
                    let mut after_delivery = before_delivery.clone();
                    after_delivery.state = DeliveryState::Delivered;
                    deliveries.push((before_delivery, after_delivery));
                    device_acked = true;
                }
            }
            let legacy_acked = record.wire_id.as_ref().is_some_and(acked);
            if (device_acked || legacy_acked)
                && record.direction == Direction::Outbound
                && record.state != DeliveryState::Delivered
            {
                let mut after_record = record.clone();
                after_record.state = DeliveryState::Delivered;
                events.push(Event::DeliveryUpdated {
                    id: after_record.id,
                    state: DeliveryState::Delivered,
                });
                messages.push((record, after_record));
            }
        }

        if !receipt.acks.is_empty() {
            for before_group in self.store.groups()? {
                let mut after_group = before_group.clone();
                after_group.pending.retain(|pending| {
                    !(pending.peer == peer && pending.wire_id.as_ref().is_some_and(acked))
                });
                if let Some(origin_after) =
                    self.prepare_group_origin_ack(&after_group, &peer, peer_device, &receipt.acks)?
                {
                    after_group = origin_after;
                }
                if after_group != before_group {
                    groups.push((before_group, after_group));
                }
            }
            for before_message in self.store.all_group_messages()? {
                let mut device_acked = false;
                for before_delivery in self.store.message_device_deliveries(&before_message.id)? {
                    if before_delivery.account == peer
                        && before_delivery.device == *peer_device
                        && before_delivery.wire_id.as_ref().is_some_and(acked)
                        && before_delivery.state != DeliveryState::Delivered
                    {
                        let mut after_delivery = before_delivery.clone();
                        after_delivery.state = DeliveryState::Delivered;
                        deliveries.push((before_delivery, after_delivery));
                        device_acked = true;
                    }
                }
                let mut after_message = before_message.clone();
                let mut changed = false;
                for delivery in &mut after_message.deliveries {
                    if delivery.peer == peer
                        && delivery.state != DeliveryState::Delivered
                        && (device_acked || delivery.wire_id.as_ref().is_some_and(acked))
                    {
                        delivery.state = DeliveryState::Delivered;
                        changed = true;
                    }
                }
                if changed {
                    events.push(Event::GroupDeliveryUpdated {
                        id: before_message.id,
                        peer,
                        state: DeliveryState::Delivered,
                    });
                    group_messages.push((before_message, after_message));
                }
            }
        }
        Ok(PreparedReceipt {
            delete_queue,
            queue,
            messages,
            deliveries,
            group_messages,
            groups,
            events,
        })
    }

    /// Which session (if any) recognizes this delivery token, scanning a
    /// window of daily epochs so long-latency carriers still route. Tokens
    /// are recipient-scoped (ADR-0007), so only envelopes addressed to *this*
    /// node match — never multipath echoes of our own outbound.
    fn match_session(&self, token: &[u8; 32], now: u64) -> Option<[u8; 32]> {
        let me = self.account.ed;
        let device = self.device_id();
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        for (peer, session) in &self.sessions {
            let key = MailboxKey::from_bytes(*session.mailbox_key());
            for epoch in lo..=hi {
                if bool::from(delivery_token(&key, epoch, &me).ct_eq(token)) {
                    return Some(*peer);
                }
                if device != me && bool::from(delivery_token(&key, epoch, &device).ct_eq(token)) {
                    return Some(*peer);
                }
            }
        }
        None
    }

    /// Whether this delivery token addresses *this* node at all: a session
    /// token some ratchet recognizes, or one of our own introduction tokens
    /// (an inbound handshake) over the same epoch window. The bridging
    /// foreignness test (ADR-0009) — everything it cannot claim is transit.
    fn token_is_mine(&self, token: &[u8; 32], now: u64) -> bool {
        if self.match_session(token, now).is_some() {
            return true;
        }
        let me = self.account.ed;
        let device = self.device_id();
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        (lo..=hi).any(|epoch| {
            bool::from(
                kult_crypto::discovery_introduction_token(
                    &self.device_state.discovery.capability,
                    &device,
                    epoch,
                )
                .ct_eq(token),
            ) || (self.device_state.discovery.legacy_v1_enabled
                && (bool::from(intro_token(&me, epoch).ct_eq(token))
                    || (device != me && bool::from(intro_token(&device, epoch).ct_eq(token)))))
        })
    }

    /// Partials incomplete for at least [`NACK_AFTER_SECS`] (and not NACKed
    /// within [`NACK_INTERVAL_SECS`]), with their missing indices — the
    /// batch worth requesting selective retransmission for this tick. Also
    /// prunes metadata for partials the reassembler no longer tracks
    /// (completed, or expired out of the 24 h window).
    fn stale_partials(&mut self, now: u64) -> FragNacks {
        let missing = self.reassembler.missing(now);
        let live: HashSet<[u8; 4]> = missing.iter().map(|(id, _)| *id).collect();
        self.frag_meta.retain(|id, _| live.contains(id));
        let mut indices_left = MAX_NACK_INDICES_PER_TICK;
        missing
            .into_iter()
            .filter_map(|(id, mut miss)| {
                if miss.is_empty() {
                    return None;
                }
                let meta = self.frag_meta.get(&id)?;
                let due = now.saturating_sub(meta.first_seen) >= NACK_AFTER_SECS
                    && meta
                        .last_nack
                        .is_none_or(|t| now.saturating_sub(t) >= NACK_INTERVAL_SECS);
                if !due || indices_left == 0 {
                    return None;
                }
                miss.truncate(indices_left);
                indices_left -= miss.len();
                Some((id, miss))
            })
            .take(MAX_NACK_PARTIALS_PER_TICK)
            .collect()
    }

    fn queue_receipt(
        &mut self,
        peer: &[u8; 32],
        acks: Vec<[u8; 16]>,
        nacks: FragNacks,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if acks.is_empty() && nacks.is_empty() {
            return Ok(());
        }
        let payload = ReceiptPayload { acks, nacks }.encode();
        self.commit_pairwise_control_send(peer, &payload, now, rng)?;
        Ok(())
    }

    // ---- send path (delivery engine + scheduler) ----------------------------

    fn prepare_wake_pending(
        &self,
        peer_device: &[u8; 32],
        now: u64,
    ) -> Result<Option<PreparedWakeUpdate>> {
        if self.wake_client.is_none() {
            return Ok(None);
        }
        let Some(before) = self.store.get_wake_service_state(peer_device)? else {
            return Ok(None);
        };
        if before.remote_conflict_generation.is_some() {
            return Ok(None);
        }
        let mut after = before.clone();
        for capability in after.remote_mut() {
            if capability.expires_at > now {
                capability.mark_pending(now)?;
            }
        }
        if before == after {
            return Ok(None);
        }
        Ok(Some(PreparedWakeUpdate {
            peer_device: *peer_device,
            before,
            after,
        }))
    }

    fn commit_wake_update(
        &mut self,
        update: &PreparedWakeUpdate,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.store.commit_plan(
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
                delete_controls: &[],
                wake: &[WakeServiceTransition {
                    peer_device: update.peer_device,
                    before: &update.before,
                    after: &update.after,
                }],
                acknowledge_presentation: None,
                presentation_changed: false,
            }),
            rng,
        )?;
        Ok(())
    }

    fn commit_wake_revocation(
        &mut self,
        before: &WakeRevocationRecord,
        after: Option<&WakeRevocationRecord>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        self.store.commit_plan(
            CommitPlan::WakeRevocation(WakeRevocationPlan {
                transitions: &[WakeRevocationTransition { before, after }],
            }),
            rng,
        )?;
        Ok(())
    }

    async fn maintain_wake(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let deadline = Instant::now() + WAKE_MAINTENANCE_BUDGET;
        let mut attempts = 0usize;
        let mut revocation_attempts = 0usize;
        let mut revocation_changes = 0usize;
        let client = self.wake_client.clone();
        let mut revocations = self.store.wake_revocations(MAX_WAKE_REVOCATION_ROWS)?;
        revocations.sort_by_key(|record| {
            (
                if record.expires_at <= now {
                    0
                } else {
                    record.next_attempt_at
                },
                record.id,
            )
        });
        for before in revocations {
            if revocation_changes >= MAX_WAKE_REVOCATION_CHANGES_PER_TICK
                || Instant::now() >= deadline
            {
                break;
            }
            if before.expires_at <= now {
                self.commit_wake_revocation(&before, None, rng)?;
                revocation_changes += 1;
                continue;
            }
            if before.next_attempt_at > now
                || attempts >= MAX_WAKE_GATEWAY_OPERATIONS_PER_TICK
                || revocation_attempts >= MAX_WAKE_REVOCATIONS_PER_TICK
            {
                continue;
            }
            let Some(client) = client.as_ref() else {
                continue;
            };
            let provider = WakeProvider::new(before.origin.clone(), before.static_key)?;
            if provider.provider_id() != before.provider_id {
                return Err(NodeError::CorruptState);
            }
            let mut request_nonce = [0u8; 16];
            rng.fill_bytes(&mut request_nonce);
            if request_nonce == [0u8; 16] {
                request_nonce[15] = 1;
            }
            let request = WakeTriggerRequest {
                capability: before.decoded_capability()?,
                request_nonce,
            };
            attempts += 1;
            revocation_attempts += 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let outcome = before_timeout(remaining, client.revoke(&provider, &request)).await;
            match outcome {
                Some(Ok(())) => self.commit_wake_revocation(&before, None, rng)?,
                Some(Err(_)) | None => {
                    let mut after = before.clone();
                    after.mark_failed(now)?;
                    self.commit_wake_revocation(&before, Some(&after), rng)?;
                }
            }
            revocation_changes += 1;
        }
        let Some(client) = client else {
            return Ok(());
        };
        let mut devices = self.sessions.keys().copied().collect::<Vec<_>>();
        devices.sort_unstable();
        for peer_device in devices {
            if attempts >= MAX_WAKE_GATEWAY_OPERATIONS_PER_TICK || Instant::now() >= deadline {
                break;
            }
            let Some(before) = self.store.get_wake_service_state(&peer_device)? else {
                continue;
            };
            if before.remote_conflict_generation.is_some() {
                continue;
            }
            let mut after = before.clone();
            for capability in after.remote_mut() {
                if attempts >= MAX_WAKE_GATEWAY_OPERATIONS_PER_TICK || Instant::now() >= deadline {
                    break;
                }
                if !capability.pending
                    || capability.expires_at <= now
                    || capability.next_attempt_at > now
                {
                    continue;
                }
                let provider =
                    match WakeProvider::new(capability.origin.clone(), capability.static_key) {
                        Ok(provider) => provider,
                        Err(_) => {
                            capability.mark_failed(now)?;
                            continue;
                        }
                    };
                let mut request_nonce = [0u8; 16];
                rng.fill_bytes(&mut request_nonce);
                if request_nonce == [0u8; 16] {
                    request_nonce[15] = 1;
                }
                let request = WakeTriggerRequest {
                    capability: capability.decoded_capability()?,
                    request_nonce,
                };
                attempts += 1;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let outcome = before_timeout(remaining, client.trigger(&provider, &request)).await;
                match outcome {
                    Some(Ok(())) => capability.mark_attempted(),
                    Some(Err(_)) | None => capability.mark_failed(now)?,
                }
            }
            if before != after {
                self.commit_wake_update(
                    &PreparedWakeUpdate {
                        peer_device,
                        before,
                        after,
                    },
                    rng,
                )?;
            }
        }
        Ok(())
    }

    fn commit_queue_maintenance(
        &mut self,
        sequence: i64,
        before: &QueueItem,
        after: Option<&QueueItem>,
        prepared: PreparedDeliveryUpdate,
        wake: Option<PreparedWakeUpdate>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let delete = after.is_none().then_some(QueueDelete {
            sequence,
            content_id: before.envelope.content_id(),
        });
        let update = after.map(|after| QueueTransition {
            sequence,
            before,
            after,
        });
        let messages = prepared
            .messages
            .iter()
            .map(|(before, after)| MessageTransition { before, after })
            .collect::<Vec<_>>();
        let deliveries = prepared
            .deliveries
            .iter()
            .map(|(before, after)| DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let group_messages = prepared
            .group_messages
            .iter()
            .map(|(before, after)| GroupMessageTransition { before, after })
            .collect::<Vec<_>>();
        let wake = wake
            .as_ref()
            .map(|transition| WakeServiceTransition {
                peer_device: transition.peer_device,
                before: &transition.before,
                after: &transition.after,
            })
            .into_iter()
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[],
                delete_pending: &[],
                delete_queue: delete.as_slice(),
                update_queue: update.as_slice(),
                delete_replay: &[],
                messages: &messages,
                deliveries: &deliveries,
                group_messages: &group_messages,
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
                wake: &wake,
                acknowledge_presentation: None,
                presentation_changed: !prepared.events.is_empty(),
            }),
            rng,
        )?;
        if delete.is_some() {
            self.held_notified.remove(&sequence);
            self.call_queue_deadlines.remove(&sequence);
        }
        self.accept_commit_receipt(receipt, prepared.events);
        Ok(())
    }

    async fn flush(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let transports = self.transports.clone();
        let deadline = Instant::now() + FLUSH_BUDGET;
        // Priority classes (docs/05-transports.md §4.2 rule 3): when a
        // scarce link finally opens, text goes first, then receipts, then
        // handshakes — FIFO within each class.
        let mut queue = self.store.queue_all()?;
        queue.sort_by_key(|(seq, item)| (queue_lane(item), flush_class(item.envelope.kind), *seq));
        for (seq, mut item) in queue {
            let before = item.clone();
            if Instant::now() >= deadline {
                break;
            }
            if item.class == QueueClass::Realtime
                && self
                    .call_queue_deadlines
                    .get(&seq)
                    .is_none_or(|deadline| now >= *deadline)
            {
                self.commit_queue_maintenance(
                    seq,
                    &before,
                    None,
                    PreparedDeliveryUpdate::default(),
                    None,
                    rng,
                )?;
                continue;
            }
            if item
                .envelope
                .retention_until
                .is_some_and(|deadline| deadline <= now)
            {
                self.commit_queue_maintenance(
                    seq,
                    &before,
                    None,
                    PreparedDeliveryUpdate::default(),
                    None,
                    rng,
                )?;
                continue;
            }
            if now < item.next_attempt_at {
                continue;
            }
            // Relationship routes are refreshed only by authenticated
            // controls or pairwise rendezvous, never public discovery.
            let remaining = deadline.saturating_duration_since(Instant::now());
            let hints =
                match before_timeout(remaining, self.resolve_hints(&item.peer, now, false, rng))
                    .await
                {
                    Some(result) => result?,
                    None => {
                        schedule_passive_retry(&mut item, now);
                        self.commit_queue_maintenance(
                            seq,
                            &before,
                            Some(&item),
                            PreparedDeliveryUpdate::default(),
                            None,
                            rng,
                        )?;
                        break;
                    }
                };
            let oversize = item.envelope.encode().len() > airtime_ceiling(&item.envelope);
            let mut held_for_airtime = false;

            // Scheduler: rank every (transport, hint) pair by reachability
            // (immediate beats store-and-forward), then latency, then cost.
            let mut candidates = Vec::new();
            for transport in &transports {
                let profile = transport.profile();
                // Rule 3: media-sized payloads never hog the mesh — hold
                // for a faster carrier instead.
                if (oversize || item.class == QueueClass::Bulk)
                    && profile.cost == CostClass::Airtime
                {
                    held_for_airtime = true;
                    continue;
                }
                if item.class == QueueClass::Realtime
                    && (profile.cost == CostClass::Airtime
                        || profile.latency != kult_transport::LatencyClass::Millis)
                {
                    continue;
                }
                for hint in &hints {
                    if item.class == QueueClass::Realtime
                        && !matches!(
                            hint,
                            DeliveryHint::Multiaddr(address)
                                if address.contains("/quic-v1")
                                    && !address.contains("/p2p-circuit")
                        )
                    {
                        continue;
                    }
                    let rank = match transport.reachable(hint).await {
                        Reachability::Now => 0u8,
                        Reachability::StoreAndForward if item.class != QueueClass::Realtime => 1,
                        Reachability::StoreAndForward => continue,
                        Reachability::Unreachable => continue,
                    };
                    candidates.push((
                        (rank, profile.latency, profile.cost),
                        Arc::clone(transport),
                        hint.clone(),
                    ));
                }
            }
            candidates.sort_by_key(|(rank, _, _)| *rank);

            let mut sent = false;
            let mut sent_receipt = None;
            let mut sent_fragments = None;
            let mut capacity_refused = false;
            for (_, transport, hint) in &candidates {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let Some(result) = before_timeout(
                    remaining,
                    send_via(transport.as_ref(), hint, &item.envelope),
                )
                .await
                else {
                    break;
                };
                match result {
                    Ok((receipt, fragments)) => {
                        sent_receipt = Some(receipt);
                        sent_fragments = fragments;
                        sent = true;
                        break;
                    }
                    Err(NodeError::Transport(kult_transport::TransportError::RefusedByNextHop)) => {
                        capacity_refused = true;
                    }
                    Err(_) => {}
                }
            }

            if sent {
                let mut prepared = PreparedDeliveryUpdate::default();
                if let Some(msg_id) = item.msg_id {
                    let account = self.account_for_device(&item.peer)?;
                    let update = self.prepare_mark_sent(&account, &item.peer, &msg_id)?;
                    prepared.messages.extend(update.messages);
                    prepared.deliveries.extend(update.deliveries);
                    prepared.events.extend(update.events);
                }
                if let Some(group_msg_id) = item.group_msg_id {
                    let account = self.account_for_device(&item.peer)?;
                    let update =
                        self.prepare_group_mark_sent(&account, &item.peer, &group_msg_id)?;
                    prepared.deliveries.extend(update.deliveries);
                    prepared.group_messages.extend(update.group_messages);
                    prepared.events.extend(update.events);
                }
                if item.msg_id.is_some() || item.group_msg_id.is_some() {
                    // A transport handoff is only `Sent`, not end-to-end
                    // delivery. Retain the exact sealed envelope and retry it
                    // passively until its encrypted receipt arrives.
                    schedule_after_handoff(&mut item, now);
                    let wake = if sent_receipt == Some(SendReceipt::AckedByNextHop) {
                        self.prepare_wake_pending(&item.peer, now)?
                    } else {
                        None
                    };
                    self.commit_queue_maintenance(seq, &before, Some(&item), prepared, wake, rng)?;
                } else {
                    // Receipts, capability controls, fragments, and realtime
                    // controls are terminal at transport handoff.
                    self.commit_queue_maintenance(seq, &before, None, prepared, None, rng)?;
                }
                if let Some(bodies) = sent_fragments {
                    self.remember_fragments(
                        item.peer,
                        item.envelope.token,
                        item.envelope.retention_until,
                        bodies,
                        now,
                    );
                }
            } else if candidates.is_empty() && held_for_airtime {
                // Held, not failed: nothing was attempted, so no backoff —
                // the item goes out on the first tick after a faster
                // carrier reaches the peer. Surface the honest feedback
                // once per message, not per tick.
                if let Some(msg_id) = item.msg_id {
                    if self.held_notified.insert(seq) {
                        self.events
                            .push_back(Event::AwaitingFasterLink { id: msg_id });
                    }
                }
            } else {
                if capacity_refused {
                    schedule_capacity_retry(&mut item, now);
                } else {
                    schedule_passive_retry(&mut item, now);
                }
                self.commit_queue_maintenance(
                    seq,
                    &before,
                    Some(&item),
                    PreparedDeliveryUpdate::default(),
                    None,
                    rng,
                )?;
            }
        }
        Ok(())
    }

    /// Move third-party transit toward its other side (ADR-0009): mesh-heard
    /// envelopes become mailbox deposits at the bridge relays (any
    /// acceptance means the recipient registered that token there — done);
    /// carrier-surfaced (internet-origin) envelopes flood the broadcast
    /// carriers a bounded number of times. Runs after [`Node::flush`], so
    /// the node's own traffic always claims airtime first. Transit failures
    /// are paced with the same backoff as the delivery engine and dropped
    /// at their attempt caps or TTL — the *senders'* end-to-end retries and
    /// receipts remain the source of reliability, never the bridge.
    async fn flush_transit(&mut self, now: u64) {
        let Some(bridge) = &mut self.bridge else {
            return;
        };
        bridge.queue.retain(|item| {
            now.saturating_sub(item.first_seen) <= TRANSIT_TTL_SECS
                && item
                    .envelope
                    .retention_until
                    .is_none_or(|deadline| deadline > now)
        });
        if bridge.queue.is_empty() {
            bridge.queue_bytes = 0;
            return;
        }
        let relays = bridge.relays.clone();
        let mut queue = std::mem::take(&mut bridge.queue);
        let transports = self.transports.clone();

        let mut mesh_floods = 0usize;
        let mut kept = VecDeque::new();
        for mut item in queue.drain(..) {
            if now < item.next_ok {
                kept.push_back(item);
                continue;
            }
            if item.from_mesh {
                // Mesh → internet: offer the deposit around; the first
                // acceptance hands custody to a store-and-forward hop that
                // recognized the token.
                let mut accepted = false;
                let mut attempted = false;
                'relays: for relay in &relays {
                    for transport in &transports {
                        // Split horizon: transit never returns to the mesh.
                        if transport.profile().cost == CostClass::Airtime {
                            continue;
                        }
                        if transport.reachable(relay).await == Reachability::Unreachable {
                            continue;
                        }
                        attempted = true;
                        if transport.send(relay, &item.envelope).await.is_ok() {
                            accepted = true;
                            break 'relays;
                        }
                    }
                }
                if accepted {
                    continue; // done — drop from the queue
                }
                if !attempted {
                    // No relay was even reachable (none configured yet, or
                    // the internet side is down): held, not failed.
                    item.next_ok = now + RETRY_BASE_SECS;
                    kept.push_back(item);
                    continue;
                }
                let delay =
                    (TRANSIT_DEPOSIT_RETRY_BASE_SECS << item.attempts.min(7)).min(RETRY_CAP_SECS);
                item.attempts += 1;
                if item.attempts >= TRANSIT_DEPOSIT_ATTEMPTS {
                    continue; // no relay ever recognized it — bounded honesty
                }
                item.next_ok = now + delay;
                kept.push_back(item);
            } else {
                // Internet → mesh: flood on the broadcast carriers, paced
                // per tick and re-flooded on a fixed short schedule (no
                // feedback channel exists — receipts are end-to-end).
                if mesh_floods >= TRANSIT_MESH_PER_TICK {
                    kept.push_back(item);
                    continue;
                }
                let mut flooded = false;
                for transport in &transports {
                    let Some(hint) = transport.broadcast_hint() else {
                        continue;
                    };
                    // Fragment bodies are not retained: the bridge cannot
                    // serve NACKs for traffic it cannot read.
                    if send_via(transport.as_ref(), &hint, &item.envelope)
                        .await
                        .is_ok()
                    {
                        flooded = true;
                    }
                }
                if flooded {
                    mesh_floods += 1;
                    item.attempts += 1;
                    if item.attempts >= TRANSIT_MESH_FLOODS {
                        continue; // flood budget spent — drop
                    }
                    item.next_ok = now + (TRANSIT_REFLOOD_BASE_SECS << item.attempts.min(7));
                } else {
                    // No broadcast carrier took it (airtime exhausted, radio
                    // gone): try again shortly, without spending a flood.
                    item.next_ok = now + RETRY_BASE_SECS;
                }
                kept.push_back(item);
            }
        }

        let bridge = self.bridge.as_mut().expect("bridge unchanged during flush");
        bridge.queue_bytes = kept
            .iter()
            .map(|i| i.envelope.header_len() + i.envelope.body.len())
            .sum();
        bridge.queue = kept;
    }

    /// Remember a just-sent envelope's fragment bodies so an inbound NACK
    /// can retransmit exactly the missing indices. Bounded two ways:
    /// entries expire with the receiver's reassembly window, and beyond
    /// [`MAX_FRAG_CACHE`] messages the oldest is evicted first.
    fn remember_fragments(
        &mut self,
        peer: [u8; 32],
        token: [u8; 32],
        retention_until: Option<u64>,
        bodies: Vec<Vec<u8>>,
        now: u64,
    ) {
        let Some(id) = bodies
            .first()
            .and_then(|b| b.get(..4))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
        else {
            return;
        };
        self.frag_cache
            .retain(|_, f| now.saturating_sub(f.sent_at) <= REASSEMBLY_WINDOW_SECS);
        while self.frag_cache.len() >= MAX_FRAG_CACHE {
            let oldest = self
                .frag_cache
                .iter()
                .min_by_key(|(_, f)| f.sent_at)
                .map(|(id, _)| *id);
            match oldest {
                Some(oldest) => self.frag_cache.remove(&oldest),
                None => break,
            };
        }
        self.frag_cache.insert(
            id,
            SentFragments {
                peer,
                token,
                retention_until,
                bodies,
                sent_at: now,
            },
        );
    }

    fn prepare_mark_sent(
        &self,
        peer: &[u8; 32],
        device: &[u8; 32],
        msg_id: &[u8; 16],
    ) -> Result<PreparedDeliveryUpdate> {
        let mut deliveries = Vec::new();
        for delivery in self.store.message_device_deliveries(msg_id)? {
            if &delivery.device == device && delivery.state == DeliveryState::Queued {
                let mut after = delivery.clone();
                after.state = DeliveryState::Sent;
                deliveries.push((delivery, after));
            }
        }
        let mut messages = Vec::new();
        let mut events = Vec::new();
        for record in self.store.messages_with(peer)? {
            if &record.id == msg_id && record.state == DeliveryState::Queued {
                let mut updated = record.clone();
                updated.state = DeliveryState::Sent;
                messages.push((record, updated));
                events.push(Event::DeliveryUpdated {
                    id: *msg_id,
                    state: DeliveryState::Sent,
                });
            }
        }
        Ok(PreparedDeliveryUpdate {
            messages,
            deliveries,
            group_messages: Vec::new(),
            events,
        })
    }

    fn base_hints_for(&self, peer: &[u8; 32]) -> Result<Vec<DeliveryHint>> {
        if let Some(endpoint) = self
            .store
            .contact_devices()?
            .into_iter()
            .find(|endpoint| endpoint.device == *peer && endpoint.revoked_at.is_none())
        {
            let hints = decode_hints(&endpoint.hints);
            if !hints.is_empty() {
                return Ok(hints);
            }
        }
        let Some(contact) = self.store.get_contact(peer)? else {
            let account = self.account_for_device(peer)?;
            let Some(contact) = self.store.get_contact(&account)? else {
                return Ok(Vec::new());
            };
            return Ok(decode_hints(&contact.hints));
        };
        Ok(decode_hints(&contact.hints))
    }

    fn hints_for(&self, peer: &[u8; 32], now: u64) -> Result<Vec<DeliveryHint>> {
        let mut hints = self.base_hints_for(peer)?;
        let Some(state) = self.store.get_rendezvous_service_state(peer)? else {
            return Ok(hints);
        };
        for provider in state
            .providers
            .iter()
            .filter(|provider| provider.lookup_enabled && provider.routes_expires_at > now)
        {
            for stored in &provider.routes {
                let Ok(kind) = stored.route_kind() else {
                    continue;
                };
                let Ok(value) = core::str::from_utf8(&stored.value) else {
                    continue;
                };
                let route = RendezvousRoute {
                    kind,
                    value: value.to_owned(),
                };
                let Ok(hint) = rendezvous_route_hint(&route) else {
                    continue;
                };
                if !hints.contains(&hint) {
                    hints.push(hint);
                }
            }
        }
        Ok(hints)
    }

    /// Delivery hints for a peer.
    ///
    /// Post-pairing failures deliberately never return to public DHT lookup.
    /// Stored mailboxes, authenticated route controls, pairwise rendezvous,
    /// and the ordinary fallback ladder are the only relationship routes.
    async fn resolve_hints(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        _refresh: bool,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<DeliveryHint>> {
        self.hints_for(peer, now)
    }
}

/// Poll one transport operation only until this heartbeat's remaining
/// budget expires. Dropping the waiter is safe: envelopes are content-id
/// deduplicated and remain in the durable queue until a completed send.
async fn before_timeout<F: std::future::Future>(
    duration: std::time::Duration,
    future: F,
) -> Option<F::Output> {
    let delay = futures_timer::Delay::new(duration);
    futures::pin_mut!(future);
    futures::pin_mut!(delay);
    match select(future, delay).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

/// Hand one envelope to a transport, fragmenting if it exceeds the link MTU.
/// Returns the fragment bodies when fragmentation happened, so the caller
/// can retain them for selective retransmission.
async fn send_via(
    transport: &dyn Transport,
    hint: &DeliveryHint,
    envelope: &Envelope,
) -> Result<(SendReceipt, Option<Vec<Vec<u8>>>)> {
    let mtu = transport.profile().mtu;
    let encoded = envelope.try_encode()?;
    if encoded.len() <= mtu {
        let receipt = transport.send(hint, envelope).await?;
        return Ok((receipt, None));
    }
    // Fragments never nest (the receiver treats nested ones as malformed):
    // a retransmitted fragment that does not fit this link makes the
    // scheduler fall through to a wider one, it is never split again.
    if envelope.kind == EnvelopeKind::Fragment {
        return Err(NodeError::Protocol(
            kult_protocol::ProtocolError::MtuTooSmall,
        ));
    }
    let budget = mtu
        .checked_sub(ENVELOPE_HEADER_LEN)
        .ok_or(NodeError::Protocol(
            kult_protocol::ProtocolError::MtuTooSmall,
        ))?;
    let bodies = fragment(&encoded, budget)?;
    let mut receipt = SendReceipt::AckedByNextHop;
    for body in &bodies {
        let fragment_envelope = match envelope.retention_until {
            Some(deadline) => Envelope::new_retained(
                EnvelopeKind::Fragment,
                envelope.token,
                deadline,
                body.clone(),
            )?,
            None => Envelope::new(EnvelopeKind::Fragment, envelope.token, body.clone()),
        };
        if transport.send(hint, &fragment_envelope).await? == SendReceipt::HandedToLink {
            receipt = SendReceipt::HandedToLink;
        }
    }
    Ok((receipt, Some(bodies)))
}

/// Flush priority (docs/05-transports.md §4.2 rule 3): text > receipts >
/// prekey/handshake. Fragments rank with text — a retransmitted piece
/// completes a message the mesh has already mostly paid for. Group text is
/// text; group control ranks with receipts (it unlocks reading but carries
/// no user words).
fn flush_class(kind: EnvelopeKind) -> u8 {
    match kind {
        EnvelopeKind::Message | EnvelopeKind::Fragment | EnvelopeKind::GroupMessage => 0,
        EnvelopeKind::Receipt | EnvelopeKind::GroupControl => 1,
        EnvelopeKind::Handshake => 2,
    }
}

/// Foreground calls and fresh user messages lead; maintenance follows; an
/// interactive item that repeatedly failed is demoted behind normal upkeep;
/// attachment bulk remains last.
fn queue_lane(item: &QueueItem) -> u8 {
    match item.class {
        QueueClass::Realtime => 0,
        QueueClass::Interactive if item.attempts < PASSIVE_AFTER_ATTEMPTS => 1,
        QueueClass::Normal => 2,
        QueueClass::Interactive => 3,
        QueueClass::Bulk => 4,
    }
}

fn schedule_passive_retry(item: &mut QueueItem, now: u64) {
    if item.created_at == 0 {
        item.created_at = now;
    }
    item.attempts = item.attempts.saturating_add(1);
    let delay = retry_delay(item.attempts);
    item.next_attempt_at = now.saturating_add(delay);
}

fn schedule_capacity_retry(item: &mut QueueItem, now: u64) {
    if item.created_at == 0 {
        item.created_at = now;
    }
    item.attempts = item.attempts.saturating_add(1);
    item.next_attempt_at = now.saturating_add(capacity_retry_delay(item.attempts));
}

fn schedule_after_handoff(item: &mut QueueItem, now: u64) {
    if item.created_at == 0 {
        item.created_at = now;
    }
    item.attempts = if item.attempts < PASSIVE_AFTER_ATTEMPTS {
        PASSIVE_AFTER_ATTEMPTS
    } else {
        item.attempts.saturating_add(1)
    };
    item.next_attempt_at = now.saturating_add(retry_delay(item.attempts));
}

fn retry_delay(attempts: u32) -> u64 {
    let exponent = attempts.saturating_sub(1).min(7);
    let mut delay = (RETRY_BASE_SECS << exponent).min(RETRY_CAP_SECS);
    if attempts >= PASSIVE_AFTER_ATTEMPTS {
        delay = delay.max(PASSIVE_RETRY_MIN_SECS);
    }
    delay
}

fn capacity_retry_delay(attempts: u32) -> u64 {
    let exponent = attempts.saturating_sub(1).min(5);
    (CAPACITY_RETRY_BASE_SECS << exponent).min(CAPACITY_RETRY_CAP_SECS)
}

fn rendezvous_jitter(rng: &mut impl CryptoRngCore) -> u64 {
    rng.next_u64() % RENDEZVOUS_INITIAL_JITTER_SECS.saturating_add(1)
}

fn note_rendezvous_failure(
    provider: &mut RendezvousProviderState,
    operation: RendezvousOperationKind,
    now: u64,
) {
    provider.consecutive_failures = provider.consecutive_failures.saturating_add(1);
    let exponent = u32::from(provider.consecutive_failures.saturating_sub(1)).min(8);
    let retry_at = if provider.consecutive_failures >= RENDEZVOUS_CIRCUIT_FAILURES {
        provider.circuit_open_until = now.saturating_add(RENDEZVOUS_CIRCUIT_OPEN_SECS);
        provider.circuit_open_until
    } else {
        let delay = RENDEZVOUS_BACKOFF_MIN_SECS
            .saturating_mul(1u64 << exponent)
            .min(RENDEZVOUS_BACKOFF_MAX_SECS);
        now.saturating_add(delay)
    };
    match operation {
        RendezvousOperationKind::Register => provider.next_register_at = retry_at,
        RendezvousOperationKind::Lookup => provider.next_lookup_at = retry_at,
    }
}

fn admission_transport(ingress: IngressClass) -> AdmissionTransportClass {
    match ingress {
        IngressClass::Unknown => AdmissionTransportClass::Unknown,
        IngressClass::Direct => AdmissionTransportClass::Direct,
        IngressClass::Mailbox => AdmissionTransportClass::Mailbox,
        IngressClass::Mesh => AdmissionTransportClass::Mesh,
        IngressClass::Delayed => AdmissionTransportClass::Delayed,
        IngressClass::Bridge => AdmissionTransportClass::Bridge,
    }
}

fn admission_transport_index(transport: AdmissionTransportClass) -> usize {
    match transport {
        AdmissionTransportClass::Unknown => 0,
        AdmissionTransportClass::Direct => 1,
        AdmissionTransportClass::Mailbox => 2,
        AdmissionTransportClass::Mesh => 3,
        AdmissionTransportClass::Delayed => 4,
        AdmissionTransportClass::Bridge => 5,
    }
}

fn scheduled_info(record: ScheduledMessageRecord) -> ScheduledMessageInfo {
    let conversation = match record.conversation {
        StoreScheduledConversation::Peer(peer) => ScheduledConversation::Peer(peer),
        StoreScheduledConversation::Group(group) => ScheduledConversation::Group(group),
    };
    ScheduledMessageInfo {
        id: record.id,
        conversation,
        created_at: record.created_at,
        not_before: record.not_before,
        body: record.body,
    }
}

fn bounded_request_preview(text: &str) -> String {
    if text.len() <= MAX_PROVISIONAL_PREVIEW_BYTES {
        return text.to_owned();
    }
    let mut boundary = MAX_PROVISIONAL_PREVIEW_BYTES;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text[..boundary].to_owned()
}

fn encode_hints(hints: &[DeliveryHint]) -> Vec<Vec<u8>> {
    hints
        .iter()
        .map(|h| postcard::to_allocvec(h).expect("hint serialization cannot fail"))
        .collect()
}

fn discovery_routes(
    hints: &[DeliveryHint],
    policy: DiscoveryPublicationPolicy,
) -> Result<Vec<DiscoveryRoute>> {
    let mut routes = Vec::new();
    for hint in hints {
        let kind = match hint {
            DeliveryHint::Relay(_) => DiscoveryRouteKind::IntroductionMailbox,
            DeliveryHint::Multiaddr(_) if policy.permits_direct_routes() => {
                DiscoveryRouteKind::SovereignDirect
            }
            DeliveryHint::Multiaddr(_) | DeliveryHint::MeshNode(_) | DeliveryHint::Spool(_) => {
                continue;
            }
            _ => continue,
        };
        let value = postcard::to_allocvec(hint).map_err(|_| NodeError::CorruptState)?;
        routes.push(DiscoveryRoute { kind, value });
    }
    routes.sort_by(|left, right| {
        (left.kind as u8, left.value.as_slice()).cmp(&(right.kind as u8, right.value.as_slice()))
    });
    routes.dedup_by(|left, right| left.kind == right.kind && left.value == right.value);
    if routes.len() > MAX_DISCOVERY_ROUTES {
        return Err(NodeError::Protocol(kult_protocol::ProtocolError::TooLarge));
    }
    Ok(routes)
}

fn decode_discovery_route(route: &DiscoveryRoute) -> Result<DeliveryHint> {
    let (hint, remainder): (DeliveryHint, &[u8]) =
        postcard::take_from_bytes(&route.value).map_err(|_| NodeError::CorruptState)?;
    if !remainder.is_empty()
        || !matches!(
            (route.kind, &hint),
            (
                DiscoveryRouteKind::IntroductionMailbox,
                DeliveryHint::Relay(_)
            ) | (
                DiscoveryRouteKind::SovereignDirect,
                DeliveryHint::Multiaddr(_)
            )
        )
    {
        return Err(NodeError::CorruptState);
    }
    Ok(hint)
}

/// Decode persisted/published hint blobs, skipping any that fail to parse
/// (hints are routing data — a bad entry costs a delivery path, never
/// correctness; the bundle signature already guarantees the blobs are the
/// owner's, not what they contain).
fn decode_hints(blobs: &[Vec<u8>]) -> Vec<DeliveryHint> {
    blobs
        .iter()
        .filter_map(|bytes| postcard::from_bytes(bytes).ok())
        .collect()
}

fn validate_discovery_upgrade_routes(blobs: &[Vec<u8>]) -> Result<()> {
    for bytes in blobs {
        let (hint, remainder): (DeliveryHint, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| NodeError::CorruptState)?;
        if !remainder.is_empty()
            || postcard::to_allocvec(&hint).map_err(|_| NodeError::CorruptState)? != *bytes
        {
            return Err(NodeError::CorruptState);
        }
    }
    Ok(())
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;

    #[test]
    fn capacity_refusal_retries_promptly_then_caps() {
        assert_eq!(capacity_retry_delay(1), 1);
        assert_eq!(capacity_retry_delay(2), 2);
        assert_eq!(capacity_retry_delay(3), 4);
        assert_eq!(capacity_retry_delay(4), 8);
        assert_eq!(capacity_retry_delay(5), 16);
        assert_eq!(capacity_retry_delay(6), 30);
        assert_eq!(capacity_retry_delay(u32::MAX), 30);
    }
}

#[cfg(test)]
mod operating_mode_tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use rand::{rngs::StdRng, SeedableRng};

    use kult_crypto::{KdfProfile, RENDEZVOUS_SEALED_RECORD_LEN};
    use kult_protocol::{
        RendezvousLookupRequest, RendezvousRegisterRequest, RENDEZVOUS_REGISTER_ACK_LEN,
    };
    use kult_transport::{
        RendezvousClient, RendezvousProvider, Result as TransportResult, TransportError,
    };

    use super::*;

    struct NoopRendezvousClient;

    #[async_trait]
    impl RendezvousClient for NoopRendezvousClient {
        async fn register(
            &self,
            _provider: &RendezvousProvider,
            _request: &RendezvousRegisterRequest,
        ) -> TransportResult<[u8; RENDEZVOUS_REGISTER_ACK_LEN]> {
            Ok([0u8; RENDEZVOUS_REGISTER_ACK_LEN])
        }

        async fn lookup(
            &self,
            _provider: &RendezvousProvider,
            _request: &RendezvousLookupRequest,
        ) -> TransportResult<[u8; RENDEZVOUS_SEALED_RECORD_LEN]> {
            Err(TransportError::RefusedByNextHop)
        }
    }

    #[test]
    fn mode_reconciliation_is_monotonic_restart_safe_and_sovereign_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut rng = StdRng::seed_from_u64(0x1717);
        let mut node = Node::create(
            &path,
            b"passphrase",
            KdfProfile {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
            &mut rng,
        )
        .unwrap();
        let identity = node.account.ed;
        let client = Arc::new(NoopRendezvousClient);
        let first = RendezvousProvider::new("https://first.example".to_owned(), [1u8; 32]).unwrap();
        node.reconcile_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![first.clone()],
        )
        .unwrap();
        assert_eq!(node.rendezvous_provider_generation, 1);

        node.reconcile_rendezvous(
            DiscoveryMode::Private,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![first],
        )
        .unwrap();
        assert_eq!(node.rendezvous_provider_generation, 1);

        node.reconcile_rendezvous(DiscoveryMode::Sovereign, None, Vec::new())
            .unwrap();
        assert_eq!(node.rendezvous_provider_generation, 2);
        assert!(node.rendezvous_providers.is_empty());
        drop(node);

        let mut node = Node::open(&path, b"passphrase").unwrap();
        assert_eq!(node.account.ed, identity);
        assert_eq!(node.rendezvous_provider_generation, 2);
        assert!(node.rendezvous_providers.is_empty());
        node.reconcile_rendezvous(DiscoveryMode::Sovereign, None, Vec::new())
            .unwrap();
        assert_eq!(node.rendezvous_provider_generation, 2);

        let replacement =
            RendezvousProvider::new("https://replacement.example".to_owned(), [2u8; 32]).unwrap();
        node.reconcile_rendezvous(
            DiscoveryMode::Standard,
            Some(client as Arc<dyn RendezvousClient>),
            vec![replacement],
        )
        .unwrap();
        assert_eq!(node.rendezvous_provider_generation, 3);
    }
}

#[cfg(test)]
mod handshake_flight_tests {
    use super::*;

    #[test]
    fn device_initial_v2_round_trips_and_legacy_is_explicit() {
        let flight = DeviceInitialFlight {
            initial: vec![1, 2, 3],
            return_bundle: vec![4, 5],
            intent: DeviceHandshakeIntent::Replace {
                prior_session_id: [6u8; 32],
            },
        };
        let encoded = encode_device_initial(&flight).unwrap();
        assert!(encoded.starts_with(DEVICE_INITIAL_MAGIC));
        let decoded = decode_device_initial(&encoded).unwrap();
        assert_eq!(decoded.initial, flight.initial);
        assert_eq!(decoded.return_bundle, flight.return_bundle);
        assert_eq!(decoded.intent, flight.intent);

        let legacy = LegacyDeviceInitialFlight {
            initial: vec![7, 8],
            return_bundle: vec![9],
        };
        let mut encoded_legacy = LEGACY_DEVICE_INITIAL_MAGIC.to_vec();
        encoded_legacy.extend(postcard::to_allocvec(&legacy).unwrap());
        let decoded_legacy = decode_device_initial(&encoded_legacy).unwrap();
        assert_eq!(decoded_legacy.initial, legacy.initial);
        assert_eq!(decoded_legacy.return_bundle, legacy.return_bundle);
        assert_eq!(decoded_legacy.intent, DeviceHandshakeIntent::Legacy);

        encoded_legacy.push(0);
        assert!(decode_device_initial(&encoded_legacy).is_none());
    }

    #[test]
    fn simultaneous_establishments_choose_one_device_initiator() {
        let lower = [1u8; 32];
        let higher = [2u8; 32];
        let lower_session = [3u8; 32];
        let higher_session = [4u8; 32];

        assert_eq!(
            decide_inbound_session(
                lower,
                higher,
                Some(&lower_session),
                DeviceHandshakeIntent::Establish,
            ),
            HandshakeSessionDecision::KeepPrior
        );
        assert_eq!(
            decide_inbound_session(
                higher,
                lower,
                Some(&higher_session),
                DeviceHandshakeIntent::Establish,
            ),
            HandshakeSessionDecision::AcceptInbound
        );
    }

    #[test]
    fn replacement_is_bound_to_the_exact_prior_session() {
        let local = [1u8; 32];
        let peer = [2u8; 32];
        let prior = [3u8; 32];
        assert_eq!(
            decide_inbound_session(
                local,
                peer,
                Some(&prior),
                DeviceHandshakeIntent::Replace {
                    prior_session_id: prior,
                },
            ),
            HandshakeSessionDecision::AcceptInbound
        );
        assert_eq!(
            decide_inbound_session(
                local,
                peer,
                Some(&prior),
                DeviceHandshakeIntent::Replace {
                    prior_session_id: [4u8; 32],
                },
            ),
            HandshakeSessionDecision::Reject
        );
        assert_eq!(
            decide_inbound_session(
                local,
                peer,
                None,
                DeviceHandshakeIntent::Replace {
                    prior_session_id: prior,
                },
            ),
            HandshakeSessionDecision::Reject
        );
        assert_eq!(
            decide_inbound_session(local, peer, Some(&prior), DeviceHandshakeIntent::Reset),
            HandshakeSessionDecision::AcceptInbound
        );
    }
}

#[cfg(test)]
mod edit_tests {
    use rand::{rngs::StdRng, SeedableRng};

    use kult_crypto::KdfProfile;

    use super::*;

    #[test]
    fn pairwise_edit_refuses_missing_old_client_capability() {
        let mut rng = StdRng::seed_from_u64(0x00c3_0003);
        let directory = tempfile::tempdir().unwrap();
        let profile = KdfProfile {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let mut alice =
            Node::create(&directory.path().join("alice.db"), b"a", profile, &mut rng).unwrap();
        let mut bob =
            Node::create(&directory.path().join("bob.db"), b"b", profile, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(1_800_000_000, &mut rng).unwrap();
        let bob_peer = alice
            .add_contact("bob", &bob_bundle, &[], 1_800_000_000, &mut rng)
            .unwrap();
        let original = alice
            .send_message(&bob_peer, b"legacy first flight", 1_800_000_001, &mut rng)
            .unwrap();
        let alice_peer = alice.account.ed;

        assert!(matches!(
            alice.edit_message(
                &bob_peer,
                alice_peer,
                original,
                "must not send",
                1_800_000_002,
                &mut rng,
            ),
            Err(NodeError::EditUnsupported)
        ));
    }
}

#[cfg(test)]
mod wake_tests {
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rand::{rngs::StdRng, SeedableRng};

    use kult_protocol::{
        WakeCapability, WakeRegisterRequest, WakeRegisterResponse, WakeTriggerRequest,
        WAKE_CAPABILITY_PLAINTEXT_LEN,
    };
    use kult_transport::{LatencyClass, LinkProfile, Result as TransportResult, TransportError};

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[derive(Default)]
    struct RecordingWakeClient {
        registrations: AtomicUsize,
        triggers: AtomicUsize,
        revokes: AtomicUsize,
        issue_registrations: AtomicBool,
        fail_revokes: AtomicBool,
    }

    #[async_trait]
    impl WakeClient for RecordingWakeClient {
        async fn register(
            &self,
            _provider: &WakeProvider,
            request: &WakeRegisterRequest,
        ) -> TransportResult<WakeRegisterResponse> {
            request.encode().map_err(TransportError::Protocol)?;
            let registration = self.registrations.fetch_add(1, Ordering::SeqCst) + 1;
            if !self.issue_registrations.load(Ordering::SeqCst) {
                return Ok(WakeRegisterResponse::refused());
            }
            let byte = u8::try_from(registration).unwrap_or(u8::MAX).max(1);
            WakeRegisterResponse::issued(
                NOW + 3_600,
                WakeCapability::from_parts(
                    1,
                    [byte; 24],
                    &[byte; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
                )
                .map_err(TransportError::Protocol)?,
            )
            .map_err(TransportError::Protocol)
        }

        async fn trigger(
            &self,
            _provider: &WakeProvider,
            _request: &WakeTriggerRequest,
        ) -> TransportResult<()> {
            self.triggers.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn revoke(
            &self,
            _provider: &WakeProvider,
            _request: &WakeTriggerRequest,
        ) -> TransportResult<()> {
            self.revokes.fetch_add(1, Ordering::SeqCst);
            if self.fail_revokes.load(Ordering::SeqCst) {
                Err(TransportError::RefusedByNextHop)
            } else {
                Ok(())
            }
        }
    }

    struct RecordingTransport {
        receipt: AtomicU8,
        sends: AtomicUsize,
        receives: AtomicUsize,
        inbound: Mutex<Vec<Envelope>>,
        profile: LinkProfile,
    }

    impl RecordingTransport {
        fn new(receipt: SendReceipt, latency: LatencyClass, cost: CostClass) -> Self {
            Self {
                receipt: AtomicU8::new(match receipt {
                    SendReceipt::HandedToLink => 1,
                    SendReceipt::AckedByNextHop => 2,
                }),
                sends: AtomicUsize::new(0),
                receives: AtomicUsize::new(0),
                inbound: Mutex::new(Vec::new()),
                profile: LinkProfile {
                    mtu: 64 * 1024,
                    latency,
                    cost,
                    broadcast: cost == CostClass::Airtime,
                },
            }
        }

        fn set_receipt(&self, receipt: SendReceipt) {
            self.receipt.store(
                match receipt {
                    SendReceipt::HandedToLink => 1,
                    SendReceipt::AckedByNextHop => 2,
                },
                Ordering::SeqCst,
            );
        }
    }

    #[async_trait]
    impl Transport for RecordingTransport {
        fn profile(&self) -> LinkProfile {
            self.profile
        }

        async fn reachable(&self, _peer: &DeliveryHint) -> Reachability {
            Reachability::Now
        }

        async fn send(
            &self,
            _peer: &DeliveryHint,
            _envelope: &Envelope,
        ) -> TransportResult<SendReceipt> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            match self.receipt.load(Ordering::SeqCst) {
                1 => Ok(SendReceipt::HandedToLink),
                2 => Ok(SendReceipt::AckedByNextHop),
                _ => Err(TransportError::RefusedByNextHop),
            }
        }

        async fn recv(&self) -> TransportResult<Vec<Envelope>> {
            self.receives.fetch_add(1, Ordering::SeqCst);
            Ok(std::mem::take(
                &mut *self.inbound.lock().expect("test inbound lock"),
            ))
        }
    }

    fn add_sender_contact(
        directory: &tempfile::TempDir,
        rng: &mut StdRng,
    ) -> (Node, [u8; 32], [u8; 32]) {
        let mut sender = Node::create(
            &directory.path().join("sender.db"),
            b"sender",
            TEST_KDF,
            rng,
        )
        .unwrap();
        let mut receiver = Node::create(
            &directory.path().join("receiver.db"),
            b"receiver",
            TEST_KDF,
            rng,
        )
        .unwrap();
        let bundle = receiver.handshake_bundle(NOW, rng).unwrap();
        let account = sender
            .add_contact(
                "receiver",
                &bundle,
                &[DeliveryHint::Multiaddr(
                    "/ip4/127.0.0.1/udp/4001/quic-v1".into(),
                )],
                NOW,
                rng,
            )
            .unwrap();
        let device = sender
            .store
            .contact_devices_for(&account)
            .unwrap()
            .into_iter()
            .find(|endpoint| endpoint.revoked_at.is_none())
            .unwrap()
            .device;
        (sender, account, device)
    }

    fn install_remote_wake(node: &mut Node, peer_device: [u8; 32], rng: &mut StdRng) {
        let capability =
            WakeCapability::from_parts(1, [3u8; 24], &[4u8; WAKE_CAPABILITY_PLAINTEXT_LEN + 16])
                .unwrap();
        let mut state = node
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        state
            .replace_direction(
                WakeCapabilityDirection::Remote,
                1,
                vec![WakeStoredCapability::new(
                    WakeCapabilityDirection::Remote,
                    "https://wake.example".into(),
                    [5u8; 32],
                    capability.as_bytes().to_vec(),
                    NOW + 3_600,
                )
                .unwrap()],
            )
            .unwrap();
        node.store
            .put_wake_service_state(&peer_device, &state, rng)
            .unwrap();
    }

    #[tokio::test]
    async fn only_next_hop_acceptance_triggers_and_gateway_ack_never_delivers() {
        let mut rng = StdRng::seed_from_u64(0x1901_0001);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        let wake = Arc::new(RecordingWakeClient::default());
        sender
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&wake) as Arc<dyn WakeClient>),
            )
            .unwrap();
        let transport = Arc::new(RecordingTransport::new(
            SendReceipt::AckedByNextHop,
            LatencyClass::Millis,
            CostClass::Metered,
        ));
        sender.add_transport(Arc::clone(&transport) as Arc<dyn Transport>);

        let first = sender
            .send_message(&account, b"accepted by next hop", NOW + 1, &mut rng)
            .unwrap();
        install_remote_wake(&mut sender, peer_device, &mut rng);
        sender.tick(NOW + 2, &mut rng).await.unwrap();
        assert_eq!(wake.triggers.load(Ordering::SeqCst), 1);
        assert_eq!(
            sender
                .messages_with(&account)
                .unwrap()
                .into_iter()
                .find(|message| message.id == first)
                .unwrap()
                .state,
            DeliveryState::Sent
        );

        transport.set_receipt(SendReceipt::HandedToLink);
        let second = sender
            .send_message(&account, b"link handoff only", NOW + 3, &mut rng)
            .unwrap();
        sender.tick(NOW + 4, &mut rng).await.unwrap();
        assert_eq!(wake.triggers.load(Ordering::SeqCst), 1);
        assert_eq!(
            sender
                .messages_with(&account)
                .unwrap()
                .into_iter()
                .find(|message| message.id == second)
                .unwrap()
                .state,
            DeliveryState::Sent
        );
    }

    #[tokio::test]
    async fn wake_collection_does_not_flush_or_touch_mesh_and_sneakernet() {
        let mut rng = StdRng::seed_from_u64(0x1901_0002);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, _) = add_sender_contact(&directory, &mut rng);
        let immediate = Arc::new(RecordingTransport::new(
            SendReceipt::AckedByNextHop,
            LatencyClass::Millis,
            CostClass::Metered,
        ));
        let mesh = Arc::new(RecordingTransport::new(
            SendReceipt::HandedToLink,
            LatencyClass::Seconds,
            CostClass::Airtime,
        ));
        let sneakernet = Arc::new(RecordingTransport::new(
            SendReceipt::HandedToLink,
            LatencyClass::HumanScale,
            CostClass::Free,
        ));
        sender.add_transport(Arc::clone(&immediate) as Arc<dyn Transport>);
        sender.add_transport(Arc::clone(&mesh) as Arc<dyn Transport>);
        sender.add_transport(Arc::clone(&sneakernet) as Arc<dyn Transport>);
        let message = sender
            .send_message(&account, b"must remain queued", NOW + 1, &mut rng)
            .unwrap();

        sender
            .wake_tick(NOW + 2, Duration::from_secs(2), &mut rng)
            .await
            .unwrap();
        assert_eq!(immediate.sends.load(Ordering::SeqCst), 0);
        assert_eq!(mesh.sends.load(Ordering::SeqCst), 0);
        assert_eq!(sneakernet.sends.load(Ordering::SeqCst), 0);
        assert_eq!(immediate.receives.load(Ordering::SeqCst), 1);
        assert_eq!(mesh.receives.load(Ordering::SeqCst), 0);
        assert_eq!(sneakernet.receives.load(Ordering::SeqCst), 0);
        assert_eq!(
            sender
                .messages_with(&account)
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.id == message)
                .unwrap()
                .state,
            DeliveryState::Queued
        );
    }

    #[tokio::test]
    async fn issued_capability_generations_are_atomic_idempotent_and_revocable() {
        let mut rng = StdRng::seed_from_u64(0x1901_0003);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        let message = sender
            .send_message(&account, b"create session", NOW + 1, &mut rng)
            .unwrap();
        let wake = Arc::new(RecordingWakeClient::default());
        sender
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&wake) as Arc<dyn WakeClient>),
            )
            .unwrap();
        let descriptor = |byte| WakeCapabilityDescriptor {
            origin: "https://wake.example".into(),
            static_key: [5u8; 32],
            expires_at: NOW + 3_600,
            capability: WakeCapability::from_parts(
                1,
                [byte; 24],
                &[byte; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
            )
            .unwrap(),
        };
        sender
            .publish_wake_capabilities(peer_device, 1, vec![descriptor(6)], NOW + 2, &mut rng)
            .unwrap();
        let after_first = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(after_first.issued_generation, 1);
        assert_eq!(after_first.issued().count(), 1);
        let queue_len = sender.store.queue_all().unwrap().len();

        sender
            .publish_wake_capabilities(peer_device, 1, vec![descriptor(6)], NOW + 2, &mut rng)
            .unwrap();
        assert_eq!(sender.store.queue_all().unwrap().len(), queue_len);
        assert!(matches!(
            sender.publish_wake_capabilities(
                peer_device,
                1,
                vec![descriptor(7)],
                NOW + 2,
                &mut rng,
            ),
            Err(NodeError::WakeConflict)
        ));

        sender
            .publish_wake_capabilities(peer_device, 2, Vec::new(), NOW + 3, &mut rng)
            .unwrap();
        let revoked = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(revoked.issued_generation, 2);
        assert_eq!(revoked.issued().count(), 0);
        assert_eq!(
            sender
                .store
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            1
        );
        let delivery_before = sender
            .messages_with(&account)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == message)
            .unwrap()
            .state;
        sender.maintain_wake(NOW + 4, &mut rng).await.unwrap();
        assert_eq!(wake.revokes.load(Ordering::SeqCst), 1);
        assert!(sender
            .store
            .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
            .unwrap()
            .is_empty());
        assert_eq!(
            sender
                .messages_with(&account)
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.id == message)
                .unwrap()
                .state,
            delivery_before
        );
        sender
            .configure_wake(DiscoveryMode::Sovereign, None)
            .unwrap();
        assert!(matches!(
            sender.publish_wake_capabilities(
                peer_device,
                3,
                vec![descriptor(8)],
                NOW + 5,
                &mut rng,
            ),
            Err(NodeError::WakeUnavailable)
        ));
        sender
            .publish_wake_capabilities(peer_device, 3, Vec::new(), NOW + 5, &mut rng)
            .unwrap();
        assert_eq!(
            sender
                .store
                .get_wake_service_state(&peer_device)
                .unwrap()
                .unwrap()
                .issued_generation,
            3
        );
        assert!(sender
            .configure_wake(
                DiscoveryMode::Sovereign,
                Some(Arc::new(RecordingWakeClient::default()) as Arc<dyn WakeClient>),
            )
            .is_err());
    }

    #[tokio::test]
    async fn native_token_registration_rotates_and_permission_revocation_is_complete() {
        let mut rng = StdRng::seed_from_u64(0x1901_0015);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        sender
            .send_message(&account, b"establish session", NOW, &mut rng)
            .unwrap();
        let wake = Arc::new(RecordingWakeClient::default());
        wake.issue_registrations.store(true, Ordering::SeqCst);
        sender
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&wake) as Arc<dyn WakeClient>),
            )
            .unwrap();
        let provider = WakeProvider::new("https://wake.example".into(), [5u8; 32]).unwrap();

        let first = sender
            .register_native_wake_destination(
                NativeWakeDestinationRegistration {
                    platform: WakePlatform::Fcm,
                    environment: WakeEnvironment::Production,
                    profile: WakeProfile::GenericVisible,
                    provider_token: b"fcm-registration-token",
                    app_topic: b"is.andri.komms",
                    providers: core::slice::from_ref(&provider),
                    now: NOW,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(
            first,
            NativeWakeRegistrationResult {
                updated: 1,
                remaining: false
            }
        );
        let first_state = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(first_state.issued_generation, 1);
        assert_eq!(first_state.issued().count(), 1);

        let second = sender
            .register_native_wake_destination(
                NativeWakeDestinationRegistration {
                    platform: WakePlatform::Fcm,
                    environment: WakeEnvironment::Production,
                    profile: WakeProfile::GenericVisible,
                    provider_token: b"rotated-fcm-registration-token",
                    app_topic: b"is.andri.komms",
                    providers: core::slice::from_ref(&provider),
                    now: NOW + 1,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(second.updated, 1);
        let second_state = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(second_state.issued_generation, 2);
        assert_eq!(second_state.issued().count(), 1);
        assert_eq!(
            sender
                .store
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            sender
                .revoke_native_wake_capabilities(NOW + 2, &mut rng)
                .unwrap(),
            1
        );
        let revoked = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(revoked.issued_generation, 3);
        assert_eq!(revoked.issued().count(), 0);
    }

    #[test]
    fn native_wake_revocation_skips_a_legacy_session_without_service_state() {
        let mut rng = StdRng::seed_from_u64(0x1901_0018);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        sender
            .send_message(&account, b"establish session", NOW, &mut rng)
            .unwrap();
        sender.store.delete_session(&peer_device).unwrap();

        assert_eq!(
            sender
                .revoke_native_wake_capabilities(NOW + 1, &mut rng)
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn partial_gateway_registration_preserves_prior_complete_set() {
        struct PartialRegistrationClient {
            calls: AtomicUsize,
        }

        #[async_trait]
        impl WakeClient for PartialRegistrationClient {
            async fn register(
                &self,
                _provider: &WakeProvider,
                _request: &WakeRegisterRequest,
            ) -> TransportResult<WakeRegisterResponse> {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call % 2 == 1 {
                    return Ok(WakeRegisterResponse::refused());
                }
                WakeRegisterResponse::issued(
                    NOW + 3_600,
                    WakeCapability::from_parts(
                        1,
                        [31u8; 24],
                        &[32u8; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
                    )
                    .map_err(TransportError::Protocol)?,
                )
                .map_err(TransportError::Protocol)
            }

            async fn trigger(
                &self,
                _provider: &WakeProvider,
                _request: &WakeTriggerRequest,
            ) -> TransportResult<()> {
                Ok(())
            }

            async fn revoke(
                &self,
                _provider: &WakeProvider,
                _request: &WakeTriggerRequest,
            ) -> TransportResult<()> {
                Ok(())
            }
        }

        let mut rng = StdRng::seed_from_u64(0x1901_0016);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        sender
            .send_message(&account, b"establish session", NOW, &mut rng)
            .unwrap();
        let client = Arc::new(PartialRegistrationClient {
            calls: AtomicUsize::new(0),
        });
        sender
            .configure_wake(DiscoveryMode::Standard, Some(client as Arc<dyn WakeClient>))
            .unwrap();
        let existing = WakeCapabilityDescriptor {
            origin: "https://wake-a.example".into(),
            static_key: [41u8; 32],
            expires_at: NOW + 3_600,
            capability: WakeCapability::from_parts(
                1,
                [42u8; 24],
                &[43u8; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
            )
            .unwrap(),
        };
        sender
            .publish_wake_capabilities(peer_device, 1, vec![existing], NOW, &mut rng)
            .unwrap();
        let providers = vec![
            WakeProvider::new("https://wake-a.example".into(), [41u8; 32]).unwrap(),
            WakeProvider::new("https://wake-b.example".into(), [44u8; 32]).unwrap(),
        ];

        let result = sender
            .register_native_wake_destination(
                NativeWakeDestinationRegistration {
                    platform: WakePlatform::Apns,
                    environment: WakeEnvironment::Development,
                    profile: WakeProfile::BackgroundOnly,
                    provider_token: &[9u8; 32],
                    app_topic: b"is.andri.komms",
                    providers: &providers,
                    now: NOW + 1,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(result.updated, 0);
        let after = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        assert_eq!(after.issued_generation, 1);
        assert_eq!(after.issued().count(), 1);
    }

    #[tokio::test]
    async fn failed_gateway_revocation_survives_restart_and_retries() {
        let mut rng = StdRng::seed_from_u64(0x1901_0004);
        let directory = tempfile::tempdir().unwrap();
        let sender_path = directory.path().join("sender.db");
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        let message = sender
            .send_message(&account, b"retain delivery state", NOW + 1, &mut rng)
            .unwrap();
        let failing = Arc::new(RecordingWakeClient::default());
        failing.fail_revokes.store(true, Ordering::SeqCst);
        sender
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&failing) as Arc<dyn WakeClient>),
            )
            .unwrap();
        let descriptor = WakeCapabilityDescriptor {
            origin: "https://wake.example".into(),
            static_key: [5u8; 32],
            expires_at: NOW + 3_600,
            capability: WakeCapability::from_parts(
                1,
                [12u8; 24],
                &[13u8; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
            )
            .unwrap(),
        };
        sender
            .publish_wake_capabilities(peer_device, 1, vec![descriptor], NOW + 2, &mut rng)
            .unwrap();
        sender
            .publish_wake_capabilities(peer_device, 2, Vec::new(), NOW + 3, &mut rng)
            .unwrap();
        let delivery_before = sender
            .messages_with(&account)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == message)
            .unwrap()
            .state;
        sender.maintain_wake(NOW + 4, &mut rng).await.unwrap();
        assert_eq!(failing.revokes.load(Ordering::SeqCst), 1);
        let retry = sender
            .store
            .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(retry.consecutive_failures, 1);
        drop(sender);

        let mut reopened = Node::open(&sender_path, b"sender").unwrap();
        let succeeding = Arc::new(RecordingWakeClient::default());
        reopened
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&succeeding) as Arc<dyn WakeClient>),
            )
            .unwrap();
        reopened
            .maintain_wake(retry.next_attempt_at, &mut rng)
            .await
            .unwrap();
        assert_eq!(succeeding.revokes.load(Ordering::SeqCst), 1);
        assert!(reopened
            .store
            .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
            .unwrap()
            .is_empty());
        assert_eq!(
            reopened
                .messages_with(&account)
                .unwrap()
                .into_iter()
                .find(|candidate| candidate.id == message)
                .unwrap()
                .state,
            delivery_before
        );
    }

    #[tokio::test]
    async fn revocation_backlog_cannot_starve_an_eligible_wake_trigger() {
        let mut rng = StdRng::seed_from_u64(0x1901_0005);
        let directory = tempfile::tempdir().unwrap();
        let (mut sender, account, peer_device) = add_sender_contact(&directory, &mut rng);
        sender
            .send_message(&account, b"create session", NOW + 1, &mut rng)
            .unwrap();
        let wake = Arc::new(RecordingWakeClient::default());
        sender
            .configure_wake(
                DiscoveryMode::Standard,
                Some(Arc::clone(&wake) as Arc<dyn WakeClient>),
            )
            .unwrap();
        let descriptors = |generation: u8| {
            (0..4u8)
                .map(|provider| WakeCapabilityDescriptor {
                    origin: format!("https://wake-{provider}.example"),
                    static_key: [provider + 20; 32],
                    expires_at: NOW + 3_600,
                    capability: WakeCapability::from_parts(
                        1,
                        [generation.saturating_mul(8).saturating_add(provider); 24],
                        &[generation.saturating_add(provider); WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
                    )
                    .unwrap(),
                })
                .collect::<Vec<_>>()
        };
        sender
            .publish_wake_capabilities(peer_device, 1, descriptors(1), NOW + 2, &mut rng)
            .unwrap();
        sender
            .publish_wake_capabilities(peer_device, 2, descriptors(2), NOW + 3, &mut rng)
            .unwrap();
        sender
            .publish_wake_capabilities(peer_device, 3, descriptors(3), NOW + 4, &mut rng)
            .unwrap();
        assert_eq!(
            sender
                .store
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            8
        );
        install_remote_wake(&mut sender, peer_device, &mut rng);
        let mut state = sender
            .store
            .get_wake_service_state(&peer_device)
            .unwrap()
            .unwrap();
        state
            .remote_mut()
            .next()
            .unwrap()
            .mark_pending(NOW + 5)
            .unwrap();
        sender
            .store
            .put_wake_service_state(&peer_device, &state, &mut rng)
            .unwrap();

        sender.maintain_wake(NOW + 5, &mut rng).await.unwrap();
        assert_eq!(
            wake.revokes.load(Ordering::SeqCst),
            MAX_WAKE_REVOCATIONS_PER_TICK
        );
        assert_eq!(wake.triggers.load(Ordering::SeqCst), 1);
        assert_eq!(
            sender
                .store
                .wake_revocations(MAX_WAKE_REVOCATION_ROWS)
                .unwrap()
                .len(),
            4
        );
    }
}

#[cfg(test)]
mod authority_migration_tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use kult_crypto::{
        derive_kek, mnemonic_from_entropy, DeviceCertificate, DeviceManifest, DeviceManifestEntry,
        StorageKey,
    };
    use kult_store::{
        ContactRecord, DeliveryState, DeviceStateRecord, Direction, MessageRecord,
        NoteMessageRecord,
    };

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn legacy_backup_v1_fixture(
        identity: &Identity,
        contacts: Vec<ContactRecord>,
        messages: Vec<MessageRecord>,
        created_at: u64,
        rng: &mut StdRng,
    ) -> (Vec<u8>, String) {
        let reset_peers = Vec::<[u8; 32]>::new();
        let payload = postcard::to_allocvec(&(
            created_at,
            identity.to_bytes().to_vec(),
            contacts,
            messages,
            reset_peers,
        ))
        .unwrap();
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let mnemonic = mnemonic_from_entropy(&entropy);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let key =
            StorageKey::from_bytes(*derive_kek(&entropy, &salt, TEST_KDF).expect("fixture KDF"));
        let mut backup = Vec::new();
        backup.extend_from_slice(b"KKR1");
        backup.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
        backup.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
        backup.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, rng));
        (backup, (*mnemonic).clone())
    }

    fn create_legacy_profile(
        path: &std::path::Path,
        copied_root: bool,
        rng: &mut StdRng,
    ) -> (Identity, [u8; 32], ContactRecord) {
        let root = Identity::generate(rng);
        let device = Identity::generate(rng);
        let certificate = DeviceCertificate::issue(&root, &device, 10, rng);
        let mut manifest =
            DeviceManifest::initial(&root, certificate.clone(), "Original phone".into(), 10)
                .unwrap();
        if copied_root {
            let copied_device = Identity::generate(rng);
            let copied_certificate = DeviceCertificate::issue(&root, &copied_device, 11, rng);
            manifest
                .add_device(
                    &root,
                    DeviceManifestEntry {
                        certificate: copied_certificate,
                        name: "Former laptop".into(),
                        last_seen: 11,
                        revoked_at: None,
                        revoked_after_counter: None,
                    },
                )
                .unwrap();
            manifest
                .revoke_device(&root, &copied_device.public().ed, 12, 0)
                .unwrap();
        }
        let state = DeviceStateRecord {
            local_device_secret: device.to_bytes().to_vec(),
            local_certificate: certificate,
            manifest,
            sync_counter: 7,
            channels: Vec::new(),
        };
        let prekeys = PrekeyVault::generate(rng).encode();
        let store = Store::create_legacy_profile_fixture(
            path, b"legacy", TEST_KDF, &root, &state, &prekeys, rng,
        )
        .unwrap();
        let contact_identity = Identity::generate(rng).public();
        let contact = ContactRecord {
            peer: contact_identity.ed,
            identity: postcard::to_allocvec(&contact_identity).unwrap(),
            name: "Preserved petname".into(),
            bundle: Vec::new(),
            hints: Vec::new(),
            verified: true,
        };
        store.put_contact(&contact, rng).unwrap();
        drop(store);
        (root, device.public().ed, contact)
    }

    #[test]
    fn single_device_alpha_migration_is_explicit_atomic_and_root_free() {
        let mut rng = StdRng::seed_from_u64(0x2600_6001);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.db");
        let recovery_path = directory.path().join("offline.kra");
        let (root, old_device, contact) = create_legacy_profile(&path, false, &mut rng);

        assert!(matches!(
            Node::open(&path, b"legacy"),
            Err(NodeError::AuthorityMigrationRequired)
        ));
        let mnemonic =
            Node::prepare_authority_migration(&path, b"legacy", &recovery_path, &mut rng).unwrap();
        assert!(recovery_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&recovery_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // Preparing the protected package never mutates the live database.
        let store = Store::open(&path, b"legacy").unwrap();
        assert_eq!(
            store.get_identity().unwrap().unwrap().public(),
            root.public()
        );
        assert!(store.get_account_identity().unwrap().is_none());
        drop(store);

        // An unrelated valid authority cannot authorize the conversion.
        let unrelated = Identity::generate(&mut rng);
        let (wrong_package, wrong_words) =
            seal_account_recovery_authority(&unrelated, &mut rng).unwrap();
        assert!(matches!(
            Node::complete_authority_migration(
                &path,
                b"legacy",
                &wrong_package,
                &wrong_words,
                20,
                &mut rng,
            ),
            Err(NodeError::RecoveryAuthorityRequired)
        ));
        let store = Store::open(&path, b"legacy").unwrap();
        assert!(store.contains_legacy_account_root().unwrap());
        drop(store);

        let package = std::fs::read(&recovery_path).unwrap();
        let mut node =
            Node::complete_authority_migration(&path, b"legacy", &package, &mnemonic, 20, &mut rng)
                .unwrap();
        assert_eq!(node.peer_id(), root.public().ed);
        assert_eq!(node.device_id(), old_device);
        assert_eq!(node.linked_devices().len(), 1);
        assert_eq!(node.linked_devices()[0].name, "Original phone");
        assert!(matches!(
            node.export_account_recovery_authority(
                &directory.path().join("unexpected-second-authority.kra")
            ),
            Err(NodeError::RecoveryAuthorityUnavailable)
        ));
        drop(node);

        let store = Store::open(&path, b"legacy").unwrap();
        assert!(!store.contains_legacy_account_root().unwrap());
        assert!(store.get_identity().unwrap().is_none());
        assert_eq!(store.get_account_identity().unwrap(), Some(root.public()));
        assert_eq!(store.get_contact(&contact.peer).unwrap(), Some(contact));
        assert_eq!(
            store
                .get_device_authority_state()
                .unwrap()
                .unwrap()
                .sync_counter,
            7
        );
        drop(store);

        let reopened = Node::open(&path, b"legacy").unwrap();
        assert_eq!(reopened.peer_id(), root.public().ed);
        assert_eq!(reopened.device_id(), old_device);
        drop(reopened);

        // A retry after an AfterCommit-style interruption is idempotent.
        let reopened =
            Node::complete_authority_migration(&path, b"legacy", &package, &mnemonic, 21, &mut rng)
                .unwrap();
        assert_eq!(reopened.peer_id(), root.public().ed);
        assert_eq!(reopened.device_id(), old_device);
    }

    #[test]
    fn any_durable_evidence_of_a_copied_alpha_root_requires_new_identity_reset() {
        let mut rng = StdRng::seed_from_u64(0x2600_6002);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("copied-root.db");
        let recovery_path = directory.path().join("must-not-exist.kra");
        create_legacy_profile(&path, true, &mut rng);

        assert!(matches!(
            Node::open(&path, b"legacy"),
            Err(NodeError::AuthorityResetRequired)
        ));
        assert!(matches!(
            Node::prepare_authority_migration(&path, b"legacy", &recovery_path, &mut rng),
            Err(NodeError::AuthorityResetRequired)
        ));
        assert!(!recovery_path.exists());
    }

    #[test]
    fn copied_root_reset_creates_new_identity_and_preserves_only_local_archive() {
        let mut rng = StdRng::seed_from_u64(0x2600_6003);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("copied-root.db");
        let recovery_path = directory.path().join("new-offline-authority.kra");
        let (former_root, former_device, contact) = create_legacy_profile(&path, true, &mut rng);
        let message = MessageRecord {
            id: [0x61; 16],
            peer: contact.peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp: 13,
            body: b"local history from the former identity".to_vec(),
            wire_id: Some([0x62; 16]),
        };
        let note = NoteMessageRecord {
            id: [0x63; 16],
            timestamp: 14,
            body: "device-local note".into(),
        };
        let store = Store::open(&path, b"legacy").unwrap();
        store.put_message(&message, &mut rng).unwrap();
        store.put_note_message(&note, &mut rng).unwrap();
        drop(store);

        let prepared =
            Node::prepare_authority_reset(&path, b"legacy", &recovery_path, &mut rng).unwrap();
        assert_ne!(prepared.new_account, former_root.public());
        assert_eq!(prepared.new_address, prepared.new_account.address());
        assert!(recovery_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&recovery_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // Preparation never changes the copied-root source.
        let store = Store::open(&path, b"legacy").unwrap();
        assert_eq!(
            store.get_identity().unwrap().unwrap().public(),
            former_root.public()
        );
        assert!(store.get_account_identity().unwrap().is_none());
        drop(store);

        let package = std::fs::read(&recovery_path).unwrap();
        let node = Node::complete_authority_reset(
            &path,
            b"legacy",
            &package,
            &prepared.mnemonic,
            20,
            &mut rng,
        )
        .unwrap();
        assert_eq!(node.peer_id(), prepared.new_account.ed);
        assert_ne!(node.peer_id(), former_root.public().ed);
        assert_ne!(node.device_id(), former_device);
        assert_eq!(node.linked_devices().len(), 1);
        let reset = node.authority_reset_history().unwrap().unwrap();
        assert_eq!(reset.former_account, former_root.public().ed);
        assert_eq!(reset.new_account, node.peer_id());
        assert_eq!(reset.preserved_contacts, 1);
        assert_eq!(reset.preserved_pairwise_messages, 1);
        assert_eq!(reset.preserved_note_messages, 1);
        assert_eq!(reset.pending_reverification, vec![contact.peer]);
        drop(node);

        let store = Store::open(&path, b"legacy").unwrap();
        assert!(!store.contains_legacy_account_root().unwrap());
        assert!(store.get_identity().unwrap().is_none());
        let preserved = store.get_contact(&contact.peer).unwrap().unwrap();
        assert_eq!(preserved.name, contact.name);
        assert_eq!(preserved.identity, contact.identity);
        assert!(preserved.bundle.is_empty());
        assert!(preserved.hints.is_empty());
        assert!(!preserved.verified);
        let archived = store.messages_with(&contact.peer).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].body, message.body);
        assert_eq!(archived[0].state, DeliveryState::Failed);
        assert_eq!(archived[0].wire_id, None);
        assert_eq!(store.note_messages().unwrap(), vec![note]);
        assert!(store.groups().unwrap().is_empty());
        assert!(store.contact_devices().unwrap().is_empty());
        assert!(store.queue_all().unwrap().is_empty());
        drop(store);

        let mut node = Node::open(&path, b"legacy").unwrap();
        assert!(matches!(
            node.send_message(&contact.peer, b"must re-verify first", 21, &mut rng),
            Err(NodeError::ContactReverificationRequired)
        ));
        node.mark_verified(&contact.peer, &mut rng).unwrap();
        let reset = node.authority_reset_history().unwrap().unwrap();
        assert!(reset.pending_reverification.is_empty());
        assert!(node.contacts().unwrap()[0].verified);
        assert!(matches!(
            node.send_message(&contact.peer, b"still needs a fresh route", 22, &mut rng),
            Err(NodeError::NoSession)
        ));
        drop(node);

        // Retrying after the atomic replacement returns the same new profile.
        let reopened = Node::complete_authority_reset(
            &path,
            b"legacy",
            &package,
            &prepared.mnemonic,
            23,
            &mut rng,
        )
        .unwrap();
        assert_eq!(reopened.peer_id(), prepared.new_account.ed);
        assert!(reopened
            .authority_reset_history()
            .unwrap()
            .unwrap()
            .pending_reverification
            .is_empty());
    }

    #[test]
    fn single_device_profile_can_choose_conservative_new_identity_reset() {
        let mut rng = StdRng::seed_from_u64(0x2600_6004);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("single-device.db");
        let recovery_path = directory.path().join("conservative-reset.kra");
        let (former_root, _, contact) = create_legacy_profile(&path, false, &mut rng);
        let prepared =
            Node::prepare_authority_reset(&path, b"legacy", &recovery_path, &mut rng).unwrap();
        assert_ne!(prepared.new_account, former_root.public());
        let package = std::fs::read(&recovery_path).unwrap();
        let node = Node::complete_authority_reset(
            &path,
            b"legacy",
            &package,
            &prepared.mnemonic,
            20,
            &mut rng,
        )
        .unwrap();
        let reset = node.authority_reset_history().unwrap().unwrap();
        assert_eq!(reset.former_account, former_root.public().ed);
        assert_eq!(reset.new_account, prepared.new_account.ed);
        assert_eq!(reset.pending_reverification, vec![contact.peer]);
    }

    #[test]
    fn legacy_backup_recovers_only_as_a_visible_new_identity_archive() {
        let mut rng = StdRng::seed_from_u64(0x2600_6005);
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("legacy-source.db");
        let target_path = directory.path().join("fresh-target.db");
        let recovery_path = directory.path().join("fresh-authority.kra");
        let (former_root, former_device, contact) =
            create_legacy_profile(&source_path, true, &mut rng);
        let message = MessageRecord {
            id: [0x81; 16],
            peer: contact.peer,
            direction: Direction::Outbound,
            state: DeliveryState::Sent,
            timestamp: 15,
            body: b"legacy backup archive".to_vec(),
            wire_id: Some([0x82; 16]),
        };
        let source = Store::open(&source_path, b"legacy").unwrap();
        source.put_message(&message, &mut rng).unwrap();
        let (backup, backup_mnemonic) = legacy_backup_v1_fixture(
            &former_root,
            vec![contact.clone()],
            vec![message.clone()],
            16,
            &mut rng,
        );
        drop(source);

        let prepared =
            Node::prepare_legacy_backup_authority_reset(&recovery_path, &mut rng).unwrap();
        assert_ne!(prepared.new_account, former_root.public());
        assert_eq!(prepared.new_address, prepared.new_account.address());
        let package = std::fs::read(&recovery_path).unwrap();
        let node = Node::restore_legacy_backup_with_authority_reset(
            &target_path,
            &backup,
            &backup_mnemonic,
            &package,
            &prepared.mnemonic,
            17,
            b"fresh-pass",
            TEST_KDF,
            &mut rng,
        )
        .unwrap();

        assert_eq!(node.peer_id(), prepared.new_account.ed);
        assert_ne!(node.peer_id(), former_root.public().ed);
        assert_ne!(node.device_id(), former_device);
        let reset = node.authority_reset_history().unwrap().unwrap();
        assert_eq!(reset.former_account, former_root.public().ed);
        assert_eq!(reset.new_account, prepared.new_account.ed);
        assert_eq!(reset.pending_reverification, vec![contact.peer]);
        drop(node);

        let store = Store::open(&target_path, b"fresh-pass").unwrap();
        assert!(!store.contains_legacy_account_root().unwrap());
        assert!(store.get_identity().unwrap().is_none());
        let archived = store.messages_with(&contact.peer).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].state, DeliveryState::Failed);
        assert_eq!(archived[0].wire_id, None);
        assert!(!store.get_contact(&contact.peer).unwrap().unwrap().verified);
    }

    #[test]
    fn offline_recovery_attempts_are_locally_bounded() {
        let mut rng = StdRng::seed_from_u64(0x2600_6006);
        let root = Identity::generate(&mut rng);
        let other = Identity::generate(&mut rng);
        let (package, correct_mnemonic) = seal_account_recovery_authority(&root, &mut rng).unwrap();
        let (_, wrong_mnemonic) = seal_account_recovery_authority(&other, &mut rng).unwrap();
        for _ in 0..MAX_RECOVERY_ATTEMPTS_PER_WINDOW {
            assert!(matches!(
                open_account_recovery_authority_throttled(&package, &wrong_mnemonic),
                Err(NodeError::Crypto(_))
            ));
        }
        assert!(matches!(
            open_account_recovery_authority_throttled(&package, &wrong_mnemonic),
            Err(NodeError::RecoveryAttemptLimited)
        ));
        assert!(matches!(
            open_account_recovery_authority_throttled(&package, &correct_mnemonic),
            Err(NodeError::RecoveryAttemptLimited)
        ));
    }
}
