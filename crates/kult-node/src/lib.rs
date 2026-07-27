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
use std::sync::Arc;
use std::time::Instant;

use futures::future::{select, Either};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use kult_crypto::{
    initiate, open_anonymous, respond, safety_number, seal_anonymous, DevicePrekeyBundle, Identity,
    IdentityPublic, InitialMessage, KdfProfile, PendingDeviceLinkSource, PendingDeviceLinkTarget,
    PrekeyBundle, RatchetMessage, SafetyNumber, Session,
};
use kult_protocol::{
    decode_content, delivery_token, encode_disappearing_text_payload, encode_edit,
    encode_ephemeral, encode_text, epoch_day, fragment, intro_token, is_capability_control, pad,
    retention_bucket, unpad, CapabilityControl, DecodedContent, Edit, Envelope, EnvelopeKind,
    Ephemeral, FormatCapabilities, MailboxKey, Reassembler, ReceiptPayload, CONTENT_FORMAT_V1,
    CONTENT_KIND_ATTACHMENT, CONTENT_KIND_CALL_CONTROL, CONTENT_KIND_EDIT, CONTENT_KIND_EPHEMERAL,
    CONTENT_KIND_GROUP_AUTHORITY, CONTENT_KIND_MENTION, CONTENT_KIND_POLL, CONTENT_KIND_TEXT,
    ENVELOPE_HEADER_LEN, MAX_EDIT_TEXT_LEN, MAX_EPHEMERAL_LIFETIME_SECS,
    MIN_EPHEMERAL_LIFETIME_SECS, REASSEMBLY_WINDOW_SECS,
};
use kult_store::{
    AttachmentStatePlan, CommitPlan, CommitReceipt, ContactDeviceDelete, ContactDeviceRecord,
    ContactRecord, ConversationId, ConversationMetadata, DeferredControlKind,
    DeferredControlRecord, DeliveryState, DeliveryTransition, DeviceStateRecord, Direction,
    EphemeralConversation, EphemeralMode, EphemeralRecord, EphemeralState, EphemeralTransition,
    GroupMessageDelete, GroupMessageRecord, GroupMessageTransition, GroupRecord, GroupTransition,
    HandshakeReceivePlan, LocalMetadataKey, LocalMetadataRecord, MaintenancePlan, MediaDelete,
    MediaObjectRecord, MediaObjectTransition, MediaTransferRecord, MediaTransferTransition,
    MessageDelete, MessageDeviceDeliveryRecord, MessageRecord, MessageTransition,
    NoteMessageRecord, PairwiseReceivePlan, PairwiseSendPlan, PendingDelete, PrekeyPublishPlan,
    PrekeyTransition, QueueClass, QueueDelete, QueueItem, QueueTransition, ReceiptReceivePlan,
    ScheduledConversation as StoreScheduledConversation, ScheduledMessageRecord, SessionTransition,
    Store, MAX_MAINTENANCE_TRANSITIONS,
};
use kult_transport::{CostClass, DeliveryHint, Discovery, Reachability, Transport};

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
    ContentStatus, CustomIconCrop, CustomIconInfo, CustomIconUsage, DeviceLinkSelection,
    EditVersionInfo, Event, FolderConversationInfo, FolderConversationList, FolderInfo,
    FolderSelection, GroupAuthorityInfo, GroupInfo, GroupMemberRoleInfo, GroupMentionCapability,
    LabelConversationInfo, LabelFilterInfo, LabelInfo, LabelMatchMode, LinkedDeviceInfo,
    MentionCapabilityIssue, MentionCapabilityIssueReason, MentionSpan, MessageDeviceDeliveryInfo,
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
pub use incognito_keyboard::{
    incognito_keyboard_policy, IncognitoKeyboardLevel, IncognitoKeyboardPlatform,
    IncognitoKeyboardPolicy, INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
};
pub use kult_protocol::GroupRole;
#[cfg(feature = "test-failpoints")]
#[doc(hidden)]
pub use kult_store::{CommitFailpoint, CommitFailure};
pub use kult_store::{
    ConversationId as LabelConversationId, CustomIconTarget, ThemePreference,
    CUSTOM_ICON_BUNDLED_GLYPHS, CUSTOM_ICON_DIMENSION, CUSTOM_ICON_MEDIA_TYPE,
    FOLDER_ID_RETRY_LIMIT, LABEL_COLORS, MAX_CUSTOM_ICONS, MAX_CUSTOM_ICON_BYTES,
    MAX_CUSTOM_ICON_TOTAL_BYTES, MAX_FOLDERS, MAX_FOLDER_ASSIGNMENTS, MAX_LABELS,
    MAX_LABELS_PER_CONVERSATION, MAX_LABEL_ASSIGNMENTS, MAX_LOCAL_METADATA_STRING_BYTES, MAX_PINS,
    NOTE_TO_SELF_CONVERSATION_ID, THEME_PREFERENCES, THEME_PREFERENCE_KEY, THEME_SEMANTIC_ROLES,
};
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
const DEVICE_INITIAL_MAGIC: &[u8; 4] = b"KDI1";
const ACCOUNT_INITIAL_MAGIC: &[u8; 4] = b"KAI1";

/// Prekey bundles expire after 30 days (docs/06-identity-trust.md).
const BUNDLE_TTL_SECS: u64 = 30 * 86_400;

#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceInitialFlight {
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
    let body = bytes.strip_prefix(DEVICE_INITIAL_MAGIC)?;
    let (flight, remainder): (DeviceInitialFlight, &[u8]) = postcard::take_from_bytes(body).ok()?;
    remainder.is_empty().then_some(flight)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountInitialFlight {
    initial: Vec<u8>,
    return_bundle: Vec<u8>,
}

fn encode_account_initial(flight: &AccountInitialFlight) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(flight).map_err(|_| NodeError::CorruptState)?;
    let mut out = Vec::with_capacity(ACCOUNT_INITIAL_MAGIC.len() + body.len());
    out.extend_from_slice(ACCOUNT_INITIAL_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
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

/// After this many failed delivery attempts for an item, its peer's stored
/// hints are treated as possibly stale and the discovery planes are
/// consulted again (a peer that rebound to fresh OS-assigned ports has a
/// newer address in its republished bundle than in the pairing-time hint).
const HINT_REFRESH_MIN_ATTEMPTS: u32 = 1;
/// Discovery re-lookups for one account are spaced at least this far
/// apart, so a long outage costs one bounded lookup per interval instead
/// of one per queued item per tick.
const HINT_REFRESH_INTERVAL_SECS: u64 = 60;

/// Envelopes above this size never ride an airtime-budgeted (LoRa) link:
/// they are held for a faster carrier, with honest feedback
/// ([`Event::AwaitingFasterLink`]), instead of silently hogging the mesh
/// (docs/05-transports.md §4.2 rule 3).
const AIRTIME_CEILING_BYTES: usize = 4 * 1024;

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

enum Consumed {
    /// Fully handled (or permanently unprocessable) — never seen again.
    Done,
    /// Fully handled by a transaction that also acknowledged its named
    /// deferred-inbox source row, when one existed.
    DoneAtomic,
    /// Cannot be processed *yet* (no matching session) — stash and retry.
    Later,
}

#[derive(Clone, Copy)]
struct ConsumeOrigin {
    depth: u8,
    pending_sequence: Option<i64>,
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
        // Anything over the airtime ceiling could neither ride the mesh nor
        // have come off it whole — never transit (§4.2 rule 3).
        if encoded_len > AIRTIME_CEILING_BYTES {
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

/// The Komms runtime: one identity, one store, any number of transports.
pub struct Node {
    store: Store,
    /// Stable account identity used for conversation ids and existing wire compatibility.
    identity: Identity,
    /// Separately authenticated key unique to this physical installation.
    device_identity: Identity,
    device_state: DeviceStateRecord,
    device_state_dirty: bool,
    pending_device_link_source: Option<PendingDeviceLinkSource>,
    pending_device_link_target: Option<PendingDeviceLinkTarget>,
    vault: PrekeyVault,
    /// Current signed return routes included in anonymous first flights.
    own_hints: Vec<DeliveryHint>,
    transports: Vec<Arc<dyn Transport>>,
    discoveries: Vec<Arc<dyn Discovery>>,
    sessions: HashMap<[u8; 32], kult_crypto::Session>,
    capabilities_advertised: HashSet<[u8; 32]>,
    media_reconciled: bool,
    attachment_request_at: HashMap<[u8; 16], u64>,
    attachment_request_target: HashMap<[u8; 16], usize>,
    carrier_capabilities: HashMap<[u8; 32], CarrierCapabilitySnapshot>,
    calls: HashMap<[u8; 16], calls::ActiveCall>,
    call_queue_deadlines: HashMap<i64, u64>,
    reassembler: Reassembler,
    /// Per-account floor on the next allowed stale-hint discovery re-lookup.
    hint_refresh: HashMap<[u8; 32], u64>,
    frag_meta: HashMap<[u8; 4], PartialMeta>,
    frag_cache: HashMap<[u8; 4], SentFragments>,
    held_notified: HashSet<i64>,
    next_delivery_sweep: u64,
    bridge: Option<Bridge>,
    events: VecDeque<Event>,
    presentation_marker: Option<[u8; 16]>,
    delivered_presentation_marker: Option<[u8; 16]>,
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

    /// Create a brand-new node: fresh store, fresh identity, fresh prekeys.
    pub fn create(
        path: &std::path::Path,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let store = Store::create(path, passphrase, profile, rng)?;
        let identity = Identity::generate(rng);
        store.put_identity(&identity, rng)?;
        devices::initialize_fresh_device(&store, &identity, rng)?;
        let vault = PrekeyVault::generate(rng);
        store.put_prekeys(&vault.encode(), rng)?;
        Self::assemble(store, identity, vault)
    }

    /// Open an existing node.
    pub fn open(path: &std::path::Path, passphrase: &[u8]) -> Result<Self> {
        let store = Store::open(path, passphrase)?;
        let identity = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
        let vault = PrekeyVault::decode(&vault_blob)?;
        Self::assemble(store, identity, vault)
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
        let (store, vault) = Store::restore_backup_with_initializer(
            path,
            backup,
            mnemonic,
            passphrase,
            profile,
            rng,
            |store, rng| {
                let identity = store
                    .get_identity()?
                    .ok_or(kult_store::StoreError::NotAStore)?;
                if store.get_device_state()?.is_none() {
                    devices::initialize_fresh_device(store, &identity, rng)?;
                }
                let vault = PrekeyVault::generate(rng);
                store.put_prekeys(&vault.encode(), rng)?;
                Ok(vault)
            },
        )?;
        let identity = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        Self::assemble(store, identity, vault)
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
        Ok(self.store.export_backup(now, rng)?)
    }

    fn assemble(store: Store, identity: Identity, vault: PrekeyVault) -> Result<Self> {
        // Call controls are transient and their in-memory state and secrets
        // deliberately do not survive a process restart. The first bounded
        // flush retires any sealed realtime rows through Maintenance.
        let (device_identity, device_state, device_state_dirty) =
            devices::load_or_migrate_device(&store, &identity)?;
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
        let presentation_marker = store.presentation_resync_marker()?;
        let mut events = VecDeque::new();
        if presentation_marker.is_some() {
            events.push_back(Event::StateResyncRequired);
        }
        Ok(Self {
            store,
            identity,
            device_identity,
            device_state,
            device_state_dirty,
            pending_device_link_source: None,
            pending_device_link_target: None,
            vault,
            own_hints: Vec::new(),
            transports: Vec::new(),
            discoveries: Vec::new(),
            sessions,
            capabilities_advertised: HashSet::new(),
            media_reconciled: false,
            attachment_request_at: HashMap::new(),
            attachment_request_target: HashMap::new(),
            carrier_capabilities: HashMap::new(),
            calls: HashMap::new(),
            call_queue_deadlines: HashMap::new(),
            reassembler: Reassembler::new(),
            hint_refresh: HashMap::new(),
            frag_meta: HashMap::new(),
            frag_cache: HashMap::new(),
            held_notified: HashSet::new(),
            next_delivery_sweep: 0,
            bridge: None,
            events,
            presentation_marker,
            delivered_presentation_marker: None,
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
        self.discoveries.push(discovery);
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
        self.identity.public().ed
    }

    /// This node's public identity.
    pub fn public(&self) -> IdentityPublic {
        self.identity.public()
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.identity.public().address()
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
        Ok(safety_number(&self.identity.public(), &their))
    }

    /// Export a fresh signed prekey bundle for out-of-band sharing (QR, file,
    /// dictation). Each call mints a new one-time prekey, so hand each
    /// prospective contact their own bundle.
    pub fn handshake_bundle(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        self.handshake_bundle_with_hints(&[], now, rng)
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
        let before_vault = self.vault.encode();
        let mut candidate_vault = self.vault.clone();
        let step = self.begin_crypto_step()?;
        let opk = candidate_vault.fresh_opk(rng);
        self.finish_crypto_step(step)?;
        let linked = self.device_state.manifest.devices.len() > 1;
        let signing_identity = if linked {
            &self.device_identity
        } else {
            &self.identity
        };
        let bundle = PrekeyBundle::build(
            signing_identity,
            &candidate_vault.spk(),
            &candidate_vault.pqspk()?,
            Some(&opk),
            now + BUNDLE_TTL_SECS,
            encode_hints(hints),
        );
        let encoded = if linked {
            DevicePrekeyBundle::new(
                self.device_state.local_certificate.clone(),
                self.device_state.manifest.clone(),
                bundle,
            )?
            .encode()?
        } else {
            bundle.encode()
        };
        let after_vault = candidate_vault.encode();
        self.store.commit_plan(
            CommitPlan::PrekeyPublish(PrekeyPublishPlan {
                prekeys: PrekeyTransition {
                    before: &before_vault,
                    after: &after_vault,
                },
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.vault = candidate_vault;
        self.own_hints = hints.to_vec();
        self.after_memory_replacement()?;
        Ok(encoded)
    }

    // ---- discovery (DHT prekey records, docs/05-transports.md §2) -----------

    /// Publish this node's prekey bundle on every registered discovery
    /// plane, keyed by the digest inside our kult address — after this,
    /// anyone holding the address can start a session with no further
    /// out-of-band exchange.
    ///
    /// `hints` are our own reachable addresses (e.g.
    /// [`kult_transport::Libp2pTransport::listen_addrs`] as
    /// [`DeliveryHint::Multiaddr`]); they ride in the bundle's `relay_hints`
    /// so a fetcher learns both *who* we are and *where* to deliver.
    ///
    /// The published bundle deliberately carries **no one-time prekey**: a
    /// DHT record is served to arbitrarily many fetchers, and an OPK is
    /// single-use — the first handshake would consume it and strand everyone
    /// else. First-flight forward secrecy for DHT-initiated sessions rests
    /// on the signed prekeys, exactly as specified for OPK-less PQXDH
    /// (docs/04-cryptography.md §3). Call it again after rotating prekeys or
    /// when listen addresses change; the record replaces the previous one.
    pub async fn publish_bundle(&mut self, hints: &[DeliveryHint], now: u64) -> Result<()> {
        if self.discoveries.is_empty() {
            return Err(NodeError::NoDiscovery);
        }
        let bundle = PrekeyBundle::build(
            &self.identity,
            &self.vault.spk(),
            &self.vault.pqspk()?,
            None,
            now + BUNDLE_TTL_SECS,
            encode_hints(hints),
        );
        let key = self.identity.public().address_digest();
        let value = bundle.encode();
        let mut published = false;
        for discovery in &self.discoveries {
            if discovery.publish(key, value.clone()).await.is_ok() {
                published = true;
            }
        }
        if published {
            Ok(())
        } else {
            Err(NodeError::NoDiscovery)
        }
    }

    /// Add a contact from their kult address alone, fetching the prekey
    /// bundle from the discovery planes. Every candidate record is untrusted
    /// input: it must carry valid signatures **and** hash back to the very
    /// digest the address encodes, so a malicious DHT node can withhold a
    /// bundle but never substitute one. Among the survivors the freshest
    /// (latest-expiring) bundle wins, and its embedded delivery hints become
    /// the contact's hints. Returns the contact's peer id.
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
        let digest = kult_crypto::parse_address(address)?;
        let bundle = self
            .lookup_bundle(digest, now)
            .await
            .ok_or(NodeError::BundleNotFound)?;
        let hints = decode_hints(&bundle.relay_hints);
        self.add_contact(name, &bundle.encode(), &hints, now, rng)
    }

    /// Fetch, verify, and select the freshest prekey bundle for `digest`
    /// across all discovery planes. `None` means no candidate survived
    /// verification — never that a record was accepted unverified.
    async fn lookup_bundle(&self, digest: [u8; 32], now: u64) -> Option<PrekeyBundle> {
        let mut best: Option<PrekeyBundle> = None;
        for discovery in &self.discoveries {
            let Ok(candidates) = discovery.lookup(digest).await else {
                continue;
            };
            for bytes in candidates {
                let Ok(bundle) = PrekeyBundle::decode(&bytes) else {
                    continue;
                };
                if bundle.verify(now).is_err() || bundle.identity.address_digest() != digest {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|b| bundle.expires_at > b.expires_at)
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
        let me = self.identity.public().ed;
        let device = self.device_id();
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + MAILBOX_AHEAD_EPOCHS;
        let mut tokens = Vec::new();
        for epoch in lo..=hi {
            tokens.push(intro_token(&me, epoch));
            if device != me {
                tokens.push(intro_token(&device, epoch));
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
        let name = contact_names::normalize_contact_name(name)?;
        let (peer, identity, stored_bundle, mut endpoint, manifest, advertised_hints) =
            if DevicePrekeyBundle::is_encoded(bundle_bytes) {
                let device_bundle = DevicePrekeyBundle::decode(bundle_bytes)?;
                device_bundle.verify(now)?;
                let advertised_hints = decode_hints(&device_bundle.prekey.relay_hints);
                let peer = device_bundle.manifest.account.ed;
                let identity = postcard::to_allocvec(&device_bundle.manifest.account)
                    .map_err(|_| NodeError::CorruptState)?;
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device: device_bundle.certificate.device_id(),
                    name: device_bundle
                        .manifest
                        .devices
                        .iter()
                        .find(|entry| entry.certificate == device_bundle.certificate)
                        .map(|entry| entry.name.clone()),
                    certificate: postcard::to_allocvec(&device_bundle.certificate)
                        .map_err(|_| NodeError::CorruptState)?,
                    bundle: device_bundle.prekey.encode(),
                    hints: Vec::new(),
                    manifest_generation: device_bundle.manifest.generation,
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
                let advertised_hints = decode_hints(&verified.bundle().relay_hints);
                let peer = verified.bundle().identity.ed;
                let identity = postcard::to_allocvec(&verified.bundle().identity)
                    .map_err(|_| NodeError::CorruptState)?;
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device: peer,
                    name: None,
                    certificate: Vec::new(),
                    bundle: bundle_bytes.to_vec(),
                    hints: Vec::new(),
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
            self.validate_contact_device_manifest(manifest)?;
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
                endpoint.device,
                endpoint.bundle,
                endpoint.hints,
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
                acknowledge_presentation: None,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        self.sessions.remove(device);
        self.capabilities_advertised.remove(device);
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

    /// Message history with a peer, in insertion order.
    pub fn messages_with(&self, peer: &[u8; 32]) -> Result<Vec<MessageRecord>> {
        Ok(self.store.messages_with(peer)?)
    }

    /// Pairwise message read model with immutable edits resolved and edit
    /// events removed from the ordinary row sequence.
    pub fn resolved_messages_with(&self, peer: &[u8; 32]) -> Result<Vec<ResolvedMessage>> {
        Ok(edits::resolve_pairwise(
            self.store.messages_with(peer)?,
            self.identity.public().ed,
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
        let me = self.identity.public().ed;
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
        let endpoints = self.store.contact_devices_for(peer)?;
        let mut routes = endpoints;
        if routes.is_empty() {
            routes.push(ContactDeviceRecord {
                account: *peer,
                device: *peer,
                name: None,
                certificate: Vec::new(),
                bundle: contact.bundle.clone(),
                hints: contact.hints.clone(),
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
                author: self.identity.public().ed,
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
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        for route in prepared {
            self.sessions.insert(route.route, route.after);
            if route.resets_capabilities {
                self.capabilities_advertised.remove(&route.route);
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

    /// One receive/flush cycle: drain every transport, consume what can be
    /// consumed (dedup → reassemble → decrypt → persist), queue encrypted
    /// receipts for consumed messages, then flush the outbound queue through
    /// the transport scheduler. Returns all events produced.
    pub async fn tick(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<Event>> {
        self.acknowledge_presentation(rng)?;
        if self.device_state_dirty {
            self.store.put_device_state(&self.device_state, rng)?;
            self.device_state_dirty = false;
        }
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
        let mut work: Vec<(Option<i64>, Envelope, u64)> = Vec::new();
        let mut gathered = HashSet::new();
        let mut redundant_pending = Vec::new();
        for (sequence, envelope, first_seen) in self
            .store
            .pending_all()?
            .into_iter()
            .take(MAX_PENDING_WORK_PER_TICK)
        {
            if gathered.insert(envelope.content_id()) {
                work.push((Some(sequence), envelope, first_seen));
            } else {
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
            let airtime = transport.profile().cost == CostClass::Airtime;
            // A dead link must not stall the others; its envelopes will
            // arrive via retry or another path.
            if let Ok(envelopes) = transport.recv().await {
                for envelope in envelopes {
                    let content_id = envelope.content_id();
                    if airtime
                        && self.bridge.is_some()
                        && !self.token_is_mine(&envelope.token, now)
                        && bridge_seen.insert((true, content_id))
                    {
                        if let Some(bridge) = &mut self.bridge {
                            bridge.admit(&envelope, true, now);
                        }
                    }
                    if !gathered.insert(content_id) {
                        continue;
                    }
                    if envelope.kind == EnvelopeKind::Fragment {
                        if fresh_fragments < MAX_PENDING_WORK_PER_TICK {
                            fresh_fragments += 1;
                            work.push((None, envelope, now));
                        }
                        continue;
                    }
                    match self.store.pending_push(&envelope, now, rng) {
                        Ok(sequence) if work.len() < MAX_PENDING_WORK_PER_TICK => {
                            work.push((Some(sequence), envelope, now));
                        }
                        Ok(_) | Err(kult_store::StoreError::PendingQuota) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            if self.bridge.is_some() {
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
                            if fresh_fragments < MAX_PENDING_WORK_PER_TICK {
                                fresh_fragments += 1;
                                work.push((None, envelope, now));
                            }
                            continue;
                        }
                        match self.store.pending_push(&envelope, now, rng) {
                            Ok(sequence) if work.len() < MAX_PENDING_WORK_PER_TICK => {
                                work.push((Some(sequence), envelope, now));
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
        work.retain(|(pending_sequence, env, first_seen)| {
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
            for (pending_sequence, env, first_seen) in work {
                match self.consume(
                    &env,
                    ConsumeOrigin {
                        depth: 0,
                        pending_sequence,
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
                    Consumed::Later => {
                        let sequence = match pending_sequence {
                            Some(sequence) => sequence,
                            None => match self.store.pending_push(&env, first_seen, rng) {
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
                        stash.push((Some(sequence), env, first_seen));
                    }
                }
            }
            if !stash.is_empty() && (established || self.apply_deferred_controls(now, rng)?) {
                work = stash;
                continue;
            }
            // Every entry in `stash` is already durable. Leaving it in place
            // is the retry action; no delete/reinsert cycle or new sequence
            // number is needed.
            break;
        }

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
                    acknowledge_presentation: None,
                    presentation_changed: false,
                }),
                rng,
            )?;
        }

        // 4. Flush the outbound queue, then — only with whatever airtime and
        //    attention is left — third-party transit (ADR-0009).
        self.flush(now, rng).await?;
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
        let mut bundle = PrekeyBundle::decode(bundle_bytes)?.verify(now)?;
        let reset_markers = self.store.reset_markers()?;
        if (reset_markers.contains(account) || reset_markers.contains(device))
            || self.device_state.manifest.devices.len() > 1
        {
            bundle = bundle.without_opk();
        }
        let linked = self.device_state.manifest.devices.len() > 1;
        let initiator = if linked {
            &self.device_identity
        } else {
            &self.identity
        };
        let step = self.begin_crypto_step()?;
        let initiated = initiate(initiator, &bundle, padded, now, rng);
        self.finish_crypto_step(step)?;
        let (session, init) = initiated?;
        let initial_bytes = if linked {
            let return_prekey = PrekeyBundle::build(
                &self.device_identity,
                &self.vault.spk(),
                &self.vault.pqspk()?,
                None,
                now + BUNDLE_TTL_SECS,
                Vec::new(),
            );
            let return_bundle = DevicePrekeyBundle::new(
                self.device_state.local_certificate.clone(),
                self.device_state.manifest.clone(),
                return_prekey,
            )?
            .encode()?;
            encode_device_initial(&DeviceInitialFlight {
                initial: init.encode(),
                return_bundle,
            })?
        } else {
            let return_bundle = PrekeyBundle::build(
                &self.identity,
                &self.vault.spk(),
                &self.vault.pqspk()?,
                None,
                now + BUNDLE_TTL_SECS,
                encode_hints(&self.own_hints),
            );
            encode_account_initial(&AccountInitialFlight {
                initial: init.encode(),
                return_bundle: return_bundle.encode(),
            })?
        };
        let step = self.begin_crypto_step()?;
        let sealed = seal_anonymous(&bundle.bundle().identity, HS_AD, &initial_bytes, rng);
        self.finish_crypto_step(step)?;
        Ok((
            session,
            Envelope::new(
                EnvelopeKind::Handshake,
                intro_token(device, epoch_day(now)),
                sealed,
            ),
        ))
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
        let me = self.identity.public().ed;
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
                        bundle: contact.bundle,
                        hints: contact.hints,
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
                    presentation_changed: false,
                }),
                rng,
            )?;
            self.before_memory_replacement()?;
            for route in prepared {
                self.sessions.insert(route.route, route.after);
                self.capabilities_advertised.remove(&route.route);
            }
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
                        presentation_changed: false,
                    }),
                    rng,
                )?;
                self.before_memory_replacement()?;
                for route in prepared {
                    self.sessions.insert(route.route, route.after);
                    if route.resets_capabilities {
                        self.capabilities_advertised.remove(&route.route);
                    }
                }
                self.after_memory_replacement()?;
            }
        }
        Ok(())
    }

    // ---- receive path ------------------------------------------------------

    fn apply_deferred_controls(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<bool> {
        let mut made_progress = false;
        for control in self
            .store
            .deferred_controls(MAX_DEFERRED_CONTROLS_PER_TICK)?
        {
            let (applied, acknowledged) = match control.kind {
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
                    self.apply_group_control(&control, now, rng, &mut established)?
                }
            };
            if !applied {
                continue;
            }
            made_progress = true;
            if acknowledged {
                continue;
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
                acknowledge_presentation: None,
                presentation_changed: false,
            }),
            rng,
        )?;
        Ok(Consumed::DoneAtomic)
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
                            },
                            now,
                            rng,
                            established,
                        )? {
                            // Reassembled before its session exists — stash
                            // the inner envelope for later ticks.
                            match self.store.pending_push(&inner, now, rng) {
                                Ok(_) | Err(kult_store::StoreError::PendingQuota) => {}
                                Err(error) => return Err(error.into()),
                            }
                        }
                    }
                }
                Ok(Consumed::Done)
            }
            EnvelopeKind::Handshake => {
                self.consume_handshake(env, origin.pending_sequence, now, rng, established)
            }
            EnvelopeKind::Message | EnvelopeKind::Receipt | EnvelopeKind::GroupControl => {
                self.consume_ratchet(env, origin.pending_sequence, now, rng, established)
            }
            EnvelopeKind::GroupMessage => {
                self.consume_group_message(env, origin.pending_sequence, now, rng)
            }
        }
    }

    fn consume_handshake(
        &mut self,
        env: &Envelope,
        pending_sequence: Option<i64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<Consumed> {
        // Every failure below is permanent for this envelope (it cannot
        // become decryptable later), so it is marked seen and dropped —
        // parsers never panic, dropped flights never wedge the queue.
        let step = self.begin_crypto_step()?;
        let device_open = open_anonymous(&self.device_identity, HS_AD, &env.body);
        self.finish_crypto_step(step)?;
        let (recipient, init_bytes) = if let Ok(bytes) = device_open {
            (&self.device_identity, bytes)
        } else {
            let step = self.begin_crypto_step()?;
            let account_open = open_anonymous(&self.identity, HS_AD, &env.body);
            self.finish_crypto_step(step)?;
            if let Ok(bytes) = account_open {
                (&self.identity, bytes)
            } else {
                return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
            }
        };
        let (raw_initial, sender_bundle, sender_account_bundle) =
            if let Some(flight) = decode_device_initial(&init_bytes) {
                let Ok(bundle) = DevicePrekeyBundle::decode(&flight.return_bundle) else {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                };
                if bundle.verify(now).is_err() {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                }
                (flight.initial, Some(bundle), None)
            } else if let Some(flight) = decode_account_initial(&init_bytes) {
                let Ok(bundle) = PrekeyBundle::decode(&flight.return_bundle) else {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                };
                if bundle.verify(now).is_err() {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
                }
                (flight.initial, None, Some(bundle))
            } else {
                (init_bytes, None, None)
            };
        let Ok(init) = InitialMessage::decode(&raw_initial) else {
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        };
        if sender_bundle
            .as_ref()
            .is_some_and(|bundle| bundle.prekey.identity != init.initiator)
            || sender_account_bundle
                .as_ref()
                .is_some_and(|bundle| bundle.identity != init.initiator)
        {
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        }
        if init.spk_id != self.vault.spk_id || init.pqspk_id != self.vault.pqspk_id {
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        }
        let opk = match init.opk_id {
            Some(id) => match self.vault.opk(id) {
                Some(opk) => Some(opk),
                None => {
                    return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
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
            return self.commit_terminal_input(env.content_id(), pending_sequence, rng);
        };

        let before_vault = self.vault.encode();
        let mut candidate_vault = self.vault.clone();
        if let Some(id) = init.opk_id {
            candidate_vault.remove_opk(id);
        }
        let after_vault = candidate_vault.encode();
        let peer_device = init.initiator.ed;
        let (peer, account_identity) = sender_bundle.as_ref().map_or_else(
            || (peer_device, init.initiator.clone()),
            |bundle| (bundle.manifest.account.ed, bundle.manifest.account.clone()),
        );
        let identity =
            postcard::to_allocvec(&account_identity).map_err(|_| NodeError::CorruptState)?;
        let account_return_bundle = sender_account_bundle
            .as_ref()
            .map_or_else(Vec::new, PrekeyBundle::encode);
        let account_return_hints = sender_account_bundle
            .as_ref()
            .map_or_else(Vec::new, |bundle| bundle.relay_hints.clone());
        let existing_contact = self.store.get_contact(&peer)?;
        let was_new_contact = existing_contact.is_none();
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
            self.validate_contact_device_manifest(&bundle.manifest)?;
            let state_id = bundle.manifest.state_id();
            let legacy_alias = existing_endpoints
                .iter()
                .find(|endpoint| endpoint.device == peer && endpoint.manifest_generation == 0);
            let mut active_by_issuance = bundle
                .manifest
                .devices
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
            for entry in &bundle.manifest.devices {
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
                    if !bundle.prekey.relay_hints.is_empty() || hints.is_empty() {
                        hints = bundle.prekey.relay_hints.clone();
                    }
                }
                let endpoint = ContactDeviceRecord {
                    account: peer,
                    device,
                    name: Some(entry.name.clone()),
                    certificate: postcard::to_allocvec(&entry.certificate)
                        .map_err(|_| NodeError::CorruptState)?,
                    bundle: endpoint_bundle,
                    hints,
                    manifest_generation: bundle.manifest.generation,
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
                bundle: account_return_bundle,
                hints: account_return_hints,
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
                if endpoint.name.is_none() {
                    endpoint.name.clone_from(&prior.name);
                }
                endpoint.last_seen = endpoint.last_seen.max(prior.last_seen);
            }
            endpoints.push(endpoint);
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
        delete_capabilities.push(peer_device);
        delete_capabilities.sort_unstable();
        delete_capabilities.dedup();
        let cleanup_set = cleanup_devices.iter().copied().collect::<HashSet<_>>();
        let delete_queue = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(sequence, item)| {
                cleanup_set.contains(&item.peer).then_some(QueueDelete {
                    sequence,
                    content_id: item.envelope.content_id(),
                })
            })
            .collect::<Vec<_>>();
        let group_candidates = self.prepare_groups_on_session_established(&peer)?;
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
        let needs_receipt = prepared_inbound.is_some();
        let receipt_queue = if needs_receipt {
            let payload = ReceiptPayload {
                acks: vec![env.content_id()],
                nacks: Vec::new(),
            }
            .encode();
            Some(self.prepare_control_queue(&mut session, peer_device, &payload, now, rng)?)
        } else {
            None
        };
        let prior_session = self.store.get_session(&peer_device)?;
        let delete_devices = delete_endpoint_records
            .iter()
            .map(|before| ContactDeviceDelete { before })
            .collect::<Vec<_>>();
        let source_pending = Self::pending_delete(pending_sequence, env.content_id());
        let mut events = Vec::new();
        if was_new_contact {
            events.push(Event::ContactAdded { peer });
        }
        events.push(Event::SessionEstablished { peer });
        if let Some(prepared) = prepared_inbound.as_ref() {
            events.extend(prepared.events.clone());
        }
        let prekeys = init.opk_id.map(|_| PrekeyTransition {
            before: before_vault.as_ref(),
            after: after_vault.as_ref(),
        });
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
                content_id: env.content_id(),
                received_at: now,
                receipt_replay: needs_receipt,
                source_pending,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        if init.opk_id.is_some() {
            self.vault = candidate_vault;
        }
        for device in cleanup_devices {
            self.sessions.remove(&device);
            self.capabilities_advertised.remove(&device);
        }
        self.capabilities_advertised.remove(&peer_device);
        self.sessions.insert(peer_device, session);
        *established = true;
        self.after_memory_replacement()?;
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
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
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
                                media_transfers: &[],
                                media_objects: &[],
                                capabilities: Some(&capabilities),
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
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
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
                            media_transfers: &[],
                            media_objects: &[],
                            capabilities: None,
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
                        media_transfers: &[],
                        media_objects: &[],
                        capabilities: None,
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
            formats: vec![FormatCapabilities {
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
            }],
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
        let me = self.identity.public().ed;
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
        let me = self.identity.public().ed;
        let device = self.device_id();
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        (lo..=hi).any(|epoch| {
            bool::from(intro_token(&me, epoch).ct_eq(token))
                || (device != me && bool::from(intro_token(&device, epoch).ct_eq(token)))
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

    fn commit_queue_maintenance(
        &mut self,
        sequence: i64,
        before: &QueueItem,
        after: Option<&QueueItem>,
        prepared: PreparedDeliveryUpdate,
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
                    rng,
                )?;
                continue;
            }
            if now < item.next_attempt_at {
                continue;
            }
            // A route that keeps failing is a stale-hint suspect: re-consult
            // the discovery planes for the peer's current address.
            let refresh = item.attempts >= HINT_REFRESH_MIN_ATTEMPTS;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let hints =
                match before_timeout(remaining, self.resolve_hints(&item.peer, now, refresh, rng))
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
                            rng,
                        )?;
                        break;
                    }
                };
            let oversize = item.envelope.encode().len() > AIRTIME_CEILING_BYTES;
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
            let mut sent_fragments = None;
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
                if let Ok(fragments) = result {
                    sent_fragments = fragments;
                    sent = true;
                    break;
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
                    self.commit_queue_maintenance(seq, &before, Some(&item), prepared, rng)?;
                } else {
                    // Receipts, capability controls, fragments, and realtime
                    // controls are terminal at transport handoff.
                    self.commit_queue_maintenance(seq, &before, None, prepared, rng)?;
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
                schedule_passive_retry(&mut item, now);
                self.commit_queue_maintenance(
                    seq,
                    &before,
                    Some(&item),
                    PreparedDeliveryUpdate::default(),
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

    fn hints_for(&self, peer: &[u8; 32]) -> Result<Vec<DeliveryHint>> {
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

    /// Delivery hints for a peer, consulting the discovery planes when the
    /// contact record has none — or, with `refresh`, when delivery over the
    /// stored hints keeps failing. Sealed sender means an inbound handshake
    /// never reveals a return path — for a contact learned that way, the
    /// peer's published DHT bundle is where the reply path comes from. A
    /// pairing-time hint also goes stale whenever the peer rebinds to fresh
    /// OS-assigned ports (mobile shells restart often), so a failing route
    /// re-consults the same bundle for the peer's current address instead
    /// of retrying the dead one forever. Discovered hints are persisted via
    /// [`Node::set_hints`]; refresh lookups are rate-limited per account
    /// (and failed sends stay gated by the delivery engine's backoff
    /// regardless).
    async fn resolve_hints(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        refresh: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<DeliveryHint>> {
        let hints = self.hints_for(peer)?;
        if self.discoveries.is_empty() || (!hints.is_empty() && !refresh) {
            return Ok(hints);
        }
        let account = self.account_for_device(peer)?;
        if !hints.is_empty() {
            // Refresh of a non-empty (possibly stale) hint set: bounded by
            // the per-account interval so retries stay cheap.
            if self
                .hint_refresh
                .get(&account)
                .is_some_and(|next| now < *next)
            {
                return Ok(hints);
            }
            self.hint_refresh
                .insert(account, now + HINT_REFRESH_INTERVAL_SECS);
        }
        let Some(contact) = self.store.get_contact(&account)? else {
            return Ok(hints);
        };
        let Ok(identity) = postcard::from_bytes::<IdentityPublic>(&contact.identity) else {
            return Ok(hints);
        };
        let Some(bundle) = self.lookup_bundle(identity.address_digest(), now).await else {
            return Ok(hints);
        };
        let found = decode_hints(&bundle.relay_hints);
        if found.is_empty() {
            return Ok(hints);
        }
        if found != hints {
            self.set_hints(&account, &found, rng)?;
        }
        Ok(found)
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
) -> Result<Option<Vec<Vec<u8>>>> {
    let mtu = transport.profile().mtu;
    let encoded = envelope.try_encode()?;
    if encoded.len() <= mtu {
        transport.send(hint, envelope).await?;
        return Ok(None);
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
        transport.send(hint, &fragment_envelope).await?;
    }
    Ok(Some(bodies))
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

fn encode_hints(hints: &[DeliveryHint]) -> Vec<Vec<u8>> {
    hints
        .iter()
        .map(|h| postcard::to_allocvec(h).expect("hint serialization cannot fail"))
        .collect()
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
        let alice_peer = alice.identity.public().ed;

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
