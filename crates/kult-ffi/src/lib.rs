//! UniFFI bindings exposing the node's command/event API to Kotlin, Swift,
//! and desktop shells (docs/03-architecture.md FFI layer, ADR-0010).
//!
//! The surface is exactly `kult-node`'s command/event API
//! (docs/09-implementation-guide.md §3.5) — nothing more. Behind it sits an
//! embedded in-process runtime ([`runtime`]) composing the same carriers and
//! connectivity lifecycle as `kultd`; applications get a running node from a
//! single constructor and never touch Rust internals.
//!
//! Conventions at the boundary (ADR-0010):
//! - Calls are **blocking** — bindings dispatch them off the UI thread
//!   (Kotlin coroutines / Swift dispatch queues make this one line).
//! - Events arrive on a dedicated thread through the application's
//!   [`EventListener`], in order, never on a caller's stack.
//! - Peer ids and message ids travel as lowercase hex strings; prekey
//!   bundles as bytes (they are QR/file payloads, not identifiers).
//! - Delivery states are honest by construction: `Sent` means handed to a
//!   link, `Delivered` means an end-to-end encrypted receipt came back.
//!
//! Generating bindings: build the library, then run
//! `cargo run -p kult-ffi --features bindgen --bin uniffi-bindgen -- \
//!  generate --library target/debug/libkult_ffi.so --language kotlin --out-dir out`
//! (swap `--language swift` for iOS).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod audio;
mod image_edit;
mod runtime;

pub use audio::{
    canonicalize_recorded_audio, probe_recorded_audio, AudioInfo, AUDIO_BITS_PER_SAMPLE,
    AUDIO_CHANNELS, AUDIO_MAX_BYTES, AUDIO_MAX_DURATION_MS, AUDIO_MEDIA_TYPE, AUDIO_SAMPLE_RATE,
    AUDIO_WAVEFORM_BINS,
};
pub use image_edit::{
    edit_image, probe_edited_image, ImageCrop, ImageEditRecipe, ImageEditRegion,
    ImageEditRegionKind, ImageInfo, IMAGE_MAX_DIMENSION, IMAGE_MAX_INPUT_BYTES,
    IMAGE_MAX_OUTPUT_BYTES, IMAGE_MAX_PIXELS, IMAGE_MAX_REGIONS, IMAGE_MEDIA_TYPE,
};

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

use kult_transport::DeliveryHint;

use runtime::{Msg, RestoreSource, Runtime, RuntimeConfig};

uniffi::setup_scaffolding!();

/// Stable label failure categories shared by Kotlin and Swift wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LabelErrorCode {
    /// Label id was not exactly 16 bytes of hexadecimal.
    InvalidId,
    /// Typed peer/group/note-to-self target was malformed.
    InvalidTarget,
    /// Name violated the exact UTF-8 length or fixed whitespace rule.
    InvalidName,
    /// Color was outside the canonical vocabulary.
    InvalidColor,
    /// Stable label id has no definition.
    UnknownLabel,
    /// Exact typed conversation is unavailable.
    UnavailableTarget,
    /// Definition limit is exhausted.
    DefinitionLimit,
    /// Aggregate assignment limit is exhausted.
    AssignmentLimit,
    /// Per-conversation assignment limit is exhausted.
    ConversationLimit,
    /// Cryptorandom id collision retry budget was exhausted.
    IdCollision,
    /// Requested stale assignment is now active or absent.
    StaleAssignmentActive,
    /// Explicit destructive confirmation was absent.
    ConfirmationRequired,
    /// Storage or another local implementation failure occurred.
    StorageFailure,
}

/// Errors crossing the FFI boundary. Messages are the node's own, verbatim
/// — honest and human-readable, never downgraded to a fake success.
///
/// The field is named `reason` (not `message`): Kotlin exposes errors as
/// exception classes, and a field literally named `message` collides with
/// `Throwable.message` in the generated bindings.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    /// Startup failed: store open/create (wrong passphrase, corrupt file),
    /// transport bind, or an unreachable configured radio.
    Startup {
        /// What failed, verbatim.
        reason: String,
    },
    /// The node rejected the operation (unknown contact, malformed input…).
    Node {
        /// The node's error, verbatim.
        reason: String,
    },
    /// A private-label operation failed with a stable programmatic category.
    Label {
        /// Stable category shared across Rust, Kotlin, and Swift.
        code: LabelErrorCode,
        /// Generic render-safe explanation with no label text or relationship.
        reason: String,
    },
    /// The node was stopped; the handle is spent.
    Stopped,
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Startup { reason } => write!(f, "startup: {reason}"),
            Self::Node { reason } => write!(f, "{reason}"),
            Self::Label { reason, .. } => write!(f, "{reason}"),
            Self::Stopped => write!(f, "node is stopped"),
        }
    }
}

impl std::error::Error for FfiError {}

/// Argon2id cost profile for store creation (docs/04-cryptography.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KdfChoice {
    /// 256 MiB — desktops.
    Desktop,
    /// 64 MiB — phones.
    Mobile,
}

/// Everything a node needs to run. Get a sensible baseline from
/// [`default_config`] and override what the platform knows better.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Config {
    /// Data directory: the encrypted store (`node.db`) lives here, created
    /// on first run.
    pub data_dir: String,
    /// Store passphrase.
    pub passphrase: String,
    /// Argon2id cost profile for store creation.
    pub kdf: KdfChoice,
    /// Multiaddrs to listen on.
    pub listen: Vec<String>,
    /// DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
    /// discovery then never leaves this node.
    pub bootstrap: Vec<String>,
    /// Relay to reserve a circuit at when NAT-ed. Defaults to the first
    /// bootstrap peer when unset.
    pub relay: Option<String>,
    /// Mailbox relays to check in with (register accept-filters, collect).
    /// These are also published as relay hints in our prekey bundle.
    pub mailboxes: Vec<String>,
    /// Volunteer bounded mailbox service for others.
    pub serve_mailbox: bool,
    /// Announce on, and discover peers from, the local network over mDNS.
    /// What makes LAN-only operation configuration-free.
    pub mdns: bool,
    /// Also receive from a sneakernet spool directory.
    pub spool: Option<String>,
    /// Attach a Meshtastic radio on this USB-serial port (needs a build
    /// with the `meshtastic` feature; unreachable radio = startup error).
    pub meshtastic_serial: Option<String>,
    /// Attach a Meshtastic radio via its network API (`host:4403`).
    pub meshtastic_tcp: Option<String>,
    /// Bridge third-party sealed traffic between mesh and internet
    /// (ADR-0009). Takes effect only when a radio is attached.
    pub bridge: bool,
    /// Delivery-engine heartbeat, milliseconds.
    pub tick_ms: u64,
    /// Mailbox check-in cadence, seconds.
    pub checkin_secs: u64,
    /// NAT probe cadence, seconds (until a circuit is reserved).
    pub nat_secs: u64,
}

/// A sensible baseline configuration, mirroring `kultd`'s defaults: QUIC +
/// TCP on OS-assigned ports, desktop KDF profile, mDNS on, no bootstrap
/// peers, bridging armed (it activates only if a radio is attached).
#[uniffi::export]
pub fn default_config(data_dir: String, passphrase: String) -> Config {
    Config {
        data_dir,
        passphrase,
        kdf: KdfChoice::Desktop,
        listen: vec![
            "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
            "/ip4/0.0.0.0/tcp/0".to_owned(),
        ],
        bootstrap: Vec::new(),
        relay: None,
        mailboxes: Vec::new(),
        serve_mailbox: false,
        mdns: true,
        spool: None,
        meshtastic_serial: None,
        meshtastic_tcp: None,
        bridge: true,
        tick_ms: 500,
        checkin_secs: 300,
        nat_secs: 30,
    }
}

/// How to reach a contact, per transport (docs/05-transports.md).
#[derive(Clone, Debug, uniffi::Enum)]
pub enum Hint {
    /// A libp2p multiaddr (with `/p2p/…`).
    Multiaddr {
        /// The multiaddr string.
        addr: String,
    },
    /// A mailbox relay's multiaddr: deposit sealed envelopes there.
    Relay {
        /// The relay's multiaddr.
        addr: String,
    },
    /// A sneakernet spool directory.
    Spool {
        /// The directory path.
        path: String,
    },
    /// A Meshtastic node number; `u32::MAX` floods the whole mesh (the
    /// normal mode — recipients recognize their delivery tokens).
    Mesh {
        /// The node number.
        node: u32,
    },
}

impl Hint {
    fn to_delivery(&self) -> DeliveryHint {
        match self {
            Self::Multiaddr { addr } => DeliveryHint::Multiaddr(addr.clone()),
            Self::Relay { addr } => DeliveryHint::Relay(addr.clone()),
            Self::Spool { path } => DeliveryHint::Spool(path.into()),
            Self::Mesh { node } => DeliveryHint::MeshNode(*node),
        }
    }
}

/// Delivery state of a message (docs/03-architecture.md §3). Honest by
/// construction: `Delivered` is an end-to-end encrypted receipt, never a
/// transport ack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryState {
    /// Persisted locally, not yet handed to any transport.
    Queued,
    /// Handed to at least one transport.
    Sent,
    /// Encrypted delivery receipt received.
    Delivered,
    /// Inbound message (no delivery tracking).
    Received,
}

impl DeliveryState {
    fn from_store(state: kult_store::DeliveryState) -> Self {
        match state {
            kult_store::DeliveryState::Queued => Self::Queued,
            kult_store::DeliveryState::Sent => Self::Sent,
            kult_store::DeliveryState::Delivered => Self::Delivered,
            kult_store::DeliveryState::Received => Self::Received,
        }
    }
}

/// Direction of a stored message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Direction {
    /// Sent by this device.
    Outbound,
    /// Received from a peer.
    Inbound,
}

/// Application-visible interpretation of authenticated message content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ContentKind {
    /// Valid UTF-8 from the permanent pre-frame compatibility path.
    LegacyText,
    /// Canonical framed text.
    Text,
    /// Supported encrypted attachment offer.
    Attachment,
    /// Canonical group Mention with stable peer-targeted UTF-8 byte spans.
    Mention,
    /// Authenticated content this version cannot interpret.
    Unsupported,
    /// A typed frame that violated the canonical contract.
    Malformed,
}

/// Pairwise or sender-key group attachment conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentConversation {
    /// Conversation with one contact.
    Pairwise,
    /// Sender-key group conversation.
    Group,
}

/// Local direction of an attachment transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentDirection {
    /// Bytes are being received from the manifest author.
    Inbound,
    /// This device authored and may serve the bytes.
    Outbound,
}

/// Durable attachment lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentState {
    /// Valid offer retained in history.
    Offered,
    /// Waiting for explicit local consent.
    AwaitingConsent,
    /// Accepted and waiting for an eligible carrier.
    Queued,
    /// Authenticated transfer work is active.
    Transferring,
    /// Explicitly paused while verified progress remains durable.
    Paused,
    /// Every chunk and the final object hash were verified.
    Complete,
    /// Durable receiver refusal.
    Rejected,
    /// Transfer activity was cancelled.
    Cancelled,
    /// Authentication or final integrity failed.
    Corrupt,
    /// Required local state or sealed files are unavailable.
    Unavailable,
}

impl AttachmentState {
    fn from_store(state: kult_store::MediaTransferState) -> Self {
        match state {
            kult_store::MediaTransferState::Offered => Self::Offered,
            kult_store::MediaTransferState::AwaitingConsent => Self::AwaitingConsent,
            kult_store::MediaTransferState::Queued => Self::Queued,
            kult_store::MediaTransferState::Transferring => Self::Transferring,
            kult_store::MediaTransferState::Paused => Self::Paused,
            kult_store::MediaTransferState::Complete => Self::Complete,
            kult_store::MediaTransferState::Rejected => Self::Rejected,
            kult_store::MediaTransferState::Cancelled => Self::Cancelled,
            kult_store::MediaTransferState::Corrupt => Self::Corrupt,
            kult_store::MediaTransferState::Unavailable => Self::Unavailable,
        }
    }
}

/// Render-safe progress for one primary or preview object.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentObject {
    /// Whether this object is the optional preview.
    pub preview: bool,
    /// Exact authenticated object size.
    pub total_bytes: u64,
    /// Bytes represented by durably verified chunks.
    pub verified_bytes: u64,
    /// Authenticated but untrusted media-type display hint.
    pub media_type: String,
    /// Optional sanitized display basename.
    pub filename: Option<String>,
    /// Object lifecycle state.
    pub state: AttachmentState,
}

/// Render-safe attachment state. Cryptographic keys, object ids, hashes,
/// chunk paths, bitmaps, ranges, frames, and transport addresses stay private.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Attachment {
    /// Random local transfer id (hex), used by lifecycle methods.
    pub transfer_id: String,
    /// Peer serving or being served (hex).
    pub peer: String,
    /// Pairwise or group conversation.
    pub conversation: AttachmentConversation,
    /// Group id for group attachments; absent for pairwise transfers.
    pub group: Option<String>,
    /// Inbound or outbound on this device.
    pub direction: AttachmentDirection,
    /// Original manifest author (hex).
    pub author: String,
    /// Stable encrypted content id (hex).
    pub content_id: String,
    /// Transfer lifecycle state.
    pub state: AttachmentState,
    /// Primary object followed by an optional preview.
    pub objects: Vec<AttachmentObject>,
}

impl Attachment {
    fn from_node(attachment: kult_node::AttachmentInfo) -> Self {
        Self {
            transfer_id: hex_encode(&attachment.transfer_id),
            peer: hex_encode(&attachment.peer),
            conversation: match attachment.conversation {
                kult_node::AttachmentConversation::Pairwise => AttachmentConversation::Pairwise,
                kult_node::AttachmentConversation::Group => AttachmentConversation::Group,
            },
            group: attachment.group.map(|group| hex_encode(&group)),
            direction: match attachment.direction {
                kult_node::AttachmentDirection::Inbound => AttachmentDirection::Inbound,
                kult_node::AttachmentDirection::Outbound => AttachmentDirection::Outbound,
            },
            author: hex_encode(&attachment.author),
            content_id: hex_encode(&attachment.content_id),
            state: AttachmentState::from_store(attachment.state),
            objects: attachment
                .objects
                .into_iter()
                .map(|object| AttachmentObject {
                    preview: object.preview,
                    total_bytes: object.total_bytes,
                    verified_bytes: object.verified_bytes,
                    media_type: object.media_type,
                    filename: object.filename,
                    state: AttachmentState::from_store(object.state),
                })
                .collect(),
        }
    }
}

/// A stored contact.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Contact {
    /// The contact's peer id (hex).
    pub peer: String,
    /// Local display name.
    pub name: String,
    /// Whether safety numbers were verified out-of-band.
    pub verified: bool,
}

/// Exact typed target kind for local label membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LabelTargetKind {
    /// Pairwise conversation keyed by peer identity.
    Peer,
    /// Sender-key group keyed by group id.
    Group,
    /// Reserved device-local note-to-self conversation.
    NoteToSelf,
}

/// Exact technical target used by label mutations.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LabelTarget {
    /// Target type; display names are never accepted here.
    pub kind: LabelTargetKind,
    /// 64-hex-character peer/group id, or absent for note-to-self.
    pub id: Option<String>,
}

/// Render-safe available conversation in label membership/filter output.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LabelConversation {
    /// Exact technical typed target.
    pub target: LabelTarget,
    /// Current local petname/group name; absent for note-to-self.
    pub display_name: Option<String>,
}

/// Render-safe private label definition.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Label {
    /// Stable random 32-hex-character id for technical mutation calls.
    pub id: String,
    /// Exact user-authored UTF-8 label name.
    pub name: String,
    /// Canonical color token, with unknown stored values safely neutralized.
    pub color: String,
    /// Stable zero-based durable insertion order.
    pub order: u32,
}

/// Local multi-label matching semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LabelMatchMode {
    /// Match at least one selected label.
    Any,
    /// Match every selected label.
    All,
}

/// Why a durable membership is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StaleLabelReason {
    /// Label definition is unavailable.
    MissingLabel,
    /// Exact conversation target is unavailable.
    UnavailableConversation,
    /// Both definition and target are unavailable.
    MissingLabelAndConversation,
}

/// Render-safe stale membership diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct StaleLabel {
    /// Stable technical label id.
    pub label: String,
    /// Exact typed target.
    pub target: LabelTarget,
    /// The unavailable side or sides.
    pub reason: StaleLabelReason,
}

/// Deterministic local label-filter result.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LabelFilterResult {
    /// Deduplicated available selected ids in caller order.
    pub selected: Vec<String>,
    /// Selected ids whose definitions are unavailable.
    pub unavailable_selected: Vec<String>,
    /// Eligible conversations matching the active selection.
    pub conversations: Vec<LabelConversation>,
}

/// Best currently known carrier class for one contact. Positive verdicts are
/// advisory and expire at the time carried by [`CarrierCapabilitySnapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CarrierCapability {
    /// Direct low-latency non-airtime path reachable now.
    Realtime,
    /// Non-airtime path reachable now or by store-and-forward.
    Bulk,
    /// Only airtime-budgeted reachability is currently known.
    MeshOnly,
    /// No fresh reachable carrier is currently known.
    OfflineOrUnknown,
}

impl CarrierCapability {
    fn from_node(capability: kult_node::CarrierCapability) -> Self {
        match capability {
            kult_node::CarrierCapability::Realtime => Self::Realtime,
            kult_node::CarrierCapability::Bulk => Self::Bulk,
            kult_node::CarrierCapability::MeshOnly => Self::MeshOnly,
            kult_node::CarrierCapability::OfflineOrUnknown => Self::OfflineOrUnknown,
        }
    }
}

/// Stable, time-bounded carrier verdict for one contact.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CarrierCapabilitySnapshot {
    /// Contact peer id (hex).
    pub peer: String,
    /// Best observed carrier class.
    pub capability: CarrierCapability,
    /// Unix time at which transports were probed.
    pub observed_at: u64,
    /// Unix time at which the verdict stops being authoritative.
    pub expires_at: u64,
}

impl CarrierCapabilitySnapshot {
    fn from_node(snapshot: kult_node::CarrierCapabilitySnapshot) -> Self {
        Self {
            peer: hex_encode(&snapshot.peer),
            capability: CarrierCapability::from_node(snapshot.capability),
            observed_at: snapshot.observed_at,
            expires_at: snapshot.expires_at,
        }
    }
}

/// One message in a conversation's history.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Message {
    /// Message record id (hex).
    pub id: String,
    /// The conversation peer (hex).
    pub peer: String,
    /// Sent or received.
    pub direction: Direction,
    /// Delivery state.
    pub state: DeliveryState,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message body (UTF-8 text).
    pub body: String,
    /// Explicit content interpretation.
    pub content_kind: ContentKind,
}

/// One message in the reserved device-local note-to-self conversation.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NoteMessage {
    /// Local note record id (hex).
    pub id: String,
    /// Stable reserved identity: `note_to_self`.
    pub conversation: String,
    /// Unix seconds when the note was added.
    pub timestamp: u64,
    /// UTF-8 note text.
    pub body: String,
}

/// Destination type for a scheduled outbox entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ScheduledConversation {
    /// Pairwise conversation with a contact.
    Peer,
    /// Sender-key group conversation.
    Group,
}

/// Text sealed locally until an absolute UTC activation instant.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ScheduledMessage {
    /// Stable id retained after activation (hex).
    pub id: String,
    /// Pairwise or group destination.
    pub conversation: ScheduledConversation,
    /// Peer or group id (hex).
    pub destination: String,
    /// Unix time when the schedule was created.
    pub created_at: u64,
    /// Absolute UTC Unix send instant.
    pub not_before: u64,
    /// UTF-8 message text.
    pub body: String,
}

/// A sender-key group, excluding every secret and chain value.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Group {
    /// Group id (hex).
    pub id: String,
    /// Creator-controlled display name.
    pub name: String,
    /// Managing member's peer id (hex).
    pub creator: String,
    /// Full roster, this node included (hex peer ids).
    pub members: Vec<String>,
}

/// Honest delivery state for one member's copy of an outbound group message.
#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupDelivery {
    /// Member peer id (hex).
    pub peer: String,
    /// Delivery state for this member's copy.
    pub state: DeliveryState,
}

/// One render-safe semantic Mention span. Offsets address the exact fallback
/// text in UTF-8 bytes and `target` is an explicit peer id, never a petname.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MentionSpan {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
    /// Exact target peer id (hex).
    pub target: String,
}

/// Why one current group co-member blocks semantic Mention content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MentionCapabilityIssueReason {
    /// No authenticated capability exists for the current session.
    Unknown,
    /// The current authenticated capability omits exact Mention kind v1.
    Unsupported,
}

/// One current group co-member that blocks semantic Mention content.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MentionCapabilityIssue {
    /// Exact member peer id (hex).
    pub peer: String,
    /// Unknown or explicitly unsupported.
    pub reason: MentionCapabilityIssueReason,
}

/// Current all-member Mention support and immutable local review binding.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct GroupMentionCapability {
    /// Group id (hex).
    pub group: String,
    /// True only when every current co-member advertises exact Mention v1.
    pub supported: bool,
    /// Opaque token binding current roster, display mapping, and support.
    pub review_token: String,
    /// Incompatible or unknown current co-members.
    pub issues: Vec<MentionCapabilityIssue>,
}

/// One message in a group's history.
#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMessage {
    /// Group message record id (hex).
    pub id: String,
    /// Group id (hex).
    pub group: String,
    /// Sending member's peer id (hex).
    pub sender: String,
    /// Sent or received.
    pub direction: Direction,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message body (UTF-8 text).
    pub body: String,
    /// Explicit content interpretation.
    pub content_kind: ContentKind,
    /// Stable semantic Mention spans; empty for every other content kind.
    pub mention_spans: Vec<MentionSpan>,
    /// Per-member delivery states (outbound only).
    pub deliveries: Vec<GroupDelivery>,
}

/// A comparable safety number (docs/06-identity-trust.md): both parties
/// compute the identical value; compare out-of-band.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SafetyNumber {
    /// 60 decimal digits.
    pub digits: String,
    /// The digits grouped 5-at-a-time for display.
    pub display: String,
    /// Raw 32-byte comparison value for QR encoding.
    pub qr: Vec<u8>,
}

/// NAT reachability as last probed (docs/05-transports.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NatVerdict {
    /// Publicly reachable.
    Public,
    /// Behind NAT; a relay circuit will be reserved when one is configured.
    Private,
    /// Not probed yet (needs a peer to dial back).
    Unknown,
}

/// A point-in-time snapshot of the node.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Status {
    /// This node's human-shareable kult address.
    pub address: String,
    /// This node's peer id (hex).
    pub peer: String,
    /// Live listen addresses (circuit addresses included once reserved).
    pub listen: Vec<String>,
    /// Peers currently visible on the LAN via mDNS.
    pub lan_peers: Vec<String>,
    /// NAT reachability as last probed.
    pub nat: NatVerdict,
    /// Outbound messages not yet delivered.
    pub queued: u64,
    /// Plaintext messages sealed locally until a future UTC instant.
    pub scheduled: u64,
    /// Third-party envelopes buffered for mesh↔internet bridging.
    pub transit: u64,
    /// Stored contacts.
    pub contacts: u64,
}

/// What the node reports back to the application
/// (docs/09-implementation-guide.md §3.5).
#[derive(Clone, Debug, uniffi::Enum)]
pub enum Event {
    /// Private local labels changed; shells re-read local label state.
    LabelsChanged,
    /// A scheduled message was created or edited.
    ScheduledMessageUpdated {
        /// Stable message id (hex).
        id: String,
    },
    /// A scheduled message was cancelled before activation.
    ScheduledMessageCancelled {
        /// Stable message id (hex).
        id: String,
    },
    /// A scheduled message entered the ordinary encrypted delivery queue.
    ScheduledMessageActivated {
        /// Stable message id (hex).
        id: String,
    },
    /// A message record changed delivery state
    /// (`Queued` → `Sent` → `Delivered`).
    DeliveryUpdated {
        /// Message record id (hex).
        id: String,
        /// The new state.
        state: DeliveryState,
    },
    /// An inbound message was decrypted and stored.
    MessageReceived {
        /// Sender peer id (hex).
        peer: String,
        /// Message record id (hex).
        id: String,
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Decrypted body.
        body: String,
        /// Explicit content interpretation.
        content_kind: ContentKind,
    },
    /// Text was appended to the reserved local note-to-self conversation.
    NoteToSelfMessageAdded {
        /// Stable reserved identity: `note_to_self`.
        conversation: String,
        /// Local note record id (hex).
        id: String,
        /// Local creation time (Unix seconds).
        timestamp: u64,
        /// UTF-8 note text.
        body: String,
    },
    /// An unknown peer completed a handshake with us; a contact stub was
    /// created (unverified, no hints — the application fills those in).
    ContactAdded {
        /// The new peer (hex).
        peer: String,
    },
    /// A ratchet session with this peer was (re-)established from an
    /// inbound handshake. A *re*-establishment for a known contact means
    /// their key or device changed — surface it.
    SessionEstablished {
        /// The peer (hex).
        peer: String,
    },
    /// An outbound message exceeds the airtime ceiling and only
    /// duty-cycle-limited (LoRa) carriers currently reach the recipient:
    /// held, honestly — "will send when a faster link exists".
    AwaitingFasterLink {
        /// Message record id (hex).
        id: String,
    },
    /// The authoritative time-bounded carrier verdict for a contact changed.
    CarrierCapabilityChanged {
        /// Current snapshot.
        snapshot: CarrierCapabilitySnapshot,
    },
    /// A group was created, joined, re-keyed, re-rostered, or left.
    GroupUpdated {
        /// Group id (hex).
        group: String,
    },
    /// An inbound group message was decrypted and stored.
    GroupMessageReceived {
        /// Group id (hex).
        group: String,
        /// Sending member's peer id (hex).
        sender: String,
        /// Group message record id (hex).
        id: String,
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Decrypted body.
        body: String,
        /// Explicit content interpretation.
        content_kind: ContentKind,
        /// Stable semantic spans; empty for every other content kind.
        mention_spans: Vec<MentionSpan>,
    },
    /// A stored canonical group Mention targets this exact local peer.
    MentionReceived {
        /// Stored group message id (hex). Text and target lists stay out of
        /// the notification signal and are read from protected history.
        id: String,
    },
    /// One member's copy of an outbound group message changed state.
    GroupDeliveryUpdated {
        /// Group message record id (hex).
        id: String,
        /// Member peer id (hex).
        peer: String,
        /// Delivery state for this member's copy.
        state: DeliveryState,
    },
    /// Attachment offer, consent, progress, completion, or terminal state
    /// changed.
    AttachmentUpdated {
        /// Current render-safe transfer state.
        attachment: Attachment,
    },
}

impl Event {
    /// Convert a node event. `None` for variants this binding predates —
    /// the enum is `#[non_exhaustive]` and new variants ship with an FFI
    /// update, never silently mislabeled.
    fn from_node(event: kult_node::Event) -> Option<Self> {
        Some(match event {
            kult_node::Event::LabelsChanged => Self::LabelsChanged,
            kult_node::Event::ScheduledMessageUpdated { id } => Self::ScheduledMessageUpdated {
                id: hex_encode(&id),
            },
            kult_node::Event::ScheduledMessageCancelled { id } => Self::ScheduledMessageCancelled {
                id: hex_encode(&id),
            },
            kult_node::Event::ScheduledMessageActivated { id } => Self::ScheduledMessageActivated {
                id: hex_encode(&id),
            },
            kult_node::Event::DeliveryUpdated { id, state } => Self::DeliveryUpdated {
                id: hex_encode(&id),
                state: DeliveryState::from_store(state),
            },
            kult_node::Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content,
            } => Self::MessageReceived {
                peer: hex_encode(&peer),
                id: hex_encode(&id),
                timestamp,
                body: render_event_body(&body, &content),
                content_kind: content_kind(&content),
            },
            kult_node::Event::NoteToSelfMessageAdded {
                id,
                timestamp,
                body,
            } => Self::NoteToSelfMessageAdded {
                conversation: kult_node::NOTE_TO_SELF_CONVERSATION_ID.to_owned(),
                id: hex_encode(&id),
                timestamp,
                body,
            },
            kult_node::Event::ContactAdded { peer } => Self::ContactAdded {
                peer: hex_encode(&peer),
            },
            kult_node::Event::SessionEstablished { peer } => Self::SessionEstablished {
                peer: hex_encode(&peer),
            },
            kult_node::Event::AwaitingFasterLink { id } => Self::AwaitingFasterLink {
                id: hex_encode(&id),
            },
            kult_node::Event::CarrierCapabilityChanged { snapshot } => {
                Self::CarrierCapabilityChanged {
                    snapshot: CarrierCapabilitySnapshot::from_node(snapshot),
                }
            }
            kult_node::Event::GroupUpdated { group } => Self::GroupUpdated {
                group: hex_encode(&group),
            },
            kult_node::Event::GroupMessageReceived {
                group,
                sender,
                id,
                timestamp,
                body,
                content,
            } => Self::GroupMessageReceived {
                group: hex_encode(&group),
                sender: hex_encode(&sender),
                id: hex_encode(&id),
                timestamp,
                body: render_event_body(&body, &content),
                content_kind: content_kind(&content),
                mention_spans: mention_status(&content),
            },
            kult_node::Event::MentionReceived { id } => Self::MentionReceived {
                id: hex_encode(&id),
            },
            kult_node::Event::GroupDeliveryUpdated { id, peer, state } => {
                Self::GroupDeliveryUpdated {
                    id: hex_encode(&id),
                    peer: hex_encode(&peer),
                    state: DeliveryState::from_store(state),
                }
            }
            kult_node::Event::AttachmentUpdated { attachment } => Self::AttachmentUpdated {
                attachment: Attachment::from_node(attachment),
            },
            _ => return None,
        })
    }
}

/// The application's event sink. Called on a dedicated thread, in order;
/// implementations may block briefly (the node is never stalled) but should
/// hand off to their own executor quickly.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    /// One node event.
    fn on_event(&self, event: Event);
}

/// A running node: the full delivery engine over the configured carriers,
/// embedded in-process. One constructor, blocking methods, events through
/// the [`EventListener`]. Call [`KultNode::stop`] when done.
#[derive(uniffi::Object)]
pub struct KultNode {
    address: String,
    peer: String,
    inner: Mutex<Option<Runtime>>,
}

#[uniffi::export]
impl KultNode {
    /// Open (or create, on first run) the node and start it. Blocking:
    /// Argon2id key derivation and transport binding happen before this
    /// returns, so a wrong passphrase or an unreachable configured radio
    /// is a startup error — never a broken half-running node.
    #[uniffi::constructor]
    pub fn start(config: Config, listener: Box<dyn EventListener>) -> Result<Arc<Self>, FfiError> {
        Self::boot(runtime_config(config, None)?, listener)
    }

    /// First run only: restore the node from an encrypted backup file
    /// (docs/07-storage.md §4) instead of creating a fresh identity, then
    /// start it exactly like [`KultNode::start`]. The exported identity
    /// resumes with contacts and history intact; every peer that had a
    /// live session at export time is re-handshaked automatically.
    /// Refused when the data directory already holds a store.
    #[uniffi::constructor]
    pub fn restore(
        config: Config,
        backup_path: String,
        mnemonic: String,
        listener: Box<dyn EventListener>,
    ) -> Result<Arc<Self>, FfiError> {
        let backup = std::fs::read(&backup_path).map_err(|e| FfiError::Startup {
            reason: format!("backup file: {e}"),
        })?;
        let restore = RestoreSource { backup, mnemonic };
        Self::boot(runtime_config(config, Some(restore))?, listener)
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// This node's peer id (hex).
    pub fn peer(&self) -> String {
        self.peer.clone()
    }

    /// A point-in-time snapshot: listen addresses, LAN peers, NAT verdict,
    /// queue depths, contact count.
    pub fn status(&self) -> Result<Status, FfiError> {
        let counts = self.call(|resp| Msg::Counts { resp })?;
        let guard = self.inner.lock().expect("lock");
        let rt = guard.as_ref().ok_or(FfiError::Stopped)?;
        let nat = match rt.block_on(rt.net.nat_status()) {
            Ok(kult_transport::NatStatus::Public) => NatVerdict::Public,
            Ok(kult_transport::NatStatus::Private) => NatVerdict::Private,
            _ => NatVerdict::Unknown,
        };
        Ok(Status {
            address: self.address.clone(),
            peer: self.peer.clone(),
            listen: rt.net.listen_addrs(),
            lan_peers: rt.net.lan_peers(),
            nat,
            queued: counts.queued,
            scheduled: counts.scheduled,
            transit: counts.transit,
            contacts: counts.contacts,
        })
    }

    /// Export a fresh signed prekey bundle for out-of-band sharing
    /// (QR code, file, …).
    pub fn handshake_bundle(&self) -> Result<Vec<u8>, FfiError> {
        self.call(|resp| Msg::HandshakeBundle { resp })
    }

    /// Add (or replace) a contact from their prekey bundle, with delivery
    /// hints. Returns the contact's peer id (hex).
    pub fn add_contact(
        &self,
        name: String,
        bundle: Vec<u8>,
        hints: Vec<Hint>,
    ) -> Result<String, FfiError> {
        let hints = hints.iter().map(Hint::to_delivery).collect();
        self.call(|resp| Msg::AddContact {
            name,
            bundle,
            hints,
            resp,
        })
        .map(|peer| hex_encode(&peer))
    }

    /// Add a contact from their kult address alone (DHT lookup). Returns
    /// the contact's peer id (hex).
    pub fn add_contact_by_address(
        &self,
        name: String,
        address: String,
    ) -> Result<String, FfiError> {
        self.call(|resp| Msg::AddByAddress {
            name,
            address,
            resp,
        })
        .map(|peer| hex_encode(&peer))
    }

    /// Queue a message to a known contact. Returns the message record id
    /// (hex); progress arrives as [`Event::DeliveryUpdated`].
    pub fn send(&self, peer: String, body: String) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::Send {
            peer,
            body: body.into_bytes(),
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Import a caller-selected file as a pairwise attachment without
    /// buffering the complete object in memory. Returns its content id (hex).
    pub fn send_attachment(
        &self,
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        let metadata = kult_node::AttachmentMetadata {
            media_type,
            filename,
        };
        self.call(|resp| Msg::AttachmentSend {
            peer,
            metadata,
            path: PathBuf::from(path),
            preview: None,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Import a caller-selected file with a locally generated JPEG/PNG
    /// preview. The preview path is read with the same bounded streaming
    /// boundary and is stored sealed as a distinct manifest object.
    pub fn send_attachment_with_preview(
        &self,
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        preview_path: String,
        preview_media_type: String,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::AttachmentSend {
            peer,
            metadata: kult_node::AttachmentMetadata {
                media_type,
                filename,
            },
            path: PathBuf::from(path),
            preview: Some((
                kult_node::AttachmentMetadata {
                    media_type: preview_media_type,
                    filename: None,
                },
                PathBuf::from(preview_path),
            )),
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Import a caller-selected file as one encrypt-once sender-key group
    /// attachment. Returns its content id (hex).
    pub fn send_group_attachment(
        &self,
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        let metadata = kult_node::AttachmentMetadata {
            media_type,
            filename,
        };
        self.call(|resp| Msg::GroupAttachmentSend {
            group,
            metadata,
            path: PathBuf::from(path),
            preview: None,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Import a sender-key group attachment with a locally generated sealed
    /// JPEG/PNG preview.
    pub fn send_group_attachment_with_preview(
        &self,
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        preview_path: String,
        preview_media_type: String,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        self.call(|resp| Msg::GroupAttachmentSend {
            group,
            metadata: kult_node::AttachmentMetadata {
                media_type,
                filename,
            },
            path: PathBuf::from(path),
            preview: Some((
                kult_node::AttachmentMetadata {
                    media_type: preview_media_type,
                    filename: None,
                },
                PathBuf::from(preview_path),
            )),
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Every supported attachment transfer as render-safe state.
    pub fn attachments(&self) -> Result<Vec<Attachment>, FfiError> {
        Ok(self
            .call(|resp| Msg::Attachments { resp })?
            .into_iter()
            .map(Attachment::from_node)
            .collect())
    }

    /// Accept an inbound attachment offer.
    pub fn accept_attachment(&self, transfer: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentAccept { transfer, resp })
    }

    /// Durably reject an inbound attachment offer.
    pub fn reject_attachment(&self, transfer: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentReject { transfer, resp })
    }

    /// Cancel local attachment activity and release unreferenced partial data.
    pub fn cancel_attachment(&self, transfer: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentCancel { transfer, resp })
    }

    /// Pause attachment activity while retaining verified progress.
    pub fn pause_attachment(&self, transfer: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentPause { transfer, resp })
    }

    /// Resume a paused attachment and reset its retry window.
    pub fn resume_attachment(&self, transfer: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentResume { transfer, resp })
    }

    /// Stream a completed primary object to a new caller-selected path. The
    /// destination is created protected and is never overwritten.
    pub fn export_attachment(&self, transfer: String, path: String) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentExport {
            transfer,
            path: PathBuf::from(path),
            preview: false,
            resp,
        })
    }

    /// Stream a completed preview object to a new caller-selected protected
    /// path for transient local rendering.
    pub fn export_attachment_preview(
        &self,
        transfer: String,
        path: String,
    ) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentExport {
            transfer,
            path: PathBuf::from(path),
            preview: true,
            resp,
        })
    }

    /// Schedule pairwise text at an absolute UTC Unix instant. The returned
    /// id remains stable when it later enters the delivery queue.
    pub fn schedule(
        &self,
        peer: String,
        body: String,
        not_before: u64,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::Schedule {
            peer,
            body: body.into_bytes(),
            not_before,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Schedule group text at an absolute UTC Unix instant.
    pub fn schedule_group(
        &self,
        group: String,
        body: String,
        not_before: u64,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        self.call(|resp| Msg::GroupSchedule {
            group,
            body: body.into_bytes(),
            not_before,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Edit text and/or the UTC instant before a scheduled message activates.
    pub fn edit_scheduled(
        &self,
        message: String,
        body: String,
        not_before: u64,
    ) -> Result<(), FfiError> {
        let id = parse_message(&message)?;
        self.call(|resp| Msg::ScheduledEdit {
            id,
            body: body.into_bytes(),
            not_before,
            resp,
        })
    }

    /// Cancel a scheduled message before it activates.
    pub fn cancel_scheduled(&self, message: String) -> Result<(), FfiError> {
        let id = parse_message(&message)?;
        self.call(|resp| Msg::ScheduledCancel { id, resp })
    }

    /// Full durable scheduled outbox.
    pub fn scheduled_messages(&self) -> Result<Vec<ScheduledMessage>, FfiError> {
        Ok(self
            .call(|resp| Msg::ScheduledMessages { resp })?
            .into_iter()
            .map(|message| {
                let (conversation, destination) = match message.conversation {
                    kult_node::ScheduledConversation::Peer(peer) => {
                        (ScheduledConversation::Peer, hex_encode(&peer))
                    }
                    kult_node::ScheduledConversation::Group(group) => {
                        (ScheduledConversation::Group, hex_encode(&group))
                    }
                };
                ScheduledMessage {
                    id: hex_encode(&message.id),
                    conversation,
                    destination,
                    created_at: message.created_at,
                    not_before: message.not_before,
                    body: String::from_utf8_lossy(&message.body).into_owned(),
                }
            })
            .collect())
    }

    /// Stable identity shared by every shell for the one local note-to-self
    /// conversation.
    pub fn note_to_self_id(&self) -> String {
        kult_node::NOTE_TO_SELF_CONVERSATION_ID.to_owned()
    }

    /// Append text to note-to-self. No delivery state or transport work is
    /// created; the returned id names the durable local record.
    pub fn send_note_to_self(&self, body: String) -> Result<String, FfiError> {
        self.call(|resp| Msg::NoteToSelfSend { body, resp })
            .map(|id| hex_encode(&id))
    }

    /// Full local note-to-self text history in insertion order.
    pub fn note_to_self_messages(&self) -> Result<Vec<NoteMessage>, FfiError> {
        Ok(self
            .call(|resp| Msg::NoteToSelfMessages { resp })?
            .into_iter()
            .map(|message| NoteMessage {
                id: hex_encode(&message.id),
                conversation: kult_node::NOTE_TO_SELF_CONVERSATION_ID.to_owned(),
                timestamp: message.timestamp,
                body: message.body,
            })
            .collect())
    }

    /// Create one private local label with a collision-safe random stable id.
    pub fn create_label(&self, name: String, color: String) -> Result<Label, FfiError> {
        validate_label_write_ffi(&name, &color)?;
        self.label_call(|resp| Msg::LabelCreate { name, color, resp })
            .map(Label::from_node)
    }

    /// List private labels in deterministic durable insertion order.
    pub fn labels(&self) -> Result<Vec<Label>, FfiError> {
        Ok(self
            .label_call(|resp| Msg::Labels { resp })?
            .into_iter()
            .map(Label::from_node)
            .collect())
    }

    /// Get one private label by exact 32-hex-character id.
    pub fn label(&self, label: String) -> Result<Label, FfiError> {
        let label = parse_label_ffi(&label)?;
        self.label_call(|resp| Msg::LabelGet { label, resp })
            .map(Label::from_node)
    }

    /// Rename and recolor one label while preserving id, order, and memberships.
    pub fn update_label(
        &self,
        label: String,
        name: String,
        color: String,
    ) -> Result<Label, FfiError> {
        validate_label_write_ffi(&name, &color)?;
        let label = parse_label_ffi(&label)?;
        self.label_call(|resp| Msg::LabelUpdate {
            label,
            name,
            color,
            resp,
        })
        .map(Label::from_node)
    }

    /// Count every membership before an explicit destructive delete decision.
    pub fn label_delete_assignment_count(&self, label: String) -> Result<u64, FfiError> {
        let label = parse_label_ffi(&label)?;
        let count = self.label_call(|resp| Msg::LabelDeletePreview { label, resp })?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Atomically delete a label and every membership.
    ///
    /// `confirm` must be true so automation cannot make the destructive choice
    /// implicitly. Returns the deleted membership count.
    pub fn delete_label(&self, label: String, confirm: bool) -> Result<u64, FfiError> {
        if !confirm {
            return Err(label_error(
                LabelErrorCode::ConfirmationRequired,
                "label deletion requires explicit confirmation",
            ));
        }
        let label = parse_label_ffi(&label)?;
        let count = self.label_call(|resp| Msg::LabelDelete { label, resp })?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Idempotently apply one label to one exact typed conversation.
    pub fn assign_label(&self, label: String, target: LabelTarget) -> Result<bool, FfiError> {
        let label = parse_label_ffi(&label)?;
        let target = parse_label_target_ffi(&target)?;
        self.label_call(|resp| Msg::LabelAssign {
            label,
            target,
            resp,
        })
    }

    /// Idempotently remove one exact membership, including a stale one.
    pub fn unassign_label(&self, label: String, target: LabelTarget) -> Result<bool, FfiError> {
        let label = parse_label_ffi(&label)?;
        let target = parse_label_target_ffi(&target)?;
        self.label_call(|resp| Msg::LabelUnassign {
            label,
            target,
            resp,
        })
    }

    /// Active typed conversation membership for one label.
    pub fn label_membership(&self, label: String) -> Result<Vec<LabelConversation>, FfiError> {
        let label = parse_label_ffi(&label)?;
        Ok(self
            .label_call(|resp| Msg::LabelMembership { label, resp })?
            .into_iter()
            .map(LabelConversation::from_node)
            .collect())
    }

    /// Active labels for one exact available typed conversation.
    pub fn labels_for_conversation(&self, target: LabelTarget) -> Result<Vec<Label>, FfiError> {
        let target = parse_label_target_ffi(&target)?;
        Ok(self
            .label_call(|resp| Msg::LabelsForConversation { target, resp })?
            .into_iter()
            .map(Label::from_node)
            .collect())
    }

    /// Render-safe diagnostics for stale local memberships.
    pub fn stale_labels(&self) -> Result<Vec<StaleLabel>, FfiError> {
        Ok(self
            .label_call(|resp| Msg::LabelStale { resp })?
            .into_iter()
            .map(StaleLabel::from_node)
            .collect())
    }

    /// Remove one exact membership only while it remains stale.
    pub fn cleanup_stale_label(
        &self,
        label: String,
        target: LabelTarget,
    ) -> Result<bool, FfiError> {
        let label = parse_label_ffi(&label)?;
        let target = parse_label_target_ffi(&target)?;
        self.label_call(|resp| Msg::LabelStaleCleanup {
            label,
            target,
            resp,
        })
    }

    /// Filter eligible conversations locally using match-any or match-all.
    pub fn filter_labels(
        &self,
        labels: Vec<String>,
        mode: LabelMatchMode,
    ) -> Result<LabelFilterResult, FfiError> {
        if labels.len() > kult_node::MAX_LABELS {
            return Err(label_error(
                LabelErrorCode::DefinitionLimit,
                "selected label count exceeds 128",
            ));
        }
        let labels = labels
            .iter()
            .map(|label| parse_label_ffi(label))
            .collect::<Result<Vec<_>, _>>()?;
        let result = self.label_call(|resp| Msg::LabelFilter {
            labels,
            mode: match mode {
                LabelMatchMode::Any => kult_node::LabelMatchMode::Any,
                LabelMatchMode::All => kult_node::LabelMatchMode::All,
            },
            resp,
        })?;
        Ok(LabelFilterResult {
            selected: result.selected.iter().map(|id| hex_encode(id)).collect(),
            unavailable_selected: result
                .unavailable_selected
                .iter()
                .map(|id| hex_encode(id))
                .collect(),
            conversations: result
                .conversations
                .into_iter()
                .map(LabelConversation::from_node)
                .collect(),
        })
    }

    /// Create a sender-key group with stored contacts. Returns its id (hex).
    pub fn create_group(&self, name: String, members: Vec<String>) -> Result<String, FfiError> {
        let members = members
            .iter()
            .map(|peer| parse_peer(peer))
            .collect::<Result<Vec<_>, _>>()?;
        self.call(|resp| Msg::GroupCreate {
            name,
            members,
            resp,
        })
        .map(|group| hex_encode(&group))
    }

    /// Queue a message to a group. Returns its record id (hex); per-member
    /// progress arrives as [`Event::GroupDeliveryUpdated`].
    pub fn send_group(&self, group: String, body: String) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        self.call(|resp| Msg::GroupSend {
            group,
            body: body.into_bytes(),
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Conservative current-roster Mention support and review binding.
    pub fn group_mention_capability(
        &self,
        group: String,
    ) -> Result<GroupMentionCapability, FfiError> {
        let group = parse_group(&group)?;
        let capability = self.call(|resp| Msg::GroupMentionCapability { group, resp })?;
        Ok(GroupMentionCapability {
            group: hex_encode(&capability.group),
            supported: capability.supported(),
            review_token: hex_encode(&capability.review_token),
            issues: capability
                .issues
                .into_iter()
                .map(|issue| MentionCapabilityIssue {
                    peer: hex_encode(&issue.peer),
                    reason: match issue.reason {
                        kult_node::MentionCapabilityIssueReason::Unknown => {
                            MentionCapabilityIssueReason::Unknown
                        }
                        kult_node::MentionCapabilityIssueReason::Unsupported => {
                            MentionCapabilityIssueReason::Unsupported
                        }
                    },
                })
                .collect(),
        })
    }

    /// Queue canonical semantic Mention content after atomic roster and
    /// capability revalidation. Targets are explicit peer ids; display names
    /// are never parsed or inferred.
    pub fn send_group_mention(
        &self,
        group: String,
        text: String,
        spans: Vec<MentionSpan>,
        review_token: String,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        let review_token = parse_review_token(&review_token)?;
        let spans = spans
            .into_iter()
            .map(|span| {
                Ok(kult_node::MentionSpan {
                    start: span.start,
                    end: span.end,
                    target: parse_peer(&span.target)?,
                })
            })
            .collect::<Result<Vec<_>, FfiError>>()?;
        self.call(|resp| Msg::GroupMentionSend {
            group,
            text,
            spans,
            review_token,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Add a stored contact to a group (creator only).
    pub fn add_group_member(&self, group: String, peer: String) -> Result<(), FfiError> {
        let group = parse_group(&group)?;
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::GroupAdd { group, peer, resp })
    }

    /// Remove a member from a group (creator only), rotating group keys.
    pub fn remove_group_member(&self, group: String, peer: String) -> Result<(), FfiError> {
        let group = parse_group(&group)?;
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::GroupRemove { group, peer, resp })
    }

    /// Leave a group and drop its local group state; history remains.
    pub fn leave_group(&self, group: String) -> Result<(), FfiError> {
        let group = parse_group(&group)?;
        self.call(|resp| Msg::GroupLeave { group, resp })
    }

    /// All stored groups, excluding secrets and sender chains.
    pub fn groups(&self) -> Result<Vec<Group>, FfiError> {
        Ok(self
            .call(|resp| Msg::Groups { resp })?
            .iter()
            .map(|group| Group {
                id: hex_encode(&group.id),
                name: group.name.clone(),
                creator: hex_encode(&group.creator),
                members: group.members.iter().map(|peer| hex_encode(peer)).collect(),
            })
            .collect())
    }

    /// Message history for a group, including per-member delivery states.
    pub fn group_messages(&self, group: String) -> Result<Vec<GroupMessage>, FfiError> {
        let group = parse_group(&group)?;
        Ok(self
            .call(|resp| Msg::GroupMessages { group, resp })?
            .iter()
            .map(|message| {
                let (body, content_kind, mention_spans) =
                    render_stored_content(&message.body, true);
                GroupMessage {
                    id: hex_encode(&message.id),
                    group: hex_encode(&message.group),
                    sender: hex_encode(&message.sender),
                    direction: match message.direction {
                        kult_store::Direction::Outbound => Direction::Outbound,
                        kult_store::Direction::Inbound => Direction::Inbound,
                    },
                    timestamp: message.timestamp,
                    body,
                    content_kind,
                    mention_spans,
                    deliveries: message
                        .deliveries
                        .iter()
                        .map(|delivery| GroupDelivery {
                            peer: hex_encode(&delivery.peer),
                            state: DeliveryState::from_store(delivery.state),
                        })
                        .collect(),
                }
            })
            .collect())
    }

    /// All stored contacts.
    pub fn contacts(&self) -> Result<Vec<Contact>, FfiError> {
        let contacts = self.call(|resp| Msg::Contacts { resp })?;
        Ok(contacts
            .iter()
            .map(|c| Contact {
                peer: hex_encode(&c.peer),
                name: c.name.clone(),
                verified: c.verified,
            })
            .collect())
    }

    /// Fresh, safe carrier snapshots for all stored contacts. Expired
    /// positive observations are returned as `offline_or_unknown`.
    pub fn carrier_capabilities(&self) -> Result<Vec<CarrierCapabilitySnapshot>, FfiError> {
        Ok(self
            .call(|resp| Msg::CarrierCapabilities { resp })?
            .into_iter()
            .map(CarrierCapabilitySnapshot::from_node)
            .collect())
    }

    /// Message history with a peer.
    pub fn messages_with(&self, peer: String) -> Result<Vec<Message>, FfiError> {
        let peer = parse_peer(&peer)?;
        let messages = self.call(|resp| Msg::Messages { peer, resp })?;
        Ok(messages
            .iter()
            .map(|m| {
                let (body, content_kind, _) = render_stored_content(&m.body, false);
                Message {
                    id: hex_encode(&m.id),
                    peer: hex_encode(&m.peer),
                    direction: match m.direction {
                        kult_store::Direction::Outbound => Direction::Outbound,
                        kult_store::Direction::Inbound => Direction::Inbound,
                    },
                    state: DeliveryState::from_store(m.state),
                    timestamp: m.timestamp,
                    body,
                    content_kind,
                }
            })
            .collect())
    }

    /// The safety number to verify out-of-band with a peer.
    pub fn safety_number(&self, peer: String) -> Result<SafetyNumber, FfiError> {
        let peer = parse_peer(&peer)?;
        let sn = self.call(|resp| Msg::SafetyNumber { peer, resp })?;
        Ok(SafetyNumber {
            digits: sn.digits.clone(),
            display: sn.display_groups(),
            qr: sn.qr.to_vec(),
        })
    }

    /// Record that safety numbers were verified out-of-band.
    pub fn mark_verified(&self, peer: String) -> Result<(), FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::MarkVerified { peer, resp })
    }

    /// Replace a contact's delivery hints.
    pub fn set_hints(&self, peer: String, hints: Vec<Hint>) -> Result<(), FfiError> {
        let peer = parse_peer(&peer)?;
        let hints = hints.iter().map(Hint::to_delivery).collect();
        self.call(|resp| Msg::SetHints { peer, hints, resp })
    }

    /// Publish this node's prekey bundle on the DHT now (also done
    /// automatically at startup and after relay reservation).
    pub fn publish(&self) -> Result<(), FfiError> {
        self.call(|resp| Msg::Publish { resp })
    }

    /// Write an encrypted backup file (identity + contacts + history +
    /// session-reset markers — docs/07-storage.md §4) to `path`, created
    /// 0600 and never overwriting an existing file. Returns the one-time
    /// 24-word mnemonic that seals it: show it to the user exactly once;
    /// it is not stored anywhere. Restore with [`KultNode::restore`].
    pub fn export_backup(&self, path: String) -> Result<String, FfiError> {
        self.call(|resp| Msg::Backup {
            path: PathBuf::from(path),
            resp,
        })
    }

    /// Stop the node and release everything. Idempotent; every later call
    /// on this handle fails with [`FfiError::Stopped`].
    pub fn stop(&self) {
        if let Some(rt) = self.inner.lock().expect("lock").take() {
            rt.stop();
        }
    }
}

impl KultNode {
    /// Shared tail of the constructors: start the runtime and wrap it.
    fn boot(cfg: RuntimeConfig, listener: Box<dyn EventListener>) -> Result<Arc<Self>, FfiError> {
        let sink: Box<dyn Fn(kult_node::Event) + Send> = Box::new(move |event| {
            if let Some(event) = Event::from_node(event) {
                listener.on_event(event);
            }
        });
        let rt = Runtime::start(cfg, sink).map_err(|reason| FfiError::Startup { reason })?;
        Ok(Arc::new(Self {
            address: rt.address.clone(),
            peer: hex_encode(&rt.peer),
            inner: Mutex::new(Some(rt)),
        }))
    }

    /// Send one typed operation to the actor and wait for its reply.
    /// The channel handle is cloned out of the lock first, so slow
    /// operations don't serialize callers or block [`KultNode::stop`].
    fn call<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Msg,
    ) -> Result<T, FfiError> {
        let tx = {
            let guard = self.inner.lock().expect("lock");
            guard.as_ref().ok_or(FfiError::Stopped)?.tx.clone()
        };
        let (resp, rx) = oneshot::channel();
        tx.blocking_send(build(resp))
            .map_err(|_| FfiError::Stopped)?;
        rx.blocking_recv()
            .map_err(|_| FfiError::Stopped)?
            .map_err(|reason| FfiError::Node { reason })
    }

    fn label_call<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Msg,
    ) -> Result<T, FfiError> {
        self.call(build).map_err(label_ffi_error)
    }
}

impl Label {
    fn from_node(label: kult_node::LabelInfo) -> Self {
        Self {
            id: hex_encode(&label.id),
            name: label.name,
            color: label.color,
            order: label.order,
        }
    }
}

impl LabelConversation {
    fn from_node(conversation: kult_node::LabelConversationInfo) -> Self {
        Self {
            target: label_target_from_store(&conversation.conversation),
            display_name: conversation.display_name,
        }
    }
}

impl StaleLabel {
    fn from_node(stale: kult_node::StaleLabelInfo) -> Self {
        Self {
            label: hex_encode(&stale.label),
            target: label_target_from_store(&stale.conversation),
            reason: match stale.reason {
                kult_node::NodeStaleLabelReason::MissingLabel => StaleLabelReason::MissingLabel,
                kult_node::NodeStaleLabelReason::UnavailableConversation => {
                    StaleLabelReason::UnavailableConversation
                }
                kult_node::NodeStaleLabelReason::MissingLabelAndConversation => {
                    StaleLabelReason::MissingLabelAndConversation
                }
            },
        }
    }
}

fn label_target_from_store(target: &kult_store::ConversationId) -> LabelTarget {
    match target {
        kult_store::ConversationId::Peer(peer) => LabelTarget {
            kind: LabelTargetKind::Peer,
            id: Some(hex_encode(peer)),
        },
        kult_store::ConversationId::Group(group) => LabelTarget {
            kind: LabelTargetKind::Group,
            id: Some(hex_encode(group)),
        },
        kult_store::ConversationId::NoteToSelf => LabelTarget {
            kind: LabelTargetKind::NoteToSelf,
            id: None,
        },
    }
}

fn parse_label_ffi(value: &str) -> Result<[u8; 16], FfiError> {
    parse_message(value).map_err(|_| label_error(LabelErrorCode::InvalidId, "invalid label id"))
}

fn parse_label_target_ffi(target: &LabelTarget) -> Result<kult_store::ConversationId, FfiError> {
    match (&target.kind, &target.id) {
        (LabelTargetKind::Peer, Some(id)) => parse_peer(id)
            .map(kult_store::ConversationId::Peer)
            .map_err(|_| label_error(LabelErrorCode::InvalidTarget, "invalid label target")),
        (LabelTargetKind::Group, Some(id)) => parse_group(id)
            .map(kult_store::ConversationId::Group)
            .map_err(|_| label_error(LabelErrorCode::InvalidTarget, "invalid label target")),
        (LabelTargetKind::NoteToSelf, None) => Ok(kult_store::ConversationId::NoteToSelf),
        _ => Err(label_error(
            LabelErrorCode::InvalidTarget,
            "invalid label target",
        )),
    }
}

fn validate_label_write_ffi(name: &str, color: &str) -> Result<(), FfiError> {
    if !kult_store::valid_label_name(name) {
        return Err(label_error(
            LabelErrorCode::InvalidName,
            "invalid label name",
        ));
    }
    if !kult_store::valid_label_color(color) {
        return Err(label_error(
            LabelErrorCode::InvalidColor,
            "unsupported label color",
        ));
    }
    Ok(())
}

fn label_error(code: LabelErrorCode, reason: &str) -> FfiError {
    FfiError::Label {
        code,
        reason: reason.to_owned(),
    }
}

fn label_ffi_error(error: FfiError) -> FfiError {
    let FfiError::Node { reason } = error else {
        return error;
    };
    let code = match reason.as_str() {
        "store error: invalid label name" => LabelErrorCode::InvalidName,
        "store error: unsupported label color" => LabelErrorCode::InvalidColor,
        "store error: label id does not exist" => LabelErrorCode::UnknownLabel,
        "store error: typed conversation target is unavailable" => {
            LabelErrorCode::UnavailableTarget
        }
        "store error: label definition limit exhausted" => LabelErrorCode::DefinitionLimit,
        "store error: label assignment limit exhausted" => LabelErrorCode::AssignmentLimit,
        "store error: conversation label limit exhausted" => LabelErrorCode::ConversationLimit,
        "store error: label id collision budget exhausted" => LabelErrorCode::IdCollision,
        "store error: label assignment is active or absent" => {
            LabelErrorCode::StaleAssignmentActive
        }
        _ => LabelErrorCode::StorageFailure,
    };
    FfiError::Label { code, reason }
}

/// Validate and convert the FFI-facing [`Config`], creating the data
/// directory on the way.
fn runtime_config(
    config: Config,
    restore: Option<RestoreSource>,
) -> Result<RuntimeConfig, FfiError> {
    let data_dir = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|e| FfiError::Startup {
        reason: format!("data dir: {e}"),
    })?;
    Ok(RuntimeConfig {
        db_path: data_dir.join("node.db"),
        passphrase: config.passphrase.into_bytes(),
        kdf: match config.kdf {
            KdfChoice::Desktop => kult_crypto::KDF_PROFILE_DESKTOP,
            KdfChoice::Mobile => kult_crypto::KDF_PROFILE_MOBILE,
        },
        restore,
        listen: config.listen,
        bootstrap: config.bootstrap,
        relay: config.relay,
        mailboxes: config.mailboxes,
        serve_mailbox: config.serve_mailbox,
        mdns: config.mdns,
        spool: config.spool.map(PathBuf::from),
        meshtastic_serial: config.meshtastic_serial,
        meshtastic_tcp: config.meshtastic_tcp,
        bridge: config.bridge,
        tick_interval: Duration::from_millis(config.tick_ms.max(10)),
        checkin_interval: Duration::from_secs(config.checkin_secs.max(1)),
        nat_interval: Duration::from_secs(config.nat_secs.max(1)),
    })
}

const UNSUPPORTED_MESSAGE: &str = "Unsupported message — update Komms";

fn content_kind(status: &kult_node::ContentStatus) -> ContentKind {
    match status {
        kult_node::ContentStatus::LegacyText => ContentKind::LegacyText,
        kult_node::ContentStatus::Text { .. } => ContentKind::Text,
        kult_node::ContentStatus::Attachment { .. } => ContentKind::Attachment,
        kult_node::ContentStatus::Mention { .. } => ContentKind::Mention,
        kult_node::ContentStatus::Unsupported { .. } => ContentKind::Unsupported,
        kult_node::ContentStatus::Malformed => ContentKind::Malformed,
        _ => ContentKind::Unsupported,
    }
}

fn render_event_body(body: &[u8], status: &kult_node::ContentStatus) -> String {
    match status {
        kult_node::ContentStatus::LegacyText
        | kult_node::ContentStatus::Text { .. }
        | kult_node::ContentStatus::Mention { .. } => {
            String::from_utf8(body.to_vec()).expect("node exposes only validated UTF-8 text")
        }
        kult_node::ContentStatus::Attachment { .. } => String::new(),
        kult_node::ContentStatus::Unsupported { .. } | kult_node::ContentStatus::Malformed => {
            UNSUPPORTED_MESSAGE.to_owned()
        }
        _ => UNSUPPORTED_MESSAGE.to_owned(),
    }
}

fn mention_status(status: &kult_node::ContentStatus) -> Vec<MentionSpan> {
    match status {
        kult_node::ContentStatus::Mention { spans, .. } => spans
            .iter()
            .map(|span| MentionSpan {
                start: span.start,
                end: span.end,
                target: hex_encode(&span.target),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn render_stored_content(
    bytes: &[u8],
    allow_group_mention: bool,
) -> (String, ContentKind, Vec<MentionSpan>) {
    match kult_protocol::decode_content(bytes) {
        kult_protocol::DecodedContent::LegacyText(text) => {
            (text.to_owned(), ContentKind::LegacyText, Vec::new())
        }
        kult_protocol::DecodedContent::Text { text, .. } => {
            (text.to_owned(), ContentKind::Text, Vec::new())
        }
        kult_protocol::DecodedContent::Attachment { .. } => {
            (String::new(), ContentKind::Attachment, Vec::new())
        }
        kult_protocol::DecodedContent::Mention { mention, .. } if allow_group_mention => {
            let spans = mention
                .spans()
                .map(|span| MentionSpan {
                    start: span.start,
                    end: span.end,
                    target: hex_encode(&span.target),
                })
                .collect();
            (mention.text.to_owned(), ContentKind::Mention, spans)
        }
        kult_protocol::DecodedContent::Mention { .. } => (
            UNSUPPORTED_MESSAGE.to_owned(),
            ContentKind::Malformed,
            Vec::new(),
        ),
        kult_protocol::DecodedContent::Unsupported { .. } => (
            UNSUPPORTED_MESSAGE.to_owned(),
            ContentKind::Unsupported,
            Vec::new(),
        ),
        kult_protocol::DecodedContent::Malformed => (
            UNSUPPORTED_MESSAGE.to_owned(),
            ContentKind::Malformed,
            Vec::new(),
        ),
    }
}

/// Lowercase hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    out
}

/// Decode a 32-byte hex peer id (case-insensitive).
fn parse_peer(s: &str) -> Result<[u8; 32], FfiError> {
    parse_hex_32(s, "peer")
}

/// Decode a 32-byte hex group id (case-insensitive).
fn parse_group(s: &str) -> Result<[u8; 32], FfiError> {
    parse_hex_32(s, "group")
}

fn parse_message(s: &str) -> Result<[u8; 16], FfiError> {
    let fail = || FfiError::Node {
        reason: "message id must be 32 hex chars".to_owned(),
    };
    if s.len() != 32 {
        return Err(fail());
    }
    let digits: Vec<u32> = s
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()
        .ok_or_else(fail)?;
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = ((pair[0] << 4) | pair[1]) as u8;
    }
    Ok(out)
}

fn parse_review_token(s: &str) -> Result<[u8; 16], FfiError> {
    let fail = || FfiError::Node {
        reason: "review token must be 32 hex chars".to_owned(),
    };
    if s.len() != 32 {
        return Err(fail());
    }
    let digits: Vec<u32> = s
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()
        .ok_or_else(fail)?;
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = ((pair[0] << 4) | pair[1]) as u8;
    }
    Ok(out)
}

fn parse_transfer(s: &str) -> Result<[u8; 16], FfiError> {
    let fail = || FfiError::Node {
        reason: "transfer id must be 32 hex chars".to_owned(),
    };
    if s.len() != 32 {
        return Err(fail());
    }
    let digits: Vec<u32> = s
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()
        .ok_or_else(fail)?;
    let mut out = [0u8; 16];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = ((pair[0] << 4) | pair[1]) as u8;
    }
    Ok(out)
}

fn parse_hex_32(s: &str, kind: &str) -> Result<[u8; 32], FfiError> {
    let fail = || FfiError::Node {
        reason: format!("{kind} must be 64 hex chars"),
    };
    if s.len() != 64 {
        return Err(fail());
    }
    let digits: Vec<u32> = s
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()
        .ok_or_else(fail)?;
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| ((pair[0] << 4) | pair[1]) as u8)
        .collect();
    Ok(<[u8; 32]>::try_from(bytes).expect("64 hex chars"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let peer = [0xab; 32];
        let s = hex_encode(&peer);
        assert_eq!(s.len(), 64);
        assert_eq!(parse_peer(&s).unwrap(), peer);
        assert_eq!(parse_peer(&s.to_uppercase()).unwrap(), peer);
        assert!(parse_peer("ab").is_err());
        assert!(parse_peer(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn events_convert_with_hex_ids() {
        let event = Event::from_node(kult_node::Event::MessageReceived {
            peer: [1; 32],
            id: [2; 16],
            timestamp: 7,
            body: b"hi".to_vec(),
            content: kult_node::ContentStatus::LegacyText,
        })
        .unwrap();
        match event {
            Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content_kind,
            } => {
                assert_eq!(peer, "01".repeat(32));
                assert_eq!(id, "02".repeat(16));
                assert_eq!(timestamp, 7);
                assert_eq!(body, "hi");
                assert_eq!(content_kind, ContentKind::LegacyText);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn non_text_content_never_crosses_as_lossy_or_raw_text() {
        let mut unknown = kult_protocol::CONTENT_MAGIC.to_vec();
        unknown.push(2);
        let (body, kind, spans) = render_stored_content(&unknown, false);
        assert_eq!(body, UNSUPPORTED_MESSAGE);
        assert_eq!(kind, ContentKind::Unsupported);
        assert!(!body.contains('\u{fffd}'));
        assert!(spans.is_empty());

        let (body, kind, spans) = render_stored_content(&kult_protocol::CONTENT_MAGIC, false);
        assert_eq!(body, UNSUPPORTED_MESSAGE);
        assert_eq!(kind, ContentKind::Malformed);
        assert!(spans.is_empty());

        let manifest = kult_protocol::AttachmentManifest {
            attachment_key: [0x41; 32],
            primary: kult_protocol::AttachmentObject {
                role: kult_protocol::AttachmentRole::Primary,
                object_id: [0x42; 16],
                total_len: 1,
                chunk_data_len: kult_protocol::ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count: 1,
                content_hash: [0x43; 32],
                media_type: "image/png",
                filename: Some("private.png"),
            },
            preview: None,
        };
        let frame = kult_protocol::encode_attachment([0x44; 16], &manifest).unwrap();
        let (body, kind, spans) = render_stored_content(&frame, false);
        assert!(body.is_empty());
        assert_eq!(kind, ContentKind::Attachment);
        assert!(!body.contains("private.png"));
        assert!(spans.is_empty());

        let event = Event::from_node(kult_node::Event::AttachmentUpdated {
            attachment: kult_node::AttachmentInfo {
                transfer_id: [0x11; 16],
                peer: [0x12; 32],
                conversation: kult_node::AttachmentConversation::Pairwise,
                group: None,
                direction: kult_node::AttachmentDirection::Inbound,
                author: [0x12; 32],
                content_id: [0x13; 16],
                state: kult_store::MediaTransferState::AwaitingConsent,
                objects: vec![kult_node::AttachmentObjectInfo {
                    preview: false,
                    total_bytes: 1,
                    verified_bytes: 0,
                    media_type: "image/png".to_owned(),
                    filename: Some("private.png".to_owned()),
                    state: kult_store::MediaTransferState::AwaitingConsent,
                }],
            },
        })
        .unwrap();
        assert!(matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.transfer_id == "11".repeat(16)
                    && attachment.state == AttachmentState::AwaitingConsent
                    && attachment.objects[0].filename.as_deref() == Some("private.png")
        ));
    }
}
