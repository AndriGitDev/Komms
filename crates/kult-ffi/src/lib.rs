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

/// Stable folder failure categories shared by Kotlin and Swift wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FolderErrorCode {
    /// Folder id was not exactly 16 bytes of hexadecimal.
    InvalidId,
    /// Typed peer/group/note-to-self target was malformed.
    InvalidTarget,
    /// Name violated the exact UTF-8 length or fixed whitespace rule.
    InvalidName,
    /// Stable folder id has no definition.
    UnknownFolder,
    /// Exact typed conversation is unavailable.
    UnavailableTarget,
    /// Definition limit is exhausted.
    DefinitionLimit,
    /// Aggregate assignment limit is exhausted.
    AssignmentLimit,
    /// Cryptorandom id collision retry budget was exhausted.
    IdCollision,
    /// Reorder input was not the exact active id set once each.
    InvalidOrder,
    /// Requested stale assignment is now active or absent.
    StaleAssignmentActive,
    /// Explicit destructive confirmation was absent.
    ConfirmationRequired,
    /// Storage or another local implementation failure occurred.
    StorageFailure,
}

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

/// Stable private-pin failure categories shared by Kotlin and Swift wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PinErrorCode {
    /// Typed peer/group/note-to-self target was malformed.
    InvalidTarget,
    /// Exact typed conversation is unavailable and cannot be newly pinned.
    UnavailableTarget,
    /// The durable pin definition limit is exhausted.
    Limit,
    /// Reorder input was not the exact durable target set once each.
    InvalidOrder,
    /// Requested stale pin is now active or absent.
    StalePinActive,
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
    /// A private-folder operation failed with a stable programmatic category.
    Folder {
        /// Stable category shared across Rust, Kotlin, and Swift.
        code: FolderErrorCode,
        /// Generic render-safe explanation with no folder text or relationship.
        reason: String,
    },
    /// A private-label operation failed with a stable programmatic category.
    Label {
        /// Stable category shared across Rust, Kotlin, and Swift.
        code: LabelErrorCode,
        /// Generic render-safe explanation with no label text or relationship.
        reason: String,
    },
    /// A private-pin operation failed with a stable programmatic category.
    Pin {
        /// Stable category shared across Rust, Kotlin, and Swift.
        code: PinErrorCode,
        /// Generic render-safe explanation with no relationship data.
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
            Self::Folder { reason, .. } => write!(f, "{reason}"),
            Self::Label { reason, .. } => write!(f, "{reason}"),
            Self::Pin { reason, .. } => write!(f, "{reason}"),
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

/// One inert inline presentation token produced by the shared formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TextFormatStyle {
    /// Emphasized text.
    Emphasis,
    /// Strongly emphasized text.
    Strong,
    /// Inline monospace code.
    InlineCode,
    /// Existing semantic content, such as an authenticated mention.
    Highlight,
}

/// One render-safe block role produced by the shared formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TextFormatBlockKind {
    /// Ordinary text.
    Paragraph,
    /// Quoted text.
    Quote,
    /// One unordered list item.
    UnorderedListItem,
    /// One ordered list item.
    OrderedListItem,
    /// A fenced, inert monospace code block.
    CodeBlock,
}

/// Exact UTF-8 source range that receives an inert highlight style.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TextFormatHighlight {
    /// Inclusive UTF-8 byte offset in the exact source text.
    pub start: u32,
    /// Exclusive UTF-8 byte offset in the exact source text.
    pub end: u32,
}

/// One text run with a deterministic set of inert styles.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FormattedTextRun {
    /// Exact display text; shells insert it only through native text APIs.
    pub text: String,
    /// Sorted, de-duplicated style tokens.
    pub styles: Vec<TextFormatStyle>,
}

/// One local, render-safe display block.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FormattedTextBlock {
    /// Semantic block role.
    pub kind: TextFormatBlockKind,
    /// Zero-based list indentation; zero for non-list blocks.
    pub depth: u8,
    /// Ordered-list number, or zero for every other block kind.
    pub ordinal: u32,
    /// Display runs in exact order.
    pub runs: Vec<FormattedTextRun>,
}

/// Complete local formatting result shared by Kotlin and Swift.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FormattedText {
    /// Exact authenticated and stored source, unchanged.
    pub source: String,
    /// Readable inert text used for copy-as-plain-text.
    pub plain_text: String,
    /// Bounded render-safe blocks.
    pub blocks: Vec<FormattedTextBlock>,
    /// Whether a complexity bound caused literal source rendering.
    pub used_fallback: bool,
}

impl From<kult_node::TextFormatStyle> for TextFormatStyle {
    fn from(style: kult_node::TextFormatStyle) -> Self {
        match style {
            kult_node::TextFormatStyle::Emphasis => Self::Emphasis,
            kult_node::TextFormatStyle::Strong => Self::Strong,
            kult_node::TextFormatStyle::InlineCode => Self::InlineCode,
            kult_node::TextFormatStyle::Highlight => Self::Highlight,
        }
    }
}

impl From<kult_node::TextFormatBlockKind> for TextFormatBlockKind {
    fn from(kind: kult_node::TextFormatBlockKind) -> Self {
        match kind {
            kult_node::TextFormatBlockKind::Paragraph => Self::Paragraph,
            kult_node::TextFormatBlockKind::Quote => Self::Quote,
            kult_node::TextFormatBlockKind::UnorderedListItem => Self::UnorderedListItem,
            kult_node::TextFormatBlockKind::OrderedListItem => Self::OrderedListItem,
            kult_node::TextFormatBlockKind::CodeBlock => Self::CodeBlock,
        }
    }
}

impl From<kult_node::FormattedText> for FormattedText {
    fn from(formatted: kult_node::FormattedText) -> Self {
        Self {
            source: formatted.source,
            plain_text: formatted.plain_text,
            blocks: formatted
                .blocks
                .into_iter()
                .map(|block| FormattedTextBlock {
                    kind: block.kind.into(),
                    depth: block.depth,
                    ordinal: block.ordinal,
                    runs: block
                        .runs
                        .into_iter()
                        .map(|run| FormattedTextRun {
                            text: run.text,
                            styles: run.styles.into_iter().map(Into::into).collect(),
                        })
                        .collect(),
                })
                .collect(),
            used_fallback: formatted.used_fallback,
        }
    }
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
    /// Canonical disappearing UTF-8 with an exact local deadline.
    DisappearingText,
    /// Canonical view-once attachment offer.
    ViewOnceAttachment,
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

/// Inert local category derived from untrusted attachment display hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentFileKind {
    /// Still-image hint.
    Image,
    /// Audio hint.
    Audio,
    /// Video hint.
    Video,
    /// Document or textual-data hint.
    Document,
    /// Archive hint.
    Archive,
    /// Executable, script, installer, or active-document hint.
    Executable,
    /// Unrecognized or generic binary hint.
    Other,
}

/// Strongest local action permitted for a completed attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentOpenPolicy {
    /// Existing bounded protected image/audio rendering may be offered.
    ProtectedMedia,
    /// An explicit user action may hand a protected materialization to the OS.
    ExternalOpen,
    /// Caller-selected export is the only permitted presentation action.
    ExportOnly,
}

/// Stable caution derived from untrusted authenticated file hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentFileWarning {
    /// Filename extension and media type disagree.
    MediaTypeMismatch,
    /// A hint identifies executable or active content.
    DangerousType,
    /// A hint is outside the reviewed type set.
    UnrecognizedType,
    /// No filename was supplied for extension comparison.
    MissingFilename,
}

/// Shared local presentation decision. It never claims that content is safe.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AttachmentFilePresentation {
    /// Inert icon/label category.
    pub kind: AttachmentFileKind,
    /// Strongest permitted local action.
    pub open_policy: AttachmentOpenPolicy,
    /// Canonically ordered warnings.
    pub warnings: Vec<AttachmentFileWarning>,
}

impl AttachmentFilePresentation {
    fn from_node(value: kult_node::AttachmentFilePresentation) -> Self {
        Self {
            kind: match value.kind {
                kult_node::AttachmentFileKind::Image => AttachmentFileKind::Image,
                kult_node::AttachmentFileKind::Audio => AttachmentFileKind::Audio,
                kult_node::AttachmentFileKind::Video => AttachmentFileKind::Video,
                kult_node::AttachmentFileKind::Document => AttachmentFileKind::Document,
                kult_node::AttachmentFileKind::Archive => AttachmentFileKind::Archive,
                kult_node::AttachmentFileKind::Executable => AttachmentFileKind::Executable,
                kult_node::AttachmentFileKind::Other => AttachmentFileKind::Other,
            },
            open_policy: match value.open_policy {
                kult_node::AttachmentOpenPolicy::ProtectedMedia => {
                    AttachmentOpenPolicy::ProtectedMedia
                }
                kult_node::AttachmentOpenPolicy::ExternalOpen => AttachmentOpenPolicy::ExternalOpen,
                kult_node::AttachmentOpenPolicy::ExportOnly => AttachmentOpenPolicy::ExportOnly,
            },
            warnings: value
                .warnings
                .into_iter()
                .map(|warning| match warning {
                    kult_node::AttachmentFileWarning::MediaTypeMismatch => {
                        AttachmentFileWarning::MediaTypeMismatch
                    }
                    kult_node::AttachmentFileWarning::DangerousType => {
                        AttachmentFileWarning::DangerousType
                    }
                    kult_node::AttachmentFileWarning::UnrecognizedType => {
                        AttachmentFileWarning::UnrecognizedType
                    }
                    kult_node::AttachmentFileWarning::MissingFilename => {
                        AttachmentFileWarning::MissingFilename
                    }
                })
                .collect(),
        }
    }
}

/// Apply the shared bounded C1 file-presentation policy without touching
/// storage, transports, crypto, or the network.
#[uniffi::export]
pub fn attachment_file_presentation(
    media_type: String,
    filename: Option<String>,
) -> AttachmentFilePresentation {
    AttachmentFilePresentation::from_node(kult_node::classify_attachment_file(
        &media_type,
        filename.as_deref(),
    ))
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
    /// Shared conservative local presentation decision.
    pub presentation: AttachmentFilePresentation,
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
    /// Whether first-open consumption governs this transfer.
    pub view_once: bool,
    /// Exact fallback deadline for view-once media.
    pub expires_at: Option<u64>,
    /// Whether it is permanently unavailable after open/expiry.
    pub consumed: bool,
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
            view_once: attachment.view_once,
            expires_at: attachment.expires_at,
            consumed: attachment.consumed,
            objects: attachment
                .objects
                .into_iter()
                .map(|object| AttachmentObject {
                    preview: object.preview,
                    total_bytes: object.total_bytes,
                    verified_bytes: object.verified_bytes,
                    media_type: object.media_type,
                    filename: object.filename,
                    presentation: AttachmentFilePresentation::from_node(object.presentation),
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

/// One deterministic local warning for a proposed contact petname.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ContactNameWarning {
    /// Another contact already has the same NFC-normalized petname.
    DuplicateName,
    /// Mixed scripts or a local lookalike collision may be deceptive.
    ConfusableName,
    /// Directional formatting controls can make display order misleading.
    BidirectionalControl,
    /// Invisible formatting characters can hide meaningful differences.
    InvisibleCharacter,
}

impl From<kult_node::ContactNameWarning> for ContactNameWarning {
    fn from(value: kult_node::ContactNameWarning) -> Self {
        match value {
            kult_node::ContactNameWarning::DuplicateName => Self::DuplicateName,
            kult_node::ContactNameWarning::ConfusableName => Self::ConfusableName,
            kult_node::ContactNameWarning::BidirectionalControl => Self::BidirectionalControl,
            kult_node::ContactNameWarning::InvisibleCharacter => Self::InvisibleCharacter,
        }
    }
}

/// Canonical proposed petname and its local-only review warnings.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ContactNameAssessment {
    /// NFC value that will be stored after confirmation.
    pub normalized_name: String,
    /// Whether canonical normalization changed the proposed scalar sequence.
    pub changed_by_normalization: bool,
    /// Ordered warning kinds; empty means no explicit acknowledgement is needed.
    pub warnings: Vec<ContactNameWarning>,
    /// Number of other contacts with this exact canonical petname.
    pub duplicate_count: u32,
}

impl From<kult_node::ContactNameAssessment> for ContactNameAssessment {
    fn from(value: kult_node::ContactNameAssessment) -> Self {
        Self {
            normalized_name: value.normalized_name,
            changed_by_normalization: value.changed_by_normalization,
            warnings: value.warnings.into_iter().map(Into::into).collect(),
            duplicate_count: value.duplicate_count,
        }
    }
}

/// Exact typed target kind for local folder assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FolderTargetKind {
    /// Pairwise conversation keyed by peer identity.
    Peer,
    /// Sender-key group keyed by group id.
    Group,
    /// Reserved device-local note-to-self conversation.
    NoteToSelf,
}

/// Exact technical target used by folder mutations.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderTarget {
    /// Target type; display names are never accepted here.
    pub kind: FolderTargetKind,
    /// 64-hex-character peer/group id, or absent for note-to-self.
    pub id: Option<String>,
}

/// Render-safe available conversation in folder membership/navigation output.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderConversation {
    /// Exact technical typed target.
    pub target: FolderTarget,
    /// Current local petname/group name; absent for note-to-self.
    pub display_name: Option<String>,
}

/// Render-safe private folder definition.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Folder {
    /// Stable random 32-hex-character id for technical mutation calls.
    pub id: String,
    /// Exact user-authored UTF-8 folder name.
    pub name: String,
    /// Persisted manual order.
    pub order: u32,
}

/// One explicit local folder-navigation selection kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FolderSelectionKind {
    /// Every available conversation.
    All,
    /// Available conversations with no active assignment.
    Unfiled,
    /// One exact stable folder id.
    Folder,
}

/// Exact virtual or stable-folder navigation selection.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderSelection {
    /// Selection kind.
    pub kind: FolderSelectionKind,
    /// 32-hex-character folder id only when kind is Folder.
    pub id: Option<String>,
}

/// Why a durable folder assignment is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum StaleFolderReason {
    /// Folder definition is unavailable.
    MissingFolder,
    /// Exact conversation target is unavailable.
    UnavailableConversation,
    /// Both definition and target are unavailable.
    MissingFolderAndConversation,
}

/// Render-safe stale folder-assignment diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct StaleFolder {
    /// Stable technical folder id.
    pub folder: String,
    /// Exact typed target.
    pub target: FolderTarget,
    /// The unavailable side or sides.
    pub reason: StaleFolderReason,
}

/// Deterministic folder-first navigation result with label-filter state.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FolderConversationResult {
    /// Exact applied folder selection.
    pub selection: FolderSelection,
    /// Deduplicated available selected label ids.
    pub selected_labels: Vec<String>,
    /// Selected label ids whose definitions are unavailable.
    pub unavailable_labels: Vec<String>,
    /// Conversations matching both independent controls.
    pub conversations: Vec<FolderConversation>,
}

/// Shared appearance choice. System resolves from native platform signals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ThemePreference {
    /// Follow the operating-system appearance live.
    #[default]
    System,
    /// Force the light semantic palette.
    Light,
    /// Force the dark semantic palette.
    Dark,
}

/// Current private local appearance preference and persistence state.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ThemeInfo {
    /// Canonical system/light/dark choice.
    pub preference: ThemePreference,
    /// Whether a canonical choice already exists in the sealed F5 store.
    pub persisted: bool,
}

/// Shipped platform whose native screen-security policy is requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ScreenSecurityPlatform {
    /// Android application window.
    Android,
    /// iOS application scene.
    Ios,
    /// Tauri desktop application window.
    Desktop,
}

/// Strength of one platform screen-security capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ScreenSecurityLevel {
    /// Komms enables the supported native protection across its whole surface.
    PlatformEnforced,
    /// Komms requests native protection, but the environment may ignore it.
    BestEffort,
    /// The platform has no honest API for this capability.
    Unavailable,
}

/// Immutable, render-safe B14 policy for one shipped shell.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ScreenSecurityPolicy {
    /// Platform this policy describes.
    pub platform: ScreenSecurityPlatform,
    /// Always true; protection applies before the encrypted store opens.
    pub always_on: bool,
    /// Screenshot and screen-recording prevention strength.
    pub capture_prevention: ScreenSecurityLevel,
    /// App-switcher, task-preview, or recent-window obscuring strength.
    pub background_obscuring: ScreenSecurityLevel,
    /// Live capture detection strength.
    pub capture_detection: ScreenSecurityLevel,
    /// Immediate user-triggered session lock strength.
    pub rapid_lock: ScreenSecurityLevel,
    /// Short native-mechanism description.
    pub mechanism: String,
    /// Honest platform limitations shown beside the claims.
    pub limitations: Vec<String>,
}

/// Return the shared always-on B14 policy without opening a node or store.
#[uniffi::export]
pub fn screen_security_policy(platform: ScreenSecurityPlatform) -> ScreenSecurityPolicy {
    let node_platform = match platform {
        ScreenSecurityPlatform::Android => kult_node::ScreenSecurityPlatform::Android,
        ScreenSecurityPlatform::Ios => kult_node::ScreenSecurityPlatform::Ios,
        ScreenSecurityPlatform::Desktop => kult_node::ScreenSecurityPlatform::Desktop,
    };
    let policy = kult_node::screen_security_policy(node_platform);
    let level = |value| match value {
        kult_node::ScreenSecurityLevel::PlatformEnforced => ScreenSecurityLevel::PlatformEnforced,
        kult_node::ScreenSecurityLevel::BestEffort => ScreenSecurityLevel::BestEffort,
        kult_node::ScreenSecurityLevel::Unavailable => ScreenSecurityLevel::Unavailable,
    };
    ScreenSecurityPolicy {
        platform,
        always_on: policy.always_on,
        capture_prevention: level(policy.capture_prevention),
        background_obscuring: level(policy.background_obscuring),
        capture_detection: level(policy.capture_detection),
        rapid_lock: level(policy.rapid_lock),
        mechanism: policy.mechanism.to_owned(),
        limitations: policy
            .limitations
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

/// Shipped platform whose native B15 input-privacy policy is requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum IncognitoKeyboardPlatform {
    /// Android application input controls.
    Android,
    /// iOS application input controls.
    Ios,
    /// Tauri desktop webview input controls.
    Desktop,
}

/// Strength of one platform input-privacy capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum IncognitoKeyboardLevel {
    /// The platform enforces the narrowly named behavior.
    PlatformEnforced,
    /// Komms sets a documented control that an input method may ignore.
    PlatformRequested,
    /// Komms supplies the strongest available hint without enforcement.
    BestEffort,
    /// The platform exposes no honest per-field control.
    Unavailable,
}

/// Immutable, render-safe B15 policy for one shipped shell.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct IncognitoKeyboardPolicy {
    /// Platform this policy describes.
    pub platform: IncognitoKeyboardPlatform,
    /// Always true; input privacy cannot be disabled.
    pub always_on: bool,
    /// Always true; unlock and restore inputs are covered.
    pub applies_before_unlock: bool,
    /// Per-field personalized-learning control.
    pub personalized_learning: IncognitoKeyboardLevel,
    /// Per-field autocorrection and prediction control.
    pub suggestions: IncognitoKeyboardLevel,
    /// Per-field spelling-service control.
    pub spellcheck: IncognitoKeyboardLevel,
    /// Visual masking strength for passphrases and mnemonics.
    pub secret_text_masking: IncognitoKeyboardLevel,
    /// Required semantic field classes, including future search inputs.
    pub protected_fields: Vec<String>,
    /// Short native-mechanism description.
    pub mechanism: String,
    /// Honest platform limitations shown beside the claims.
    pub limitations: Vec<String>,
}

/// Return the shared always-on B15 policy without opening a node or store.
#[uniffi::export]
pub fn incognito_keyboard_policy(platform: IncognitoKeyboardPlatform) -> IncognitoKeyboardPolicy {
    let node_platform = match platform {
        IncognitoKeyboardPlatform::Android => kult_node::IncognitoKeyboardPlatform::Android,
        IncognitoKeyboardPlatform::Ios => kult_node::IncognitoKeyboardPlatform::Ios,
        IncognitoKeyboardPlatform::Desktop => kult_node::IncognitoKeyboardPlatform::Desktop,
    };
    let policy = kult_node::incognito_keyboard_policy(node_platform);
    let level = |value| match value {
        kult_node::IncognitoKeyboardLevel::PlatformEnforced => {
            IncognitoKeyboardLevel::PlatformEnforced
        }
        kult_node::IncognitoKeyboardLevel::PlatformRequested => {
            IncognitoKeyboardLevel::PlatformRequested
        }
        kult_node::IncognitoKeyboardLevel::BestEffort => IncognitoKeyboardLevel::BestEffort,
        kult_node::IncognitoKeyboardLevel::Unavailable => IncognitoKeyboardLevel::Unavailable,
    };
    IncognitoKeyboardPolicy {
        platform,
        always_on: policy.always_on,
        applies_before_unlock: policy.applies_before_unlock,
        personalized_learning: level(policy.personalized_learning),
        suggestions: level(policy.suggestions),
        spellcheck: level(policy.spellcheck),
        secret_text_masking: level(policy.secret_text_masking),
        protected_fields: policy
            .protected_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        mechanism: policy.mechanism.to_owned(),
        limitations: policy
            .limitations
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

/// Exact typed target kind for one private local custom icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CustomIconTargetKind {
    /// Contact keyed by peer identity.
    Contact,
    /// Sender-key group keyed by group id.
    Group,
    /// Private local folder keyed by its random stable id.
    Folder,
    /// Reserved local note-to-self conversation.
    NoteToSelf,
}

/// Exact technical target used by custom-icon operations.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CustomIconTarget {
    /// Target type; display names and list positions are never accepted.
    pub kind: CustomIconTargetKind,
    /// 64-hex peer/group id, 32-hex folder id, or absent for note-to-self.
    pub id: Option<String>,
}

/// Optional exact square crop in oriented source pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CustomIconCrop {
    /// Left edge after orientation normalization.
    pub x: u32,
    /// Top edge after orientation normalization.
    pub y: u32,
    /// Non-zero crop width.
    pub width: u32,
    /// Non-zero crop height; must equal width.
    pub height: u32,
}

/// Canonical render-safe local custom icon.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CustomIcon {
    /// Exact typed target.
    pub target: CustomIconTarget,
    /// Canonical `image/png` media type.
    pub media_type: String,
    /// Exact metadata-free 256×256 RGBA PNG bytes.
    pub bytes: Vec<u8>,
    /// Canonical width.
    pub width: u32,
    /// Canonical height.
    pub height: u32,
}

/// Current sealed custom-icon quota usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CustomIconQuotaUsage {
    /// Durable icon records.
    pub records: u64,
    /// Aggregate encoded bytes.
    pub bytes: u64,
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

/// Exact typed target kind for private local conversation pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PinTargetKind {
    /// Pairwise conversation keyed by peer identity.
    Peer,
    /// Sender-key group keyed by group id.
    Group,
    /// Reserved device-local note-to-self conversation.
    NoteToSelf,
}

/// Exact technical target used by pin mutations and complete-set reorder.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PinTarget {
    /// Target type; display names are never accepted here.
    pub kind: PinTargetKind,
    /// 64-hex-character peer/group id, or absent for note-to-self.
    pub id: Option<String>,
}

/// Render-safe durable pin, including unavailable stale targets.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Pin {
    /// Exact stable typed identity.
    pub target: PinTarget,
    /// Current local name while available; absent for stale/note-to-self.
    pub display_name: Option<String>,
    /// Exact persisted manual order.
    pub order: u32,
    /// Whether the exact conversation is currently available.
    pub active: bool,
}

/// One eligible conversation after folder, label, and pin composition.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PinConversation {
    /// Exact stable typed identity.
    pub target: PinTarget,
    /// Current local display name; absent for note-to-self.
    pub display_name: Option<String>,
    /// Whether this row belongs to the leading pinned block.
    pub pinned: bool,
    /// Exact persisted order when pinned.
    pub pin_order: Option<u32>,
    /// Latest ordinary local message activity, or zero with no history.
    pub recent_activity: u64,
}

/// Folder-first, label-second, pin-order-last conversation presentation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PinConversationResult {
    /// Exact applied folder selection.
    pub selection: FolderSelection,
    /// Deduplicated available selected label ids.
    pub selected_labels: Vec<String>,
    /// Selected label ids whose definitions are unavailable.
    pub unavailable_labels: Vec<String>,
    /// Eligible rows with one leading pinned block and no duplicates.
    pub conversations: Vec<PinConversation>,
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

/// One immutable original or edit version in deterministic resolution order.
#[derive(Clone, Debug, uniffi::Record)]
pub struct EditVersion {
    /// Original content id for revision zero, otherwise edit-event id (hex).
    pub id: String,
    /// Zero for original, positive for an immutable edit.
    pub revision: u64,
    /// Local presentation timestamp.
    pub timestamp: u64,
    /// Exact authenticated text for this version.
    pub body: String,
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
    /// Exact authenticated local expiry for ephemeral content.
    pub expires_at: Option<u64>,
    /// Whether a valid immutable edit wins over the original.
    pub edited: bool,
    /// Winning edit revision, or zero for the original.
    pub edit_revision: u64,
    /// Original plus valid immutable edits in deterministic order.
    pub versions: Vec<EditVersion>,
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
    /// Exact authenticated local expiry for ephemeral content.
    pub expires_at: Option<u64>,
    /// Stable semantic Mention spans; empty for every other content kind.
    pub mention_spans: Vec<MentionSpan>,
    /// Whether a valid immutable edit wins over the original.
    pub edited: bool,
    /// Winning edit revision, or zero for the original.
    pub edit_revision: u64,
    /// Original plus valid immutable edits in deterministic order.
    pub versions: Vec<EditVersion>,
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
    /// Private local custom icons changed; shells re-read visible targets.
    CustomIconsChanged,
    /// Private local appearance preference changed; shells re-read it.
    ThemeChanged,
    /// Private local folders changed; shells re-read local folder state.
    FoldersChanged,
    /// Private local labels changed; shells re-read local label state.
    LabelsChanged,
    /// Private local pins changed; shells re-read local pin state.
    PinsChanged,
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
        /// Exact deadline for ephemeral content.
        expires_at: Option<u64>,
    },
    /// A canonical inbound edit was stored; refresh the exact pairwise target.
    MessageEdited {
        /// Pairwise peer that authored both the edit and original (hex).
        peer: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
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
    /// A stored contact's sealed private local petname changed.
    ContactRenamed {
        /// Exact stable peer id (hex).
        peer: String,
        /// Canonical NFC petname now stored locally.
        name: String,
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
        /// Exact deadline for ephemeral content.
        expires_at: Option<u64>,
        /// Stable semantic spans; empty for every other content kind.
        mention_spans: Vec<MentionSpan>,
    },
    /// A canonical inbound group edit was stored; refresh the exact target.
    GroupMessageEdited {
        /// Group id (hex).
        group: String,
        /// Authenticated edit and original author (hex).
        sender: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
    },
    /// Ephemeral plaintext/media became terminal on this installation.
    EphemeralRemoved {
        /// `pairwise` or `group`.
        conversation_kind: String,
        /// Peer or group id (hex).
        conversation_id: String,
        /// Authenticated author id (hex).
        author: String,
        /// Content id (hex).
        content_id: String,
        /// `expired` or `consumed`.
        reason: String,
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
            kult_node::Event::CustomIconsChanged => Self::CustomIconsChanged,
            kult_node::Event::ThemeChanged => Self::ThemeChanged,
            kult_node::Event::FoldersChanged => Self::FoldersChanged,
            kult_node::Event::LabelsChanged => Self::LabelsChanged,
            kult_node::Event::PinsChanged => Self::PinsChanged,
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
                expires_at: content_expiry(&content),
            },
            kult_node::Event::MessageEdited {
                peer,
                target_content_id,
            } => Self::MessageEdited {
                peer: hex_encode(&peer),
                target_content_id: hex_encode(&target_content_id),
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
            kult_node::Event::ContactRenamed { peer, name } => Self::ContactRenamed {
                peer: hex_encode(&peer),
                name,
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
                expires_at: content_expiry(&content),
                mention_spans: mention_status(&content),
            },
            kult_node::Event::GroupMessageEdited {
                group,
                sender,
                target_content_id,
            } => Self::GroupMessageEdited {
                group: hex_encode(&group),
                sender: hex_encode(&sender),
                target_content_id: hex_encode(&target_content_id),
            },
            kult_node::Event::EphemeralRemoved {
                conversation,
                author,
                content_id,
                reason,
            } => {
                let (conversation_kind, conversation_id) = match conversation {
                    kult_store::EphemeralConversation::Pairwise(peer) => {
                        ("pairwise".to_owned(), hex_encode(&peer))
                    }
                    kult_store::EphemeralConversation::Group(group) => {
                        ("group".to_owned(), hex_encode(&group))
                    }
                };
                Self::EphemeralRemoved {
                    conversation_kind,
                    conversation_id,
                    author: hex_encode(&author),
                    content_id: hex_encode(&content_id),
                    reason: match reason {
                        kult_store::EphemeralState::Expired => "expired",
                        kult_store::EphemeralState::Consumed => "consumed",
                        kult_store::EphemeralState::Active => "active",
                    }
                    .to_owned(),
                }
            }
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

    /// Render exact message source into the bounded, inert shared display model.
    ///
    /// The result never interprets HTML, URLs, images, or executable content.
    /// Existing authenticated semantic ranges can be composed as highlights.
    pub fn format_text(
        &self,
        source: String,
        highlights: Vec<TextFormatHighlight>,
    ) -> Result<FormattedText, FfiError> {
        let highlights = highlights
            .into_iter()
            .map(|highlight| kult_node::TextFormatHighlight {
                start: highlight.start,
                end: highlight.end,
            })
            .collect::<Vec<_>>();
        kult_node::format_text(&source, &highlights)
            .map(Into::into)
            .map_err(|error| FfiError::Node {
                reason: error.to_string(),
            })
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

    /// Validate and assess a proposed private local petname without mutation.
    pub fn assess_contact_name(
        &self,
        peer: String,
        name: String,
    ) -> Result<ContactNameAssessment, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::AssessContactName { peer, name, resp })
            .map(Into::into)
    }

    /// Rename one contact locally by exact peer id, with explicit warning review.
    pub fn rename_contact(
        &self,
        peer: String,
        name: String,
        accept_warnings: bool,
    ) -> Result<ContactNameAssessment, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::RenameContact {
            peer,
            name,
            accept_warnings,
            resp,
        })
        .map(Into::into)
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

    /// Queue pairwise UTF-8 with a 60-second through 30-day local lifetime.
    pub fn send_disappearing(
        &self,
        peer: String,
        body: String,
        lifetime_secs: u64,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        self.call(|resp| Msg::SendDisappearing {
            peer,
            body,
            lifetime_secs,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Send one immutable edit targeting this identity's exact canonical Text.
    pub fn edit_message(
        &self,
        peer: String,
        target_author: String,
        target_content_id: String,
        text: String,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        let target_author = parse_peer(&target_author)?;
        let target_content_id = parse_message(&target_content_id)?;
        self.call(|resp| Msg::EditMessage {
            peer,
            target_author,
            target_content_id,
            text,
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

    /// Import a pairwise view-once attachment with an optional protected preview.
    #[allow(clippy::too_many_arguments)] // stable UniFFI flat-value boundary
    pub fn send_view_once_attachment(
        &self,
        peer: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        preview_path: Option<String>,
        preview_media_type: Option<String>,
        lifetime_secs: u64,
    ) -> Result<String, FfiError> {
        let peer = parse_peer(&peer)?;
        let preview = match (preview_path, preview_media_type) {
            (None, None) => None,
            (Some(path), Some(media_type)) => Some((
                kult_node::AttachmentMetadata {
                    media_type,
                    filename: None,
                },
                PathBuf::from(path),
            )),
            _ => {
                return Err(FfiError::Node {
                    reason: "preview path/type must be paired".into(),
                })
            }
        };
        self.call(|resp| Msg::AttachmentSendViewOnce {
            peer,
            metadata: kult_node::AttachmentMetadata {
                media_type,
                filename,
            },
            path: PathBuf::from(path),
            preview,
            lifetime_secs,
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

    /// Import a sender-key group view-once attachment.
    #[allow(clippy::too_many_arguments)] // stable UniFFI flat-value boundary
    pub fn send_group_view_once_attachment(
        &self,
        group: String,
        path: String,
        media_type: String,
        filename: Option<String>,
        preview_path: Option<String>,
        preview_media_type: Option<String>,
        lifetime_secs: u64,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        let preview = match (preview_path, preview_media_type) {
            (None, None) => None,
            (Some(path), Some(media_type)) => Some((
                kult_node::AttachmentMetadata {
                    media_type,
                    filename: None,
                },
                PathBuf::from(path),
            )),
            _ => {
                return Err(FfiError::Node {
                    reason: "preview path/type must be paired".into(),
                })
            }
        };
        self.call(|resp| Msg::GroupAttachmentSendViewOnce {
            group,
            metadata: kult_node::AttachmentMetadata {
                media_type,
                filename,
            },
            path: PathBuf::from(path),
            preview,
            lifetime_secs,
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

    /// Terminal first open of a view-once primary into a protected new path.
    pub fn consume_view_once_attachment(
        &self,
        transfer: String,
        path: String,
    ) -> Result<(), FfiError> {
        let transfer = parse_transfer(&transfer)?;
        self.call(|resp| Msg::AttachmentConsumeViewOnce {
            transfer,
            path: PathBuf::from(path),
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

    /// Read the safe current choice and whether it exists in sealed storage.
    pub fn theme(&self) -> Result<ThemeInfo, FfiError> {
        let (preference, persisted) = self.call(|resp| Msg::Theme { resp })?;
        Ok(ThemeInfo {
            preference: ThemePreference::from_node(preference),
            persisted,
        })
    }

    /// Idempotently persist one canonical private local appearance choice.
    pub fn set_theme(&self, preference: ThemePreference) -> Result<bool, FfiError> {
        self.call(|resp| Msg::ThemeSet {
            preference: preference.into_node(),
            resp,
        })
    }

    /// Read one canonical sealed icon, or `None` for generated-initials fallback.
    pub fn custom_icon(&self, target: CustomIconTarget) -> Result<Option<CustomIcon>, FfiError> {
        let target = parse_custom_icon_target_ffi(&target)?;
        Ok(self
            .call(|resp| Msg::CustomIcon { target, resp })?
            .map(CustomIcon::from_node))
    }

    /// Center-crop or explicitly square-crop a local JPEG/PNG and seal it.
    pub fn set_custom_icon_from_path(
        &self,
        target: CustomIconTarget,
        path: String,
        crop: Option<CustomIconCrop>,
    ) -> Result<CustomIcon, FfiError> {
        let target = parse_custom_icon_target_ffi(&target)?;
        let crop = crop.map(|crop| kult_node::CustomIconCrop {
            x: crop.x,
            y: crop.y,
            width: crop.width,
            height: crop.height,
        });
        self.call(|resp| Msg::CustomIconSetPath {
            target,
            path: PathBuf::from(path),
            crop,
            resp,
        })
        .map(CustomIcon::from_node)
    }

    /// Render and seal one exact bundled glyph token.
    pub fn set_bundled_custom_icon(
        &self,
        target: CustomIconTarget,
        glyph: String,
    ) -> Result<CustomIcon, FfiError> {
        let target = parse_custom_icon_target_ffi(&target)?;
        self.call(|resp| Msg::CustomIconSetBundled {
            target,
            glyph,
            resp,
        })
        .map(CustomIcon::from_node)
    }

    /// Remove one icon and return to deterministic generated initials.
    pub fn clear_custom_icon(&self, target: CustomIconTarget) -> Result<bool, FfiError> {
        let target = parse_custom_icon_target_ffi(&target)?;
        self.call(|resp| Msg::CustomIconClear { target, resp })
    }

    /// Read current sealed icon quota usage.
    pub fn custom_icon_quota_usage(&self) -> Result<CustomIconQuotaUsage, FfiError> {
        let usage = self.call(|resp| Msg::CustomIconUsage { resp })?;
        Ok(CustomIconQuotaUsage {
            records: usage.records as u64,
            bytes: usage.bytes as u64,
        })
    }

    /// Create one private local folder with a collision-safe random stable id.
    pub fn create_folder(&self, name: String) -> Result<Folder, FfiError> {
        validate_folder_write_ffi(&name)?;
        self.folder_call(|resp| Msg::FolderCreate { name, resp })
            .map(Folder::from_node)
    }

    /// List private folders in deterministic persisted manual order.
    pub fn folders(&self) -> Result<Vec<Folder>, FfiError> {
        Ok(self
            .folder_call(|resp| Msg::Folders { resp })?
            .into_iter()
            .map(Folder::from_node)
            .collect())
    }

    /// Get one private folder by exact 32-hex-character id.
    pub fn folder(&self, folder: String) -> Result<Folder, FfiError> {
        let folder = parse_folder_ffi(&folder)?;
        self.folder_call(|resp| Msg::FolderGet { folder, resp })
            .map(Folder::from_node)
    }

    /// Rename one folder while preserving id, order, and membership.
    pub fn rename_folder(&self, folder: String, name: String) -> Result<Folder, FfiError> {
        validate_folder_write_ffi(&name)?;
        let folder = parse_folder_ffi(&folder)?;
        self.folder_call(|resp| Msg::FolderRename { folder, name, resp })
            .map(Folder::from_node)
    }

    /// Atomically reorder the complete active folder id set.
    pub fn reorder_folders(&self, folders: Vec<String>) -> Result<Vec<Folder>, FfiError> {
        if folders.len() > kult_node::MAX_FOLDERS {
            return Err(folder_error(
                FolderErrorCode::InvalidOrder,
                "invalid folder order",
            ));
        }
        let folders = folders
            .iter()
            .map(|folder| parse_folder_ffi(folder))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .folder_call(|resp| Msg::FolderReorder { folders, resp })?
            .into_iter()
            .map(Folder::from_node)
            .collect())
    }

    /// Count every assignment before an explicit destructive delete decision.
    pub fn folder_delete_assignment_count(&self, folder: String) -> Result<u64, FfiError> {
        let folder = parse_folder_ffi(&folder)?;
        let count = self.folder_call(|resp| Msg::FolderDeletePreview { folder, resp })?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Atomically delete a folder and cascade every assignment to Unfiled.
    pub fn delete_folder(&self, folder: String, confirm: bool) -> Result<u64, FfiError> {
        if !confirm {
            return Err(folder_error(
                FolderErrorCode::ConfirmationRequired,
                "folder deletion requires explicit confirmation",
            ));
        }
        let folder = parse_folder_ffi(&folder)?;
        let count = self.folder_call(|resp| Msg::FolderDelete { folder, resp })?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Idempotently move one exact typed conversation into one exact folder.
    pub fn move_to_folder(&self, folder: String, target: FolderTarget) -> Result<bool, FfiError> {
        let folder = parse_folder_ffi(&folder)?;
        let target = parse_folder_target_ffi(&target)?;
        self.folder_call(|resp| Msg::FolderMove {
            folder,
            target,
            resp,
        })
    }

    /// Idempotently move one exact typed conversation to virtual Unfiled.
    pub fn unfile_conversation(&self, target: FolderTarget) -> Result<bool, FfiError> {
        let target = parse_folder_target_ffi(&target)?;
        self.folder_call(|resp| Msg::FolderUnfile { target, resp })
    }

    /// List active typed conversation membership for one folder.
    pub fn folder_membership(&self, folder: String) -> Result<Vec<FolderConversation>, FfiError> {
        let folder = parse_folder_ffi(&folder)?;
        Ok(self
            .folder_call(|resp| Msg::FolderMembership { folder, resp })?
            .into_iter()
            .map(FolderConversation::from_node)
            .collect())
    }

    /// Get the active folder for one exact available typed conversation.
    pub fn conversation_folder(&self, target: FolderTarget) -> Result<Option<Folder>, FfiError> {
        let target = parse_folder_target_ffi(&target)?;
        Ok(self
            .folder_call(|resp| Msg::ConversationFolder { target, resp })?
            .map(Folder::from_node))
    }

    /// Classify All/Unfiled/one folder, then independently apply labels.
    pub fn folder_conversations(
        &self,
        selection: FolderSelection,
        labels: Vec<String>,
        mode: LabelMatchMode,
    ) -> Result<FolderConversationResult, FfiError> {
        if labels.len() > kult_node::MAX_LABELS {
            return Err(label_error(
                LabelErrorCode::DefinitionLimit,
                "selected label count exceeds 128",
            ));
        }
        let selection = parse_folder_selection_ffi(&selection)?;
        let labels = labels
            .iter()
            .map(|label| parse_label_ffi(label))
            .collect::<Result<Vec<_>, _>>()?;
        let result = self.folder_call(|resp| Msg::FolderConversations {
            selection,
            labels,
            mode: match mode {
                LabelMatchMode::Any => kult_node::LabelMatchMode::Any,
                LabelMatchMode::All => kult_node::LabelMatchMode::All,
            },
            resp,
        })?;
        Ok(FolderConversationResult::from_node(result))
    }

    /// Render-safe diagnostics for stale local folder assignments.
    pub fn stale_folders(&self) -> Result<Vec<StaleFolder>, FfiError> {
        Ok(self
            .folder_call(|resp| Msg::FolderStale { resp })?
            .into_iter()
            .map(StaleFolder::from_node)
            .collect())
    }

    /// Remove one exact folder assignment only while it remains stale.
    pub fn cleanup_stale_folder(
        &self,
        folder: String,
        target: FolderTarget,
    ) -> Result<bool, FfiError> {
        let folder = parse_folder_ffi(&folder)?;
        let target = parse_folder_target_ffi(&target)?;
        self.folder_call(|resp| Msg::FolderStaleCleanup {
            folder,
            target,
            resp,
        })
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

    /// Idempotently append one exact available conversation to pin order.
    pub fn pin_conversation(&self, target: PinTarget) -> Result<bool, FfiError> {
        let target = parse_pin_target_ffi(&target)?;
        self.pin_call(|resp| Msg::Pin { target, resp })
    }

    /// Idempotently remove one exact active or stale pin.
    pub fn unpin_conversation(&self, target: PinTarget) -> Result<bool, FfiError> {
        let target = parse_pin_target_ffi(&target)?;
        self.pin_call(|resp| Msg::Unpin { target, resp })
    }

    /// Get the durable pin state for one exact typed target.
    pub fn pin_state(&self, target: PinTarget) -> Result<Option<Pin>, FfiError> {
        let target = parse_pin_target_ffi(&target)?;
        Ok(self
            .pin_call(|resp| Msg::PinState { target, resp })?
            .map(Pin::from_node))
    }

    /// List every durable pin, including unavailable stale targets.
    pub fn pins(&self) -> Result<Vec<Pin>, FfiError> {
        Ok(self
            .pin_call(|resp| Msg::Pins { resp })?
            .into_iter()
            .map(Pin::from_node)
            .collect())
    }

    /// Atomically reorder the exact complete durable pin target set.
    pub fn reorder_pins(&self, targets: Vec<PinTarget>) -> Result<Vec<Pin>, FfiError> {
        if targets.len() > kult_node::MAX_PINS {
            return Err(pin_error(
                PinErrorCode::InvalidOrder,
                "pin reorder count exceeds 8192",
            ));
        }
        let targets = targets
            .iter()
            .map(parse_pin_target_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .pin_call(|resp| Msg::PinReorder { targets, resp })?
            .into_iter()
            .map(Pin::from_node)
            .collect())
    }

    /// List unavailable durable pins for explicit diagnosis and cleanup.
    pub fn stale_pins(&self) -> Result<Vec<Pin>, FfiError> {
        Ok(self
            .pin_call(|resp| Msg::PinStale { resp })?
            .into_iter()
            .map(Pin::from_node)
            .collect())
    }

    /// Remove one exact pin only while its target remains unavailable.
    pub fn cleanup_stale_pin(&self, target: PinTarget) -> Result<bool, FfiError> {
        let target = parse_pin_target_ffi(&target)?;
        self.pin_call(|resp| Msg::PinStaleCleanup { target, resp })
    }

    /// Classify by folder, filter by labels, then apply pin/activity ordering.
    pub fn pin_conversations(
        &self,
        selection: FolderSelection,
        labels: Vec<String>,
        mode: LabelMatchMode,
    ) -> Result<PinConversationResult, FfiError> {
        if labels.len() > kult_node::MAX_LABELS {
            return Err(label_error(
                LabelErrorCode::DefinitionLimit,
                "selected label count exceeds 128",
            ));
        }
        let selection = parse_folder_selection_ffi(&selection)?;
        let labels = labels
            .iter()
            .map(|label| parse_label_ffi(label))
            .collect::<Result<Vec<_>, _>>()?;
        self.pin_call(|resp| Msg::PinConversations {
            selection,
            labels,
            mode: match mode {
                LabelMatchMode::Any => kult_node::LabelMatchMode::Any,
                LabelMatchMode::All => kult_node::LabelMatchMode::All,
            },
            resp,
        })
        .map(PinConversationResult::from_node)
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

    /// Queue group UTF-8 with an exact local lifetime on every installation.
    pub fn send_group_disappearing(
        &self,
        group: String,
        body: String,
        lifetime_secs: u64,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        self.call(|resp| Msg::GroupSendDisappearing {
            group,
            body,
            lifetime_secs,
            resp,
        })
        .map(|id| hex_encode(&id))
    }

    /// Send one immutable edit targeting this identity's exact group Text.
    pub fn edit_group_message(
        &self,
        group: String,
        target_author: String,
        target_content_id: String,
        text: String,
    ) -> Result<String, FfiError> {
        let group = parse_group(&group)?;
        let target_author = parse_peer(&target_author)?;
        let target_content_id = parse_message(&target_content_id)?;
        self.call(|resp| Msg::GroupEditMessage {
            group,
            target_author,
            target_content_id,
            text,
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
                let record = &message.record;
                let decoded = kult_protocol::decode_content(&record.body);
                let expires_at = decoded_content_expiry(&decoded);
                let (body, content_kind, mention_spans) = render_stored_content(&record.body, true);
                GroupMessage {
                    id: hex_encode(&record.id),
                    group: hex_encode(&record.group),
                    sender: hex_encode(&record.sender),
                    direction: match record.direction {
                        kult_store::Direction::Outbound => Direction::Outbound,
                        kult_store::Direction::Inbound => Direction::Inbound,
                    },
                    timestamp: record.timestamp,
                    body,
                    content_kind,
                    expires_at,
                    mention_spans,
                    edited: message.edited,
                    edit_revision: message.winning_revision,
                    versions: message
                        .versions
                        .iter()
                        .map(edit_version_from_node)
                        .collect(),
                    deliveries: record
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
            .map(|message| {
                let record = &message.record;
                let decoded = kult_protocol::decode_content(&record.body);
                let expires_at = decoded_content_expiry(&decoded);
                let (body, content_kind, _) = render_stored_content(&record.body, false);
                Message {
                    id: hex_encode(&record.id),
                    peer: hex_encode(&record.peer),
                    direction: match record.direction {
                        kult_store::Direction::Outbound => Direction::Outbound,
                        kult_store::Direction::Inbound => Direction::Inbound,
                    },
                    state: DeliveryState::from_store(record.state),
                    timestamp: record.timestamp,
                    body,
                    content_kind,
                    expires_at,
                    edited: message.edited,
                    edit_revision: message.winning_revision,
                    versions: message
                        .versions
                        .iter()
                        .map(edit_version_from_node)
                        .collect(),
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

    fn folder_call<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Msg,
    ) -> Result<T, FfiError> {
        self.call(build).map_err(folder_ffi_error)
    }

    fn pin_call<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, String>>) -> Msg,
    ) -> Result<T, FfiError> {
        self.call(build).map_err(pin_ffi_error)
    }
}

impl Folder {
    fn from_node(folder: kult_node::FolderInfo) -> Self {
        Self {
            id: hex_encode(&folder.id),
            name: folder.name,
            order: folder.order,
        }
    }
}

impl ThemePreference {
    fn from_node(preference: kult_node::ThemePreference) -> Self {
        match preference {
            kult_node::ThemePreference::System => Self::System,
            kult_node::ThemePreference::Light => Self::Light,
            kult_node::ThemePreference::Dark => Self::Dark,
        }
    }

    fn into_node(self) -> kult_node::ThemePreference {
        match self {
            Self::System => kult_node::ThemePreference::System,
            Self::Light => kult_node::ThemePreference::Light,
            Self::Dark => kult_node::ThemePreference::Dark,
        }
    }
}

impl CustomIcon {
    fn from_node(icon: kult_node::CustomIconInfo) -> Self {
        Self {
            target: custom_icon_target_from_node(&icon.target),
            media_type: icon.media_type,
            bytes: icon.bytes,
            width: icon.width,
            height: icon.height,
        }
    }
}

fn custom_icon_target_from_node(target: &kult_node::CustomIconTarget) -> CustomIconTarget {
    match target {
        kult_node::CustomIconTarget::Contact(id) => CustomIconTarget {
            kind: CustomIconTargetKind::Contact,
            id: Some(hex_encode(id)),
        },
        kult_node::CustomIconTarget::Group(id) => CustomIconTarget {
            kind: CustomIconTargetKind::Group,
            id: Some(hex_encode(id)),
        },
        kult_node::CustomIconTarget::Folder(id) => CustomIconTarget {
            kind: CustomIconTargetKind::Folder,
            id: Some(hex_encode(id)),
        },
        kult_node::CustomIconTarget::NoteToSelf => CustomIconTarget {
            kind: CustomIconTargetKind::NoteToSelf,
            id: None,
        },
    }
}

impl FolderConversation {
    fn from_node(conversation: kult_node::FolderConversationInfo) -> Self {
        Self {
            target: folder_target_from_store(&conversation.conversation),
            display_name: conversation.display_name,
        }
    }
}

impl StaleFolder {
    fn from_node(stale: kult_node::StaleFolderInfo) -> Self {
        Self {
            folder: hex_encode(&stale.folder),
            target: folder_target_from_store(&stale.conversation),
            reason: match stale.reason {
                kult_node::NodeStaleFolderReason::MissingFolder => StaleFolderReason::MissingFolder,
                kult_node::NodeStaleFolderReason::UnavailableConversation => {
                    StaleFolderReason::UnavailableConversation
                }
                kult_node::NodeStaleFolderReason::MissingFolderAndConversation => {
                    StaleFolderReason::MissingFolderAndConversation
                }
            },
        }
    }
}

impl FolderConversationResult {
    fn from_node(result: kult_node::FolderConversationList) -> Self {
        Self {
            selection: folder_selection_from_node(result.selection),
            selected_labels: result
                .selected_labels
                .iter()
                .map(|id| hex_encode(id))
                .collect(),
            unavailable_labels: result
                .unavailable_labels
                .iter()
                .map(|id| hex_encode(id))
                .collect(),
            conversations: result
                .conversations
                .into_iter()
                .map(FolderConversation::from_node)
                .collect(),
        }
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

impl Pin {
    fn from_node(pin: kult_node::PinInfo) -> Self {
        Self {
            target: pin_target_from_store(&pin.conversation),
            display_name: pin.display_name,
            order: pin.order,
            active: pin.active,
        }
    }
}

impl PinConversation {
    fn from_node(conversation: kult_node::PinConversationInfo) -> Self {
        Self {
            target: pin_target_from_store(&conversation.conversation),
            display_name: conversation.display_name,
            pinned: conversation.pinned,
            pin_order: conversation.pin_order,
            recent_activity: conversation.recent_activity,
        }
    }
}

impl PinConversationResult {
    fn from_node(result: kult_node::PinConversationList) -> Self {
        Self {
            selection: folder_selection_from_node(result.selection),
            selected_labels: result
                .selected_labels
                .iter()
                .map(|id| hex_encode(id))
                .collect(),
            unavailable_labels: result
                .unavailable_labels
                .iter()
                .map(|id| hex_encode(id))
                .collect(),
            conversations: result
                .conversations
                .into_iter()
                .map(PinConversation::from_node)
                .collect(),
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

fn pin_target_from_store(target: &kult_store::ConversationId) -> PinTarget {
    match target {
        kult_store::ConversationId::Peer(peer) => PinTarget {
            kind: PinTargetKind::Peer,
            id: Some(hex_encode(peer)),
        },
        kult_store::ConversationId::Group(group) => PinTarget {
            kind: PinTargetKind::Group,
            id: Some(hex_encode(group)),
        },
        kult_store::ConversationId::NoteToSelf => PinTarget {
            kind: PinTargetKind::NoteToSelf,
            id: None,
        },
    }
}

fn folder_target_from_store(target: &kult_store::ConversationId) -> FolderTarget {
    match target {
        kult_store::ConversationId::Peer(peer) => FolderTarget {
            kind: FolderTargetKind::Peer,
            id: Some(hex_encode(peer)),
        },
        kult_store::ConversationId::Group(group) => FolderTarget {
            kind: FolderTargetKind::Group,
            id: Some(hex_encode(group)),
        },
        kult_store::ConversationId::NoteToSelf => FolderTarget {
            kind: FolderTargetKind::NoteToSelf,
            id: None,
        },
    }
}

fn folder_selection_from_node(selection: kult_node::FolderSelection) -> FolderSelection {
    match selection {
        kult_node::FolderSelection::All => FolderSelection {
            kind: FolderSelectionKind::All,
            id: None,
        },
        kult_node::FolderSelection::Unfiled => FolderSelection {
            kind: FolderSelectionKind::Unfiled,
            id: None,
        },
        kult_node::FolderSelection::Folder(folder) => FolderSelection {
            kind: FolderSelectionKind::Folder,
            id: Some(hex_encode(&folder)),
        },
    }
}

fn parse_folder_ffi(value: &str) -> Result<[u8; 16], FfiError> {
    parse_message(value).map_err(|_| folder_error(FolderErrorCode::InvalidId, "invalid folder id"))
}

fn parse_custom_icon_target_ffi(
    target: &CustomIconTarget,
) -> Result<kult_node::CustomIconTarget, FfiError> {
    let invalid = || FfiError::Node {
        reason: "invalid custom icon target".to_owned(),
    };
    match (&target.kind, &target.id) {
        (CustomIconTargetKind::Contact, Some(id)) => parse_peer(id)
            .map(kult_node::CustomIconTarget::Contact)
            .map_err(|_| invalid()),
        (CustomIconTargetKind::Group, Some(id)) => parse_group(id)
            .map(kult_node::CustomIconTarget::Group)
            .map_err(|_| invalid()),
        (CustomIconTargetKind::Folder, Some(id)) => parse_folder_ffi(id)
            .map(kult_node::CustomIconTarget::Folder)
            .map_err(|_| invalid()),
        (CustomIconTargetKind::NoteToSelf, None) => Ok(kult_node::CustomIconTarget::NoteToSelf),
        _ => Err(invalid()),
    }
}

fn parse_folder_target_ffi(target: &FolderTarget) -> Result<kult_store::ConversationId, FfiError> {
    match (&target.kind, &target.id) {
        (FolderTargetKind::Peer, Some(id)) => parse_peer(id)
            .map(kult_store::ConversationId::Peer)
            .map_err(|_| folder_error(FolderErrorCode::InvalidTarget, "invalid folder target")),
        (FolderTargetKind::Group, Some(id)) => parse_group(id)
            .map(kult_store::ConversationId::Group)
            .map_err(|_| folder_error(FolderErrorCode::InvalidTarget, "invalid folder target")),
        (FolderTargetKind::NoteToSelf, None) => Ok(kult_store::ConversationId::NoteToSelf),
        _ => Err(folder_error(
            FolderErrorCode::InvalidTarget,
            "invalid folder target",
        )),
    }
}

fn parse_folder_selection_ffi(
    selection: &FolderSelection,
) -> Result<kult_node::FolderSelection, FfiError> {
    match (&selection.kind, &selection.id) {
        (FolderSelectionKind::All, None) => Ok(kult_node::FolderSelection::All),
        (FolderSelectionKind::Unfiled, None) => Ok(kult_node::FolderSelection::Unfiled),
        (FolderSelectionKind::Folder, Some(id)) => {
            parse_folder_ffi(id).map(kult_node::FolderSelection::Folder)
        }
        _ => Err(folder_error(
            FolderErrorCode::InvalidId,
            "invalid folder selection",
        )),
    }
}

fn validate_folder_write_ffi(name: &str) -> Result<(), FfiError> {
    if kult_store::valid_folder_name(name) {
        Ok(())
    } else {
        Err(folder_error(
            FolderErrorCode::InvalidName,
            "invalid folder name",
        ))
    }
}

fn folder_error(code: FolderErrorCode, reason: &str) -> FfiError {
    FfiError::Folder {
        code,
        reason: reason.to_owned(),
    }
}

fn folder_ffi_error(error: FfiError) -> FfiError {
    let FfiError::Node { reason } = error else {
        return error;
    };
    let code = match reason.as_str() {
        "store error: invalid folder name" => FolderErrorCode::InvalidName,
        "store error: folder id does not exist" => FolderErrorCode::UnknownFolder,
        "store error: typed conversation target is unavailable" => {
            FolderErrorCode::UnavailableTarget
        }
        "store error: folder definition limit exhausted" => FolderErrorCode::DefinitionLimit,
        "store error: folder assignment limit exhausted" => FolderErrorCode::AssignmentLimit,
        "store error: folder id collision budget exhausted" => FolderErrorCode::IdCollision,
        "store error: invalid complete folder order" => FolderErrorCode::InvalidOrder,
        "store error: folder assignment is active or absent" => {
            FolderErrorCode::StaleAssignmentActive
        }
        _ => FolderErrorCode::StorageFailure,
    };
    FfiError::Folder { code, reason }
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

fn parse_pin_target_ffi(target: &PinTarget) -> Result<kult_store::ConversationId, FfiError> {
    match (&target.kind, &target.id) {
        (PinTargetKind::Peer, Some(id)) => parse_peer(id)
            .map(kult_store::ConversationId::Peer)
            .map_err(|_| pin_error(PinErrorCode::InvalidTarget, "invalid pin target")),
        (PinTargetKind::Group, Some(id)) => parse_group(id)
            .map(kult_store::ConversationId::Group)
            .map_err(|_| pin_error(PinErrorCode::InvalidTarget, "invalid pin target")),
        (PinTargetKind::NoteToSelf, None) => Ok(kult_store::ConversationId::NoteToSelf),
        _ => Err(pin_error(PinErrorCode::InvalidTarget, "invalid pin target")),
    }
}

fn pin_error(code: PinErrorCode, reason: &str) -> FfiError {
    FfiError::Pin {
        code,
        reason: reason.to_owned(),
    }
}

fn pin_ffi_error(error: FfiError) -> FfiError {
    let FfiError::Node { reason } = error else {
        return error;
    };
    let code = match reason.as_str() {
        "store error: typed conversation target is unavailable" => PinErrorCode::UnavailableTarget,
        "store error: conversation pin limit exhausted" => PinErrorCode::Limit,
        "store error: invalid complete pin order" => PinErrorCode::InvalidOrder,
        "store error: conversation pin is active or absent" => PinErrorCode::StalePinActive,
        _ => PinErrorCode::StorageFailure,
    };
    FfiError::Pin { code, reason }
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
        kult_node::ContentStatus::DisappearingText { .. } => ContentKind::DisappearingText,
        kult_node::ContentStatus::ViewOnceAttachment { .. } => ContentKind::ViewOnceAttachment,
        kult_node::ContentStatus::Unsupported { .. } => ContentKind::Unsupported,
        kult_node::ContentStatus::Malformed => ContentKind::Malformed,
        _ => ContentKind::Unsupported,
    }
}

fn content_expiry(status: &kult_node::ContentStatus) -> Option<u64> {
    match status {
        kult_node::ContentStatus::DisappearingText { expires_at, .. }
        | kult_node::ContentStatus::ViewOnceAttachment { expires_at, .. } => Some(*expires_at),
        _ => None,
    }
}

fn decoded_content_expiry(content: &kult_protocol::DecodedContent<'_>) -> Option<u64> {
    match content {
        kult_protocol::DecodedContent::Ephemeral {
            ephemeral:
                kult_protocol::Ephemeral::DisappearingText { expires_at, .. }
                | kult_protocol::Ephemeral::ViewOnceAttachment { expires_at, .. },
            ..
        } => Some(*expires_at),
        _ => None,
    }
}

fn render_event_body(body: &[u8], status: &kult_node::ContentStatus) -> String {
    match status {
        kult_node::ContentStatus::LegacyText
        | kult_node::ContentStatus::Text { .. }
        | kult_node::ContentStatus::Mention { .. }
        | kult_node::ContentStatus::DisappearingText { .. } => {
            String::from_utf8(body.to_vec()).expect("node exposes only validated UTF-8 text")
        }
        kult_node::ContentStatus::Attachment { .. }
        | kult_node::ContentStatus::ViewOnceAttachment { .. } => String::new(),
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
        kult_protocol::DecodedContent::Edit { .. } => (
            UNSUPPORTED_MESSAGE.to_owned(),
            ContentKind::Malformed,
            Vec::new(),
        ),
        kult_protocol::DecodedContent::Ephemeral { ephemeral, .. } => match ephemeral {
            kult_protocol::Ephemeral::DisappearingText { text, .. } => {
                (text.to_owned(), ContentKind::DisappearingText, Vec::new())
            }
            kult_protocol::Ephemeral::ViewOnceAttachment { .. } => {
                (String::new(), ContentKind::ViewOnceAttachment, Vec::new())
            }
        },
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

fn edit_version_from_node(version: &kult_node::EditVersionInfo) -> EditVersion {
    EditVersion {
        id: hex_encode(&version.id),
        revision: version.revision,
        timestamp: version.timestamp,
        body: version.body.clone(),
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
                expires_at,
            } => {
                assert_eq!(peer, "01".repeat(32));
                assert_eq!(id, "02".repeat(16));
                assert_eq!(timestamp, 7);
                assert_eq!(body, "hi");
                assert_eq!(content_kind, ContentKind::LegacyText);
                assert_eq!(expires_at, None);
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
                view_once: false,
                expires_at: None,
                consumed: false,
                objects: vec![kult_node::AttachmentObjectInfo {
                    preview: false,
                    total_bytes: 1,
                    verified_bytes: 0,
                    media_type: "image/png".to_owned(),
                    filename: Some("private.png".to_owned()),
                    presentation: kult_node::classify_attachment_file(
                        "image/png",
                        Some("private.png"),
                    ),
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

    #[test]
    fn shared_formatter_converts_without_active_content_capabilities() {
        let core = kult_node::format_text("**safe** <img src=x>", &[]).unwrap();
        let formatted = FormattedText::from(core);
        assert_eq!(formatted.source, "**safe** <img src=x>");
        assert_eq!(formatted.plain_text, "safe <img src=x>");
        assert_eq!(formatted.blocks[0].kind, TextFormatBlockKind::Paragraph);
        assert_eq!(
            formatted.blocks[0].runs[0].styles,
            vec![TextFormatStyle::Strong]
        );
        assert!(formatted.blocks.iter().all(|block| block
            .runs
            .iter()
            .all(|run| { !run.text.contains("href=") && !run.text.contains("src=https://") })));
    }
}
