//! The node's command/event surface (docs/09-implementation-guide.md §3.5).
//! Render-safe attachment state lands here before the planned RPC/UniFFI and
//! shell adapters; protocol secrets and storage internals never cross it.

use kult_store::{ConversationId, DeliveryState, MediaTransferState};
use kult_transport::DeliveryHint;

/// Render-safe private local folder definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderInfo {
    /// Random stable local id used by technical mutation APIs.
    pub id: [u8; 16],
    /// Exact user-authored UTF-8, without normalization or rewriting.
    pub name: String,
    /// Persisted manual order.
    pub order: u32,
}

/// One explicit local folder-navigation selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderSelection {
    /// Every available conversation.
    All,
    /// Available conversations with no active folder assignment.
    Unfiled,
    /// One exact stable folder id.
    Folder([u8; 16]),
}

/// Render-safe available typed conversation in a folder view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderConversationInfo {
    /// Exact stable typed identity.
    pub conversation: ConversationId,
    /// Current local petname/group name; absent for note-to-self.
    pub display_name: Option<String>,
}

/// Why one durable local folder assignment is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleFolderReason {
    /// Its stable folder id has no definition.
    MissingFolder,
    /// Its exact conversation target is unavailable.
    UnavailableConversation,
    /// Both the folder definition and target are unavailable.
    MissingFolderAndConversation,
}

/// Render-safe stale folder-assignment diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleFolderInfo {
    /// Exact stable technical folder id.
    pub folder: [u8; 16],
    /// Exact typed target; never a name or list position.
    pub conversation: ConversationId,
    /// The unavailable side or sides.
    pub reason: StaleFolderReason,
}

/// Deterministic folder classification composed with the active label filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderConversationList {
    /// Exact folder selection applied before label matching.
    pub selection: FolderSelection,
    /// Available selected label ids after canonical validation.
    pub selected_labels: Vec<[u8; 16]>,
    /// Requested label ids whose definitions are unavailable.
    pub unavailable_labels: Vec<[u8; 16]>,
    /// Available conversations matching both independent controls.
    pub conversations: Vec<FolderConversationInfo>,
}

/// Canonical local label filter semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelMatchMode {
    /// Match at least one selected label.
    Any,
    /// Match every selected label.
    All,
}

/// Render-safe local label definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelInfo {
    /// Random stable local id used by technical mutation APIs.
    pub id: [u8; 16],
    /// Exact user-authored UTF-8, without normalization or rewriting.
    pub name: String,
    /// Canonical presentation token; unknown stored values safely become neutral.
    pub color: String,
    /// Stable zero-based durable insertion order for duplicate disambiguation.
    pub order: u32,
}

/// Render-safe available typed conversation target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelConversationInfo {
    /// Exact stable typed identity.
    pub conversation: ConversationId,
    /// Current local petname/group name; absent for note-to-self.
    pub display_name: Option<String>,
}

/// Why one durable local label membership is stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleLabelReason {
    /// Its stable label id has no definition.
    MissingLabel,
    /// Its exact conversation target is unavailable.
    UnavailableConversation,
    /// Both the label definition and target are unavailable.
    MissingLabelAndConversation,
}

/// Render-safe stale membership diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleLabelInfo {
    /// Exact stable technical label id.
    pub label: [u8; 16],
    /// Exact typed target; never a name or list position.
    pub conversation: ConversationId,
    /// The unavailable side or sides.
    pub reason: StaleLabelReason,
}

/// Deterministic result of a local any/all label filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelFilterInfo {
    /// Canonically deduplicated available selected ids in caller order.
    pub selected: Vec<[u8; 16]>,
    /// Selected ids that no longer have definitions.
    pub unavailable_selected: Vec<[u8; 16]>,
    /// Available conversations matching the active selection.
    pub conversations: Vec<LabelConversationInfo>,
}

/// Application-facing summary of the best carrier currently known for one
/// peer. The ordering is semantic rather than a promise that a particular
/// transport remains reachable after the snapshot expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierCapability {
    /// A direct, low-latency non-airtime path is reachable now. Suitable for
    /// bulk transfer and a future measured real-time media profile.
    Realtime,
    /// A non-airtime path is reachable now or via store-and-forward. Suitable
    /// for bounded attachment transfer, but not necessarily live media.
    Bulk,
    /// At least one airtime-budgeted path is reachable, with no non-airtime
    /// path currently known. Bulk work must remain held.
    MeshOnly,
    /// No route is currently reachable, the peer is unknown, or the last
    /// positive observation expired.
    OfflineOrUnknown,
}

/// Time-bounded carrier verdict for one contact. Consumers must treat the
/// snapshot as [`CarrierCapability::OfflineOrUnknown`] after `expires_at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierCapabilitySnapshot {
    /// Contact identity key.
    pub peer: [u8; 32],
    /// Best currently observed carrier class.
    pub capability: CarrierCapability,
    /// Unix time at which transports were probed.
    pub observed_at: u64,
    /// Unix time at which this observation stops being authoritative.
    pub expires_at: u64,
}

/// Instructions the application layer gives the node. Every command is also
/// available as a typed method on [`crate::Node`]; this enum is the single
/// serializable entry point the FFI layer wraps.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Command {
    /// Queue a message to a known contact.
    Send {
        /// Recipient (Ed25519 identity key bytes).
        peer: [u8; 32],
        /// Message body (will be padded and encrypted).
        body: Vec<u8>,
    },
    /// Persist pairwise text until an absolute UTC send instant.
    Schedule {
        /// Recipient (Ed25519 identity key bytes).
        peer: [u8; 32],
        /// Message body.
        body: Vec<u8>,
        /// Unix seconds before which no encryption or transport work occurs.
        not_before: u64,
    },
    /// Persist group text until an absolute UTC send instant.
    GroupSchedule {
        /// Group id.
        group: [u8; 32],
        /// Message body.
        body: Vec<u8>,
        /// Unix seconds before which no encryption or transport work occurs.
        not_before: u64,
    },
    /// Edit text or the send instant while a scheduled entry is inactive.
    ScheduledEdit {
        /// Stable scheduled message id.
        id: [u8; 16],
        /// Replacement message body.
        body: Vec<u8>,
        /// Replacement absolute UTC send instant.
        not_before: u64,
    },
    /// Cancel a scheduled entry before it activates.
    ScheduledCancel {
        /// Stable scheduled message id.
        id: [u8; 16],
    },
    /// Append text to the reserved device-local note-to-self conversation.
    NoteToSelfSend {
        /// UTF-8 note text; no envelope or delivery state is created.
        body: String,
    },
    /// Add (or replace) a contact from their encoded prekey bundle.
    AddContact {
        /// Local display name.
        name: String,
        /// Encoded [`kult_crypto::PrekeyBundle`].
        bundle: Vec<u8>,
        /// How to reach them, per transport.
        hints: Vec<DeliveryHint>,
    },
    /// Replace a contact's delivery hints.
    SetHints {
        /// The contact.
        peer: [u8; 32],
        /// New hints.
        hints: Vec<DeliveryHint>,
    },
    /// Record that safety numbers were verified out-of-band.
    MarkVerified {
        /// The contact.
        peer: [u8; 32],
    },
    /// Create a sender-key group with stored contacts (ADR-0012). The
    /// caller becomes the group's creator — the only member who may add,
    /// remove, or re-key.
    GroupCreate {
        /// Display name.
        name: String,
        /// Initial co-members (each must be a stored contact).
        members: Vec<[u8; 32]>,
    },
    /// Queue a message to a group: encrypted once, fanned out per member.
    GroupSend {
        /// The group id.
        group: [u8; 32],
        /// Message body (will be padded and encrypted).
        body: Vec<u8>,
    },
    /// Queue canonical semantic Mention content to a sender-key group after
    /// exact roster/capability review revalidation (ADR-0016).
    GroupMentionSend {
        /// Group id.
        group: [u8; 32],
        /// Exact UTF-8 fallback message text.
        text: String,
        /// Sorted non-overlapping UTF-8 byte spans with explicit peer targets.
        spans: Vec<MentionSpan>,
        /// Token returned by the most recent capability/review snapshot.
        review_token: [u8; 16],
    },
    /// Add a stored contact to a group (creator only).
    GroupAdd {
        /// The group id.
        group: [u8; 32],
        /// The new member.
        peer: [u8; 32],
    },
    /// Remove a member (creator only): the group re-keys and every
    /// remaining member rotates.
    GroupRemove {
        /// The group id.
        group: [u8; 32],
        /// The member to remove.
        peer: [u8; 32],
    },
    /// Leave a group: co-members are told, local state is dropped
    /// (history stays).
    GroupLeave {
        /// The group id.
        group: [u8; 32],
    },
    /// Accept an offered attachment and request its missing chunks when a
    /// fresh non-airtime route is available.
    AttachmentAccept {
        /// Random local transfer id returned by attachment state APIs.
        transfer: [u8; 16],
    },
    /// Durably reject an offered attachment.
    AttachmentReject {
        /// Random local transfer id returned by attachment state APIs.
        transfer: [u8; 16],
    },
    /// Cancel local transfer activity and release unreferenced partial data.
    AttachmentCancel {
        /// Random local transfer id returned by attachment state APIs.
        transfer: [u8; 16],
    },
    /// Pause automatic attachment requests or serving while retaining
    /// durable verified progress.
    AttachmentPause {
        /// Random local transfer id returned by attachment state APIs.
        transfer: [u8; 16],
    },
    /// Resume an explicitly or automatically paused attachment.
    AttachmentResume {
        /// Random local transfer id returned by attachment state APIs.
        transfer: [u8; 16],
    },
}

/// Conversation scope of an attachment offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentConversation {
    /// Pairwise conversation with one contact.
    Pairwise,
    /// Sender-key group conversation.
    Group,
}

/// Local direction of an attachment transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentDirection {
    /// Bytes are being received from the manifest author.
    Inbound,
    /// This device authored and may serve the bytes.
    Outbound,
}

/// Render-safe object progress and authenticated display hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentObjectInfo {
    /// `false` for the primary object and `true` for its optional preview.
    pub preview: bool,
    /// Exact object size.
    pub total_bytes: u64,
    /// Bytes represented by durably committed, authenticated chunks.
    pub verified_bytes: u64,
    /// Untrusted authenticated media-type display hint.
    pub media_type: String,
    /// Optional sanitized filename display hint.
    pub filename: Option<String>,
    /// Durable lifecycle state.
    pub state: MediaTransferState,
}

/// Render-safe transfer state. Keys, chunk paths, bitmaps, ciphertext
/// addresses, and raw unsupported payloads deliberately remain private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// Random local transfer id used by consent/cancel APIs.
    pub transfer_id: [u8; 16],
    /// Peer served by or serving this transfer.
    pub peer: [u8; 32],
    /// Pairwise or group conversation.
    pub conversation: AttachmentConversation,
    /// Group id for group attachments; pairwise scope hashes are not exposed.
    pub group: Option<[u8; 32]>,
    /// Inbound or outbound local direction.
    pub direction: AttachmentDirection,
    /// Original manifest author.
    pub author: [u8; 32],
    /// Stable encrypted content id of the attachment offer.
    pub content_id: [u8; 16],
    /// Transfer-level lifecycle state.
    pub state: MediaTransferState,
    /// Primary object followed by an optional preview.
    pub objects: Vec<AttachmentObjectInfo>,
}

/// Authenticated display metadata supplied while importing one attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentMetadata {
    /// Lowercase IANA-style media type without parameters.
    pub media_type: String,
    /// Optional sanitized basename.
    pub filename: Option<String>,
}

/// A group as the application layer sees it — never the secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    /// The group id.
    pub id: [u8; 32],
    /// Display name (creator-controlled).
    pub name: String,
    /// The managing member.
    pub creator: [u8; 32],
    /// Full roster, this node included.
    pub members: Vec<[u8; 32]>,
}

/// One render-safe semantic mention span. Offsets address the exact UTF-8
/// fallback text in bytes; target identity is never inferred from petnames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MentionSpan {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
    /// Exact Ed25519 group peer identity key bytes.
    pub target: [u8; 32],
}

impl From<MentionSpan> for kult_protocol::MentionSpan {
    fn from(value: MentionSpan) -> Self {
        Self {
            start: value.start,
            end: value.end,
            target: value.target,
        }
    }
}

impl From<kult_protocol::MentionSpan> for MentionSpan {
    fn from(value: kult_protocol::MentionSpan) -> Self {
        Self {
            start: value.start,
            end: value.end,
            target: value.target,
        }
    }
}

/// Why one current group co-member blocks semantic Mention content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MentionCapabilityIssueReason {
    /// No authenticated capability snapshot exists for the current session.
    Unknown,
    /// A snapshot exists but does not advertise exact kind `0x0003`.
    Unsupported,
}

/// One current co-member that prevents a typed Mention send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MentionCapabilityIssue {
    /// Exact member peer id.
    pub peer: [u8; 32],
    /// Unknown or explicitly unsupported.
    pub reason: MentionCapabilityIssueReason,
}

/// Current all-co-member semantic Mention verdict and immutable review binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMentionCapability {
    /// Group this snapshot describes.
    pub group: [u8; 32],
    /// Opaque local token binding roster, display mapping, and exact support.
    pub review_token: [u8; 16],
    /// Empty only when typed Mention may be sent now.
    pub issues: Vec<MentionCapabilityIssue>,
}

impl GroupMentionCapability {
    /// Whether every current co-member supports exact Mention kind `0x0003`.
    pub fn supported(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Conversation addressed by one scheduled outbox entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledConversation {
    /// Pairwise conversation with a contact.
    Peer([u8; 32]),
    /// Sender-key group conversation.
    Group([u8; 32]),
}

/// Render-safe scheduled text. The plaintext has not entered a ratchet or
/// transport queue yet and can therefore still be edited or cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledMessageInfo {
    /// Stable id retained after activation.
    pub id: [u8; 16],
    /// Destination conversation.
    pub conversation: ScheduledConversation,
    /// Unix time when the schedule was created.
    pub created_at: u64,
    /// Absolute UTC Unix send instant.
    pub not_before: u64,
    /// Plaintext body, safe for the local application to render.
    pub body: Vec<u8>,
}

/// Render-safe classification of authenticated message content (ADR-0014).
///
/// Text bytes are carried separately by the event. Unsupported and malformed
/// content never exposes its raw authenticated bytes to application surfaces.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentStatus {
    /// Valid UTF-8 from the permanent pre-frame compatibility path.
    LegacyText,
    /// Canonical framed text with its author-minted content id.
    Text {
        /// Content id scoped to the conversation and author.
        id: [u8; 16],
    },
    /// Supported Attachment manifest with durable local transfer state.
    Attachment {
        /// Content id scoped to the conversation and author.
        id: [u8; 16],
        /// Random local transfer id used by attachment state APIs.
        transfer: [u8; 16],
    },
    /// Canonical group Mention with exact stable peer spans. The event body
    /// carries its exact authenticated fallback text.
    Mention {
        /// Content id scoped to the group and authenticated author.
        id: [u8; 16],
        /// Sorted non-overlapping semantic spans.
        spans: Vec<MentionSpan>,
    },
    /// Authenticated content this client version cannot interpret.
    Unsupported {
        /// Typed framing version, when known.
        format_version: Option<u8>,
        /// Content kind, when known from the common header.
        kind: Option<u16>,
    },
    /// A typed frame that violated the canonical framing contract.
    Malformed,
}

/// What the node reports back to the application layer. Delivery states are
/// honest by construction (docs/09-implementation-guide.md ground rule 4):
/// `Sent` means handed to a link, `Delivered` means an end-to-end encrypted
/// receipt came back — never anything weaker.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Local folder definitions, ordering, or assignments changed.
    /// This event never enters an envelope, capability, group state, or transport.
    FoldersChanged,
    /// Local label definitions or memberships changed; re-read label state.
    /// This event never enters an envelope, capability, group state, or transport.
    LabelsChanged,
    /// A scheduled message was created or edited; re-read the scheduled
    /// outbox for the authoritative record.
    ScheduledMessageUpdated {
        /// Stable scheduled message id.
        id: [u8; 16],
    },
    /// A scheduled message was cancelled before activation.
    ScheduledMessageCancelled {
        /// Stable scheduled message id.
        id: [u8; 16],
    },
    /// A scheduled message reached its UTC instant and entered the ordinary
    /// encrypted delivery queue under the same stable id.
    ScheduledMessageActivated {
        /// Stable scheduled message id.
        id: [u8; 16],
    },
    /// A message record changed delivery state
    /// (`Queued` → `Sent` → `Delivered`).
    DeliveryUpdated {
        /// Message record id.
        id: [u8; 16],
        /// The new state.
        state: DeliveryState,
    },
    /// An inbound message was decrypted and stored.
    MessageReceived {
        /// Sender (Ed25519 identity key bytes).
        peer: [u8; 32],
        /// Message record id.
        id: [u8; 16],
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Renderable UTF-8 bytes for legacy or framed text; empty for
        /// unsupported or malformed content.
        body: Vec<u8>,
        /// Explicit content interpretation.
        content: ContentStatus,
    },
    /// Text was appended to the reserved local note-to-self conversation.
    NoteToSelfMessageAdded {
        /// Local note record id.
        id: [u8; 16],
        /// Local creation time (Unix seconds).
        timestamp: u64,
        /// UTF-8 note text.
        body: String,
    },
    /// An unknown peer completed a handshake with us; a contact stub was
    /// created (unverified, no hints — the application fills those in).
    ContactAdded {
        /// The new peer (Ed25519 identity key bytes).
        peer: [u8; 32],
    },
    /// A ratchet session with this peer was (re-)established from an inbound
    /// handshake. A *re*-establishment for a known contact means their key
    /// or device changed — surface it.
    SessionEstablished {
        /// The peer (Ed25519 identity key bytes).
        peer: [u8; 32],
    },
    /// An outbound message exceeds the airtime ceiling and only
    /// duty-cycle-limited (LoRa) carriers currently reach the recipient, so
    /// it was held rather than sent (docs/05-transports.md §4.2 rule 3).
    /// Honest UI feedback: "will send when a faster link exists". The
    /// message stays queued and goes out on the first tick after a faster
    /// carrier can reach the peer. Emitted once per message, not per tick.
    AwaitingFasterLink {
        /// Message record id.
        id: [u8; 16],
    },
    /// The best time-bounded carrier verdict for a contact changed. Initial
    /// observation is emitted too, so applications can populate state from
    /// the same stream used for later transitions.
    CarrierCapabilityChanged {
        /// Current authoritative snapshot.
        snapshot: CarrierCapabilitySnapshot,
    },
    /// A group was created, joined, re-keyed, re-rostered, or left
    /// (ADR-0012) — re-read it via [`crate::Node::groups`].
    GroupUpdated {
        /// The group id.
        group: [u8; 32],
    },
    /// An inbound group message was decrypted and stored.
    GroupMessageReceived {
        /// The group id.
        group: [u8; 32],
        /// The sending member (Ed25519 identity key bytes).
        sender: [u8; 32],
        /// Group message record id.
        id: [u8; 16],
        /// Local receive time (Unix seconds).
        timestamp: u64,
        /// Renderable UTF-8 bytes for legacy or framed text; empty for
        /// unsupported or malformed content.
        body: Vec<u8>,
        /// Explicit content interpretation.
        content: ContentStatus,
    },
    /// A durably stored canonical group Mention targets this exact local peer.
    /// Applications re-read the record by id; no text or target list is copied
    /// into this signal.
    MentionReceived {
        /// Stored group message record id.
        id: [u8; 16],
    },
    /// One member's copy of an outbound group message changed delivery
    /// state — per member, honestly, like the pairwise ladder.
    GroupDeliveryUpdated {
        /// Group message record id.
        id: [u8; 16],
        /// The member this copy addresses.
        peer: [u8; 32],
        /// The new state.
        state: DeliveryState,
    },
    /// Attachment offer, consent, progress, completion, or terminal state
    /// changed; the included state is safe to render directly.
    AttachmentUpdated {
        /// Current transfer state.
        attachment: AttachmentInfo,
    },
}
