//! The node's command/event surface (docs/09-implementation-guide.md §3.5).
//! Render-safe attachment state lands here before the planned RPC/UniFFI and
//! shell adapters; protocol secrets and storage internals never cross it.

use kult_store::{
    ConversationId, CustomIconTarget, DeliveryState, GroupMessageRecord, MediaTransferState,
    MessageRecord,
};
use kult_transport::DeliveryHint;

/// Optional exact crop in oriented source pixels for a custom icon.
/// Absence requests the deterministic centered-square crop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomIconCrop {
    /// Left edge after orientation normalization.
    pub x: u32,
    /// Top edge after orientation normalization.
    pub y: u32,
    /// Non-zero crop width.
    pub width: u32,
    /// Non-zero crop height.
    pub height: u32,
}

/// Render-safe canonical custom icon bytes for one exact local target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomIconInfo {
    /// Exact typed contact, group, folder, or note-to-self target.
    pub target: CustomIconTarget,
    /// Canonical `image/png` media type.
    pub media_type: String,
    /// Exact metadata-free 256×256 RGBA PNG bytes.
    pub bytes: Vec<u8>,
    /// Canonical width in pixels.
    pub width: u32,
    /// Canonical height in pixels.
    pub height: u32,
}

/// Current sealed custom-icon quota usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomIconUsage {
    /// Number of durable icon records.
    pub records: usize,
    /// Aggregate encoded PNG bytes.
    pub bytes: usize,
}

/// One immutable original/edit version retained for local inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditVersionInfo {
    /// Original content id for revision zero, otherwise the edit-event id.
    pub id: [u8; 16],
    /// Zero for the original; positive for an Edit event.
    pub revision: u64,
    /// Local send/receive time for presentation only.
    pub timestamp: u64,
    /// Exact authenticated UTF-8 for this version.
    pub body: String,
}

/// Pairwise history row with ADR-0020 edits deterministically resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMessage {
    /// Original immutable record with only its returned read-model body
    /// replaced by the winning canonical Text frame when edited.
    pub record: MessageRecord,
    /// Whether a valid edit wins over the original.
    pub edited: bool,
    /// Winning positive revision, or zero for the original.
    pub winning_revision: u64,
    /// Original plus every valid edit, ordered by convergence tuple.
    pub versions: Vec<EditVersionInfo>,
}

/// Group history row with ADR-0020 edits deterministically resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedGroupMessage {
    /// Original immutable group record with only its returned read-model body
    /// replaced by the winning canonical Text frame when edited.
    pub record: GroupMessageRecord,
    /// Whether a valid edit wins over the original.
    pub edited: bool,
    /// Winning positive revision, or zero for the original.
    pub winning_revision: u64,
    /// Original plus every valid edit, ordered by convergence tuple.
    pub versions: Vec<EditVersionInfo>,
}

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

/// Render-safe durable private conversation pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinInfo {
    /// Exact stable typed conversation identity.
    pub conversation: ConversationId,
    /// Current local display name while active; absent for stale/note-to-self.
    pub display_name: Option<String>,
    /// Exact persisted manual order.
    pub order: u32,
    /// Whether the exact typed conversation is currently available.
    pub active: bool,
}

/// One eligible conversation after folder, label, and pin composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinConversationInfo {
    /// Exact stable typed conversation identity.
    pub conversation: ConversationId,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinConversationList {
    /// Exact folder selection applied first.
    pub selection: FolderSelection,
    /// Available selected label ids after canonical validation.
    pub selected_labels: Vec<[u8; 16]>,
    /// Requested labels whose definitions are unavailable.
    pub unavailable_labels: Vec<[u8; 16]>,
    /// Eligible rows with one leading pinned block and no duplicates.
    pub conversations: Vec<PinConversationInfo>,
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

/// Render-safe account-authorized physical-device row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedDeviceInfo {
    /// Exact stable physical-device id.
    pub id: [u8; 32],
    /// User-visible exact UTF-8 device name.
    pub name: String,
    /// Coarse authenticated observation time; not a presence promise.
    pub last_seen: u64,
    /// Revocation time, if this credential is permanently excluded.
    pub revoked_at: Option<u64>,
    /// Whether this row is the current physical installation.
    pub current: bool,
}

/// Honest delivery state for one exact recipient physical device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDeviceDeliveryInfo {
    /// Exact recipient physical-device id.
    pub device: [u8; 32],
    /// Current account-authorized user-visible name, if known.
    pub name: Option<String>,
    /// Honest queued/sent/delivered state for this copy.
    pub state: DeliveryState,
}

/// User-controlled state selection for a confirmed initial device transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLinkSelection {
    /// Transfer contacts and verification state.
    pub contacts: bool,
    /// Transfer folders, labels, pins, icons, and appearance choice.
    pub organization: bool,
    /// Transfer pairwise/group/note history without downloaded media.
    pub history: bool,
}

impl Default for DeviceLinkSelection {
    fn default() -> Self {
        Self {
            contacts: true,
            organization: true,
            history: true,
        }
    }
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
    /// Queue pairwise text with an authenticated exact local deadline.
    SendDisappearing {
        /// Recipient identity.
        peer: [u8; 32],
        /// Exact UTF-8 text.
        body: String,
        /// Relative lifetime in seconds, from 60 seconds through 30 days.
        lifetime_secs: u64,
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
    /// Rename a stored contact's private local petname by exact peer identity.
    RenameContact {
        /// The contact; display names are never accepted as targets.
        peer: [u8; 32],
        /// Proposed UTF-8 petname; the node stores its NFC form.
        name: String,
        /// Explicit acknowledgement of duplicate/spoofing warnings.
        accept_warnings: bool,
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
    /// Queue group text with an authenticated exact local deadline.
    GroupSendDisappearing {
        /// Group id.
        group: [u8; 32],
        /// Exact UTF-8 text.
        body: String,
        /// Relative lifetime in seconds, from 60 seconds through 30 days.
        lifetime_secs: u64,
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
    /// Conservative local classification of the authenticated display hints.
    pub presentation: crate::AttachmentFilePresentation,
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
    /// Whether this transfer is governed by first-open consumption.
    pub view_once: bool,
    /// Exact fallback deadline for view-once media.
    pub expires_at: Option<u64>,
    /// Whether first-open or expiry has made the source permanently unavailable.
    pub consumed: bool,
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

/// One exact member role in signed C6 authority state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupMemberRoleInfo {
    /// Exact peer identity.
    pub peer: [u8; 32],
    /// Fixed owner/admin/member role.
    pub role: kult_protocol::GroupRole,
}

/// Render-safe group authority snapshot without secrets or signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAuthorityInfo {
    /// Exact group id.
    pub group: [u8; 32],
    /// Whether the legacy group has entered signed C6 mode.
    pub signed: bool,
    /// Immutable original creator.
    pub original_owner: [u8; 32],
    /// Current single owner.
    pub owner: [u8; 32],
    /// Owner-transfer epoch.
    pub owner_epoch: u64,
    /// Current authority/roster generation.
    pub generation: u64,
    /// Sorted exact roles.
    pub members: Vec<GroupMemberRoleInfo>,
    /// Local identity's role, when still a member.
    pub my_role: Option<kult_protocol::GroupRole>,
}

/// One stable choice and its locally derived tally in a group poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollOptionInfo {
    /// Author-minted option id, scoped to the poll.
    pub id: [u8; 16],
    /// Exact authenticated UTF-8 label.
    pub text: String,
    /// Number of accepted vote heads selecting this option.
    pub votes: u32,
    /// Whether this installation's identity selected the option.
    pub selected_by_me: bool,
}

/// One visible authenticated vote head used by a poll tally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollVoteInfo {
    /// Authenticated voting member.
    pub voter: [u8; 32],
    /// Exact vote event id, or the creator-attested reference after closure.
    pub event_id: [u8; 16],
    /// Stable selected option id.
    pub option_id: [u8; 16],
    /// Positive voter-local monotonic revision.
    pub revision: u64,
}

/// Render-safe, locally derived single-choice group poll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollInfo {
    /// Exact group conversation.
    pub group: [u8; 32],
    /// Authenticated poll creator.
    pub author: [u8; 32],
    /// Stable creator-minted poll id.
    pub id: [u8; 16],
    /// Creation-time group roster generation.
    pub generation: u64,
    /// Exact authenticated UTF-8 question.
    pub question: String,
    /// Sorted fixed creation-time electorate.
    pub eligible_voters: Vec<[u8; 32]>,
    /// Stable choices in creator presentation order with derived tallies.
    pub options: Vec<PollOptionInfo>,
    /// Visible accepted vote heads, sorted by voter.
    pub votes: Vec<PollVoteInfo>,
    /// Whether a creator- or owner-authored final snapshot irreversibly closed the poll.
    pub closed: bool,
    /// Winning close event under the deterministic conflict rule.
    pub close_event_id: Option<[u8; 16]>,
    /// Authenticated group owner when the winning closure was moderation;
    /// absent when the poll creator closed their own poll.
    pub moderated_by: Option<[u8; 32]>,
    /// Whether the local identity belongs to the fixed electorate.
    pub eligible: bool,
    /// Whether the local identity may close this still-open poll.
    pub can_close: bool,
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
    /// Canonical immutable message edit. It refreshes the exact target and is
    /// never rendered as a standalone chat row.
    Edit {
        /// Edit-event content id.
        id: [u8; 16],
        /// Exact authenticated original author.
        target_author: [u8; 32],
        /// Exact canonical Text content id being edited.
        target_content_id: [u8; 16],
        /// Positive author-local revision.
        revision: u64,
    },
    /// Canonical disappearing UTF-8 removed locally at the exact deadline.
    DisappearingText {
        /// Content id scoped to the conversation and author.
        id: [u8; 16],
        /// Exact authenticated Unix-seconds local deadline.
        expires_at: u64,
    },
    /// Canonical view-once attachment offer.
    ViewOnceAttachment {
        /// Content id scoped to the conversation and author.
        id: [u8; 16],
        /// Random local transfer id used by consent/open state APIs.
        transfer: [u8; 16],
        /// Exact authenticated fallback deadline.
        expires_at: u64,
    },
    /// Canonical group-only poll event. It refreshes a derived poll card and
    /// is never rendered as an ordinary chat row.
    Poll {
        /// Exact event content id.
        id: [u8; 16],
        /// Authenticated creator of the target poll.
        poll_author: [u8; 32],
        /// Stable creator-minted poll id.
        poll_id: [u8; 16],
    },
    /// Canonical owner-signed C6 public authority commit.
    GroupAuthority {
        /// Exact event id.
        id: [u8; 16],
        /// Committed generation.
        generation: u64,
        /// Resulting current owner.
        owner: [u8; 32],
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
    /// Account-authorized physical-device list, name, or revocation changed.
    DevicesChanged,
    /// This installation completed a confirmed proximate account link.
    DeviceLinkCompleted {
        /// Stable account identity now active on this installation.
        account: [u8; 32],
        /// Exact new physical-device id.
        device: [u8; 32],
    },
    /// One or more private local custom icons changed; shells re-read visible targets.
    /// This event never enters an envelope, capability, group state, or transport.
    CustomIconsChanged,
    /// The private local appearance preference changed; shells re-read it.
    /// This event never enters an envelope, capability, group state, or transport.
    ThemeChanged,
    /// Local folder definitions, ordering, or assignments changed.
    /// This event never enters an envelope, capability, group state, or transport.
    FoldersChanged,
    /// Local label definitions or memberships changed; re-read label state.
    /// This event never enters an envelope, capability, group state, or transport.
    LabelsChanged,
    /// Local conversation pin membership or order changed; re-read pin state.
    /// This event never enters an envelope, capability, group state, or transport.
    PinsChanged,
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
    /// A canonical inbound edit was stored; shells refresh the exact pairwise
    /// target rather than append a row.
    MessageEdited {
        /// Pairwise peer that authored the edit and original.
        peer: [u8; 32],
        /// Original canonical Text content id.
        target_content_id: [u8; 16],
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
    /// A contact's sealed private local petname changed.
    ContactRenamed {
        /// Exact stable peer identity.
        peer: [u8; 32],
        /// Canonical NFC petname now stored locally.
        name: String,
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
    /// A canonical inbound group edit was stored; shells refresh the target.
    GroupMessageEdited {
        /// Exact group conversation.
        group: [u8; 32],
        /// Authenticated edit/original author.
        sender: [u8; 32],
        /// Original canonical Text content id.
        target_content_id: [u8; 16],
    },
    /// A poll creation, vote, or closure event changed one derived group poll.
    /// Applications re-read [`crate::Node::group_polls`] for the tally.
    PollUpdated {
        /// Exact group conversation.
        group: [u8; 32],
        /// Authenticated poll creator.
        poll_author: [u8; 32],
        /// Stable poll id.
        poll_id: [u8; 16],
    },
    /// Signed group roles/owner state changed or was observed.
    GroupAuthorityUpdated {
        /// Exact group.
        group: [u8; 32],
        /// Committed generation.
        generation: u64,
        /// Resulting current owner.
        owner: [u8; 32],
    },
    /// The current owner accepted or rejected one local admin request.
    GroupAdminRequestResolved {
        /// Exact group.
        group: [u8; 32],
        /// Stable locally minted request id.
        request_id: [u8; 16],
        /// Whether the owner committed the requested action.
        accepted: bool,
        /// Owner-observed authority generation after processing.
        generation: u64,
        /// Resulting authority event when accepted.
        state_id: Option<[u8; 16]>,
        /// Stable rejection reason code; zero on acceptance.
        reason: u8,
    },
    /// Ephemeral plaintext or decryptable media was durably removed locally.
    EphemeralRemoved {
        /// Exact pairwise or group scope.
        conversation: kult_store::EphemeralConversation,
        /// Authenticated author identity.
        author: [u8; 32],
        /// Author-minted content id.
        content_id: [u8; 16],
        /// Whether a deadline or first open caused removal.
        reason: kult_store::EphemeralState,
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
