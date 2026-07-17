//! The local RPC wire format: newline-delimited JSON over a Unix socket.
//!
//! One request object per line, one response object per line, correlated by
//! `id`. A connection that sent `subscribe` additionally receives event
//! objects (`{"event": …}`) as they happen. Binary values (peer ids, message
//! ids, prekey bundles) travel as lowercase hex — the socket is local and
//! trusted, so readability beats compactness.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kult_node::{
    AttachmentConversation, AttachmentDirection, AttachmentFileKind, AttachmentFilePresentation,
    AttachmentFileWarning, AttachmentInfo, AttachmentOpenPolicy, CallAudioFrame, CallAvailability,
    CallDirection, CallEndReason, CallInfo, CallPhase, CallUnavailableReason, CarrierCapability,
    CarrierCapabilitySnapshot, ContactNameAssessment, ContactNameWarning, ContentStatus,
    CustomIconInfo, CustomIconTarget, CustomIconUsage, Event, FolderConversationInfo,
    FolderConversationList, FolderInfo, FolderSelection, GroupAuthorityInfo, GroupInfo,
    GroupMentionCapability, GroupRole, IncognitoKeyboardPlatform, IncognitoKeyboardPolicy,
    LabelConversationInfo, LabelFilterInfo, LabelInfo, MentionCapabilityIssueReason,
    NodeStaleFolderReason, NodeStaleLabelReason, PinConversationInfo, PinConversationList, PinInfo,
    PollInfo, ResolvedGroupMessage, ResolvedMessage, ScheduledConversation, ScheduledMessageInfo,
    ScreenSecurityPlatform, ScreenSecurityPolicy, StaleFolderInfo, StaleLabelInfo,
    TextFormatBlockKind, TextFormatHighlight, TextFormatStyle, NOTE_TO_SELF_CONVERSATION_ID,
};
use kult_store::{
    valid_folder_name, valid_label_color, valid_label_name, ConversationId, DeliveryState,
    Direction, MediaTransferState, NoteMessageRecord, MAX_FOLDERS, MAX_LABELS, MAX_PINS,
};
use kult_transport::DeliveryHint;

/// One request line.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Client-chosen correlation id, echoed in the response.
    pub id: u64,
    /// The operation.
    #[serde(flatten)]
    pub op: Op,
}

/// One exact UTF-8 source range supplied to the shared formatter.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextFormatHighlightInput {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
}

impl From<TextFormatHighlightInput> for TextFormatHighlight {
    fn from(highlight: TextFormatHighlightInput) -> Self {
        Self {
            start: highlight.start,
            end: highlight.end,
        }
    }
}

/// Strictly parse one complete RPC request, rejecting unknown fields and
/// non-whitespace trailing input instead of silently accepting ambiguity.
pub fn parse_request(line: &str) -> Result<Request, String> {
    let mut deserializer = serde_json::Deserializer::from_str(line);
    let value = Value::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "request must be a JSON object".to_owned())?;
    if let Some(op) = object.get("op").and_then(Value::as_str) {
        if let Some(allowed) = local_metadata_request_fields(op) {
            if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
                return Err(format!("unknown request field: {unknown}"));
            }
        }
    }
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn local_metadata_request_fields(op: &str) -> Option<&'static [&'static str]> {
    match op {
        "contact_name_assessment" => Some(&["id", "op", "peer", "name"]),
        "rename_contact" => Some(&["id", "op", "peer", "name", "accept_warnings"]),
        "screen_security_policy" | "incognito_keyboard_policy" => Some(&["id", "op", "platform"]),
        "theme" => Some(&["id", "op"]),
        "device_id" | "linked_devices" | "device_link_begin" => Some(&["id", "op"]),
        "message_device_deliveries" => Some(&["id", "op", "message"]),
        "device_rename" => Some(&["id", "op", "device", "name"]),
        "device_revoke" | "device_sync_export" => Some(&["id", "op", "device"]),
        "device_link_accept" => Some(&["id", "op", "offer", "name"]),
        "device_link_code" => Some(&["id", "op", "response"]),
        "device_link_approve" => Some(&["id", "op", "response", "selection", "confirmed"]),
        "device_link_complete" => Some(&["id", "op", "package", "confirmed"]),
        "device_sync_import" => Some(&["id", "op", "bundle"]),
        "theme_set" => Some(&["id", "op", "preference"]),
        "custom_icon" | "custom_icon_clear" => Some(&["id", "op", "target"]),
        "custom_icon_set_path" => Some(&["id", "op", "target", "path", "crop"]),
        "custom_icon_set_bundled" => Some(&["id", "op", "target", "glyph"]),
        "custom_icon_usage" => Some(&["id", "op"]),
        "folder_create" => Some(&["id", "op", "name"]),
        "folders" | "folder_stale" => Some(&["id", "op"]),
        "folder_get" | "folder_delete_preview" | "folder_membership" => {
            Some(&["id", "op", "folder"])
        }
        "folder_rename" => Some(&["id", "op", "folder", "name"]),
        "folder_reorder" => Some(&["id", "op", "folders"]),
        "folder_delete" => Some(&["id", "op", "folder", "confirm"]),
        "folder_move" | "folder_stale_cleanup" => Some(&["id", "op", "folder", "target"]),
        "folder_unfile" | "conversation_folder" => Some(&["id", "op", "target"]),
        "folder_conversations" => Some(&["id", "op", "selection", "labels", "mode"]),
        "label_create" => Some(&["id", "op", "name", "color"]),
        "labels" | "label_stale" => Some(&["id", "op"]),
        "label_get" | "label_delete_preview" | "label_membership" => Some(&["id", "op", "label"]),
        "label_update" => Some(&["id", "op", "label", "name", "color"]),
        "label_delete" => Some(&["id", "op", "label", "confirm"]),
        "label_assign" | "label_unassign" | "label_stale_cleanup" => {
            Some(&["id", "op", "label", "target"])
        }
        "labels_for_conversation" => Some(&["id", "op", "target"]),
        "label_filter" => Some(&["id", "op", "labels", "mode"]),
        "pin" | "unpin" | "pin_state" | "pin_stale_cleanup" => Some(&["id", "op", "target"]),
        "pins" | "pin_stale" => Some(&["id", "op"]),
        "pin_reorder" => Some(&["id", "op", "targets"]),
        "pin_conversations" => Some(&["id", "op", "selection", "labels", "mode"]),
        "format_text" => Some(&["id", "op", "source", "highlights"]),
        "attachment_file_presentation" => Some(&["id", "op", "media_type", "filename"]),
        "edit_message" => Some(&[
            "id",
            "op",
            "peer",
            "target_author",
            "target_content_id",
            "text",
        ]),
        "send_disappearing" => Some(&["id", "op", "peer", "body", "lifetime_secs"]),
        "attachment_send_view_once" => Some(&[
            "id",
            "op",
            "peer",
            "path",
            "media_type",
            "filename",
            "preview_path",
            "preview_media_type",
            "lifetime_secs",
        ]),
        "group_attachment_send_view_once" => Some(&[
            "id",
            "op",
            "group",
            "path",
            "media_type",
            "filename",
            "preview_path",
            "preview_media_type",
            "lifetime_secs",
        ]),
        "attachment_consume_view_once" => Some(&["id", "op", "transfer", "path"]),
        "group_edit_message" => Some(&[
            "id",
            "op",
            "group",
            "target_author",
            "target_content_id",
            "text",
        ]),
        "group_send_disappearing" => Some(&["id", "op", "group", "body", "lifetime_secs"]),
        "group_poll_create" => Some(&["id", "op", "group", "question", "options"]),
        "group_polls" => Some(&["id", "op", "group"]),
        "group_poll_vote" => Some(&["id", "op", "group", "poll_author", "poll_id", "option_id"]),
        "group_poll_close" => Some(&["id", "op", "group", "poll_author", "poll_id"]),
        "group_poll_moderate_close" => Some(&["id", "op", "group", "poll_author", "poll_id"]),
        "group_authority" | "group_upgrade_authority" => Some(&["id", "op", "group"]),
        "group_rename" => Some(&["id", "op", "group", "name"]),
        "group_set_role" => Some(&["id", "op", "group", "peer", "role"]),
        "group_transfer_owner" => Some(&["id", "op", "group", "peer"]),
        "calls" => Some(&["id", "op"]),
        "call_availability" | "call_start" => Some(&["id", "op", "peer"]),
        "call_answer" | "call_decline" | "call_cancel" | "call_hangup" | "call_audio_take" => {
            Some(&["id", "op", "call"])
        }
        "call_audio_send" => Some(&["id", "op", "call", "timestamp_ms", "opus"]),
        _ => None,
    }
}

/// Explicit selective state imported during a confirmed device link.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceLinkSelectionInput {
    /// Import contacts and verification.
    pub contacts: bool,
    /// Import private local organization.
    pub organization: bool,
    /// Import non-ephemeral history.
    pub history: bool,
}

/// Every operation the daemon serves. Mirrors the node's command/event API
/// (docs/09-implementation-guide.md §3.5) plus daemon-level introspection.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Daemon and node status: address, listen addrs, LAN peers seen via
    /// mDNS, NAT verdict, queue.
    Status,
    /// Export a fresh signed prekey bundle (hex) for out-of-band sharing.
    Bundle,
    /// Exact separately authenticated physical-device id.
    DeviceId,
    /// Complete account-authorized local device list.
    LinkedDevices,
    /// Per-device delivery state for one account-level message.
    MessageDeviceDeliveries {
        /// Stable message id (hex).
        message: String,
    },
    /// Rename one active linked physical device.
    DeviceRename {
        /// Exact device id (hex).
        device: String,
        /// Exact bounded UTF-8 display name.
        name: String,
    },
    /// Permanently revoke another linked physical device.
    DeviceRevoke {
        /// Exact device id (hex).
        device: String,
    },
    /// Begin a bounded account-authenticated proximate link offer.
    DeviceLinkBegin,
    /// Accept a link offer on a pristine target and return response/code.
    DeviceLinkAccept {
        /// Hex-encoded offer bytes.
        offer: String,
        /// Exact proposed device name.
        name: String,
    },
    /// Derive the source-side comparison code for one target response.
    DeviceLinkCode {
        /// Hex-encoded response bytes.
        response: String,
    },
    /// Confirm and produce the encrypted selective initial-transfer package.
    DeviceLinkApprove {
        /// Hex-encoded target response.
        response: String,
        /// Explicit initial-transfer selection.
        selection: DeviceLinkSelectionInput,
        /// Both users explicitly confirmed the comparison code.
        confirmed: bool,
    },
    /// Confirm and import one encrypted link package on the pristine target.
    DeviceLinkComplete {
        /// Hex-encoded approved package.
        package: String,
        /// Both users explicitly confirmed the comparison code.
        confirmed: bool,
    },
    /// Export one encrypted convergence bundle to an active linked device.
    DeviceSyncExport {
        /// Exact recipient device id (hex).
        device: String,
    },
    /// Import one encrypted convergence bundle.
    DeviceSyncImport {
        /// Hex-encoded bundle bytes.
        bundle: String,
    },
    /// Render exact source into the bounded, inert shared display model.
    FormatText {
        /// Exact authenticated or composed UTF-8 source.
        source: String,
        /// Optional existing semantic ranges composed as inert highlights.
        #[serde(default)]
        highlights: Vec<TextFormatHighlightInput>,
    },
    /// Classify untrusted authenticated attachment hints for inert local UI.
    AttachmentFilePresentation {
        /// Exact lower-case media-type hint.
        media_type: String,
        /// Optional sanitized display basename.
        filename: Option<String>,
    },
    /// Add a contact from an out-of-band prekey bundle.
    AddContact {
        /// Local display name.
        name: String,
        /// Hex-encoded prekey bundle.
        bundle: String,
        /// How to reach them.
        #[serde(default)]
        hints: Vec<Hint>,
    },
    /// Add a contact from their kult address alone (DHT lookup).
    AddByAddress {
        /// Local display name.
        name: String,
        /// The peer's kult address string.
        address: String,
    },
    /// Validate and assess a proposed private local petname without mutation.
    ContactNameAssessment {
        /// Exact contact peer id (hex).
        peer: String,
        /// Proposed UTF-8 petname.
        name: String,
    },
    /// Rename one stored contact locally by exact peer id.
    RenameContact {
        /// Exact contact peer id (hex).
        peer: String,
        /// Proposed UTF-8 petname; the node stores its NFC form.
        name: String,
        /// Explicit acknowledgement of every returned warning.
        #[serde(default)]
        accept_warnings: bool,
    },
    /// Queue a message.
    Send {
        /// Recipient peer id (hex).
        peer: String,
        /// Message body (UTF-8 text).
        body: String,
    },
    /// Queue pairwise text with exact local expiry and coarse relay retention.
    SendDisappearing {
        /// Recipient peer id (hex).
        peer: String,
        /// Exact UTF-8 body.
        body: String,
        /// Lifetime in seconds (60 through 30 days).
        lifetime_secs: u64,
    },
    /// Queue an immutable edit for an exact authored pairwise Text event.
    EditMessage {
        /// Pairwise conversation peer id (hex).
        peer: String,
        /// Original author peer id (hex); must be this node for local send.
        target_author: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
        /// Exact non-empty replacement UTF-8.
        text: String,
    },
    /// Import and queue a pairwise attachment from a caller-selected path.
    AttachmentSend {
        /// Recipient peer id (hex).
        peer: String,
        /// Plaintext input path selected by the local caller.
        path: String,
        /// Authenticated lowercase media-type hint.
        media_type: String,
        /// Optional authenticated display basename.
        filename: Option<String>,
        /// Optional locally generated preview input path.
        #[serde(default)]
        preview_path: Option<String>,
        /// JPEG/PNG media type required when `preview_path` is present.
        #[serde(default)]
        preview_media_type: Option<String>,
    },
    /// Import and queue a pairwise view-once attachment.
    AttachmentSendViewOnce {
        /// Recipient peer id (hex).
        peer: String,
        /// Plaintext input path selected by the local caller.
        path: String,
        /// Authenticated lowercase media-type hint.
        media_type: String,
        /// Optional authenticated display basename.
        filename: Option<String>,
        /// Optional locally generated preview input path.
        #[serde(default)]
        preview_path: Option<String>,
        /// JPEG/PNG media type required with a preview.
        #[serde(default)]
        preview_media_type: Option<String>,
        /// Fallback lifetime in seconds.
        lifetime_secs: u64,
    },
    /// Import and queue a sender-key group attachment.
    GroupAttachmentSend {
        /// Group id (hex).
        group: String,
        /// Plaintext input path selected by the local caller.
        path: String,
        /// Authenticated lowercase media-type hint.
        media_type: String,
        /// Optional authenticated display basename.
        filename: Option<String>,
        /// Optional locally generated preview input path.
        #[serde(default)]
        preview_path: Option<String>,
        /// JPEG/PNG media type required when `preview_path` is present.
        #[serde(default)]
        preview_media_type: Option<String>,
    },
    /// Import and queue a sender-key group view-once attachment.
    GroupAttachmentSendViewOnce {
        /// Group id (hex).
        group: String,
        /// Plaintext input path selected by the local caller.
        path: String,
        /// Authenticated lowercase media-type hint.
        media_type: String,
        /// Optional authenticated display basename.
        filename: Option<String>,
        /// Optional locally generated preview input path.
        #[serde(default)]
        preview_path: Option<String>,
        /// JPEG/PNG media type required with a preview.
        #[serde(default)]
        preview_media_type: Option<String>,
        /// Fallback lifetime in seconds.
        lifetime_secs: u64,
    },
    /// List render-safe attachment transfer state.
    Attachments,
    /// Accept an inbound attachment offer.
    AttachmentAccept {
        /// Local transfer id (hex).
        transfer: String,
    },
    /// Reject an inbound attachment offer.
    AttachmentReject {
        /// Local transfer id (hex).
        transfer: String,
    },
    /// Cancel local attachment activity.
    AttachmentCancel {
        /// Local transfer id (hex).
        transfer: String,
    },
    /// Pause attachment activity while retaining verified progress.
    AttachmentPause {
        /// Local transfer id (hex).
        transfer: String,
    },
    /// Resume a paused attachment.
    AttachmentResume {
        /// Local transfer id (hex).
        transfer: String,
    },
    /// Stream a completed primary object to a new caller-selected file.
    AttachmentExport {
        /// Local transfer id (hex).
        transfer: String,
        /// Destination path, created without overwriting.
        path: String,
        /// Export the optional preview instead of the primary object.
        #[serde(default)]
        preview: bool,
    },
    /// Consume a view-once primary into a new caller-selected protected file.
    AttachmentConsumeViewOnce {
        /// Local transfer id (hex).
        transfer: String,
        /// Destination path, created without overwriting.
        path: String,
    },
    /// Schedule pairwise text for an absolute UTC Unix instant.
    Schedule {
        /// Recipient peer id (hex).
        peer: String,
        /// Message body (UTF-8 text).
        body: String,
        /// Unix seconds before which no transport work occurs.
        not_before: u64,
    },
    /// Schedule group text for an absolute UTC Unix instant.
    GroupSchedule {
        /// Group id (hex).
        group: String,
        /// Message body (UTF-8 text).
        body: String,
        /// Unix seconds before which no transport work occurs.
        not_before: u64,
    },
    /// Edit a scheduled message before activation.
    ScheduledEdit {
        /// Stable scheduled message id (hex).
        message: String,
        /// Replacement message body.
        body: String,
        /// Replacement absolute UTC Unix instant.
        not_before: u64,
    },
    /// Cancel a scheduled message before activation.
    ScheduledCancel {
        /// Stable scheduled message id (hex).
        message: String,
    },
    /// List the durable scheduled outbox.
    ScheduledMessages,
    /// Append text to the reserved local note-to-self conversation.
    NoteToSelfSend {
        /// UTF-8 note text.
        body: String,
    },
    /// Read the reserved local note-to-self history.
    NoteToSelfMessages,
    /// Read the private local appearance preference.
    Theme,
    /// Read the immutable always-on screen-security policy for one shell.
    ScreenSecurityPolicy {
        /// One of `android`, `ios`, or `desktop`.
        platform: String,
    },
    /// Read the immutable always-on incognito-keyboard policy for one shell.
    IncognitoKeyboardPolicy {
        /// One of `android`, `ios`, or `desktop`.
        platform: String,
    },
    /// Persist one exact canonical appearance preference.
    ThemeSet {
        /// One of `system`, `light`, or `dark`.
        preference: String,
    },
    /// Read one canonical sealed icon, or null for generated initials.
    CustomIcon {
        /// Exact typed local target.
        target: CustomIconTargetInput,
    },
    /// Crop, sanitize, canonicalize, and seal one selected local JPEG/PNG.
    CustomIconSetPath {
        /// Exact typed local target.
        target: CustomIconTargetInput,
        /// Caller-selected local input path.
        path: String,
        /// Optional exact square crop in oriented source pixels.
        #[serde(default)]
        crop: Option<CustomIconCropInput>,
    },
    /// Render and seal one bundled glyph token.
    CustomIconSetBundled {
        /// Exact typed local target.
        target: CustomIconTargetInput,
        /// One canonical bundled glyph token.
        glyph: String,
    },
    /// Remove one icon and return to generated initials.
    CustomIconClear {
        /// Exact typed local target.
        target: CustomIconTargetInput,
    },
    /// Read current sealed icon quota usage.
    CustomIconUsage,
    /// Create one private local conversation folder.
    FolderCreate {
        /// Exact UTF-8 folder name.
        name: String,
    },
    /// List all private folders in deterministic manual order.
    Folders,
    /// Get one private folder by explicit 32-hex-character id.
    FolderGet {
        /// Stable folder id.
        folder: String,
    },
    /// Rename one folder without changing id, order, or membership.
    FolderRename {
        /// Stable folder id.
        folder: String,
        /// Exact replacement UTF-8 name.
        name: String,
    },
    /// Atomically reorder the explicit complete active folder id set.
    FolderReorder {
        /// Every active stable folder id exactly once, in desired order.
        folders: Vec<String>,
    },
    /// Read assignment count before destructive folder deletion.
    FolderDeletePreview {
        /// Stable folder id.
        folder: String,
    },
    /// Atomically delete one folder and move every assignment to Unfiled.
    FolderDelete {
        /// Stable folder id.
        folder: String,
        /// Must be true; automation cannot delete implicitly.
        confirm: bool,
    },
    /// Idempotently move one exact typed conversation into a folder.
    FolderMove {
        /// Stable folder id.
        folder: String,
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Idempotently move one exact typed conversation to virtual Unfiled.
    FolderUnfile {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// List active typed membership for one folder.
    FolderMembership {
        /// Stable folder id.
        folder: String,
    },
    /// Get the active folder for one exact typed conversation.
    ConversationFolder {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Classify All/Unfiled/one folder and then apply an independent label filter.
    FolderConversations {
        /// Exact virtual or stable-folder selection.
        selection: FolderSelectionInput,
        /// Stable label ids for the second-stage filter.
        labels: Vec<String>,
        /// Match-any or match-all label semantics.
        mode: LabelMatchInput,
    },
    /// Inspect render-safe stale folder assignments.
    FolderStale,
    /// Remove one exact assignment only if it remains stale.
    FolderStaleCleanup {
        /// Stable folder id referenced by the stale row.
        folder: String,
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Create one private local label.
    LabelCreate {
        /// Exact UTF-8 label name.
        name: String,
        /// Canonical color token.
        color: String,
    },
    /// List all private labels in stable insertion order.
    Labels,
    /// Get one private label by explicit 32-hex-character id.
    LabelGet {
        /// Stable label id.
        label: String,
    },
    /// Rename and recolor one label without changing its id or memberships.
    LabelUpdate {
        /// Stable label id.
        label: String,
        /// Exact replacement UTF-8 name.
        name: String,
        /// Canonical replacement color token.
        color: String,
    },
    /// Read assignment count before destructive label deletion.
    LabelDeletePreview {
        /// Stable label id.
        label: String,
    },
    /// Atomically delete one label and all memberships.
    LabelDelete {
        /// Stable label id.
        label: String,
        /// Must be true; automation cannot delete implicitly.
        confirm: bool,
    },
    /// Idempotently apply a label to an explicit typed conversation.
    LabelAssign {
        /// Stable label id.
        label: String,
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Idempotently remove one exact membership.
    LabelUnassign {
        /// Stable label id.
        label: String,
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// List active typed conversation membership for one label.
    LabelMembership {
        /// Stable label id.
        label: String,
    },
    /// List active labels for one explicit typed conversation.
    LabelsForConversation {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Inspect render-safe stale local label memberships.
    LabelStale,
    /// Remove one exact membership only if it remains stale.
    LabelStaleCleanup {
        /// Stable label id.
        label: String,
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Filter eligible conversations by explicit label ids.
    LabelFilter {
        /// Stable label ids, canonically deduplicated by the node.
        labels: Vec<String>,
        /// Match-any or match-all semantics.
        mode: LabelMatchInput,
    },
    /// Idempotently append one exact available conversation to the pin order.
    Pin {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Idempotently unpin one exact active or stale target.
    Unpin {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// Get the durable pin state for one exact target.
    PinState {
        /// Exact pairwise/group/note-to-self target.
        target: LabelTargetInput,
    },
    /// List every durable active or stale pin in manual order.
    Pins,
    /// Atomically reorder the complete durable pin target set.
    PinReorder {
        /// Every durable typed target exactly once, in desired order.
        targets: Vec<LabelTargetInput>,
    },
    /// List unavailable durable pins.
    PinStale,
    /// Remove one exact pin only while its target remains unavailable.
    PinStaleCleanup {
        /// Exact unavailable typed target.
        target: LabelTargetInput,
    },
    /// Apply folder classification, label filtering, and pin-aware ordering.
    PinConversations {
        /// Exact virtual or stable-folder selection.
        selection: FolderSelectionInput,
        /// Stable label ids for the second-stage filter.
        labels: Vec<String>,
        /// Match-any or match-all label semantics.
        mode: LabelMatchInput,
    },
    /// Create a sender-key group with stored contacts.
    GroupCreate {
        /// Display name.
        name: String,
        /// Initial co-members (hex peer ids).
        members: Vec<String>,
    },
    /// Queue a group message.
    GroupSend {
        /// Group id (hex).
        group: String,
        /// Message body (UTF-8 text).
        body: String,
    },
    /// Queue group text with exact local expiry and coarse relay retention.
    GroupSendDisappearing {
        /// Group id (hex).
        group: String,
        /// Exact UTF-8 body.
        body: String,
        /// Lifetime in seconds (60 through 30 days).
        lifetime_secs: u64,
    },
    /// Queue an immutable edit for an exact authored group Text event.
    GroupEditMessage {
        /// Group id (hex).
        group: String,
        /// Original author peer id (hex); must be this node for local send.
        target_author: String,
        /// Original canonical Text content id (hex).
        target_content_id: String,
        /// Exact non-empty replacement UTF-8.
        text: String,
    },
    /// Read the current all-member Mention support verdict and review token.
    GroupMentionCapability {
        /// Group id (hex).
        group: String,
    },
    /// Queue canonical semantic Mention content using explicit peer targets.
    GroupMentionSend {
        /// Group id (hex).
        group: String,
        /// Exact UTF-8 fallback message text.
        text: String,
        /// Canonical UTF-8 byte ranges and explicit peer ids.
        spans: Vec<MentionSpanInput>,
        /// Review token from `group_mention_capability` (hex).
        review_token: String,
    },
    /// Create a single-choice poll with explicit ordered UTF-8 options.
    GroupPollCreate {
        /// Group id (hex).
        group: String,
        /// Exact UTF-8 question.
        question: String,
        /// Ordered exact UTF-8 option labels.
        options: Vec<String>,
    },
    /// List locally derived polls and visible vote heads for a group.
    GroupPolls {
        /// Group id (hex).
        group: String,
    },
    /// Cast or change this identity's vote using stable ids only.
    GroupPollVote {
        /// Group id (hex).
        group: String,
        /// Poll creator peer id (hex).
        poll_author: String,
        /// Stable poll id (hex).
        poll_id: String,
        /// Stable selected option id (hex).
        option_id: String,
    },
    /// Irreversibly close this identity's poll using stable ids only.
    GroupPollClose {
        /// Group id (hex).
        group: String,
        /// Poll creator peer id (hex).
        poll_author: String,
        /// Stable poll id (hex).
        poll_id: String,
    },
    /// Owner/admin moderation closure bound to signed group authority.
    GroupPollModerateClose {
        /// Group id (hex).
        group: String,
        /// Poll creator peer id (hex).
        poll_author: String,
        /// Stable poll id (hex).
        poll_id: String,
    },
    /// Read current signed or synthesized group roles and ownership.
    GroupAuthority {
        /// Group id (hex).
        group: String,
    },
    /// Upgrade a legacy creator group to signed authority state.
    GroupUpgradeAuthority {
        /// Group id (hex).
        group: String,
    },
    /// Rename a group directly as owner or by admin request.
    GroupRename {
        /// Group id (hex).
        group: String,
        /// Exact replacement name.
        name: String,
    },
    /// Grant or revoke admin role as owner.
    GroupSetRole {
        /// Group id (hex).
        group: String,
        /// Existing member peer id (hex).
        peer: String,
        /// `admin` or `member`.
        role: GroupRoleInput,
    },
    /// Transfer sole ownership to an existing member.
    GroupTransferOwner {
        /// Group id (hex).
        group: String,
        /// Existing member peer id (hex).
        peer: String,
    },
    /// Add a stored contact to a group (creator only).
    GroupAdd {
        /// Group id (hex).
        group: String,
        /// New member's peer id (hex).
        peer: String,
    },
    /// Remove a member from a group (creator only).
    GroupRemove {
        /// Group id (hex).
        group: String,
        /// Member's peer id (hex).
        peer: String,
    },
    /// Leave a group.
    GroupLeave {
        /// Group id (hex).
        group: String,
    },
    /// List stored groups.
    Groups,
    /// Message history for a group.
    GroupMessages {
        /// Group id (hex).
        group: String,
    },
    /// List stored contacts.
    Contacts,
    /// List safe, time-bounded carrier snapshots for all contacts.
    CarrierCapabilities,
    /// List transient render-safe call state retained by this installation.
    Calls,
    /// Return the honest current call-start verdict for one contact.
    CallAvailability {
        /// Exact contact peer id (hex).
        peer: String,
    },
    /// Start one capability-gated outgoing audio call.
    CallStart {
        /// Exact contact peer id (hex).
        peer: String,
    },
    /// Answer one ringing incoming call on this physical device.
    CallAnswer {
        /// Exact call id (hex).
        call: String,
    },
    /// Decline one ringing incoming call on this physical device.
    CallDecline {
        /// Exact call id (hex).
        call: String,
    },
    /// Cancel one locally initiated ringing call.
    CallCancel {
        /// Exact call id (hex).
        call: String,
    },
    /// End one connecting or active call.
    CallHangup {
        /// Exact call id (hex).
        call: String,
    },
    /// Queue one native-encoded Opus packet for authenticated transmission.
    CallAudioSend {
        /// Exact call id (hex).
        call: String,
        /// Sender capture timestamp in milliseconds.
        timestamp_ms: u64,
        /// Exact bounded Opus packet (hex).
        opus: String,
    },
    /// Take at most one authenticated Opus packet from the bounded jitter buffer.
    CallAudioTake {
        /// Exact call id (hex).
        call: String,
    },
    /// Message history with a peer.
    Messages {
        /// The peer id (hex).
        peer: String,
    },
    /// The safety number to verify out-of-band with a peer.
    SafetyNumber {
        /// The peer id (hex).
        peer: String,
    },
    /// Record that safety numbers were verified out-of-band.
    Verify {
        /// The peer id (hex).
        peer: String,
    },
    /// Replace a contact's delivery hints.
    SetHints {
        /// The peer id (hex).
        peer: String,
        /// The new hints.
        hints: Vec<Hint>,
    },
    /// Publish this node's prekey bundle on the DHT now (also done
    /// automatically at startup and after relay reservation).
    Publish,
    /// Export an encrypted backup file (identity + contacts + history +
    /// session-reset markers — docs/07-storage.md §4). The response carries
    /// the one-time 24-word mnemonic that seals the file: show it to the
    /// user once; the daemon does not keep it.
    Backup {
        /// Where to write the backup file (created 0600; an existing file
        /// is never overwritten).
        path: String,
    },
    /// Turn this connection into an event stream.
    Subscribe,
}

/// One structured semantic Mention range supplied by a local RPC caller.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MentionSpanInput {
    /// Inclusive UTF-8 byte offset.
    pub start: u32,
    /// Exclusive UTF-8 byte offset.
    pub end: u32,
    /// Exact target peer id (hex), never a display name.
    pub target: String,
}

/// An explicit typed local conversation target for label RPC operations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LabelTargetInput {
    /// Pairwise conversation with an exact peer identity.
    Peer {
        /// 64-hex-character peer id.
        id: String,
    },
    /// Sender-key group conversation with an exact group id.
    Group {
        /// 64-hex-character group id.
        id: String,
    },
    /// The reserved device-local note-to-self conversation.
    NoteToSelf,
}

/// An exact local custom-icon target, including folder identities.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustomIconTargetInput {
    /// Contact keyed by peer identity.
    Contact {
        /// 64-hex-character peer id.
        id: String,
    },
    /// Sender-key group keyed by group id.
    Group {
        /// 64-hex-character group id.
        id: String,
    },
    /// Private local folder keyed by its stable id.
    Folder {
        /// 32-hex-character folder id.
        id: String,
    },
    /// Reserved local note-to-self conversation.
    NoteToSelf {},
}

/// Optional exact square crop in oriented source pixels.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomIconCropInput {
    /// Left edge after orientation normalization.
    pub x: u32,
    /// Top edge after orientation normalization.
    pub y: u32,
    /// Non-zero crop width.
    pub width: u32,
    /// Non-zero crop height; must equal width.
    pub height: u32,
}

/// Label filter matching mode on the RPC surface.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelMatchInput {
    /// Match at least one selected label.
    Any,
    /// Match every selected label.
    All,
}

/// Strict mutable C6 role input; ownership uses its dedicated operation.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRoleInput {
    /// Grant bounded administration capability.
    Admin,
    /// Revoke administration capability.
    Member,
}

impl From<GroupRoleInput> for GroupRole {
    fn from(value: GroupRoleInput) -> Self {
        match value {
            GroupRoleInput::Admin => GroupRole::Admin,
            GroupRoleInput::Member => GroupRole::Member,
        }
    }
}

/// Explicit virtual or stable-folder navigation selection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FolderSelectionInput {
    /// Every available conversation.
    All,
    /// Available conversations with no active assignment.
    Unfiled,
    /// One exact stable folder id.
    Folder {
        /// 32-hex-character folder id.
        id: String,
    },
}

/// A delivery hint on the wire.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hint {
    /// A libp2p multiaddr (with `/p2p/…`).
    Multiaddr(String),
    /// A mailbox relay's multiaddr: deposit sealed envelopes there.
    Relay(String),
    /// A sneakernet spool directory.
    Spool(String),
    /// A Meshtastic node number; `u32::MAX` floods the whole mesh (the
    /// normal mode — recipients recognize their delivery tokens).
    Mesh(u32),
}

impl Hint {
    /// Convert to the transport-layer hint.
    pub fn to_delivery(&self) -> DeliveryHint {
        match self {
            Self::Multiaddr(a) => DeliveryHint::Multiaddr(a.clone()),
            Self::Relay(a) => DeliveryHint::Relay(a.clone()),
            Self::Spool(p) => DeliveryHint::Spool(p.into()),
            Self::Mesh(n) => DeliveryHint::MeshNode(*n),
        }
    }
}

/// A successful response line.
pub fn ok(id: u64, value: Value) -> String {
    json!({ "id": id, "ok": value }).to_string()
}

/// A failed response line. Errors are honest and human-readable; nothing is
/// downgraded to a fake success (docs/09-implementation-guide.md rule 4).
pub fn err(id: u64, message: &str) -> String {
    json!({
        "id": id,
        "err": message,
        "error": {
            "code": error_code(message),
            "message": message,
        },
    })
    .to_string()
}

/// An event line for subscribed connections.
pub fn event_line(event: &Event) -> String {
    let body = match event {
        Event::DevicesChanged => json!({
            "type": "devices_changed",
        }),
        Event::DeviceLinkCompleted { account, device } => json!({
            "type": "device_link_completed",
            "account": hex_encode(account),
            "device": hex_encode(device),
        }),
        Event::CustomIconsChanged => json!({
            "type": "custom_icons_changed",
        }),
        Event::ThemeChanged => json!({
            "type": "theme_changed",
        }),
        Event::FoldersChanged => json!({
            "type": "folders_changed",
        }),
        Event::LabelsChanged => json!({
            "type": "labels_changed",
        }),
        Event::PinsChanged => json!({
            "type": "pins_changed",
        }),
        Event::ScheduledMessageUpdated { id } => json!({
            "type": "scheduled_updated",
            "id": hex_encode(id),
        }),
        Event::ScheduledMessageCancelled { id } => json!({
            "type": "scheduled_cancelled",
            "id": hex_encode(id),
        }),
        Event::ScheduledMessageActivated { id } => json!({
            "type": "scheduled_activated",
            "id": hex_encode(id),
        }),
        Event::DeliveryUpdated { id, state } => json!({
            "type": "delivery",
            "id": hex_encode(id),
            "state": state_str(*state),
        }),
        Event::MessageReceived {
            peer,
            id,
            timestamp,
            body,
            content,
        } => json!({
            "type": "message",
            "peer": hex_encode(peer),
            "id": hex_encode(id),
            "timestamp": timestamp,
            "body": render_event_body(body, content),
            "content_kind": content_kind(content),
            "expires_at": content_expiry(content),
            "mention_spans": mention_status_json(content),
        }),
        Event::MessageEdited {
            peer,
            target_content_id,
        } => json!({
            "type": "message_edited",
            "peer": hex_encode(peer),
            "target_content_id": hex_encode(target_content_id),
        }),
        Event::NoteToSelfMessageAdded {
            id,
            timestamp,
            body,
        } => json!({
            "type": "note_to_self_message",
            "conversation": NOTE_TO_SELF_CONVERSATION_ID,
            "id": hex_encode(id),
            "timestamp": timestamp,
            "body": body,
        }),
        Event::ContactAdded { peer } => json!({
            "type": "contact_added",
            "peer": hex_encode(peer),
        }),
        Event::ContactRenamed { peer, name } => json!({
            "type": "contact_renamed",
            "peer": hex_encode(peer),
            "name": name,
        }),
        Event::SessionEstablished { peer } => json!({
            "type": "session_established",
            "peer": hex_encode(peer),
        }),
        Event::AwaitingFasterLink { id } => json!({
            "type": "awaiting_faster_link",
            "id": hex_encode(id),
        }),
        Event::CarrierCapabilityChanged { snapshot } => json!({
            "type": "carrier_capability",
            "snapshot": carrier_json(snapshot),
        }),
        Event::CallUpdated { call } => json!({
            "type": "call_updated",
            "call": call_json(call),
        }),
        Event::GroupUpdated { group } => json!({
            "type": "group_updated",
            "group": hex_encode(group),
        }),
        Event::GroupMessageReceived {
            group,
            sender,
            id,
            timestamp,
            body,
            content,
        } => json!({
            "type": "group_message",
            "group": hex_encode(group),
            "sender": hex_encode(sender),
            "id": hex_encode(id),
            "timestamp": timestamp,
            "body": render_event_body(body, content),
            "content_kind": content_kind(content),
            "expires_at": content_expiry(content),
            "mention_spans": mention_status_json(content),
        }),
        Event::GroupMessageEdited {
            group,
            sender,
            target_content_id,
        } => json!({
            "type": "group_message_edited",
            "group": hex_encode(group),
            "sender": hex_encode(sender),
            "target_content_id": hex_encode(target_content_id),
        }),
        Event::PollUpdated {
            group,
            poll_author,
            poll_id,
        } => json!({
            "type": "poll_updated",
            "group": hex_encode(group),
            "poll_author": hex_encode(poll_author),
            "poll_id": hex_encode(poll_id),
        }),
        Event::GroupAuthorityUpdated {
            group,
            generation,
            owner,
        } => json!({
            "type": "group_authority_updated",
            "group": hex_encode(group),
            "generation": generation,
            "owner": hex_encode(owner),
        }),
        Event::GroupAdminRequestResolved {
            group,
            request_id,
            accepted,
            generation,
            state_id,
            reason,
        } => json!({
            "type": "group_admin_request_resolved",
            "group": hex_encode(group),
            "request_id": hex_encode(request_id),
            "accepted": accepted,
            "generation": generation,
            "state_id": state_id.map(|id| hex_encode(&id)),
            "reason": reason,
        }),
        Event::EphemeralRemoved {
            conversation,
            author,
            content_id,
            reason,
        } => json!({
            "type": "ephemeral_removed",
            "conversation": match conversation {
                kult_store::EphemeralConversation::Pairwise(peer) => {
                    json!({ "type": "pairwise", "id": hex_encode(peer) })
                }
                kult_store::EphemeralConversation::Group(group) => {
                    json!({ "type": "group", "id": hex_encode(group) })
                }
            },
            "author": hex_encode(author),
            "content_id": hex_encode(content_id),
            "reason": match reason {
                kult_store::EphemeralState::Consumed => "consumed",
                kult_store::EphemeralState::Expired => "expired",
                kult_store::EphemeralState::Active => "active",
            },
        }),
        Event::MentionReceived { id } => json!({
            "type": "mention_received",
            "id": hex_encode(id),
        }),
        Event::GroupDeliveryUpdated { id, peer, state } => json!({
            "type": "group_delivery",
            "id": hex_encode(id),
            "peer": hex_encode(peer),
            "state": state_str(*state),
        }),
        Event::AttachmentUpdated { attachment } => json!({
            "type": "attachment_updated",
            "attachment": attachment_json(attachment),
        }),
        _ => json!({ "type": "unknown" }),
    };
    json!({ "event": body }).to_string()
}

/// Render the bounded text model using stable snake-case tokens.
pub fn formatted_text_json(formatted: &kult_node::FormattedText) -> Value {
    json!({
        "source": formatted.source,
        "plain_text": formatted.plain_text,
        "blocks": formatted.blocks.iter().map(|block| json!({
            "kind": match block.kind {
                TextFormatBlockKind::Paragraph => "paragraph",
                TextFormatBlockKind::Quote => "quote",
                TextFormatBlockKind::UnorderedListItem => "unordered_list_item",
                TextFormatBlockKind::OrderedListItem => "ordered_list_item",
                TextFormatBlockKind::CodeBlock => "code_block",
            },
            "depth": block.depth,
            "ordinal": block.ordinal,
            "runs": block.runs.iter().map(|run| json!({
                "text": run.text,
                "styles": run.styles.iter().map(|style| match style {
                    TextFormatStyle::Emphasis => "emphasis",
                    TextFormatStyle::Strong => "strong",
                    TextFormatStyle::InlineCode => "inline_code",
                    TextFormatStyle::Highlight => "highlight",
                }).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "used_fallback": formatted.used_fallback,
    })
}

/// Render one contact-name review result without exposing sealed contact data.
pub fn contact_name_assessment_json(assessment: &ContactNameAssessment) -> Value {
    json!({
        "normalized_name": assessment.normalized_name,
        "changed_by_normalization": assessment.changed_by_normalization,
        "warnings": assessment.warnings.iter().map(|warning| match warning {
            ContactNameWarning::DuplicateName => "duplicate_name",
            ContactNameWarning::ConfusableName => "confusable_name",
            ContactNameWarning::BidirectionalControl => "bidirectional_control",
            ContactNameWarning::InvisibleCharacter => "invisible_character",
        }).collect::<Vec<_>>(),
        "duplicate_count": assessment.duplicate_count,
    })
}

/// Parse one exact canonical B12 theme token.
pub fn parse_theme(value: &str) -> Result<kult_node::ThemePreference, String> {
    kult_node::ThemePreference::parse(value)
        .ok_or_else(|| "preference must be one of: system, light, dark".to_owned())
}

/// Parse one exact icon target without display-name inference.
pub fn parse_custom_icon_target(
    target: &CustomIconTargetInput,
) -> Result<CustomIconTarget, String> {
    match target {
        CustomIconTargetInput::Contact { id } => Ok(CustomIconTarget::Contact(parse_peer(id)?)),
        CustomIconTargetInput::Group { id } => Ok(CustomIconTarget::Group(parse_group(id)?)),
        CustomIconTargetInput::Folder { id } => Ok(CustomIconTarget::Folder(parse_folder(id)?)),
        CustomIconTargetInput::NoteToSelf {} => Ok(CustomIconTarget::NoteToSelf),
    }
}

/// Render one canonical icon, including its local PNG bytes as lowercase hex.
pub fn custom_icon_json(icon: &CustomIconInfo) -> Value {
    json!({
        "target": custom_icon_target_json(&icon.target),
        "media_type": icon.media_type,
        "bytes": hex_encode(&icon.bytes),
        "width": icon.width,
        "height": icon.height,
    })
}

/// Render current sealed icon quota use.
pub fn custom_icon_usage_json(usage: CustomIconUsage) -> Value {
    json!({
        "records": usage.records,
        "bytes": usage.bytes,
    })
}

/// Render one exact typed local icon target.
pub fn custom_icon_target_json(target: &CustomIconTarget) -> Value {
    match target {
        CustomIconTarget::Contact(id) => json!({ "type": "contact", "id": hex_encode(id) }),
        CustomIconTarget::Group(id) => json!({ "type": "group", "id": hex_encode(id) }),
        CustomIconTarget::Folder(id) => json!({ "type": "folder", "id": hex_encode(id) }),
        CustomIconTarget::NoteToSelf => json!({ "type": "note_to_self" }),
    }
}

/// Parse one canonical shipped-platform token.
pub fn parse_screen_security_platform(value: &str) -> Result<ScreenSecurityPlatform, String> {
    match value {
        "android" => Ok(ScreenSecurityPlatform::Android),
        "ios" => Ok(ScreenSecurityPlatform::Ios),
        "desktop" => Ok(ScreenSecurityPlatform::Desktop),
        _ => Err("screen-security platform must be android, ios, or desktop".to_owned()),
    }
}

/// Render the shared B14 policy using stable snake-case capability levels.
pub fn screen_security_policy_json(policy: &ScreenSecurityPolicy) -> Value {
    json!({
        "platform": policy.platform.as_str(),
        "always_on": policy.always_on,
        "capture_prevention": policy.capture_prevention.as_str(),
        "background_obscuring": policy.background_obscuring.as_str(),
        "capture_detection": policy.capture_detection.as_str(),
        "rapid_lock": policy.rapid_lock.as_str(),
        "mechanism": policy.mechanism,
        "limitations": policy.limitations,
    })
}

/// Parse one canonical shipped-platform token for input privacy.
pub fn parse_incognito_keyboard_platform(value: &str) -> Result<IncognitoKeyboardPlatform, String> {
    match value {
        "android" => Ok(IncognitoKeyboardPlatform::Android),
        "ios" => Ok(IncognitoKeyboardPlatform::Ios),
        "desktop" => Ok(IncognitoKeyboardPlatform::Desktop),
        _ => Err("incognito-keyboard platform must be android, ios, or desktop".to_owned()),
    }
}

/// Render the shared B15 policy using stable snake-case capability levels.
pub fn incognito_keyboard_policy_json(policy: &IncognitoKeyboardPolicy) -> Value {
    json!({
        "platform": policy.platform.as_str(),
        "always_on": policy.always_on,
        "applies_before_unlock": policy.applies_before_unlock,
        "personalized_learning": policy.personalized_learning.as_str(),
        "suggestions": policy.suggestions.as_str(),
        "spellcheck": policy.spellcheck.as_str(),
        "secret_text_masking": policy.secret_text_masking.as_str(),
        "protected_fields": policy.protected_fields,
        "mechanism": policy.mechanism,
        "limitations": policy.limitations,
    })
}

/// Render one folder without sealed bytes, nonces, or unrelated metadata.
pub fn folder_json(folder: &FolderInfo) -> Value {
    json!({
        "id": hex_encode(&folder.id),
        "name": folder.name,
        "order": folder.order,
    })
}

/// Render one exact available typed folder member and current local name.
pub fn folder_conversation_json(conversation: &FolderConversationInfo) -> Value {
    let mut value = conversation_id_json(&conversation.conversation);
    if let Some(name) = &conversation.display_name {
        value["name"] = json!(name);
    }
    value
}

/// Render one stale folder assignment without storage internals.
pub fn stale_folder_json(stale: &StaleFolderInfo) -> Value {
    json!({
        "folder": hex_encode(&stale.folder),
        "target": conversation_id_json(&stale.conversation),
        "reason": match stale.reason {
            NodeStaleFolderReason::MissingFolder => "missing_folder",
            NodeStaleFolderReason::UnavailableConversation => "unavailable_conversation",
            NodeStaleFolderReason::MissingFolderAndConversation => "missing_folder_and_conversation",
        },
    })
}

/// Render folder-first classification and independent label-filter state.
pub fn folder_conversation_list_json(list: &FolderConversationList) -> Value {
    json!({
        "selection": folder_selection_json(list.selection),
        "selected_labels": list.selected_labels.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "unavailable_labels": list.unavailable_labels.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "conversations": list.conversations.iter().map(folder_conversation_json).collect::<Vec<_>>(),
    })
}

/// Render one exact folder selection without display-name inference.
pub fn folder_selection_json(selection: FolderSelection) -> Value {
    match selection {
        FolderSelection::All => json!({ "type": "all" }),
        FolderSelection::Unfiled => json!({ "type": "unfiled" }),
        FolderSelection::Folder(folder) => {
            json!({ "type": "folder", "id": hex_encode(&folder) })
        }
    }
}

/// Render one durable pin without sealed storage material.
pub fn pin_json(pin: &PinInfo) -> Value {
    let mut value = json!({
        "target": conversation_id_json(&pin.conversation),
        "order": pin.order,
        "active": pin.active,
    });
    if let Some(name) = &pin.display_name {
        value["name"] = json!(name);
    }
    value
}

/// Render one eligible pin-aware conversation row.
pub fn pin_conversation_json(conversation: &PinConversationInfo) -> Value {
    let mut value = json!({
        "target": conversation_id_json(&conversation.conversation),
        "pinned": conversation.pinned,
        "pin_order": conversation.pin_order,
        "recent_activity": conversation.recent_activity,
    });
    if let Some(name) = &conversation.display_name {
        value["name"] = json!(name);
    }
    value
}

/// Render folder/label selection plus one pin-aware ordered conversation list.
pub fn pin_conversation_list_json(list: &PinConversationList) -> Value {
    json!({
        "selection": folder_selection_json(list.selection),
        "selected_labels": list.selected_labels.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "unavailable_labels": list.unavailable_labels.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "conversations": list.conversations.iter().map(pin_conversation_json).collect::<Vec<_>>(),
    })
}

/// Render one label without sealed bytes, nonces, or unrelated metadata.
pub fn label_json(label: &LabelInfo) -> Value {
    json!({
        "id": hex_encode(&label.id),
        "name": label.name,
        "color": label.color,
        "order": label.order,
    })
}

/// Render one exact available typed target and its current local name.
pub fn label_conversation_json(conversation: &LabelConversationInfo) -> Value {
    let mut value = conversation_id_json(&conversation.conversation);
    if let Some(name) = &conversation.display_name {
        value["name"] = json!(name);
    }
    value
}

/// Render one stale membership diagnostic without storage internals.
pub fn stale_label_json(stale: &StaleLabelInfo) -> Value {
    json!({
        "label": hex_encode(&stale.label),
        "target": conversation_id_json(&stale.conversation),
        "reason": match stale.reason {
            NodeStaleLabelReason::MissingLabel => "missing_label",
            NodeStaleLabelReason::UnavailableConversation => "unavailable_conversation",
            NodeStaleLabelReason::MissingLabelAndConversation => "missing_label_and_conversation",
        },
    })
}

/// Render deterministic local filter output.
pub fn label_filter_json(filter: &LabelFilterInfo) -> Value {
    json!({
        "selected": filter.selected.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "unavailable_selected": filter.unavailable_selected.iter().map(|id| hex_encode(id)).collect::<Vec<_>>(),
        "conversations": filter.conversations.iter().map(label_conversation_json).collect::<Vec<_>>(),
    })
}

/// Parse one exact typed label target without display-name inference.
pub fn parse_label_target(target: &LabelTargetInput) -> Result<ConversationId, String> {
    match target {
        LabelTargetInput::Peer { id } => Ok(ConversationId::Peer(parse_peer(id)?)),
        LabelTargetInput::Group { id } => Ok(ConversationId::Group(parse_group(id)?)),
        LabelTargetInput::NoteToSelf => Ok(ConversationId::NoteToSelf),
    }
}

/// Parse one unambiguous 16-byte label id.
pub fn parse_label(value: &str) -> Result<[u8; 16], String> {
    hex_decode(value)
        .ok_or_else(|| "label id must be 32 hexadecimal characters".to_owned())?
        .try_into()
        .map_err(|_| "label id must be 32 hexadecimal characters".to_owned())
}

/// Parse one unambiguous 16-byte folder id.
pub fn parse_folder(value: &str) -> Result<[u8; 16], String> {
    hex_decode(value)
        .ok_or_else(|| "folder id must be 32 hexadecimal characters".to_owned())?
        .try_into()
        .map_err(|_| "folder id must be 32 hexadecimal characters".to_owned())
}

/// Parse and bound the complete folder reorder list before storage work.
pub fn parse_folder_order(values: &[String]) -> Result<Vec<[u8; 16]>, String> {
    if values.len() > MAX_FOLDERS {
        return Err("folder reorder count exceeds 128".to_owned());
    }
    values.iter().map(|value| parse_folder(value)).collect()
}

/// Parse an explicit virtual or stable-folder navigation selection.
pub fn parse_folder_selection(selection: &FolderSelectionInput) -> Result<FolderSelection, String> {
    match selection {
        FolderSelectionInput::All => Ok(FolderSelection::All),
        FolderSelectionInput::Unfiled => Ok(FolderSelection::Unfiled),
        FolderSelectionInput::Folder { id } => Ok(FolderSelection::Folder(parse_folder(id)?)),
    }
}

/// Parse and bound selected ids before avoidable allocation or storage work.
pub fn parse_selected_labels(values: &[String]) -> Result<Vec<[u8; 16]>, String> {
    if values.len() > MAX_LABELS {
        return Err("selected label count exceeds 128".to_owned());
    }
    values.iter().map(|value| parse_label(value)).collect()
}

/// Parse and bound the explicit complete pin reorder target list.
pub fn parse_pin_order(values: &[LabelTargetInput]) -> Result<Vec<ConversationId>, String> {
    if values.len() > MAX_PINS {
        return Err("pin reorder count exceeds 8192".to_owned());
    }
    values.iter().map(parse_label_target).collect()
}

/// Enforce the shared name/color contract at the RPC boundary.
pub fn validate_label_write(name: &str, color: &str) -> Result<(), String> {
    if !valid_label_name(name) {
        return Err("invalid label name".to_owned());
    }
    if !valid_label_color(color) {
        return Err("unsupported label color".to_owned());
    }
    Ok(())
}

/// Enforce the shared exact-name contract at the RPC boundary.
pub fn validate_folder_write(name: &str) -> Result<(), String> {
    if valid_folder_name(name) {
        Ok(())
    } else {
        Err("invalid folder name".to_owned())
    }
}

fn conversation_id_json(conversation: &ConversationId) -> Value {
    match conversation {
        ConversationId::Peer(peer) => json!({ "type": "peer", "id": hex_encode(peer) }),
        ConversationId::Group(group) => json!({ "type": "group", "id": hex_encode(group) }),
        ConversationId::NoteToSelf => json!({ "type": "note_to_self" }),
    }
}

/// Render one exact typed target without a display name.
pub fn label_target_json(conversation: &ConversationId) -> Value {
    conversation_id_json(conversation)
}

fn error_code(message: &str) -> &'static str {
    match message {
        "invalid folder name" | "store error: invalid folder name" => "invalid_folder_name",
        "folder id must be 32 hexadecimal characters" => "invalid_folder_id",
        "store error: folder id does not exist" => "unknown_folder",
        "store error: folder definition limit exhausted" => "folder_limit",
        "store error: folder assignment limit exhausted" => "folder_assignment_limit",
        "store error: folder id collision budget exhausted" => "folder_id_collision",
        "store error: invalid complete folder order" => "invalid_folder_order",
        "store error: folder assignment is active or absent" => "stale_folder_assignment_active",
        "folder deletion requires explicit confirmation" => "confirmation_required",
        "folder reorder count exceeds 128" => "folder_reorder_limit",
        "invalid label name" | "store error: invalid label name" => "invalid_label_name",
        "unsupported label color" | "store error: unsupported label color" => "invalid_label_color",
        "label id must be 32 hexadecimal characters" => "invalid_label_id",
        "store error: label id does not exist" => "unknown_label",
        "peer must be hex"
        | "peer must be 32 bytes"
        | "group must be hex"
        | "group must be 32 bytes" => "invalid_target_id",
        "store error: typed conversation target is unavailable" => "unavailable_target",
        "store error: label definition limit exhausted" => "label_limit",
        "store error: label assignment limit exhausted" => "label_assignment_limit",
        "store error: conversation label limit exhausted" => "conversation_label_limit",
        "store error: label id collision budget exhausted" => "label_id_collision",
        "store error: label assignment is active or absent" => "stale_assignment_active",
        "label deletion requires explicit confirmation" => "confirmation_required",
        "selected label count exceeds 128" => "selected_label_limit",
        "pin reorder count exceeds 8192" => "pin_reorder_limit",
        "store error: conversation pin limit exhausted" => "pin_limit",
        "store error: invalid complete pin order" => "invalid_pin_order",
        "store error: conversation pin is active or absent" => "stale_pin_active",
        "call id must be hex" | "call id must be 16 bytes" => "invalid_call_id",
        "invalid call control, route, expiry, or transition" => "invalid_call",
        "call does not exist on this installation" => "unknown_call",
        "peer does not support live calls" => "call_unsupported",
        "no fresh direct QUIC route is available" => "call_unavailable",
        "this installation is already in a call" => "call_busy",
        _ if message.starts_with("bad request:") => "bad_request",
        _ if message.starts_with("store error:") => "storage_failure",
        _ => "operation_failed",
    }
}

/// One render-safe attachment transfer as JSON. No manifest key, object id,
/// hash, chunk address, bitmap, missing range, or transport address crosses
/// the local RPC boundary.
pub fn attachment_json(attachment: &AttachmentInfo) -> Value {
    json!({
        "transfer_id": hex_encode(&attachment.transfer_id),
        "peer": hex_encode(&attachment.peer),
        "conversation": match attachment.conversation {
            AttachmentConversation::Pairwise => "pairwise",
            AttachmentConversation::Group => "group",
        },
        "group": attachment.group.map(|group| hex_encode(&group)),
        "direction": match attachment.direction {
            AttachmentDirection::Inbound => "in",
            AttachmentDirection::Outbound => "out",
        },
        "author": hex_encode(&attachment.author),
        "content_id": hex_encode(&attachment.content_id),
        "state": attachment_state_str(attachment.state),
        "view_once": attachment.view_once,
        "expires_at": attachment.expires_at,
        "consumed": attachment.consumed,
        "objects": attachment.objects.iter().map(|object| json!({
            "preview": object.preview,
            "total_bytes": object.total_bytes,
            "verified_bytes": object.verified_bytes,
            "media_type": object.media_type,
            "filename": object.filename,
            "presentation": attachment_file_presentation_json(&object.presentation),
            "state": attachment_state_str(object.state),
        })).collect::<Vec<_>>(),
    })
}

/// Stable snake-case JSON for the shared C1 file-presentation policy.
pub fn attachment_file_presentation_json(presentation: &AttachmentFilePresentation) -> Value {
    json!({
        "kind": match presentation.kind {
            AttachmentFileKind::Image => "image",
            AttachmentFileKind::Audio => "audio",
            AttachmentFileKind::Video => "video",
            AttachmentFileKind::Document => "document",
            AttachmentFileKind::Archive => "archive",
            AttachmentFileKind::Executable => "executable",
            AttachmentFileKind::Other => "other",
        },
        "open_policy": match presentation.open_policy {
            AttachmentOpenPolicy::ProtectedMedia => "protected_media",
            AttachmentOpenPolicy::ExternalOpen => "external_open",
            AttachmentOpenPolicy::ExportOnly => "export_only",
        },
        "warnings": presentation.warnings.iter().map(|warning| match warning {
            AttachmentFileWarning::MediaTypeMismatch => "media_type_mismatch",
            AttachmentFileWarning::DangerousType => "dangerous_type",
            AttachmentFileWarning::UnrecognizedType => "unrecognized_type",
            AttachmentFileWarning::MissingFilename => "missing_filename",
        }).collect::<Vec<_>>(),
    })
}

fn attachment_state_str(state: MediaTransferState) -> &'static str {
    match state {
        MediaTransferState::Offered => "offered",
        MediaTransferState::AwaitingConsent => "awaiting_consent",
        MediaTransferState::Queued => "queued",
        MediaTransferState::Transferring => "transferring",
        MediaTransferState::Paused => "paused",
        MediaTransferState::Complete => "complete",
        MediaTransferState::Rejected => "rejected",
        MediaTransferState::Cancelled => "cancelled",
        MediaTransferState::Corrupt => "corrupt",
        MediaTransferState::Unavailable => "unavailable",
    }
}

/// A group record as JSON, excluding every secret and chain value.
pub fn group_json(group: &GroupInfo) -> Value {
    json!({
        "id": hex_encode(&group.id),
        "name": group.name,
        "creator": hex_encode(&group.creator),
        "members": group.members.iter().map(|peer| hex_encode(peer)).collect::<Vec<_>>(),
    })
}

/// Current group authority without identities, secrets, signatures, or chains.
pub fn group_authority_json(authority: &GroupAuthorityInfo) -> Value {
    json!({
        "group": hex_encode(&authority.group),
        "signed": authority.signed,
        "original_owner": hex_encode(&authority.original_owner),
        "owner": hex_encode(&authority.owner),
        "owner_epoch": authority.owner_epoch,
        "generation": authority.generation,
        "my_role": authority.my_role.map(group_role_str),
        "members": authority.members.iter().map(|member| json!({
            "peer": hex_encode(&member.peer),
            "role": group_role_str(member.role),
        })).collect::<Vec<_>>(),
    })
}

fn group_role_str(role: GroupRole) -> &'static str {
    match role {
        GroupRole::Owner => "owner",
        GroupRole::Admin => "admin",
        GroupRole::Member => "member",
    }
}

/// The current conservative semantic Mention capability verdict.
pub fn group_mention_capability_json(capability: &GroupMentionCapability) -> Value {
    json!({
        "group": hex_encode(&capability.group),
        "supported": capability.supported(),
        "review_token": hex_encode(&capability.review_token),
        "issues": capability.issues.iter().map(|issue| json!({
            "peer": hex_encode(&issue.peer),
            "reason": match issue.reason {
                MentionCapabilityIssueReason::Unknown => "unknown",
                MentionCapabilityIssueReason::Unsupported => "unsupported",
            },
        })).collect::<Vec<_>>(),
    })
}

/// One render-safe derived poll, including visible voter identities and heads.
pub fn poll_json(poll: &PollInfo) -> Value {
    json!({
        "group": hex_encode(&poll.group),
        "author": hex_encode(&poll.author),
        "id": hex_encode(&poll.id),
        "generation": poll.generation,
        "question": poll.question,
        "eligible_voters": poll.eligible_voters.iter().map(|peer| hex_encode(peer)).collect::<Vec<_>>(),
        "options": poll.options.iter().map(|option| json!({
            "id": hex_encode(&option.id),
            "text": option.text,
            "votes": option.votes,
            "selected_by_me": option.selected_by_me,
        })).collect::<Vec<_>>(),
        "votes": poll.votes.iter().map(|vote| json!({
            "voter": hex_encode(&vote.voter),
            "event_id": hex_encode(&vote.event_id),
            "option_id": hex_encode(&vote.option_id),
            "revision": vote.revision,
        })).collect::<Vec<_>>(),
        "closed": poll.closed,
        "close_event_id": poll.close_event_id.map(|id| hex_encode(&id)),
        "moderated_by": poll.moderated_by.map(|peer| hex_encode(&peer)),
        "eligible": poll.eligible,
        "can_close": poll.can_close,
        "votes_visible": true,
        "anonymous": false,
        "close_policy": if poll.moderated_by.is_some() {
            "signed_owner_snapshot"
        } else {
            "manual_creator_snapshot"
        },
    })
}

/// One render-safe, time-bounded carrier snapshot as JSON.
pub fn carrier_json(snapshot: &CarrierCapabilitySnapshot) -> Value {
    json!({
        "peer": hex_encode(&snapshot.peer),
        "capability": carrier_str(snapshot.capability),
        "observed_at": snapshot.observed_at,
        "expires_at": snapshot.expires_at,
    })
}

/// One render-safe transient call snapshot as JSON.
pub fn call_json(call: &CallInfo) -> Value {
    json!({
        "id": hex_encode(&call.id),
        "peer": hex_encode(&call.peer),
        "direction": match call.direction {
            CallDirection::Outgoing => "outgoing",
            CallDirection::Incoming => "incoming",
        },
        "phase": match call.phase {
            CallPhase::Ringing => "ringing",
            CallPhase::Connecting => "connecting",
            CallPhase::Active => "active",
            CallPhase::Ended => "ended",
        },
        "initiator_device": hex_encode(&call.initiator_device),
        "responder_device": call.responder_device.map(|device| hex_encode(&device)),
        "expires_at": call.expires_at,
        "end_reason": call.end_reason.map(|reason| match reason {
            CallEndReason::Declined => "declined",
            CallEndReason::Busy => "busy",
            CallEndReason::Cancelled => "cancelled",
            CallEndReason::HungUp => "hung_up",
            CallEndReason::Expired => "expired",
            CallEndReason::AnsweredElsewhere => "answered_elsewhere",
            CallEndReason::RouteLost => "route_lost",
        }),
    })
}

/// One honest contact call-start verdict as JSON.
pub fn call_availability_json(availability: &CallAvailability) -> Value {
    json!({
        "peer": hex_encode(&availability.peer),
        "available": availability.available(),
        "unavailable": availability.unavailable.map(|reason| match reason {
            CallUnavailableReason::OfflineOrUnknown => "offline_or_unknown",
            CallUnavailableReason::BulkOnly => "bulk_only",
            CallUnavailableReason::MeshOnly => "mesh_only",
            CallUnavailableReason::MissingSession => "missing_session",
            CallUnavailableReason::Unsupported => "unsupported",
            CallUnavailableReason::AlreadyInCall => "already_in_call",
        }),
    })
}

/// One authenticated decoded Opus packet as JSON. The frame owns and erases
/// its packet bytes immediately after this short-lived serialization copy.
pub fn call_audio_json(frame: &CallAudioFrame) -> Value {
    json!({
        "call": hex_encode(&frame.call_id),
        "sequence": frame.sequence,
        "timestamp_ms": frame.timestamp_ms,
        "opus": hex_encode(&frame.opus_packet),
    })
}

fn carrier_str(capability: CarrierCapability) -> &'static str {
    match capability {
        CarrierCapability::Realtime => "realtime",
        CarrierCapability::Bulk => "bulk",
        CarrierCapability::MeshOnly => "mesh_only",
        CarrierCapability::OfflineOrUnknown => "offline_or_unknown",
    }
}

/// A group message record as JSON, including honest per-member delivery.
pub fn group_message_json(message: &ResolvedGroupMessage) -> Value {
    let rec = &message.record;
    let (body, content_kind, expires_at, mention_spans) = render_stored_content(&rec.body, true);
    json!({
        "id": hex_encode(&rec.id),
        "group": hex_encode(&rec.group),
        "sender": hex_encode(&rec.sender),
        "direction": match rec.direction {
            Direction::Inbound => "in",
            Direction::Outbound => "out",
        },
        "timestamp": rec.timestamp,
        "body": body,
        "content_kind": content_kind,
        "expires_at": expires_at,
        "mention_spans": mention_spans,
        "edited": message.edited,
        "edit_revision": message.winning_revision,
        "versions": edit_versions_json(&message.versions),
        "deliveries": rec.deliveries.iter().map(|delivery| json!({
            "peer": hex_encode(&delivery.peer),
            "state": state_str(delivery.state),
        })).collect::<Vec<_>>(),
    })
}

/// A message record as JSON.
pub fn message_json(message: &ResolvedMessage) -> Value {
    let rec = &message.record;
    let (body, content_kind, expires_at, mention_spans) = render_stored_content(&rec.body, false);
    json!({
        "id": hex_encode(&rec.id),
        "peer": hex_encode(&rec.peer),
        "direction": match rec.direction {
            Direction::Inbound => "in",
            Direction::Outbound => "out",
        },
        "state": state_str(rec.state),
        "timestamp": rec.timestamp,
        "body": body,
        "content_kind": content_kind,
        "expires_at": expires_at,
        "mention_spans": mention_spans,
        "edited": message.edited,
        "edit_revision": message.winning_revision,
        "versions": edit_versions_json(&message.versions),
    })
}

fn edit_versions_json(versions: &[kult_node::EditVersionInfo]) -> Value {
    Value::Array(
        versions
            .iter()
            .map(|version| {
                json!({
                    "id": hex_encode(&version.id),
                    "revision": version.revision,
                    "timestamp": version.timestamp,
                    "body": version.body,
                })
            })
            .collect(),
    )
}

/// One note-to-self record as render-safe JSON.
pub fn note_message_json(rec: &NoteMessageRecord) -> Value {
    json!({
        "id": hex_encode(&rec.id),
        "conversation": NOTE_TO_SELF_CONVERSATION_ID,
        "timestamp": rec.timestamp,
        "body": rec.body,
    })
}

/// One scheduled outbox record as render-safe JSON.
pub fn scheduled_message_json(message: &ScheduledMessageInfo) -> Value {
    let (conversation, destination) = match message.conversation {
        ScheduledConversation::Peer(peer) => ("peer", hex_encode(&peer)),
        ScheduledConversation::Group(group) => ("group", hex_encode(&group)),
    };
    json!({
        "id": hex_encode(&message.id),
        "conversation": conversation,
        "destination": destination,
        "created_at": message.created_at,
        "not_before": message.not_before,
        "body": String::from_utf8_lossy(&message.body),
        "state": "scheduled",
    })
}

const UNSUPPORTED_MESSAGE: &str = "Unsupported message — update Komms";

fn content_kind(status: &ContentStatus) -> &'static str {
    match status {
        ContentStatus::LegacyText => "legacy_text",
        ContentStatus::Text { .. } => "text",
        ContentStatus::Attachment { .. } => "attachment",
        ContentStatus::Mention { .. } => "mention",
        ContentStatus::DisappearingText { .. } => "disappearing_text",
        ContentStatus::ViewOnceAttachment { .. } => "view_once_attachment",
        ContentStatus::Unsupported { .. } => "unsupported",
        ContentStatus::Malformed => "malformed",
        _ => "unsupported",
    }
}

fn content_expiry(status: &ContentStatus) -> Option<u64> {
    match status {
        ContentStatus::DisappearingText { expires_at, .. }
        | ContentStatus::ViewOnceAttachment { expires_at, .. } => Some(*expires_at),
        _ => None,
    }
}

fn render_event_body(body: &[u8], status: &ContentStatus) -> String {
    match status {
        ContentStatus::LegacyText
        | ContentStatus::Text { .. }
        | ContentStatus::Mention { .. }
        | ContentStatus::DisappearingText { .. } => {
            String::from_utf8(body.to_vec()).expect("node exposes only validated UTF-8 text")
        }
        ContentStatus::Attachment { .. } | ContentStatus::ViewOnceAttachment { .. } => {
            String::new()
        }
        ContentStatus::Unsupported { .. } | ContentStatus::Malformed => {
            UNSUPPORTED_MESSAGE.to_owned()
        }
        _ => UNSUPPORTED_MESSAGE.to_owned(),
    }
}

fn mention_status_json(status: &ContentStatus) -> Value {
    match status {
        ContentStatus::Mention { spans, .. } => mention_spans_json(spans),
        _ => json!([]),
    }
}

fn mention_spans_json(spans: &[kult_node::MentionSpan]) -> Value {
    Value::Array(
        spans
            .iter()
            .map(|span| {
                json!({
                    "start": span.start,
                    "end": span.end,
                    "target": hex_encode(&span.target),
                })
            })
            .collect(),
    )
}

fn render_stored_content(
    bytes: &[u8],
    allow_group_mention: bool,
) -> (String, &'static str, Option<u64>, Value) {
    match kult_protocol::decode_content(bytes) {
        kult_protocol::DecodedContent::LegacyText(text) => {
            (text.to_owned(), "legacy_text", None, json!([]))
        }
        kult_protocol::DecodedContent::Text { text, .. } => {
            (text.to_owned(), "text", None, json!([]))
        }
        kult_protocol::DecodedContent::Attachment { .. } => {
            (String::new(), "attachment", None, json!([]))
        }
        kult_protocol::DecodedContent::Mention { mention, .. } if allow_group_mention => {
            let spans = mention
                .spans()
                .map(kult_node::MentionSpan::from)
                .collect::<Vec<_>>();
            (
                mention.text.to_owned(),
                "mention",
                None,
                mention_spans_json(&spans),
            )
        }
        kult_protocol::DecodedContent::Mention { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", None, json!([]))
        }
        kult_protocol::DecodedContent::Edit { .. } => (String::new(), "malformed", None, json!([])),
        kult_protocol::DecodedContent::Ephemeral { ephemeral, .. } => match ephemeral {
            kult_protocol::Ephemeral::DisappearingText {
                text, expires_at, ..
            } => (
                text.to_owned(),
                "disappearing_text",
                Some(expires_at),
                json!([]),
            ),
            kult_protocol::Ephemeral::ViewOnceAttachment { expires_at, .. } => (
                String::new(),
                "view_once_attachment",
                Some(expires_at),
                json!([]),
            ),
        },
        kult_protocol::DecodedContent::Poll { .. } if allow_group_mention => {
            (String::new(), "poll", None, json!([]))
        }
        kult_protocol::DecodedContent::Poll { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", None, json!([]))
        }
        kult_protocol::DecodedContent::GroupAuthority { .. } if allow_group_mention => {
            (String::new(), "group_authority", None, json!([]))
        }
        kult_protocol::DecodedContent::GroupAuthority { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", None, json!([]))
        }
        kult_protocol::DecodedContent::CallControl { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", None, json!([]))
        }
        kult_protocol::DecodedContent::Unsupported { .. } => (
            UNSUPPORTED_MESSAGE.to_owned(),
            "unsupported",
            None,
            json!([]),
        ),
        kult_protocol::DecodedContent::Malformed => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", None, json!([]))
        }
    }
}

fn state_str(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Queued => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Received => "received",
    }
}

/// Lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    out
}

/// Hex decoding (case-insensitive). `None` on odd length or non-hex input.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let digits: Vec<u32> = s.chars().map(|c| c.to_digit(16)).collect::<Option<_>>()?;
    Some(
        digits
            .chunks(2)
            .map(|pair| ((pair[0] << 4) | pair[1]) as u8)
            .collect(),
    )
}

/// Decode a 32-byte hex peer id.
pub fn parse_peer(s: &str) -> Result<[u8; 32], String> {
    hex_decode(s)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| "peer must be 64 hex chars".to_owned())
}

/// Decode a 32-byte hex group id.
pub fn parse_group(s: &str) -> Result<[u8; 32], String> {
    hex_decode(s)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| "group must be 64 hex chars".to_owned())
}

/// Parse a 16-byte message id from lowercase/uppercase hex.
pub fn parse_message(s: &str) -> Result<[u8; 16], String> {
    hex_decode(s)
        .ok_or_else(|| "message id must be hex".to_owned())?
        .try_into()
        .map_err(|_| "message id must be 16 bytes".to_owned())
}

/// Parse a 16-byte transient call id from lowercase/uppercase hex.
pub fn parse_call(s: &str) -> Result<[u8; 16], String> {
    hex_decode(s)
        .ok_or_else(|| "call id must be hex".to_owned())?
        .try_into()
        .map_err(|_| "call id must be 16 bytes".to_owned())
}

/// Parse a 16-byte local Mention review token.
pub fn parse_review_token(s: &str) -> Result<[u8; 16], String> {
    hex_decode(s)
        .ok_or_else(|| "review token must be hex".to_owned())?
        .try_into()
        .map_err(|_| "review token must be 16 bytes".to_owned())
}

/// Parse a 16-byte local attachment transfer id.
pub fn parse_transfer(s: &str) -> Result<[u8; 16], String> {
    hex_decode(s)
        .ok_or_else(|| "transfer id must be hex".to_owned())?
        .try_into()
        .map_err(|_| "transfer id must be 16 bytes".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let data = [0x00, 0x0f, 0xf0, 0xff, 0x5a];
        let s = hex_encode(&data);
        assert_eq!(s, "000ff0ff5a");
        assert_eq!(hex_decode(&s).unwrap(), data);
        assert_eq!(hex_decode("0F").unwrap(), vec![0x0f]);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn contact_name_ops_are_strict_and_peer_targeted() {
        let peer = "ab".repeat(32);
        let assessment = parse_request(
            &json!({
                "id": 1,
                "op": "contact_name_assessment",
                "peer": peer,
                "name": "Cafe\u{301}",
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(assessment.op, Op::ContactNameAssessment { .. }));
        let rename = parse_request(
            &json!({
                "id": 2,
                "op": "rename_contact",
                "peer": "cd".repeat(32),
                "name": "same name",
                "accept_warnings": true,
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(
            rename.op,
            Op::RenameContact {
                accept_warnings: true,
                ..
            }
        ));
        assert!(parse_request(
            &json!({
                "id": 3,
                "op": "rename_contact",
                "peer": "cd".repeat(32),
                "name": "x",
                "remote_suggestion": "Mallory",
            })
            .to_string(),
        )
        .is_err());
    }

    #[test]
    fn poll_ops_reject_ambiguous_or_trailing_fields() {
        let request = parse_request(
            &json!({
                "id": 4,
                "op": "group_poll_vote",
                "group": "01".repeat(32),
                "poll_author": "02".repeat(32),
                "poll_id": "03".repeat(16),
                "option_id": "04".repeat(16),
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(request.op, Op::GroupPollVote { .. }));
        assert!(parse_request(
            &json!({
                "id": 5,
                "op": "group_polls",
                "group": "01".repeat(32),
                "unexpected": true,
            })
            .to_string(),
        )
        .is_err());
        assert!(parse_request(r#"{"id":6,"op":"group_polls","group":"00"} trailing"#).is_err());
    }

    #[test]
    fn text_formatting_rpc_is_strict_and_render_safe() {
        let request = parse_request(
            r#"{"id":9,"op":"format_text","source":"**safe** <img src=x>","highlights":[]}"#,
        )
        .unwrap();
        assert!(matches!(request.op, Op::FormatText { .. }));
        assert!(parse_request(
            r#"{"id":9,"op":"format_text","source":"safe","highlights":[],"html":true}"#
        )
        .is_err());
        assert!(parse_request(
            r#"{"id":9,"op":"format_text","source":"safe","highlights":[{"start":0,"end":1,"target":"peer"}]}"#
        )
        .is_err());

        let formatted = kult_node::format_text("**safe** <img src=x>", &[]).unwrap();
        assert_eq!(
            formatted_text_json(&formatted),
            json!({
                "source": "**safe** <img src=x>",
                "plain_text": "safe <img src=x>",
                "blocks": [{
                    "kind": "paragraph",
                    "depth": 0,
                    "ordinal": 0,
                    "runs": [
                        {"text": "safe", "styles": ["strong"]},
                        {"text": " <img src=x>", "styles": []},
                    ],
                }],
                "used_fallback": false,
            })
        );
    }

    #[test]
    fn file_presentation_rpc_is_strict_and_fail_closed() {
        let request = parse_request(
            r#"{"id":10,"op":"attachment_file_presentation","media_type":"application/pdf","filename":"invoice.pdf.exe"}"#,
        )
        .unwrap();
        assert!(matches!(request.op, Op::AttachmentFilePresentation { .. }));
        assert!(parse_request(
            r#"{"id":10,"op":"attachment_file_presentation","media_type":"application/pdf","filename":"report.pdf","scan":true}"#,
        )
        .is_err());

        let presentation =
            kult_node::classify_attachment_file("application/pdf", Some("invoice.pdf.exe"));
        assert_eq!(
            attachment_file_presentation_json(&presentation),
            json!({
                "kind": "executable",
                "open_policy": "export_only",
                "warnings": ["media_type_mismatch", "dangerous_type"],
            })
        );
    }

    #[test]
    fn edit_rpcs_require_exact_author_target_and_fields() {
        let peer = "11".repeat(32);
        let content = "22".repeat(16);
        let pairwise = parse_request(
            &json!({
                "id": 20,
                "op": "edit_message",
                "peer": peer,
                "target_author": peer,
                "target_content_id": content,
                "text": "replacement",
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(pairwise.op, Op::EditMessage { .. }));
        let group = parse_request(
            &json!({
                "id": 21,
                "op": "group_edit_message",
                "group": "33".repeat(32),
                "target_author": peer,
                "target_content_id": content,
                "text": "replacement",
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(group.op, Op::GroupEditMessage { .. }));
        assert!(parse_request(
            &json!({
                "id": 22,
                "op": "edit_message",
                "peer": peer,
                "target_author": peer,
                "target_content_id": content,
                "text": "replacement",
                "display_name": "not authority",
            })
            .to_string(),
        )
        .is_err());
    }

    #[test]
    fn linked_device_rpcs_are_explicit_bounded_and_strict() {
        let device = "11".repeat(32);
        let response = "22".repeat(64);
        let approve = parse_request(
            &json!({
                "id": 30,
                "op": "device_link_approve",
                "response": response,
                "selection": {
                    "contacts": true,
                    "organization": false,
                    "history": true,
                },
                "confirmed": true,
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(approve.op, Op::DeviceLinkApprove { .. }));
        assert!(parse_request(
            &json!({
                "id": 31,
                "op": "device_link_approve",
                "response": "00",
                "selection": {
                    "contacts": true,
                    "organization": true,
                    "history": true,
                    "drafts": true,
                },
                "confirmed": true,
            })
            .to_string(),
        )
        .is_err());
        assert!(parse_request(
            &json!({
                "id": 32,
                "op": "device_revoke",
                "device": device,
                "name": "ambiguous",
            })
            .to_string(),
        )
        .is_err());
        assert!(matches!(
            parse_request(r#"{"id":33,"op":"linked_devices"}"#)
                .unwrap()
                .op,
            Op::LinkedDevices
        ));
    }

    #[test]
    fn requests_parse() {
        let r: Request = serde_json::from_str(r#"{"id":1,"op":"status"}"#).unwrap();
        assert!(matches!(r.op, Op::Status));
        let r: Request = serde_json::from_str(
            r#"{"id":2,"op":"add_contact","name":"bob","bundle":"aa","hints":[{"multiaddr":"/ip4/1.2.3.4/tcp/1"}]}"#,
        )
        .unwrap();
        assert!(matches!(r.op, Op::AddContact { .. }));
        let r: Request = serde_json::from_str(r#"{"id":3,"op":"carrier_capabilities"}"#).unwrap();
        assert!(matches!(r.op, Op::CarrierCapabilities));
        let call = "ab".repeat(16);
        let r = parse_request(
            &json!({
                "id": 34,
                "op": "call_audio_send",
                "call": call,
                "timestamp_ms": 42,
                "opus": "f801",
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(
            r.op,
            Op::CallAudioSend {
                timestamp_ms: 42,
                ..
            }
        ));
        assert!(parse_request(
            &json!({
                "id": 35,
                "op": "call_answer",
                "call": "ab".repeat(16),
                "peer": "ambiguous",
            })
            .to_string(),
        )
        .is_err());
        let r: Request =
            serde_json::from_str(r#"{"id":4,"op":"note_to_self_send","body":"remember this"}"#)
                .unwrap();
        assert!(matches!(r.op, Op::NoteToSelfSend { .. }));
        let r = parse_request(r#"{"id":40,"op":"theme_set","preference":"dark"}"#).unwrap();
        assert!(matches!(r.op, Op::ThemeSet { preference } if preference == "dark"));
        let r =
            parse_request(r#"{"id":39,"op":"screen_security_policy","platform":"ios"}"#).unwrap();
        assert!(matches!(r.op, Op::ScreenSecurityPolicy { platform } if platform == "ios"));
        assert!(parse_request(
            r#"{"id":38,"op":"screen_security_policy","platform":"desktop","extra":true}"#,
        )
        .is_err());
        assert!(parse_screen_security_platform("android").is_ok());
        assert!(parse_screen_security_platform("web").is_err());
        let r = parse_request(r#"{"id":37,"op":"incognito_keyboard_policy","platform":"android"}"#)
            .unwrap();
        assert!(matches!(r.op, Op::IncognitoKeyboardPolicy { platform } if platform == "android"));
        assert!(parse_request(
            r#"{"id":36,"op":"incognito_keyboard_policy","platform":"ios","extra":true}"#,
        )
        .is_err());
        assert!(parse_incognito_keyboard_platform("desktop").is_ok());
        assert!(parse_incognito_keyboard_platform("web").is_err());
        assert!(parse_request(r#"{"id":41,"op":"theme","extra":true}"#).is_err());
        assert!(parse_theme("system").is_ok());
        assert!(parse_theme("sepia").is_err());
        let r = parse_request(
            &json!({
                "id": 42,
                "op": "custom_icon_set_path",
                "target": { "type": "folder", "id": "ab".repeat(16) },
                "path": "/tmp/local.png",
                "crop": { "x": 2, "y": 3, "width": 10, "height": 10 },
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(r.op, Op::CustomIconSetPath { .. }));
        assert!(parse_request(
            &json!({
                "id": 43,
                "op": "custom_icon",
                "target": { "type": "note_to_self", "id": "ambiguous" },
            })
            .to_string(),
        )
        .is_err());
        assert!(parse_request(r#"{"id":44,"op":"custom_icon_usage","extra":true}"#).is_err());
        assert_eq!(
            parse_custom_icon_target(&CustomIconTargetInput::Contact {
                id: "01".repeat(32),
            })
            .unwrap(),
            CustomIconTarget::Contact([1; 32])
        );
        let icon_event: Value =
            serde_json::from_str(&event_line(&Event::CustomIconsChanged)).unwrap();
        assert_eq!(icon_event["event"]["type"], "custom_icons_changed");

        let r = parse_request(
            &json!({
                "id": 5,
                "op": "label_assign",
                "label": "ab".repeat(16),
                "target": { "type": "group", "id": "cd".repeat(32) },
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(r.op, Op::LabelAssign { .. }));
        assert!(parse_request(
            &json!({
                "id": 6,
                "op": "label_assign",
                "label": "ab".repeat(16),
                "target": { "type": "group", "id": "cd".repeat(32), "name": "ambiguous" },
            })
            .to_string(),
        )
        .is_err());
        assert!(parse_request(
            r#"{"id":7,"op":"label_create","name":"private","color":"red","extra":true}"#
        )
        .is_err());
        let r = parse_request(
            &json!({
                "id": 8,
                "op": "folder_move",
                "folder": "ef".repeat(16),
                "target": { "type": "peer", "id": "01".repeat(32) },
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(r.op, Op::FolderMove { .. }));
        assert!(parse_request(
            &json!({
                "id": 9,
                "op": "folder_move",
                "folder": "ef".repeat(16),
                "target": { "type": "peer", "id": "01".repeat(32), "name": "ambiguous" },
            })
            .to_string(),
        )
        .is_err());
        assert!(
            parse_request(r#"{"id":10,"op":"folder_create","name":"friends","extra":true}"#)
                .is_err()
        );
        assert!(parse_request(r#"{"id":11,"op":"folders"} {"id":12,"op":"folders"}"#).is_err());
    }

    #[test]
    fn label_errors_are_stable_and_structured() {
        let value: Value =
            serde_json::from_str(&err(4, "store error: conversation label limit exhausted"))
                .unwrap();
        assert_eq!(value["id"], json!(4));
        assert_eq!(value["error"]["code"], json!("conversation_label_limit"));
        assert_eq!(
            value["err"],
            json!("store error: conversation label limit exhausted")
        );
        assert!(value.to_string().find("label name").is_none());
    }

    #[test]
    fn folder_errors_are_stable_and_structured() {
        let value: Value =
            serde_json::from_str(&err(5, "store error: invalid complete folder order")).unwrap();
        assert_eq!(value["id"], json!(5));
        assert_eq!(value["error"]["code"], json!("invalid_folder_order"));
        assert_eq!(
            value["err"],
            json!("store error: invalid complete folder order")
        );
        assert!(value.to_string().find("folder name").is_none());
    }

    #[test]
    fn carrier_event_is_explicit_and_time_bounded() {
        let line = event_line(&Event::CarrierCapabilityChanged {
            snapshot: CarrierCapabilitySnapshot {
                peer: [0x12; 32],
                capability: CarrierCapability::MeshOnly,
                observed_at: 10,
                expires_at: 70,
            },
        });
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["event"]["type"], json!("carrier_capability"));
        assert_eq!(value["event"]["snapshot"]["capability"], json!("mesh_only"));
        assert_eq!(value["event"]["snapshot"]["expires_at"], json!(70));
    }

    #[test]
    fn call_event_is_render_safe_and_exact() {
        let line = event_line(&Event::CallUpdated {
            call: CallInfo {
                id: [0x21; 16],
                peer: [0x22; 32],
                direction: CallDirection::Incoming,
                phase: CallPhase::Ended,
                initiator_device: [0x23; 32],
                responder_device: Some([0x24; 32]),
                expires_at: 90,
                end_reason: Some(CallEndReason::AnsweredElsewhere),
            },
        });
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["event"]["type"], json!("call_updated"));
        assert_eq!(value["event"]["call"]["direction"], json!("incoming"));
        assert_eq!(
            value["event"]["call"]["end_reason"],
            json!("answered_elsewhere")
        );
        assert!(value.to_string().find("secret").is_none());
        assert!(value.to_string().find("route").is_none());
    }

    #[test]
    fn attachment_foundation_never_exposes_manifest_metadata() {
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
        let (body, kind, expires_at, mention_spans) = render_stored_content(&frame, false);
        assert!(body.is_empty());
        assert_eq!(kind, "attachment");
        assert_eq!(expires_at, None);
        assert_eq!(mention_spans, json!([]));
        assert!(!body.contains("private.png"));
    }
}
