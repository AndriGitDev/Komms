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
    AttachmentConversation, AttachmentDirection, AttachmentInfo, CarrierCapability,
    CarrierCapabilitySnapshot, ContentStatus, Event, GroupInfo, GroupMentionCapability,
    MentionCapabilityIssueReason, ScheduledConversation, ScheduledMessageInfo,
    NOTE_TO_SELF_CONVERSATION_ID,
};
use kult_store::{
    DeliveryState, Direction, GroupMessageRecord, MediaTransferState, MessageRecord,
    NoteMessageRecord,
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
    /// Queue a message.
    Send {
        /// Recipient peer id (hex).
        peer: String,
        /// Message body (UTF-8 text).
        body: String,
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
    json!({ "id": id, "err": message }).to_string()
}

/// An event line for subscribed connections.
pub fn event_line(event: &Event) -> String {
    let body = match event {
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
            "mention_spans": mention_status_json(content),
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
            "mention_spans": mention_status_json(content),
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
        "objects": attachment.objects.iter().map(|object| json!({
            "preview": object.preview,
            "total_bytes": object.total_bytes,
            "verified_bytes": object.verified_bytes,
            "media_type": object.media_type,
            "filename": object.filename,
            "state": attachment_state_str(object.state),
        })).collect::<Vec<_>>(),
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

/// One render-safe, time-bounded carrier snapshot as JSON.
pub fn carrier_json(snapshot: &CarrierCapabilitySnapshot) -> Value {
    json!({
        "peer": hex_encode(&snapshot.peer),
        "capability": carrier_str(snapshot.capability),
        "observed_at": snapshot.observed_at,
        "expires_at": snapshot.expires_at,
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
pub fn group_message_json(rec: &GroupMessageRecord) -> Value {
    let (body, content_kind, mention_spans) = render_stored_content(&rec.body, true);
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
        "mention_spans": mention_spans,
        "deliveries": rec.deliveries.iter().map(|delivery| json!({
            "peer": hex_encode(&delivery.peer),
            "state": state_str(delivery.state),
        })).collect::<Vec<_>>(),
    })
}

/// A message record as JSON.
pub fn message_json(rec: &MessageRecord) -> Value {
    let (body, content_kind, mention_spans) = render_stored_content(&rec.body, false);
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
        "mention_spans": mention_spans,
    })
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
        ContentStatus::Unsupported { .. } => "unsupported",
        ContentStatus::Malformed => "malformed",
        _ => "unsupported",
    }
}

fn render_event_body(body: &[u8], status: &ContentStatus) -> String {
    match status {
        ContentStatus::LegacyText | ContentStatus::Text { .. } | ContentStatus::Mention { .. } => {
            String::from_utf8(body.to_vec()).expect("node exposes only validated UTF-8 text")
        }
        ContentStatus::Attachment { .. } => String::new(),
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

fn render_stored_content(bytes: &[u8], allow_group_mention: bool) -> (String, &'static str, Value) {
    match kult_protocol::decode_content(bytes) {
        kult_protocol::DecodedContent::LegacyText(text) => {
            (text.to_owned(), "legacy_text", json!([]))
        }
        kult_protocol::DecodedContent::Text { text, .. } => (text.to_owned(), "text", json!([])),
        kult_protocol::DecodedContent::Attachment { .. } => {
            (String::new(), "attachment", json!([]))
        }
        kult_protocol::DecodedContent::Mention { mention, .. } if allow_group_mention => {
            let spans = mention
                .spans()
                .map(kult_node::MentionSpan::from)
                .collect::<Vec<_>>();
            (
                mention.text.to_owned(),
                "mention",
                mention_spans_json(&spans),
            )
        }
        kult_protocol::DecodedContent::Mention { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", json!([]))
        }
        kult_protocol::DecodedContent::Unsupported { .. } => {
            (UNSUPPORTED_MESSAGE.to_owned(), "unsupported", json!([]))
        }
        kult_protocol::DecodedContent::Malformed => {
            (UNSUPPORTED_MESSAGE.to_owned(), "malformed", json!([]))
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
        let r: Request =
            serde_json::from_str(r#"{"id":4,"op":"note_to_self_send","body":"remember this"}"#)
                .unwrap();
        assert!(matches!(r.op, Op::NoteToSelfSend { .. }));
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
        let (body, kind, mention_spans) = render_stored_content(&frame, false);
        assert!(body.is_empty());
        assert_eq!(kind, "attachment");
        assert_eq!(mention_spans, json!([]));
        assert!(!body.contains("private.png"));
    }
}
