//! The local RPC wire format: newline-delimited JSON over a Unix socket.
//!
//! One request object per line, one response object per line, correlated by
//! `id`. A connection that sent `subscribe` additionally receives event
//! objects (`{"event": …}`) as they happen. Binary values (peer ids, message
//! ids, prekey bundles) travel as lowercase hex — the socket is local and
//! trusted, so readability beats compactness.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kult_node::{Event, GroupInfo};
use kult_store::{DeliveryState, Direction, GroupMessageRecord, MessageRecord};
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
        } => json!({
            "type": "message",
            "peer": hex_encode(peer),
            "id": hex_encode(id),
            "timestamp": timestamp,
            "body": String::from_utf8_lossy(body),
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
        } => json!({
            "type": "group_message",
            "group": hex_encode(group),
            "sender": hex_encode(sender),
            "id": hex_encode(id),
            "timestamp": timestamp,
            "body": String::from_utf8_lossy(body),
        }),
        Event::GroupDeliveryUpdated { id, peer, state } => json!({
            "type": "group_delivery",
            "id": hex_encode(id),
            "peer": hex_encode(peer),
            "state": state_str(*state),
        }),
        _ => json!({ "type": "unknown" }),
    };
    json!({ "event": body }).to_string()
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

/// A group message record as JSON, including honest per-member delivery.
pub fn group_message_json(rec: &GroupMessageRecord) -> Value {
    json!({
        "id": hex_encode(&rec.id),
        "group": hex_encode(&rec.group),
        "sender": hex_encode(&rec.sender),
        "direction": match rec.direction {
            Direction::Inbound => "in",
            Direction::Outbound => "out",
        },
        "timestamp": rec.timestamp,
        "body": String::from_utf8_lossy(&rec.body),
        "deliveries": rec.deliveries.iter().map(|delivery| json!({
            "peer": hex_encode(&delivery.peer),
            "state": state_str(delivery.state),
        })).collect::<Vec<_>>(),
    })
}

/// A message record as JSON.
pub fn message_json(rec: &MessageRecord) -> Value {
    json!({
        "id": hex_encode(&rec.id),
        "peer": hex_encode(&rec.peer),
        "direction": match rec.direction {
            Direction::Inbound => "in",
            Direction::Outbound => "out",
        },
        "state": state_str(rec.state),
        "timestamp": rec.timestamp,
        "body": String::from_utf8_lossy(&rec.body),
    })
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
    }
}
