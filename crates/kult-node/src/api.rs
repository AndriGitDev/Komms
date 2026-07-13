//! The node's command/event surface (docs/09-implementation-guide.md §3.5).
//! `kult-ffi` exposes exactly this shape — nothing more.

use kult_store::DeliveryState;
use kult_transport::DeliveryHint;

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

/// Render-safe classification of authenticated message content (ADR-0014).
///
/// Text bytes are carried separately by the event. Unsupported and malformed
/// content never exposes its raw authenticated bytes to application surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentStatus {
    /// Valid UTF-8 from the permanent pre-frame compatibility path.
    LegacyText,
    /// Canonical framed text with its author-minted content id.
    Text {
        /// Content id scoped to the conversation and author.
        id: [u8; 16],
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
}
