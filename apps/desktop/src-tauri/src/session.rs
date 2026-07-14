//! The desktop shell's view of a running node: a thin, testable layer over
//! `kult-ffi`'s [`KultNode`] that speaks the webview's language (serde JSON
//! view-models, string errors) and nothing else.
//!
//! Everything the UI can do goes through [`Session`] — the Tauri commands
//! in [`crate::commands`] are one-line wrappers. That keeps the whole
//! behavior testable without a webview: the integration test drives two
//! [`Session`]s through exactly these methods.
//!
//! The shell adds **no** protocol logic. Honesty rules from the core carry
//! through verbatim: delivery states come from the node (`delivered` means
//! an end-to-end encrypted receipt), errors are the node's own words, and
//! the backup mnemonic is returned exactly once and never stored.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use kult_ffi::{
    default_config, CarrierCapability, Config, ContentKind, DeliveryState, Direction, Event,
    EventListener, Hint, KdfChoice, KultNode, NatVerdict,
};

use crate::qr;

/// Network configuration the user can edit on the unlock screen. Persisted
/// as plain JSON next to the store — it holds the same information as
/// `kultd`'s command-line flags and **no secrets** (the store passphrase
/// and everything inside the store never touch this file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// Multiaddrs to listen on. The default binds QUIC + TCP on
    /// OS-assigned ports; pin a port here for port-forwarding setups.
    pub listen: Vec<String>,
    /// DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
    /// discovery then never leaves this node (mDNS still works).
    pub bootstrap: Vec<String>,
    /// Relay to reserve a circuit at when NAT-ed (defaults to the first
    /// bootstrap peer when unset).
    pub relay: Option<String>,
    /// Mailbox relays to check in with.
    pub mailboxes: Vec<String>,
    /// Volunteer bounded mailbox service for others.
    pub serve_mailbox: bool,
    /// Announce/discover on the local network (zero-config LAN delivery).
    pub mdns: bool,
    /// Also receive from a sneakernet spool directory.
    pub spool: Option<String>,
    /// Attach a Meshtastic radio on this USB-serial port (needs a build
    /// with the `meshtastic` feature).
    pub meshtastic_serial: Option<String>,
    /// Attach a Meshtastic radio via its network API (`host:4403`).
    pub meshtastic_tcp: Option<String>,
    /// Bridge third-party sealed traffic between mesh and internet
    /// (ADR-0009); active only while a radio is attached.
    pub bridge: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
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
        }
    }
}

impl NetworkSettings {
    /// The settings file inside a data directory.
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("settings.json")
    }

    /// Load from `data_dir`, falling back to defaults when absent. A
    /// present-but-corrupt file is an error — silently reverting a user's
    /// network configuration would be a lie.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        match std::fs::read(Self::path(data_dir)) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("settings.json is corrupt: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("settings.json: {e}")),
        }
    }

    /// Persist to `data_dir` (creating it if needed).
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("data dir: {e}"))?;
        let json = serde_json::to_vec_pretty(self).expect("settings serialize");
        std::fs::write(Self::path(data_dir), json).map_err(|e| format!("settings.json: {e}"))
    }
}

/// A contact row for the UI.
#[derive(Clone, Debug, Serialize)]
pub struct UiContact {
    /// The contact's peer id (hex).
    pub peer: String,
    /// Local display name.
    pub name: String,
    /// Whether safety numbers were verified out-of-band.
    pub verified: bool,
}

/// A message row for the UI. `state` is one of `queued`, `sent`,
/// `delivered`, `received` — never anything the node didn't report.
#[derive(Clone, Debug, Serialize)]
pub struct UiMessage {
    /// Message record id (hex).
    pub id: String,
    /// The conversation peer (hex).
    pub peer: String,
    /// Sent by this device (vs. received).
    pub outbound: bool,
    /// Delivery state, verbatim from the node.
    pub state: &'static str,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub body: String,
    /// `legacy_text`, `text`, `unsupported`, or `malformed`.
    pub content_kind: &'static str,
}

/// One sealed, local-only note-to-self entry. It intentionally has no
/// transport direction or delivery state because it never leaves the node.
#[derive(Clone, Debug, Serialize)]
pub struct UiNoteMessage {
    /// Message record id (hex).
    pub id: String,
    /// Stable reserved conversation identity shared by every shell.
    pub conversation: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Note text.
    pub body: String,
}

/// A sender-key group row for the desktop UI. Secret material and sender
/// chains never cross into the shell.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroup {
    /// Group id (hex).
    pub id: String,
    /// Creator-controlled display name.
    pub name: String,
    /// Managing member's peer id (hex).
    pub creator: String,
    /// Full roster, this node included (hex peer ids).
    pub members: Vec<String>,
}

/// One member's honest delivery state for an outbound group message.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroupDelivery {
    /// Recipient peer id (hex).
    pub peer: String,
    /// `queued`, `sent`, or `delivered`, verbatim from the node.
    pub state: &'static str,
}

/// A group message row for the desktop conversation view.
#[derive(Clone, Debug, Serialize)]
pub struct UiGroupMessage {
    /// Group message record id (hex).
    pub id: String,
    /// Group id (hex).
    pub group: String,
    /// Sending member's peer id (hex).
    pub sender: String,
    /// Sent by this device (vs. received).
    pub outbound: bool,
    /// Unix seconds.
    pub timestamp: u64,
    /// Message text.
    pub body: String,
    /// `legacy_text`, `text`, `unsupported`, or `malformed`.
    pub content_kind: &'static str,
    /// Per-recipient states for outbound messages; empty for inbound.
    pub deliveries: Vec<UiGroupDelivery>,
}

/// A point-in-time node snapshot for the status bar.
#[derive(Clone, Debug, Serialize)]
pub struct UiStatus {
    /// This node's human-shareable kult address.
    pub address: String,
    /// This node's peer id (hex).
    pub peer: String,
    /// Live listen addresses (circuit addresses included once reserved).
    pub listen: Vec<String>,
    /// Peers currently visible on the LAN via mDNS.
    pub lan_peers: Vec<String>,
    /// `public`, `private`, or `unknown`.
    pub nat: &'static str,
    /// Outbound messages not yet delivered.
    pub queued: u64,
    /// Third-party envelopes buffered for mesh↔internet bridging.
    pub transit: u64,
    /// Stored contacts.
    pub contacts: u64,
}

/// The safety number screen's payload: digits to read aloud, and a QR of
/// the raw comparison value to scan.
#[derive(Clone, Debug, Serialize)]
pub struct UiSafetyNumber {
    /// 60 decimal digits.
    pub digits: String,
    /// The digits grouped 5-at-a-time for display.
    pub display: String,
    /// QR of the comparison value — identical on both ends.
    pub qr_svg: String,
}

/// An exported prekey bundle: hex to paste (interoperable with
/// `kult bundle` / `kult add`), QR carrying the same hex to scan.
#[derive(Clone, Debug, Serialize)]
pub struct UiBundle {
    /// The bundle bytes, lowercase hex.
    pub hex: String,
    /// QR carrying the same hex (uppercase, alphanumeric mode).
    pub qr_svg: String,
}

/// A delivery hint as the UI edits it: a `kind` tag plus one string value.
#[derive(Clone, Debug, Deserialize)]
pub struct UiHint {
    /// `multiaddr`, `relay`, `spool`, or `mesh`.
    pub kind: String,
    /// The multiaddr / path / mesh node number (`broadcast` floods).
    pub value: String,
}

impl UiHint {
    fn to_ffi(&self) -> Result<Hint, String> {
        let value = self.value.trim();
        if value.is_empty() {
            return Err("hint value must not be empty".to_owned());
        }
        Ok(match self.kind.as_str() {
            "multiaddr" => Hint::Multiaddr {
                addr: value.to_owned(),
            },
            "relay" => Hint::Relay {
                addr: value.to_owned(),
            },
            "spool" => Hint::Spool {
                path: value.to_owned(),
            },
            "mesh" => Hint::Mesh {
                node: if value.eq_ignore_ascii_case("broadcast") {
                    u32::MAX
                } else {
                    value.parse().map_err(|_| {
                        format!("mesh hint must be a node number or `broadcast`, got `{value}`")
                    })?
                },
            },
            other => return Err(format!("unknown hint kind `{other}`")),
        })
    }
}

/// A node event as the webview receives it (`type` tag plus fields).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UiEvent {
    /// A message record changed delivery state.
    DeliveryUpdated {
        /// Message record id (hex).
        id: String,
        /// The new state (`queued`/`sent`/`delivered`).
        state: &'static str,
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
        content_kind: &'static str,
    },
    /// A sealed local-only note was appended.
    NoteToSelfMessageAdded {
        /// Stable reserved conversation identity.
        conversation: String,
        /// Message record id (hex).
        id: String,
        /// Local creation time (Unix seconds).
        timestamp: u64,
        /// Note text.
        body: String,
    },
    /// An unknown peer completed a handshake; a contact stub exists now.
    ContactAdded {
        /// The new peer (hex).
        peer: String,
    },
    /// A ratchet session was (re-)established from an inbound handshake —
    /// for a known contact this means their key or device changed.
    SessionEstablished {
        /// The peer (hex).
        peer: String,
    },
    /// An outbound message is held: only duty-cycle-limited (LoRa)
    /// carriers currently reach the recipient.
    AwaitingFasterLink {
        /// Message record id (hex).
        id: String,
    },
    /// The authoritative time-bounded carrier verdict for a contact changed.
    CarrierCapabilityChanged {
        /// Contact peer id (hex).
        peer: String,
        /// `realtime`, `bulk`, `mesh_only`, or `offline_or_unknown`.
        capability: &'static str,
        /// Unix time at which transports were probed.
        observed_at: u64,
        /// Unix time at which the verdict stops being authoritative.
        expires_at: u64,
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
        content_kind: &'static str,
    },
    /// One member's copy of an outbound group message changed state.
    GroupDeliveryUpdated {
        /// Group message record id (hex).
        id: String,
        /// Member peer id (hex).
        peer: String,
        /// Delivery state for this member's copy.
        state: &'static str,
    },
}

impl UiEvent {
    fn from_ffi(event: Event) -> Self {
        match event {
            Event::DeliveryUpdated { id, state } => Self::DeliveryUpdated {
                id,
                state: state_str(state),
            },
            Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content_kind,
            } => Self::MessageReceived {
                peer,
                id,
                timestamp,
                body,
                content_kind: content_kind_str(content_kind),
            },
            Event::NoteToSelfMessageAdded {
                conversation,
                id,
                timestamp,
                body,
            } => Self::NoteToSelfMessageAdded {
                conversation,
                id,
                timestamp,
                body,
            },
            Event::ContactAdded { peer } => Self::ContactAdded { peer },
            Event::SessionEstablished { peer } => Self::SessionEstablished { peer },
            Event::AwaitingFasterLink { id } => Self::AwaitingFasterLink { id },
            Event::CarrierCapabilityChanged { snapshot } => Self::CarrierCapabilityChanged {
                peer: snapshot.peer,
                capability: carrier_capability_str(snapshot.capability),
                observed_at: snapshot.observed_at,
                expires_at: snapshot.expires_at,
            },
            Event::GroupUpdated { group } => Self::GroupUpdated { group },
            Event::GroupMessageReceived {
                group,
                sender,
                id,
                timestamp,
                body,
                content_kind,
            } => Self::GroupMessageReceived {
                group,
                sender,
                id,
                timestamp,
                body,
                content_kind: content_kind_str(content_kind),
            },
            Event::GroupDeliveryUpdated { id, peer, state } => Self::GroupDeliveryUpdated {
                id,
                peer,
                state: state_str(state),
            },
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

fn content_kind_str(kind: ContentKind) -> &'static str {
    match kind {
        ContentKind::LegacyText => "legacy_text",
        ContentKind::Text => "text",
        ContentKind::Unsupported => "unsupported",
        ContentKind::Malformed => "malformed",
    }
}

fn carrier_capability_str(capability: CarrierCapability) -> &'static str {
    match capability {
        CarrierCapability::Realtime => "realtime",
        CarrierCapability::Bulk => "bulk",
        CarrierCapability::MeshOnly => "mesh_only",
        CarrierCapability::OfflineOrUnknown => "offline_or_unknown",
    }
}

/// Where the shell delivers node events (the Tauri app emits them to the
/// webview; tests collect them in a `Vec`).
pub type EventSink = Box<dyn Fn(UiEvent) + Send + Sync>;

/// Adapter: `kult-ffi`'s listener trait onto an [`EventSink`].
struct Forwarder(EventSink);

impl EventListener for Forwarder {
    fn on_event(&self, event: Event) {
        (self.0)(UiEvent::from_ffi(event));
    }
}

/// A running node plus the shell-side conveniences the UI needs.
pub struct Session {
    node: Arc<KultNode>,
}

impl Session {
    /// Open (or create on first run) the store in `data_dir` and start the
    /// node. Blocking — call off the UI thread. `kdf` is the Argon2id cost
    /// profile for store *creation* (the app passes the desktop profile;
    /// tests pass the cheaper mobile one, exactly like the core's own).
    pub fn open(
        data_dir: &Path,
        passphrase: String,
        settings: &NetworkSettings,
        kdf: KdfChoice,
        sink: EventSink,
    ) -> Result<Self, String> {
        let config = build_config(data_dir, passphrase, settings, kdf);
        let node = KultNode::start(config, Box::new(Forwarder(sink))).map_err(|e| e.to_string())?;
        Ok(Self { node })
    }

    /// First run only: restore from an encrypted backup file instead of
    /// creating a fresh identity, then start.
    pub fn restore(
        data_dir: &Path,
        passphrase: String,
        backup_path: String,
        mnemonic: String,
        settings: &NetworkSettings,
        kdf: KdfChoice,
        sink: EventSink,
    ) -> Result<Self, String> {
        let config = build_config(data_dir, passphrase, settings, kdf);
        let node = KultNode::restore(config, backup_path, mnemonic, Box::new(Forwarder(sink)))
            .map_err(|e| e.to_string())?;
        Ok(Self { node })
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.node.address()
    }

    /// A QR of the kult address (for adding this node by address).
    pub fn address_qr(&self) -> Result<String, String> {
        qr::svg(self.node.address().as_bytes())
    }

    /// Status snapshot for the UI's transport indicators.
    pub fn status(&self) -> Result<UiStatus, String> {
        let s = self.node.status().map_err(|e| e.to_string())?;
        Ok(UiStatus {
            address: s.address,
            peer: s.peer,
            listen: s.listen,
            lan_peers: s.lan_peers,
            nat: match s.nat {
                NatVerdict::Public => "public",
                NatVerdict::Private => "private",
                NatVerdict::Unknown => "unknown",
            },
            queued: s.queued,
            transit: s.transit,
            contacts: s.contacts,
        })
    }

    /// Export a fresh prekey bundle as pasteable hex plus a QR carrying
    /// the same hex (uppercase, so the QR stays in its compact
    /// alphanumeric mode; decoding is case-insensitive everywhere).
    pub fn my_bundle(&self) -> Result<UiBundle, String> {
        let bytes = self.node.handshake_bundle().map_err(|e| e.to_string())?;
        let hex = hex_encode(&bytes);
        let qr_svg = qr::svg(hex.to_uppercase().as_bytes())?;
        Ok(UiBundle { hex, qr_svg })
    }

    /// Add a contact from pasted/scanned bundle hex, with delivery hints.
    /// Returns the new contact's peer id.
    pub fn add_contact(
        &self,
        name: String,
        bundle_hex: &str,
        hints: &[UiHint],
    ) -> Result<String, String> {
        let bundle = hex_decode(bundle_hex).ok_or("bundle must be hex")?;
        let hints = hints
            .iter()
            .map(UiHint::to_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        self.node
            .add_contact(name, bundle, hints)
            .map_err(|e| e.to_string())
    }

    /// Add a contact from their kult address alone (DHT lookup).
    pub fn add_contact_by_address(&self, name: String, address: String) -> Result<String, String> {
        self.node
            .add_contact_by_address(name, address)
            .map_err(|e| e.to_string())
    }

    /// All stored contacts.
    pub fn contacts(&self) -> Result<Vec<UiContact>, String> {
        Ok(self
            .node
            .contacts()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|c| UiContact {
                peer: c.peer,
                name: c.name,
                verified: c.verified,
            })
            .collect())
    }

    /// Message history with a peer.
    pub fn messages(&self, peer: String) -> Result<Vec<UiMessage>, String> {
        Ok(self
            .node
            .messages_with(peer)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|m| UiMessage {
                id: m.id,
                peer: m.peer,
                outbound: m.direction == Direction::Outbound,
                state: state_str(m.state),
                timestamp: m.timestamp,
                body: m.body,
                content_kind: content_kind_str(m.content_kind),
            })
            .collect())
    }

    /// Queue a message; returns its id (progress arrives as events).
    pub fn send(&self, peer: String, body: String) -> Result<String, String> {
        self.node.send(peer, body).map_err(|e| e.to_string())
    }

    /// Stable reserved identity for the local note-to-self conversation.
    pub fn note_to_self_id(&self) -> String {
        self.node.note_to_self_id()
    }

    /// All sealed local-only note-to-self entries.
    pub fn note_to_self_messages(&self) -> Result<Vec<UiNoteMessage>, String> {
        Ok(self
            .node
            .note_to_self_messages()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|message| UiNoteMessage {
                id: message.id,
                conversation: message.conversation,
                timestamp: message.timestamp,
                body: message.body,
            })
            .collect())
    }

    /// Append one sealed local-only note; no transport work is created.
    pub fn send_note_to_self(&self, body: String) -> Result<String, String> {
        self.node
            .send_note_to_self(body)
            .map_err(|e| e.to_string())
    }

    /// Create a sender-key group from stored contacts. Returns its id.
    pub fn create_group(&self, name: String, members: Vec<String>) -> Result<String, String> {
        self.node
            .create_group(name, members)
            .map_err(|e| e.to_string())
    }

    /// All locally stored groups, excluding every secret and chain value.
    pub fn groups(&self) -> Result<Vec<UiGroup>, String> {
        Ok(self
            .node
            .groups()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|group| UiGroup {
                id: group.id,
                name: group.name,
                creator: group.creator,
                members: group.members,
            })
            .collect())
    }

    /// Group history with honest per-recipient delivery states.
    pub fn group_messages(&self, group: String) -> Result<Vec<UiGroupMessage>, String> {
        Ok(self
            .node
            .group_messages(group)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|message| UiGroupMessage {
                id: message.id,
                group: message.group,
                sender: message.sender,
                outbound: message.direction == Direction::Outbound,
                timestamp: message.timestamp,
                body: message.body,
                content_kind: content_kind_str(message.content_kind),
                deliveries: message
                    .deliveries
                    .into_iter()
                    .map(|delivery| UiGroupDelivery {
                        peer: delivery.peer,
                        state: state_str(delivery.state),
                    })
                    .collect(),
            })
            .collect())
    }

    /// Queue one encrypted group message. Per-member progress arrives as
    /// `GroupDeliveryUpdated` events.
    pub fn send_group(&self, group: String, body: String) -> Result<String, String> {
        self.node.send_group(group, body).map_err(|e| e.to_string())
    }

    /// Add a stored contact to a group (creator only).
    pub fn add_group_member(&self, group: String, peer: String) -> Result<(), String> {
        self.node
            .add_group_member(group, peer)
            .map_err(|e| e.to_string())
    }

    /// Remove a member and rotate the group keys (creator only).
    pub fn remove_group_member(&self, group: String, peer: String) -> Result<(), String> {
        self.node
            .remove_group_member(group, peer)
            .map_err(|e| e.to_string())
    }

    /// Leave a group and drop its live local state; stored history remains.
    pub fn leave_group(&self, group: String) -> Result<(), String> {
        self.node.leave_group(group).map_err(|e| e.to_string())
    }

    /// The safety number with a peer, plus a QR of the raw comparison
    /// value (uppercase hex — both sides render the identical code).
    pub fn safety_number(&self, peer: String) -> Result<UiSafetyNumber, String> {
        let sn = self.node.safety_number(peer).map_err(|e| e.to_string())?;
        let qr_svg = qr::svg(hex_encode(&sn.qr).to_uppercase().as_bytes())?;
        Ok(UiSafetyNumber {
            digits: sn.digits,
            display: sn.display,
            qr_svg,
        })
    }

    /// Record an out-of-band verification.
    pub fn mark_verified(&self, peer: String) -> Result<(), String> {
        self.node.mark_verified(peer).map_err(|e| e.to_string())
    }

    /// Replace a contact's delivery hints.
    pub fn set_hints(&self, peer: String, hints: &[UiHint]) -> Result<(), String> {
        let hints = hints
            .iter()
            .map(UiHint::to_ffi)
            .collect::<Result<Vec<_>, _>>()?;
        self.node.set_hints(peer, hints).map_err(|e| e.to_string())
    }

    /// Publish the prekey bundle on the DHT now.
    pub fn publish(&self) -> Result<(), String> {
        self.node.publish().map_err(|e| e.to_string())
    }

    /// Write an encrypted backup file; returns the one-time 24-word
    /// mnemonic. The shell shows it exactly once and keeps no copy.
    pub fn export_backup(&self, path: String) -> Result<String, String> {
        self.node.export_backup(path).map_err(|e| e.to_string())
    }

    /// Stop the node (idempotent).
    pub fn stop(&self) {
        self.node.stop();
    }
}

/// The FFI config for this data dir + settings: `kult-ffi`'s desktop
/// baseline (QUIC + TCP on OS ports, desktop KDF, bridging armed) with the
/// user's network settings on top.
fn build_config(
    data_dir: &Path,
    passphrase: String,
    settings: &NetworkSettings,
    kdf: KdfChoice,
) -> Config {
    let mut config = default_config(data_dir.display().to_string(), passphrase);
    config.kdf = kdf;
    // An emptied-out listen list falls back to the baseline rather than
    // silently starting a node nothing can dial.
    if !settings.listen.is_empty() {
        config.listen = settings.listen.clone();
    }
    config.bootstrap = settings.bootstrap.clone();
    config.relay = settings.relay.clone();
    config.mailboxes = settings.mailboxes.clone();
    config.serve_mailbox = settings.serve_mailbox;
    config.mdns = settings.mdns;
    config.spool = settings.spool.clone();
    config.meshtastic_serial = settings.meshtastic_serial.clone();
    config.meshtastic_tcp = settings.meshtastic_tcp.clone();
    config.bridge = settings.bridge;
    config
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

/// Hex decoding: case-insensitive, whitespace-tolerant (QR scanners and
/// terminals both like to wrap long strings). `None` on odd length or
/// non-hex input.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()?;
    if digits.len() % 2 != 0 {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| ((pair[0] << 4) | pair[1]) as u8)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_tolerates_noise() {
        let bytes = [0x00, 0x7f, 0xab, 0xff];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "007fabff");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
        assert_eq!(hex_decode("00 7F\nAB\tff").unwrap(), bytes);
        assert!(hex_decode("007").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn hints_convert_and_reject_garbage() {
        let hint = |kind: &str, value: &str| UiHint {
            kind: kind.to_owned(),
            value: value.to_owned(),
        };
        assert!(matches!(
            hint("multiaddr", "/ip4/1.2.3.4/tcp/1").to_ffi().unwrap(),
            Hint::Multiaddr { .. }
        ));
        assert!(matches!(
            hint("mesh", "broadcast").to_ffi().unwrap(),
            Hint::Mesh { node: u32::MAX }
        ));
        assert!(matches!(
            hint("mesh", "42").to_ffi().unwrap(),
            Hint::Mesh { node: 42 }
        ));
        assert!(hint("mesh", "not-a-number").to_ffi().is_err());
        assert!(hint("teleport", "x").to_ffi().is_err());
        assert!(hint("relay", "  ").to_ffi().is_err());
    }

    #[test]
    fn settings_round_trip_and_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = NetworkSettings::load(dir.path()).unwrap();
        assert!(loaded.mdns && loaded.bridge && loaded.bootstrap.is_empty());

        let mut edited = loaded;
        edited.bootstrap = vec!["/dns4/example.org/udp/4001/quic-v1/p2p/xyz".to_owned()];
        edited.mdns = false;
        edited.save(dir.path()).unwrap();
        let back = NetworkSettings::load(dir.path()).unwrap();
        assert_eq!(back.bootstrap, edited.bootstrap);
        assert!(!back.mdns);

        std::fs::write(dir.path().join("settings.json"), b"{ nope").unwrap();
        assert!(NetworkSettings::load(dir.path())
            .unwrap_err()
            .contains("corrupt"));
    }

    #[test]
    fn events_serialize_with_type_tags() {
        let json = serde_json::to_value(UiEvent::DeliveryUpdated {
            id: "ab".to_owned(),
            state: "delivered",
        })
        .unwrap();
        assert_eq!(json["type"], "delivery_updated");
        assert_eq!(json["state"], "delivered");

        let note = serde_json::to_value(UiEvent::NoteToSelfMessageAdded {
            conversation: "note_to_self".to_owned(),
            id: "05".repeat(16),
            timestamp: 11,
            body: "remember".to_owned(),
        })
        .unwrap();
        assert_eq!(note["type"], "note_to_self_message_added");
        assert_eq!(note["conversation"], "note_to_self");

        let carrier = serde_json::to_value(UiEvent::CarrierCapabilityChanged {
            peer: "04".repeat(32),
            capability: "mesh_only",
            observed_at: 10,
            expires_at: 70,
        })
        .unwrap();
        assert_eq!(carrier["type"], "carrier_capability_changed");
        assert_eq!(carrier["capability"], "mesh_only");
        assert_eq!(carrier["expires_at"], 70);

        let updated = serde_json::to_value(UiEvent::GroupUpdated {
            group: "01".repeat(32),
        })
        .unwrap();
        assert_eq!(updated["type"], "group_updated");

        let received = serde_json::to_value(UiEvent::GroupMessageReceived {
            group: "01".repeat(32),
            sender: "02".repeat(32),
            id: "03".repeat(16),
            timestamp: 7,
            body: "meet at the pass".to_owned(),
            content_kind: "text",
        })
        .unwrap();
        assert_eq!(received["type"], "group_message_received");
        assert_eq!(received["body"], "meet at the pass");

        let delivery = serde_json::to_value(UiEvent::GroupDeliveryUpdated {
            id: "03".repeat(16),
            peer: "02".repeat(32),
            state: "delivered",
        })
        .unwrap();
        assert_eq!(delivery["type"], "group_delivery_updated");
        assert_eq!(delivery["state"], "delivered");
    }
}
