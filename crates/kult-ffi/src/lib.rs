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

mod runtime;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

use kult_transport::DeliveryHint;

use runtime::{Msg, RestoreSource, Runtime, RuntimeConfig};

uniffi::setup_scaffolding!();

/// Errors crossing the FFI boundary. Messages are the node's own, verbatim
/// — honest and human-readable, never downgraded to a fake success.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    /// Startup failed: store open/create (wrong passphrase, corrupt file),
    /// transport bind, or an unreachable configured radio.
    Startup {
        /// What failed, verbatim.
        message: String,
    },
    /// The node rejected the operation (unknown contact, malformed input…).
    Node {
        /// The node's error, verbatim.
        message: String,
    },
    /// The node was stopped; the handle is spent.
    Stopped,
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Startup { message } => write!(f, "startup: {message}"),
            Self::Node { message } => write!(f, "{message}"),
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
    /// Third-party envelopes buffered for mesh↔internet bridging.
    pub transit: u64,
    /// Stored contacts.
    pub contacts: u64,
}

/// What the node reports back to the application
/// (docs/09-implementation-guide.md §3.5).
#[derive(Clone, Debug, uniffi::Enum)]
pub enum Event {
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
}

impl Event {
    /// Convert a node event. `None` for variants this binding predates —
    /// the enum is `#[non_exhaustive]` and new variants ship with an FFI
    /// update, never silently mislabeled.
    fn from_node(event: kult_node::Event) -> Option<Self> {
        Some(match event {
            kult_node::Event::DeliveryUpdated { id, state } => Self::DeliveryUpdated {
                id: hex_encode(&id),
                state: DeliveryState::from_store(state),
            },
            kult_node::Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
            } => Self::MessageReceived {
                peer: hex_encode(&peer),
                id: hex_encode(&id),
                timestamp,
                body: String::from_utf8_lossy(&body).into_owned(),
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
            message: format!("backup file: {e}"),
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

    /// Message history with a peer.
    pub fn messages_with(&self, peer: String) -> Result<Vec<Message>, FfiError> {
        let peer = parse_peer(&peer)?;
        let messages = self.call(|resp| Msg::Messages { peer, resp })?;
        Ok(messages
            .iter()
            .map(|m| Message {
                id: hex_encode(&m.id),
                peer: hex_encode(&m.peer),
                direction: match m.direction {
                    kult_store::Direction::Outbound => Direction::Outbound,
                    kult_store::Direction::Inbound => Direction::Inbound,
                },
                state: DeliveryState::from_store(m.state),
                timestamp: m.timestamp,
                body: String::from_utf8_lossy(&m.body).into_owned(),
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
        let rt = Runtime::start(cfg, sink).map_err(|message| FfiError::Startup { message })?;
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
            .map_err(|message| FfiError::Node { message })
    }
}

/// Validate and convert the FFI-facing [`Config`], creating the data
/// directory on the way.
fn runtime_config(
    config: Config,
    restore: Option<RestoreSource>,
) -> Result<RuntimeConfig, FfiError> {
    let data_dir = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|e| FfiError::Startup {
        message: format!("data dir: {e}"),
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
    let fail = || FfiError::Node {
        message: "peer must be 64 hex chars".to_owned(),
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
        })
        .unwrap();
        match event {
            Event::MessageReceived {
                peer,
                id,
                timestamp,
                body,
            } => {
                assert_eq!(peer, "01".repeat(32));
                assert_eq!(id, "02".repeat(16));
                assert_eq!(timestamp, 7);
                assert_eq!(body, "hi");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
