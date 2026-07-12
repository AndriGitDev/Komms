//! KommsKult transport layer (docs/05-transports.md).
//!
//! Defines the [`Transport`] contract that every carrier — internet (M3),
//! BLE (M5), Meshtastic (M4), sneakernet — fulfills, and ships the first
//! implementation: [`SneakernetTransport`], which moves sealed envelopes
//! through spool directories (USB sticks, shared folders, any file channel).
//!
//! Contract rules (docs/05-transports.md §1, enforced by construction):
//! transports carry **ciphertext only** ([`kult_protocol::Envelope`]s), never
//! see key material, and address peers by [`DeliveryHint`] — never by
//! identity keys.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;

use async_trait::async_trait;

use kult_protocol::Envelope;

mod sneakernet;

pub use sneakernet::SneakernetTransport;

/// Failures surfaced by transports.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// I/O failure on the underlying link.
    Io(std::io::Error),
    /// Bytes on the link failed protocol parsing.
    Protocol(kult_protocol::ProtocolError),
    /// The delivery hint is not addressable by this transport.
    UnsupportedHint,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "link i/o error: {e}"),
            Self::Protocol(e) => write!(f, "link protocol error: {e}"),
            Self::UnsupportedHint => f.write_str("delivery hint not supported by this transport"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<kult_protocol::ProtocolError> for TransportError {
    fn from(e: kult_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Latency class of a link, for scheduler ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LatencyClass {
    /// Milliseconds (internet, LAN).
    Millis,
    /// Seconds to minutes (BLE, LoRa single-hop).
    Seconds,
    /// Hours to days (multi-hop mesh store-and-forward, sneakernet).
    HumanScale,
}

/// Cost class of a link, for scheduler ranking and quota decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CostClass {
    /// Effectively free (LAN, file copy).
    Free,
    /// Metered but plentiful (internet data).
    Metered,
    /// Scarce shared medium — duty-cycle limited (LoRa airtime).
    Airtime,
}

/// Static properties of a link, used by the transport scheduler
/// (docs/03-architecture.md §3) to rank and combine carriers.
#[derive(Clone, Copy, Debug)]
pub struct LinkProfile {
    /// Maximum envelope bytes per send before fragmentation is required.
    pub mtu: usize,
    /// Expected latency class.
    pub latency: LatencyClass,
    /// Cost class.
    pub cost: CostClass,
    /// Whether sends reach multiple peers at once (mesh flooding).
    pub broadcast: bool,
}

/// How a transport addresses a peer. Deliberately **not** an identity key —
/// hints are per-transport routing data only (contract rule 2). Serializable
/// so the runtime can persist hints (as opaque bytes) with contacts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum DeliveryHint {
    /// A spool directory (sneakernet): envelopes are written into it.
    Spool(PathBuf),
    /// A libp2p multiaddr (M3).
    Multiaddr(String),
    /// A Meshtastic node number (M4).
    MeshNode(u32),
    /// A relay mailbox identified by the current delivery token (M3).
    Mailbox([u8; 32]),
}

/// Reachability verdict for a peer on this transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// Deliverable immediately.
    Now,
    /// Deliverable eventually (store-and-forward semantics).
    StoreAndForward,
    /// Not deliverable via this transport.
    Unreachable,
}

/// Honest delivery signal (contract rule 4): what actually happened, no more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendReceipt {
    /// The envelope was handed to the link (e.g. written to the spool,
    /// radioed out). Nothing is known about arrival.
    HandedToLink,
    /// The next hop acknowledged receipt (not end-to-end delivery — only
    /// encrypted receipts prove that).
    AckedByNextHop,
}

/// The contract every carrier implements (docs/05-transports.md §1).
///
/// Event-driven integration with the delivery engine (an `EventSink` instead
/// of polling [`Transport::recv`]) arrives with `kult-node` in M3; the
/// send/receive contract below is what all transports share regardless.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Static link properties for scheduler ranking.
    fn profile(&self) -> LinkProfile;

    /// Can this transport deliver to `peer`, and how?
    async fn reachable(&self, peer: &DeliveryHint) -> Reachability;

    /// Hand one sealed envelope to the link. Envelopes larger than
    /// `profile().mtu` must be fragmented by the caller first
    /// ([`kult_protocol::fragment`]).
    async fn send(&self, peer: &DeliveryHint, envelope: &Envelope) -> Result<SendReceipt>;

    /// Drain envelopes that arrived on this link since the last call.
    /// Duplicates are permitted (multipath is normal); dedup is the
    /// delivery engine's job via content ids.
    async fn recv(&self) -> Result<Vec<Envelope>>;
}
