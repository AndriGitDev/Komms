//! The internet transport (docs/05-transports.md §2): rust-libp2p with QUIC
//! as the primary link protocol and TCP+Noise+Yamux as the fallback.
//!
//! Envelopes travel over a dedicated request-response protocol
//! (`/komms/envelope/2`); the response is an acceptance acknowledgment, so a
//! successful send honestly reports [`SendReceipt::AckedByNextHop`] — never
//! end-to-end delivery (only encrypted receipts prove that).
//!
//! Contract compliance (docs/05-transports.md §1): the swarm identity is
//! always transport-only — **never** the kult identity. Endpoints generate a
//! fresh runtime pseudonym; a mailbox service uses its separately persisted
//! service key so published operator addresses survive restart. Peers are
//! addressed by multiaddr hints; link encryption (QUIC-TLS / Noise) is
//! additive, not load-bearing.
//!
//! The discovery plane (docs/05-transports.md §2) also lives here: a
//! Kademlia DHT (`/komms/kad/1`) storing prekey-bundle records, exposed
//! through the transport-agnostic [`Discovery`] trait. Records are served
//! as untrusted bytes — bundles are self-authenticating and verified by the
//! caller, so a malicious DHT node can at worst withhold, never forge.
//! Bootstrap follows the spec's "defaults, not dependencies" rule:
//! [`Libp2pTransport::bootstrap`] takes whatever peers the *user* configures
//! — nothing is hardcoded, and any reachable peer will do.
//!
//! Mailbox relays (docs/05-transports.md §2) ride a second request-response
//! protocol (`/komms/mailbox/2`): any node started with
//! [`Libp2pTransport::with_mailbox`] serves store-and-forward for offline
//! recipients, who register rotating delivery tokens as accept-filters and
//! collect on reconnect ([`Libp2pTransport::mailbox_checkin`]). Senders
//! reach a mailbox through [`DeliveryHint::Relay`] — a deposit the relay
//! durably accepted is, honestly, [`SendReceipt::AckedByNextHop`] and nothing
//! more. Collection leases remain at the relay until endpoint staging commits.
//!
//! NAT traversal (docs/05-transports.md §2) is the pinned trio:
//! **AutoNAT** probes tell a node whether it is publicly dialable
//! ([`Libp2pTransport::nat_status`]); a private node reserves a **Circuit
//! Relay v2** slot at any public peer ([`Libp2pTransport::reserve_relay`]
//! — every node volunteers bounded relay service, mirroring the mailbox
//! ethic) and hands out the returned circuit address as an ordinary
//! [`DeliveryHint::Multiaddr`]; **DCUtR** then upgrades relayed
//! connections to direct ones by hole punching, so the relay carries
//! traffic only until the punch lands. Relays see what any hop sees:
//! sealed envelopes between transport pseudonyms.
//!
//! mDNS LAN auto-discovery (docs/05-transports.md §3) completes the M3
//! carrier: with [`TransportOptions::lan_discovery`] on, the in-tree mDNS
//! responder (see [`crate::mdns`], ADR-0008) announces this node's listen
//! addresses on the local network and feeds discovered peers into the
//! Kademlia routing table — so two nodes on the same LAN find each other,
//! and the whole discovery plane (prekey publish/lookup) works with zero
//! configured bootstrap peers and no internet at all.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, GetRecordOk, Mode, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{
    autonat, connection_limits, dcutr, identify, noise, relay, tcp, yamux, Multiaddr, PeerId,
    StreamProtocol,
};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};

use kult_protocol::{Envelope, MAX_ENVELOPE_BYTES};

use crate::mailbox::{MailboxRequest, MailboxResponse, MAX_MAILBOX_CHECKIN_TOKENS};
use crate::mailbox_v2::{
    MailboxDepositDisposition, MailboxV2Request, MailboxV2Response, MailboxV2Store,
    MAILBOX_V2_PAGE_MAX_BYTES, MAILBOX_V2_PAGE_MAX_ROWS,
};
use crate::mdns::{self, DiscoveredPeer};
use crate::{
    CostClass, DeliveryHint, Discovery, InboundReceipt, IngressClass, LatencyClass, LinkProfile,
    MailboxMetrics, MailboxServiceConfig, Reachability, ReceivedEnvelope, Result, SendReceipt,
    Transport, TransportError,
};

/// Poison recovery for the transport's shared-state mutexes. A panicking
/// holder poisons a std [`Mutex`]; every value guarded here is a single
/// self-consistent field (a map, vec, or buffer updated in one statement),
/// so continuing with the inner value is sound and beats cascading the
/// panic through a long-lived daemon or FFI runtime.
pub(crate) trait LockExt<T> {
    fn lock_unpoisoned(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_unpoisoned(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| {
            tracing::error!("recovered poisoned transport lock");
            poisoned.into_inner()
        })
    }
}

/// How long a send waits for the next hop's acknowledgment before reporting
/// failure to the delivery engine (which then retries with backoff).
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// A call may wait this long for its explicitly supplied direct QUIC path.
/// Signaling has already established the usual case; this covers a direct
/// re-dial after a TCP/relay path is discarded.
const CALL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The only negotiated media protocol. Its records remain opaque to this
/// transport; authentication and encryption live in `kult-crypto`.
const CALL_PROTOCOL: StreamProtocol = StreamProtocol::new("/komms/call/1");

/// Direct-envelope v2 adds an explicit acceptance bit so a full receiver can
/// refuse work without acknowledging an envelope it did not retain.
const ENVELOPE_PROTOCOL: StreamProtocol = StreamProtocol::new("/komms/envelope/2");

/// Bound unauthenticated inbound media handshakes. A caller must consume and
/// prove the call-media hello before accepting any audio.
const CALL_INBOX_MAX: usize = 16;

/// Maximum unsolicited direct envelopes retained until the delivery engine
/// drains the internet carrier.
const DIRECT_INBOX_MAX_ITEMS: usize = 256;

/// Maximum encoded bytes of unsolicited direct envelopes retained in memory.
/// Item and byte axes are independent: neither many tiny envelopes nor a few
/// maximal envelopes can grow the queue without bound.
const DIRECT_INBOX_MAX_BYTES: usize = 8 * 1024 * 1024;
/// One daemon lifecycle pass checks at most eight relays. Matching that
/// aggregate of count-bounded v2 pages prevents honest relays from overflowing
/// the local collection queue before the node task drains it.
const COLLECTED_INBOX_MAX_ITEMS: usize = 8 * MAILBOX_V2_PAGE_MAX_ROWS;
const COLLECTED_INBOX_MAX_BYTES: usize = 8 * MAILBOX_V2_PAGE_MAX_BYTES;

/// CBOR currently represents `Vec<u8>` as an integer array, so the carrier
/// frame can take just over twice the encoded-envelope bytes.
const ENVELOPE_CBOR_REQUEST_MAX_BYTES: u64 = (2 * MAX_ENVELOPE_BYTES + 64) as u64;
/// A v2 envelope response is one CBOR boolean.
const ENVELOPE_CBOR_RESPONSE_MAX_BYTES: u64 = 16;
/// Mailbox deposits and bounded token check-ins fit below this ceiling.
const MAILBOX_CBOR_REQUEST_MAX_BYTES: u64 = 320 * 1024;
/// A 2 MiB raw check-in batch can approach 4 MiB in the current CBOR array
/// representation; leave bounded framing overhead without retaining the
/// library's 10 MiB default.
const MAILBOX_CBOR_RESPONSE_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Mailbox-v2 carries the same bounded token filter plus exact row-id
/// acknowledgements and one envelope per deposit request.
const MAILBOX_V2_CBOR_REQUEST_MAX_BYTES: u64 = 320 * 1024;
/// One 1 MiB raw leased page remains bounded under CBOR's byte-array
/// representation and fixed row metadata.
const MAILBOX_V2_CBOR_RESPONSE_MAX_BYTES: u64 = 3 * 1024 * 1024;
const ENVELOPE_MAX_CONCURRENT_STREAMS: usize = 16;
const MAILBOX_MAX_CONCURRENT_STREAMS: usize = 8;
/// Commands waiting for the single swarm owner. Backpressure reaches callers
/// before connection, request, or response state can grow without bound.
const COMMAND_QUEUE_MAX: usize = 256;
/// Peer-directed operations retained across dialing and request timeouts.
const MAX_OUTBOUND_OPERATIONS: usize = 128;
const MAX_PENDING_INCOMING_CONNECTIONS: u32 = 32;
const MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 32;
const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 64;
const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 8;
const MAX_ESTABLISHED_CONNECTIONS: u32 = 96;

/// Idle connections linger briefly so a message burst reuses one connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a DHT operation (bootstrap, publish, lookup) may run before it
/// reports failure. Kademlia walks several hops; give it more room than a
/// single send.
const DHT_TIMEOUT: Duration = Duration::from_secs(60);

/// Namespace prefix for prekey-bundle record keys, so kult records can never
/// collide with (or be confused for) another protocol's records on a shared
/// DHT.
const RECORD_NAMESPACE: &[u8] = b"/kk/prekeys/1/";

/// Per-envelope size cap for bridge-transit deposits: anything larger could
/// never ride an airtime-budgeted link anyway (docs/05-transports.md §4.2
/// rule 3), so refusing it here is the honest answer.
const BRIDGE_DEPOSIT_MAX_BYTES: usize = 4 * 1024;

/// Bridge-transit buffer caps (ADR-0009): strangers may fill this, so both
/// axes are bounded and overflow is an honest refusal.
const BRIDGE_BUFFER_MAX_ITEMS: usize = 256;
const BRIDGE_BUFFER_MAX_BYTES: usize = 512 * 1024;

/// First AutoNAT probe fires this soon after start; kept short because the
/// answer gates whether a node should go reserve a relay slot.
const AUTONAT_BOOT_DELAY: Duration = Duration::from_secs(2);

/// AutoNAT re-probe interval while the status is unknown or unconfirmed.
const AUTONAT_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// This node's reachability from the open internet, as measured by AutoNAT
/// dial-back probes (docs/05-transports.md §2). Drives the relay decision:
/// a [`NatStatus::Private`] node should reserve a circuit relay slot
/// ([`Libp2pTransport::reserve_relay`]) and publish the returned address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatStatus {
    /// No probe has concluded yet.
    Unknown,
    /// A peer dialed one of our addresses back successfully — publicly
    /// reachable, and a candidate relay/mailbox for others.
    Public,
    /// Dial-backs fail: behind NAT or firewall; direct inbound connections
    /// require a relay reservation (DCUtR upgrades them once punched).
    Private,
}

#[derive(NetworkBehaviour)]
struct KultBehaviour {
    limits: connection_limits::Behaviour,
    envelopes: request_response::cbor::Behaviour<Vec<u8>, bool>,
    mailbox_v1: request_response::cbor::Behaviour<MailboxRequest, MailboxResponse>,
    mailbox_v2: request_response::cbor::Behaviour<MailboxV2Request, MailboxV2Response>,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    autonat: autonat::Behaviour,
    relay: relay::Behaviour,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    streams: libp2p_stream::Behaviour,
}

/// Internal settlement of an envelope request. This deliberately preserves
/// the distinction between an explicit remote refusal and failure to obtain
/// any response from the hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HopOutcome {
    Accepted,
    Refused,
    LinkFailed,
}

/// A request aimed at a specific peer, parked while its connection dials.
enum PendingOp {
    /// Direct envelope delivery; reports next-hop ack.
    Envelope(Vec<u8>, oneshot::Sender<HopOutcome>),
    /// Mailbox deposit of encoded envelope bytes; reports acceptance.
    Deposit(Vec<u8>, oneshot::Sender<HopOutcome>),
    /// Mailbox check-in; reports collected-envelope count, `None` on
    /// refusal or link failure.
    Checkin(Vec<[u8; 32]>, oneshot::Sender<Option<usize>>),
}

impl PendingOp {
    /// Resolve the waiter with the failure outcome (dial failed, link died).
    fn fail(self) {
        match self {
            Self::Envelope(_, ack) | Self::Deposit(_, ack) => {
                let _ = ack.send(HopOutcome::LinkFailed);
            }
            Self::Checkin(_, done) => {
                let _ = done.send(None);
            }
        }
    }
}

enum Cmd {
    Op {
        peer: PeerId,
        addr: Multiaddr,
        op: PendingOp,
    },
    Bootstrap {
        peer: PeerId,
        addr: Multiaddr,
        done: oneshot::Sender<bool>,
    },
    PutRecord {
        key: RecordKey,
        value: Vec<u8>,
        done: oneshot::Sender<bool>,
    },
    GetRecord {
        key: RecordKey,
        done: oneshot::Sender<Vec<Vec<u8>>>,
    },
    /// Listen on a `/p2p-circuit` address (a relay reservation); resolves
    /// with the circuit listen address once the relay accepts, `None` on
    /// refusal or unreachable relay.
    Reserve {
        addr: Multiaddr,
        done: oneshot::Sender<Option<Multiaddr>>,
    },
    NatStatus {
        done: oneshot::Sender<NatStatus>,
    },
    /// Establish an exclusively direct-QUIC connection for call media.
    /// Existing TCP and relay connections to the same peer are closed first,
    /// because `libp2p-stream` otherwise chooses an arbitrary live path.
    PrepareCall {
        peer: PeerId,
        addr: Multiaddr,
        done: oneshot::Sender<bool>,
    },
    /// Settle one direct inbound request after durable endpoint admission.
    SettleInbound {
        receipt: InboundReceipt,
        accepted: bool,
    },
}

/// In-flight mailbox requests awaiting their response.
enum MailboxWaiter {
    Deposit(oneshot::Sender<HopOutcome>),
    Checkin(oneshot::Sender<Option<usize>>),
    Ack,
}

impl MailboxWaiter {
    /// Resolve with the failure outcome (link failure, malformed response).
    fn fail(self) {
        match self {
            Self::Deposit(ack) => {
                let _ = ack.send(HopOutcome::LinkFailed);
            }
            Self::Checkin(done) => {
                let _ = done.send(None);
            }
            Self::Ack => {}
        }
    }
}

/// One carrier response that may be settled only after endpoint admission.
enum InboundSettlement {
    Direct(request_response::ResponseChannel<bool>),
    Mailbox {
        peer: PeerId,
        lease_id: [u8; 16],
        row_id: [u8; 16],
    },
}

/// In-flight DHT queries awaiting their final `OutboundQueryProgressed`.
enum QueryWaiter {
    Put(oneshot::Sender<bool>),
    Get {
        values: Vec<Vec<u8>>,
        done: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

/// How to build a [`Libp2pTransport`] beyond its listen addresses.
#[derive(Debug, Default)]
pub struct TransportOptions {
    /// Serve bounded store-and-forward mailboxes for others
    /// (docs/05-transports.md §2).
    pub mailbox: Option<MailboxServiceConfig>,
    /// Announce on, and discover peers from, the local network over mDNS
    /// (docs/05-transports.md §3). Discovered peers seed the Kademlia
    /// routing table, so LAN-only operation needs no bootstrap peers.
    pub lan_discovery: bool,
    /// Accept mailbox deposits for **unregistered** tokens into a bounded
    /// transit buffer instead of refusing them, surfaced via
    /// [`Transport::recv_transit`] for a bridging delivery engine to flood
    /// onto its mesh carriers (docs/05-transports.md §4.2 rule 5,
    /// ADR-0009). Off by default: only a node that actually bridges should
    /// relax the mailbox accept rule.
    pub bridge_deposits: bool,
}

/// The bounded internet→mesh transit buffer (ADR-0009). Deposits land here
/// when their token is registered nowhere locally; overflow refuses the
/// deposit — an honest signal the depositor's delivery engine retries on.
struct BridgeBuffer {
    queue: Vec<Envelope>,
    bytes: usize,
}

impl BridgeBuffer {
    fn new() -> Self {
        Self {
            queue: Vec::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, envelope: Envelope, encoded_len: usize, now: u64) -> bool {
        if envelope
            .retention_until
            .is_some_and(|deadline| deadline <= now)
        {
            return true;
        }
        if encoded_len > BRIDGE_DEPOSIT_MAX_BYTES
            || self.queue.len() >= BRIDGE_BUFFER_MAX_ITEMS
            || self.bytes + encoded_len > BRIDGE_BUFFER_MAX_BYTES
        {
            return false;
        }
        self.bytes += encoded_len;
        self.queue.push(envelope);
        true
    }

    fn drain(&mut self) -> Vec<Envelope> {
        self.bytes = 0;
        std::mem::take(&mut self.queue)
    }
}

/// Internet receive queue with independent direct and collected-mail budgets.
/// Mailbox collection is locally initiated and bounded per response as well
/// as across responses retained before the delivery engine drains this queue.
struct InternetInbox {
    queue: Vec<ReceivedEnvelope>,
    direct_items: usize,
    direct_bytes: usize,
    collected_items: usize,
    collected_bytes: usize,
}

impl InternetInbox {
    fn new() -> Self {
        Self {
            queue: Vec::new(),
            direct_items: 0,
            direct_bytes: 0,
            collected_items: 0,
            collected_bytes: 0,
        }
    }

    /// Admit an unsolicited direct envelope or refuse it without mutation.
    fn push_direct(&mut self, envelope: Envelope, receipt: InboundReceipt) -> bool {
        let encoded_len = envelope.encoded_len();
        if encoded_len > MAX_ENVELOPE_BYTES {
            return false;
        }
        let Some(next_bytes) = self.direct_bytes.checked_add(encoded_len) else {
            return false;
        };
        if self.direct_items >= DIRECT_INBOX_MAX_ITEMS || next_bytes > DIRECT_INBOX_MAX_BYTES {
            return false;
        }
        self.direct_items += 1;
        self.direct_bytes = next_bytes;
        self.queue.push(ReceivedEnvelope {
            envelope,
            receipt: Some(receipt),
            ingress: IngressClass::Direct,
        });
        true
    }

    /// Add a solicited mailbox result without allowing repeated local
    /// check-ins to grow the shared receive queue without bound.
    fn push_collected(&mut self, envelope: Envelope, receipt: InboundReceipt) -> bool {
        let encoded_len = envelope.encoded_len();
        let Some(next_bytes) = self.collected_bytes.checked_add(encoded_len) else {
            return false;
        };
        if self.collected_items >= COLLECTED_INBOX_MAX_ITEMS
            || next_bytes > COLLECTED_INBOX_MAX_BYTES
        {
            return false;
        }
        self.collected_items += 1;
        self.collected_bytes = next_bytes;
        self.queue.push(ReceivedEnvelope {
            envelope,
            receipt: Some(receipt),
            ingress: IngressClass::Mailbox,
        });
        true
    }

    fn drain(&mut self) -> Vec<ReceivedEnvelope> {
        self.direct_items = 0;
        self.direct_bytes = 0;
        self.collected_items = 0;
        self.collected_bytes = 0;
        std::mem::take(&mut self.queue)
    }
}

struct Shared {
    local_peer_id: PeerId,
    listen_addrs: Mutex<Vec<Multiaddr>>,
    /// Every live connection and whether it is a non-relayed QUIC-v1 path.
    /// Call streams proceed only when a peer has at least one connection and
    /// every entry is `true`.
    connections: Mutex<HashMap<PeerId, HashMap<ConnectionId, bool>>>,
    /// LAN peers seen via mDNS: address → when its announcement expires.
    lan_peers: Mutex<HashMap<PeerId, HashMap<Multiaddr, Instant>>>,
}

impl Shared {
    fn call_ready(&self, peer: &PeerId) -> bool {
        self.connections
            .lock_unpoisoned()
            .get(peer)
            .is_some_and(|connections| {
                !connections.is_empty() && connections.values().all(|direct| *direct)
            })
    }
}

/// A negotiated `/komms/call/1` stream on an exclusively direct QUIC path.
///
/// The peer id is a transport pseudonym, not a Komms account or device
/// identity. Call media must still authenticate its proof-of-key hello before
/// treating this stream as belonging to a call.
#[derive(Debug)]
pub struct CallStream {
    peer: PeerId,
    inner: libp2p::swarm::Stream,
}

impl CallStream {
    /// The remote libp2p transport pseudonym.
    pub fn peer_id(&self) -> String {
        self.peer.to_string()
    }
}

impl AsyncRead for CallStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for CallStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// Internet carrier: QUIC (primary) and TCP (fallback) via rust-libp2p.
pub struct Libp2pTransport {
    cmds: mpsc::Sender<Cmd>,
    inbox: Arc<Mutex<InternetInbox>>,
    shared: Arc<Shared>,
    mailbox: Option<Arc<Mutex<MailboxV2Store>>>,
    bridge: Option<Arc<Mutex<BridgeBuffer>>>,
    call_control: AsyncMutex<libp2p_stream::Control>,
    call_inbox: AsyncMutex<mpsc::Receiver<CallStream>>,
}

impl Libp2pTransport {
    /// Start a transport listening on the given multiaddrs (e.g.
    /// `/ip4/0.0.0.0/udp/0/quic-v1` and `/ip4/0.0.0.0/tcp/0`). Spawns the
    /// swarm onto the ambient tokio runtime; dropping the transport stops it.
    ///
    /// The endpoint swarm keypair is fresh and unlinked to any kult identity.
    /// A configured mailbox service instead opens its dedicated persistent
    /// transport key so the service address remains valid across restart.
    pub async fn new(listen: &[&str]) -> Result<Self> {
        Self::with_options(listen, TransportOptions::default()).await
    }

    /// Like [`Libp2pTransport::new`], but this node also serves mailboxes
    /// (docs/05-transports.md §2): store-and-forward for offline recipients,
    /// bounded by `config`. Any ordinary node can volunteer.
    pub async fn with_mailbox(listen: &[&str], config: MailboxServiceConfig) -> Result<Self> {
        Self::with_options(
            listen,
            TransportOptions {
                mailbox: Some(config),
                ..TransportOptions::default()
            },
        )
        .await
    }

    /// Full-control constructor: see [`TransportOptions`].
    pub async fn with_options(listen: &[&str], options: TransportOptions) -> Result<Self> {
        let TransportOptions {
            mailbox,
            lan_discovery,
            bridge_deposits,
        } = options;
        let transport_identity = mailbox
            .as_ref()
            .map(|config| load_or_create_service_identity(&config.transport_key_path))
            .transpose()
            .map_err(TransportError::Io)?
            .unwrap_or_else(libp2p::identity::Keypair::generate_ed25519);
        let mailbox = mailbox
            .as_ref()
            .map(MailboxV2Store::open)
            .transpose()
            .map_err(TransportError::Io)?
            .map(|store| Arc::new(Mutex::new(store)));
        // Every muxer below must stay on `yamux::Config::default()`: the
        // default pins libp2p-yamux to the patched yamux 0.13 implementation.
        // The deprecated set_window_update_mode() API would silently switch
        // to the unpatched legacy 0.12 code (CVE-2026-32314 waiver in
        // deny.toml relies on it never being called).
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(transport_identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(io_other)?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(io_other)?
            .with_behaviour(|key, relay_client| {
                let envelope_codec =
                    request_response::cbor::codec::Codec::<Vec<u8>, bool>::default()
                        .set_request_size_maximum(ENVELOPE_CBOR_REQUEST_MAX_BYTES)
                        .set_response_size_maximum(ENVELOPE_CBOR_RESPONSE_MAX_BYTES);
                let envelopes = request_response::Behaviour::with_codec(
                    envelope_codec,
                    [(ENVELOPE_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_max_concurrent_streams(ENVELOPE_MAX_CONCURRENT_STREAMS),
                );
                let mailbox_v1_codec = request_response::cbor::codec::Codec::<
                    MailboxRequest,
                    MailboxResponse,
                >::default()
                .set_request_size_maximum(MAILBOX_CBOR_REQUEST_MAX_BYTES)
                .set_response_size_maximum(MAILBOX_CBOR_RESPONSE_MAX_BYTES);
                let mailbox_v1 = request_response::Behaviour::with_codec(
                    mailbox_v1_codec,
                    [(
                        StreamProtocol::new("/komms/mailbox/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default()
                        .with_max_concurrent_streams(MAILBOX_MAX_CONCURRENT_STREAMS),
                );
                let mailbox_v2_codec = request_response::cbor::codec::Codec::<
                    MailboxV2Request,
                    MailboxV2Response,
                >::default()
                .set_request_size_maximum(MAILBOX_V2_CBOR_REQUEST_MAX_BYTES)
                .set_response_size_maximum(MAILBOX_V2_CBOR_RESPONSE_MAX_BYTES);
                let mailbox_v2 = request_response::Behaviour::with_codec(
                    mailbox_v2_codec,
                    [(
                        StreamProtocol::new("/komms/mailbox/2"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default()
                        .with_max_concurrent_streams(MAILBOX_MAX_CONCURRENT_STREAMS),
                );
                let peer_id = key.public().to_peer_id();
                let kad = kad::Behaviour::with_config(
                    peer_id,
                    MemoryStore::new(peer_id),
                    kad::Config::new(StreamProtocol::new("/komms/kad/1")),
                );
                // Identify carries only the transport pseudonym and listen
                // addresses — it is how DHT peers learn where to reach each
                // other; the kult identity never appears on this layer.
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/komms/1".into(),
                    key.public(),
                ));
                // `only_global_ips: false` — LAN and localhost reachability
                // is first-class in kult (docs/05-transports.md), so a
                // dial-back from a private-range peer is a real answer, not
                // noise. Probes go to whatever peers we're connected to;
                // nothing is hardcoded.
                let autonat = autonat::Behaviour::new(
                    peer_id,
                    autonat::Config {
                        boot_delay: AUTONAT_BOOT_DELAY,
                        retry_interval: AUTONAT_RETRY_INTERVAL,
                        only_global_ips: false,
                        ..Default::default()
                    },
                );
                // Every node volunteers bounded circuit-relay service, the
                // same ethic as mailboxes: capacity comes from peers, never
                // from project infrastructure. Default limits keep a circuit
                // short-lived — DCUtR is expected to punch a direct path.
                let relay = relay::Behaviour::new(peer_id, relay::Config::default());
                let dcutr = dcutr::Behaviour::new(peer_id);
                let streams = libp2p_stream::Behaviour::new();
                let limits = connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING_CONNECTIONS))
                        .with_max_pending_outgoing(Some(MAX_PENDING_OUTGOING_CONNECTIONS))
                        .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS))
                        .with_max_established_per_peer(Some(MAX_ESTABLISHED_CONNECTIONS_PER_PEER))
                        .with_max_established(Some(MAX_ESTABLISHED_CONNECTIONS)),
                );
                Ok(KultBehaviour {
                    limits,
                    envelopes,
                    mailbox_v1,
                    mailbox_v2,
                    kad,
                    identify,
                    autonat,
                    relay,
                    relay_client,
                    dcutr,
                    streams,
                })
            })
            .map_err(io_other)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
            .build();

        // Every node serves DHT records — there is no client/server split to
        // centralize around (docs/01-why.md). Explicit server mode rather
        // than AutoNAT-driven auto mode: LAN-only and air-gapped-adjacent
        // deployments must keep serving records with no confirmed public
        // address, and stale entries age out of peers' routing tables anyway.
        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

        let mut call_control = swarm.behaviour().streams.new_control();
        let call_incoming = call_control
            .accept(CALL_PROTOCOL)
            .map_err(|_| io_other("call protocol was registered more than once"))?;

        for addr in listen {
            let addr: Multiaddr = addr.parse().map_err(io_other)?;
            swarm.listen_on(addr).map_err(io_other)?;
        }

        let shared = Arc::new(Shared {
            local_peer_id: *swarm.local_peer_id(),
            listen_addrs: Mutex::new(Vec::new()),
            connections: Mutex::new(HashMap::new()),
            lan_peers: Mutex::new(HashMap::new()),
        });
        let inbox = Arc::new(Mutex::new(InternetInbox::new()));
        let bridge = bridge_deposits.then(|| Arc::new(Mutex::new(BridgeBuffer::new())));
        let (cmds, cmd_rx) = mpsc::channel(COMMAND_QUEUE_MAX);
        let (call_tx, call_rx) = mpsc::channel(CALL_INBOX_MAX);
        tokio::spawn(run_call_incoming(
            call_incoming,
            call_tx,
            Arc::clone(&shared),
        ));

        // The mDNS task rides two channels: listen addresses flow out to it
        // (announce on change), discovered peers flow back into the swarm
        // task. When discovery is off, its sender is simply dropped here.
        let (addr_tx, addr_rx) = watch::channel(Vec::new());
        let (found_tx, found_rx) = mpsc::unbounded_channel();
        if lan_discovery {
            // Honest failure over silent degradation: a host that cannot
            // join the multicast group (no route, hardened container) gets
            // an error naming the opt-out, not a node that quietly never
            // discovers anyone.
            let socket = mdns::mdns_socket().map_err(|e| {
                io_other(format!(
                    "mDNS socket setup failed (disable lan_discovery to run without): {e}"
                ))
            })?;
            let socket = tokio::net::UdpSocket::from_std(socket)?;
            tokio::spawn(mdns::run_mdns(
                socket,
                shared.local_peer_id,
                addr_rx,
                found_tx,
            ));
        }

        tokio::spawn(run_swarm(
            swarm,
            cmd_rx,
            Arc::clone(&inbox),
            Arc::clone(&shared),
            Services {
                mailbox: mailbox.clone(),
                bridge: bridge.clone(),
            },
            addr_tx,
            found_rx,
        ));

        Ok(Self {
            cmds,
            inbox,
            shared,
            mailbox,
            bridge,
            call_control: AsyncMutex::new(call_control),
            call_inbox: AsyncMutex::new(call_rx),
        })
    }

    /// This transport's peer id (an endpoint-runtime or dedicated service
    /// pseudonym, never the account identity).
    pub fn local_peer_id(&self) -> String {
        self.shared.local_peer_id.to_string()
    }

    /// Current listen addresses, each with the peer id appended — exactly
    /// the strings peers store as [`DeliveryHint::Multiaddr`] for us.
    /// Includes circuit addresses once [`Libp2pTransport::reserve_relay`]
    /// succeeds.
    pub fn listen_addrs(&self) -> Vec<String> {
        let id = self.shared.local_peer_id;
        self.shared
            .listen_addrs
            .lock_unpoisoned()
            .iter()
            .map(|a| with_peer_id(a, id))
            .collect()
    }

    /// Peers currently visible on the local network via mDNS, as multiaddrs
    /// with `/p2p/…` appended — ready to use as [`DeliveryHint::Multiaddr`].
    /// Empty when [`TransportOptions::lan_discovery`] is off, when the LAN
    /// is quiet, or once announcements have expired unrenewed.
    pub fn lan_peers(&self) -> Vec<String> {
        let now = Instant::now();
        self.shared
            .lan_peers
            .lock_unpoisoned()
            .iter()
            .flat_map(|(peer, addrs)| {
                addrs
                    .iter()
                    .filter(move |(_, expires)| **expires > now)
                    .map(move |(addr, _)| format!("{addr}/p2p/{peer}"))
            })
            .collect()
    }

    /// Wait (up to 5 s) for the first listen address to be bound. Convenience
    /// for tests and daemon startup.
    pub async fn wait_listen_addr(&self) -> Result<String> {
        for _ in 0..500 {
            if let Some(addr) = self.listen_addrs().into_iter().next() {
                return Ok(addr);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(TransportError::Io(io::Error::other(
            "no listen address bound within 5s",
        )))
    }

    /// Join the DHT via the given peers (multiaddrs with `/p2p/…`), then run
    /// a Kademlia bootstrap walk. Succeeds if at least one peer worked — the
    /// list is user-supplied defaults, not a dependency (docs/05-transports.md
    /// §2): any reachable peer bootstraps the whole discovery plane.
    pub async fn bootstrap(&self, peers: &[&str]) -> Result<()> {
        let mut joined = false;
        for entry in peers {
            let Some((addr, peer)) = parse_addr(entry) else {
                continue;
            };
            let (done, rx) = oneshot::channel();
            self.cmds
                .send(Cmd::Bootstrap { peer, addr, done })
                .await
                .map_err(|_| io_other("transport task stopped"))?;
            if let Ok(Ok(true)) = tokio::time::timeout(DHT_TIMEOUT, rx).await {
                joined = true;
            }
        }
        if joined {
            Ok(())
        } else {
            Err(io_other("no bootstrap peer was reachable"))
        }
    }

    /// Check in with a mailbox relay (a multiaddr with `/p2p/…`): register
    /// `tokens` as this node's accept-filters and collect one bounded page
    /// queued under them into the staged receive path ([`Transport::recv_staged`]).
    /// Returns how many envelopes were collected in one bounded v2 lease page.
    /// Callers schedule later pages instead of looping in one lifecycle pass.
    /// Errors are honest: the relay was unreachable, or does not serve
    /// mailboxes.
    ///
    /// Build the token set with `kult-node`'s `mailbox_tokens` — every token
    /// in it is scoped to the caller as recipient (ADR-0007). Exact relay rows
    /// are deleted only after the endpoint settles their durable staging.
    pub async fn mailbox_checkin(&self, relay: &str, tokens: &[[u8; 32]]) -> Result<usize> {
        if tokens.len() > MAX_MAILBOX_CHECKIN_TOKENS {
            return Err(io_other("mailbox check-in token limit exceeded"));
        }
        let (addr, peer) = parse_addr(relay).ok_or(TransportError::UnsupportedHint)?;
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Op {
                peer,
                addr,
                op: PendingOp::Checkin(tokens.to_vec(), done),
            })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, rx).await {
            Ok(Ok(Some(count))) => Ok(count),
            Ok(Ok(None)) => Err(io_other("relay unreachable or not serving mailboxes")),
            Ok(Err(_)) => Err(io_other("transport task stopped")),
            Err(_) => Err(io_other("mailbox check-in timed out")),
        }
    }

    /// Content-free aggregate mailbox-v2 capacity and lease health.
    pub fn mailbox_metrics(&self) -> Option<MailboxMetrics> {
        self.mailbox.as_ref().and_then(|store| {
            store
                .lock_unpoisoned()
                .metrics(unix_now())
                .map_err(|_| {
                    tracing::error!("mailbox metrics failed");
                })
                .ok()
        })
    }

    /// This node's NAT reachability as measured by AutoNAT dial-back probes.
    /// Starts [`NatStatus::Unknown`] and settles within seconds of the first
    /// peer connection. [`NatStatus::Private`] is the cue to call
    /// [`Libp2pTransport::reserve_relay`] so peers can still dial in.
    pub async fn nat_status(&self) -> Result<NatStatus> {
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::NatStatus { done })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        rx.await.map_err(|_| io_other("transport task stopped"))
    }

    /// Reserve a Circuit Relay v2 slot at `relay` (a multiaddr with
    /// `/p2p/…`) and return the resulting **circuit address** — publish it
    /// like any listen address (peers use it as [`DeliveryHint::Multiaddr`]).
    /// Dials through it arrive relayed and DCUtR then hole-punches a direct
    /// connection, so the relay carries traffic only briefly. Errors are
    /// honest: the relay was unreachable or refused the reservation — which
    /// includes a relay that does not yet know its own dialable address
    /// (vouchers advertise AutoNAT-confirmed addresses; a fresh relay
    /// self-confirms seconds after its first peer connects).
    pub async fn reserve_relay(&self, relay: &str) -> Result<String> {
        let (addr, _) = parse_addr(relay).ok_or(TransportError::UnsupportedHint)?;
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Reserve {
                addr: addr.with(Protocol::P2pCircuit),
                done,
            })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, rx).await {
            Ok(Ok(Some(circuit))) => Ok(with_peer_id(&circuit, self.shared.local_peer_id)),
            Ok(Ok(None)) => Err(io_other("relay unreachable or refused the reservation")),
            Ok(Err(_)) => Err(io_other("transport task stopped")),
            Err(_) => Err(io_other("relay reservation timed out")),
        }
    }

    /// Whether `peer` currently has an exclusively direct QUIC path suitable
    /// for `/komms/call/1`. The address must include the target `/p2p` id and
    /// must itself be direct QUIC; TCP and `/p2p-circuit` hints always return
    /// `false` even if another connection to that peer happens to be ready.
    pub fn call_ready(&self, peer: &str) -> bool {
        parse_direct_quic_addr(peer).is_some_and(|(_, peer)| self.shared.call_ready(&peer))
    }

    /// Open an authenticated-call media stream to a direct QUIC multiaddr.
    ///
    /// The transport first closes every live TCP or relayed connection to the
    /// target and, when needed, dials the exact supplied QUIC address. This is
    /// a fail-closed guard around `libp2p-stream`, which otherwise selects an
    /// arbitrary live connection. No TCP, relay, mailbox, mesh, or
    /// store-and-forward fallback is attempted.
    pub async fn open_call_stream(&self, address: &str) -> Result<CallStream> {
        let (addr, peer) =
            parse_direct_quic_addr(address).ok_or(TransportError::UnsupportedHint)?;
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::PrepareCall { peer, addr, done })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(CALL_CONNECT_TIMEOUT, rx).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Err(io_other("direct QUIC call path failed")),
            Ok(Err(_)) => return Err(io_other("transport task stopped")),
            Err(_) => return Err(io_other("direct QUIC call path timed out")),
        }
        if !self.shared.call_ready(&peer) {
            return Err(io_other("direct QUIC call path changed before stream open"));
        }
        let stream = self
            .call_control
            .lock()
            .await
            .open_stream(peer, CALL_PROTOCOL)
            .await
            .map_err(io_other)?;
        if !self.shared.call_ready(&peer) {
            return Err(io_other("direct QUIC call path changed during stream open"));
        }
        Ok(CallStream {
            peer,
            inner: stream,
        })
    }

    /// Wait for the next inbound direct-QUIC call stream.
    ///
    /// This is only transport admission. The consumer must parse and verify
    /// the call-media proof-of-key hello before exposing any call state or
    /// audio. Streams arriving while any connection to the peer is TCP or
    /// relayed are discarded before reaching this queue.
    pub async fn accept_call_stream(&self) -> Result<CallStream> {
        self.call_inbox
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io_other("transport task stopped"))
    }

    /// Take one already-negotiated inbound call stream without waiting.
    /// Returns `None` when no stream is currently queued or another consumer
    /// is polling the queue. This lets an application heartbeat service call
    /// media without ever stalling ordinary message delivery.
    pub fn try_accept_call_stream(&self) -> Result<Option<CallStream>> {
        let Ok(mut inbox) = self.call_inbox.try_lock() else {
            return Ok(None);
        };
        match inbox.try_recv() {
            Ok(stream) => Ok(Some(stream)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(io_other("transport task stopped")),
        }
    }
}

#[async_trait]
impl Discovery for Libp2pTransport {
    async fn publish(&self, key: [u8; 32], value: Vec<u8>) -> Result<()> {
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::PutRecord {
                key: record_key(&key),
                value,
                done,
            })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(DHT_TIMEOUT, rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(_) => Err(io_other("no DHT peer stored the record")),
            Err(_) => Err(io_other("DHT publish timed out")),
        }
    }

    async fn lookup(&self, key: [u8; 32]) -> Result<Vec<Vec<u8>>> {
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::GetRecord {
                key: record_key(&key),
                done,
            })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(DHT_TIMEOUT, rx).await {
            Ok(Ok(values)) => Ok(values),
            Ok(Err(_)) => Err(io_other("transport task stopped")),
            Err(_) => Err(io_other("DHT lookup timed out")),
        }
    }
}

/// Namespaced Kademlia key for a 32-byte discovery key.
fn record_key(key: &[u8; 32]) -> RecordKey {
    let mut bytes = Vec::with_capacity(RECORD_NAMESPACE.len() + key.len());
    bytes.extend_from_slice(RECORD_NAMESPACE);
    bytes.extend_from_slice(key);
    RecordKey::from(bytes)
}

fn io_other(e: impl std::fmt::Display) -> TransportError {
    TransportError::Io(io::Error::other(e.to_string()))
}

/// Render `addr` with `/p2p/<id>` appended exactly once — the swarm reports
/// some listen addresses (circuit ones) already carrying the local peer id.
fn with_peer_id(addr: &Multiaddr, id: PeerId) -> String {
    match addr.iter().last() {
        Some(Protocol::P2p(p)) if p == id => addr.to_string(),
        _ => format!("{addr}/p2p/{id}"),
    }
}

/// A usable address is a multiaddr carrying an explicit `/p2p/<peer-id>`.
/// The **last** `/p2p` component is the target: a circuit address
/// (`…/p2p/<relay>/p2p-circuit/p2p/<peer>`) names the relay first.
fn parse_addr(s: &str) -> Option<(Multiaddr, PeerId)> {
    let addr: Multiaddr = s.parse().ok()?;
    let peer = addr
        .iter()
        .filter_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .last()?;
    Some((addr, peer))
}

/// Parse a direct QUIC-v1 address carrying an explicit target peer id.
/// Circuit addresses are excluded even when their relay-facing segment is
/// QUIC, because the call itself would still traverse the relay.
fn parse_direct_quic_addr(s: &str) -> Option<(Multiaddr, PeerId)> {
    let (addr, peer) = parse_addr(s)?;
    is_direct_quic_addr(&addr).then_some((addr, peer))
}

fn is_direct_quic_addr(addr: &Multiaddr) -> bool {
    let mut quic = false;
    for protocol in addr.iter() {
        match protocol {
            Protocol::QuicV1 => quic = true,
            Protocol::P2pCircuit => return false,
            _ => {}
        }
    }
    quic
}

fn endpoint_is_direct_quic(endpoint: &libp2p::core::ConnectedPoint) -> bool {
    !endpoint.is_relayed() && is_direct_quic_addr(endpoint.get_remote_address())
}

async fn run_call_incoming(
    mut incoming: libp2p_stream::IncomingStreams,
    sender: mpsc::Sender<CallStream>,
    shared: Arc<Shared>,
) {
    while let Some((peer, stream)) = incoming.next().await {
        if !shared.call_ready(&peer) {
            continue;
        }
        if sender
            .send(CallStream {
                peer,
                inner: stream,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

/// Current Unix time, for the mailbox service's TTL accounting. The mailbox
/// lives at the I/O layer, so the wall clock is the right clock here.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_or_create_service_identity(
    path: &std::path::Path,
) -> io::Result<libp2p::identity::Keypair> {
    const MAX_KEY_BYTES: usize = 1024;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mailbox transport key is not a regular file",
                ));
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mailbox transport key is not a regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            let mut bytes = Vec::with_capacity(MAX_KEY_BYTES);
            file.take((MAX_KEY_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() > MAX_KEY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mailbox transport key has the wrong length",
                ));
            }
            let key = libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mailbox transport key"))?;
            if key.key_type() != libp2p::identity::KeyType::Ed25519 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mailbox transport key has the wrong type",
                ));
            }
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let encoded = key
                .to_protobuf_encoding()
                .map_err(|_| io::Error::other("mailbox transport key encoding"))?;
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mailbox transport key is not a regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(&encoded)?;
            file.sync_all()?;
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

#[async_trait]
impl Transport for Libp2pTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            // Direct-envelope v2 admits one complete bounded envelope before
            // acknowledging it. Advertising the protocol ceiling keeps a
            // 64 KiB padded attachment record plus ratchet overhead atomic
            // instead of producing memory-only fragments that must be
            // refused by durable endpoint admission.
            mtu: MAX_ENVELOPE_BYTES,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            // Either already connected or dialable on demand — both are
            // immediate at internet latency; failures surface from send()
            // and feed the delivery engine's backoff.
            DeliveryHint::Multiaddr(s) if parse_addr(s).is_some() => Reachability::Now,
            // A mailbox deposit reaches the recipient whenever it next
            // checks in — so the scheduler ranks direct paths above it.
            DeliveryHint::Relay(s) if parse_addr(s).is_some() => Reachability::StoreAndForward,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(&self, peer: &DeliveryHint, envelope: &Envelope) -> Result<SendReceipt> {
        let (s, deposit) = match peer {
            DeliveryHint::Multiaddr(s) => (s, false),
            DeliveryHint::Relay(s) => (s, true),
            _ => return Err(TransportError::UnsupportedHint),
        };
        let (addr, peer) = parse_addr(s).ok_or(TransportError::UnsupportedHint)?;
        let encoded = envelope.try_encode()?;
        // A deposit aimed at our own mailbox goes straight into the local
        // store instead of self-dialing — how a bridge that serves the
        // community mailbox hands mesh-heard transit to its internet-side
        // collectors (ADR-0009). Deliberately *not* falling back to the
        // bridge buffer: that would loop transit back onto the mesh.
        if deposit && peer == self.shared.local_peer_id {
            let Some(store) = &self.mailbox else {
                return Err(io_other("own relay hint but no mailbox service"));
            };
            let accepted = store
                .lock_unpoisoned()
                .deposit(
                    &self.shared.local_peer_id.to_bytes(),
                    envelope,
                    encoded,
                    unix_now(),
                )
                .map_err(TransportError::Io)?;
            return if accepted {
                Ok(SendReceipt::AckedByNextHop)
            } else {
                Err(TransportError::RefusedByNextHop)
            };
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        let op = if deposit {
            PendingOp::Deposit(encoded, ack_tx)
        } else {
            PendingOp::Envelope(encoded, ack_tx)
        };
        self.cmds
            .send(Cmd::Op { peer, addr, op })
            .await
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, ack_rx).await {
            // Only explicit acceptance means the peer or mailbox relay
            // retained the envelope. Refusal is typed for retry scheduling.
            Ok(Ok(HopOutcome::Accepted)) => Ok(SendReceipt::AckedByNextHop),
            Ok(Ok(HopOutcome::Refused)) => Err(TransportError::RefusedByNextHop),
            Ok(Ok(HopOutcome::LinkFailed)) => Err(io_other("next-hop request failed")),
            Ok(Err(_)) => Err(io_other("transport task stopped")),
            Err(_) => Err(io_other("send timed out")),
        }
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        let received = self.inbox.lock_unpoisoned().drain();
        let mut envelopes = Vec::with_capacity(received.len());
        for item in received {
            if let Some(receipt) = item.receipt {
                // Ordinary `recv` has no durable endpoint boundary. Refuse
                // custody honestly while still returning the copy; callers
                // that can commit or completely consume it use
                // `recv_staged` and settle the exact handle themselves.
                self.settle_recv(receipt, false).await?;
            }
            envelopes.push(item.envelope);
        }
        Ok(envelopes)
    }

    async fn recv_staged(&self) -> Result<Vec<ReceivedEnvelope>> {
        Ok(self.inbox.lock_unpoisoned().drain())
    }

    async fn settle_recv(&self, receipt: InboundReceipt, accepted: bool) -> Result<()> {
        self.cmds
            .send(Cmd::SettleInbound { receipt, accepted })
            .await
            .map_err(|_| io_other("transport task stopped"))
    }

    async fn recv_transit(&self) -> Result<Vec<Envelope>> {
        Ok(self
            .bridge
            .as_ref()
            .map(|buffer| buffer.lock_unpoisoned().drain())
            .unwrap_or_default())
    }

    fn call_ready(&self, peer: &DeliveryHint) -> bool {
        match peer {
            DeliveryHint::Multiaddr(address) => Libp2pTransport::call_ready(self, address),
            _ => false,
        }
    }

    async fn open_call_stream(&self, peer: &DeliveryHint) -> Result<CallStream> {
        match peer {
            DeliveryHint::Multiaddr(address) => {
                Libp2pTransport::open_call_stream(self, address).await
            }
            _ => Err(TransportError::UnsupportedHint),
        }
    }

    fn try_accept_call_stream(&self) -> Result<Option<CallStream>> {
        Libp2pTransport::try_accept_call_stream(self)
    }
}

/// Requests parked per peer, then issued the moment its connection is up.
type Parked = HashMap<PeerId, Vec<PendingOp>>;

fn outbound_operation_count(
    pending: &Parked,
    inflight: &HashMap<request_response::OutboundRequestId, oneshot::Sender<HopOutcome>>,
    mailbox: &HashMap<request_response::OutboundRequestId, MailboxWaiter>,
) -> usize {
    pending.values().fold(
        inflight.len().saturating_add(mailbox.len()),
        |total, ops| total.saturating_add(ops.len()),
    )
}

fn valid_mailbox_lease_response(
    serving: bool,
    lease_id: [u8; 16],
    expires_at: u64,
    rows: &[crate::mailbox_v2::MailboxV2LeasedRow],
) -> bool {
    let raw_bytes = rows
        .iter()
        .try_fold(0usize, |total, row| total.checked_add(row.envelope.len()));
    let distinct_rows = rows.iter().map(|row| row.row_id).collect::<HashSet<_>>();
    rows.len() <= MAILBOX_V2_PAGE_MAX_ROWS
        && raw_bytes.is_some_and(|bytes| bytes <= MAILBOX_V2_PAGE_MAX_BYTES)
        && distinct_rows.len() == rows.len()
        && rows.iter().all(|row| row.row_id != [0u8; 16])
        && if serving {
            lease_id != [0u8; 16] && expires_at != 0
        } else {
            lease_id == [0u8; 16] && expires_at == 0 && rows.is_empty()
        }
}

/// The local store-and-forward services the swarm task serves, both
/// optional: the mailbox store (docs/05-transports.md §2) and the
/// bridge-transit buffer (ADR-0009).
struct Services {
    mailbox: Option<Arc<Mutex<MailboxV2Store>>>,
    bridge: Option<Arc<Mutex<BridgeBuffer>>>,
}

/// Hand a peer-directed request to the right behaviour, tracking the waiter
/// by the request id it gets back.
fn issue_op(
    swarm: &mut libp2p::Swarm<KultBehaviour>,
    inflight: &mut HashMap<request_response::OutboundRequestId, oneshot::Sender<HopOutcome>>,
    mb_inflight: &mut HashMap<request_response::OutboundRequestId, MailboxWaiter>,
    peer: &PeerId,
    op: PendingOp,
) {
    match op {
        PendingOp::Envelope(bytes, ack) => {
            let id = swarm.behaviour_mut().envelopes.send_request(peer, bytes);
            inflight.insert(id, ack);
        }
        PendingOp::Deposit(bytes, ack) => {
            let id = swarm
                .behaviour_mut()
                .mailbox_v2
                .send_request(peer, MailboxV2Request::Deposit { envelope: bytes });
            mb_inflight.insert(id, MailboxWaiter::Deposit(ack));
        }
        PendingOp::Checkin(tokens, done) => {
            let id = swarm
                .behaviour_mut()
                .mailbox_v2
                .send_request(peer, MailboxV2Request::Lease { tokens });
            mb_inflight.insert(id, MailboxWaiter::Checkin(done));
        }
    }
}

fn settle_call_waiters(
    shared: &Shared,
    peer: &PeerId,
    waiters: &mut HashMap<PeerId, Vec<oneshot::Sender<bool>>>,
    targets: &mut HashMap<PeerId, Multiaddr>,
) {
    if !shared.call_ready(peer) {
        return;
    }
    for done in waiters.remove(peer).unwrap_or_default() {
        let _ = done.send(true);
    }
    targets.remove(peer);
}

fn fail_call_waiters(
    peer: &PeerId,
    waiters: &mut HashMap<PeerId, Vec<oneshot::Sender<bool>>>,
    targets: &mut HashMap<PeerId, Multiaddr>,
) {
    for done in waiters.remove(peer).unwrap_or_default() {
        let _ = done.send(false);
    }
    targets.remove(peer);
}

fn dial_call(
    swarm: &mut libp2p::Swarm<KultBehaviour>,
    peer: PeerId,
    addr: Multiaddr,
    dials: &mut HashMap<ConnectionId, PeerId>,
    waiters: &mut HashMap<PeerId, Vec<oneshot::Sender<bool>>>,
    targets: &mut HashMap<PeerId, Multiaddr>,
) {
    let opts = DialOpts::peer_id(peer)
        .addresses(vec![addr])
        .condition(PeerCondition::Always)
        .build();
    let connection = opts.connection_id();
    match swarm.dial(opts) {
        Ok(()) => {
            dials.insert(connection, peer);
        }
        Err(_) => fail_call_waiters(&peer, waiters, targets),
    }
}

/// The swarm task: owns the libp2p swarm, executes send commands, buffers
/// inbound envelopes, serves the mailbox (when configured), and mirrors
/// connection state into [`Shared`].
async fn run_swarm(
    mut swarm: libp2p::Swarm<KultBehaviour>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    inbox: Arc<Mutex<InternetInbox>>,
    shared: Arc<Shared>,
    services: Services,
    addr_tx: watch::Sender<Vec<Multiaddr>>,
    mut found_rx: mpsc::UnboundedReceiver<DiscoveredPeer>,
) {
    let Services { mailbox, bridge } = &services;
    // Whether the mDNS side is still alive; with discovery off its sender
    // was never handed out, so the first recv settles this immediately.
    let mut mdns_open = true;
    // Requests waiting for a connection to come up, then for the response.
    let mut pending: Parked = HashMap::new();
    let mut inflight: HashMap<request_response::OutboundRequestId, oneshot::Sender<HopOutcome>> =
        HashMap::new();
    let mut mb_inflight: HashMap<request_response::OutboundRequestId, MailboxWaiter> =
        HashMap::new();
    // DHT queries waiting for their final progress event.
    let mut queries: HashMap<kad::QueryId, QueryWaiter> = HashMap::new();
    // Bootstrap joins waiting for their peer's connection to come up.
    let mut joining: HashMap<PeerId, Vec<oneshot::Sender<bool>>> = HashMap::new();
    // Relay reservations waiting for their circuit listener to come up.
    let mut reservations: HashMap<ListenerId, oneshot::Sender<Option<Multiaddr>>> = HashMap::new();
    // Call preparation is separate from normal request dialing: it never
    // falls back from the exact direct-QUIC address supplied by the caller.
    let mut call_waiters: HashMap<PeerId, Vec<oneshot::Sender<bool>>> = HashMap::new();
    let mut call_targets: HashMap<PeerId, Multiaddr> = HashMap::new();
    let mut call_dials: HashMap<ConnectionId, PeerId> = HashMap::new();
    let mut inbound_responses: HashMap<u64, InboundSettlement> = HashMap::new();
    let mut next_inbound_receipt = 1u64;

    loop {
        tokio::select! {
            found = found_rx.recv(), if mdns_open => match found {
                None => mdns_open = false,
                Some(DiscoveredPeer { peer, addrs, ttl }) => {
                    // A LAN announcement seeds the routing table (this is
                    // what makes zero-bootstrap LAN-only DHT work) and is
                    // remembered until its TTL runs out. Connecting right
                    // away lets identify/AutoNAT/Kademlia converge before
                    // anyone has a message to send; failures are just a
                    // peer that left between announcing and now.
                    tracing::debug!(%peer, "mDNS LAN peer announced");
                    let expires = Instant::now() + ttl;
                    {
                        let mut lan = shared.lan_peers.lock_unpoisoned();
                        lan.retain(|_, addrs| {
                            addrs.retain(|_, expiry| *expiry > Instant::now());
                            !addrs.is_empty()
                        });
                        let entry = lan.entry(peer).or_default();
                        for addr in &addrs {
                            entry.insert(addr.clone(), expires);
                        }
                    }
                    for addr in &addrs {
                        swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
                    }
                    let opts = DialOpts::peer_id(peer)
                        .addresses(addrs)
                        .condition(PeerCondition::DisconnectedAndNotDialing)
                        .build();
                    let _ = swarm.dial(opts);
                }
            },
            cmd = cmd_rx.recv() => match cmd {
                // All handles dropped: shut the swarm down.
                None => break,
                Some(Cmd::Bootstrap { peer, addr, done }) => {
                    // "Joined via this peer" means: it is in the routing
                    // table and we reached it. The bootstrap walk itself is
                    // best-effort — kad re-runs it periodically, and a
                    // partial walk (some bucket refresh hitting a dead
                    // node) must not fail the join.
                    swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
                    if swarm.is_connected(&peer) {
                        let _ = swarm.behaviour_mut().kad.bootstrap();
                        let _ = done.send(true);
                    } else {
                        joining.entry(peer).or_default().push(done);
                        let opts = DialOpts::peer_id(peer)
                            .addresses(vec![addr])
                            .condition(PeerCondition::DisconnectedAndNotDialing)
                            .build();
                        match swarm.dial(opts) {
                            Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {}
                            Err(_) => {
                                for done in joining.remove(&peer).unwrap_or_default() {
                                    let _ = done.send(false);
                                }
                            }
                        }
                    }
                }
                Some(Cmd::PutRecord { key, value, done }) => {
                    let record = Record::new(key, value);
                    match swarm.behaviour_mut().kad.put_record(record, Quorum::One) {
                        Ok(id) => {
                            queries.insert(id, QueryWaiter::Put(done));
                        }
                        Err(_) => {
                            let _ = done.send(false);
                        }
                    }
                }
                Some(Cmd::GetRecord { key, done }) => {
                    let id = swarm.behaviour_mut().kad.get_record(key);
                    queries.insert(id, QueryWaiter::Get { values: Vec::new(), done });
                }
                Some(Cmd::Reserve { addr, done }) => {
                    // The relay client transport dials the relay and asks
                    // for the reservation; acceptance surfaces as this
                    // listener's NewListenAddr.
                    match swarm.listen_on(addr) {
                        Ok(id) => {
                            reservations.insert(id, done);
                        }
                        Err(_) => {
                            let _ = done.send(None);
                        }
                    }
                }
                Some(Cmd::NatStatus { done }) => {
                    let status = match swarm.behaviour().autonat.nat_status() {
                        autonat::NatStatus::Public(_) => NatStatus::Public,
                        autonat::NatStatus::Private => NatStatus::Private,
                        autonat::NatStatus::Unknown => NatStatus::Unknown,
                    };
                    let _ = done.send(status);
                }
                Some(Cmd::PrepareCall { peer, addr, done }) => {
                    // Re-validate at the swarm boundary: callers cannot make
                    // this command dial TCP or a circuit address.
                    if !is_direct_quic_addr(&addr) {
                        let _ = done.send(false);
                        continue;
                    }
                    call_waiters.entry(peer).or_default().push(done);
                    call_targets.insert(peer, addr);

                    // `libp2p-stream` chooses a random live connection. Make
                    // the candidate set exclusively direct QUIC before it is
                    // allowed to open a media stream.
                    let connections = shared
                        .connections
                        .lock_unpoisoned()
                        .get(&peer)
                        .cloned()
                        .unwrap_or_default();
                    for (connection, direct) in &connections {
                        if !direct {
                            let _ = swarm.close_connection(*connection);
                        }
                    }
                    if connections.values().any(|direct| *direct) {
                        settle_call_waiters(&shared, &peer, &mut call_waiters, &mut call_targets);
                    } else if !call_dials.values().any(|dialing| dialing == &peer) {
                        dial_call(
                            &mut swarm,
                            peer,
                            call_targets.get(&peer).expect("inserted").clone(),
                            &mut call_dials,
                            &mut call_waiters,
                            &mut call_targets,
                        );
                    }
                }
                Some(Cmd::SettleInbound { receipt, accepted }) => {
                    match inbound_responses.remove(&receipt.value()) {
                        Some(InboundSettlement::Direct(channel)) => {
                            let _ = swarm
                                .behaviour_mut()
                                .envelopes
                                .send_response(channel, accepted);
                        }
                        Some(InboundSettlement::Mailbox {
                            peer,
                            lease_id,
                            row_id,
                        }) if accepted
                            && swarm.is_connected(&peer)
                            && outbound_operation_count(&pending, &inflight, &mb_inflight)
                                < MAX_OUTBOUND_OPERATIONS =>
                        {
                            let request_id = swarm.behaviour_mut().mailbox_v2.send_request(
                                &peer,
                                MailboxV2Request::AckLease {
                                    lease_id,
                                    row_ids: vec![row_id],
                                },
                            );
                            mb_inflight.insert(request_id, MailboxWaiter::Ack);
                        }
                        Some(InboundSettlement::Mailbox { .. }) | None => {}
                    }
                }
                Some(Cmd::Op { peer, addr, op }) => {
                    if outbound_operation_count(&pending, &inflight, &mb_inflight)
                        >= MAX_OUTBOUND_OPERATIONS
                    {
                        op.fail();
                        continue;
                    }
                    if swarm.is_connected(&peer) {
                        issue_op(&mut swarm, &mut inflight, &mut mb_inflight, &peer, op);
                    } else {
                        pending.entry(peer).or_default().push(op);
                        let opts = DialOpts::peer_id(peer)
                            .addresses(vec![addr])
                            .condition(PeerCondition::DisconnectedAndNotDialing)
                            .build();
                        match swarm.dial(opts) {
                            // Already dialing: the pending entry rides along.
                            Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {}
                            Err(_) => {
                                for op in pending.remove(&peer).unwrap_or_default() {
                                    op.fail();
                                }
                            }
                        }
                    }
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { listener_id, address } => {
                    let addrs = {
                        let mut addrs = shared.listen_addrs.lock_unpoisoned();
                        addrs.push(address.clone());
                        addrs.clone()
                    };
                    // Mirror to the mDNS task so it announces the change
                    // (no receiver when discovery is off — fine).
                    let _ = addr_tx.send(addrs);
                    if let Some(done) = reservations.remove(&listener_id) {
                        let _ = done.send(Some(address));
                    }
                }
                // A circuit listener that dies before producing an address
                // is a refused/unreachable reservation; resolve its waiter
                // honestly instead of letting the caller time out.
                SwarmEvent::ListenerClosed { listener_id, .. } => {
                    if let Some(done) = reservations.remove(&listener_id) {
                        let _ = done.send(None);
                    }
                }
                SwarmEvent::ListenerError { listener_id, .. } => {
                    if let Some(done) = reservations.remove(&listener_id) {
                        let _ = done.send(None);
                    }
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    endpoint,
                    ..
                } => {
                    let direct = endpoint_is_direct_quic(&endpoint);
                    tracing::debug!(peer = %peer_id, ?connection_id, direct, "connection established");
                    shared
                        .connections
                        .lock_unpoisoned()
                        .entry(peer_id)
                        .or_default()
                        .insert(connection_id, direct);
                    call_dials.remove(&connection_id);
                    if call_waiters.contains_key(&peer_id) {
                        if !direct {
                            // A fallback connection racing call preparation
                            // is never admitted into the stream candidate set.
                            let _ = swarm.close_connection(connection_id);
                        }
                        settle_call_waiters(
                            &shared,
                            &peer_id,
                            &mut call_waiters,
                            &mut call_targets,
                        );
                    }
                    for op in pending.remove(&peer_id).unwrap_or_default() {
                        issue_op(&mut swarm, &mut inflight, &mut mb_inflight, &peer_id, op);
                    }
                    if let Some(waiters) = joining.remove(&peer_id) {
                        let _ = swarm.behaviour_mut().kad.bootstrap();
                        for done in waiters {
                            let _ = done.send(true);
                        }
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    ..
                } => {
                    tracing::debug!(peer = %peer_id, ?connection_id, "connection closed");
                    {
                        let mut all = shared.connections.lock_unpoisoned();
                        if let Some(connections) = all.get_mut(&peer_id) {
                            connections.remove(&connection_id);
                            if connections.is_empty() {
                                all.remove(&peer_id);
                            }
                        }
                    }
                    if call_waiters.contains_key(&peer_id) {
                        settle_call_waiters(
                            &shared,
                            &peer_id,
                            &mut call_waiters,
                            &mut call_targets,
                        );
                        if call_waiters.contains_key(&peer_id)
                            && !call_dials.values().any(|dialing| dialing == &peer_id)
                        {
                            if let Some(addr) = call_targets.get(&peer_id).cloned() {
                                dial_call(
                                    &mut swarm,
                                    peer_id,
                                    addr,
                                    &mut call_dials,
                                    &mut call_waiters,
                                    &mut call_targets,
                                );
                            }
                        }
                    }
                }
                SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(peer),
                    connection_id,
                    ..
                } => {
                    if call_dials.remove(&connection_id).is_some()
                        && !shared.call_ready(&peer)
                    {
                        fail_call_waiters(&peer, &mut call_waiters, &mut call_targets);
                    }
                    for op in pending.remove(&peer).unwrap_or_default() {
                        op.fail();
                    }
                    for done in joining.remove(&peer).unwrap_or_default() {
                        let _ = done.send(false);
                    }
                }
                SwarmEvent::Behaviour(KultBehaviourEvent::Envelopes(ev)) => match ev {
                    request_response::Event::Message { message, .. } => match message {
                        request_response::Message::Request { request, channel, .. } => {
                            // Decode and RAM budgets are only a prefilter. A
                            // valid direct request remains unanswered until
                            // the endpoint node durably stages or completely
                            // consumes it.
                            match Envelope::decode(&request) {
                                Ok(envelope)
                                    if inbound_responses.len() < DIRECT_INBOX_MAX_ITEMS =>
                                {
                                    let receipt = InboundReceipt::new(next_inbound_receipt);
                                    next_inbound_receipt =
                                        next_inbound_receipt.wrapping_add(1).max(1);
                                    if inbox
                                        .lock_unpoisoned()
                                        .push_direct(envelope, receipt)
                                    {
                                        inbound_responses.insert(
                                            receipt.value(),
                                            InboundSettlement::Direct(channel),
                                        );
                                    } else {
                                        let _ = swarm
                                            .behaviour_mut()
                                            .envelopes
                                            .send_response(channel, false);
                                    }
                                }
                                Ok(_) | Err(_) => {
                                    let _ = swarm
                                        .behaviour_mut()
                                        .envelopes
                                        .send_response(channel, false);
                                }
                            }
                        }
                        request_response::Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some(ack) = inflight.remove(&request_id) {
                                let _ = ack.send(if response {
                                    HopOutcome::Accepted
                                } else {
                                    HopOutcome::Refused
                                });
                            }
                        }
                    },
                    request_response::Event::OutboundFailure { request_id, .. } => {
                        if let Some(ack) = inflight.remove(&request_id) {
                            let _ = ack.send(HopOutcome::LinkFailed);
                        }
                    }
                    _ => {}
                },
                SwarmEvent::Behaviour(KultBehaviourEvent::MailboxV1(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                        request_response::Message::Request { request, channel, .. } => {
                            let response = match (request, mailbox) {
                                (
                                    MailboxRequest::Deposit { envelope },
                                    Some(store),
                                ) if store.lock_unpoisoned().allow_v1_compat() => {
                                    let accepted = Envelope::decode(&envelope)
                                        .ok()
                                        .and_then(|env| {
                                            store
                                                .lock_unpoisoned()
                                                .deposit(
                                                    &peer.to_bytes(),
                                                    &env,
                                                    envelope,
                                                    unix_now(),
                                                )
                                                .ok()
                                        })
                                        .unwrap_or(false);
                                    MailboxResponse::Deposit { accepted }
                                }
                                (
                                    MailboxRequest::Checkin { tokens },
                                    Some(store),
                                ) if store.lock_unpoisoned().allow_v1_compat() =>
                                {
                                    // Explicit compatibility only: v1 has
                                    // no endpoint acknowledgement, so this
                                    // intentionally retains its documented
                                    // delete-before-response risk.
                                    let mut store = store.lock_unpoisoned();
                                    let page = store
                                        .lease(&peer.to_bytes(), &tokens, unix_now())
                                        .ok()
                                        .flatten();
                                    let envelopes = page
                                        .as_ref()
                                        .map(|page| {
                                            page.rows
                                                .iter()
                                                .map(|row| row.envelope.clone())
                                                .collect::<Vec<_>>()
                                        })
                                        .unwrap_or_default();
                                    if let Some(page) = page {
                                        let row_ids: Vec<[u8; 16]> =
                                            page.rows.iter().map(|row| row.row_id).collect();
                                        if !row_ids.is_empty() {
                                            let _ = store.ack(
                                                &peer.to_bytes(),
                                                page.lease_id,
                                                &row_ids,
                                                unix_now(),
                                            );
                                        }
                                    }
                                    MailboxResponse::Checkin {
                                        serving: true,
                                        envelopes,
                                    }
                                }
                                (MailboxRequest::Deposit { .. }, _) => {
                                    MailboxResponse::Deposit { accepted: false }
                                }
                                (MailboxRequest::Checkin { .. }, _) => {
                                    MailboxResponse::Checkin {
                                        serving: false,
                                        envelopes: Vec::new(),
                                    }
                                }
                            };
                            let _ = swarm
                                .behaviour_mut()
                                .mailbox_v1
                                .send_response(channel, response);
                        }
                        request_response::Message::Response { .. } => {}
                },
                SwarmEvent::Behaviour(KultBehaviourEvent::MailboxV1(_)) => {}
                SwarmEvent::Behaviour(KultBehaviourEvent::MailboxV2(ev)) => match ev {
                    request_response::Event::Message { peer, message, .. } => match message {
                        request_response::Message::Request { request, channel, .. } => {
                            let response = match request {
                                MailboxV2Request::Deposit { envelope } => {
                                    let accepted = match Envelope::decode(&envelope) {
                                        Ok(env) => {
                                            let now = unix_now();
                                            let disposition = mailbox.as_ref().map(|store| {
                                                store.lock_unpoisoned().deposit_disposition(
                                                    &peer.to_bytes(),
                                                    &env,
                                                    envelope.clone(),
                                                    now,
                                                )
                                            });
                                            match disposition {
                                                Some(Ok(MailboxDepositDisposition::Accepted)) => {
                                                    true
                                                }
                                                Some(Ok(
                                                    MailboxDepositDisposition::Unregistered,
                                                ))
                                                | None => {
                                                    if let Some(buffer) = bridge.as_ref() {
                                                        let _ = buffer.lock_unpoisoned().push(
                                                            env,
                                                            envelope.len(),
                                                            now,
                                                        );
                                                    }
                                                    false
                                                }
                                                Some(Ok(MailboxDepositDisposition::Refused))
                                                | Some(Err(_)) => false,
                                            }
                                        }
                                        Err(_) => {
                                            if let Some(store) = mailbox.as_ref() {
                                                let _ = store
                                                    .lock_unpoisoned()
                                                    .refuse_deposit_request(
                                                        &peer.to_bytes(),
                                                        unix_now(),
                                                    );
                                            }
                                            false
                                        }
                                    };
                                    MailboxV2Response::Deposit { accepted }
                                }
                                MailboxV2Request::Lease { tokens } => {
                                    match mailbox.as_ref().and_then(|store| {
                                        store
                                            .lock_unpoisoned()
                                            .lease(&peer.to_bytes(), &tokens, unix_now())
                                            .ok()
                                            .flatten()
                                    }) {
                                        Some(page) => MailboxV2Response::Lease {
                                            serving: true,
                                            lease_id: page.lease_id,
                                            expires_at: page.expires_at,
                                            rows: page.rows,
                                        },
                                        None => MailboxV2Response::Lease {
                                            serving: false,
                                            lease_id: [0u8; 16],
                                            expires_at: 0,
                                            rows: Vec::new(),
                                        },
                                    }
                                }
                                MailboxV2Request::AckLease { lease_id, row_ids } => {
                                    let accepted = mailbox.as_ref().is_some_and(|store| {
                                        store
                                            .lock_unpoisoned()
                                            .ack(
                                                &peer.to_bytes(),
                                                lease_id,
                                                &row_ids,
                                                unix_now(),
                                            )
                                            .unwrap_or(false)
                                    });
                                    MailboxV2Response::AckLease { accepted }
                                }
                            };
                            let _ = swarm
                                .behaviour_mut()
                                .mailbox_v2
                                .send_response(channel, response);
                        }
                        request_response::Message::Response { request_id, response } => {
                            match (mb_inflight.remove(&request_id), response) {
                                (
                                    Some(MailboxWaiter::Deposit(ack)),
                                    MailboxV2Response::Deposit { accepted },
                                ) => {
                                    let _ = ack.send(if accepted {
                                        HopOutcome::Accepted
                                    } else {
                                        HopOutcome::Refused
                                    });
                                }
                                (
                                    Some(MailboxWaiter::Checkin(done)),
                                    MailboxV2Response::Lease {
                                        serving,
                                        lease_id,
                                        expires_at,
                                        rows,
                                    },
                                ) => {
                                    if !valid_mailbox_lease_response(
                                        serving, lease_id, expires_at, &rows,
                                    ) {
                                        let _ = done.send(None);
                                        continue;
                                    }
                                    let mut count = 0usize;
                                    let mut inbox = inbox.lock_unpoisoned();
                                    for row in rows {
                                        let Ok(envelope) = Envelope::decode(&row.envelope) else {
                                            continue;
                                        };
                                        if inbound_responses.len()
                                            >= DIRECT_INBOX_MAX_ITEMS + COLLECTED_INBOX_MAX_ITEMS
                                        {
                                            break;
                                        }
                                        let receipt =
                                            InboundReceipt::new(next_inbound_receipt);
                                        next_inbound_receipt =
                                            next_inbound_receipt.wrapping_add(1).max(1);
                                        if inbox.push_collected(envelope, receipt) {
                                            inbound_responses.insert(
                                                receipt.value(),
                                                InboundSettlement::Mailbox {
                                                    peer,
                                                    lease_id,
                                                    row_id: row.row_id,
                                                },
                                            );
                                            count += 1;
                                        }
                                    }
                                    let _ = done.send(serving.then_some(count));
                                }
                                (
                                    Some(MailboxWaiter::Ack),
                                    MailboxV2Response::AckLease { .. },
                                ) => {}
                                (Some(waiter), _) => waiter.fail(),
                                (None, _) => {}
                            }
                        }
                    },
                    request_response::Event::OutboundFailure { request_id, .. } => {
                        if let Some(waiter) = mb_inflight.remove(&request_id) {
                            waiter.fail();
                        }
                    }
                    _ => {}
                },
                SwarmEvent::Behaviour(KultBehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    // Feed identified listen addresses into the routing
                    // table so the DHT can walk beyond explicitly
                    // configured peers.
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
                SwarmEvent::Behaviour(KultBehaviourEvent::Kad(
                    kad::Event::OutboundQueryProgressed { id, result, step, .. },
                )) => {
                    match (queries.remove(&id), result) {
                        (Some(QueryWaiter::Put(done)), QueryResult::PutRecord(res)) => {
                            if step.last {
                                let _ = done.send(res.is_ok());
                            } else {
                                queries.insert(id, QueryWaiter::Put(done));
                            }
                        }
                        (Some(QueryWaiter::Get { mut values, done }), QueryResult::GetRecord(res)) => {
                            if let Ok(GetRecordOk::FoundRecord(found)) = res {
                                values.push(found.record.value);
                            }
                            if step.last {
                                let _ = done.send(values);
                            } else {
                                queries.insert(id, QueryWaiter::Get { values, done });
                            }
                        }
                        // Query kinds we never issued, or a waiter/result
                        // mismatch: nothing to resolve.
                        (waiter, _) => {
                            if let (Some(w), false) = (waiter, step.last) {
                                queries.insert(id, w);
                            }
                        }
                    }
                }
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_protocol::{EnvelopeKind, ENVELOPE_V1_HEADER_LEN};

    fn small_envelope(fill: u8) -> Envelope {
        Envelope::new(EnvelopeKind::Message, [fill; 32], vec![fill; 8])
    }

    #[test]
    fn direct_inbox_item_cap_refuses_without_mutation_and_recovers_after_drain() {
        let mut inbox = InternetInbox::new();
        for i in 0..DIRECT_INBOX_MAX_ITEMS {
            assert!(inbox.push_direct(small_envelope(i as u8), InboundReceipt::new(i as u64 + 1)));
        }
        let items = inbox.direct_items;
        let bytes = inbox.direct_bytes;
        assert!(!inbox.push_direct(small_envelope(255), InboundReceipt::new(10_000)));
        assert_eq!(inbox.direct_items, items);
        assert_eq!(inbox.direct_bytes, bytes);

        assert_eq!(inbox.drain().len(), DIRECT_INBOX_MAX_ITEMS);
        assert!(inbox.push_direct(small_envelope(1), InboundReceipt::new(1)));
    }

    #[test]
    fn direct_inbox_byte_cap_bounds_maximal_envelopes() {
        let mut inbox = InternetInbox::new();
        let oversized = Envelope::new(EnvelopeKind::Message, [6; 32], vec![0; MAX_ENVELOPE_BYTES]);
        assert!(!inbox.push_direct(oversized, InboundReceipt::new(2)));

        let maximal = Envelope::new(
            EnvelopeKind::Message,
            [7; 32],
            vec![0; MAX_ENVELOPE_BYTES - ENVELOPE_V1_HEADER_LEN],
        );
        let count = DIRECT_INBOX_MAX_BYTES / MAX_ENVELOPE_BYTES;
        for i in 0..count {
            assert!(inbox.push_direct(maximal.clone(), InboundReceipt::new(i as u64 + 1)));
        }
        assert_eq!(inbox.direct_bytes, DIRECT_INBOX_MAX_BYTES);
        assert!(!inbox.push_direct(small_envelope(8), InboundReceipt::new(10_000)));
    }

    #[test]
    fn collected_inbox_has_independent_item_cap_and_recovers_after_drain() {
        let mut inbox = InternetInbox::new();
        for i in 0..COLLECTED_INBOX_MAX_ITEMS {
            assert!(
                inbox.push_collected(small_envelope(i as u8), InboundReceipt::new(i as u64 + 1),)
            );
        }
        assert!(!inbox.push_collected(small_envelope(3), InboundReceipt::new(10_000),));
        assert_eq!(inbox.drain().len(), COLLECTED_INBOX_MAX_ITEMS);
        assert!(inbox.push_collected(small_envelope(4), InboundReceipt::new(10_001),));
    }

    #[test]
    fn mailbox_lease_response_shape_rejects_malformed_or_unbounded_pages() {
        use crate::mailbox_v2::MailboxV2LeasedRow;

        assert!(valid_mailbox_lease_response(true, [1; 16], 10, &[]));
        assert!(valid_mailbox_lease_response(false, [0; 16], 0, &[]));
        assert!(!valid_mailbox_lease_response(true, [0; 16], 10, &[]));
        assert!(!valid_mailbox_lease_response(false, [1; 16], 0, &[]));

        let row = MailboxV2LeasedRow {
            row_id: [2; 16],
            envelope: vec![3],
        };
        assert!(valid_mailbox_lease_response(
            true,
            [1; 16],
            10,
            std::slice::from_ref(&row)
        ));
        assert!(!valid_mailbox_lease_response(
            true,
            [1; 16],
            10,
            &[row.clone(), row]
        ));
        assert!(!valid_mailbox_lease_response(
            true,
            [1; 16],
            10,
            &[MailboxV2LeasedRow {
                row_id: [0; 16],
                envelope: vec![3],
            }]
        ));
        assert!(!valid_mailbox_lease_response(
            true,
            [1; 16],
            10,
            &[MailboxV2LeasedRow {
                row_id: [4; 16],
                envelope: vec![0; MAILBOX_V2_PAGE_MAX_BYTES + 1],
            }]
        ));
        let too_many = (1..=MAILBOX_V2_PAGE_MAX_ROWS + 1)
            .map(|index| MailboxV2LeasedRow {
                row_id: (index as u128).to_be_bytes(),
                envelope: vec![0],
            })
            .collect::<Vec<_>>();
        assert!(!valid_mailbox_lease_response(true, [1; 16], 10, &too_many));
    }

    #[test]
    fn mailbox_service_identity_is_separate_and_stable_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let config =
            MailboxServiceConfig::in_directory(directory.path(), crate::MailboxConfig::default());
        assert_ne!(config.transport_key_path, config.key_path);
        let first = load_or_create_service_identity(&config.transport_key_path).unwrap();
        let second = load_or_create_service_identity(&config.transport_key_path).unwrap();
        assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&config.transport_key_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn mailbox_service_identity_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let config =
            MailboxServiceConfig::in_directory(directory.path(), crate::MailboxConfig::default());
        let target = directory.path().join("transport-key-target");
        std::fs::File::create(&target).unwrap();
        symlink(&target, &config.transport_key_path).unwrap();
        assert!(load_or_create_service_identity(&config.transport_key_path).is_err());
    }
}
