//! The internet transport (docs/05-transports.md §2): rust-libp2p with QUIC
//! as the primary link protocol and TCP+Noise+Yamux as the fallback.
//!
//! Envelopes travel over a dedicated request-response protocol
//! (`/kommskult/envelope/1`); the response is an empty acknowledgment, so a
//! successful send honestly reports [`SendReceipt::AckedByNextHop`] — never
//! end-to-end delivery (only encrypted receipts prove that).
//!
//! Contract compliance (docs/05-transports.md §1): the swarm identity is a
//! transport-layer keypair generated fresh per instance — **never** the kult
//! identity; peers are addressed by multiaddr hints; link encryption
//! (QUIC-TLS / Noise) is additive, not load-bearing.
//!
//! The discovery plane (docs/05-transports.md §2) also lives here: a
//! Kademlia DHT (`/kommskult/kad/1`) storing prekey-bundle records, exposed
//! through the transport-agnostic [`Discovery`] trait. Records are served
//! as untrusted bytes — bundles are self-authenticating and verified by the
//! caller, so a malicious DHT node can at worst withhold, never forge.
//! Bootstrap follows the spec's "defaults, not dependencies" rule:
//! [`Libp2pTransport::bootstrap`] takes whatever peers the *user* configures
//! — nothing is hardcoded, and any reachable peer will do.
//!
//! Mailbox relays (docs/05-transports.md §2) ride a second request-response
//! protocol (`/kommskult/mailbox/1`): any node started with
//! [`Libp2pTransport::with_mailbox`] serves store-and-forward for offline
//! recipients, who register rotating delivery tokens as accept-filters and
//! collect on reconnect ([`Libp2pTransport::mailbox_checkin`]). Senders
//! reach a mailbox through [`DeliveryHint::Relay`] — a deposit the relay
//! accepted is, honestly, [`SendReceipt::AckedByNextHop`] and nothing more.
//!
//! Remaining M3 pieces that layer on top of this carrier: AutoNAT + DCUtR
//! hole punching, the headless daemon — and mDNS LAN auto-discovery, which
//! is deliberately deferred until `libp2p-mdns` moves off the
//! RUSTSEC-flagged `hickory-proto 0.25` (LAN delivery works today with
//! explicit multiaddr hints).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, GetRecordOk, Mode, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use tokio::sync::{mpsc, oneshot};

use kult_protocol::Envelope;

use crate::mailbox::{MailboxContents, MailboxRequest, MailboxResponse, MailboxStore};
use crate::{
    CostClass, DeliveryHint, Discovery, LatencyClass, LinkProfile, MailboxConfig, Reachability,
    Result, SendReceipt, Transport, TransportError,
};

/// How long a send waits for the next hop's acknowledgment before reporting
/// failure to the delivery engine (which then retries with backoff).
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

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

#[derive(NetworkBehaviour)]
struct KultBehaviour {
    envelopes: request_response::cbor::Behaviour<Vec<u8>, ()>,
    mailbox: request_response::cbor::Behaviour<MailboxRequest, MailboxResponse>,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
}

/// A request aimed at a specific peer, parked while its connection dials.
enum PendingOp {
    /// Direct envelope delivery; reports next-hop ack.
    Envelope(Vec<u8>, oneshot::Sender<bool>),
    /// Mailbox deposit of encoded envelope bytes; reports acceptance.
    Deposit(Vec<u8>, oneshot::Sender<bool>),
    /// Mailbox check-in; reports collected-envelope count, `None` on
    /// refusal or link failure.
    Checkin(Vec<[u8; 32]>, oneshot::Sender<Option<usize>>),
}

impl PendingOp {
    /// Resolve the waiter with the failure outcome (dial failed, link died).
    fn fail(self) {
        match self {
            Self::Envelope(_, ack) | Self::Deposit(_, ack) => {
                let _ = ack.send(false);
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
}

/// In-flight mailbox requests awaiting their response.
enum MailboxWaiter {
    Deposit(oneshot::Sender<bool>),
    Checkin(oneshot::Sender<Option<usize>>),
}

impl MailboxWaiter {
    /// Resolve with the failure outcome (link failure, malformed response).
    fn fail(self) {
        match self {
            Self::Deposit(ack) => {
                let _ = ack.send(false);
            }
            Self::Checkin(done) => {
                let _ = done.send(None);
            }
        }
    }
}

/// In-flight DHT queries awaiting their final `OutboundQueryProgressed`.
enum QueryWaiter {
    Put(oneshot::Sender<bool>),
    Get {
        values: Vec<Vec<u8>>,
        done: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

struct Shared {
    local_peer_id: PeerId,
    listen_addrs: Mutex<Vec<Multiaddr>>,
    connected: Mutex<HashSet<PeerId>>,
}

/// Internet carrier: QUIC (primary) and TCP (fallback) via rust-libp2p.
pub struct Libp2pTransport {
    cmds: mpsc::UnboundedSender<Cmd>,
    inbox: Arc<Mutex<Vec<Envelope>>>,
    shared: Arc<Shared>,
    mailbox: Option<Arc<Mutex<MailboxStore>>>,
}

impl Libp2pTransport {
    /// Start a transport listening on the given multiaddrs (e.g.
    /// `/ip4/0.0.0.0/udp/0/quic-v1` and `/ip4/0.0.0.0/tcp/0`). Spawns the
    /// swarm onto the ambient tokio runtime; dropping the transport stops it.
    ///
    /// The swarm keypair is generated fresh — a per-instance transport
    /// pseudonym, deliberately unlinked to any kult identity.
    pub async fn new(listen: &[&str]) -> Result<Self> {
        Self::build(listen, None).await
    }

    /// Like [`Libp2pTransport::new`], but this node also serves mailboxes
    /// (docs/05-transports.md §2): store-and-forward for offline recipients,
    /// bounded by `config`. Any ordinary node can volunteer.
    pub async fn with_mailbox(listen: &[&str], config: MailboxConfig) -> Result<Self> {
        Self::build(listen, Some(config)).await
    }

    async fn build(listen: &[&str], mailbox: Option<MailboxConfig>) -> Result<Self> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(io_other)?
            .with_quic()
            .with_behaviour(|key| {
                let envelopes = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/kommskult/envelope/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );
                let mailbox = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/kommskult/mailbox/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );
                let peer_id = key.public().to_peer_id();
                let kad = kad::Behaviour::with_config(
                    peer_id,
                    MemoryStore::new(peer_id),
                    kad::Config::new(StreamProtocol::new("/kommskult/kad/1")),
                );
                // Identify carries only the transport pseudonym and listen
                // addresses — it is how DHT peers learn where to reach each
                // other; the kult identity never appears on this layer.
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/kommskult/1".into(),
                    key.public(),
                ));
                Ok(KultBehaviour {
                    envelopes,
                    mailbox,
                    kad,
                    identify,
                })
            })
            .map_err(io_other)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
            .build();

        // Every node serves DHT records — there is no client/server split to
        // centralize around (docs/01-why.md). AutoNAT-driven auto mode can
        // replace this once the NAT-traversal slice lands.
        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

        for addr in listen {
            let addr: Multiaddr = addr.parse().map_err(io_other)?;
            swarm.listen_on(addr).map_err(io_other)?;
        }

        let shared = Arc::new(Shared {
            local_peer_id: *swarm.local_peer_id(),
            listen_addrs: Mutex::new(Vec::new()),
            connected: Mutex::new(HashSet::new()),
        });
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let mailbox = mailbox.map(|config| Arc::new(Mutex::new(MailboxStore::new(config))));
        let (cmds, cmd_rx) = mpsc::unbounded_channel();

        tokio::spawn(run_swarm(
            swarm,
            cmd_rx,
            Arc::clone(&inbox),
            Arc::clone(&shared),
            mailbox.clone(),
        ));

        Ok(Self {
            cmds,
            inbox,
            shared,
            mailbox,
        })
    }

    /// This transport's peer id (the per-instance transport pseudonym).
    pub fn local_peer_id(&self) -> String {
        self.shared.local_peer_id.to_string()
    }

    /// Current listen addresses, each with the peer id appended — exactly
    /// the strings peers store as [`DeliveryHint::Multiaddr`] for us.
    pub fn listen_addrs(&self) -> Vec<String> {
        let id = self.shared.local_peer_id;
        self.shared
            .listen_addrs
            .lock()
            .expect("lock")
            .iter()
            .map(|a| format!("{a}/p2p/{id}"))
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
    /// `tokens` as this node's accept-filters and collect everything queued
    /// under them into the normal receive path ([`Transport::recv`]).
    /// Returns how many envelopes were collected; a large backlog may take
    /// several check-ins, so call until it returns 0. Errors are honest: the
    /// relay was unreachable, or does not serve mailboxes.
    ///
    /// Build the token set with `kult-node`'s `mailbox_tokens` — every token
    /// in it is scoped to the caller as recipient (ADR-0007), which is what
    /// makes collect-and-delete safe on relays shared with one's peers.
    pub async fn mailbox_checkin(&self, relay: &str, tokens: &[[u8; 32]]) -> Result<usize> {
        let (addr, peer) = parse_addr(relay).ok_or(TransportError::UnsupportedHint)?;
        let (done, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Op {
                peer,
                addr,
                op: PendingOp::Checkin(tokens.to_vec(), done),
            })
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, rx).await {
            Ok(Ok(Some(count))) => Ok(count),
            Ok(Ok(None)) => Err(io_other("relay unreachable or not serving mailboxes")),
            Ok(Err(_)) => Err(io_other("transport task stopped")),
            Err(_) => Err(io_other("mailbox check-in timed out")),
        }
    }

    /// What this node's mailbox service currently stores, per token — relay
    /// operator transparency, and the hook for the M3 inspection test
    /// ("relay observably stores only sealed envelopes"). `None` when this
    /// node serves no mailboxes.
    pub fn mailbox_contents(&self) -> Option<MailboxContents> {
        self.mailbox
            .as_ref()
            .map(|store| store.lock().expect("lock").contents())
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

/// A usable address is a multiaddr carrying an explicit `/p2p/<peer-id>`.
fn parse_addr(s: &str) -> Option<(Multiaddr, PeerId)> {
    let addr: Multiaddr = s.parse().ok()?;
    let peer = addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })?;
    Some((addr, peer))
}

/// Current Unix time, for the mailbox service's TTL accounting. The mailbox
/// lives at the I/O layer, so the wall clock is the right clock here.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl Transport for Libp2pTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            // Practical ceiling per docs/05-transports.md §6; the codec caps
            // requests well above this.
            mtu: 64 * 1024,
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
        let (ack_tx, ack_rx) = oneshot::channel();
        let op = if deposit {
            PendingOp::Deposit(envelope.encode(), ack_tx)
        } else {
            PendingOp::Envelope(envelope.encode(), ack_tx)
        };
        self.cmds
            .send(Cmd::Op { peer, addr, op })
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, ack_rx).await {
            // Both outcomes are the same honest signal: the next hop — the
            // peer itself, or its mailbox relay — acknowledged receipt.
            Ok(Ok(true)) => Ok(SendReceipt::AckedByNextHop),
            Ok(_) => Err(io_other("peer unreachable or refused the envelope")),
            Err(_) => Err(io_other("send timed out")),
        }
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        Ok(self.inbox.lock().expect("lock").drain(..).collect())
    }
}

/// Requests parked per peer, then issued the moment its connection is up.
type Parked = HashMap<PeerId, Vec<PendingOp>>;

/// Hand a peer-directed request to the right behaviour, tracking the waiter
/// by the request id it gets back.
fn issue_op(
    swarm: &mut libp2p::Swarm<KultBehaviour>,
    inflight: &mut HashMap<request_response::OutboundRequestId, oneshot::Sender<bool>>,
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
                .mailbox
                .send_request(peer, MailboxRequest::Deposit { envelope: bytes });
            mb_inflight.insert(id, MailboxWaiter::Deposit(ack));
        }
        PendingOp::Checkin(tokens, done) => {
            let id = swarm
                .behaviour_mut()
                .mailbox
                .send_request(peer, MailboxRequest::Checkin { tokens });
            mb_inflight.insert(id, MailboxWaiter::Checkin(done));
        }
    }
}

/// The swarm task: owns the libp2p swarm, executes send commands, buffers
/// inbound envelopes, serves the mailbox (when configured), and mirrors
/// connection state into [`Shared`].
async fn run_swarm(
    mut swarm: libp2p::Swarm<KultBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    inbox: Arc<Mutex<Vec<Envelope>>>,
    shared: Arc<Shared>,
    mailbox: Option<Arc<Mutex<MailboxStore>>>,
) {
    // Requests waiting for a connection to come up, then for the response.
    let mut pending: Parked = HashMap::new();
    let mut inflight: HashMap<request_response::OutboundRequestId, oneshot::Sender<bool>> =
        HashMap::new();
    let mut mb_inflight: HashMap<request_response::OutboundRequestId, MailboxWaiter> =
        HashMap::new();
    // DHT queries waiting for their final progress event.
    let mut queries: HashMap<kad::QueryId, QueryWaiter> = HashMap::new();
    // Bootstrap joins waiting for their peer's connection to come up.
    let mut joining: HashMap<PeerId, Vec<oneshot::Sender<bool>>> = HashMap::new();

    loop {
        tokio::select! {
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
                Some(Cmd::Op { peer, addr, op }) => {
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
                SwarmEvent::NewListenAddr { address, .. } => {
                    shared.listen_addrs.lock().expect("lock").push(address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    shared.connected.lock().expect("lock").insert(peer_id);
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
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    if num_established == 0 {
                        shared.connected.lock().expect("lock").remove(&peer_id);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), .. } => {
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
                            // Parse failures are dropped silently: transports
                            // carry sealed envelopes, nothing else.
                            if let Ok(env) = Envelope::decode(&request) {
                                inbox.lock().expect("lock").push(env);
                            }
                            let _ = swarm.behaviour_mut().envelopes.send_response(channel, ());
                        }
                        request_response::Message::Response { request_id, .. } => {
                            if let Some(ack) = inflight.remove(&request_id) {
                                let _ = ack.send(true);
                            }
                        }
                    },
                    request_response::Event::OutboundFailure { request_id, .. } => {
                        if let Some(ack) = inflight.remove(&request_id) {
                            let _ = ack.send(false);
                        }
                    }
                    _ => {}
                },
                SwarmEvent::Behaviour(KultBehaviourEvent::Mailbox(ev)) => match ev {
                    request_response::Event::Message { message, .. } => match message {
                        request_response::Message::Request { request, channel, .. } => {
                            let response = match (request, &mailbox) {
                                // Serving: deposits are validated as sealed
                                // envelopes (a mailbox stores nothing else)
                                // and filed under their delivery token.
                                (MailboxRequest::Deposit { envelope }, Some(store)) => {
                                    let accepted = match Envelope::decode(&envelope) {
                                        Ok(env) => store
                                            .lock()
                                            .expect("lock")
                                            .deposit(env.token, envelope, unix_now()),
                                        Err(_) => false,
                                    };
                                    MailboxResponse::Deposit { accepted }
                                }
                                (MailboxRequest::Checkin { tokens }, Some(store)) => {
                                    MailboxResponse::Checkin {
                                        serving: true,
                                        envelopes: store
                                            .lock()
                                            .expect("lock")
                                            .checkin(&tokens, unix_now()),
                                    }
                                }
                                // Not serving: honest refusals.
                                (MailboxRequest::Deposit { .. }, None) => {
                                    MailboxResponse::Deposit { accepted: false }
                                }
                                (MailboxRequest::Checkin { .. }, None) => {
                                    MailboxResponse::Checkin {
                                        serving: false,
                                        envelopes: Vec::new(),
                                    }
                                }
                            };
                            let _ = swarm.behaviour_mut().mailbox.send_response(channel, response);
                        }
                        request_response::Message::Response { request_id, response } => {
                            match (mb_inflight.remove(&request_id), response) {
                                (
                                    Some(MailboxWaiter::Deposit(ack)),
                                    MailboxResponse::Deposit { accepted },
                                ) => {
                                    let _ = ack.send(accepted);
                                }
                                (
                                    Some(MailboxWaiter::Checkin(done)),
                                    MailboxResponse::Checkin { serving, envelopes },
                                ) => {
                                    // Collected mail joins the normal receive
                                    // path; parse failures are dropped, as on
                                    // any link.
                                    let mut count = 0;
                                    let mut inbox = inbox.lock().expect("lock");
                                    for bytes in envelopes {
                                        if let Ok(env) = Envelope::decode(&bytes) {
                                            inbox.push(env);
                                            count += 1;
                                        }
                                    }
                                    let _ = done.send(serving.then_some(count));
                                }
                                // A response of the wrong shape: fail the
                                // waiter rather than hang its caller.
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
