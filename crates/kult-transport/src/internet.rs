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
//! Remaining M3 pieces that layer on top of this carrier: Kademlia prekey
//! records, relay-v2 mailboxes, DCUtR hole punching — and mDNS LAN
//! auto-discovery, which is deliberately deferred until `libp2p-mdns` moves
//! off the RUSTSEC-flagged `hickory-proto 0.25` (LAN delivery works today
//! with explicit multiaddr hints).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use tokio::sync::{mpsc, oneshot};

use kult_protocol::Envelope;

use crate::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, Result, SendReceipt,
    Transport, TransportError,
};

/// How long a send waits for the next hop's acknowledgment before reporting
/// failure to the delivery engine (which then retries with backoff).
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// Idle connections linger briefly so a message burst reuses one connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(NetworkBehaviour)]
struct KultBehaviour {
    envelopes: request_response::cbor::Behaviour<Vec<u8>, ()>,
}

enum Cmd {
    Send {
        peer: PeerId,
        addr: Multiaddr,
        bytes: Vec<u8>,
        ack: oneshot::Sender<bool>,
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
}

impl Libp2pTransport {
    /// Start a transport listening on the given multiaddrs (e.g.
    /// `/ip4/0.0.0.0/udp/0/quic-v1` and `/ip4/0.0.0.0/tcp/0`). Spawns the
    /// swarm onto the ambient tokio runtime; dropping the transport stops it.
    ///
    /// The swarm keypair is generated fresh — a per-instance transport
    /// pseudonym, deliberately unlinked to any kult identity.
    pub async fn new(listen: &[&str]) -> Result<Self> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(io_other)?
            .with_quic()
            .with_behaviour(|_key| {
                let envelopes = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/kommskult/envelope/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );
                Ok(KultBehaviour { envelopes })
            })
            .map_err(io_other)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
            .build();

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
        let (cmds, cmd_rx) = mpsc::unbounded_channel();

        tokio::spawn(run_swarm(
            swarm,
            cmd_rx,
            Arc::clone(&inbox),
            Arc::clone(&shared),
        ));

        Ok(Self {
            cmds,
            inbox,
            shared,
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
}

fn io_other(e: impl std::fmt::Display) -> TransportError {
    TransportError::Io(io::Error::other(e.to_string()))
}

/// A usable hint is a multiaddr carrying an explicit `/p2p/<peer-id>`.
fn parse_hint(hint: &DeliveryHint) -> Option<(Multiaddr, PeerId)> {
    let DeliveryHint::Multiaddr(s) = hint else {
        return None;
    };
    let addr: Multiaddr = s.parse().ok()?;
    let peer = addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })?;
    Some((addr, peer))
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
        match parse_hint(peer) {
            // Either already connected or dialable on demand — both are
            // immediate at internet latency; failures surface from send()
            // and feed the delivery engine's backoff.
            Some(_) => Reachability::Now,
            None => Reachability::Unreachable,
        }
    }

    async fn send(&self, peer: &DeliveryHint, envelope: &Envelope) -> Result<SendReceipt> {
        let (addr, peer) = parse_hint(peer).ok_or(TransportError::UnsupportedHint)?;
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Send {
                peer,
                addr,
                bytes: envelope.encode(),
                ack: ack_tx,
            })
            .map_err(|_| io_other("transport task stopped"))?;
        match tokio::time::timeout(SEND_TIMEOUT, ack_rx).await {
            Ok(Ok(true)) => Ok(SendReceipt::AckedByNextHop),
            Ok(_) => Err(io_other("peer unreachable or refused the envelope")),
            Err(_) => Err(io_other("send timed out")),
        }
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        Ok(self.inbox.lock().expect("lock").drain(..).collect())
    }
}

/// Envelope bytes plus the channel that reports ack/failure to `send()`.
type PendingSend = (Vec<u8>, oneshot::Sender<bool>);

/// The swarm task: owns the libp2p swarm, executes send commands, buffers
/// inbound envelopes, and mirrors connection state into [`Shared`].
async fn run_swarm(
    mut swarm: libp2p::Swarm<KultBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    inbox: Arc<Mutex<Vec<Envelope>>>,
    shared: Arc<Shared>,
) {
    // Sends waiting for a connection to come up, then for the ack.
    let mut pending: HashMap<PeerId, Vec<PendingSend>> = HashMap::new();
    let mut inflight: HashMap<request_response::OutboundRequestId, oneshot::Sender<bool>> =
        HashMap::new();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                // All handles dropped: shut the swarm down.
                None => break,
                Some(Cmd::Send { peer, addr, bytes, ack }) => {
                    if swarm.is_connected(&peer) {
                        let id = swarm.behaviour_mut().envelopes.send_request(&peer, bytes);
                        inflight.insert(id, ack);
                    } else {
                        pending.entry(peer).or_default().push((bytes, ack));
                        let opts = DialOpts::peer_id(peer)
                            .addresses(vec![addr])
                            .condition(PeerCondition::DisconnectedAndNotDialing)
                            .build();
                        match swarm.dial(opts) {
                            // Already dialing: the pending entry rides along.
                            Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {}
                            Err(_) => {
                                for (_, ack) in pending.remove(&peer).unwrap_or_default() {
                                    let _ = ack.send(false);
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
                    for (bytes, ack) in pending.remove(&peer_id).unwrap_or_default() {
                        let id = swarm.behaviour_mut().envelopes.send_request(&peer_id, bytes);
                        inflight.insert(id, ack);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    if num_established == 0 {
                        shared.connected.lock().expect("lock").remove(&peer_id);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer), .. } => {
                    for (_, ack) in pending.remove(&peer).unwrap_or_default() {
                        let _ = ack.send(false);
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
                _ => {}
            },
        }
    }
}
