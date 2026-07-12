//! M4 internet↔mesh bridging policies (docs/05-transports.md §4.2 rule 5,
//! ADR-0009), exercised over in-memory mock links: token-blind capture,
//! deposit-with-backoff toward relays, bounded mesh flooding, split
//! horizon, dedup, and every cap — no radios, no sockets.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_node::Node;
use kult_protocol::{epoch_day, intro_token, Envelope, EnvelopeKind};
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only.
const TEST_KDF: kult_crypto::KdfProfile = kult_crypto::KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// A configurable mock carrier: records every send, can be told to refuse
/// sends, and lets tests inject inbound and transit envelopes.
struct MockLink {
    cost: CostClass,
    mtu: usize,
    broadcast: Option<DeliveryHint>,
    inbox: Arc<Mutex<Vec<Envelope>>>,
    transit: Arc<Mutex<Vec<Envelope>>>,
    sent: Arc<Mutex<Vec<(DeliveryHint, Envelope)>>>,
    refuse: Arc<Mutex<bool>>,
}

impl MockLink {
    /// An airtime-class broadcast link (the mesh side).
    fn mesh(mtu: usize) -> Self {
        Self {
            cost: CostClass::Airtime,
            mtu,
            broadcast: Some(DeliveryHint::MeshNode(u32::MAX)),
            inbox: Arc::default(),
            transit: Arc::default(),
            sent: Arc::default(),
            refuse: Arc::default(),
        }
    }

    /// A metered internet-class link (relays reachable store-and-forward).
    fn net() -> Self {
        Self {
            cost: CostClass::Metered,
            mtu: 64 * 1024,
            broadcast: None,
            inbox: Arc::default(),
            transit: Arc::default(),
            sent: Arc::default(),
            refuse: Arc::default(),
        }
    }
}

#[async_trait]
impl Transport for MockLink {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: self.mtu,
            latency: match self.cost {
                CostClass::Airtime => LatencyClass::Seconds,
                _ => LatencyClass::Millis,
            },
            cost: self.cost,
            broadcast: self.broadcast.is_some(),
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match (self.cost, peer) {
            (CostClass::Airtime, DeliveryHint::MeshNode(_)) => Reachability::Now,
            (CostClass::Metered, DeliveryHint::Multiaddr(_)) => Reachability::Now,
            (CostClass::Metered, DeliveryHint::Relay(_)) => Reachability::StoreAndForward,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        if *self.refuse.lock().unwrap() {
            return Err(TransportError::Io(std::io::Error::other("refused")));
        }
        self.sent
            .lock()
            .unwrap()
            .push((peer.clone(), envelope.clone()));
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self.inbox.lock().unwrap().drain(..).collect())
    }

    async fn recv_transit(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self.transit.lock().unwrap().drain(..).collect())
    }

    fn broadcast_hint(&self) -> Option<DeliveryHint> {
        self.broadcast.clone()
    }
}

/// A sealed envelope addressed to nobody this node knows.
fn foreign(seed: u8, body_len: usize) -> Envelope {
    Envelope::new(EnvelopeKind::Message, [seed; 32], vec![seed; body_len])
}

/// A bridging node wired to one mesh link and one internet link, with a
/// single configured deposit relay.
fn bridge_node(
    dir: &std::path::Path,
    mesh: MockLink,
    net: MockLink,
    rng: &mut StdRng,
) -> (Node, DeliveryHint) {
    let mut node = Node::create(&dir.join("bridge.db"), b"b", TEST_KDF, rng).unwrap();
    node.add_transport(Arc::new(mesh));
    node.add_transport(Arc::new(net));
    let relay = DeliveryHint::Relay("/mock/relay".to_owned());
    node.set_bridge(Some(vec![relay.clone()]));
    (node, relay)
}

// ---------------------------------------------------------------------------
// Mesh → internet: a foreign envelope heard on the airtime link is deposited
// at the configured relay exactly once (dedup absorbs multipath echoes), and
// never re-flooded onto the mesh (split horizon).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mesh_foreign_traffic_is_deposited_on_the_relay_once() {
    let mut rng = StdRng::seed_from_u64(1);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(233);
    let net = MockLink::net();
    let (mesh_inbox, mesh_sent) = (mesh.inbox.clone(), mesh.sent.clone());
    let net_sent = net.sent.clone();
    let (mut node, relay) = bridge_node(dir.path(), mesh, net, &mut rng);

    let env = foreign(0x11, 64);
    mesh_inbox.lock().unwrap().push(env.clone());
    node.tick(NOW, &mut rng).await.unwrap();

    let deposits = net_sent.lock().unwrap().clone();
    assert_eq!(deposits.len(), 1, "one deposit at the configured relay");
    assert_eq!(deposits[0].0, relay);
    assert_eq!(deposits[0].1, env);
    assert!(
        mesh_sent.lock().unwrap().is_empty(),
        "split horizon: transit never returns to the mesh"
    );
    assert_eq!(
        node.transit_queued(),
        0,
        "accepted deposit completes transit"
    );

    // The same envelope heard again (another mesh path, another bridge's
    // echo) is not forwarded twice.
    mesh_inbox.lock().unwrap().push(env.clone());
    node.tick(NOW + 1, &mut rng).await.unwrap();
    assert_eq!(net_sent.lock().unwrap().len(), 1, "content-id dedup");
}

// ---------------------------------------------------------------------------
// Mesh → internet: refusals pace with backoff and give up after the attempt
// cap — mesh-internal chatter no relay recognizes costs a bounded number of
// deposits, never an unbounded queue.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refused_deposits_back_off_then_drop_at_the_cap() {
    let mut rng = StdRng::seed_from_u64(2);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(233);
    let net = MockLink::net();
    let mesh_inbox = mesh.inbox.clone();
    let (net_sent, net_refuse) = (net.sent.clone(), net.refuse.clone());
    let (mut node, _) = bridge_node(dir.path(), mesh, net, &mut rng);

    *net_refuse.lock().unwrap() = true;
    mesh_inbox.lock().unwrap().push(foreign(0x22, 64));
    node.tick(NOW, &mut rng).await.unwrap();
    assert_eq!(node.transit_queued(), 1, "refused: kept for retry");

    // Immediately after, the item is backing off — no hammering.
    node.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(node.transit_queued(), 1);

    // Step far past every backoff: the attempt cap drains it.
    let mut t = NOW;
    for _ in 0..10 {
        t += 4_000;
        node.tick(t, &mut rng).await.unwrap();
    }
    assert_eq!(node.transit_queued(), 0, "bounded attempts, then dropped");
    assert!(
        net_sent.lock().unwrap().is_empty(),
        "every attempt was refused, none recorded as sent"
    );

    // A relay that finally accepts ends transit at the first attempt.
    *net_refuse.lock().unwrap() = false;
    mesh_inbox.lock().unwrap().push(foreign(0x23, 64));
    node.tick(t + 1, &mut rng).await.unwrap();
    assert_eq!(node.transit_queued(), 0);
    assert_eq!(net_sent.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Internet → mesh: carrier-surfaced transit floods the broadcast hint a
// fixed number of times on an exponential schedule, then stops — there is
// no feedback channel, so the budget is the whole story.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn internet_transit_floods_the_mesh_a_bounded_number_of_times() {
    let mut rng = StdRng::seed_from_u64(3);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(233);
    let net = MockLink::net();
    let mesh_sent = mesh.sent.clone();
    let net_transit = net.transit.clone();
    let net_sent = net.sent.clone();
    let (mut node, _) = bridge_node(dir.path(), mesh, net, &mut rng);

    let env = foreign(0x33, 64);
    net_transit.lock().unwrap().push(env.clone());
    node.tick(NOW, &mut rng).await.unwrap();
    {
        let sent = mesh_sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "first flood is immediate");
        assert_eq!(sent[0].0, DeliveryHint::MeshNode(u32::MAX));
        assert_eq!(sent[0].1, env);
    }
    assert_eq!(node.transit_queued(), 1, "held for re-flooding");

    // Not re-flooded every tick.
    node.tick(NOW + 10, &mut rng).await.unwrap();
    assert_eq!(mesh_sent.lock().unwrap().len(), 1);

    // Step through the re-flood schedule until the budget is spent.
    let mut t = NOW;
    for _ in 0..8 {
        t += 3_000;
        node.tick(t, &mut rng).await.unwrap();
    }
    assert_eq!(mesh_sent.lock().unwrap().len(), 3, "flood budget of three");
    assert_eq!(node.transit_queued(), 0, "then dropped");
    assert!(
        net_sent.lock().unwrap().is_empty(),
        "split horizon: internet-origin transit is never deposited back"
    );
}

// ---------------------------------------------------------------------------
// Internet → mesh: an envelope over the mesh MTU is fragmented for the
// flood (the recipient's normal reassembly path picks it up); one over the
// airtime ceiling never rides at all.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transit_fragments_for_the_mesh_and_honors_the_airtime_ceiling() {
    let mut rng = StdRng::seed_from_u64(4);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(200);
    let net = MockLink::net();
    let mesh_sent = mesh.sent.clone();
    let net_transit = net.transit.clone();
    let (mut node, _) = bridge_node(dir.path(), mesh, net, &mut rng);

    // Larger than one frame, far under the ceiling: fragmented flood.
    let env = foreign(0x44, 400);
    net_transit.lock().unwrap().push(env.clone());
    node.tick(NOW, &mut rng).await.unwrap();
    {
        let sent = mesh_sent.lock().unwrap();
        assert!(sent.len() > 1, "fragmented into several frames");
        assert!(sent
            .iter()
            .all(|(_, e)| e.kind == EnvelopeKind::Fragment && e.token == env.token));
    }

    // Over the 4 KiB airtime ceiling: refused outright, not queued.
    mesh_sent.lock().unwrap().clear();
    net_transit.lock().unwrap().push(foreign(0x45, 5_000));
    node.tick(NOW + 1, &mut rng).await.unwrap();
    assert!(mesh_sent.lock().unwrap().is_empty());
    assert_eq!(node.transit_queued(), 1, "only the fragmented one remains");
}

// ---------------------------------------------------------------------------
// Token blindness has a flip side: traffic addressed to *this* node — here
// an introduction token of ours — is never treated as transit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn own_tokens_are_never_bridged() {
    let mut rng = StdRng::seed_from_u64(5);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(233);
    let net = MockLink::net();
    let mesh_inbox = mesh.inbox.clone();
    let net_sent = net.sent.clone();
    let (mut node, _) = bridge_node(dir.path(), mesh, net, &mut rng);

    let token = intro_token(&node.peer_id(), epoch_day(NOW));
    mesh_inbox
        .lock()
        .unwrap()
        .push(Envelope::new(EnvelopeKind::Handshake, token, vec![0u8; 64]));
    node.tick(NOW, &mut rng).await.unwrap();
    assert!(net_sent.lock().unwrap().is_empty());
    assert_eq!(node.transit_queued(), 0);
}

// ---------------------------------------------------------------------------
// Bridging is opt-in: a node that never called set_bridge forwards nothing,
// exactly as before M4.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn without_opt_in_nothing_is_bridged() {
    let mut rng = StdRng::seed_from_u64(6);
    let dir = tempfile::tempdir().unwrap();
    let mesh = MockLink::mesh(233);
    let net = MockLink::net();
    let mesh_inbox = mesh.inbox.clone();
    let net_transit = net.transit.clone();
    let (mesh_sent, net_sent) = (mesh.sent.clone(), net.sent.clone());

    let mut node = Node::create(&dir.path().join("plain.db"), b"p", TEST_KDF, &mut rng).unwrap();
    node.add_transport(Arc::new(mesh));
    node.add_transport(Arc::new(net));

    mesh_inbox.lock().unwrap().push(foreign(0x66, 64));
    net_transit.lock().unwrap().push(foreign(0x67, 64));
    node.tick(NOW, &mut rng).await.unwrap();
    assert!(net_sent.lock().unwrap().is_empty());
    assert!(mesh_sent.lock().unwrap().is_empty());
    assert_eq!(node.transit_queued(), 0);
}
