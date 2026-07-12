//! M4 bridging acceptance (docs/05-transports.md §4.2 rule 5, ADR-0009):
//! a node attached to both a (mock) LoRa mesh and a (mock) internet link
//! bridges sealed traffic in both directions — the village-with-one-
//! Starlink-terminal topology. The bridge never learns whose traffic it
//! moves: it forwards exactly the envelopes whose tokens it cannot match
//! and the handshakes it cannot open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_node::{BridgeConfig, Event, Node};
use kult_protocol::{Envelope, EnvelopeKind};
use kult_store::DeliveryState;
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

/// The Meshtastic broadcast node number (kult-transport's MESH_BROADCAST,
/// spelled out here because that constant lives behind the `meshtastic`
/// feature).
const BROADCAST: u32 = u32::MAX;

// ---- mock carriers ---------------------------------------------------------

type MeshNet = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

/// Broadcast LoRa mesh: a send to [`BROADCAST`] reaches every other radio,
/// airtime-priced, 180-byte frames (so real traffic fragments).
struct Radio {
    net: MeshNet,
    me: u32,
}

impl Radio {
    fn new(net: &MeshNet, me: u32) -> Self {
        net.lock().unwrap().entry(me).or_default();
        Self {
            net: net.clone(),
            me,
        }
    }
}

#[async_trait]
impl Transport for Radio {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 180,
            latency: LatencyClass::Seconds,
            cost: CostClass::Airtime,
            broadcast: true,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            DeliveryHint::MeshNode(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::MeshNode(to) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        let mut net = self.net.lock().unwrap();
        for (id, queue) in net.iter_mut() {
            if *id == self.me {
                continue; // a radio does not hear its own transmission
            }
            if *to == BROADCAST || *to == *id {
                queue.push(envelope.clone());
            }
        }
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .entry(self.me)
            .or_default()
            .drain(..)
            .collect())
    }
}

type WireNet = Arc<Mutex<HashMap<String, Vec<Envelope>>>>;

/// Point-to-point internet link addressed by name (stand-in for multiaddr
/// dialing): fast, large frames.
struct Wire {
    net: WireNet,
    me: String,
}

impl Wire {
    fn new(net: &WireNet, me: &str) -> Self {
        net.lock().unwrap().entry(me.to_owned()).or_default();
        Self {
            net: net.clone(),
            me: me.to_owned(),
        }
    }
}

#[async_trait]
impl Transport for Wire {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            DeliveryHint::Multiaddr(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::Multiaddr(to) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(to.clone())
            .or_default()
            .push(envelope.clone());
        Ok(SendReceipt::AckedByNextHop)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .entry(self.me.clone())
            .or_default()
            .drain(..)
            .collect())
    }
}

// ---- tests -----------------------------------------------------------------

/// The full village topology: Alice has only a radio, Bob has only
/// internet, the bridge has both. Handshake, message, receipt, and the
/// reply all cross the bridge — in both directions.
#[tokio::test]
async fn village_bridge_carries_traffic_both_ways() {
    let mut rng = StdRng::seed_from_u64(11);
    let dir = tempfile::tempdir().unwrap();
    let mesh: MeshNet = Arc::new(Mutex::new(HashMap::new()));
    let wire: WireNet = Arc::new(Mutex::new(HashMap::new()));

    // Alice: radio only (the valley).
    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(Radio::new(&mesh, 1)));

    // The bridge: radio + internet, no contacts, no sessions — it knows
    // nobody and still delivers. Destination-blind forwarding to the mesh
    // and to Bob's side of the wire.
    let mut bridge = Node::create(&dir.path().join("br.db"), b"br", TEST_KDF, &mut rng).unwrap();
    bridge.add_transport(Arc::new(Radio::new(&mesh, 2)));
    bridge.add_transport(Arc::new(Wire::new(&wire, "bridge")));
    bridge.enable_bridge(BridgeConfig {
        forward_to: vec![
            DeliveryHint::MeshNode(BROADCAST),
            DeliveryHint::Multiaddr("bob".into()),
        ],
    });

    // Bob: internet only (the wider world), reachable behind the bridge.
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();
    bob.add_transport(Arc::new(Wire::new(&wire, "bob")));

    // Out-of-band pairing: Alice writes to the mesh at large; Bob's path
    // to Alice is "hand it to the bridge".
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(BROADCAST)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr("bridge".into())],
            NOW,
            &mut rng,
        )
        .unwrap();

    // Mesh → internet: Alice's handshake flight floods the valley as LoRa
    // fragments; the bridge cannot open it, forwards each fragment, and
    // Bob reassembles and reads.
    let m1 = alice
        .send_message(&bob_id, b"hello from the valley", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bridge.tick(NOW + 2, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 3, &mut rng).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::MessageReceived { peer, body, .. }
                if *peer == alice_id && body == b"hello from the valley")),
        "message must cross mesh → bridge → internet"
    );

    // Internet → mesh: Bob's encrypted receipt goes to the bridge, which
    // floods it back over the radio; Alice's record turns Delivered.
    bridge.tick(NOW + 4, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 5, &mut rng).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Delivered,
            } if *id == m1
        )),
        "the receipt must cross internet → bridge → mesh"
    );

    // And a full reply on the established session, same path.
    bob.send_message(&alice_id, b"heard you loud and clear", NOW + 10, &mut rng)
        .unwrap();
    bob.tick(NOW + 11, &mut rng).await.unwrap();
    bridge.tick(NOW + 12, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 13, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::MessageReceived { body, .. }
            if body == b"heard you loud and clear")));

    // The bridge itself learned nothing it can act on: no contacts, no
    // decrypted messages, no sessions.
    assert!(bridge.contacts().unwrap().is_empty());
}

/// Loop prevention: the same envelope heard twice (multipath) is forwarded
/// exactly once.
#[tokio::test]
async fn bridge_forwards_each_envelope_once() {
    let mut rng = StdRng::seed_from_u64(12);
    let dir = tempfile::tempdir().unwrap();
    let mesh: MeshNet = Arc::new(Mutex::new(HashMap::new()));
    let wire: WireNet = Arc::new(Mutex::new(HashMap::new()));

    let mut bridge = Node::create(&dir.path().join("br.db"), b"br", TEST_KDF, &mut rng).unwrap();
    bridge.add_transport(Arc::new(Radio::new(&mesh, 2)));
    bridge.add_transport(Arc::new(Wire::new(&wire, "bridge")));
    bridge.enable_bridge(BridgeConfig {
        forward_to: vec![DeliveryHint::Multiaddr("out".into())],
    });

    // Two copies of the same third-party envelope arrive over the radio.
    let envelope = Envelope::new(EnvelopeKind::Message, [0x42; 32], vec![7; 40]);
    {
        let mut net = mesh.lock().unwrap();
        let inbox = net.entry(2).or_default();
        inbox.push(envelope.clone());
        inbox.push(envelope.clone());
    }
    bridge.tick(NOW, &mut rng).await.unwrap();
    bridge.tick(NOW + 1, &mut rng).await.unwrap();

    let delivered = wire.lock().unwrap().entry("out".into()).or_default().len();
    assert_eq!(delivered, 1, "multipath duplicates forward once");
}

/// A bridge does not hold other people's media: an over-ceiling envelope
/// whose only forward hint is airtime-priced is dropped, not queued and
/// not radiated.
#[tokio::test]
async fn bridge_drops_oversize_for_airtime_only_hints() {
    let mut rng = StdRng::seed_from_u64(13);
    let dir = tempfile::tempdir().unwrap();
    let mesh: MeshNet = Arc::new(Mutex::new(HashMap::new()));
    let wire: WireNet = Arc::new(Mutex::new(HashMap::new()));

    let mut bridge = Node::create(&dir.path().join("br.db"), b"br", TEST_KDF, &mut rng).unwrap();
    bridge.add_transport(Arc::new(Radio::new(&mesh, 2)));
    bridge.add_transport(Arc::new(Wire::new(&wire, "bridge")));
    bridge.enable_bridge(BridgeConfig {
        forward_to: vec![DeliveryHint::MeshNode(BROADCAST)],
    });
    // A listener on the mesh, to catch anything the bridge radiates.
    let _listener = Radio::new(&mesh, 3);

    // 5 KiB of someone's media arrives over the wire.
    let envelope = Envelope::new(EnvelopeKind::Message, [0x43; 32], vec![9; 5 * 1024]);
    wire.lock()
        .unwrap()
        .entry("bridge".into())
        .or_default()
        .push(envelope);
    for step in 0..3 {
        bridge.tick(NOW + step, &mut rng).await.unwrap();
    }

    let radiated = mesh.lock().unwrap().entry(3).or_default().len();
    assert_eq!(radiated, 0, "over-ceiling media never hits the mesh");
}
