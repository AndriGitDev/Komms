//! ADR-0013 transient call signaling, carrier gating, and no-airtime acceptance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{CallDirection, CallEndReason, CallPhase, Event, Node, NodeError};
use kult_protocol::Envelope;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
const ALICE_ADDR: &str = "/ip4/127.0.0.1/udp/4101/quic-v1/p2p/alice";
const BOB_ADDR: &str = "/ip4/127.0.0.1/udp/4102/quic-v1/p2p/bob";
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Net = Arc<Mutex<HashMap<String, Vec<Envelope>>>>;

struct DirectLink {
    net: Net,
    me: &'static str,
    reachable: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for DirectLink {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }

    async fn reachable(&self, hint: &DeliveryHint) -> Reachability {
        if self.reachable.load(Ordering::SeqCst)
            && matches!(hint, DeliveryHint::Multiaddr(address) if address.contains("/quic-v1"))
        {
            Reachability::Now
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        hint: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::Multiaddr(destination) = hint else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(destination.clone())
            .or_default()
            .push(envelope.clone());
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .entry(self.me.to_owned())
            .or_default()
            .drain(..)
            .collect())
    }
}

struct MeshSpy {
    sends: Arc<AtomicUsize>,
}

#[async_trait]
impl Transport for MeshSpy {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 512,
            latency: LatencyClass::Seconds,
            cost: CostClass::Airtime,
            broadcast: false,
        }
    }

    async fn reachable(&self, hint: &DeliveryHint) -> Reachability {
        if matches!(hint, DeliveryHint::MeshNode(_)) {
            Reachability::Now
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        _hint: &DeliveryHint,
        _envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }
}

async fn settle(alice: &mut Node, bob: &mut Node, rng: &mut StdRng, start: u64) {
    for round in 0..8 {
        alice.tick(start + round * 2, rng).await.unwrap();
        bob.tick(start + round * 2 + 1, rng).await.unwrap();
    }
}

fn call_update(events: &[Event], phase: CallPhase) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::CallUpdated { call } if call.phase == phase))
}

#[tokio::test]
async fn call_controls_are_transient_authenticated_and_never_chat_history() {
    let mut rng = StdRng::seed_from_u64(0xc700_0001);
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Mutex::new(HashMap::new()));
    let reachable = Arc::new(AtomicBool::new(true));
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(DirectLink {
        net: net.clone(),
        me: ALICE_ADDR,
        reachable: reachable.clone(),
    }));
    bob.add_transport(Arc::new(DirectLink {
        net,
        me: BOB_ADDR,
        reachable,
    }));

    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr(ALICE_ADDR.to_owned())],
            NOW,
            &mut rng,
        )
        .unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(BOB_ADDR.to_owned())],
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1).await;
    let alice_history = alice.messages_with(&bob_id).unwrap().len();
    let bob_history = bob.messages_with(&alice_id).unwrap().len();

    let call_id = alice.start_call(&bob_id, NOW + 30, &mut rng).unwrap();
    let alice_events = alice.tick(NOW + 31, &mut rng).await.unwrap();
    assert!(call_update(&alice_events, CallPhase::Ringing));
    let bob_events = bob.tick(NOW + 32, &mut rng).await.unwrap();
    assert!(call_update(&bob_events, CallPhase::Ringing));
    let incoming = bob
        .calls()
        .into_iter()
        .find(|call| call.id == call_id)
        .unwrap();
    assert_eq!(incoming.direction, CallDirection::Incoming);
    assert_eq!(alice.messages_with(&bob_id).unwrap().len(), alice_history);
    assert_eq!(bob.messages_with(&alice_id).unwrap().len(), bob_history);
    assert!(!bob_events
        .iter()
        .any(|event| matches!(event, Event::MessageReceived { .. })));

    bob.answer_call(&call_id, NOW + 33, &mut rng).unwrap();
    bob.tick(NOW + 34, &mut rng).await.unwrap();
    let alice_events = alice.tick(NOW + 35, &mut rng).await.unwrap();
    assert!(call_update(&alice_events, CallPhase::Connecting));
    assert!(alice
        .calls()
        .iter()
        .find(|call| call.id == call_id)
        .unwrap()
        .responder_device
        .is_some());

    alice.mark_call_active(&call_id, NOW + 36).unwrap();
    bob.mark_call_active(&call_id, NOW + 36).unwrap();
    alice.hangup_call(&call_id, NOW + 37, &mut rng).unwrap();
    alice.tick(NOW + 38, &mut rng).await.unwrap();
    let bob_events = bob.tick(NOW + 39, &mut rng).await.unwrap();
    assert!(bob_events.iter().any(|event| matches!(
        event,
        Event::CallUpdated { call }
            if call.id == call_id
                && call.phase == CallPhase::Ended
                && call.end_reason == Some(CallEndReason::HungUp)
    )));
    assert_eq!(alice.messages_with(&bob_id).unwrap().len(), alice_history);
    assert_eq!(bob.messages_with(&alice_id).unwrap().len(), bob_history);
}

#[tokio::test]
async fn call_attempts_never_fall_back_to_mesh_and_expire_locally() {
    let mut rng = StdRng::seed_from_u64(0xc700_0002);
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Mutex::new(HashMap::new()));
    let reachable = Arc::new(AtomicBool::new(true));
    let mesh_sends = Arc::new(AtomicUsize::new(0));
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(DirectLink {
        net: net.clone(),
        me: ALICE_ADDR,
        reachable: reachable.clone(),
    }));
    bob.add_transport(Arc::new(DirectLink {
        net,
        me: BOB_ADDR,
        reachable: reachable.clone(),
    }));
    alice.add_transport(Arc::new(MeshSpy {
        sends: mesh_sends.clone(),
    }));

    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    bob.add_contact(
        "alice",
        &alice_bundle,
        &[DeliveryHint::Multiaddr(ALICE_ADDR.to_owned())],
        NOW,
        &mut rng,
    )
    .unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[
                DeliveryHint::Multiaddr(BOB_ADDR.to_owned()),
                DeliveryHint::MeshNode(7),
            ],
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1).await;
    mesh_sends.store(0, Ordering::SeqCst);

    let call_id = alice.start_call(&bob_id, NOW + 30, &mut rng).unwrap();
    reachable.store(false, Ordering::SeqCst);
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    assert_eq!(mesh_sends.load(Ordering::SeqCst), 0);
    assert!(
        alice.queued().unwrap() > 0,
        "offer remains held while fresh"
    );
    let events = alice.tick(NOW + 91, &mut rng).await.unwrap();
    assert_eq!(
        alice.queued().unwrap(),
        0,
        "expired call control is discarded"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        Event::CallUpdated { call }
            if call.id == call_id
                && call.phase == CallPhase::Ended
                && call.end_reason == Some(CallEndReason::Expired)
    )));
    assert_eq!(mesh_sends.load(Ordering::SeqCst), 0);
    assert!(matches!(
        alice.start_call(&bob_id, NOW + 92, &mut rng),
        Err(NodeError::CallUnavailable)
    ));
}
