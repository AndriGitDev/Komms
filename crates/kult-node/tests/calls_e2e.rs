//! ADR-0013 transient call signaling, carrier gating, and no-airtime acceptance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{
    CallDirection, CallEndReason, CallPhase, DeviceLinkSelection, Event, Node, NodeError,
};
use kult_protocol::Envelope;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
const ALICE_ADDR: &str = "/ip4/127.0.0.1/udp/4101/quic-v1/p2p/alice";
const BOB_ADDR: &str = "/ip4/127.0.0.1/udp/4102/quic-v1/p2p/bob";
const PHONE_ADDR: &str = "/ip4/127.0.0.1/udp/4201/quic-v1/p2p/phone";
const LAPTOP_ADDR: &str = "/ip4/127.0.0.1/udp/4202/quic-v1/p2p/laptop";
const CAROL_ADDR: &str = "/ip4/127.0.0.1/udp/4203/quic-v1/p2p/carol";
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

    fn call_ready(&self, hint: &DeliveryHint) -> bool {
        self.reachable.load(Ordering::SeqCst)
            && matches!(hint, DeliveryHint::Multiaddr(address) if address.contains("/quic-v1"))
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

fn link_devices(source: &mut Node, target: &mut Node, now: u64, rng: &mut StdRng) {
    let offer = source.begin_device_link(now, rng).unwrap();
    let (response, target_code) = target
        .accept_device_link(&offer, "Laptop", now + 1, rng)
        .unwrap();
    assert_eq!(
        source.device_link_confirmation_code(&response).unwrap(),
        target_code
    );
    let package = source
        .approve_device_link(
            &response,
            DeviceLinkSelection::default(),
            true,
            now + 2,
            rng,
        )
        .unwrap();
    target
        .complete_device_link(&package, true, now + 3, rng)
        .unwrap();
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

#[tokio::test]
async fn first_linked_device_answer_wins_and_later_answer_ends_elsewhere() {
    let mut rng = StdRng::seed_from_u64(0xc700_0003);
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Mutex::new(HashMap::new()));
    let reachable = Arc::new(AtomicBool::new(true));
    let mut phone =
        Node::create(&dir.path().join("phone.db"), b"phone", TEST_KDF, &mut rng).unwrap();
    let mut laptop =
        Node::create(&dir.path().join("laptop.db"), b"laptop", TEST_KDF, &mut rng).unwrap();
    let mut carol =
        Node::create(&dir.path().join("carol.db"), b"carol", TEST_KDF, &mut rng).unwrap();
    link_devices(&mut phone, &mut laptop, NOW, &mut rng);
    let phone_device = phone.device_id();
    let laptop_device = laptop.device_id();

    for (node, address) in [
        (&mut phone, PHONE_ADDR),
        (&mut laptop, LAPTOP_ADDR),
        (&mut carol, CAROL_ADDR),
    ] {
        node.add_transport(Arc::new(DirectLink {
            net: Arc::clone(&net),
            me: address,
            reachable: Arc::clone(&reachable),
        }));
    }

    let phone_bundle = phone.handshake_bundle(NOW + 10, &mut rng).unwrap();
    let laptop_bundle = laptop.handshake_bundle(NOW + 10, &mut rng).unwrap();
    let carol_bundle = carol.handshake_bundle(NOW + 10, &mut rng).unwrap();
    let carol_for_phone = phone
        .add_contact(
            "Carol",
            &carol_bundle,
            &[DeliveryHint::Multiaddr(CAROL_ADDR.to_owned())],
            NOW + 10,
            &mut rng,
        )
        .unwrap();
    let carol_for_laptop = laptop
        .add_contact(
            "Carol",
            &carol_bundle,
            &[DeliveryHint::Multiaddr(CAROL_ADDR.to_owned())],
            NOW + 10,
            &mut rng,
        )
        .unwrap();
    let account = carol
        .add_contact(
            "Shared account",
            &phone_bundle,
            &[DeliveryHint::Multiaddr(PHONE_ADDR.to_owned())],
            NOW + 10,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        carol
            .add_contact(
                "Shared account",
                &laptop_bundle,
                &[DeliveryHint::Multiaddr(LAPTOP_ADDR.to_owned())],
                NOW + 10,
                &mut rng,
            )
            .unwrap(),
        account
    );

    phone
        .send_message(&carol_for_phone, b"phone session", NOW + 11, &mut rng)
        .unwrap();
    laptop
        .send_message(&carol_for_laptop, b"laptop session", NOW + 11, &mut rng)
        .unwrap();
    for round in 0..10 {
        phone.tick(NOW + 12 + round * 3, &mut rng).await.unwrap();
        laptop.tick(NOW + 13 + round * 3, &mut rng).await.unwrap();
        carol.tick(NOW + 14 + round * 3, &mut rng).await.unwrap();
    }

    let call_id = carol.start_call(&account, NOW + 50, &mut rng).unwrap();
    carol.tick(NOW + 51, &mut rng).await.unwrap();
    phone.tick(NOW + 52, &mut rng).await.unwrap();
    laptop.tick(NOW + 52, &mut rng).await.unwrap();
    phone.answer_call(&call_id, NOW + 53, &mut rng).unwrap();
    laptop.answer_call(&call_id, NOW + 53, &mut rng).unwrap();

    // Phone flushes first, so its authenticated answer is the winner. The
    // laptop answer arriving later is a terminal no-op plus an exact hangup.
    phone.tick(NOW + 54, &mut rng).await.unwrap();
    laptop.tick(NOW + 55, &mut rng).await.unwrap();
    carol.tick(NOW + 56, &mut rng).await.unwrap();
    let selected = carol
        .calls()
        .into_iter()
        .find(|call| call.id == call_id)
        .unwrap();
    assert_eq!(selected.phase, CallPhase::Connecting);
    assert_eq!(selected.responder_device, Some(phone_device));
    assert_ne!(selected.responder_device, Some(laptop_device));

    let laptop_events = laptop.tick(NOW + 57, &mut rng).await.unwrap();
    assert!(
        laptop_events.iter().any(|event| matches!(
            event,
            Event::CallUpdated { call }
                if call.id == call_id
                    && call.phase == CallPhase::Ended
                    && call.end_reason == Some(CallEndReason::AnsweredElsewhere)
        )),
        "events={laptop_events:?} calls={:?} carol_queued={}",
        laptop.calls(),
        carol.queued().unwrap()
    );
    assert_eq!(
        phone
            .calls()
            .into_iter()
            .find(|call| call.id == call_id)
            .unwrap()
            .phase,
        CallPhase::Connecting
    );
}
