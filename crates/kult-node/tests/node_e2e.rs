//! End-to-end tests for the `kult-node` runtime: the delivery engine,
//! transport scheduler, receipts, fragmentation, retry/backoff, and
//! out-of-order arrival — all over real or mock transports, with real
//! encrypted stores and process "restarts" (node drop + reopen).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{
    Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle, SignedPrekeySecret,
};
use kult_node::{Event, Node};
use kult_protocol::{Envelope, EnvelopeKind};
use kult_store::DeliveryState;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt,
    SneakernetTransport, Transport, TransportError,
};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only.
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn count_received(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::MessageReceived { .. }))
        .count()
}

fn delivered_ids(events: &[Event]) -> Vec<[u8; 16]> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Delivered,
            } => Some(*id),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Full round trip over sneakernet spools: handshake, messages, receipts,
//    restart persistence, reply on the established session.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sneakernet_round_trip_with_receipts_and_restart() {
    let mut rng = StdRng::seed_from_u64(1);
    let dir = tempfile::tempdir().unwrap();
    let alice_db = dir.path().join("alice.db");
    let bob_db = dir.path().join("bob.db");
    let alice_inbox = dir.path().join("alice-spool");
    let bob_inbox = dir.path().join("bob-spool");

    let mut alice = Node::create(&alice_db, b"alice-pass", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&bob_db, b"bob-pass", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(SneakernetTransport::new(&alice_inbox).unwrap()));
    bob.add_transport(Arc::new(SneakernetTransport::new(&bob_inbox).unwrap()));

    // Mutual out-of-band exchange (QR codes at a kitchen table): each side
    // gets the other's signed bundle and spool hint.
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Spool(bob_inbox.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Spool(alice_inbox.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();
    assert_eq!(bob_id, bob.peer_id());
    assert_eq!(alice_id, alice.peer_id());

    // Alice queues two messages; the first rides the handshake flight.
    let m1 = alice
        .send_message(&bob_id, b"hello over a usb stick", NOW, &mut rng)
        .unwrap();
    let m2 = alice
        .send_message(&bob_id, b"second, same courier", NOW, &mut rng)
        .unwrap();

    // Flush: envelopes land in Bob's spool; records advance Queued -> Sent.
    let events = alice.tick(NOW + 1, &mut rng).await.unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                Event::DeliveryUpdated {
                    state: DeliveryState::Sent,
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(alice.queued().unwrap(), 0);

    // Bob "receives the stick": session established, both messages decrypt,
    // an encrypted receipt is queued and flushed back in the same tick
    // (Bob already has Alice's hints).
    let events = bob.tick(NOW + 60, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == alice_id)));
    assert_eq!(count_received(&events), 2);
    assert_eq!(bob.queued().unwrap(), 0, "receipt flushed to alice's spool");

    // Alice reads the return courier: both records advance to Delivered.
    let events = alice.tick(NOW + 120, &mut rng).await.unwrap();
    let delivered = delivered_ids(&events);
    assert!(delivered.contains(&m1) && delivered.contains(&m2));
    let history = alice.messages_with(&bob_id).unwrap();
    assert!(history.iter().all(|r| r.state == DeliveryState::Delivered));

    // ---- Both devices restart; everything must survive. ----
    drop(alice);
    drop(bob);
    let mut alice = Node::open(&alice_db, b"alice-pass").unwrap();
    let mut bob = Node::open(&bob_db, b"bob-pass").unwrap();
    alice.add_transport(Arc::new(SneakernetTransport::new(&alice_inbox).unwrap()));
    bob.add_transport(Arc::new(SneakernetTransport::new(&bob_inbox).unwrap()));
    assert_eq!(
        alice.messages_with(&bob_id).unwrap().len(),
        2,
        "history survives restart"
    );

    // Bob replies on the established (persisted) session — no new handshake.
    let r1 = bob
        .send_message(&alice_id, b"got both, replying", NOW + 200, &mut rng)
        .unwrap();
    bob.tick(NOW + 201, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 260, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 1);
    // Alice's receipt makes it back to Bob.
    let events = bob.tick(NOW + 320, &mut rng).await.unwrap();
    assert!(delivered_ids(&events).contains(&r1));

    // Wrong passphrase still fails closed.
    assert!(Node::open(&alice_db, b"wrong").is_err());
}

// ---------------------------------------------------------------------------
// Mock mesh transport: in-memory network keyed by MeshNode number, small MTU,
// optional duplicate delivery (multipath is normal).
// ---------------------------------------------------------------------------

type Net = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

struct MockMesh {
    net: Net,
    me: u32,
    mtu: usize,
    duplicate: bool,
}

#[async_trait]
impl Transport for MockMesh {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: self.mtu,
            latency: LatencyClass::Seconds,
            cost: CostClass::Airtime,
            broadcast: false,
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
        let DeliveryHint::MeshNode(n) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        let mut net = self.net.lock().unwrap();
        let queue = net.entry(*n).or_default();
        queue.push(envelope.clone());
        if self.duplicate {
            queue.push(envelope.clone());
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

// ---------------------------------------------------------------------------
// 2. 180-byte MTU with duplicate delivery: envelopes fragment on send,
//    reassemble on receive, and multipath duplicates dedup to exactly one
//    message and one receipt.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn small_mtu_fragmentation_and_duplicate_dedup() {
    let mut rng = StdRng::seed_from_u64(2);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 1,
        mtu: 180,
        duplicate: true,
    }));
    bob.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 2,
        mtu: 180,
        duplicate: true,
    }));

    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(2)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::MeshNode(1)],
            NOW,
            &mut rng,
        )
        .unwrap();
    assert_eq!(alice_id, alice.peer_id());

    // 600 bytes of body pads to the 1024 bucket — far over one 180 B frame.
    let big = vec![0x42u8; 600];
    let m1 = alice.send_message(&bob_id, &big, NOW, &mut rng).unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();

    // Everything on the wire is a fragment within the MTU (and duplicated).
    {
        let net = net.lock().unwrap();
        let frames = net.get(&2).unwrap();
        assert!(frames.len() >= 4, "large envelope must fragment");
        assert!(frames.iter().all(|f| f.encode().len() <= 180));
    }

    let events = bob.tick(NOW + 5, &mut rng).await.unwrap();
    assert_eq!(
        count_received(&events),
        1,
        "duplicates dedup to one message"
    );
    let received = events.iter().find_map(|e| match e {
        Event::MessageReceived { body, .. } => Some(body.clone()),
        _ => None,
    });
    assert_eq!(received.unwrap(), big);

    // Receipt returns (also fragmented, also duplicated) → exactly one
    // Delivered transition.
    let events = alice.tick(NOW + 10, &mut rng).await.unwrap();
    assert_eq!(delivered_ids(&events), vec![m1]);
    let events = alice.tick(NOW + 15, &mut rng).await.unwrap();
    assert!(delivered_ids(&events).is_empty(), "no double delivery");
}

// ---------------------------------------------------------------------------
// 3. A failing link: sends error, the item stays queued with exponential
//    backoff, and goes out once the link recovers.
// ---------------------------------------------------------------------------

struct FlakyLink {
    healthy: Arc<AtomicBool>,
    attempts: Arc<AtomicU32>,
    net: Net,
}

#[async_trait]
impl Transport for FlakyLink {
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
            DeliveryHint::MeshNode(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }
    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self.healthy.load(Ordering::SeqCst) {
            return Err(TransportError::Io(std::io::Error::other("link down")));
        }
        let DeliveryHint::MeshNode(n) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(*n)
            .or_default()
            .push(envelope.clone());
        Ok(SendReceipt::HandedToLink)
    }
    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn retry_with_backoff_until_link_recovers() {
    let mut rng = StdRng::seed_from_u64(3);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let healthy = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU32::new(0));

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(FlakyLink {
        healthy: healthy.clone(),
        attempts: attempts.clone(),
        net: net.clone(),
    }));

    // A standalone signed bundle is enough to add a contact.
    let peer_identity = Identity::generate(&mut rng);
    let spk = SignedPrekeySecret::generate(&mut rng, 1);
    let pqspk = PqPrekeySecret::generate(&mut rng, 1);
    let opk = OneTimePrekeySecret::generate(&mut rng, 1);
    let bundle = PrekeyBundle::build(
        &peer_identity,
        &spk,
        &pqspk,
        Some(&opk),
        NOW + 86_400,
        vec![],
    )
    .encode();
    let peer = alice
        .add_contact("peer", &bundle, &[DeliveryHint::MeshNode(9)], NOW, &mut rng)
        .unwrap();

    let msg = alice
        .send_message(&peer, b"stubborn", NOW, &mut rng)
        .unwrap();

    // Link down: first flush fails, item stays queued.
    alice.tick(NOW, &mut rng).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(alice.queued().unwrap(), 1);

    // Inside the backoff window nothing is attempted.
    alice.tick(NOW + 5, &mut rng).await.unwrap();
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "backoff suppresses retry"
    );

    // Link recovers; after the backoff expires the send succeeds.
    healthy.store(true, Ordering::SeqCst);
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(alice.queued().unwrap(), 0);
    let record = alice
        .messages_with(&peer)
        .unwrap()
        .into_iter()
        .find(|r| r.id == msg)
        .unwrap();
    assert_eq!(record.state, DeliveryState::Sent);
    assert_eq!(net.lock().unwrap().get(&9).unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 4. Courier reordering: a session message arrives before the handshake that
//    creates the session — and the receiver restarts in between. The stashed
//    envelope survives and both messages decrypt once the handshake lands.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn out_of_order_arrival_survives_restart() {
    let mut rng = StdRng::seed_from_u64(4);
    let dir = tempfile::tempdir().unwrap();
    let bob_db = dir.path().join("b.db");
    let net: Net = Arc::new(Mutex::new(HashMap::new()));

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&bob_db, b"b", TEST_KDF, &mut rng).unwrap();
    let mesh = |me| MockMesh {
        net: net.clone(),
        me,
        mtu: 64 * 1024,
        duplicate: false,
    };
    alice.add_transport(Arc::new(mesh(1)));
    bob.add_transport(Arc::new(mesh(2)));

    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(2)],
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .send_message(&bob_id, b"first (handshake)", NOW, &mut rng)
        .unwrap();
    alice
        .send_message(&bob_id, b"second (session)", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();

    // Intercept the two envelopes and deliver the session message first.
    // (Picked by kind: priority flushing sends the text-class envelope
    // before the handshake, so wire order is not handshake-first.)
    let (handshake, session_msg) = {
        let mut locked = net.lock().unwrap();
        let queue = locked.get_mut(&2).unwrap();
        assert_eq!(queue.len(), 2);
        let hs_at = queue
            .iter()
            .position(|e| e.kind == EnvelopeKind::Handshake)
            .unwrap();
        let hs = queue.remove(hs_at);
        let sm = queue.remove(0);
        (hs, sm)
    };

    // Session message first: nothing can read it yet → stashed, no events.
    net.lock().unwrap().entry(2).or_default().push(session_msg);
    let events = bob.tick(NOW + 10, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 0);

    // Bob's device restarts. The stash must survive.
    drop(bob);
    let mut bob = Node::open(&bob_db, b"b").unwrap();
    bob.add_transport(Arc::new(mesh(2)));

    // Handshake arrives: the same tick consumes it AND the stashed message.
    net.lock().unwrap().entry(2).or_default().push(handshake);
    let events = bob.tick(NOW + 20, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 2, "stash replays after handshake");
    let bodies: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|e| match e {
            Event::MessageReceived { body, .. } => Some(body.clone()),
            _ => None,
        })
        .collect();
    assert!(bodies.contains(&b"first (handshake)".to_vec()));
    assert!(bodies.contains(&b"second (session)".to_vec()));
}
