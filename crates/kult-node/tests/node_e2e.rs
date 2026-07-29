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
    AuthorityDevicePrekeyBundle, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret,
    PrekeyBundle, SignedPrekeySecret,
};
use kult_node::{ContentStatus, Event, Node};
use kult_protocol::{
    decode_content, encode_text, fragment, DecodedContent, Envelope, EnvelopeKind, CONTENT_MAGIC,
};
use kult_store::{DeliveryState, Store, MAX_PENDING_ENVELOPES};
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

#[test]
fn pairing_bundle_carries_signed_first_message_routes() {
    let mut rng = StdRng::seed_from_u64(700);
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::create(&dir.path().join("node.db"), b"pass", TEST_KDF, &mut rng).unwrap();
    let hints = vec![
        DeliveryHint::Multiaddr("/ip4/192.0.2.7/udp/4242/quic-v1/p2p/12D3KooWExample".to_owned()),
        DeliveryHint::Relay("/ip4/198.51.100.4/tcp/443".to_owned()),
    ];

    let encoded = node
        .handshake_bundle_with_hints(&hints, NOW, &mut rng)
        .unwrap();
    let bundle = AuthorityDevicePrekeyBundle::decode(&encoded).unwrap();
    let decoded = bundle
        .prekey
        .relay_hints
        .iter()
        .map(|bytes| postcard::from_bytes::<DeliveryHint>(bytes).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(decoded, hints);
    bundle.verify(NOW).unwrap();

    let mut receiver =
        Node::create(&dir.path().join("receiver.db"), b"pass", TEST_KDF, &mut rng).unwrap();
    receiver
        .add_contact("sender", &encoded, &[], NOW, &mut rng)
        .unwrap();
    let stored = receiver.contacts().unwrap().pop().unwrap();
    let imported = stored
        .hints
        .iter()
        .map(|bytes| postcard::from_bytes::<DeliveryHint>(bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(imported, hints);
}

#[tokio::test]
async fn rescanning_a_fresh_bundle_rekeys_and_retries_unconfirmed_messages() {
    let mut rng = StdRng::seed_from_u64(701);
    let dir = tempfile::tempdir().unwrap();
    let sender_inbox = dir.path().join("sender-spool");
    let stale_receiver_inbox = dir.path().join("stale-receiver-spool");
    let fresh_receiver_inbox = dir.path().join("fresh-receiver-spool");
    let mut sender =
        Node::create(&dir.path().join("sender.db"), b"sender", TEST_KDF, &mut rng).unwrap();
    let mut receiver = Node::create(
        &dir.path().join("receiver.db"),
        b"receiver",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    let _stale_receiver = SneakernetTransport::new(&stale_receiver_inbox).unwrap();
    sender.add_transport(Arc::new(SneakernetTransport::new(&sender_inbox).unwrap()));
    receiver.add_transport(Arc::new(
        SneakernetTransport::new(&fresh_receiver_inbox).unwrap(),
    ));

    let stale_bundle = receiver.handshake_bundle(NOW, &mut rng).unwrap();
    let receiver_id = sender
        .add_contact(
            "receiver",
            &stale_bundle,
            &[DeliveryHint::Spool(stale_receiver_inbox)],
            NOW,
            &mut rng,
        )
        .unwrap();
    sender
        .send_message(&receiver_id, b"first attempt", NOW, &mut rng)
        .unwrap();
    sender
        .send_message(&receiver_id, b"follow-up", NOW + 1, &mut rng)
        .unwrap();
    sender.tick(NOW + 2, &mut rng).await.unwrap();
    assert!(sender
        .messages_with(&receiver_id)
        .unwrap()
        .iter()
        .all(|message| message.state == DeliveryState::Sent));

    // Both first-flight envelopes were handed to a transport but never
    // reached the recipient. A new scan must abandon that unconfirmed
    // ratchet and encrypt the pending messages against the fresh bundle.
    let fresh_bundle = receiver.handshake_bundle(NOW + 3, &mut rng).unwrap();
    sender
        .add_contact(
            "receiver",
            &fresh_bundle,
            &[DeliveryHint::Spool(fresh_receiver_inbox)],
            NOW + 3,
            &mut rng,
        )
        .unwrap();
    assert!(sender
        .messages_with(&receiver_id)
        .unwrap()
        .iter()
        .all(|message| { message.state == DeliveryState::Queued && message.wire_id.is_none() }));

    sender.tick(NOW + 4, &mut rng).await.unwrap();
    let events = receiver.tick(NOW + 5, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 2);
}

#[tokio::test]
async fn one_way_pairing_imports_the_initiators_signed_return_route() {
    let mut rng = StdRng::seed_from_u64(702);
    let dir = tempfile::tempdir().unwrap();
    let phone_inbox = dir.path().join("phone-spool");
    let desktop_inbox = dir.path().join("desktop-spool");
    let mut phone =
        Node::create(&dir.path().join("phone.db"), b"phone", TEST_KDF, &mut rng).unwrap();
    let mut desktop = Node::create(
        &dir.path().join("desktop.db"),
        b"desktop",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    phone.add_transport(Arc::new(SneakernetTransport::new(&phone_inbox).unwrap()));
    desktop.add_transport(Arc::new(SneakernetTransport::new(&desktop_inbox).unwrap()));

    // Runtime startup records the phone's current signed return route even
    // though only the phone scans the desktop during pairing.
    phone
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(phone_inbox.clone())], NOW, &mut rng)
        .unwrap();
    let desktop_bundle = desktop.handshake_bundle(NOW, &mut rng).unwrap();
    let desktop_id = phone
        .add_contact(
            "desktop",
            &desktop_bundle,
            &[DeliveryHint::Spool(desktop_inbox)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let message = phone
        .send_message(&desktop_id, b"one scan is bidirectional", NOW, &mut rng)
        .unwrap();

    phone.tick(NOW + 1, &mut rng).await.unwrap();
    let events = desktop.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 1);
    assert_eq!(desktop.contacts().unwrap().len(), 1);
    desktop.tick(NOW + 3, &mut rng).await.unwrap();
    let events = phone.tick(NOW + 4, &mut rng).await.unwrap();
    assert!(delivered_ids(&events).contains(&message));
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
    assert!(history
        .iter()
        .all(|record| matches!(decode_content(&record.body), DecodedContent::LegacyText(_))));

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
    let reply_history = bob.messages_with(&alice_id).unwrap();
    assert!(matches!(
        decode_content(&reply_history.last().unwrap().body),
        DecodedContent::Text { id, text: "got both, replying" } if id == r1
    ));
    bob.tick(NOW + 201, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 260, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 1);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageReceived {
            id,
            content: ContentStatus::Text { id: content_id },
            body,
            ..
        } if *id == r1 && content_id == id && body == b"got both, replying"
    )));
    // Alice's receipt makes it back to Bob.
    let events = bob.tick(NOW + 320, &mut rng).await.unwrap();
    assert!(delivered_ids(&events).contains(&r1));

    // Authenticated unsupported and malformed content is retained exactly,
    // acknowledged normally, and never exposed as raw application text.
    let mut unsupported = CONTENT_MAGIC.to_vec();
    unsupported.push(2); // unknown framing version
    let mut malformed = CONTENT_MAGIC.to_vec();
    malformed.push(1); // truncated v1 header
    let unsupported_id = bob
        .send_message(&alice_id, &unsupported, NOW + 400, &mut rng)
        .unwrap();
    let malformed_id = bob
        .send_message(&alice_id, &malformed, NOW + 400, &mut rng)
        .unwrap();
    bob.tick(NOW + 401, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 460, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageReceived {
            body,
            content: ContentStatus::Unsupported { format_version: Some(2), kind: None },
            ..
        } if body.is_empty()
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageReceived {
            body,
            content: ContentStatus::Malformed,
            ..
        } if body.is_empty()
    )));
    let retained = alice.messages_with(&bob_id).unwrap();
    assert!(retained.iter().any(|record| record.body == unsupported));
    assert!(retained.iter().any(|record| record.body == malformed));
    let events = bob.tick(NOW + 520, &mut rng).await.unwrap();
    let delivered = delivered_ids(&events);
    assert!(delivered.contains(&unsupported_id) && delivered.contains(&malformed_id));

    // Re-encrypting the same logical event under two transport envelopes is
    // still one message inside this conversation and author scope. Both
    // envelopes are acknowledged so the sender's delivery ladder completes.
    let repeated = encode_text([0x42; 16], "once").unwrap();
    let copy_one = bob
        .send_message(&alice_id, &repeated, NOW + 600, &mut rng)
        .unwrap();
    let copy_two = bob
        .send_message(&alice_id, &repeated, NOW + 600, &mut rng)
        .unwrap();
    bob.tick(NOW + 601, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 660, &mut rng).await.unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                Event::MessageReceived {
                    content: ContentStatus::Text { id },
                    ..
                } if *id == [0x42; 16]
            ))
            .count(),
        1
    );
    assert_eq!(
        alice
            .messages_with(&bob_id)
            .unwrap()
            .iter()
            .filter(|record| matches!(
                decode_content(&record.body),
                DecodedContent::Text { id, .. } if id == [0x42; 16]
            ))
            .count(),
        1
    );
    let events = bob.tick(NOW + 720, &mut rng).await.unwrap();
    let delivered = delivered_ids(&events);
    assert!(delivered.contains(&copy_one) && delivered.contains(&copy_two));

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

#[tokio::test]
async fn passive_retry_replays_a_lost_end_to_end_receipt() {
    let mut rng = StdRng::seed_from_u64(202);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 1,
        mtu: 64 * 1024,
        duplicate: false,
    }));
    bob.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 2,
        mtu: 64 * 1024,
        duplicate: false,
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
    bob.add_contact(
        "alice",
        &alice_bundle,
        &[DeliveryHint::MeshNode(1)],
        NOW,
        &mut rng,
    )
    .unwrap();

    let message = alice
        .send_message(&bob_id, b"receipt may be lost", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    assert_eq!(
        count_received(&bob.tick(NOW + 2, &mut rng).await.unwrap()),
        1
    );

    // Simulate a carrier losing Bob's first receipt after Bob handed it off.
    net.lock().unwrap().entry(1).or_default().clear();
    assert_eq!(
        alice
            .messages_with(&bob_id)
            .unwrap()
            .iter()
            .find(|record| record.id == message)
            .unwrap()
            .state,
        DeliveryState::Sent
    );

    // The retained ciphertext retries in the passive lane. Bob recognizes
    // the exact duplicate and replays the receipt without storing it twice.
    alice.tick(NOW + 901, &mut rng).await.unwrap();
    let replay_events = bob.tick(NOW + 902, &mut rng).await.unwrap();
    assert_eq!(count_received(&replay_events), 0);
    let alice_events = alice.tick(NOW + 903, &mut rng).await.unwrap();
    assert!(delivered_ids(&alice_events).contains(&message));
    assert_eq!(alice.queued().unwrap(), 0);
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

    // Link down: message and terminal capability control both stay queued.
    alice.tick(NOW, &mut rng).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(alice.queued().unwrap(), 2);

    // Inside the backoff window nothing is attempted.
    alice.tick(NOW + 5, &mut rng).await.unwrap();
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "backoff suppresses retry"
    );

    // Link recovers; after the backoff expires the send succeeds.
    healthy.store(true, Ordering::SeqCst);
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    assert_eq!(alice.queued().unwrap(), 0);
    let record = alice
        .messages_with(&peer)
        .unwrap()
        .into_iter()
        .find(|r| r.id == msg)
        .unwrap();
    assert_eq!(record.state, DeliveryState::Sent);
    assert_eq!(net.lock().unwrap().get(&9).unwrap().len(), 2);
}

#[tokio::test]
async fn fresh_user_message_bypasses_passive_unreachable_retry() {
    let mut rng = StdRng::seed_from_u64(303);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let healthy = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU32::new(0));
    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(FlakyLink {
        healthy: healthy.clone(),
        attempts,
        net: net.clone(),
    }));

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

    let old = alice
        .send_message(&peer, b"old unreachable", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW, &mut rng).await.unwrap();
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    alice.tick(NOW + 92, &mut rng).await.unwrap();

    // Three failed rounds demote the old envelope to the passive 15-minute
    // lane. A new tap of Send still gets one immediate foreground attempt.
    let fresh = alice
        .send_message(&peer, b"fresh foreground", NOW + 100, &mut rng)
        .unwrap();
    healthy.store(true, Ordering::SeqCst);
    alice.tick(NOW + 100, &mut rng).await.unwrap();

    let history = alice.messages_with(&peer).unwrap();
    assert_eq!(
        history
            .iter()
            .find(|message| message.id == fresh)
            .unwrap()
            .state,
        DeliveryState::Sent
    );
    assert_eq!(
        history
            .iter()
            .find(|message| message.id == old)
            .unwrap()
            .state,
        DeliveryState::Queued,
        "the passive item remains paced instead of blocking the new action"
    );
    assert_eq!(net.lock().unwrap().get(&9).unwrap().len(), 1);

    // Once its passive deadline arrives, the old item resumes automatically.
    alice.tick(NOW + 992, &mut rng).await.unwrap();
    assert_eq!(
        alice
            .messages_with(&peer)
            .unwrap()
            .iter()
            .find(|message| message.id == old)
            .unwrap()
            .state,
        DeliveryState::Sent
    );
}

#[tokio::test]
async fn undelivered_message_fails_and_leaves_queue_after_thirty_days() {
    let mut rng = StdRng::seed_from_u64(304);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let healthy = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU32::new(0));
    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(FlakyLink {
        healthy,
        attempts,
        net,
    }));

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
    let message = alice
        .send_message(&peer, b"bounded delivery", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW, &mut rng).await.unwrap();

    let events = alice.tick(NOW + 30 * 86_400, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| {
        matches!(
            event,
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Failed
            } if *id == message
        )
    }));
    assert_eq!(alice.queued().unwrap(), 0);
    assert_eq!(
        alice
            .messages_with(&peer)
            .unwrap()
            .iter()
            .find(|record| record.id == message)
            .unwrap()
            .state,
        DeliveryState::Failed
    );
    assert!(alice
        .message_device_deliveries(&message)
        .unwrap()
        .iter()
        .all(|delivery| delivery.state == DeliveryState::Failed));
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

    // Intercept the two message envelopes and deliver the session message
    // first. The terminal capability control is irrelevant to this test.
    // (Picked by kind: priority flushing sends the text-class envelope
    // before the handshake, so wire order is not handshake-first.)
    let (handshake, session_msg) = {
        let mut locked = net.lock().unwrap();
        let queue = locked.get_mut(&2).unwrap();
        assert_eq!(queue.len(), 3);
        let hs_at = queue
            .iter()
            .position(|e| e.kind == EnvelopeKind::Handshake)
            .unwrap();
        let hs = queue.remove(hs_at);
        let msg_at = queue
            .iter()
            .position(|e| e.kind == EnvelopeKind::Message)
            .unwrap();
        let sm = queue.remove(msg_at);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop().unwrap().kind, EnvelopeKind::Receipt);
        (hs, sm)
    };

    // Session message first: nothing can read it yet → stashed, no events.
    net.lock().unwrap().entry(2).or_default().push(session_msg);
    let events = bob.tick(NOW + 10, &mut rng).await.unwrap();
    assert_eq!(count_received(&events), 0);

    // Bob's device restarts. The stash must survive under one stable row id:
    // merely reading it never drains or rewrites it.
    drop(bob);
    let store = Store::open(&bob_db, b"b").unwrap();
    let first_read = store.pending_all().unwrap();
    assert_eq!(first_read.len(), 1);
    assert_eq!(store.pending_all().unwrap(), first_read);
    drop(store);
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
    drop(bob);
    let store = Store::open(&bob_db, b"b").unwrap();
    assert!(
        store.pending_all().unwrap().is_empty(),
        "consumed deferred row is explicitly acknowledged"
    );
}

#[tokio::test]
async fn deferred_rows_keep_their_id_until_consumed_or_expired() {
    let mut rng = StdRng::seed_from_u64(405);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pending.db");
    let node = Node::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    drop(node);

    let store = Store::open(&db, b"pass").unwrap();
    let retryable = Envelope::new(EnvelopeKind::Message, [7; 32], vec![8]);
    let already_expired = Envelope::new(EnvelopeKind::Message, [9; 32], vec![10]);
    let retryable_sequence = store.pending_push(&retryable, NOW, &mut rng).unwrap();
    store
        .pending_push(&already_expired, NOW - 31 * 86_400, &mut rng)
        .unwrap();
    drop(store);

    // No session recognizes either token. The live row stays durable under
    // the same sequence while the over-TTL row is explicitly acknowledged.
    let mut node = Node::open(&db, b"pass").unwrap();
    node.tick(NOW, &mut rng).await.unwrap();
    drop(node);
    let store = Store::open(&db, b"pass").unwrap();
    assert_eq!(
        store.pending_all().unwrap(),
        vec![(retryable_sequence, retryable, NOW)]
    );
    drop(store);

    // Once the retained row itself passes the TTL, it too is acknowledged
    // rather than decrypted, drained, or assigned a replacement sequence.
    let mut node = Node::open(&db, b"pass").unwrap();
    node.tick(NOW + 31 * 86_400, &mut rng).await.unwrap();
    drop(node);
    let store = Store::open(&db, b"pass").unwrap();
    assert!(store.pending_all().unwrap().is_empty());
}

#[tokio::test]
async fn exact_unknown_duplicates_share_one_bounded_deferred_row() {
    let mut rng = StdRng::seed_from_u64(406);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("pending-dedup.db");
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut node = Node::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    node.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 2,
        mtu: 64 * 1024,
        duplicate: false,
    }));
    let unknown = Envelope::new(EnvelopeKind::Message, [7; 32], vec![8]);

    net.lock()
        .unwrap()
        .entry(2)
        .or_default()
        .extend([unknown.clone(), unknown.clone()]);
    node.tick(NOW, &mut rng).await.unwrap();
    drop(node);
    let store = Store::open(&db, b"pass").unwrap();
    let first = store.pending_all().unwrap();
    assert_eq!(first.len(), 1);
    let stable_sequence = first[0].0;
    drop(store);

    let mut node = Node::open(&db, b"pass").unwrap();
    node.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 2,
        mtu: 64 * 1024,
        duplicate: false,
    }));
    net.lock()
        .unwrap()
        .entry(2)
        .or_default()
        .extend([unknown.clone(), unknown]);
    node.tick(NOW + 1, &mut rng).await.unwrap();
    drop(node);

    let store = Store::open(&db, b"pass").unwrap();
    let retained = store.pending_all().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].0, stable_sequence);
}

#[tokio::test]
async fn fragment_retry_survives_a_full_deferred_inbox() {
    let mut rng = StdRng::seed_from_u64(407);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fragment-quota.db");
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let node = Node::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    drop(node);

    let store = Store::open(&db, b"pass").unwrap();
    let mut first_sequence = None;
    for i in 0..MAX_PENDING_ENVELOPES {
        let mut token = [0u8; 32];
        token[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let filler = Envelope::new(EnvelopeKind::Message, token, vec![0x55]);
        let sequence = store.pending_push(&filler, NOW, &mut rng).unwrap();
        first_sequence.get_or_insert(sequence);
    }
    drop(store);

    let inner = Envelope::new(EnvelopeKind::Message, [0xf0; 32], vec![0x33; 256]);
    let fragment_envelopes: Vec<Envelope> = fragment(&inner.try_encode().unwrap(), 80)
        .unwrap()
        .into_iter()
        .map(|body| Envelope::new(EnvelopeKind::Fragment, inner.token, body))
        .collect();
    net.lock()
        .unwrap()
        .entry(2)
        .or_default()
        .extend(fragment_envelopes.clone());
    let mut node = Node::open(&db, b"pass").unwrap();
    node.add_transport(Arc::new(MockMesh {
        net: net.clone(),
        me: 2,
        mtu: 64 * 1024,
        duplicate: false,
    }));
    node.tick(NOW, &mut rng).await.unwrap();
    drop(node);

    let store = Store::open(&db, b"pass").unwrap();
    let pending = store.pending_all().unwrap();
    assert_eq!(pending.len(), MAX_PENDING_ENVELOPES);
    assert!(!pending
        .iter()
        .any(|(_, envelope, _)| envelope.content_id() == inner.content_id()));
    for fragment in &fragment_envelopes {
        assert!(!store.is_seen(&fragment.content_id()).unwrap());
    }
    store.pending_ack(first_sequence.unwrap()).unwrap();
    drop(store);

    net.lock()
        .unwrap()
        .entry(2)
        .or_default()
        .extend(fragment_envelopes);
    let mut node = Node::open(&db, b"pass").unwrap();
    node.add_transport(Arc::new(MockMesh {
        net,
        me: 2,
        mtu: 64 * 1024,
        duplicate: false,
    }));
    node.tick(NOW + 1, &mut rng).await.unwrap();
    drop(node);

    let store = Store::open(&db, b"pass").unwrap();
    let pending = store.pending_all().unwrap();
    assert_eq!(pending.len(), MAX_PENDING_ENVELOPES);
    assert!(pending
        .iter()
        .any(|(_, envelope, _)| envelope.content_id() == inner.content_id()));
}
