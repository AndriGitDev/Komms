//! M4 delivery-engine mesh policies (docs/05-transports.md §4.2): priority
//! classes (text > receipts > handshakes), the 4 KiB airtime ceiling with
//! honest feedback, and selective-retransmission NACKs — exercised over
//! in-memory mock mesh links so the scarce-airtime logic is tested without
//! radios on the desk.

use std::collections::HashMap;
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
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only.
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Net = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

/// Configurable in-memory mesh link: records the kinds it sends (in order),
/// and can drop one fragment by index en route — LoRa loss, invisible to
/// the sender (the radio honestly reports only "handed to link").
struct MeshLink {
    net: Net,
    me: u32,
    mtu: usize,
    cost: CostClass,
    latency: LatencyClass,
    sent_kinds: Arc<Mutex<Vec<EnvelopeKind>>>,
    drop_fragment_index: Arc<Mutex<Option<u16>>>,
}

impl MeshLink {
    fn airtime(net: &Net, me: u32, mtu: usize) -> Self {
        Self {
            net: net.clone(),
            me,
            mtu,
            cost: CostClass::Airtime,
            latency: LatencyClass::Seconds,
            sent_kinds: Arc::new(Mutex::new(Vec::new())),
            drop_fragment_index: Arc::new(Mutex::new(None)),
        }
    }

    fn fast(net: &Net, me: u32) -> Self {
        Self {
            net: net.clone(),
            me,
            mtu: 64 * 1024,
            cost: CostClass::Metered,
            latency: LatencyClass::Millis,
            sent_kinds: Arc::new(Mutex::new(Vec::new())),
            drop_fragment_index: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Transport for MeshLink {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: self.mtu,
            latency: self.latency,
            cost: self.cost,
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
        self.sent_kinds.lock().unwrap().push(envelope.kind);
        // One-shot RF loss: the frame leaves the radio but never lands.
        if envelope.kind == EnvelopeKind::Fragment && envelope.body.len() >= 6 {
            let index = u16::from_le_bytes(envelope.body[4..6].try_into().unwrap());
            let mut drop = self.drop_fragment_index.lock().unwrap();
            if *drop == Some(index) {
                *drop = None;
                return Ok(SendReceipt::HandedToLink);
            }
        }
        self.net
            .lock()
            .unwrap()
            .entry(*n)
            .or_default()
            .push(envelope.clone());
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

/// Wire two fresh nodes together over the given links and run a full
/// handshake round trip so both ends hold an established session.
async fn linked_pair(
    dir: &std::path::Path,
    alice_link: MeshLink,
    bob_link: MeshLink,
    rng: &mut StdRng,
) -> (Node, Node, [u8; 32], [u8; 32]) {
    let mut alice = Node::create(&dir.join("a.db"), b"a", TEST_KDF, rng).unwrap();
    let mut bob = Node::create(&dir.join("b.db"), b"b", TEST_KDF, rng).unwrap();
    let (alice_me, bob_me) = (alice_link.me, bob_link.me);
    alice.add_transport(Arc::new(alice_link));
    bob.add_transport(Arc::new(bob_link));

    let alice_bundle = alice.handshake_bundle(NOW, rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(bob_me)],
            NOW,
            rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::MeshNode(alice_me)],
            NOW,
            rng,
        )
        .unwrap();

    alice.send_message(&bob_id, b"hi", NOW, rng).unwrap();
    alice.tick(NOW + 1, rng).await.unwrap();
    let events = bob.tick(NOW + 2, rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { .. })));
    alice.tick(NOW + 3, rng).await.unwrap();
    (alice, bob, alice_id, bob_id)
}

/// A signed prekey bundle for a peer that exists only on paper — enough to
/// queue a handshake flight to someone who will never answer.
fn paper_contact(rng: &mut StdRng) -> Vec<u8> {
    let identity = Identity::generate(rng);
    let spk = SignedPrekeySecret::generate(rng, 1);
    let pqspk = PqPrekeySecret::generate(rng, 1);
    let opk = OneTimePrekeySecret::generate(rng, 1);
    PrekeyBundle::build(&identity, &spk, &pqspk, Some(&opk), NOW + 86_400, vec![]).encode()
}

// ---------------------------------------------------------------------------
// 1. Priority classes (§4.2 rule 3): when one flush moves a text message, a
//    receipt, and a handshake, they leave in exactly that order — regardless
//    of the order they were queued in.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flush_sends_text_before_receipts_before_handshakes() {
    let mut rng = StdRng::seed_from_u64(41);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));

    let alice_link = MeshLink::airtime(&net, 1, 64 * 1024);
    let sent = alice_link.sent_kinds.clone();
    let bob_link = MeshLink::airtime(&net, 2, 64 * 1024);
    let (mut alice, mut bob, _alice_id, bob_id) =
        linked_pair(dir.path(), alice_link, bob_link, &mut rng).await;

    // Bob sends Alice a message; consuming it will make Alice owe a receipt.
    bob.send_message(&alice.peer_id(), b"ping", NOW + 10, &mut rng)
        .unwrap();
    bob.tick(NOW + 11, &mut rng).await.unwrap();

    // Alice queues a handshake first (worst class), then a text message.
    let carol = alice
        .add_contact(
            "carol",
            &paper_contact(&mut rng),
            &[DeliveryHint::MeshNode(3)],
            NOW + 12,
            &mut rng,
        )
        .unwrap();
    alice
        .send_message(&carol, b"handshake flight", NOW + 12, &mut rng)
        .unwrap();
    alice
        .send_message(&bob_id, b"text beats everything", NOW + 12, &mut rng)
        .unwrap();

    // One tick: receives Bob's ping (queuing a receipt), then flushes all
    // three. On the wire: Message, then Receipt, then Handshake.
    sent.lock().unwrap().clear();
    alice.tick(NOW + 13, &mut rng).await.unwrap();
    let kinds = sent.lock().unwrap().clone();
    assert_eq!(
        kinds,
        vec![
            EnvelopeKind::Message,
            EnvelopeKind::Receipt,
            EnvelopeKind::Handshake
        ],
        "flush order must follow priority classes, not queue order"
    );
}

// ---------------------------------------------------------------------------
// 2. Airtime ceiling (§4.2 rule 3): a >4 KiB payload is held off the mesh
//    with one honest AwaitingFasterLink event — and leaves immediately (no
//    backoff penalty) once a faster carrier appears.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversize_payload_waits_for_faster_link() {
    let mut rng = StdRng::seed_from_u64(42);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));

    let alice_link = MeshLink::airtime(&net, 1, 200);
    let sent = alice_link.sent_kinds.clone();
    let bob_link = MeshLink::airtime(&net, 2, 200);
    let (mut alice, _bob, _alice_id, bob_id) =
        linked_pair(dir.path(), alice_link, bob_link, &mut rng).await;

    // 5000 bytes pads past 4 KiB — media-sized, per the spec's proxy.
    let media = vec![0x42u8; 5000];
    let msg = alice
        .send_message(&bob_id, &media, NOW + 10, &mut rng)
        .unwrap();

    sent.lock().unwrap().clear();
    let events = alice.tick(NOW + 11, &mut rng).await.unwrap();
    assert!(sent.lock().unwrap().is_empty(), "nothing rode the mesh");
    assert_eq!(alice.queued().unwrap(), 1, "held, still queued");
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::AwaitingFasterLink { id } if *id == msg))
            .count(),
        1,
        "honest feedback: will send when a faster link exists"
    );

    // Feedback comes once per message, not once per tick.
    let events = alice.tick(NOW + 12, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .all(|e| !matches!(e, Event::AwaitingFasterLink { .. })));

    // A faster link appears: the very next tick sends — being held is not a
    // failure, so no retry backoff applies.
    alice.add_transport(Arc::new(MeshLink::fast(&net, 1)));
    alice.tick(NOW + 13, &mut rng).await.unwrap();
    assert_eq!(alice.queued().unwrap(), 0);
    assert!(sent.lock().unwrap().is_empty(), "still nothing on the mesh");
    let record = alice
        .messages_with(&bob_id)
        .unwrap()
        .into_iter()
        .find(|r| r.id == msg)
        .unwrap();
    assert_eq!(record.state, DeliveryState::Sent);
}

// ---------------------------------------------------------------------------
// 3. Selective retransmission (§4.2 rule 2): a lost fragment is NACKed by
//    index after a delay, the sender retransmits exactly that fragment —
//    never the whole message — and delivery completes end-to-end.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nack_retransmits_only_the_missing_fragment() {
    let mut rng = StdRng::seed_from_u64(43);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));

    let alice_link = MeshLink::airtime(&net, 1, 180);
    let drop = alice_link.drop_fragment_index.clone();
    let bob_link = MeshLink::airtime(&net, 2, 180);
    let (mut alice, mut bob, _alice_id, bob_id) =
        linked_pair(dir.path(), alice_link, bob_link, &mut rng).await;

    // 600 bytes pads to the 1024 bucket — several fragments at MTU 180.
    // Fragment index 1 falls off the air, once.
    *drop.lock().unwrap() = Some(1);
    let big = vec![0x37u8; 600];
    let t0 = NOW + 100;
    let msg = alice.send_message(&bob_id, &big, t0, &mut rng).unwrap();
    alice.tick(t0 + 1, &mut rng).await.unwrap();
    assert!(drop.lock().unwrap().is_none(), "one fragment was dropped");

    // Bob gathers what arrived: incomplete, no message, and no premature
    // NACK — in-flight fragments get their chance first.
    let t1 = t0 + 5;
    let events = bob.tick(t1, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .all(|e| !matches!(e, Event::MessageReceived { .. })));
    assert_eq!(bob.queued().unwrap(), 0, "no NACK before the delay");

    // Past the delay, Bob NACKs the missing index (a receipt envelope,
    // flushed back over the same mesh).
    let t2 = t1 + 65;
    bob.tick(t2, &mut rng).await.unwrap();

    // Alice consumes the NACK and retransmits exactly one fragment.
    net.lock().unwrap().entry(2).or_default().clear();
    alice.tick(t2 + 2, &mut rng).await.unwrap();
    {
        let net = net.lock().unwrap();
        let frames: Vec<_> = net.get(&2).cloned().unwrap_or_default();
        assert_eq!(
            frames.len(),
            1,
            "selective retransmission resends one fragment, not the message"
        );
        assert_eq!(frames[0].kind, EnvelopeKind::Fragment);
        assert_eq!(
            u16::from_le_bytes(frames[0].body[4..6].try_into().unwrap()),
            1,
            "and it is the missing index"
        );
    }

    // The repaired message decrypts; the ack receipt completes delivery.
    let events = bob.tick(t2 + 4, &mut rng).await.unwrap();
    let received = events.iter().find_map(|e| match e {
        Event::MessageReceived { body, .. } => Some(body.clone()),
        _ => None,
    });
    assert_eq!(received.unwrap(), big);
    let events = alice.tick(t2 + 6, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated {
            id,
            state: DeliveryState::Delivered
        } if *id == msg
    )));
}
