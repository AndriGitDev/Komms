//! M3 acceptance: recipient offline → message deposited at a mailbox relay
//! → delivered on reconnect — and the relay observably stores only sealed
//! envelopes (inspection test). Also pins the ADR-0007 property end-to-end:
//! on a relay shared by both parties, a sender's check-in cannot drain mail
//! it deposited for its peer.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{Event, Node};
use kult_protocol::{epoch_day, intro_token, Envelope, EnvelopeKind};
use kult_store::DeliveryState;
use kult_transport::{DeliveryHint, Libp2pTransport, MailboxConfig, Transport};

const NOW: u64 = 1_800_000_000;
const LISTEN: &[&str] = &["/ip4/127.0.0.1/udp/0/quic-v1"];
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[tokio::test]
async fn offline_recipient_via_relay_mailbox() {
    let mut rng = StdRng::seed_from_u64(11);
    let dir = tempfile::tempdir().unwrap();
    let plaintext = b"see you at the harbour, 09:00";

    // The relay: an ordinary node volunteering storage — no kult identity,
    // no special role, could be anyone.
    let relay = Libp2pTransport::with_mailbox(LISTEN, MailboxConfig::default())
        .await
        .unwrap();
    let relay_addr = relay.wait_listen_addr().await.unwrap();

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();

    let a_net = Arc::new(Libp2pTransport::new(LISTEN).await.unwrap());
    alice.add_transport(Arc::clone(&a_net) as Arc<dyn Transport>);

    // Bob picks the relay: one check-in registers his accept-filters. Then
    // he goes offline — his transport disappears entirely.
    let b_net = Libp2pTransport::new(LISTEN).await.unwrap();
    let collected = b_net
        .mailbox_checkin(&relay_addr, &bob.mailbox_tokens(NOW))
        .await
        .unwrap();
    assert_eq!(collected, 0);
    drop(b_net);

    // Alice knows bob's bundle and — as his published bundle would list —
    // his relay. No direct path exists.
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Relay(relay_addr.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();

    let m1 = alice
        .send_message(&bob_id, plaintext, NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    assert_eq!(
        alice.queued().unwrap(),
        1,
        "handshake deposited; capability waits for the session token"
    );

    // ADR-0007, end-to-end: alice and bob share this relay, yet alice's own
    // check-in (with *her* recipient-scoped token set) collects nothing —
    // bob's mail is not hers to drain.
    let echoes = a_net
        .mailbox_checkin(&relay_addr, &alice.mailbox_tokens(NOW + 1))
        .await
        .unwrap();
    assert_eq!(echoes, 0, "a sender must never collect its peer's mail");

    // Inspection (M3 acceptance): the relay holds exactly one blob, and it
    // is a sealed envelope — a kind byte, a rotating introduction token,
    // ciphertext. No identities, and no trace of the plaintext.
    let stored: Vec<Vec<u8>> = relay
        .mailbox_contents()
        .unwrap()
        .into_iter()
        .flat_map(|(_, queue)| queue)
        .collect();
    assert_eq!(stored.len(), 1);
    let env = Envelope::decode(&stored[0]).unwrap();
    assert_eq!(env.kind, EnvelopeKind::Handshake);
    assert_eq!(env.token, intro_token(&bob_id, epoch_day(NOW)));
    assert!(
        !stored[0]
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "plaintext must not appear in what the relay stores"
    );

    // Bob reconnects, checks in, and the message is delivered.
    let b_net = Arc::new(Libp2pTransport::new(LISTEN).await.unwrap());
    let collected = b_net
        .mailbox_checkin(&relay_addr, &bob.mailbox_tokens(NOW + 2))
        .await
        .unwrap();
    assert_eq!(collected, 1);
    bob.add_transport(Arc::clone(&b_net) as Arc<dyn Transport>);
    let events = bob.tick(NOW + 3, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::MessageReceived { body, .. } if body == plaintext)));
    let alice_id = events
        .iter()
        .find_map(|e| match e {
            Event::SessionEstablished { peer } => Some(*peer),
            _ => None,
        })
        .unwrap();

    // Bob's encrypted receipt and terminal capability control take the same
    // path back: sealed sender gave
    // him no return hints, so he routes via the shared relay, where alice's
    // earlier check-in already registered her filters. (His first flush had
    // no route and backed off — the retry runs once the backoff elapses.)
    bob.set_hints(
        &alice_id,
        &[DeliveryHint::Relay(relay_addr.clone())],
        &mut rng,
    )
    .unwrap();
    bob.tick(NOW + 60, &mut rng).await.unwrap();
    assert_eq!(bob.queued().unwrap(), 0, "receipt deposited");

    let collected = a_net
        .mailbox_checkin(&relay_addr, &alice.mailbox_tokens(NOW + 61))
        .await
        .unwrap();
    assert_eq!(collected, 2, "receipt plus terminal capability control");
    let events = alice.tick(NOW + 62, &mut rng).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == m1
        )),
        "end-to-end receipt drives Delivered — nothing faked"
    );
}
