//! M3 node-level acceptance (first slice): two nodes exchange messages and
//! receipts over the libp2p internet transport on localhost — and when both
//! a millisecond link and a human-scale link are available, the scheduler
//! prefers the faster one.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{Event, Node};
use kult_store::DeliveryState;
use kult_transport::{DeliveryHint, Libp2pTransport, SneakernetTransport};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn received_bodies(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::MessageReceived { body, .. } => Some(body.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn nodes_exchange_over_localhost_quic() {
    let mut rng = StdRng::seed_from_u64(7);
    let dir = tempfile::tempdir().unwrap();

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();

    let a_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
            .await
            .unwrap(),
    );
    let b_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
            .await
            .unwrap(),
    );
    let a_addr = a_net.wait_listen_addr().await.unwrap();
    let b_addr = b_net.wait_listen_addr().await.unwrap();
    alice.add_transport(a_net);
    bob.add_transport(b_net);

    // Out-of-band exchange: bundles + each other's multiaddrs.
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(b_addr)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr(a_addr)],
            NOW,
            &mut rng,
        )
        .unwrap();

    // Alice → Bob: handshake flight + session message, one tick each side.
    let m1 = alice
        .send_message(&bob_id, b"hello over quic", NOW, &mut rng)
        .unwrap();
    let m2 = alice
        .send_message(&bob_id, b"and a second one", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    assert_eq!(
        alice.queued().unwrap(),
        0,
        "both envelopes acked by next hop"
    );

    let events = bob.tick(NOW + 2, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == alice_id)));
    let bodies = received_bodies(&events);
    assert!(bodies.contains(&b"hello over quic".to_vec()));
    assert!(bodies.contains(&b"and a second one".to_vec()));

    // Bob's encrypted receipt flowed back in the same tick's flush; Alice's
    // records reach Delivered — end-to-end proof, not transport ack.
    let events = alice.tick(NOW + 3, &mut rng).await.unwrap();
    let delivered: Vec<[u8; 16]> = events
        .iter()
        .filter_map(|e| match e {
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Delivered,
            } => Some(*id),
            _ => None,
        })
        .collect();
    assert!(delivered.contains(&m1) && delivered.contains(&m2));

    // Bob replies over the established session.
    bob.send_message(&alice_id, b"loud and clear", NOW + 4, &mut rng)
        .unwrap();
    bob.tick(NOW + 5, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 6, &mut rng).await.unwrap();
    assert_eq!(received_bodies(&events), vec![b"loud and clear".to_vec()]);
}

#[tokio::test]
async fn scheduler_prefers_fast_link_over_sneakernet() {
    let mut rng = StdRng::seed_from_u64(8);
    let dir = tempfile::tempdir().unwrap();
    let bob_spool = dir.path().join("bob-spool");

    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut rng).unwrap();

    // Alice has both carriers; Bob is reachable by both hints.
    let a_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
            .await
            .unwrap(),
    );
    let b_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
            .await
            .unwrap(),
    );
    let b_addr = b_net.wait_listen_addr().await.unwrap();
    alice.add_transport(a_net);
    alice.add_transport(Arc::new(
        SneakernetTransport::new(dir.path().join("alice-spool")).unwrap(),
    ));
    bob.add_transport(b_net);
    bob.add_transport(Arc::new(SneakernetTransport::new(&bob_spool).unwrap()));

    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[
                DeliveryHint::Spool(bob_spool.clone()),
                DeliveryHint::Multiaddr(b_addr),
            ],
            NOW,
            &mut rng,
        )
        .unwrap();

    alice
        .send_message(&bob_id, b"take the fast lane", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();

    // The envelope went over the wire, not into the spool directory.
    let spool_files = std::fs::read_dir(&bob_spool).unwrap().count();
    assert_eq!(spool_files, 0, "millis link outranks human-scale link");
    let events = bob.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(
        received_bodies(&events),
        vec![b"take the fast lane".to_vec()]
    );
}
