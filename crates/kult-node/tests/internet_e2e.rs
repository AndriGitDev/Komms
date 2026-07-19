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

/// M3 acceptance slice: no manual configuration beyond sharing kult
/// addresses. Bob publishes his prekey bundle (with his multiaddr riding in
/// it) on the DHT; Alice — knowing only Bob's address string and a common
/// bootstrap peer — fetches it, verifies it, and messages him. The message
/// arriving over Alice's only transport proves the delivery hints came from
/// the DHT record, not out-of-band.
#[tokio::test]
async fn contact_by_kult_address_alone_via_dht() {
    let mut rng = StdRng::seed_from_u64(9);
    let dir = tempfile::tempdir().unwrap();

    // Any reachable peer bootstraps the DHT — here a bare transport with no
    // node behind it, standing in for a community node.
    let seed = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();

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
    a_net.bootstrap(&[seed_addr.as_str()]).await.unwrap();
    b_net.bootstrap(&[seed_addr.as_str()]).await.unwrap();

    // Bob publishes: bundle + where to reach him, keyed by his address.
    let b_hints: Vec<DeliveryHint> = b_net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    let a_hints: Vec<DeliveryHint> = a_net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    alice.add_transport(Arc::clone(&a_net) as Arc<dyn kult_transport::Transport>);
    alice.add_discovery(a_net);
    bob.add_transport(Arc::clone(&b_net) as Arc<dyn kult_transport::Transport>);
    bob.add_discovery(Arc::clone(&b_net) as Arc<dyn kult_transport::Discovery>);
    bob.publish_bundle(&b_hints, NOW).await.unwrap();
    // Alice publishes too: Bob learns her only through her (sealed-sender)
    // handshake, which carries no return path — his receipt finds its way
    // back via her DHT record.
    alice.publish_bundle(&a_hints, NOW).await.unwrap();

    // Alice knows nothing but the address string.
    let bob_id = alice
        .add_contact_by_address("bob", &bob.address(), NOW, &mut rng)
        .await
        .unwrap();
    assert_eq!(bob_id, bob.peer_id());

    let m1 = alice
        .send_message(&bob_id, b"found you by address", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(
        received_bodies(&events),
        vec![b"found you by address".to_vec()]
    );

    // Bob's encrypted receipt drives Alice's record to Delivered.
    let events = alice.tick(NOW + 3, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == m1
    )));

    // An address nobody published resolves to an honest BundleNotFound.
    let ghost = Node::create(&dir.path().join("g.db"), b"g", TEST_KDF, &mut rng).unwrap();
    assert!(matches!(
        alice
            .add_contact_by_address("ghost", &ghost.address(), NOW, &mut rng)
            .await,
        Err(kult_node::NodeError::BundleNotFound)
    ));
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

/// A pairing-time hint goes stale whenever the peer rebinds to fresh
/// OS-assigned ports (mobile shells restart constantly). The delivery
/// engine must not retry the dead route forever: after a failed attempt it
/// re-consults the discovery plane, finds the freshly published bundle,
/// replaces the stored route, and delivers.
#[tokio::test]
async fn stale_pairing_hint_heals_via_discovery_refresh() {
    let mut rng = StdRng::seed_from_u64(41);
    let dir = tempfile::tempdir().unwrap();

    let seed = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();

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
    a_net.bootstrap(&[seed_addr.as_str()]).await.unwrap();
    b_net.bootstrap(&[seed_addr.as_str()]).await.unwrap();

    b_net.wait_listen_addr().await.unwrap();
    let a_hints: Vec<DeliveryHint> = a_net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    let b_hints: Vec<DeliveryHint> = b_net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    alice.add_transport(Arc::clone(&a_net) as Arc<dyn kult_transport::Transport>);
    alice.add_discovery(a_net);
    bob.add_transport(Arc::clone(&b_net) as Arc<dyn kult_transport::Transport>);
    bob.add_discovery(Arc::clone(&b_net) as Arc<dyn kult_transport::Discovery>);

    // Both publish their *current* addresses; the receipt path back to
    // Alice also rides her record.
    bob.publish_bundle(&b_hints, NOW).await.unwrap();
    alice.publish_bundle(&a_hints, NOW).await.unwrap();

    // Pairing exchange — but Alice captured Bob's address from a previous
    // run. Every run mints a fresh transport pseudonym and fresh
    // OS-assigned ports, so the stale hint names a peer id and port that no
    // longer exist anywhere (the routing table cannot rescue the dial the
    // way it could for a merely re-ported current pseudonym). TCP so the
    // refusal is immediate.
    let ghost = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let ghost_id = ghost
        .wait_listen_addr()
        .await
        .unwrap()
        .split_once("/p2p/")
        .map(|(_, id)| id.to_owned())
        .unwrap();
    drop(ghost);
    let stale = format!("/ip4/127.0.0.1/tcp/9/p2p/{ghost_id}");
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(stale)],
            NOW,
            &mut rng,
        )
        .unwrap();
    bob.add_contact("alice", &alice_bundle, &a_hints, NOW, &mut rng)
        .unwrap();

    let m1 = alice
        .send_message(&bob_id, b"through the refresh", NOW, &mut rng)
        .unwrap();

    // First flush dials the dead route and fails into backoff; nothing
    // reaches Bob.
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(received_bodies(&events), Vec::<Vec<u8>>::new());
    assert!(alice.queued().unwrap() > 0, "stuck on the stale route");

    // Past the backoff, the failing route triggers a discovery refresh:
    // Bob's published bundle carries his live address and delivery heals.
    alice.tick(NOW + 40, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 41, &mut rng).await.unwrap();
    assert_eq!(
        received_bodies(&events),
        vec![b"through the refresh".to_vec()]
    );
    assert_eq!(alice.queued().unwrap(), 0, "queue drained after refresh");

    // Bob's encrypted receipt drives Alice's record to Delivered over the
    // refreshed route.
    let events = alice.tick(NOW + 42, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == m1
    )));
}
