//! M3 node-level acceptance (first slice): two nodes exchange messages and
//! receipts over the libp2p internet transport on localhost — and when both
//! a millisecond link and a human-scale link are available, the scheduler
//! prefers the faster one.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{DiscoveryMode, DiscoveryPublicationPolicy, Event, Node};
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

async fn drive_direct_pair(
    alice: &mut Node,
    bob: &mut Node,
    alice_rng: &mut StdRng,
    bob_rng: &mut StdRng,
    start: u64,
    rounds: u64,
) -> (Vec<Event>, Vec<Event>) {
    tokio::join!(
        async {
            let mut events = Vec::new();
            for round in 0..rounds {
                events.extend(alice.tick(start + round * 40, alice_rng).await.unwrap());
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            events
        },
        async {
            let mut events = Vec::new();
            tokio::time::sleep(Duration::from_millis(250)).await;
            for round in 0..rounds {
                events.extend(bob.tick(start + round * 40 + 1, bob_rng).await.unwrap());
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            events
        }
    )
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
    let mut alice_ticks = StdRng::seed_from_u64(0x3000_0001);
    let mut bob_ticks = StdRng::seed_from_u64(0x3000_0002);
    let (alice_events, bob_events) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 1,
        8,
    )
    .await;
    assert_eq!(
        alice.queued().unwrap(),
        0,
        "both envelopes acked by next hop"
    );

    assert!(bob_events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == alice_id)));
    let bodies = received_bodies(&bob_events);
    assert!(bodies.contains(&b"hello over quic".to_vec()));
    assert!(bodies.contains(&b"and a second one".to_vec()));

    // Bob's encrypted receipt flowed back through durable direct admission;
    // Alice's records reach Delivered — end-to-end proof, not transport ack.
    let delivered: Vec<[u8; 16]> = alice_events
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
    let (_, alice_events) = drive_direct_pair(
        &mut bob,
        &mut alice,
        &mut bob_ticks,
        &mut alice_ticks,
        NOW + 400,
        5,
    )
    .await;
    assert!(received_bodies(&alice_events).contains(&b"loud and clear".to_vec()));
}

#[tokio::test]
async fn simultaneous_first_flights_converge_with_follow_up_messages() {
    let mut setup_rng = StdRng::seed_from_u64(0x3000_4000);
    let dir = tempfile::tempdir().unwrap();
    let mut alice = Node::create(&dir.path().join("a.db"), b"a", TEST_KDF, &mut setup_rng).unwrap();
    let mut bob = Node::create(&dir.path().join("b.db"), b"b", TEST_KDF, &mut setup_rng).unwrap();

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

    let alice_bundle = alice.handshake_bundle(NOW, &mut setup_rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut setup_rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(b_addr)],
            NOW,
            &mut setup_rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr(a_addr)],
            NOW,
            &mut setup_rng,
        )
        .unwrap();

    alice
        .send_message(&bob_id, b"alice first", NOW, &mut setup_rng)
        .unwrap();
    alice
        .send_message(&bob_id, b"alice follow-up", NOW + 1, &mut setup_rng)
        .unwrap();
    bob.send_message(&alice_id, b"bob first", NOW, &mut setup_rng)
        .unwrap();
    bob.send_message(&alice_id, b"bob follow-up", NOW + 1, &mut setup_rng)
        .unwrap();

    let mut alice_ticks = StdRng::seed_from_u64(0x3000_4001);
    let mut bob_ticks = StdRng::seed_from_u64(0x3000_4002);
    let (mut alice_events, mut bob_events) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 2,
        10,
    )
    .await;
    let (more_alice, more_bob) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 500,
        10,
    )
    .await;
    alice_events.extend(more_alice);
    bob_events.extend(more_bob);

    let alice_bodies = received_bodies(&alice_events);
    let bob_bodies = received_bodies(&bob_events);
    assert!(alice_bodies.contains(&b"bob first".to_vec()));
    assert!(alice_bodies.contains(&b"bob follow-up".to_vec()));
    assert!(bob_bodies.contains(&b"alice first".to_vec()));
    assert!(bob_bodies.contains(&b"alice follow-up".to_vec()));
}

/// M3 acceptance slice: no manual configuration beyond sharing a Connect
/// code. Bob publishes his fixed capability-scoped record (with his multiaddr
/// inside it) on the DHT; Alice — knowing only the code and a common bootstrap
/// peer — fetches it, verifies it, and messages him. The message arriving over
/// Alice's only transport proves the delivery hints came from the DHT record,
/// not out-of-band.
#[tokio::test]
async fn contact_by_connect_code_via_dht() {
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

    // Bob publishes: authority, ingress bundle, and reachability under
    // capability-derived weekly locators.
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
    bob.publish_bundle_with_policy(
        &b_hints,
        DiscoveryPublicationPolicy {
            mode: DiscoveryMode::Sovereign,
            publish_direct_routes: true,
        },
        NOW,
    )
    .await
    .unwrap();
    // Alice publishes too: Bob learns her only through her (sealed-sender)
    // handshake, which carries no return path — his receipt finds its way
    // back via her DHT record.
    alice
        .publish_bundle_with_policy(
            &a_hints,
            DiscoveryPublicationPolicy {
                mode: DiscoveryMode::Sovereign,
                publish_direct_routes: true,
            },
            NOW,
        )
        .await
        .unwrap();

    // Alice knows nothing but Bob's capability-scoped Connect code.
    let bob_id = alice
        .add_contact_by_address("bob", &bob.connect_code().unwrap(), NOW, &mut rng)
        .await
        .unwrap();
    assert_eq!(bob_id, bob.peer_id());

    let m1 = alice
        .send_message(&bob_id, b"found you by Connect code", NOW, &mut rng)
        .unwrap();
    let mut alice_ticks = StdRng::seed_from_u64(0x3000_1001);
    let mut bob_ticks = StdRng::seed_from_u64(0x3000_1002);
    let (alice_events, bob_events) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 1,
        8,
    )
    .await;
    assert!(received_bodies(&bob_events).is_empty());
    assert!(bob_events
        .iter()
        .any(|event| matches!(event, Event::MessageRequestReceived { .. })));
    assert!(bob.contacts().unwrap().is_empty());
    let request = bob.message_requests().unwrap().remove(0);
    assert_eq!(request.preview, "found you by Connect code");
    bob.accept_message_request(&request.id, "alice", NOW + 320, &mut bob_ticks)
        .unwrap();
    assert_eq!(
        bob.messages_with(&request.account).unwrap()[0].body,
        b"found you by Connect code"
    );

    // Bob's encrypted receipt drives Alice's record to Delivered.
    let (_, accepted_events) = drive_direct_pair(
        &mut bob,
        &mut alice,
        &mut bob_ticks,
        &mut alice_ticks,
        NOW + 321,
        6,
    )
    .await;
    assert!(alice_events
        .iter()
        .chain(accepted_events.iter())
        .any(|e| matches!(
            e,
            Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == m1
        )));

    // A Connect capability nobody published resolves to an honest
    // BundleNotFound.
    let ghost = Node::create(&dir.path().join("g.db"), b"g", TEST_KDF, &mut rng).unwrap();
    assert!(matches!(
        alice
            .add_contact_by_address("ghost", &ghost.connect_code().unwrap(), NOW + 600, &mut rng,)
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
    let mut alice_ticks = StdRng::seed_from_u64(0x3000_2001);
    let mut bob_ticks = StdRng::seed_from_u64(0x3000_2002);
    let (_, bob_events) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 1,
        8,
    )
    .await;

    // The envelope went over the wire, not into the spool directory.
    let spool_files = std::fs::read_dir(&bob_spool).unwrap().count();
    assert_eq!(spool_files, 0, "millis link outranks human-scale link");
    assert!(received_bodies(&bob_events).is_empty());
    let request = bob.message_requests().unwrap().remove(0);
    assert_eq!(request.preview, "take the fast lane");
    assert_eq!(
        request.transport,
        kult_store::AdmissionTransportClass::Direct
    );
    bob.accept_message_request(&request.id, "alice", NOW + 320, &mut bob_ticks)
        .unwrap();
    assert_eq!(
        bob.messages_with(&request.account).unwrap()[0].body,
        b"take the fast lane"
    );
}

/// A pairing-time hint can go stale whenever a peer rebinds to fresh
/// OS-assigned ports. Public discovery must not become a post-pairing
/// tracking oracle: only a bundle/control received over the authenticated
/// relationship may replace that route.
#[tokio::test]
async fn stale_pairing_hint_heals_only_via_authenticated_peer_update() {
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

    // Public Standard records deliberately omit these direct routes. Their
    // presence in the DHT therefore cannot heal a paired contact.
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
    let alice_id = bob
        .add_contact("alice", &alice_bundle, &a_hints, NOW, &mut rng)
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

    // A normal authenticated first flight in the other direction carries
    // Bob's current relationship-scoped return bundle. Only that update may
    // replace Alice's stale route.
    bob.send_message(&alice_id, b"authenticated route update", NOW + 3, &mut rng)
        .unwrap();
    let mut alice_ticks = StdRng::seed_from_u64(0x3000_3001);
    let mut bob_ticks = StdRng::seed_from_u64(0x3000_3002);
    let (bob_update_events, alice_update_events) = drive_direct_pair(
        &mut bob,
        &mut alice,
        &mut bob_ticks,
        &mut alice_ticks,
        NOW + 40,
        8,
    )
    .await;
    assert!(received_bodies(&alice_update_events).contains(&b"authenticated route update".to_vec()));

    // The authenticated first flight replaced Alice's stale source. A second
    // bounded pass retries her already-queued first flight over that route.
    let (alice_events, bob_events) = drive_direct_pair(
        &mut alice,
        &mut bob,
        &mut alice_ticks,
        &mut bob_ticks,
        NOW + 400,
        8,
    )
    .await;
    assert!(received_bodies(&bob_update_events)
        .into_iter()
        .chain(received_bodies(&bob_events))
        .any(|body| body == b"through the refresh"));
    let (_, receipt_events) = drive_direct_pair(
        &mut bob,
        &mut alice,
        &mut bob_ticks,
        &mut alice_ticks,
        NOW + 800,
        6,
    )
    .await;

    // Bob's encrypted receipt drives Alice's record to Delivered over the
    // pairwise-authenticated route.
    assert!(alice_update_events
        .iter()
        .chain(alice_events.iter())
        .chain(receipt_events.iter())
        .any(|e| matches!(
            e,
            Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == m1
        )));
}
