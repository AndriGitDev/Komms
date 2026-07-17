//! C7 media acceptance over real ratchets and the production direct-QUIC stream.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{CallEndReason, CallPhase, Node, NodeError};
use kult_transport::{DeliveryHint, Libp2pTransport, Transport};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

async fn settle(alice: &mut Node, bob: &mut Node, rng: &mut StdRng, start: u64) {
    for round in 0..10 {
        alice.tick(start + round * 2, rng).await.unwrap();
        bob.tick(start + round * 2 + 1, rng).await.unwrap();
    }
}

#[tokio::test]
async fn authenticated_direct_quic_media_activates_and_carries_bounded_opus() {
    let mut rng = StdRng::seed_from_u64(0xc700_1001);
    let dir = tempfile::tempdir().unwrap();
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();

    let alice_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
            .await
            .unwrap(),
    );
    let bob_net = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
            .await
            .unwrap(),
    );
    let alice_addr = alice_net.wait_listen_addr().await.unwrap();
    let bob_addr = bob_net.wait_listen_addr().await.unwrap();
    alice.add_transport(Arc::clone(&alice_net) as Arc<dyn Transport>);
    bob.add_transport(Arc::clone(&bob_net) as Arc<dyn Transport>);

    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr(alice_addr)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(bob_addr)],
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
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    bob.tick(NOW + 32, &mut rng).await.unwrap();
    bob.answer_call(&call_id, NOW + 33, &mut rng).unwrap();
    bob.tick(NOW + 34, &mut rng).await.unwrap();
    alice.tick(NOW + 35, &mut rng).await.unwrap();

    for _ in 0..100 {
        alice.pump_call_media(NOW + 36).await.unwrap();
        bob.pump_call_media(NOW + 36).await.unwrap();
        if alice
            .calls()
            .iter()
            .find(|call| call.id == call_id)
            .is_some_and(|call| call.phase == CallPhase::Active)
            && bob
                .calls()
                .iter()
                .find(|call| call.id == call_id)
                .is_some_and(|call| call.phase == CallPhase::Active)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        alice
            .calls()
            .iter()
            .find(|call| call.id == call_id)
            .unwrap()
            .phase,
        CallPhase::Active
    );
    assert_eq!(
        bob.calls()
            .iter()
            .find(|call| call.id == call_id)
            .unwrap()
            .phase,
        CallPhase::Active
    );

    for sequence in 0..3u64 {
        assert!(alice
            .send_call_audio(&call_id, 10_000 + sequence * 20, &[0xf8, sequence as u8],)
            .unwrap());
        assert!(bob
            .send_call_audio(&call_id, 20_000 + sequence * 20, &[0xf9, sequence as u8],)
            .unwrap());
    }
    let mut heard_by_alice = None;
    let mut heard_by_bob = None;
    for _ in 0..100 {
        alice.pump_call_media(NOW + 37).await.unwrap();
        bob.pump_call_media(NOW + 37).await.unwrap();
        heard_by_alice = heard_by_alice.or_else(|| alice.take_call_audio(&call_id).unwrap());
        heard_by_bob = heard_by_bob.or_else(|| bob.take_call_audio(&call_id).unwrap());
        if heard_by_alice.is_some() && heard_by_bob.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let heard_by_alice = heard_by_alice.expect("Alice received Bob's authenticated Opus");
    assert_eq!(heard_by_alice.call_id, call_id);
    assert_eq!(heard_by_alice.opus_packet, [0xf9, 0]);
    assert_eq!(heard_by_alice.timestamp_ms, 20_000);
    let heard_by_bob = heard_by_bob.expect("Bob received Alice's authenticated Opus");
    assert_eq!(heard_by_bob.call_id, call_id);
    assert_eq!(heard_by_bob.opus_packet, [0xf8, 0]);
    assert_eq!(heard_by_bob.timestamp_ms, 10_000);

    // Eight capture packets is the complete writer budget. The ninth is
    // rejected instead of increasing latency, and the receiver keeps only
    // the newest six packets when native playout falls behind.
    for packet in 0..8u8 {
        assert!(alice
            .send_call_audio(&call_id, 30_000 + u64::from(packet) * 20, &[0xaa, packet],)
            .unwrap());
    }
    assert!(!alice.send_call_audio(&call_id, 31_000, &[0xaa, 8]).unwrap());
    for _ in 0..20 {
        alice.pump_call_media(NOW + 38).await.unwrap();
        bob.pump_call_media(NOW + 38).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let bounded = bob
        .take_call_audio(&call_id)
        .unwrap()
        .expect("bounded jitter output");
    assert_eq!(bounded.sequence, 6);
    assert_eq!(bounded.opus_packet, [0xaa, 2]);

    alice.hangup_call(&call_id, NOW + 39, &mut rng).unwrap();
    assert!(matches!(
        alice.send_call_audio(&call_id, 30_000, b"late"),
        Err(NodeError::InvalidCall)
    ));
    alice.tick(NOW + 40, &mut rng).await.unwrap();
    bob.tick(NOW + 41, &mut rng).await.unwrap();
    let ended = bob
        .calls()
        .into_iter()
        .find(|call| call.id == call_id)
        .unwrap();
    assert_eq!(ended.phase, CallPhase::Ended);
    assert_eq!(ended.end_reason, Some(CallEndReason::HungUp));
    assert_eq!(alice.messages_with(&bob_id).unwrap().len(), alice_history);
    assert_eq!(bob.messages_with(&alice_id).unwrap().len(), bob_history);
}
