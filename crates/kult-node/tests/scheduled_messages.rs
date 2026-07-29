//! Durable scheduled-outbox acceptance: no early crypto/queue work, restart
//! persistence, absolute UTC clock behavior, edit/cancel, and pairwise/group
//! activation into the ordinary honest delivery ladder.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, GroupSecurityLevel, Node, ScheduledConversation};
use kult_protocol::Envelope;
use kult_store::{DeliveryState, Direction};
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Net = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

struct MockLink {
    net: Net,
    me: u32,
    online: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for MockLink {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Free,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        if self.online.load(Ordering::SeqCst) && matches!(peer, DeliveryHint::MeshNode(_)) {
            Reachability::Now
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::UnsupportedHint);
        }
        let DeliveryHint::MeshNode(recipient) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(*recipient)
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

#[tokio::test]
async fn pairwise_schedule_survives_restart_edit_clock_changes_and_offline_due_time() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.db");
    let mut rng = StdRng::seed_from_u64(0x5ced_0001);
    let mut alice = Node::create(&alice_path, b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact("bob", &bob_bundle, &[], NOW, &mut rng)
        .unwrap();

    let id = alice
        .schedule_message(&bob_id, b"first draft", NOW + 100, NOW, &mut rng)
        .unwrap();
    assert_eq!(alice.queued().unwrap(), 0);
    assert!(alice.messages_with(&bob_id).unwrap().is_empty());
    let scheduled = alice.scheduled_messages().unwrap();
    assert_eq!(scheduled.len(), 1);
    assert_eq!(scheduled[0].id, id);
    assert_eq!(scheduled[0].not_before, NOW + 100);
    assert!(matches!(
        scheduled[0].conversation,
        ScheduledConversation::Peer(peer) if peer == bob_id
    ));

    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    alice
        .edit_scheduled_message(&id, b"final text", NOW + 200, NOW + 20, &mut rng)
        .unwrap();

    // Crossing the original instant and then rolling the clock backward do
    // not change the replacement absolute instant.
    alice.tick(NOW + 101, &mut rng).await.unwrap();
    alice.tick(NOW + 60, &mut rng).await.unwrap();
    assert!(alice.messages_with(&bob_id).unwrap().is_empty());
    assert_eq!(alice.scheduled_messages().unwrap()[0].not_before, NOW + 200);

    // Offline at the instant: activation creates an ordinary queued record
    // and durable encrypted envelope, but no transport can claim it was sent.
    let events = alice.tick(NOW + 200, &mut rng).await.unwrap();
    assert!(events.iter().any(
        |event| matches!(event, Event::ScheduledMessageActivated { id: seen } if *seen == id)
    ));
    assert!(events.iter().any(|event| matches!(
        event,
        Event::DeliveryUpdated {
            id: seen,
            state: DeliveryState::Queued,
        } if *seen == id
    )));
    assert!(alice.scheduled_messages().unwrap().is_empty());
    assert!(alice.queued().unwrap() >= 1);
    let history = alice.messages_with(&bob_id).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, id);
    assert_eq!(history[0].timestamp, NOW + 200);
    assert_eq!(history[0].direction, Direction::Outbound);
    assert_eq!(history[0].state, DeliveryState::Queued);
}

#[tokio::test]
async fn scheduled_cancel_and_group_activation_are_first_class() {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = StdRng::seed_from_u64(0x5ced_0002);
    let net = Net::default();
    let online = Arc::new(AtomicBool::new(true));
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(MockLink {
        net: net.clone(),
        me: 1,
        online: online.clone(),
    }));
    bob.add_transport(Arc::new(MockLink {
        net,
        me: 2,
        online: online.clone(),
    }));
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
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

    let cancelled = alice
        .schedule_message(&bob_id, b"do not send", NOW + 10, NOW, &mut rng)
        .unwrap();
    alice.cancel_scheduled_message(&cancelled).unwrap();
    alice.tick(NOW + 20, &mut rng).await.unwrap();
    assert!(alice.messages_with(&bob_id).unwrap().is_empty());

    let group = alice.create_group("crew", &[bob_id], &mut rng).unwrap();
    let id = alice
        .schedule_group_message(&group, b"meet later", NOW + 100, NOW + 20, &mut rng)
        .unwrap();
    for round in 0..6 {
        alice.tick(NOW + 21 + round * 2, &mut rng).await.unwrap();
        bob.tick(NOW + 22 + round * 2, &mut rng).await.unwrap();
    }
    if alice.group_security_info(&group).unwrap().level == GroupSecurityLevel::UpgradeRequired {
        alice.group_upgrade_security(&group, &mut rng).unwrap();
    }
    for round in 0..6 {
        alice.tick(NOW + 33 + round * 2, &mut rng).await.unwrap();
        bob.tick(NOW + 34 + round * 2, &mut rng).await.unwrap();
    }
    assert_eq!(
        alice.group_security_info(&group).unwrap().level,
        GroupSecurityLevel::RecipientAuthenticated
    );
    online.store(false, Ordering::SeqCst);
    alice.tick(NOW + 99, &mut rng).await.unwrap();
    assert!(alice.group_messages(&group).unwrap().is_empty());
    alice.tick(NOW + 100, &mut rng).await.unwrap();
    assert!(alice.scheduled_messages().unwrap().is_empty());
    let history = alice.group_messages(&group).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, id);
    assert_eq!(history[0].timestamp, NOW + 100);
    assert!(history[0]
        .deliveries
        .iter()
        .all(|delivery| delivery.state == DeliveryState::Queued));
}
