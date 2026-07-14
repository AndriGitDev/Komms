//! Durable scheduled-outbox acceptance: no early crypto/queue work, restart
//! persistence, absolute UTC clock behavior, edit/cancel, and pairwise/group
//! activation into the ordinary honest delivery ladder.

use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, Node, ScheduledConversation};
use kult_store::{DeliveryState, Direction};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

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
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob.handshake_bundle(NOW, &mut rng).unwrap(),
            &[],
            NOW,
            &mut rng,
        )
        .unwrap();

    let cancelled = alice
        .schedule_message(&bob_id, b"do not send", NOW + 10, NOW, &mut rng)
        .unwrap();
    alice.cancel_scheduled_message(&cancelled).unwrap();
    alice.tick(NOW + 20, &mut rng).await.unwrap();
    assert!(alice.messages_with(&bob_id).unwrap().is_empty());

    let group = alice.create_group("crew", &[bob_id], &mut rng).unwrap();
    let id = alice
        .schedule_group_message(&group, b"meet later", NOW + 40, NOW + 20, &mut rng)
        .unwrap();
    alice.tick(NOW + 39, &mut rng).await.unwrap();
    assert!(alice.group_messages(&group).unwrap().is_empty());
    alice.tick(NOW + 40, &mut rng).await.unwrap();
    assert!(alice.scheduled_messages().unwrap().is_empty());
    let history = alice.group_messages(&group).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, id);
    assert_eq!(history[0].timestamp, NOW + 40);
    assert!(history[0]
        .deliveries
        .iter()
        .all(|delivery| delivery.state == DeliveryState::Queued));
}
