//! Backup/restore at the node level (docs/07-storage.md §4): a device is
//! lost, its backup restores onto a new one, the identity resumes with
//! contacts and history intact — and messaging works again in **both**
//! directions because the restored node proactively re-handshakes every
//! peer that had a live session at export time (ratchet state is
//! deliberately not portable).

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{Event, Node};
use kult_store::DeliveryState;
use kult_transport::{DeliveryHint, SneakernetTransport};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only.
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
async fn backup_restores_identity_and_rekeys_sessions() {
    let mut rng = StdRng::seed_from_u64(21);
    let dir = tempfile::tempdir().unwrap();
    let alice_inbox = dir.path().join("alice-spool");
    let bob_inbox = dir.path().join("bob-spool");
    let spool = |path: &std::path::Path| Arc::new(SneakernetTransport::new(path).unwrap());

    // ---- Before: Alice and Bob converse normally. -----------------------
    let mut alice = Node::create(&dir.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(spool(&alice_inbox));
    bob.add_transport(spool(&bob_inbox));

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
    alice.mark_verified(&bob_id, &mut rng).unwrap();

    alice
        .send_message(&bob_id, b"before the crash", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bob.tick(NOW + 2, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 3, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated {
            state: DeliveryState::Delivered,
            ..
        }
    )));

    // ---- Backup, then the device is lost. --------------------------------
    let (backup, mnemonic) = alice.export_backup(NOW + 10, &mut rng).unwrap();
    let old_address = alice.address();
    drop(alice);

    // A wrong mnemonic cannot open it.
    let wrong = "abandon ".repeat(23) + "art";
    assert!(Node::restore(
        &dir.path().join("wrong.db"),
        &backup,
        &wrong,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .is_err());

    // ---- Restore onto a new device. --------------------------------------
    let mut alice = Node::restore(
        &dir.path().join("alice-new.db"),
        &backup,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    alice.add_transport(spool(&alice_inbox));

    // The identity resumes; contacts and history are intact.
    assert_eq!(alice.address(), old_address);
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "bob");
    assert!(contacts[0].verified);
    let history = alice.messages_with(&bob_id).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, b"before the crash");

    // First tick: the reset marker becomes a proactive re-handshake.
    alice.tick(NOW + 100, &mut rng).await.unwrap();

    // Bob sees a session re-establishment for a known contact — and no
    // phantom message (the empty first flight is session maintenance).
    let events = bob.tick(NOW + 101, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == alice_id)));
    assert!(received_bodies(&events).is_empty());
    assert_eq!(bob.messages_with(&alice_id).unwrap().len(), 1);

    // ---- Traffic flows again, both directions, on the new ratchet. -------
    bob.send_message(&alice_id, b"glad you're back", NOW + 200, &mut rng)
        .unwrap();
    bob.tick(NOW + 201, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 202, &mut rng).await.unwrap();
    assert_eq!(received_bodies(&events), vec![b"glad you're back".to_vec()]);

    let reply = alice
        .send_message(&bob_id, b"new device, same me", NOW + 300, &mut rng)
        .unwrap();
    alice.tick(NOW + 301, &mut rng).await.unwrap();
    bob.tick(NOW + 302, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 303, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated {
            id,
            state: DeliveryState::Delivered,
        } if *id == reply
    )));

    // The marker is spent: later ticks queue no further handshakes.
    alice.tick(NOW + 400, &mut rng).await.unwrap();
    assert_eq!(alice.queued().unwrap(), 0);
}

#[tokio::test]
async fn send_before_first_tick_also_rekeys() {
    // A user who restores and immediately hits send must not burn the
    // message on the archived bundle's consumed one-time prekey: the
    // reset marker selects the OPK-less handshake on the send path too.
    let mut rng = StdRng::seed_from_u64(22);
    let dir = tempfile::tempdir().unwrap();
    let alice_inbox = dir.path().join("alice-spool");
    let bob_inbox = dir.path().join("bob-spool");
    let spool = |path: &std::path::Path| Arc::new(SneakernetTransport::new(path).unwrap());

    let mut alice = Node::create(&dir.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(spool(&alice_inbox));
    bob.add_transport(spool(&bob_inbox));

    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::Spool(bob_inbox.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();
    bob.add_contact(
        "alice",
        &alice_bundle,
        &[DeliveryHint::Spool(alice_inbox.clone())],
        NOW,
        &mut rng,
    )
    .unwrap();

    // Establish the original session (consumes Bob's one-time prekey).
    alice
        .send_message(&bob_id, b"first", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bob.tick(NOW + 2, &mut rng).await.unwrap();

    let (backup, mnemonic) = alice.export_backup(NOW + 10, &mut rng).unwrap();
    drop(alice);
    let mut alice = Node::restore(
        &dir.path().join("alice-new.db"),
        &backup,
        &mnemonic,
        b"a",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    alice.add_transport(spool(&alice_inbox));

    // Send *before* any tick ran.
    let id = alice
        .send_message(&bob_id, b"straight back to it", NOW + 50, &mut rng)
        .unwrap();
    alice.tick(NOW + 51, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 52, &mut rng).await.unwrap();
    assert_eq!(
        received_bodies(&events),
        vec![b"straight back to it".to_vec()]
    );
    let events = alice.tick(NOW + 53, &mut rng).await.unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::DeliveryUpdated {
            id: got,
            state: DeliveryState::Delivered,
        } if *got == id
    )));
}
