//! ADR-0030 first-contact admission and consent acceptance tests.

use std::sync::Arc;

use kult_crypto::{AuthorityDevicePrekeyBundle, KdfProfile};
use kult_node::{Event, Node};
use kult_store::{AdmissionTransportClass, DeliveryState};
use kult_transport::{DeliveryHint, SneakernetTransport};
use rand::{rngs::StdRng, SeedableRng};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn spool(path: &std::path::Path) -> Arc<SneakernetTransport> {
    Arc::new(SneakernetTransport::new(path).unwrap())
}

#[tokio::test]
async fn unknown_sender_is_provisional_until_explicit_accept() {
    let mut rng = StdRng::seed_from_u64(0x0030_2001);
    let directory = tempfile::tempdir().unwrap();
    let alice_inbox = directory.path().join("alice-spool");
    let bob_inbox = directory.path().join("bob-spool");
    let mut alice =
        Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    let recovery_path = directory.path().join("bob-account-authority.kra");
    let recovery_mnemonic = bob
        .export_account_recovery_authority(&recovery_path)
        .unwrap();
    let recovery_package = std::fs::read(&recovery_path).unwrap();
    alice.add_transport(spool(&alice_inbox));
    bob.add_transport(spool(&bob_inbox));

    // Alice advertises a return route in the device-signed bundle carried
    // inside her sealed first flight. Bob has not added Alice.
    let alice_bundle = alice
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(alice_inbox.clone())], NOW, &mut rng)
        .unwrap();
    let alice_id = AuthorityDevicePrekeyBundle::decode(&alice_bundle)
        .unwrap()
        .manifest
        .account()
        .ed;
    let bob_bundle = bob
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(bob_inbox.clone())], NOW, &mut rng)
        .unwrap();
    let bob_id = alice
        .add_contact(
            "Bob",
            &bob_bundle,
            &[DeliveryHint::Spool(bob_inbox.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();

    let outbound = alice
        .send_message(&bob_id, b"hello from an unknown sender", NOW + 1, &mut rng)
        .unwrap();
    alice.tick(NOW + 2, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 3, &mut rng).await.unwrap();

    assert!(events
        .iter()
        .any(|event| matches!(event, Event::MessageRequestReceived { .. })));
    assert!(bob.contacts().unwrap().is_empty());
    assert!(bob.messages_with(&alice_id).unwrap().is_empty());
    let requests = bob.message_requests().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].account, alice_id);
    assert_eq!(requests[0].preview, "hello from an unknown sender");
    assert_eq!(requests[0].safety_number.len(), 35);
    assert_eq!(requests[0].transport, AdmissionTransportClass::Delayed);

    // A restart preserves the sealed request but still does not expose a
    // live contact/session.
    drop(bob);
    let mut bob = Node::open(&directory.path().join("bob.db"), b"b").unwrap();
    bob.add_transport(spool(&bob_inbox));
    assert_eq!(bob.message_requests().unwrap().len(), 1);
    assert!(bob.contacts().unwrap().is_empty());

    // Recovery never imports provisional sessions, previews, invitation
    // capabilities, or admission tombstones into the fresh device.
    let (backup, backup_mnemonic) = bob.export_backup(NOW + 4, &mut rng).unwrap();
    let recovered = Node::restore_with_recovery_authority(
        &directory.path().join("bob-recovered.db"),
        &backup,
        &backup_mnemonic,
        &recovery_package,
        &recovery_mnemonic,
        NOW + 4,
        b"recovered",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert!(recovered.message_requests().unwrap().is_empty());
    assert!(recovered.contacts().unwrap().is_empty());
    assert!(recovered.messages_with(&alice_id).unwrap().is_empty());
    drop(recovered);

    let request = requests[0].id;
    assert_eq!(
        bob.accept_message_request(&request, "Alice", NOW + 4, &mut rng)
            .unwrap(),
        alice_id
    );
    assert!(bob.message_requests().unwrap().is_empty());
    assert_eq!(bob.contacts().unwrap()[0].name, "Alice");
    assert_eq!(
        bob.messages_with(&alice_id).unwrap()[0].body,
        b"hello from an unknown sender"
    );

    let events = bob.tick(NOW + 5, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageRequestAccepted { request: got, peer }
            if *got == request && *peer == alice_id
    )));
    let events = alice.tick(NOW + 6, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::DeliveryUpdated {
            id,
            state: DeliveryState::Delivered,
        } if *id == outbound
    )));
}

#[tokio::test]
async fn delete_and_block_leave_no_contact_or_history() {
    let mut rng = StdRng::seed_from_u64(0x0030_2002);
    let directory = tempfile::tempdir().unwrap();
    let alice_inbox = directory.path().join("alice-spool");
    let bob_inbox = directory.path().join("bob-spool");
    let mut alice =
        Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(spool(&alice_inbox));
    bob.add_transport(spool(&bob_inbox));
    let alice_bundle = alice
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(alice_inbox.clone())], NOW, &mut rng)
        .unwrap();
    let alice_id = AuthorityDevicePrekeyBundle::decode(&alice_bundle)
        .unwrap()
        .manifest
        .account()
        .ed;
    let bob_bundle = bob
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(bob_inbox.clone())], NOW, &mut rng)
        .unwrap();
    let bob_id = alice
        .add_contact("Bob", &bob_bundle, &[], NOW, &mut rng)
        .unwrap();

    alice
        .send_message(&bob_id, b"please connect", NOW + 1, &mut rng)
        .unwrap();
    alice.tick(NOW + 2, &mut rng).await.unwrap();
    bob.tick(NOW + 3, &mut rng).await.unwrap();
    let request = bob.message_requests().unwrap()[0].id;
    bob.block_message_request(&request, NOW + 4, &mut rng)
        .unwrap();

    assert!(bob.message_requests().unwrap().is_empty());
    assert!(bob.contacts().unwrap().is_empty());
    assert!(bob.messages_with(&alice_id).unwrap().is_empty());
    let events = bob.tick(NOW + 5, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageRequestBlocked { request: got } if *got == request
    )));
}
