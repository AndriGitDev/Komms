//! B5 acceptance: petnames are NFC-normalized sealed local metadata, exact
//! peer ids remain the only mutation targets, duplicates are allowed after
//! explicit warning review, and rename creates no delivery work.

use kult_crypto::KdfProfile;
use kult_node::{ContactNameWarning, Event, Node, NodeError};
use rand::{rngs::StdRng, SeedableRng};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b5-contact-rename-parity.json"
    ))
    .expect("valid shared B5 fixture")
}

#[test]
fn rename_is_normalized_duplicate_capable_durable_and_delivery_free() {
    let fixture = fixture();
    let mut rng = StdRng::seed_from_u64(5);
    let directory = tempfile::tempdir().unwrap();
    let alice_path = directory.path().join("alice.db");
    let mut alice = Node::create(&alice_path, b"alice", TEST_KDF, &mut rng).unwrap();
    let bob_path = directory.path().join("bob.db");
    let mut bob = Node::create(&bob_path, b"bob", TEST_KDF, &mut rng).unwrap();
    let carol_path = directory.path().join("carol.db");
    let mut carol = Node::create(&carol_path, b"carol", TEST_KDF, &mut rng).unwrap();

    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let carol_bundle = carol.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_peer = alice
        .add_contact("Bob", &bob_bundle, &[], NOW, &mut rng)
        .unwrap();
    let carol_peer = alice
        .add_contact(
            fixture["duplicate_name"].as_str().unwrap(),
            &carol_bundle,
            &[],
            NOW,
            &mut rng,
        )
        .unwrap();
    assert_ne!(bob_peer, carol_peer);
    let queued_before = alice.queued().unwrap();

    let normalized = alice
        .rename_contact(
            &bob_peer,
            fixture["decomposed_name"].as_str().unwrap(),
            false,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        normalized.normalized_name,
        fixture["normalized_name"].as_str().unwrap()
    );
    assert!(normalized.changed_by_normalization);
    assert!(normalized.warnings.is_empty());

    let duplicate = alice
        .assess_contact_name(&bob_peer, fixture["duplicate_name"].as_str().unwrap())
        .unwrap();
    assert_eq!(duplicate.duplicate_count, 1);
    assert_eq!(duplicate.warnings, vec![ContactNameWarning::DuplicateName]);
    assert!(matches!(
        alice.rename_contact(
            &bob_peer,
            fixture["duplicate_name"].as_str().unwrap(),
            false,
            &mut rng,
        ),
        Err(NodeError::ContactNameReviewRequired)
    ));
    let accepted = alice
        .rename_contact(
            &bob_peer,
            fixture["duplicate_name"].as_str().unwrap(),
            true,
            &mut rng,
        )
        .unwrap();
    assert_eq!(accepted.duplicate_count, 1);
    assert_eq!(
        alice
            .contacts()
            .unwrap()
            .iter()
            .filter(|contact| { contact.name == fixture["duplicate_name"].as_str().unwrap() })
            .count(),
        2
    );

    let spoof = alice
        .assess_contact_name(&bob_peer, fixture["confusable_name"].as_str().unwrap())
        .unwrap();
    assert!(spoof.warnings.contains(&ContactNameWarning::ConfusableName));
    assert_eq!(alice.queued().unwrap(), queued_before);
    assert!(alice.drain_events().iter().any(|event| {
        matches!(event, Event::ContactRenamed { peer, name }
            if peer == &bob_peer && name == fixture["duplicate_name"].as_str().unwrap())
    }));

    drop(alice);
    let reopened = Node::open(&alice_path, b"alice").unwrap();
    assert_eq!(
        reopened
            .contacts()
            .unwrap()
            .into_iter()
            .find(|contact| contact.peer == bob_peer)
            .unwrap()
            .name,
        fixture["duplicate_name"].as_str().unwrap()
    );

    let (backup, mnemonic) = reopened.export_backup(NOW + 1, &mut rng).unwrap();
    assert_eq!(&backup[..4], b"KKR4");
    let restored = Node::restore(
        &directory.path().join("restored.db"),
        &backup,
        &mnemonic,
        b"restored",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        restored
            .contacts()
            .unwrap()
            .into_iter()
            .find(|contact| contact.peer == bob_peer)
            .unwrap()
            .name,
        fixture["duplicate_name"].as_str().unwrap()
    );
}
