//! Capability-scoped discovery and authenticated post-pairing upgrade tests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};

use kult_crypto::{
    discovery_epoch, open_discovery_record, ConnectCode, KdfProfile, DISCOVERY_RECORD_SIZE,
};
use kult_node::{DiscoveryMode, DiscoveryPublicationPolicy, Node, NodeError};
use kult_transport::{
    DeliveryHint, Discovery, DiscoveryNamespace, Result as TransportResult, SneakernetTransport,
};

const NOW: u64 = 1_900_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Clone)]
struct StoredDiscoveryRecord {
    namespace: DiscoveryNamespace,
    key: [u8; 32],
    value: Vec<u8>,
    expires_at: u64,
}

#[derive(Default)]
struct MemoryDiscovery {
    records: Mutex<Vec<StoredDiscoveryRecord>>,
    append: bool,
}

impl MemoryDiscovery {
    fn appending() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            append: true,
        }
    }

    fn records(&self, namespace: DiscoveryNamespace) -> Vec<StoredDiscoveryRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|record| record.namespace == namespace)
            .cloned()
            .collect()
    }

    fn inject(&self, namespace: DiscoveryNamespace, key: [u8; 32], value: Vec<u8>) {
        self.records.lock().unwrap().push(StoredDiscoveryRecord {
            namespace,
            key,
            value,
            expires_at: u64::MAX,
        });
    }
}

#[async_trait]
impl Discovery for MemoryDiscovery {
    async fn publish(
        &self,
        namespace: DiscoveryNamespace,
        key: [u8; 32],
        value: Vec<u8>,
        expires_at: u64,
    ) -> TransportResult<()> {
        let mut records = self.records.lock().unwrap();
        if !self.append {
            records.retain(|record| !(record.namespace == namespace && record.key == key));
        }
        records.push(StoredDiscoveryRecord {
            namespace,
            key,
            value,
            expires_at,
        });
        Ok(())
    }

    async fn lookup(
        &self,
        namespace: DiscoveryNamespace,
        key: [u8; 32],
    ) -> TransportResult<Vec<Vec<u8>>> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|record| record.namespace == namespace && record.key == key)
            .map(|record| record.value.clone())
            .collect())
    }
}

#[tokio::test]
async fn standard_records_are_fixed_sealed_and_mailbox_only() {
    let mut rng = StdRng::seed_from_u64(0x3100_0001);
    let dir = tempfile::tempdir().unwrap();
    let discovery = Arc::new(MemoryDiscovery::default());
    let mut node = Node::create(&dir.path().join("node.db"), b"pass", TEST_KDF, &mut rng).unwrap();
    node.add_discovery(Arc::clone(&discovery) as Arc<dyn Discovery>);
    let stable_address = node.address();
    let connect_text = node.connect_code().unwrap();
    let code = ConnectCode::parse(&connect_text).unwrap();
    let relay = DeliveryHint::Relay("/ip4/192.0.2.10/tcp/443/p2p/relay".to_owned());
    let direct =
        DeliveryHint::Multiaddr("/ip4/198.51.100.7/udp/4242/quic-v1/p2p/direct".to_owned());

    assert!(node
        .discovery_publication_needed(&[relay.clone(), direct.clone()])
        .unwrap());
    node.publish_bundle(&[relay.clone(), direct.clone()], NOW)
        .await
        .unwrap();
    assert!(!node
        .discovery_publication_needed(&[relay.clone(), direct.clone()])
        .unwrap());

    let records = discovery.records(DiscoveryNamespace::ConnectV2);
    assert_eq!(records.len(), 6);
    assert!(records
        .iter()
        .all(|record| record.value.len() == DISCOVERY_RECORD_SIZE));
    let current_epoch = discovery_epoch(NOW);
    let current = records
        .iter()
        .find(|record| {
            record.key == kult_crypto::discovery_locator(&code.capability(), current_epoch)
        })
        .unwrap();
    let opened = open_discovery_record(&code, current_epoch, &current.value, NOW).unwrap();
    assert_eq!(opened.routes.len(), 1);
    let decoded: DeliveryHint = postcard::from_bytes(&opened.routes[0].value).unwrap();
    assert_eq!(decoded, relay);
    assert!(opened
        .ingress
        .iter()
        .all(|ingress| ingress.prekey.opk.is_none()));
    assert!(!current
        .value
        .windows(node.peer_id().len())
        .any(|window| window == node.peer_id()));
    assert!(!current
        .value
        .windows(code.capability().len())
        .any(|window| window == code.capability()));
    assert_eq!(node.address(), stable_address);
    assert_eq!(
        discovery.records(DiscoveryNamespace::LegacyPrekeyV1).len(),
        0,
        "new profiles never publish beneath the stable identity key"
    );
    assert!(records.iter().all(|record| record.expires_at != 0));

    let local_device = node.device_id();
    node.rename_linked_device(&local_device, "Renamed device", &mut rng)
        .unwrap();
    assert!(
        node.discovery_publication_needed(std::slice::from_ref(&relay))
            .unwrap(),
        "an authority transition must invalidate the published material"
    );
    node.publish_bundle(std::slice::from_ref(&relay), NOW + 1)
        .await
        .unwrap();
    let replacement = DeliveryHint::Relay("/ip4/192.0.2.11/tcp/443/p2p/relay".to_owned());
    assert!(
        node.discovery_publication_needed(std::slice::from_ref(&replacement))
            .unwrap(),
        "a mailbox change must invalidate the published material"
    );
}

#[tokio::test]
async fn direct_publication_requires_both_sovereign_mode_and_warning_acknowledgement() {
    let mut rng = StdRng::seed_from_u64(0x3100_0002);
    let dir = tempfile::tempdir().unwrap();
    let discovery = Arc::new(MemoryDiscovery::default());
    let mut node = Node::create(&dir.path().join("node.db"), b"pass", TEST_KDF, &mut rng).unwrap();
    node.add_discovery(Arc::clone(&discovery) as Arc<dyn Discovery>);
    let direct = DeliveryHint::Multiaddr("/ip4/203.0.113.9/udp/4242/quic-v1/p2p/direct".to_owned());

    node.publish_bundle_with_policy(
        std::slice::from_ref(&direct),
        DiscoveryPublicationPolicy {
            mode: DiscoveryMode::Sovereign,
            publish_direct_routes: false,
        },
        NOW,
    )
    .await
    .unwrap();
    let code = ConnectCode::parse(&node.connect_code().unwrap()).unwrap();
    let epoch = discovery_epoch(NOW);
    let record = discovery
        .records(DiscoveryNamespace::ConnectV2)
        .into_iter()
        .find(|record| record.key == kult_crypto::discovery_locator(&code.capability(), epoch))
        .unwrap();
    assert!(open_discovery_record(&code, epoch, &record.value, NOW)
        .unwrap()
        .routes
        .is_empty());

    node.publish_bundle_with_policy(
        std::slice::from_ref(&direct),
        DiscoveryPublicationPolicy {
            mode: DiscoveryMode::Sovereign,
            publish_direct_routes: true,
        },
        NOW + 1,
    )
    .await
    .unwrap();
    let record = discovery
        .records(DiscoveryNamespace::ConnectV2)
        .into_iter()
        .find(|record| record.key == kult_crypto::discovery_locator(&code.capability(), epoch))
        .unwrap();
    let opened = open_discovery_record(&code, epoch, &record.value, NOW + 1).unwrap();
    assert_eq!(opened.routes.len(), 1);
    assert_eq!(
        postcard::from_bytes::<DeliveryHint>(&opened.routes[0].value).unwrap(),
        direct
    );
}

#[tokio::test]
async fn seven_invalid_candidates_still_leave_the_eighth_bounded_slot_verifiable() {
    let mut rng = StdRng::seed_from_u64(0x3100_0003);
    let dir = tempfile::tempdir().unwrap();
    let good = Arc::new(MemoryDiscovery::appending());
    let bad = Arc::new(MemoryDiscovery::appending());
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    bob.add_discovery(Arc::clone(&good) as Arc<dyn Discovery>);
    let relay = DeliveryHint::Relay("/ip4/192.0.2.20/tcp/443/p2p/relay".to_owned());
    bob.publish_bundle(std::slice::from_ref(&relay), NOW)
        .await
        .unwrap();
    let connect = bob.connect_code().unwrap();
    let code = ConnectCode::parse(&connect).unwrap();
    for epoch in discovery_epoch(NOW).saturating_sub(1)..=discovery_epoch(NOW) + 1 {
        let key = kult_crypto::discovery_locator(&code.capability(), epoch);
        for marker in 0u8..7 {
            let mut invalid = vec![marker; DISCOVERY_RECORD_SIZE];
            invalid[0] ^= 0x80;
            bad.inject(DiscoveryNamespace::ConnectV2, key, invalid);
        }
    }

    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    alice.add_discovery(bad as Arc<dyn Discovery>);
    alice.add_discovery(good as Arc<dyn Discovery>);
    let peer = alice
        .add_contact_by_address("bob", &connect, NOW, &mut rng)
        .await
        .unwrap();
    assert_eq!(peer, bob.peer_id());

    let ghost = Node::create(&dir.path().join("ghost.db"), b"ghost", TEST_KDF, &mut rng).unwrap();
    assert!(matches!(
        alice
            .add_contact_by_address("ghost", &ghost.connect_code().unwrap(), NOW, &mut rng,)
            .await,
        Err(NodeError::BundleNotFound)
    ));
}

#[tokio::test]
async fn eight_lower_invalid_candidates_crowd_out_valid_without_state_mutation() {
    let mut rng = StdRng::seed_from_u64(0x3100_0006);
    let dir = tempfile::tempdir().unwrap();
    let good = Arc::new(MemoryDiscovery::appending());
    let bad = Arc::new(MemoryDiscovery::appending());
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    bob.add_discovery(Arc::clone(&good) as Arc<dyn Discovery>);
    bob.publish_bundle(
        &[DeliveryHint::Relay(
            "/ip4/192.0.2.21/tcp/443/p2p/relay".to_owned(),
        )],
        NOW,
    )
    .await
    .unwrap();
    let connect = bob.connect_code().unwrap();
    let code = ConnectCode::parse(&connect).unwrap();
    for epoch in discovery_epoch(NOW).saturating_sub(1)..=discovery_epoch(NOW) + 1 {
        let key = kult_crypto::discovery_locator(&code.capability(), epoch);
        let valid = good
            .records(DiscoveryNamespace::ConnectV2)
            .into_iter()
            .find(|record| record.key == key)
            .unwrap()
            .value;
        let valid_digest = <[u8; 32]>::from(Sha256::digest(&valid));
        let mut inserted = 0u8;
        let mut counter = 0u64;
        while inserted < 8 {
            let mut invalid = valid.clone();
            invalid[0] ^= 0x80;
            let offset = invalid.len() - 8;
            invalid[offset..].copy_from_slice(&counter.to_be_bytes());
            if <[u8; 32]>::from(Sha256::digest(&invalid)) < valid_digest {
                bad.inject(DiscoveryNamespace::ConnectV2, key, invalid);
                inserted += 1;
            }
            counter += 1;
        }
    }

    let mut alice = Node::create(
        &dir.path().join("alice-crowded.db"),
        b"alice",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    alice.add_discovery(bad as Arc<dyn Discovery>);
    alice.add_discovery(good as Arc<dyn Discovery>);
    let contacts_before = alice.contacts().unwrap();
    assert!(matches!(
        alice
            .add_contact_by_address("bob", &connect, NOW, &mut rng)
            .await,
        Err(NodeError::BundleNotFound)
    ));
    assert_eq!(alice.contacts().unwrap(), contacts_before);
}

#[tokio::test]
async fn rotation_preserves_identity_and_new_code_resolves_after_republish() {
    let mut rng = StdRng::seed_from_u64(0x3100_0004);
    let dir = tempfile::tempdir().unwrap();
    let discovery = Arc::new(MemoryDiscovery::default());
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    bob.add_discovery(Arc::clone(&discovery) as Arc<dyn Discovery>);
    let stable = bob.address();
    let old_code = bob.connect_code().unwrap();
    let relay = DeliveryHint::Relay("/ip4/192.0.2.30/tcp/443/p2p/relay".to_owned());
    bob.publish_bundle(std::slice::from_ref(&relay), NOW)
        .await
        .unwrap();

    let new_code = bob.rotate_connect_code(&mut rng).unwrap();
    assert_ne!(old_code, new_code);
    assert_eq!(bob.address(), stable);
    assert!(!bob.legacy_discovery_enabled());
    assert!(bob
        .discovery_publication_needed(std::slice::from_ref(&relay))
        .unwrap());
    bob.publish_bundle(std::slice::from_ref(&relay), NOW + 1)
        .await
        .unwrap();
    assert!(!bob
        .discovery_publication_needed(std::slice::from_ref(&relay))
        .unwrap());

    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    alice.add_discovery(discovery as Arc<dyn Discovery>);
    assert_eq!(
        alice
            .add_contact_by_address("bob", &new_code, NOW + 1, &mut rng)
            .await
            .unwrap(),
        bob.peer_id()
    );
    assert!(matches!(
        alice
            .add_contact_by_address("wrong", "kc2not-a-code", NOW + 1, &mut rng)
            .await,
        Err(NodeError::Crypto(_))
    ));
}

#[tokio::test]
async fn authenticated_control_replaces_a_stale_relationship_route() {
    let mut rng = StdRng::seed_from_u64(0x3100_0005);
    let dir = tempfile::tempdir().unwrap();
    let alice_old = dir.path().join("alice-old");
    let alice_new = dir.path().join("alice-new");
    let bob_inbox = dir.path().join("bob-inbox");
    let mut alice =
        Node::create(&dir.path().join("alice.db"), b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"bob", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(SneakernetTransport::new(&alice_old).unwrap()));
    alice.add_transport(Arc::new(SneakernetTransport::new(&alice_new).unwrap()));
    bob.add_transport(Arc::new(SneakernetTransport::new(&bob_inbox).unwrap()));

    let alice_bundle = alice
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(alice_old.clone())], NOW, &mut rng)
        .unwrap();
    let bob_bundle = bob
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(bob_inbox.clone())], NOW, &mut rng)
        .unwrap();
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
            &[DeliveryHint::Spool(alice_old.clone())],
            NOW,
            &mut rng,
        )
        .unwrap();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bob.tick(NOW + 2, &mut rng).await.unwrap();
    bob.tick(NOW + 3, &mut rng).await.unwrap();
    alice.tick(NOW + 4, &mut rng).await.unwrap();

    alice.rotate_connect_code(&mut rng).unwrap();
    alice
        .handshake_bundle_with_hints(&[DeliveryHint::Spool(alice_new.clone())], NOW + 5, &mut rng)
        .unwrap();
    alice.tick(NOW + 6, &mut rng).await.unwrap();
    bob.tick(NOW + 7, &mut rng).await.unwrap();

    bob.send_message(&alice_id, b"new authenticated route", NOW + 8, &mut rng)
        .unwrap();
    bob.tick(NOW + 9, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 10, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        kult_node::Event::MessageReceived { body, .. }
            if body == b"new authenticated route"
    )));
}
