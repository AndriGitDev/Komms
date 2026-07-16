//! ADR-0021 end-to-end expiry, ordering, restart, and first-open behavior.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{AttachmentMetadata, ContentStatus, Event, Node, NodeError};
use kult_protocol::Envelope;
use kult_store::MediaTransferState;
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

struct Link {
    net: Net,
    me: u32,
}

#[async_trait]
impl Transport for Link {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }

    async fn reachable(&self, hint: &DeliveryHint) -> Reachability {
        if matches!(hint, DeliveryHint::MeshNode(_)) {
            Reachability::Now
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        hint: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::MeshNode(destination) = hint else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(*destination)
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

async fn settle(alice: &mut Node, bob: &mut Node, rng: &mut StdRng, start: u64, rounds: u64) {
    for round in 0..rounds {
        alice.tick(start + round * 2, rng).await.unwrap();
        bob.tick(start + round * 2 + 1, rng).await.unwrap();
    }
}

fn setup() -> (
    tempfile::TempDir,
    Net,
    Node,
    Node,
    [u8; 32],
    [u8; 32],
    StdRng,
) {
    let mut rng = StdRng::seed_from_u64(0xc4_0021);
    let dir = tempfile::tempdir().unwrap();
    let net = Arc::new(Mutex::new(HashMap::new()));
    let mut alice = Node::create(&dir.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(Link {
        net: net.clone(),
        me: 1,
    }));
    bob.add_transport(Arc::new(Link {
        net: net.clone(),
        me: 2,
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
    (dir, net, alice, bob, alice_id, bob_id, rng)
}

#[tokio::test]
async fn exact_expiry_restart_and_expiry_before_original_never_revive_plaintext() {
    let (dir, net, mut alice, mut bob, alice_id, bob_id, mut rng) = setup();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1, 6).await;

    let id = alice
        .send_disappearing_message(&bob_id, "brief", 60, NOW + 20, &mut rng)
        .unwrap();
    alice.tick(NOW + 21, &mut rng).await.unwrap();
    let received = bob.tick(NOW + 22, &mut rng).await.unwrap();
    assert!(received.iter().any(|event| matches!(
        event,
        Event::MessageReceived {
            id: event_id,
            body,
            content: ContentStatus::DisappearingText { expires_at, .. },
            ..
        } if *event_id == id && body == b"brief" && *expires_at == NOW + 80
    )));
    assert!(bob
        .messages_with(&alice_id)
        .unwrap()
        .iter()
        .any(|row| row.id == id));

    let removed = bob.tick(NOW + 80, &mut rng).await.unwrap();
    assert!(removed.iter().any(|event| matches!(
        event,
        Event::EphemeralRemoved { content_id, .. } if *content_id == id
    )));
    assert!(!bob
        .messages_with(&alice_id)
        .unwrap()
        .iter()
        .any(|row| row.id == id));

    drop(bob);
    let mut bob = Node::open(&dir.path().join("bob.db"), b"b").unwrap();
    bob.add_transport(Arc::new(Link {
        net: net.clone(),
        me: 2,
    }));
    bob.tick(NOW + 81, &mut rng).await.unwrap();
    assert!(!bob
        .messages_with(&alice_id)
        .unwrap()
        .iter()
        .any(|row| row.id == id));

    let delayed = alice
        .send_disappearing_message(&bob_id, "arrived late", 60, NOW + 100, &mut rng)
        .unwrap();
    alice.tick(NOW + 101, &mut rng).await.unwrap();
    let held = net.lock().unwrap().remove(&2).unwrap();
    net.lock().unwrap().insert(2, held);
    let late_events = bob.tick(NOW + 161, &mut rng).await.unwrap();
    assert!(late_events.iter().any(|event| matches!(
        event,
        Event::EphemeralRemoved { content_id, .. } if *content_id == delayed
    )));
    assert!(!bob
        .messages_with(&alice_id)
        .unwrap()
        .iter()
        .any(|row| row.id == delayed));
}

#[tokio::test]
async fn view_once_requires_explicit_consume_and_deletes_source_before_second_open() {
    let (_dir, _net, mut alice, mut bob, _alice_id, bob_id, mut rng) = setup();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1, 6).await;

    let bytes = b"one protected rendering only".to_vec();
    let content_id = alice
        .send_view_once_attachment(
            &bob_id,
            &AttachmentMetadata {
                media_type: "image/jpeg".to_owned(),
                filename: Some("once.jpg".to_owned()),
            },
            &mut Cursor::new(&bytes),
            3_600,
            NOW + 20,
            &mut rng,
        )
        .unwrap();
    alice.tick(NOW + 21, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 22, &mut rng).await.unwrap();
    let transfer = events
        .iter()
        .find_map(|event| match event {
            Event::MessageReceived {
                content: ContentStatus::ViewOnceAttachment { id, transfer, .. },
                ..
            } if *id == content_id => Some(*transfer),
            _ => None,
        })
        .expect("view-once offer");
    let info = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == transfer)
        .unwrap();
    assert!(info.view_once);
    assert_eq!(info.state, MediaTransferState::AwaitingConsent);
    assert!(matches!(
        bob.export_attachment(&transfer, &mut Vec::new()),
        Err(NodeError::ViewOnceExportForbidden)
    ));

    bob.accept_attachment(&transfer, NOW + 23, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 24, 4).await;
    assert_eq!(
        bob.attachments()
            .unwrap()
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer)
            .unwrap()
            .state,
        MediaTransferState::Complete
    );
    let mut opened = Vec::new();
    bob.consume_view_once_attachment(&transfer, &mut opened, NOW + 40, &mut rng)
        .unwrap();
    assert_eq!(opened, bytes);
    assert!(!bob
        .attachments()
        .unwrap()
        .iter()
        .any(|attachment| attachment.transfer_id == transfer));
    assert!(matches!(
        bob.consume_view_once_attachment(&transfer, &mut Vec::new(), NOW + 41, &mut rng),
        Err(NodeError::InvalidEphemeral)
    ));
}

#[tokio::test]
async fn group_ephemeral_fanout_uses_the_same_exact_tombstone_semantics() {
    let (_dir, _net, mut alice, mut bob, alice_id, bob_id, mut rng) = setup();
    alice
        .send_message(&bob_id, b"establish", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1, 6).await;
    let group = alice.create_group("briefing", &[bob_id], &mut rng).unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 20, 5).await;
    assert!(bob.groups().unwrap().iter().any(|value| value.id == group));

    let id = alice
        .group_send_disappearing_message(&group, "vanishes", 60, NOW + 40, &mut rng)
        .unwrap();
    alice.tick(NOW + 41, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 42, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived {
            group: event_group,
            sender,
            id: event_id,
            content: ContentStatus::DisappearingText { .. },
            body,
            ..
        } if *event_group == group && *sender == alice_id && *event_id == id && body == b"vanishes"
    )));
    assert!(bob
        .group_messages(&group)
        .unwrap()
        .iter()
        .any(|row| row.id == id));
    bob.tick(NOW + 100, &mut rng).await.unwrap();
    assert!(!bob
        .group_messages(&group)
        .unwrap()
        .iter()
        .any(|row| row.id == id));
}
