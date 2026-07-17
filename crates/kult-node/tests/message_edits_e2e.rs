//! ADR-0020 end-to-end message edits over the ordinary encrypted pairwise
//! and sender-key group lanes, including restart and encrypted backup views.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{Event, Node, NodeError};
use kult_protocol::{decode_content, encode_edit, DecodedContent, Edit, Envelope};
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

async fn settle(alice: &mut Node, bob: &mut Node, rng: &mut StdRng, start: u64) {
    for round in 0..8 {
        alice.tick(start + round * 2, rng).await.unwrap();
        bob.tick(start + round * 2 + 1, rng).await.unwrap();
    }
}

#[tokio::test]
async fn pairwise_group_and_backup_views_resolve_immutable_edits() {
    let mut rng = StdRng::seed_from_u64(0x00c3_0020);
    let dir = tempfile::tempdir().unwrap();
    let alice_db = dir.path().join("alice.db");
    let bob_db = dir.path().join("bob.db");
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut alice = Node::create(&alice_db, b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&bob_db, b"bob", TEST_KDF, &mut rng).unwrap();
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
    let alice_id = bob
        .add_contact(
            "alice",
            &alice_bundle,
            &[DeliveryHint::MeshNode(1)],
            NOW,
            &mut rng,
        )
        .unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(2)],
            NOW,
            &mut rng,
        )
        .unwrap();

    let legacy_id = alice
        .send_message(&bob_id, b"establish and advertise", NOW, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 1).await;

    let original = alice
        .send_message(&bob_id, b"pairwise original", NOW + 30, &mut rng)
        .unwrap();
    assert!(matches!(
        decode_content(&alice.messages_with(&bob_id).unwrap().last().unwrap().body),
        DecodedContent::Text { id, text: "pairwise original" } if id == original
    ));
    settle(&mut alice, &mut bob, &mut rng, NOW + 31).await;

    assert!(matches!(
        alice.edit_message(
            &bob_id,
            bob_id,
            original,
            "forged author",
            NOW + 50,
            &mut rng,
        ),
        Err(NodeError::InvalidEdit)
    ));
    assert!(matches!(
        alice.edit_message(
            &bob_id,
            alice_id,
            legacy_id,
            "legacy target",
            NOW + 50,
            &mut rng,
        ),
        Err(NodeError::InvalidEdit)
    ));

    let edit_id = alice
        .edit_message(
            &bob_id,
            alice_id,
            original,
            "pairwise revised",
            NOW + 51,
            &mut rng,
        )
        .unwrap();
    let raw = alice.messages_with(&bob_id).unwrap();
    assert_eq!(raw.len(), 3, "the immutable edit is a separate sealed row");
    assert!(matches!(
        decode_content(&raw.last().unwrap().body),
        DecodedContent::Edit { id, edit }
            if id == edit_id && edit.target_content_id == original && edit.revision == 1
    ));
    let local = alice.resolved_messages_with(&bob_id).unwrap();
    assert_eq!(
        local.len(),
        2,
        "edit events are hidden from ordinary history"
    );
    let local_original = local
        .iter()
        .find(|message| message.record.id == original)
        .unwrap();
    assert!(local_original.edited);
    assert_eq!(local_original.winning_revision, 1);
    assert_eq!(local_original.versions.len(), 2);
    assert!(matches!(
        decode_content(&local_original.record.body),
        DecodedContent::Text {
            text: "pairwise revised",
            ..
        }
    ));

    alice.tick(NOW + 52, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 53, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageEdited { peer, target_content_id }
            if *peer == alice_id && *target_content_id == original
    )));
    assert!(!events
        .iter()
        .any(|event| matches!(event, Event::MessageReceived { id, .. } if *id == edit_id)));
    let remote = bob.resolved_messages_with(&alice_id).unwrap();
    let remote_original = remote
        .iter()
        .find(|message| message.record.id == original)
        .unwrap();
    assert_eq!(
        remote_original
            .versions
            .iter()
            .map(|version| (version.id, version.revision, version.body.as_str()))
            .collect::<Vec<_>>(),
        local_original
            .versions
            .iter()
            .map(|version| (version.id, version.revision, version.body.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(remote_original.record.body, local_original.record.body);

    let encoded_bypass = encode_edit(
        [0xa5; 16],
        &Edit {
            target_author: alice_id,
            target_content_id: original,
            revision: 2,
            text: "bypass",
        },
    )
    .unwrap();
    assert!(matches!(
        alice.send_message(&bob_id, &encoded_bypass, NOW + 54, &mut rng),
        Err(NodeError::InvalidEdit)
    ));

    let group = alice
        .create_group("edited group", &[bob_id], &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 60).await;
    let group_original = alice
        .group_send(&group, b"group original", NOW + 80, &mut rng)
        .unwrap();
    assert!(matches!(
        decode_content(&alice.group_messages(&group).unwrap().last().unwrap().body),
        DecodedContent::Text { id, text: "group original" } if id == group_original
    ));
    settle(&mut alice, &mut bob, &mut rng, NOW + 81).await;
    let group_edit = alice
        .group_edit_message(
            &group,
            alice_id,
            group_original,
            "group revised",
            NOW + 100,
            &mut rng,
        )
        .unwrap();
    assert!(matches!(
        alice.group_send(&group, &encoded_bypass, NOW + 100, &mut rng),
        Err(NodeError::InvalidEdit)
    ));
    alice.tick(NOW + 101, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 102, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::GroupMessageEdited { group: event_group, sender, target_content_id }
            if *event_group == group && *sender == alice_id && *target_content_id == group_original
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived { id, .. } if *id == group_edit
    )));
    let group_remote = bob.resolved_group_messages(&group).unwrap();
    assert_eq!(group_remote.len(), 1);
    assert!(group_remote[0].edited);
    assert_eq!(group_remote[0].winning_revision, 1);
    assert_eq!(group_remote[0].versions.len(), 2);
    assert!(matches!(
        decode_content(&group_remote[0].record.body),
        DecodedContent::Text {
            text: "group revised",
            ..
        }
    ));

    alice
        .group_remove(&group, &bob_id, NOW + 103, &mut rng)
        .unwrap();
    settle(&mut alice, &mut bob, &mut rng, NOW + 103).await;
    assert!(matches!(
        bob.group_edit_message(
            &group,
            bob_id,
            group_original,
            "removed member cannot edit",
            NOW + 120,
            &mut rng,
        ),
        Err(NodeError::UnknownGroup)
    ));

    drop(bob);
    let bob = Node::open(&bob_db, b"bob").unwrap();
    assert!(
        bob.resolved_messages_with(&alice_id)
            .unwrap()
            .iter()
            .find(|message| message.record.id == original)
            .unwrap()
            .edited
    );
    assert!(bob.resolved_group_messages(&group).unwrap()[0].edited);

    let (backup, mnemonic) = alice.export_backup(NOW + 110, &mut rng).unwrap();
    let restored = Node::restore(
        &dir.path().join("alice-restored.db"),
        &backup,
        &mnemonic,
        b"restored",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    let restored_pair = restored.resolved_messages_with(&bob_id).unwrap();
    assert_eq!(
        restored_pair
            .iter()
            .find(|message| message.record.id == original)
            .unwrap()
            .record
            .body,
        local_original.record.body
    );
    assert_eq!(
        restored.resolved_group_messages(&group).unwrap()[0]
            .record
            .body,
        group_remote[0].record.body
    );
}
