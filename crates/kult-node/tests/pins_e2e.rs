//! B11 node acceptance: private conversation pins compose after folders and
//! labels, preserve exact typed identity/order, and create zero transport work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, FolderSelection, LabelConversationId, LabelMatchMode, Node, NodeError};
use kult_protocol::Envelope;
use kult_store::StoreError;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Default)]
struct SpyTransport {
    sends: AtomicUsize,
    reachability: AtomicUsize,
}

#[async_trait]
impl Transport for SpyTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Free,
            broadcast: false,
        }
    }

    async fn reachable(&self, _peer: &DeliveryHint) -> Reachability {
        self.reachability.fetch_add(1, Ordering::SeqCst);
        Reachability::Now
    }

    async fn send(
        &self,
        _peer: &DeliveryHint,
        _envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }
}

fn node_with_contact_and_group(
    directory: &std::path::Path,
    rng: &mut StdRng,
) -> (Node, [u8; 32], [u8; 32]) {
    let mut node = Node::create(&directory.join("node.db"), b"pass", TEST_KDF, rng).unwrap();
    let mut peer = Node::create(&directory.join("peer.db"), b"peer", TEST_KDF, rng).unwrap();
    let bundle = peer.handshake_bundle(NOW, rng).unwrap();
    let peer_id = node
        .add_contact("Duplicate name", &bundle, &[], NOW, rng)
        .unwrap();
    let group = node
        .create_group("Duplicate name", &[peer_id], rng)
        .unwrap();
    node.drain_events();
    (node, peer_id, group)
}

#[test]
fn typed_pin_order_folder_label_composition_restart_and_zero_network_work() {
    let mut rng = StdRng::seed_from_u64(0xb11);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let (mut node, peer, group) = node_with_contact_and_group(directory.path(), &mut rng);

    node.group_send(&group, b"group", NOW + 10, &mut rng)
        .unwrap();
    node.send_message(&peer, b"peer", NOW + 20, &mut rng)
        .unwrap();
    node.note_to_self_send("note", NOW + 30, &mut rng).unwrap();
    node.drain_events();
    let queued_before = node.queued().unwrap();
    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());

    let peer_target = LabelConversationId::Peer(peer);
    let group_target = LabelConversationId::Group(group);
    let note_target = LabelConversationId::NoteToSelf;
    assert!(node.pin_conversation(&peer_target, &mut rng).unwrap());
    assert!(!node.pin_conversation(&peer_target, &mut rng).unwrap());
    assert!(node.pin_conversation(&group_target, &mut rng).unwrap());
    assert_eq!(
        node.pins()
            .unwrap()
            .into_iter()
            .map(|pin| (pin.conversation, pin.order, pin.active))
            .collect::<Vec<_>>(),
        vec![
            (peer_target.clone(), 0, true),
            (group_target.clone(), 1, true)
        ]
    );

    node.reorder_pins(&[group_target.clone(), peer_target.clone()], &mut rng)
        .unwrap();
    let all = node
        .pin_conversations(FolderSelection::All, &[], LabelMatchMode::Any)
        .unwrap();
    assert_eq!(
        all.conversations
            .iter()
            .map(|row| (row.conversation.clone(), row.pinned, row.recent_activity))
            .collect::<Vec<_>>(),
        vec![
            (group_target.clone(), true, NOW + 10),
            (peer_target.clone(), true, NOW + 20),
            (note_target.clone(), false, NOW + 30),
        ]
    );

    let folder = node.create_folder("One", &mut rng).unwrap();
    node.move_conversation_to_folder(&peer_target, &folder.id, &mut rng)
        .unwrap();
    node.move_conversation_to_folder(&group_target, &folder.id, &mut rng)
        .unwrap();
    let label = node.create_label("Only group", "blue", &mut rng).unwrap();
    node.assign_label(&label.id, &group_target, &mut rng)
        .unwrap();
    let composed = node
        .pin_conversations(
            FolderSelection::Folder(folder.id),
            &[label.id],
            LabelMatchMode::All,
        )
        .unwrap();
    assert_eq!(composed.conversations.len(), 1);
    assert_eq!(composed.conversations[0].conversation, group_target);
    assert!(composed.conversations[0].pinned);

    assert_eq!(node.queued().unwrap(), queued_before);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability.load(Ordering::SeqCst), 0);
    assert!(node.drain_events().iter().all(|event| matches!(
        event,
        Event::PinsChanged | Event::FoldersChanged | Event::LabelsChanged
    )));

    drop(node);
    let reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(
        reopened
            .pins()
            .unwrap()
            .into_iter()
            .map(|pin| (pin.conversation, pin.order))
            .collect::<Vec<_>>(),
        vec![
            (LabelConversationId::Group(group), 0),
            (LabelConversationId::Peer(peer), 1)
        ]
    );
}

#[test]
fn stale_pin_reactivation_cleanup_errors_and_kkr5_round_trip_are_honest() {
    let mut rng = StdRng::seed_from_u64(0xb1102);
    let directory = tempfile::tempdir().unwrap();
    let (mut node, _peer, group) = node_with_contact_and_group(directory.path(), &mut rng);
    let group_target = LabelConversationId::Group(group);
    let note_target = LabelConversationId::NoteToSelf;
    node.pin_conversation(&group_target, &mut rng).unwrap();
    node.pin_conversation(&note_target, &mut rng).unwrap();
    node.group_leave(&group, NOW + 1, &mut rng).unwrap();
    node.drain_events();

    let stale = node.stale_pins().unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].conversation, group_target);
    assert!(!stale[0].active);
    assert!(matches!(
        node.cleanup_stale_pin(&note_target),
        Err(NodeError::Store(StoreError::PinActive))
    ));

    let (backup, mnemonic) = node.export_backup(NOW + 2, &mut rng).unwrap();
    assert_eq!(&backup[..4], b"KKR5");
    let mut restored = Node::restore(
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
            .pins()
            .unwrap()
            .into_iter()
            .map(|pin| (pin.conversation, pin.order, pin.active))
            .collect::<Vec<_>>(),
        vec![(group_target.clone(), 0, false), (note_target, 1, true)]
    );
    assert!(restored.cleanup_stale_pin(&group_target).unwrap());
    assert!(!restored.unpin_conversation(&group_target).unwrap());
}
