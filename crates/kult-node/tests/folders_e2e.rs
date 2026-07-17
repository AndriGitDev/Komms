//! B10 node acceptance: private folders span pairwise, group, and note-to-self
//! conversations, compose with labels, and create zero transport work.

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
        .add_contact("\u{2067}Bob\u{2069}", &bundle, &[], NOW, rng)
        .unwrap();
    let group = node.create_group("e\u{301} Team", &[peer_id], rng).unwrap();
    node.drain_events();
    (node, peer_id, group)
}

#[test]
fn typed_navigation_reorder_label_composition_restart_and_zero_network_work() {
    let mut rng = StdRng::seed_from_u64(0xb10);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let (mut node, peer, group) = node_with_contact_and_group(directory.path(), &mut rng);
    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());
    let queued_before = node.queued().unwrap();

    let first = node.create_folder("Trip 🧭", &mut rng).unwrap();
    let second = node.create_folder("Trip 🧭", &mut rng).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!((first.order, second.order), (0, 1));
    let reordered = node
        .reorder_folders(&[second.id, first.id], &mut rng)
        .unwrap();
    assert_eq!(reordered[0].id, second.id);
    assert_eq!(reordered[0].order, 0);

    let peer_target = LabelConversationId::Peer(peer);
    let group_target = LabelConversationId::Group(group);
    let note_target = LabelConversationId::NoteToSelf;
    assert!(node
        .move_conversation_to_folder(&peer_target, &first.id, &mut rng)
        .unwrap());
    assert!(node
        .move_conversation_to_folder(&group_target, &first.id, &mut rng)
        .unwrap());
    assert!(node
        .move_conversation_to_folder(&note_target, &second.id, &mut rng)
        .unwrap());
    assert!(!node
        .move_conversation_to_folder(&note_target, &second.id, &mut rng)
        .unwrap());

    let label = node.create_label("Important", "teal", &mut rng).unwrap();
    node.assign_label(&label.id, &group_target, &mut rng)
        .unwrap();
    node.assign_label(&label.id, &note_target, &mut rng)
        .unwrap();
    let folder_then_label = node
        .folder_conversations(
            FolderSelection::Folder(first.id),
            &[label.id],
            LabelMatchMode::Any,
        )
        .unwrap();
    assert_eq!(folder_then_label.selected_labels, vec![label.id]);
    assert_eq!(
        folder_then_label
            .conversations
            .iter()
            .map(|item| item.conversation.clone())
            .collect::<Vec<_>>(),
        vec![group_target.clone()]
    );
    let all_unfiltered = node
        .folder_conversations(FolderSelection::All, &[], LabelMatchMode::Any)
        .unwrap();
    assert_eq!(all_unfiltered.conversations.len(), 3);
    assert!(node.unfile_conversation(&peer_target).unwrap());
    assert!(!node.unfile_conversation(&peer_target).unwrap());
    assert_eq!(
        node.folder_conversations(FolderSelection::Unfiled, &[], LabelMatchMode::Any)
            .unwrap()
            .conversations[0]
            .conversation,
        peer_target
    );

    assert_eq!(node.queued().unwrap(), queued_before);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability.load(Ordering::SeqCst), 0);
    assert!(node
        .drain_events()
        .iter()
        .all(|event| { matches!(event, Event::FoldersChanged | Event::LabelsChanged) }));

    drop(node);
    let reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(reopened.folders().unwrap(), reordered);
    assert_eq!(
        reopened
            .folder_for_conversation(&note_target)
            .unwrap()
            .unwrap()
            .id,
        second.id
    );
    assert_eq!(reopened.queued().unwrap(), queued_before);
}

#[test]
fn delete_cascade_exact_errors_and_recreate_isolation_are_honest() {
    let mut rng = StdRng::seed_from_u64(0xb1002);
    let directory = tempfile::tempdir().unwrap();
    let (mut node, peer, _group) = node_with_contact_and_group(directory.path(), &mut rng);
    let target = LabelConversationId::Peer(peer);
    let first = node.create_folder("Same", &mut rng).unwrap();
    node.move_conversation_to_folder(&target, &first.id, &mut rng)
        .unwrap();
    assert_eq!(node.folder_delete_assignment_count(&first.id).unwrap(), 1);
    assert!(matches!(
        node.move_conversation_to_folder(&target, &[0xee; 16], &mut rng),
        Err(NodeError::Store(StoreError::UnknownFolder))
    ));
    assert!(matches!(
        node.move_conversation_to_folder(
            &LabelConversationId::Group([0xdd; 32]),
            &first.id,
            &mut rng,
        ),
        Err(NodeError::Store(StoreError::UnavailableConversation))
    ));
    assert_eq!(node.delete_folder(&first.id).unwrap(), 1);
    assert!(node.folder_for_conversation(&target).unwrap().is_none());
    let replacement = node.create_folder("Same", &mut rng).unwrap();
    assert_ne!(replacement.id, first.id);
    assert!(node.folder_members(&replacement.id).unwrap().is_empty());
}

#[test]
fn kkr5_restores_exact_ids_names_order_membership_and_stale_behavior() {
    let mut rng = StdRng::seed_from_u64(0xb1003);
    let directory = tempfile::tempdir().unwrap();
    let (mut node, peer, group) = node_with_contact_and_group(directory.path(), &mut rng);
    let first = node
        .create_folder("e\u{301}\u{2067}עברית\u{2069}", &mut rng)
        .unwrap();
    let second = node
        .create_folder("e\u{301}\u{2067}עברית\u{2069}", &mut rng)
        .unwrap();
    node.reorder_folders(&[second.id, first.id], &mut rng)
        .unwrap();
    node.move_conversation_to_folder(&LabelConversationId::Peer(peer), &first.id, &mut rng)
        .unwrap();
    node.move_conversation_to_folder(&LabelConversationId::Group(group), &second.id, &mut rng)
        .unwrap();
    node.move_conversation_to_folder(&LabelConversationId::NoteToSelf, &second.id, &mut rng)
        .unwrap();
    let before = node.folders().unwrap();
    let (backup, mnemonic) = node.export_backup(NOW + 1, &mut rng).unwrap();
    assert_eq!(&backup[..4], b"KKR7");
    let restored = Node::restore(
        &directory.path().join("restored.db"),
        &backup,
        &mnemonic,
        b"restored",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(restored.folders().unwrap(), before);
    assert_eq!(
        restored
            .folder_members(&second.id)
            .unwrap()
            .iter()
            .map(|member| member.conversation.clone())
            .collect::<Vec<_>>(),
        vec![
            LabelConversationId::NoteToSelf,
            LabelConversationId::Group(group)
        ]
    );
    assert!(restored.stale_folder_assignments().unwrap().is_empty());
}
