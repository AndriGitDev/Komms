//! B18 node acceptance: exact typed private labels span pairwise, group, and
//! note-to-self conversations while creating no delivery or transport work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, LabelConversationId, LabelMatchMode, Node, NodeError};
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
fn peer_group_note_filters_membership_restart_and_zero_network_work() {
    let mut rng = StdRng::seed_from_u64(0xb18);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let (mut node, peer, group) = node_with_contact_and_group(directory.path(), &mut rng);
    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());

    let queued_before = node.queued().unwrap();
    let red = node.create_label("Travel 🧭", "red", &mut rng).unwrap();
    let blue = node.create_label("Travel 🧭", "blue", &mut rng).unwrap();
    assert_ne!(red.id, blue.id);
    assert_eq!(red.order, 0);
    assert_eq!(blue.order, 1);

    let peer_target = LabelConversationId::Peer(peer);
    let group_target = LabelConversationId::Group(group);
    let note_target = LabelConversationId::NoteToSelf;
    assert!(node.assign_label(&red.id, &peer_target, &mut rng).unwrap());
    assert!(node.assign_label(&red.id, &note_target, &mut rng).unwrap());
    assert!(node
        .assign_label(&blue.id, &group_target, &mut rng)
        .unwrap());
    assert!(node.assign_label(&blue.id, &note_target, &mut rng).unwrap());
    assert!(!node.assign_label(&blue.id, &note_target, &mut rng).unwrap());

    let red_members = node.label_members(&red.id).unwrap();
    assert_eq!(red_members.len(), 2);
    assert_eq!(red_members[0].conversation, peer_target);
    assert_eq!(
        red_members[0].display_name.as_deref(),
        Some("\u{2067}Bob\u{2069}")
    );
    assert_eq!(red_members[1].conversation, note_target);
    assert!(red_members[1].display_name.is_none());

    let any = node
        .filter_label_conversations(&[red.id, red.id], LabelMatchMode::Any)
        .unwrap();
    assert_eq!(any.selected, vec![red.id]);
    assert_eq!(
        any.conversations
            .iter()
            .map(|item| item.conversation.clone())
            .collect::<Vec<_>>(),
        vec![note_target.clone(), peer_target.clone()]
    );
    let all = node
        .filter_label_conversations(&[red.id, blue.id], LabelMatchMode::All)
        .unwrap();
    assert_eq!(
        all.conversations
            .iter()
            .map(|item| item.conversation.clone())
            .collect::<Vec<_>>(),
        vec![note_target.clone()]
    );
    let unavailable = node
        .filter_label_conversations(&[[0xff; 16]], LabelMatchMode::Any)
        .unwrap();
    assert!(unavailable.selected.is_empty());
    assert_eq!(unavailable.unavailable_selected, vec![[0xff; 16]]);

    assert_eq!(node.queued().unwrap(), queued_before);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability.load(Ordering::SeqCst), 0);
    assert!(node
        .drain_events()
        .iter()
        .all(|event| matches!(event, Event::LabelsChanged)));

    drop(node);
    let reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(reopened.labels().unwrap(), vec![red.clone(), blue.clone()]);
    assert_eq!(
        reopened.labels_for_conversation(&note_target).unwrap(),
        vec![red, blue]
    );
    assert_eq!(reopened.queued().unwrap(), queued_before);
}

#[test]
fn exact_ids_errors_atomic_delete_and_delete_recreate_are_honest() {
    let mut rng = StdRng::seed_from_u64(0xb1802);
    let directory = tempfile::tempdir().unwrap();
    let (mut node, peer, _group) = node_with_contact_and_group(directory.path(), &mut rng);
    let target = LabelConversationId::Peer(peer);
    let first = node.create_label("Same", "purple", &mut rng).unwrap();
    node.assign_label(&first.id, &target, &mut rng).unwrap();
    assert_eq!(node.label_delete_assignment_count(&first.id).unwrap(), 1);

    assert!(matches!(
        node.assign_label(&[0xee; 16], &target, &mut rng),
        Err(NodeError::Store(StoreError::UnknownLabel))
    ));
    assert!(matches!(
        node.assign_label(&first.id, &LabelConversationId::Group([0xdd; 32]), &mut rng,),
        Err(NodeError::Store(StoreError::UnavailableConversation))
    ));
    assert_eq!(node.delete_label(&first.id).unwrap(), 1);
    let replacement = node.create_label("Same", "purple", &mut rng).unwrap();
    assert_ne!(replacement.id, first.id);
    assert!(node.label_members(&replacement.id).unwrap().is_empty());
    assert!(matches!(
        node.label(&first.id),
        Err(NodeError::Store(StoreError::UnknownLabel))
    ));
}

#[test]
fn kkr5_backup_restores_exact_ids_order_names_colors_and_memberships() {
    let mut rng = StdRng::seed_from_u64(0xb1803);
    let directory = tempfile::tempdir().unwrap();
    let (mut node, peer, group) = node_with_contact_and_group(directory.path(), &mut rng);
    let first = node
        .create_label("e\u{301}\u{2067}עברית\u{2069}", "teal", &mut rng)
        .unwrap();
    let second = node
        .create_label("e\u{301}\u{2067}עברית\u{2069}", "pink", &mut rng)
        .unwrap();
    node.assign_label(&first.id, &LabelConversationId::Peer(peer), &mut rng)
        .unwrap();
    node.assign_label(&first.id, &LabelConversationId::Group(group), &mut rng)
        .unwrap();
    node.assign_label(&second.id, &LabelConversationId::NoteToSelf, &mut rng)
        .unwrap();
    let before = node.labels().unwrap();
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
    assert_eq!(restored.labels().unwrap(), before);
    assert_eq!(
        restored
            .label_members(&first.id)
            .unwrap()
            .iter()
            .map(|member| member.conversation.clone())
            .collect::<Vec<_>>(),
        vec![
            LabelConversationId::Peer(peer),
            LabelConversationId::Group(group)
        ]
    );
    assert_eq!(
        restored
            .label_members(&second.id)
            .unwrap()
            .iter()
            .map(|member| member.conversation.clone())
            .collect::<Vec<_>>(),
        vec![LabelConversationId::NoteToSelf]
    );
    assert!(restored.stale_label_assignments().unwrap().is_empty());
}
