//! B7 node acceptance: note-to-self is first-class local history with no
//! contact, session, envelope, receipt, queue, or transport send.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, Node, NOTE_TO_SELF_CONVERSATION_ID};
use kult_protocol::Envelope;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Default)]
struct SpyTransport {
    sends: AtomicUsize,
    reachability_checks: AtomicUsize,
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
        self.reachability_checks.fetch_add(1, Ordering::SeqCst);
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

#[tokio::test]
async fn note_is_local_survives_restart_and_backup_and_emits_zero_envelopes() {
    assert_eq!(NOTE_TO_SELF_CONVERSATION_ID, "note_to_self");
    let mut rng = StdRng::seed_from_u64(0x407e_5e1f);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let mut node = Node::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());

    let id = node
        .note_to_self_send("pack spare batteries", 1_800_000_000, &mut rng)
        .unwrap();
    assert!(node.contacts().unwrap().is_empty());
    assert_eq!(node.queued().unwrap(), 0);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability_checks.load(Ordering::SeqCst), 0);
    assert_eq!(node.note_to_self_messages().unwrap()[0].id, id);

    let events = node.tick(1_800_000_001, &mut rng).await.unwrap();
    assert!(matches!(
        events.as_slice(),
        [Event::NoteToSelfMessageAdded { id: event_id, body, .. }]
            if *event_id == id && body == "pack spare batteries"
    ));
    assert_eq!(node.queued().unwrap(), 0);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability_checks.load(Ordering::SeqCst), 0);

    let (backup, mnemonic) = node.export_backup(1_800_000_002, &mut rng).unwrap();
    drop(node);
    let reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(reopened.note_to_self_messages().unwrap()[0].id, id);
    drop(reopened);

    let restored = Node::restore(
        &directory.path().join("restored.db"),
        &backup,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    let history = restored.note_to_self_messages().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "pack spare batteries");
    assert_eq!(restored.queued().unwrap(), 0);
}
