//! B12 acceptance: the private theme choice is sealed, idempotent, restored,
//! and wholly disconnected from delivery and transport work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{Event, Node, ThemePreference};
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

#[test]
fn default_idempotency_restart_restore_and_zero_network_work() {
    let mut rng = StdRng::seed_from_u64(0xb12);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let mut node = Node::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());

    assert_eq!(node.theme_preference().unwrap(), ThemePreference::System);
    assert!(!node.theme_preference_is_persisted().unwrap());
    assert!(node
        .set_theme_preference(ThemePreference::Dark, &mut rng)
        .unwrap());
    assert!(!node
        .set_theme_preference(ThemePreference::Dark, &mut rng)
        .unwrap());
    assert_eq!(node.drain_events(), vec![Event::ThemeChanged]);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability.load(Ordering::SeqCst), 0);

    drop(node);
    let mut reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(reopened.theme_preference().unwrap(), ThemePreference::Dark);
    assert!(reopened.theme_preference_is_persisted().unwrap());
    assert!(reopened
        .set_theme_preference(ThemePreference::Light, &mut rng)
        .unwrap());
    let (backup, mnemonic) = reopened.export_backup(1_800_000_000, &mut rng).unwrap();
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
    assert_eq!(restored.theme_preference().unwrap(), ThemePreference::Light);
    assert!(restored.theme_preference_is_persisted().unwrap());
}
