//! F4 acceptance: one stable, expiring carrier verdict drives application
//! feature gates and changes when transport reachability changes.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{CarrierCapability, Event, Node};
use kult_protocol::Envelope;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

struct Link {
    cost: CostClass,
    latency: LatencyClass,
    reachability: Arc<AtomicU8>,
}

impl Link {
    fn new(cost: CostClass, latency: LatencyClass, reachability: Reachability) -> Self {
        Self {
            cost,
            latency,
            reachability: Arc::new(AtomicU8::new(encode_reachability(reachability))),
        }
    }

    fn set(&self, reachability: Reachability) {
        self.reachability
            .store(encode_reachability(reachability), Ordering::SeqCst);
    }
}

#[async_trait]
impl Transport for Link {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: self.latency,
            cost: self.cost,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        if matches!(peer, DeliveryHint::Multiaddr(_)) {
            decode_reachability(self.reachability.load(Ordering::SeqCst))
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        _peer: &DeliveryHint,
        _envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }

    fn call_ready(&self, peer: &DeliveryHint) -> bool {
        self.latency == LatencyClass::Millis
            && decode_reachability(self.reachability.load(Ordering::SeqCst)) == Reachability::Now
            && matches!(peer, DeliveryHint::Multiaddr(address) if address.contains("/quic-v1") && !address.contains("/p2p-circuit"))
    }
}

#[tokio::test]
async fn verdict_changes_are_evented_and_positive_snapshots_expire_safe() {
    let mut rng = StdRng::seed_from_u64(0xf400);
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::create(&dir.path().join("node.db"), b"node", TEST_KDF, &mut rng).unwrap();
    let mut peer = Node::create(&dir.path().join("peer.db"), b"peer", TEST_KDF, &mut rng).unwrap();
    let bundle = peer.handshake_bundle(NOW, &mut rng).unwrap();
    let peer_id = node
        .add_contact(
            "peer",
            &bundle,
            &[DeliveryHint::Multiaddr(
                "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/test".to_owned(),
            )],
            NOW,
            &mut rng,
        )
        .unwrap();

    let mesh = Arc::new(Link::new(
        CostClass::Airtime,
        LatencyClass::Seconds,
        Reachability::Now,
    ));
    let bulk = Arc::new(Link::new(
        CostClass::Free,
        LatencyClass::HumanScale,
        Reachability::Unreachable,
    ));
    let realtime = Arc::new(Link::new(
        CostClass::Metered,
        LatencyClass::Millis,
        Reachability::Unreachable,
    ));
    node.add_transport(mesh.clone());
    node.add_transport(bulk.clone());
    node.add_transport(realtime.clone());

    assert_capability_event(
        &node.tick(NOW + 1, &mut rng).await.unwrap(),
        CarrierCapability::MeshOnly,
    );
    let mesh_snapshot = node.carrier_capability(&peer_id, NOW + 1).unwrap();
    assert_eq!(mesh_snapshot.capability, CarrierCapability::MeshOnly);
    assert!(node
        .tick(NOW + 2, &mut rng)
        .await
        .unwrap()
        .iter()
        .all(|event| !matches!(event, Event::CarrierCapabilityChanged { .. })));

    bulk.set(Reachability::StoreAndForward);
    assert_capability_event(
        &node.tick(NOW + 3, &mut rng).await.unwrap(),
        CarrierCapability::Bulk,
    );

    realtime.set(Reachability::Now);
    assert_capability_event(
        &node.tick(NOW + 4, &mut rng).await.unwrap(),
        CarrierCapability::Realtime,
    );
    let realtime_snapshot = node.carrier_capability(&peer_id, NOW + 4).unwrap();
    assert_eq!(
        node.carrier_capability(&peer_id, realtime_snapshot.expires_at)
            .unwrap()
            .capability,
        CarrierCapability::OfflineOrUnknown
    );

    node.set_hints(
        &peer_id,
        &[DeliveryHint::Multiaddr(
            "/ip4/127.0.0.1/tcp/1/p2p/relay/p2p-circuit/p2p/peer".to_owned(),
        )],
        &mut rng,
    )
    .unwrap();
    assert_capability_event(
        &node.tick(NOW + 5, &mut rng).await.unwrap(),
        CarrierCapability::Bulk,
    );

    mesh.set(Reachability::Unreachable);
    bulk.set(Reachability::Unreachable);
    realtime.set(Reachability::Unreachable);
    assert_capability_event(
        &node.tick(NOW + 6, &mut rng).await.unwrap(),
        CarrierCapability::OfflineOrUnknown,
    );
}

fn assert_capability_event(events: &[Event], expected: CarrierCapability) {
    assert!(events.iter().any(|event| matches!(
        event,
        Event::CarrierCapabilityChanged { snapshot } if snapshot.capability == expected
    )));
}

const fn encode_reachability(reachability: Reachability) -> u8 {
    match reachability {
        Reachability::Now => 1,
        Reachability::StoreAndForward => 2,
        Reachability::Unreachable => 0,
    }
}

const fn decode_reachability(value: u8) -> Reachability {
    match value {
        1 => Reachability::Now,
        2 => Reachability::StoreAndForward,
        _ => Reachability::Unreachable,
    }
}
