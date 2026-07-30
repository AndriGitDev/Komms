//! ADR-0018 endpoint/service acceptance over an in-memory fixed-shape
//! provider and a route-selective transport.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{
    derive_rendezvous_epoch_keys, rendezvous_epoch, seal_rendezvous_record,
    DeviceAuthorityCertificate, KdfProfile, RENDEZVOUS_MAX_TTL_SECS, RENDEZVOUS_SEALED_RECORD_LEN,
};
use kult_node::{DiscoveryMode, Event, Node, NodeError};
use kult_protocol::{
    Envelope, RendezvousLookupRequest, RendezvousRegisterRequest, RendezvousRoute,
    RendezvousRouteKind, RendezvousRouteRecord, RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_MEDIA_TYPE,
    RENDEZVOUS_REGISTER_ACK_LEN, RENDEZVOUS_REGISTER_PATH,
};
use kult_rendezvous::{ClientAdmissionKey, RendezvousService, RendezvousServiceConfig};
use kult_store::{RendezvousLocalConfig, Store};
use kult_transport::{
    CostClass, DeliveryHint, IngressClass, LatencyClass, LinkProfile, Reachability,
    RendezvousClient, RendezvousProvider, SendReceipt, Transport, TransportError,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const ALICE_BOOT: &str =
    "/ip4/192.0.2.1/udp/4101/quic-v1/p2p/12D3KooW9tHTtS3inCZiYykw4u5G4frbjVFqhkmJX12gSNCVeH3e";
const BOB_BOOT: &str =
    "/ip4/192.0.2.2/udp/4102/quic-v1/p2p/12D3KooW9xCm2jWjNVrwh51SWCQBMYdMyeU3NpT85QhLVkF6PcNM";
const ALICE_FRESH: &str =
    "/ip4/198.51.100.1/udp/5101/quic-v1/p2p/12D3KooW9tHTtS3inCZiYykw4u5G4frbjVFqhkmJX12gSNCVeH3e";
const BOB_FRESH: &str =
    "/ip4/198.51.100.2/udp/5102/quic-v1/p2p/12D3KooW9xCm2jWjNVrwh51SWCQBMYdMyeU3NpT85QhLVkF6PcNM";

#[derive(Default)]
struct RouteBus {
    queues: Mutex<HashMap<String, Vec<Envelope>>>,
    enabled: Mutex<HashSet<String>>,
    sent: Mutex<Vec<String>>,
}

impl RouteBus {
    fn enable_only(&self, routes: &[&str]) {
        *self.enabled.lock().unwrap() = routes.iter().map(|route| (*route).into()).collect();
    }

    fn clear_sent(&self) {
        self.sent.lock().unwrap().clear();
    }

    fn sent_routes(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }
}

struct RouteTransport {
    inboxes: Vec<String>,
    bus: Arc<RouteBus>,
}

impl RouteTransport {
    fn new(inboxes: &[&str], bus: Arc<RouteBus>) -> Self {
        Self {
            inboxes: inboxes.iter().map(|route| (*route).into()).collect(),
            bus,
        }
    }
}

#[async_trait]
impl Transport for RouteTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Free,
            broadcast: false,
        }
    }

    fn ingress_class(&self) -> IngressClass {
        IngressClass::Direct
    }

    async fn reachable(&self, hint: &DeliveryHint) -> Reachability {
        let DeliveryHint::Multiaddr(route) = hint else {
            return Reachability::Unreachable;
        };
        if self.bus.enabled.lock().unwrap().contains(route) {
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
        let DeliveryHint::Multiaddr(route) = hint else {
            return Err(TransportError::UnsupportedHint);
        };
        if !self.bus.enabled.lock().unwrap().contains(route) {
            return Err(TransportError::UnsupportedHint);
        }
        self.bus
            .queues
            .lock()
            .unwrap()
            .entry(route.clone())
            .or_default()
            .push(envelope.clone());
        self.bus.sent.lock().unwrap().push(route.clone());
        Ok(SendReceipt::AckedByNextHop)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        let mut queues = self.bus.queues.lock().unwrap();
        let mut received = Vec::new();
        for inbox in &self.inboxes {
            received.extend(queues.remove(inbox).unwrap_or_default());
        }
        Ok(received)
    }
}

struct InMemoryRendezvousClient {
    service: Arc<RendezvousService>,
    now: AtomicU64,
    blackhole: AtomicBool,
    registers: AtomicUsize,
    lookups: AtomicUsize,
    rng: Mutex<StdRng>,
}

impl InMemoryRendezvousClient {
    fn new() -> Self {
        Self {
            service: Arc::new(RendezvousService::new(RendezvousServiceConfig::default()).unwrap()),
            now: AtomicU64::new(NOW),
            blackhole: AtomicBool::new(false),
            registers: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
            rng: Mutex::new(StdRng::seed_from_u64(0x1818)),
        }
    }

    fn set_now(&self, now: u64) {
        self.now.store(now, Ordering::Release);
    }
}

#[async_trait]
impl RendezvousClient for InMemoryRendezvousClient {
    async fn register(
        &self,
        _provider: &RendezvousProvider,
        request: &RendezvousRegisterRequest,
    ) -> kult_transport::Result<[u8; RENDEZVOUS_REGISTER_ACK_LEN]> {
        self.registers.fetch_add(1, Ordering::Relaxed);
        if self.blackhole.load(Ordering::Acquire) {
            return Err(TransportError::RefusedByNextHop);
        }
        let response = self.service.handle(
            RENDEZVOUS_REGISTER_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &request.encode()?,
            ClientAdmissionKey([7u8; 16]),
            self.now.load(Ordering::Acquire),
            &mut *self.rng.lock().unwrap(),
        );
        response
            .body
            .try_into()
            .map_err(|_| TransportError::RefusedByNextHop)
    }

    async fn lookup(
        &self,
        _provider: &RendezvousProvider,
        request: &RendezvousLookupRequest,
    ) -> kult_transport::Result<[u8; RENDEZVOUS_SEALED_RECORD_LEN]> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if self.blackhole.load(Ordering::Acquire) {
            return Err(TransportError::RefusedByNextHop);
        }
        let response = self.service.handle(
            RENDEZVOUS_LOOKUP_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &request.encode(),
            ClientAdmissionKey([7u8; 16]),
            self.now.load(Ordering::Acquire),
            &mut *self.rng.lock().unwrap(),
        );
        response
            .body
            .try_into()
            .map_err(|_| TransportError::RefusedByNextHop)
    }
}

async fn tick(
    node: &mut Node,
    client: &InMemoryRendezvousClient,
    now: u64,
    rng: &mut StdRng,
) -> Vec<Event> {
    client.set_now(now);
    node.tick(now, rng).await.unwrap()
}

#[tokio::test]
async fn provider_control_registration_lookup_and_source_merge_recover_a_route() {
    let mut setup_rng = StdRng::seed_from_u64(0x1100);
    let mut alice_rng = StdRng::seed_from_u64(0x1101);
    let mut bob_rng = StdRng::seed_from_u64(0x1102);
    let dir = tempfile::tempdir().unwrap();
    let bus = Arc::new(RouteBus::default());
    bus.enable_only(&[ALICE_BOOT, BOB_BOOT, ALICE_FRESH, BOB_FRESH]);

    let alice_path = dir.path().join("alice.db");
    let bob_path = dir.path().join("bob.db");
    let mut alice = Node::create(&alice_path, b"alice", TEST_KDF, &mut setup_rng).unwrap();
    let mut bob = Node::create(&bob_path, b"bob", TEST_KDF, &mut setup_rng).unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    bob.add_transport(Arc::new(RouteTransport::new(
        &[BOB_BOOT, BOB_FRESH],
        Arc::clone(&bus),
    )));

    let alice_bundle = alice.handshake_bundle(NOW, &mut setup_rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut setup_rng).unwrap();
    let bob_id = alice
        .add_contact(
            "Bob",
            &bob_bundle,
            &[DeliveryHint::Multiaddr(BOB_BOOT.into())],
            NOW,
            &mut setup_rng,
        )
        .unwrap();
    let alice_id = bob
        .add_contact(
            "Alice",
            &alice_bundle,
            &[DeliveryHint::Multiaddr(ALICE_BOOT.into())],
            NOW,
            &mut setup_rng,
        )
        .unwrap();

    alice
        .send_message(&bob_id, b"establish", NOW + 1, &mut setup_rng)
        .unwrap();
    let client = Arc::new(InMemoryRendezvousClient::new());
    tick(&mut alice, &client, NOW + 2, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 3, &mut bob_rng).await;
    tick(&mut bob, &client, NOW + 5, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 6, &mut alice_rng).await;

    alice
        .handshake_bundle_with_hints(
            &[DeliveryHint::Multiaddr(ALICE_FRESH.into())],
            NOW + 7,
            &mut setup_rng,
        )
        .unwrap();
    bob.handshake_bundle_with_hints(
        &[DeliveryHint::Multiaddr(BOB_FRESH.into())],
        NOW + 7,
        &mut setup_rng,
    )
    .unwrap();
    let provider = RendezvousProvider::new("https://rv.example".into(), [9u8; 32]).unwrap();
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![provider.clone()],
            1,
        )
        .unwrap();
    bob.configure_rendezvous(
        DiscoveryMode::Standard,
        Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
        vec![provider],
        1,
    )
    .unwrap();

    // Exchange authenticated provider sets, wait past initial jitter, then
    // let both sides publish current+next and query prev/current/next.
    tick(&mut alice, &client, NOW + 10, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 11, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 12, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 13, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 400, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 401, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 407, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 408, &mut bob_rng).await;
    assert!(client.registers.load(Ordering::Relaxed) >= 4);
    assert!(client.lookups.load(Ordering::Relaxed) >= 6);
    assert!(client.service.record_count() >= 4);

    // The original authenticated routes are now blackholed. A fixed
    // three-epoch refresh must recover the independently stored rendezvous
    // source and ordinary delivery must use it without changing semantics.
    alice
        .set_hints(
            &bob_id,
            &[DeliveryHint::Multiaddr(BOB_BOOT.into())],
            &mut setup_rng,
        )
        .unwrap();
    bob.set_hints(
        &alice_id,
        &[DeliveryHint::Multiaddr(ALICE_BOOT.into())],
        &mut setup_rng,
    )
    .unwrap();
    bus.enable_only(&[ALICE_FRESH, BOB_FRESH]);
    bus.clear_sent();
    assert!(matches!(
        alice.set_rendezvous_conversation_active(&[0xff; 32], true),
        Err(NodeError::UnknownPeer)
    ));
    alice
        .set_rendezvous_conversation_active(&bob_id, true)
        .unwrap();
    tick(&mut alice, &client, NOW + 410, &mut alice_rng).await;
    let message = alice
        .send_message(&bob_id, b"rendezvous route", NOW + 411, &mut setup_rng)
        .unwrap();
    tick(&mut alice, &client, NOW + 412, &mut alice_rng).await;
    let events = tick(&mut bob, &client, NOW + 413, &mut bob_rng).await;
    assert!(events.iter().any(
        |event| matches!(event, Event::MessageReceived { id, body, .. }
            if *id == message && body == b"rendezvous route")
    ));
    let sent = bus.sent_routes();
    assert!(sent.iter().any(|route| route == BOB_FRESH));
    assert!(!sent.iter().any(|route| route == BOB_BOOT));
    alice
        .set_rendezvous_conversation_active(&bob_id, false)
        .unwrap();

    // A stale or compromised peer process can present a second authenticated,
    // complete provider set at the same generation. That is a durable
    // provider-authority fork: disable every remote lookup role, clear its
    // routes, and surface the conflict across restart until a strictly newer
    // complete set arrives.
    drop(bob);
    let bob_store = Store::open(&bob_path, b"bob").unwrap();
    let fork_provider = RendezvousProvider::new("https://fork.example".into(), [8u8; 32]).unwrap();
    bob_store
        .put_rendezvous_local_config(
            &RendezvousLocalConfig::new(
                1,
                vec![(
                    fork_provider.origin().to_owned(),
                    fork_provider.static_key(),
                )],
            )
            .unwrap(),
            &mut setup_rng,
        )
        .unwrap();
    drop(bob_store);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    bob.add_transport(Arc::new(RouteTransport::new(
        &[BOB_BOOT, BOB_FRESH],
        Arc::clone(&bus),
    )));
    bob.handshake_bundle_with_hints(
        &[DeliveryHint::Multiaddr(BOB_FRESH.into())],
        NOW + 414,
        &mut setup_rng,
    )
    .unwrap();
    bob.configure_rendezvous(
        DiscoveryMode::Standard,
        Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
        vec![fork_provider],
        1,
    )
    .unwrap();
    tick(&mut bob, &client, NOW + 414, &mut bob_rng).await;
    let provider_fork_events = tick(&mut alice, &client, NOW + 415, &mut alice_rng).await;
    assert!(provider_fork_events.iter().any(|event| {
        matches!(
            event,
            Event::RendezvousConflict { peer, provider, .. }
                if *peer == bob_id && *provider == [0u8; 32]
        )
    }));

    drop(alice);
    let inspection = Store::open(&alice_path, b"alice").unwrap();
    let bob_device = inspection.contact_devices_for(&bob_id).unwrap()[0].device;
    let provider_fork = inspection
        .get_rendezvous_service_state(&bob_device)
        .unwrap()
        .unwrap();
    assert_eq!(provider_fork.remote_provider_conflict_generation, Some(1));
    assert!(provider_fork
        .providers
        .iter()
        .all(|provider| !provider.lookup_enabled && provider.routes.is_empty()));
    drop(inspection);

    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![RendezvousProvider::new("https://rv.example".into(), [9u8; 32]).unwrap()],
            1,
        )
        .unwrap();
    let restart_events = tick(&mut alice, &client, NOW + 416, &mut alice_rng).await;
    assert!(restart_events.iter().any(
        |event| matches!(event, Event::RendezvousConflict { provider, .. } if *provider == [0u8; 32])
    ));

    let recovered_provider =
        RendezvousProvider::new("https://rv.example".into(), [9u8; 32]).unwrap();
    bob.configure_rendezvous(
        DiscoveryMode::Standard,
        Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
        vec![recovered_provider],
        2,
    )
    .unwrap();
    tick(&mut bob, &client, NOW + 417, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 418, &mut alice_rng).await;

    // Two valid complete records at one generation are a durable fork, not an
    // ordering choice. The source is cleared immediately and remains closed
    // across restart until a strictly newer authenticated generation exists.
    drop(alice);
    let inspection = Store::open(&alice_path, b"alice").unwrap();
    let bob_device = inspection.contact_devices_for(&bob_id).unwrap()[0].device;
    let state = inspection
        .get_rendezvous_service_state(&bob_device)
        .unwrap()
        .unwrap();
    assert_eq!(state.remote_provider_generation, 2);
    assert!(state.remote_provider_conflict_generation.is_none());
    let provider_id = RendezvousProvider::new("https://rv.example".into(), [9u8; 32]).unwrap();
    let accepted_generation = state
        .provider(&provider_id.provider_id())
        .unwrap()
        .accepted_generation;
    assert!(accepted_generation > 0);
    let endpoint = inspection
        .contact_devices_for(&bob_id)
        .unwrap()
        .into_iter()
        .find(|endpoint| endpoint.device == bob_device)
        .unwrap();
    let (certificate, remainder): (DeviceAuthorityCertificate, &[u8]) =
        postcard::take_from_bytes(&endpoint.certificate).unwrap();
    assert!(remainder.is_empty());
    let exporter = state.hybrid_service_exporter;
    drop(inspection);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    assert!(matches!(
        alice.configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![RendezvousProvider::new("https://other.example".into(), [8u8; 32]).unwrap()],
            1,
        ),
        Err(NodeError::RendezvousConflict)
    ));
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![provider_id.clone()],
            1,
        )
        .unwrap();

    let conflict_at = NOW + 420;
    let current_epoch = rendezvous_epoch(conflict_at);
    for (epoch, route) in [(current_epoch, BOB_FRESH), (current_epoch + 1, BOB_BOOT)] {
        let keys = derive_rendezvous_epoch_keys(
            &exporter,
            &provider_id.provider_id(),
            &certificate.device,
            epoch,
        )
        .unwrap();
        let record = RendezvousRouteRecord {
            epoch,
            generation: accepted_generation,
            issued_at: conflict_at,
            expires_at: conflict_at + u64::from(RENDEZVOUS_MAX_TTL_SECS),
            routes: vec![RendezvousRoute {
                kind: RendezvousRouteKind::Multiaddr,
                value: route.into(),
            }],
        };
        let plaintext = record.encode().unwrap();
        let request = RendezvousRegisterRequest {
            slot: keys.slot(),
            epoch,
            ttl_seconds: RENDEZVOUS_MAX_TTL_SECS,
            sealed_record: seal_rendezvous_record(&keys, &plaintext, &mut setup_rng),
        };
        let response = client.service.handle(
            RENDEZVOUS_REGISTER_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &request.encode().unwrap(),
            ClientAdmissionKey([0x51; 16]),
            conflict_at,
            &mut setup_rng,
        );
        assert_eq!(response.status, 200);
    }
    let before_conflict_lookups = client.lookups.load(Ordering::Relaxed);
    alice.request_rendezvous_refresh(&bob_id).unwrap();
    let events = tick(&mut alice, &client, conflict_at + 1, &mut alice_rng).await;
    let saw_conflict = events.iter().any(|event| {
        matches!(
            event,
            Event::RendezvousConflict {
                peer,
                device,
                provider,
            } if *peer == bob_id
                && *device == bob_device
                && *provider == provider_id.provider_id()
        )
    });
    drop(alice);
    let inspection = Store::open(&alice_path, b"alice").unwrap();
    let forked = inspection
        .get_rendezvous_service_state(&bob_device)
        .unwrap()
        .unwrap();
    let forked_provider = forked.provider(&provider_id.provider_id()).unwrap();
    assert_eq!(
        client.lookups.load(Ordering::Relaxed),
        before_conflict_lookups + 3,
        "unexpected events: {events:?}; state: {forked_provider:?}"
    );
    assert!(
        saw_conflict,
        "unexpected events: {events:?}; state: {forked_provider:?}"
    );
    assert!(forked_provider.routes.is_empty());
    assert_eq!(forked_provider.routes_expires_at, 0);
    assert_eq!(
        forked_provider.conflict_generation,
        Some(accepted_generation)
    );
    drop(inspection);

    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![provider_id.clone()],
            1,
        )
        .unwrap();
    let restart_events = tick(&mut alice, &client, conflict_at + 2, &mut alice_rng).await;
    assert!(restart_events.iter().any(
        |event| matches!(event, Event::RendezvousConflict { device, .. } if *device == bob_device)
    ));

    tick(&mut bob, &client, NOW + 5_000, &mut bob_rng).await;
    alice.request_rendezvous_refresh(&bob_id).unwrap();
    tick(&mut alice, &client, NOW + 5_001, &mut alice_rng).await;
    drop(alice);
    let inspection = Store::open(&alice_path, b"alice").unwrap();
    let recovered = inspection
        .get_rendezvous_service_state(&bob_device)
        .unwrap()
        .unwrap();
    let recovered_provider = recovered
        .provider(
            &RendezvousProvider::new("https://rv.example".into(), [9u8; 32])
                .unwrap()
                .provider_id(),
        )
        .unwrap();
    assert!(
        recovered_provider.conflict_generation.is_none(),
        "record fork did not resolve: accepted before={accepted_generation}, state={recovered_provider:?}"
    );
    assert!(
        recovered_provider.accepted_generation > accepted_generation,
        "strictly newer record was not accepted: before={accepted_generation}, state={recovered_provider:?}"
    );
    assert!(
        !recovered_provider.routes.is_empty(),
        "new record did not restore routes: state={recovered_provider:?}"
    );
    drop(inspection);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![provider_id],
            1,
        )
        .unwrap();

    // A hostile or unavailable provider cannot make a heartbeat loop until a
    // hit appears. Each explicit attempt performs exactly the three bounded
    // epoch lookups; five failures open the provider circuit.
    client.blackhole.store(true, Ordering::Release);
    let before_blackhole = client.lookups.load(Ordering::Relaxed);
    for at in [
        NOW + 6_000,
        NOW + 6_010,
        NOW + 6_030,
        NOW + 6_070,
        NOW + 6_150,
    ] {
        alice.request_rendezvous_refresh(&bob_id).unwrap();
        tick(&mut alice, &client, at, &mut alice_rng).await;
    }
    assert_eq!(
        client.lookups.load(Ordering::Relaxed),
        before_blackhole + 15
    );
    alice.request_rendezvous_refresh(&bob_id).unwrap();
    tick(&mut alice, &client, NOW + 6_160, &mut alice_rng).await;
    assert_eq!(
        client.lookups.load(Ordering::Relaxed),
        before_blackhole + 15
    );

    // Simulate a pre-ADR-0018 restore: the ratchets remain authenticated but
    // their non-backup exporters and service rows are absent. Provider
    // control may request an upgrade, but only one deterministic endpoint
    // starts a fresh PQXDH handshake. Both sides then regain independently
    // derived exporters and can publish again.
    drop(alice);
    drop(bob);
    for (path, passphrase) in [
        (alice_path.as_path(), b"alice".as_slice()),
        (bob_path.as_path(), b"bob".as_slice()),
    ] {
        let store = Store::open(path, passphrase).unwrap();
        let peer_device = store.contact_devices().unwrap()[0].device;
        let mut session = store.get_session(&peer_device).unwrap().unwrap();
        session.restore_hybrid_service_exporter(None);
        store
            .put_session(&peer_device, &session, &mut setup_rng)
            .unwrap();
    }

    client.blackhole.store(false, Ordering::Release);
    bus.enable_only(&[ALICE_BOOT, BOB_BOOT, ALICE_FRESH, BOB_FRESH]);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    alice.add_transport(Arc::new(RouteTransport::new(
        &[ALICE_BOOT, ALICE_FRESH],
        Arc::clone(&bus),
    )));
    bob.add_transport(Arc::new(RouteTransport::new(
        &[BOB_BOOT, BOB_FRESH],
        Arc::clone(&bus),
    )));
    alice
        .handshake_bundle_with_hints(
            &[DeliveryHint::Multiaddr(ALICE_FRESH.into())],
            NOW + 8_000,
            &mut setup_rng,
        )
        .unwrap();
    bob.handshake_bundle_with_hints(
        &[DeliveryHint::Multiaddr(BOB_FRESH.into())],
        NOW + 8_000,
        &mut setup_rng,
    )
    .unwrap();
    let provider = RendezvousProvider::new("https://rv.example".into(), [9u8; 32]).unwrap();
    alice
        .configure_rendezvous(
            DiscoveryMode::Standard,
            Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
            vec![provider.clone()],
            2,
        )
        .unwrap();
    bob.configure_rendezvous(
        DiscoveryMode::Standard,
        Some(Arc::clone(&client) as Arc<dyn RendezvousClient>),
        vec![provider],
        2,
    )
    .unwrap();
    let before_upgrade = client.registers.load(Ordering::Relaxed);
    tick(&mut alice, &client, NOW + 8_001, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 8_002, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 8_003, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 8_004, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 8_005, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 8_006, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 8_007, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 8_008, &mut bob_rng).await;
    tick(&mut alice, &client, NOW + 8_400, &mut alice_rng).await;
    tick(&mut bob, &client, NOW + 8_401, &mut bob_rng).await;
    assert!(
        client.registers.load(Ordering::Relaxed) >= before_upgrade + 4,
        "legacy sessions must register only after a verified replacement handshake"
    );
}
