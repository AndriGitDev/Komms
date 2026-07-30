use std::borrow::Cow;
use std::collections::{hash_map, HashMap, HashSet};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use hmac::{Hmac, Mac};
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::kad::store::{Error as StoreError, RecordStore};
use libp2p::kad::{self, Mode, ProviderRecord, Record, RecordKey, StoreInserts};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, SwarmEvent, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{connection_limits, identify, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use rand_core::{OsRng, RngCore};
use tokio::sync::watch;
use zeroize::Zeroize;

use crate::config::DhtConfig;
use crate::runtime::ServiceError;

const RECORD_NAMESPACE_V1: &[u8] = b"/kk/prekeys/1/";
const RECORD_NAMESPACE_V2: &[u8] = b"/kk/prekeys/2/";
const RECORD_KEY_BYTES: usize = 32;
const LEGACY_MAX_VALUE_BYTES: usize =
    kult_crypto::MAX_DEVICE_AUTHORITY_BYTES + kult_crypto::MAX_PREKEY_BUNDLE_BYTES + 16 * 1024;
const DHT_MAX_PACKET_BYTES: usize = kult_crypto::DISCOVERY_RECORD_SIZE + 64 * 1024;
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const DHT_SUBSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const DHT_REPLICATION_INTERVAL: Duration = Duration::from_secs(30 * 60);
const DHT_PERIODIC_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_QUIC_STREAMS: u32 = 32;
const MAX_QUIC_STREAM_BYTES: u32 = 2 * 1024 * 1024;
const MAX_QUIC_CONNECTION_BYTES: u32 = 16 * 1024 * 1024;
const RATE_WINDOW_SECONDS: u64 = 60;

/// Aggregate-only Kademlia cache metrics.
#[derive(Clone, Debug, Default)]
pub struct DhtMetrics {
    records: Arc<AtomicUsize>,
    value_bytes: Arc<AtomicUsize>,
}

impl DhtMetrics {
    /// Current cached row count.
    pub fn record_count(&self) -> usize {
        self.records.load(Ordering::Acquire)
    }

    /// Current combined cached value bytes.
    pub fn value_bytes(&self) -> usize {
        self.value_bytes.load(Ordering::Acquire)
    }
}

/// The dedicated bootstrap/Kademlia-cache role.
pub struct DhtService {
    config: DhtConfig,
    identity: libp2p::identity::Keypair,
    listen: Vec<Multiaddr>,
    bootstrap: Vec<(Multiaddr, PeerId)>,
    metrics: DhtMetrics,
}

impl DhtService {
    /// Parse all addresses and construct a service without opening sockets.
    pub fn new(
        config: DhtConfig,
        identity: libp2p::identity::Keypair,
    ) -> Result<Self, ServiceError> {
        let listen = config
            .listen
            .iter()
            .map(|address| {
                address.parse::<Multiaddr>().map_err(|_| {
                    ServiceError::invalid(format!("invalid DHT listen multiaddress: {address}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bootstrap = config
            .bootstrap
            .iter()
            .map(|address| parse_bootstrap(address))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            config,
            identity,
            listen,
            bootstrap,
            metrics: DhtMetrics::default(),
        })
    }

    /// Aggregate counters shared with the loopback health endpoint.
    pub fn metrics(&self) -> DhtMetrics {
        self.metrics.clone()
    }

    /// Own the swarm until shutdown. No endpoint or application protocol is
    /// negotiated by this behavior tree.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ServiceError> {
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let mut ingress_secret = [0u8; 32];
        OsRng.fill_bytes(&mut ingress_secret);
        let rate_limit = InboundConnectionRateLimit::new(
            ingress_secret,
            config.max_inbound_connections_per_minute,
            config.max_inbound_connections_per_address_per_minute,
            config.max_inbound_rate_buckets,
        );
        let mut quic_configure = |mut quic: libp2p::quic::Config| {
            quic.max_concurrent_stream_limit = MAX_QUIC_STREAMS;
            quic.max_stream_data = MAX_QUIC_STREAM_BYTES;
            quic.max_connection_data = MAX_QUIC_CONNECTION_BYTES;
            quic
        };
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(self.identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|error| ServiceError::invalid(format!("build DHT TCP transport: {error}")))?
            .with_quic_config(&mut quic_configure)
            .with_behaviour(move |key| {
                let local_peer = key.public().to_peer_id();
                let store =
                    BoundedRecordStore::new(config.max_records, config.max_value_bytes, metrics);
                let mut kad_config = kad::Config::new(StreamProtocol::new("/komms/kad/1"));
                kad_config
                    .set_max_packet_size(DHT_MAX_PACKET_BYTES)
                    .set_query_timeout(DHT_QUERY_TIMEOUT)
                    .set_substreams_timeout(DHT_SUBSTREAM_TIMEOUT)
                    .set_record_ttl(Some(Duration::from_secs(config.record_ttl_seconds)))
                    .set_replication_interval(Some(DHT_REPLICATION_INTERVAL))
                    .set_publication_interval(None)
                    .set_provider_publication_interval(None)
                    .set_record_filtering(StoreInserts::Unfiltered)
                    .set_periodic_bootstrap_interval(Some(DHT_PERIODIC_BOOTSTRAP_INTERVAL))
                    .set_kbucket_size(NonZeroUsize::new(20).expect("non-zero constant"));
                let kad = kad::Behaviour::with_config(local_peer, store, kad_config);
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/komms/reference/1".into(),
                    key.public(),
                ));
                let limits = connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(config.max_pending_incoming))
                        .with_max_pending_outgoing(Some(config.max_pending_outgoing))
                        .with_max_established_incoming(Some(config.max_established_incoming))
                        .with_max_established(Some(config.max_established))
                        .with_max_established_per_peer(Some(config.max_established_per_peer)),
                );
                ReferenceBehaviour {
                    rate_limit,
                    limits,
                    kad,
                    identify,
                }
            })
            .map_err(|error| ServiceError::invalid(format!("build DHT behavior: {error}")))?
            .with_swarm_config(|swarm| swarm.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
            .build();
        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

        let mut listeners = HashSet::with_capacity(self.listen.len());
        for address in self.listen {
            let listener = swarm
                .listen_on(address)
                .map_err(|error| ServiceError::invalid(format!("open DHT listener: {error}")))?;
            listeners.insert(listener);
        }
        for (address, peer) in self.bootstrap {
            swarm.behaviour_mut().kad.add_address(&peer, address);
        }
        if !self.config.bootstrap.is_empty() {
            let _ = swarm.behaviour_mut().kad.bootstrap();
        }

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(ReferenceBehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. }
                        )) => {
                            for address in info.listen_addrs.into_iter().take(8) {
                                swarm.behaviour_mut().kad.add_address(&peer_id, address);
                            }
                        }
                        SwarmEvent::ListenerClosed { listener_id, .. } => {
                            listeners.remove(&listener_id);
                            if listeners.is_empty() {
                                return Err(ServiceError::invalid(
                                    "all DHT listeners closed"
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        drop(swarm);
        Ok(())
    }
}

#[derive(NetworkBehaviour)]
struct ReferenceBehaviour {
    rate_limit: InboundConnectionRateLimit,
    limits: connection_limits::Behaviour,
    kad: kad::Behaviour<BoundedRecordStore>,
    identify: identify::Behaviour,
}

struct BoundedRecordStore {
    records: HashMap<RecordKey, Record>,
    value_bytes: usize,
    max_records: usize,
    max_value_bytes: usize,
    metrics: DhtMetrics,
}

impl BoundedRecordStore {
    fn new(max_records: usize, max_value_bytes: usize, metrics: DhtMetrics) -> Self {
        Self {
            records: HashMap::new(),
            value_bytes: 0,
            max_records,
            max_value_bytes,
            metrics,
        }
    }

    fn value_shape_allowed(key: &RecordKey, value: &[u8]) -> bool {
        let key = key.as_ref();
        if let Some(suffix) = key.strip_prefix(RECORD_NAMESPACE_V2) {
            suffix.len() == RECORD_KEY_BYTES && value.len() == kult_crypto::DISCOVERY_RECORD_SIZE
        } else if let Some(suffix) = key.strip_prefix(RECORD_NAMESPACE_V1) {
            suffix.len() == RECORD_KEY_BYTES
                && !value.is_empty()
                && value.len() <= LEGACY_MAX_VALUE_BYTES
        } else {
            false
        }
    }

    fn sync_metrics(&self) {
        self.metrics
            .records
            .store(self.records.len(), Ordering::Release);
        self.metrics
            .value_bytes
            .store(self.value_bytes, Ordering::Release);
    }
}

impl Drop for BoundedRecordStore {
    fn drop(&mut self) {
        for (_, mut record) in self.records.drain() {
            record.value.zeroize();
        }
        self.value_bytes = 0;
        self.sync_metrics();
    }
}

fn borrowed_record(record: &Record) -> Cow<'_, Record> {
    Cow::Borrowed(record)
}

impl RecordStore for BoundedRecordStore {
    type RecordsIter<'a> =
        std::iter::Map<hash_map::Values<'a, RecordKey, Record>, fn(&'a Record) -> Cow<'a, Record>>;
    type ProvidedIter<'a> = std::iter::Empty<Cow<'a, ProviderRecord>>;

    fn get(&self, key: &RecordKey) -> Option<Cow<'_, Record>> {
        self.records.get(key).map(Cow::Borrowed)
    }

    fn put(&mut self, record: Record) -> Result<(), StoreError> {
        if !Self::value_shape_allowed(&record.key, &record.value) {
            return Err(StoreError::ValueTooLarge);
        }
        let previous_bytes = self
            .records
            .get(&record.key)
            .map_or(0, |previous| previous.value.len());
        if previous_bytes == 0 && self.records.len() >= self.max_records {
            return Err(StoreError::MaxRecords);
        }
        let next_bytes = self
            .value_bytes
            .saturating_sub(previous_bytes)
            .checked_add(record.value.len())
            .ok_or(StoreError::ValueTooLarge)?;
        if next_bytes > self.max_value_bytes {
            return Err(StoreError::ValueTooLarge);
        }
        self.value_bytes = next_bytes;
        if let Some(mut previous) = self.records.insert(record.key.clone(), record) {
            previous.value.zeroize();
        }
        self.sync_metrics();
        Ok(())
    }

    fn remove(&mut self, key: &RecordKey) {
        if let Some(mut record) = self.records.remove(key) {
            self.value_bytes = self.value_bytes.saturating_sub(record.value.len());
            record.value.zeroize();
            self.sync_metrics();
        }
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.records.values().map(borrowed_record)
    }

    fn add_provider(&mut self, _record: ProviderRecord) -> Result<(), StoreError> {
        Err(StoreError::MaxProvidedKeys)
    }

    fn providers(&self, _key: &RecordKey) -> Vec<ProviderRecord> {
        Vec::new()
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        std::iter::empty()
    }

    fn remove_provider(&mut self, _key: &RecordKey, _provider: &PeerId) {}
}

struct InboundConnectionRateLimit {
    secret: [u8; 32],
    max_global: u32,
    max_per_address: u32,
    max_buckets: usize,
    window: u64,
    global: u32,
    buckets: HashMap<[u8; 16], u32>,
}

impl InboundConnectionRateLimit {
    fn new(secret: [u8; 32], max_global: u32, max_per_address: u32, max_buckets: usize) -> Self {
        Self {
            secret,
            max_global,
            max_per_address,
            max_buckets,
            window: unix_now() / RATE_WINDOW_SECONDS,
            global: 0,
            buckets: HashMap::new(),
        }
    }

    fn admit(&mut self, address: &Multiaddr) -> bool {
        let window = unix_now() / RATE_WINDOW_SECONDS;
        if window != self.window {
            self.window = window;
            self.global = 0;
            self.buckets.clear();
        }
        if self.global >= self.max_global {
            return false;
        }
        let key = keyed_address(&self.secret, address);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_buckets {
            return false;
        }
        let count = self.buckets.entry(key).or_default();
        if *count >= self.max_per_address {
            return false;
        }
        *count = count.saturating_add(1);
        self.global = self.global.saturating_add(1);
        true
    }
}

impl Drop for InboundConnectionRateLimit {
    fn drop(&mut self) {
        self.secret.zeroize();
        for (mut key, _) in self.buckets.drain() {
            key.zeroize();
        }
    }
}

impl NetworkBehaviour for InboundConnectionRateLimit {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.admit(remote_addr).then_some(()).ok_or_else(|| {
            ConnectionDenied::new(std::io::Error::other("inbound connection rate limit"))
        })
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _address: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

fn keyed_address(secret: &[u8; 32], address: &Multiaddr) -> [u8; 16] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("fixed HMAC key");
    let mut found_ip = false;
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
                found_ip = true;
                break;
            }
            Protocol::Ip6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
                found_ip = true;
                break;
            }
            _ => {}
        }
    }
    if !found_ip {
        mac.update(address.to_string().as_bytes());
    }
    let digest = mac.finalize().into_bytes();
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn parse_bootstrap(value: &str) -> Result<(Multiaddr, PeerId), ServiceError> {
    let address: Multiaddr = value
        .parse()
        .map_err(|_| ServiceError::invalid(format!("invalid bootstrap multiaddress: {value}")))?;
    let peer = address
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .last()
        .ok_or_else(|| {
            ServiceError::invalid(format!("bootstrap address lacks /p2p peer id: {value}"))
        })?;
    Ok((address, peer))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use libp2p::kad::store::RecordStore;

    use super::*;

    fn record_key(namespace: &[u8]) -> RecordKey {
        let mut bytes = namespace.to_vec();
        bytes.extend_from_slice(&[7u8; 32]);
        RecordKey::from(bytes)
    }

    #[test]
    fn store_accepts_only_bounded_komms_namespaces() {
        let metrics = DhtMetrics::default();
        let mut store =
            BoundedRecordStore::new(2, 2 * kult_crypto::DISCOVERY_RECORD_SIZE, metrics.clone());
        assert!(store
            .put(Record::new(
                record_key(RECORD_NAMESPACE_V2),
                vec![1u8; kult_crypto::DISCOVERY_RECORD_SIZE],
            ))
            .is_ok());
        assert!(store
            .put(Record::new(record_key(RECORD_NAMESPACE_V1), vec![2u8; 1]))
            .is_ok());
        assert!(store
            .put(Record::new(
                RecordKey::from(b"/unrelated/record".to_vec()),
                vec![3u8; 1],
            ))
            .is_err());
        assert!(store
            .put(Record::new(
                record_key(RECORD_NAMESPACE_V2),
                vec![4u8; kult_crypto::DISCOVERY_RECORD_SIZE - 1],
            ))
            .is_err());
        assert_eq!(metrics.record_count(), 2);
        assert_eq!(
            metrics.value_bytes(),
            kult_crypto::DISCOVERY_RECORD_SIZE + 1
        );
    }

    #[test]
    fn volatile_address_rate_is_exact_and_bounded() {
        let mut limiter = InboundConnectionRateLimit::new([5u8; 32], 2, 1, 1);
        let first: Multiaddr = "/ip4/192.0.2.10/tcp/4405".parse().unwrap();
        let second: Multiaddr = "/ip4/192.0.2.11/tcp/4405".parse().unwrap();
        assert!(limiter.admit(&first));
        assert!(!limiter.admit(&first));
        assert!(!limiter.admit(&second));
    }

    #[tokio::test]
    async fn blackholed_bootstrap_does_not_prevent_start_or_clean_restart() {
        let unreachable = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let config = DhtConfig {
            listen: vec![
                "/ip4/127.0.0.1/tcp/0".into(),
                "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            ],
            bootstrap: vec![format!("/ip4/127.0.0.1/tcp/9/p2p/{unreachable}")],
            max_records: 2,
            max_value_bytes: 4 * kult_crypto::DISCOVERY_RECORD_SIZE,
            record_ttl_seconds: 3_600,
            max_pending_incoming: 2,
            max_pending_outgoing: 2,
            max_established_incoming: 2,
            max_established: 4,
            max_established_per_peer: 1,
            max_inbound_connections_per_minute: 8,
            max_inbound_connections_per_address_per_minute: 4,
            max_inbound_rate_buckets: 8,
        };
        let identity = libp2p::identity::Keypair::generate_ed25519();
        for _ in 0..2 {
            let service = DhtService::new(config.clone(), identity.clone()).unwrap();
            let (shutdown_sender, shutdown_receiver) = watch::channel(false);
            let task = tokio::spawn(service.run(shutdown_receiver));
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown_sender.send(true).unwrap();
            task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn komms_client_round_trips_connect_record_through_reference_cache() {
        use kult_transport::{Discovery, DiscoveryNamespace, Libp2pTransport};

        let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let identity = libp2p::identity::Keypair::generate_ed25519();
        let peer = identity.public().to_peer_id();
        let config = DhtConfig {
            listen: vec![format!("/ip4/127.0.0.1/tcp/{port}")],
            bootstrap: Vec::new(),
            max_records: 4,
            max_value_bytes: 4 * kult_crypto::DISCOVERY_RECORD_SIZE,
            record_ttl_seconds: 3_600,
            max_pending_incoming: 4,
            max_pending_outgoing: 4,
            max_established_incoming: 4,
            max_established: 8,
            max_established_per_peer: 2,
            max_inbound_connections_per_minute: 32,
            max_inbound_connections_per_address_per_minute: 16,
            max_inbound_rate_buckets: 8,
        };
        let service = DhtService::new(config, identity).unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let service_task = tokio::spawn(service.run(shutdown_receiver));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let publisher = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
            .await
            .unwrap();
        let reader = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
            .await
            .unwrap();
        let seed = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
        publisher.bootstrap(&[seed.as_str()]).await.unwrap();
        reader.bootstrap(&[seed.as_str()]).await.unwrap();

        let key = [0x41; 32];
        let value = vec![0x5a; kult_crypto::DISCOVERY_RECORD_SIZE];
        publisher
            .publish(
                DiscoveryNamespace::ConnectV2,
                key,
                value.clone(),
                4_000_000_000,
            )
            .await
            .unwrap();
        assert_eq!(
            reader
                .lookup(DiscoveryNamespace::ConnectV2, key)
                .await
                .unwrap(),
            vec![value]
        );

        shutdown_sender.send(true).unwrap();
        service_task.await.unwrap().unwrap();
    }
}
