//! Dedicated least-authority mailbox-v2 network service.
//!
//! This behavior tree negotiates only `/komms/mailbox/2`. It deliberately has
//! no endpoint envelope, Kademlia, identify, relay, call, wake, or mailbox-v1
//! behavior.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::transport::ListenerId;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{connection_limits, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol};
use tokio::sync::watch;

use kult_protocol::Envelope;

use crate::internet::{load_or_create_service_identity, LockExt};
use crate::mailbox_v2::{
    MailboxDepositDisposition, MailboxV2Request, MailboxV2Response, MailboxV2Store,
};
use crate::{
    MailboxMetrics, MailboxServiceConfig, Result, TransportError, MAILBOX_V2_REQUEST_MAX_BYTES,
    MAILBOX_V2_RESPONSE_MAX_BYTES,
};

/// Complete application-protocol surface of the dedicated mailbox artifact.
pub const MAILBOX_SERVICE_PROTOCOLS: &[&str] = &["/komms/mailbox/2"];
const MAILBOX_V2_PROTOCOL: StreamProtocol = StreamProtocol::new(MAILBOX_SERVICE_PROTOCOLS[0]);
const MAILBOX_MAX_CONCURRENT_STREAMS: usize = 8;
const MAX_PENDING_INCOMING_CONNECTIONS: u32 = 32;
const MAX_PENDING_OUTGOING_CONNECTIONS: u32 = 0;
const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 64;
const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 8;
const MAX_ESTABLISHED_CONNECTIONS: u32 = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(NetworkBehaviour)]
struct MailboxBehaviour {
    limits: connection_limits::Behaviour,
    mailbox_v2: request_response::cbor::Behaviour<MailboxV2Request, MailboxV2Response>,
}

/// Non-secret identity and initial aggregate state for an initialized relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxServiceInfo {
    /// Stable libp2p service peer id.
    pub peer_id: String,
    /// Physical store schema version.
    pub schema_version: u32,
}

/// Cloneable access to content-free aggregate mailbox metrics.
#[derive(Clone)]
pub struct MailboxServiceMetrics {
    store: Arc<Mutex<MailboxV2Store>>,
}

impl MailboxServiceMetrics {
    /// Sweep expired rows and return one aggregate-only snapshot.
    pub fn snapshot(&self) -> io::Result<MailboxMetrics> {
        self.store.lock_unpoisoned().metrics(unix_now())
    }
}

/// A running dedicated mailbox-v2 service.
pub struct MailboxV2Service {
    peer_id: PeerId,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    metrics: MailboxServiceMetrics,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl MailboxV2Service {
    /// Open initialized service state and bind the configured libp2p
    /// listeners. No other Komms application protocol is registered.
    pub async fn start(listen: &[String], config: MailboxServiceConfig) -> Result<Self> {
        validate_service_config(&config)?;
        require_initialized(&config)?;
        if listen.is_empty() || listen.len() > 4 {
            return Err(io_other("mailbox listener count is outside 1..=4"));
        }

        let identity = load_or_create_service_identity(&config.transport_key_path)
            .map_err(TransportError::Io)?;
        let peer_id = identity.public().to_peer_id();
        let store = Arc::new(Mutex::new(
            MailboxV2Store::open(&config).map_err(TransportError::Io)?,
        ));
        let metrics = MailboxServiceMetrics {
            store: Arc::clone(&store),
        };

        let mut quic_configure = |mut quic: libp2p::quic::Config| {
            quic.max_concurrent_stream_limit = MAILBOX_MAX_CONCURRENT_STREAMS as u32;
            quic.max_stream_data = MAILBOX_V2_RESPONSE_MAX_BYTES as u32;
            quic.max_connection_data =
                (MAILBOX_V2_RESPONSE_MAX_BYTES * MAILBOX_MAX_CONCURRENT_STREAMS) as u32;
            quic
        };
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|error| io_other(format!("build mailbox TCP transport: {error}")))?
            .with_quic_config(&mut quic_configure)
            .with_behaviour(|_| {
                let codec = request_response::cbor::codec::Codec::<
                    MailboxV2Request,
                    MailboxV2Response,
                >::default()
                .set_request_size_maximum(MAILBOX_V2_REQUEST_MAX_BYTES as u64)
                .set_response_size_maximum(MAILBOX_V2_RESPONSE_MAX_BYTES as u64);
                let mailbox_v2 = request_response::Behaviour::with_codec(
                    codec,
                    [(MAILBOX_V2_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_max_concurrent_streams(MAILBOX_MAX_CONCURRENT_STREAMS),
                );
                let limits = connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING_CONNECTIONS))
                        .with_max_pending_outgoing(Some(MAX_PENDING_OUTGOING_CONNECTIONS))
                        .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS))
                        .with_max_established_per_peer(Some(MAX_ESTABLISHED_CONNECTIONS_PER_PEER))
                        .with_max_established(Some(MAX_ESTABLISHED_CONNECTIONS)),
                );
                MailboxBehaviour { limits, mailbox_v2 }
            })
            .expect("mailbox behavior construction is infallible")
            .with_swarm_config(|swarm| swarm.with_idle_connection_timeout(IDLE_TIMEOUT))
            .build();

        let mut listeners = HashSet::with_capacity(listen.len());
        for address in listen {
            if address.len() > 512 {
                return Err(io_other("mailbox listen multiaddress exceeds 512 bytes"));
            }
            let address: Multiaddr = address
                .parse()
                .map_err(|_| io_other("invalid mailbox listen multiaddress"))?;
            if address
                .iter()
                .any(|part| matches!(part, libp2p::multiaddr::Protocol::P2p(_)))
            {
                return Err(io_other(
                    "mailbox listen multiaddress must not contain a peer id",
                ));
            }
            let listener = swarm
                .listen_on(address)
                .map_err(|error| io_other(format!("open mailbox listener: {error:?}")))?;
            listeners.insert(listener);
        }

        let listen_addrs = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(run_service(
            swarm,
            Arc::clone(&listen_addrs),
            store,
            listeners,
            shutdown_receiver,
        ));
        Ok(Self {
            peer_id,
            listen_addrs,
            metrics,
            shutdown,
            task: Some(task),
        })
    }

    /// Stable libp2p service peer id.
    pub fn peer_id(&self) -> String {
        self.peer_id.to_string()
    }

    /// Current bound listener addresses with the service peer id appended.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs
            .lock_unpoisoned()
            .iter()
            .cloned()
            .map(|address| address.with(libp2p::multiaddr::Protocol::P2p(self.peer_id)))
            .map(|address| address.to_string())
            .collect()
    }

    /// Wait for the first configured listener to bind.
    pub async fn wait_listen_addr(&self) -> Result<String> {
        tokio::time::timeout(LISTEN_TIMEOUT, async {
            loop {
                if let Some(address) = self.listen_addrs().into_iter().next() {
                    return address;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| io_other("no mailbox listener bound within 5s"))
    }

    /// Clone the aggregate-only metrics handle.
    pub fn metrics(&self) -> MailboxServiceMetrics {
        self.metrics.clone()
    }

    /// Whether the network task has stopped before explicit shutdown.
    pub fn is_finished(&self) -> bool {
        self.task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    /// Request clean shutdown and wait for the service task to release its
    /// listeners and durable store.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        task.await
            .map_err(|error| io_other(format!("mailbox service task stopped: {error}")))?
    }
}

impl Drop for MailboxV2Service {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Initialize a new durable store key, database, and transport-only service
/// identity. Existing targets are never overwritten.
pub fn initialize_mailbox_service(config: &MailboxServiceConfig) -> Result<MailboxServiceInfo> {
    validate_service_config(config)?;
    for path in [
        &config.database_path,
        &config.key_path,
        &config.transport_key_path,
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(io_other("mailbox initialization target already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
    let mut store = MailboxV2Store::open(config).map_err(TransportError::Io)?;
    let schema_version = store
        .metrics(unix_now())
        .map_err(TransportError::Io)?
        .schema_version;
    drop(store);
    let identity =
        load_or_create_service_identity(&config.transport_key_path).map_err(TransportError::Io)?;
    Ok(MailboxServiceInfo {
        peer_id: identity.public().to_peer_id().to_string(),
        schema_version,
    })
}

/// Validate and inspect initialized service state without opening a listener.
pub fn inspect_mailbox_service(config: &MailboxServiceConfig) -> Result<MailboxServiceInfo> {
    validate_service_config(config)?;
    require_initialized(config)?;
    let identity =
        load_or_create_service_identity(&config.transport_key_path).map_err(TransportError::Io)?;
    let mut store = MailboxV2Store::open(config).map_err(TransportError::Io)?;
    let schema_version = store
        .metrics(unix_now())
        .map_err(TransportError::Io)?
        .schema_version;
    Ok(MailboxServiceInfo {
        peer_id: identity.public().to_peer_id().to_string(),
        schema_version,
    })
}

async fn run_service(
    mut swarm: libp2p::Swarm<MailboxBehaviour>,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    store: Arc<Mutex<MailboxV2Store>>,
    mut listeners: HashSet<ListenerId>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let mut addrs = listen_addrs.lock_unpoisoned();
                    if !addrs.contains(&address) {
                        addrs.push(address);
                    }
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    listen_addrs
                        .lock_unpoisoned()
                        .retain(|candidate| candidate != &address);
                }
                SwarmEvent::ListenerClosed { listener_id, .. } => {
                    listeners.remove(&listener_id);
                    if listeners.is_empty() {
                        return Err(io_other("all mailbox listeners closed"));
                    }
                }
                SwarmEvent::Behaviour(MailboxBehaviourEvent::MailboxV2(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) => {
                    let response = handle_request(&store, &peer, request);
                    let _ = swarm
                        .behaviour_mut()
                        .mailbox_v2
                        .send_response(channel, response);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn handle_request(
    store: &Arc<Mutex<MailboxV2Store>>,
    peer: &PeerId,
    request: MailboxV2Request,
) -> MailboxV2Response {
    let client = peer.to_bytes();
    match request {
        MailboxV2Request::Deposit { envelope } => {
            let accepted = match Envelope::decode(&envelope) {
                Ok(decoded) => matches!(
                    store.lock_unpoisoned().deposit_disposition(
                        &client,
                        &decoded,
                        envelope,
                        unix_now(),
                    ),
                    Ok(MailboxDepositDisposition::Accepted)
                ),
                Err(_) => {
                    let _ = store
                        .lock_unpoisoned()
                        .refuse_deposit_request(&client, unix_now());
                    false
                }
            };
            MailboxV2Response::Deposit { accepted }
        }
        MailboxV2Request::Lease { tokens } => {
            match store
                .lock_unpoisoned()
                .lease(&client, &tokens, unix_now())
                .ok()
                .flatten()
            {
                Some(page) => MailboxV2Response::Lease {
                    serving: true,
                    lease_id: page.lease_id,
                    expires_at: page.expires_at,
                    rows: page.rows,
                },
                None => MailboxV2Response::Lease {
                    serving: false,
                    lease_id: [0u8; 16],
                    expires_at: 0,
                    rows: Vec::new(),
                },
            }
        }
        MailboxV2Request::AckLease { lease_id, row_ids } => {
            let accepted = store
                .lock_unpoisoned()
                .ack(&client, lease_id, &row_ids, unix_now())
                .unwrap_or(false);
            MailboxV2Response::AckLease { accepted }
        }
    }
}

fn validate_service_config(config: &MailboxServiceConfig) -> Result<()> {
    if config.allow_v1_compat {
        return Err(io_other(
            "dedicated mailbox service cannot enable mailbox-v1 compatibility",
        ));
    }
    if config.database_path == config.key_path
        || config.database_path == config.transport_key_path
        || config.key_path == config.transport_key_path
    {
        return Err(io_other(
            "mailbox database, row key, and transport identity must be separate files",
        ));
    }
    Ok(())
}

fn require_initialized(config: &MailboxServiceConfig) -> Result<()> {
    for (label, path) in [
        ("mailbox database", &config.database_path),
        ("mailbox row key", &config.key_path),
        ("mailbox transport identity", &config.transport_key_path),
    ] {
        let metadata = std::fs::symlink_metadata(path).map_err(TransportError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io_other(format!(
                "{label} must be a regular non-symlink file"
            )));
        }
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn io_other(message: impl std::fmt::Display) -> TransportError {
    TransportError::Io(io::Error::other(message.to_string()))
}
