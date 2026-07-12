//! The daemon: one [`Node`] running over the internet carrier, driven by a
//! tick loop, exposed as local RPC on a Unix socket.
//!
//! Structure — the node lives in a single **actor task** (it is deliberately
//! not shared): RPC connections and background lifecycle tasks talk to it
//! over a channel. Around it:
//!
//! - **Tick loop**: one receive/flush cycle per interval; resulting events
//!   fan out to every subscribed RPC connection.
//! - **Lifecycle task**: waits for listen addresses, joins the DHT via the
//!   configured bootstrap peers, publishes the prekey bundle, probes NAT and
//!   reserves a relay circuit when private (republished as a new hint), and
//!   checks in with configured mailbox relays on an interval.
//! - **RPC server**: newline-delimited JSON on a mode-0600 Unix socket
//!   (see [`crate::wire`]).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::rngs::OsRng;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use kult_crypto::KdfProfile;
use kult_node::{Node, NodeError};
use kult_transport::{
    DeliveryHint, Discovery, Libp2pTransport, MailboxConfig, NatStatus, Transport,
};

use crate::wire::{self, Hint, Op, Request};

/// Everything the daemon needs to run. Built by the CLI in `bin/kultd.rs`,
/// or directly by tests.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// The encrypted store (created on first run).
    pub db_path: PathBuf,
    /// The RPC socket path (stale files are replaced).
    pub socket_path: PathBuf,
    /// Store passphrase.
    pub passphrase: Vec<u8>,
    /// Argon2id cost profile for store creation.
    pub kdf: KdfProfile,
    /// Multiaddrs to listen on.
    pub listen: Vec<String>,
    /// DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
    /// discovery then never leaves this node, exactly like M2.
    pub bootstrap: Vec<String>,
    /// Relay to reserve a circuit at when NAT-ed. Defaults to the first
    /// bootstrap peer when unset.
    pub relay: Option<String>,
    /// Mailbox relays to check in with (register accept-filters, collect).
    /// These are also published as `Relay` hints in our prekey bundle.
    pub mailboxes: Vec<String>,
    /// Volunteer bounded mailbox service for others.
    pub serve_mailbox: bool,
    /// Also receive from a sneakernet spool directory.
    pub spool: Option<PathBuf>,
    /// Delivery-engine heartbeat.
    pub tick_interval: Duration,
    /// Mailbox check-in cadence.
    pub checkin_interval: Duration,
    /// NAT probe cadence (until a circuit is reserved).
    pub nat_interval: Duration,
}

impl DaemonConfig {
    /// Sensible defaults rooted in a data directory: QUIC + TCP on
    /// OS-assigned ports, desktop KDF profile, no bootstrap peers.
    pub fn new(data_dir: &std::path::Path, passphrase: Vec<u8>) -> Self {
        Self {
            db_path: data_dir.join("node.db"),
            socket_path: data_dir.join("kultd.sock"),
            passphrase,
            kdf: kult_crypto::KDF_PROFILE_DESKTOP,
            listen: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
                "/ip4/0.0.0.0/tcp/0".to_owned(),
            ],
            bootstrap: Vec::new(),
            relay: None,
            mailboxes: Vec::new(),
            serve_mailbox: false,
            spool: None,
            tick_interval: Duration::from_millis(500),
            checkin_interval: Duration::from_secs(300),
            nat_interval: Duration::from_secs(30),
        }
    }
}

/// Daemon startup failures.
#[derive(Debug)]
pub enum DaemonError {
    /// Node open/create failed (wrong passphrase, corrupt store, …).
    Node(NodeError),
    /// Socket or spool I/O failed.
    Io(io::Error),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node(e) => write!(f, "node: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<NodeError> for DaemonError {
    fn from(e: NodeError) -> Self {
        Self::Node(e)
    }
}
impl From<io::Error> for DaemonError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// What the actor task is asked to do.
enum NodeMsg {
    /// An RPC operation, answered with a JSON value or an error string.
    Op {
        op: Op,
        resp: oneshot::Sender<Result<Value, String>>,
    },
    /// The current mailbox accept-filter token set.
    Tokens {
        resp: oneshot::Sender<Vec<[u8; 32]>>,
    },
    /// Publish the prekey bundle with the current hints (best-effort).
    Publish,
}

/// A running daemon. Dropping it does **not** stop the tasks — call
/// [`Daemon::shutdown`].
pub struct Daemon {
    /// This node's human-shareable kult address.
    pub address: String,
    /// This node's peer id (Ed25519 identity key bytes).
    pub peer: [u8; 32],
    /// The RPC socket path.
    pub socket_path: PathBuf,
    /// The internet transport (exposed for tests and status).
    pub net: Arc<Libp2pTransport>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Daemon {
    /// Open (or create) the node and start all daemon tasks.
    pub async fn start(cfg: DaemonConfig) -> Result<Self, DaemonError> {
        // Argon2id is deliberately slow — keep it off the async threads.
        let mut node = {
            let cfg = cfg.clone();
            tokio::task::spawn_blocking(move || -> Result<Node, NodeError> {
                if cfg.db_path.exists() {
                    Node::open(&cfg.db_path, &cfg.passphrase)
                } else {
                    Node::create(&cfg.db_path, &cfg.passphrase, cfg.kdf, &mut OsRng)
                }
            })
            .await
            .map_err(|e| DaemonError::Io(io::Error::other(e)))??
        };

        let listen: Vec<&str> = cfg.listen.iter().map(String::as_str).collect();
        let net = if cfg.serve_mailbox {
            Libp2pTransport::with_mailbox(&listen, MailboxConfig::default()).await
        } else {
            Libp2pTransport::new(&listen).await
        }
        .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
        let net = Arc::new(net);
        node.add_transport(Arc::clone(&net) as Arc<dyn Transport>);
        node.add_discovery(Arc::clone(&net) as Arc<dyn Discovery>);
        if let Some(spool) = &cfg.spool {
            let sneaker = kult_transport::SneakernetTransport::new(spool)?;
            node.add_transport(Arc::new(sneaker));
        }

        let address = node.address();
        let peer = node.peer_id();

        let (shutdown, _) = watch::channel(false);
        let (node_tx, node_rx) = mpsc::channel::<NodeMsg>(64);
        let (events_tx, _) = broadcast::channel::<String>(256);

        // Replace a stale socket from an unclean shutdown; a live daemon on
        // the same path would have to be stopped first anyway.
        let _ = std::fs::remove_file(&cfg.socket_path);
        let listener = UnixListener::bind(&cfg.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        let mut tasks = Vec::new();
        // The node's store is single-threaded by design (one SQLite
        // connection), so its futures are not `Send`: the actor gets its own
        // current-thread runtime on a blocking thread instead of the shared
        // pool. Channels bridge the two runtimes safely.
        let actor_inputs = (
            cfg.clone(),
            Arc::clone(&net),
            events_tx.clone(),
            shutdown.subscribe(),
        );
        tasks.push(tokio::task::spawn_blocking(move || {
            let (cfg, net, events, shutdown) = actor_inputs;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("actor runtime");
            rt.block_on(actor(node, cfg, net, node_rx, events, shutdown));
        }));
        tasks.push(tokio::spawn(lifecycle(
            cfg.clone(),
            Arc::clone(&net),
            node_tx.clone(),
            shutdown.subscribe(),
        )));
        tasks.push(tokio::spawn(serve(
            listener,
            node_tx,
            events_tx,
            shutdown.subscribe(),
        )));

        Ok(Self {
            address,
            peer,
            socket_path: cfg.socket_path,
            net,
            shutdown,
            tasks,
        })
    }

    /// Stop every task and remove the socket.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The hints this node publishes: every live listen address (circuit
/// addresses included once reserved) plus each mailbox relay it collects
/// from.
fn own_hints(net: &Libp2pTransport, mailboxes: &[String]) -> Vec<DeliveryHint> {
    let mut hints: Vec<DeliveryHint> = net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    hints.extend(mailboxes.iter().cloned().map(DeliveryHint::Relay));
    hints
}

/// The actor task: sole owner of the [`Node`]. Alternates between serving
/// channel messages and the delivery-engine heartbeat.
async fn actor(
    mut node: Node,
    cfg: DaemonConfig,
    net: Arc<Libp2pTransport>,
    mut rx: mpsc::Receiver<NodeMsg>,
    events: broadcast::Sender<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(cfg.tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                match node.tick(now(), &mut OsRng).await {
                    Ok(batch) => {
                        for event in &batch {
                            let _ = events.send(wire::event_line(event));
                        }
                    }
                    Err(e) => eprintln!("kultd: tick failed: {e}"),
                }
            }
            msg = rx.recv() => match msg {
                None => break,
                Some(NodeMsg::Tokens { resp }) => {
                    let _ = resp.send(node.mailbox_tokens(now()));
                }
                Some(NodeMsg::Publish) => {
                    let hints = own_hints(&net, &cfg.mailboxes);
                    if let Err(e) = node.publish_bundle(&hints, now()).await {
                        eprintln!("kultd: bundle publish failed: {e}");
                    }
                }
                Some(NodeMsg::Op { op, resp }) => {
                    let result = handle_op(&mut node, &cfg, &net, op).await;
                    let _ = resp.send(result);
                }
            },
        }
    }
}

/// Execute one RPC operation against the node.
async fn handle_op(
    node: &mut Node,
    cfg: &DaemonConfig,
    net: &Libp2pTransport,
    op: Op,
) -> Result<Value, String> {
    let fail = |e: NodeError| e.to_string();
    match op {
        Op::Status => {
            let nat = match net.nat_status().await {
                Ok(NatStatus::Public) => "public",
                Ok(NatStatus::Private) => "private",
                _ => "unknown",
            };
            Ok(json!({
                "address": node.address(),
                "peer": wire::hex_encode(&node.peer_id()),
                "listen": net.listen_addrs(),
                "nat": nat,
                "queued": node.queued().map_err(fail)?,
                "contacts": node.contacts().map_err(fail)?.len(),
            }))
        }
        Op::Bundle => {
            let bundle = node.handshake_bundle(now(), &mut OsRng).map_err(fail)?;
            Ok(json!({ "bundle": wire::hex_encode(&bundle) }))
        }
        Op::AddContact {
            name,
            bundle,
            hints,
        } => {
            let bundle = wire::hex_decode(&bundle).ok_or("bundle must be hex")?;
            let hints: Vec<DeliveryHint> = hints.iter().map(Hint::to_delivery).collect();
            let peer = node
                .add_contact(&name, &bundle, &hints, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "peer": wire::hex_encode(&peer) }))
        }
        Op::AddByAddress { name, address } => {
            let peer = node
                .add_contact_by_address(&name, &address, now(), &mut OsRng)
                .await
                .map_err(fail)?;
            Ok(json!({ "peer": wire::hex_encode(&peer) }))
        }
        Op::Send { peer, body } => {
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .send_message(&peer, body.as_bytes(), now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::Contacts => {
            let contacts: Vec<Value> = node
                .contacts()
                .map_err(fail)?
                .iter()
                .map(|c| {
                    json!({
                        "peer": wire::hex_encode(&c.peer),
                        "name": c.name,
                        "verified": c.verified,
                    })
                })
                .collect();
            Ok(json!({ "contacts": contacts }))
        }
        Op::Messages { peer } => {
            let peer = wire::parse_peer(&peer)?;
            let messages: Vec<Value> = node
                .messages_with(&peer)
                .map_err(fail)?
                .iter()
                .map(wire::message_json)
                .collect();
            Ok(json!({ "messages": messages }))
        }
        Op::SafetyNumber { peer } => {
            let peer = wire::parse_peer(&peer)?;
            let sn = node.safety_number_with(&peer).map_err(fail)?;
            Ok(json!({ "digits": sn.digits, "groups": sn.display_groups() }))
        }
        Op::Verify { peer } => {
            let peer = wire::parse_peer(&peer)?;
            node.mark_verified(&peer, &mut OsRng).map_err(fail)?;
            Ok(json!({}))
        }
        Op::SetHints { peer, hints } => {
            let peer = wire::parse_peer(&peer)?;
            let hints: Vec<DeliveryHint> = hints.iter().map(Hint::to_delivery).collect();
            node.set_hints(&peer, &hints, &mut OsRng).map_err(fail)?;
            Ok(json!({}))
        }
        Op::Publish => {
            let hints = own_hints(net, &cfg.mailboxes);
            node.publish_bundle(&hints, now()).await.map_err(fail)?;
            Ok(json!({}))
        }
        // Handled at the connection layer; reaching the actor is a bug.
        Op::Subscribe => Err("subscribe is connection-level".to_owned()),
    }
}

/// Background lifecycle: bootstrap, publish, NAT probing + relay
/// reservation, mailbox check-ins. Everything here is best-effort and
/// retried on its interval — the daemon works without connectivity and
/// picks these up when it appears.
async fn lifecycle(
    cfg: DaemonConfig,
    net: Arc<Libp2pTransport>,
    node_tx: mpsc::Sender<NodeMsg>,
    mut shutdown: watch::Receiver<bool>,
) {
    if net.wait_listen_addr().await.is_err() {
        eprintln!("kultd: no listen address bound");
    }
    if !cfg.bootstrap.is_empty() {
        let peers: Vec<&str> = cfg.bootstrap.iter().map(String::as_str).collect();
        if let Err(e) = net.bootstrap(&peers).await {
            eprintln!("kultd: DHT bootstrap failed: {e}");
        }
        // Publish once the DHT has peers (a lone node has nowhere to put
        // records; contacts then come from out-of-band bundles instead).
        let _ = node_tx.send(NodeMsg::Publish).await;
    }

    let relay_candidate = cfg.relay.clone().or_else(|| cfg.bootstrap.first().cloned());
    let mut circuit_reserved = false;
    let mut nat_tick = tokio::time::interval(cfg.nat_interval);
    let mut checkin_tick = tokio::time::interval(cfg.checkin_interval);

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = nat_tick.tick() => {
                if circuit_reserved {
                    continue;
                }
                let Some(relay) = &relay_candidate else { continue };
                if let Ok(NatStatus::Private) = net.nat_status().await {
                    match net.reserve_relay(relay).await {
                        Ok(circuit) => {
                            eprintln!("kultd: NAT-ed; reserved relay circuit {circuit}");
                            circuit_reserved = true;
                            // The circuit is a new listen address — republish.
                            let _ = node_tx.send(NodeMsg::Publish).await;
                        }
                        Err(e) => eprintln!("kultd: relay reservation failed: {e}"),
                    }
                }
            }
            _ = checkin_tick.tick() => {
                if cfg.mailboxes.is_empty() {
                    continue;
                }
                let (resp, rx) = oneshot::channel();
                if node_tx.send(NodeMsg::Tokens { resp }).await.is_err() {
                    break;
                }
                let Ok(tokens) = rx.await else { break };
                for mailbox in &cfg.mailboxes {
                    // Drain the backlog: a check-in returns at most one
                    // batch; repeat until empty.
                    loop {
                        match net.mailbox_checkin(mailbox, &tokens).await {
                            Ok(0) => break,
                            Ok(_) => continue,
                            Err(e) => {
                                eprintln!("kultd: mailbox check-in at {mailbox} failed: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Accept loop for the RPC socket.
async fn serve(
    listener: UnixListener,
    node_tx: mpsc::Sender<NodeMsg>,
    events: broadcast::Sender<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                tokio::spawn(connection(
                    stream,
                    node_tx.clone(),
                    events.clone(),
                    shutdown.clone(),
                ));
            }
        }
    }
}

/// One RPC connection: serve request lines; after `subscribe`, interleave
/// event lines.
async fn connection(
    stream: UnixStream,
    node_tx: mpsc::Sender<NodeMsg>,
    events: broadcast::Sender<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut subscription: Option<broadcast::Receiver<String>> = None;

    loop {
        let reply = tokio::select! {
            _ = shutdown.changed() => break,
            event = recv_event(&mut subscription) => match event {
                Some(line) => line,
                None => continue, // lagged; skip
            },
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Request>(&line) {
                    Err(e) => wire::err(0, &format!("bad request: {e}")),
                    Ok(Request { id, op: Op::Subscribe }) => {
                        subscription = Some(events.subscribe());
                        wire::ok(id, json!({ "subscribed": true }))
                    }
                    Ok(Request { id, op }) => {
                        let (resp, rx) = oneshot::channel();
                        if node_tx.send(NodeMsg::Op { op, resp }).await.is_err() {
                            break;
                        }
                        match rx.await {
                            Ok(Ok(value)) => wire::ok(id, value),
                            Ok(Err(message)) => wire::err(id, &message),
                            Err(_) => break,
                        }
                    }
                }
            }
        };
        if writer
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .is_err()
        {
            break;
        }
    }
}

/// Await the next event line on an optional subscription; pends forever
/// while unsubscribed (so the select arm never fires). `None` marks a
/// lagged/skipped slot, never end-of-stream.
async fn recv_event(subscription: &mut Option<broadcast::Receiver<String>>) -> Option<String> {
    match subscription {
        Some(rx) => match rx.recv().await {
            Ok(line) => Some(line),
            Err(broadcast::error::RecvError::Lagged(_)) => None,
            Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}
