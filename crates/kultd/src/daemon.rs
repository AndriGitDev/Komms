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
use kult_node::{FolderSelection, LabelMatchMode, Node, NodeError};
use kult_transport::{
    DeliveryHint, Discovery, Libp2pTransport, MailboxConfig, MeshtasticOptions,
    MeshtasticTransport, NatStatus, Transport, TransportOptions,
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
    /// First run only: restore the store from this encrypted backup file
    /// instead of creating a fresh identity (docs/07-storage.md §4).
    /// Refused when `db_path` already exists.
    pub restore_from: Option<PathBuf>,
    /// The 24-word mnemonic sealing `restore_from`.
    pub restore_mnemonic: Option<String>,
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
    /// Announce on, and discover peers from, the local network over mDNS.
    /// On by default: it is what makes LAN-only operation configuration-free
    /// (and it leaks nothing an internet listener doesn't — transport
    /// pseudonym and listen addresses, never the kult identity).
    pub mdns: bool,
    /// Also receive from a sneakernet spool directory.
    pub spool: Option<PathBuf>,
    /// Attach a Meshtastic radio on this USB-serial port (`/dev/ttyUSB0`,
    /// `/dev/ttyACM0`, …) as an off-grid carrier.
    pub meshtastic_serial: Option<String>,
    /// Attach a Meshtastic radio via its network API (`host:4403`).
    pub meshtastic_tcp: Option<String>,
    /// Bridge third-party sealed traffic between mesh and internet
    /// (docs/05-transports.md §4.2 rule 5, ADR-0009). Takes effect only
    /// when a Meshtastic radio is attached — a bridge needs both sides.
    /// On by default: a node with both carriers is exactly the "village
    /// with one Starlink terminal" the spec promises; `--no-bridge` opts
    /// out.
    pub bridge: bool,
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
            restore_from: None,
            restore_mnemonic: None,
            listen: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
                "/ip4/0.0.0.0/tcp/0".to_owned(),
            ],
            bootstrap: Vec::new(),
            relay: None,
            mailboxes: Vec::new(),
            serve_mailbox: false,
            mdns: true,
            spool: None,
            meshtastic_serial: None,
            meshtastic_tcp: None,
            bridge: true,
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
    /// Replace the bridge's internet-side deposit targets (sent by the
    /// lifecycle task once listen addresses are known, so a bridge serving
    /// its own mailbox can deposit mesh transit there locally).
    BridgeRelays(Vec<DeliveryHint>),
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
            tokio::task::spawn_blocking(move || -> Result<Node, DaemonError> {
                if let Some(backup_path) = &cfg.restore_from {
                    // Restore is a first-run operation: an existing store
                    // holds an identity, and silently replacing it would
                    // destroy keys. Refuse; the operator moves it aside.
                    if cfg.db_path.exists() {
                        return Err(DaemonError::Io(io::Error::other(format!(
                            "refusing to restore over the existing store {}",
                            cfg.db_path.display()
                        ))));
                    }
                    let mnemonic = cfg.restore_mnemonic.as_deref().ok_or_else(|| {
                        DaemonError::Io(io::Error::other("restore needs its mnemonic"))
                    })?;
                    let backup = std::fs::read(backup_path)?;
                    Ok(Node::restore(
                        &cfg.db_path,
                        &backup,
                        mnemonic,
                        &cfg.passphrase,
                        cfg.kdf,
                        &mut OsRng,
                    )?)
                } else if cfg.db_path.exists() {
                    Ok(Node::open(&cfg.db_path, &cfg.passphrase)?)
                } else {
                    Ok(Node::create(
                        &cfg.db_path,
                        &cfg.passphrase,
                        cfg.kdf,
                        &mut OsRng,
                    )?)
                }
            })
            .await
            .map_err(|e| DaemonError::Io(io::Error::other(e)))??
        };

        // Bridging needs both sides: it activates only when a radio is
        // configured (and startup fails hard if that radio is unreachable,
        // so "bridging" is never claimed without a mesh).
        let bridging =
            cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
        let listen: Vec<&str> = cfg.listen.iter().map(String::as_str).collect();
        let options = TransportOptions {
            mailbox: cfg.serve_mailbox.then(MailboxConfig::default),
            lan_discovery: cfg.mdns,
            bridge_deposits: bridging,
        };
        let net = Libp2pTransport::with_options(&listen, options)
            .await
            .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
        let net = Arc::new(net);
        node.add_transport(Arc::clone(&net) as Arc<dyn Transport>);
        node.add_discovery(Arc::clone(&net) as Arc<dyn Discovery>);
        if let Some(spool) = &cfg.spool {
            let sneaker = kult_transport::SneakernetTransport::new(spool)?;
            node.add_transport(Arc::new(sneaker));
        }
        // A radio that was asked for but cannot be reached is a hard startup
        // error, matching the spool: silently running without the configured
        // off-grid carrier would be a lie about coverage.
        if let Some(port) = &cfg.meshtastic_serial {
            let radio =
                MeshtasticTransport::connect_serial(port, None, MeshtasticOptions::default())
                    .await
                    .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
            eprintln!(
                "kultd: meshtastic radio on {port} is node {}",
                radio.node_num()
            );
            node.add_transport(Arc::new(radio));
        }
        if let Some(addr) = &cfg.meshtastic_tcp {
            let radio = MeshtasticTransport::connect_tcp(addr, MeshtasticOptions::default())
                .await
                .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
            eprintln!(
                "kultd: meshtastic radio at {addr} is node {}",
                radio.node_num()
            );
            node.add_transport(Arc::new(radio));
        }
        if bridging {
            // Mesh-heard transit is offered to the same relays this node
            // checks in with; once a listen address is bound, the lifecycle
            // task adds this node's own mailbox service to the set.
            node.set_bridge(Some(bridge_relays(&cfg, None)));
            eprintln!("kultd: bridging mesh↔internet (--no-bridge to opt out)");
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

/// Write a secret-bearing file: created 0600 from the first byte, and an
/// existing file is never overwritten (pick a new name or remove it first).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    open_private(path)?.write_all(bytes)
}

/// Create a caller-selected plaintext destination without ever clobbering an
/// existing file. Attachment exports stream directly into this handle.
fn open_private(path: &std::path::Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn open_preview(
    path: Option<String>,
    media_type: Option<String>,
) -> Result<Option<(kult_node::AttachmentMetadata, std::fs::File)>, String> {
    match (path, media_type) {
        (None, None) => Ok(None),
        (Some(path), Some(media_type)) => Ok(Some((
            kult_node::AttachmentMetadata {
                media_type,
                filename: None,
            },
            std::fs::File::open(path).map_err(|e| format!("attachment preview source: {e}"))?,
        ))),
        _ => Err("preview_path and preview_media_type must be supplied together".to_owned()),
    }
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

/// The internet-side deposit targets for mesh-heard transit (ADR-0009):
/// the configured mailbox relays, plus this node's own mailbox service
/// (as a relay hint on its own listen address) once one is bound.
fn bridge_relays(cfg: &DaemonConfig, own_addr: Option<&str>) -> Vec<DeliveryHint> {
    let mut relays: Vec<DeliveryHint> = cfg
        .mailboxes
        .iter()
        .cloned()
        .map(DeliveryHint::Relay)
        .collect();
    if cfg.serve_mailbox {
        if let Some(addr) = own_addr {
            relays.push(DeliveryHint::Relay(addr.to_owned()));
        }
    }
    relays
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
                Some(NodeMsg::BridgeRelays(relays)) => {
                    node.set_bridge(Some(relays));
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
                "lan_peers": net.lan_peers(),
                "nat": nat,
                "queued": node.queued().map_err(fail)?,
                "scheduled": node.scheduled_messages().map_err(fail)?.len(),
                "transit": node.transit_queued(),
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
        Op::AttachmentSend {
            peer,
            path,
            media_type,
            filename,
            preview_path,
            preview_media_type,
        } => {
            let peer = wire::parse_peer(&peer)?;
            let mut source =
                std::fs::File::open(&path).map_err(|e| format!("attachment source: {e}"))?;
            let metadata = kult_node::AttachmentMetadata {
                media_type,
                filename,
            };
            let mut preview = open_preview(preview_path, preview_media_type)?;
            let preview = preview
                .as_mut()
                .map(|(metadata, source)| (&*metadata, source));
            let id = node
                .send_attachment_with_preview(
                    &peer,
                    &metadata,
                    &mut source,
                    preview,
                    now(),
                    &mut OsRng,
                )
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupAttachmentSend {
            group,
            path,
            media_type,
            filename,
            preview_path,
            preview_media_type,
        } => {
            let group = wire::parse_group(&group)?;
            let mut source =
                std::fs::File::open(&path).map_err(|e| format!("attachment source: {e}"))?;
            let metadata = kult_node::AttachmentMetadata {
                media_type,
                filename,
            };
            let mut preview = open_preview(preview_path, preview_media_type)?;
            let preview = preview
                .as_mut()
                .map(|(metadata, source)| (&*metadata, source));
            let id = node
                .send_group_attachment_with_preview(
                    &group,
                    &metadata,
                    &mut source,
                    preview,
                    now(),
                    &mut OsRng,
                )
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::Attachments => Ok(json!({
            "attachments": node
                .attachments()
                .map_err(fail)?
                .iter()
                .map(wire::attachment_json)
                .collect::<Vec<_>>(),
        })),
        Op::AttachmentAccept { transfer } => {
            let transfer = wire::parse_transfer(&transfer)?;
            node.accept_attachment(&transfer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::AttachmentReject { transfer } => {
            let transfer = wire::parse_transfer(&transfer)?;
            node.reject_attachment(&transfer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::AttachmentCancel { transfer } => {
            let transfer = wire::parse_transfer(&transfer)?;
            node.cancel_attachment(&transfer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::AttachmentPause { transfer } => {
            let transfer = wire::parse_transfer(&transfer)?;
            node.pause_attachment(&transfer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::AttachmentResume { transfer } => {
            let transfer = wire::parse_transfer(&transfer)?;
            node.resume_attachment(&transfer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::AttachmentExport {
            transfer,
            path,
            preview,
        } => {
            let transfer = wire::parse_transfer(&transfer)?;
            let destination_path = std::path::Path::new(&path);
            let mut destination =
                open_private(destination_path).map_err(|e| format!("attachment export: {e}"))?;
            if let Err(error) = node.export_attachment_object(&transfer, preview, &mut destination)
            {
                drop(destination);
                let _ = std::fs::remove_file(destination_path);
                return Err(fail(error));
            }
            Ok(json!({ "path": path }))
        }
        Op::Schedule {
            peer,
            body,
            not_before,
        } => {
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .schedule_message(&peer, body.as_bytes(), not_before, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupSchedule {
            group,
            body,
            not_before,
        } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .schedule_group_message(&group, body.as_bytes(), not_before, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::ScheduledEdit {
            message,
            body,
            not_before,
        } => {
            let id = wire::parse_message(&message)?;
            node.edit_scheduled_message(&id, body.as_bytes(), not_before, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::ScheduledCancel { message } => {
            let id = wire::parse_message(&message)?;
            node.cancel_scheduled_message(&id).map_err(fail)?;
            Ok(json!({}))
        }
        Op::ScheduledMessages => Ok(json!({
            "messages": node
                .scheduled_messages()
                .map_err(fail)?
                .iter()
                .map(wire::scheduled_message_json)
                .collect::<Vec<_>>(),
        })),
        Op::NoteToSelfSend { body } => {
            let id = node
                .note_to_self_send(&body, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "conversation": kult_node::NOTE_TO_SELF_CONVERSATION_ID,
                "id": wire::hex_encode(&id),
            }))
        }
        Op::NoteToSelfMessages => {
            let messages = node
                .note_to_self_messages()
                .map_err(fail)?
                .iter()
                .map(wire::note_message_json)
                .collect::<Vec<_>>();
            Ok(json!({
                "conversation": kult_node::NOTE_TO_SELF_CONVERSATION_ID,
                "messages": messages,
            }))
        }
        Op::Theme => Ok(json!({
            "preference": node.theme_preference().map_err(fail)?.as_str(),
            "persisted": node.theme_preference_is_persisted().map_err(fail)?,
        })),
        Op::ThemeSet { preference } => {
            let preference = wire::parse_theme(&preference)?;
            let changed = node
                .set_theme_preference(preference, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "preference": preference.as_str(),
                "persisted": true,
                "changed": changed,
            }))
        }
        Op::CustomIcon { target } => {
            let target = wire::parse_custom_icon_target(&target)?;
            Ok(json!({
                "icon": node
                    .custom_icon(&target)
                    .map_err(fail)?
                    .as_ref()
                    .map(wire::custom_icon_json),
            }))
        }
        Op::CustomIconSetPath { target, path, crop } => {
            let target = wire::parse_custom_icon_target(&target)?;
            let crop = crop.map(|crop| kult_node::CustomIconCrop {
                x: crop.x,
                y: crop.y,
                width: crop.width,
                height: crop.height,
            });
            let icon = node
                .set_custom_icon_from_path(target, &PathBuf::from(path), crop, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::custom_icon_json(&icon))
        }
        Op::CustomIconSetBundled { target, glyph } => {
            let target = wire::parse_custom_icon_target(&target)?;
            let icon = node
                .set_bundled_custom_icon(target, &glyph, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::custom_icon_json(&icon))
        }
        Op::CustomIconClear { target } => {
            let target = wire::parse_custom_icon_target(&target)?;
            Ok(json!({
                "changed": node.clear_custom_icon(&target).map_err(fail)?,
                "target": wire::custom_icon_target_json(&target),
            }))
        }
        Op::CustomIconUsage => Ok(wire::custom_icon_usage_json(
            node.custom_icon_usage().map_err(fail)?,
        )),
        Op::FolderCreate { name } => {
            wire::validate_folder_write(&name)?;
            let folder = node.create_folder(&name, &mut OsRng).map_err(fail)?;
            Ok(wire::folder_json(&folder))
        }
        Op::Folders => Ok(json!({
            "folders": node
                .folders()
                .map_err(fail)?
                .iter()
                .map(wire::folder_json)
                .collect::<Vec<_>>(),
        })),
        Op::FolderGet { folder } => {
            let folder = wire::parse_folder(&folder)?;
            Ok(wire::folder_json(&node.folder(&folder).map_err(fail)?))
        }
        Op::FolderRename { folder, name } => {
            wire::validate_folder_write(&name)?;
            let folder = wire::parse_folder(&folder)?;
            let renamed = node
                .rename_folder(&folder, &name, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::folder_json(&renamed))
        }
        Op::FolderReorder { folders } => {
            let folders = wire::parse_folder_order(&folders)?;
            Ok(json!({
                "folders": node
                    .reorder_folders(&folders, &mut OsRng)
                    .map_err(fail)?
                    .iter()
                    .map(wire::folder_json)
                    .collect::<Vec<_>>(),
            }))
        }
        Op::FolderDeletePreview { folder } => {
            let folder = wire::parse_folder(&folder)?;
            let assignments = node.folder_delete_assignment_count(&folder).map_err(fail)?;
            Ok(json!({
                "id": wire::hex_encode(&folder),
                "assignments": assignments,
            }))
        }
        Op::FolderDelete { folder, confirm } => {
            if !confirm {
                return Err("folder deletion requires explicit confirmation".to_owned());
            }
            let folder = wire::parse_folder(&folder)?;
            let assignments = node.delete_folder(&folder).map_err(fail)?;
            Ok(json!({
                "id": wire::hex_encode(&folder),
                "assignments_deleted": assignments,
            }))
        }
        Op::FolderMove { folder, target } => {
            let folder = wire::parse_folder(&folder)?;
            let target = wire::parse_label_target(&target)?;
            let changed = node
                .move_conversation_to_folder(&target, &folder, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "folder": wire::hex_encode(&folder),
                "target": wire::label_target_json(&target),
            }))
        }
        Op::FolderUnfile { target } => {
            let target = wire::parse_label_target(&target)?;
            let changed = node.unfile_conversation(&target).map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "target": wire::label_target_json(&target),
            }))
        }
        Op::FolderMembership { folder } => {
            let folder = wire::parse_folder(&folder)?;
            let members = node.folder_members(&folder).map_err(fail)?;
            Ok(json!({
                "folder": wire::hex_encode(&folder),
                "members": members.iter().map(wire::folder_conversation_json).collect::<Vec<_>>(),
            }))
        }
        Op::ConversationFolder { target } => {
            let target = wire::parse_label_target(&target)?;
            let folder = node.folder_for_conversation(&target).map_err(fail)?;
            Ok(json!({
                "target": wire::label_target_json(&target),
                "folder": folder.as_ref().map(wire::folder_json),
            }))
        }
        Op::FolderConversations {
            selection,
            labels,
            mode,
        } => {
            let selection = wire::parse_folder_selection(&selection)?;
            let labels = wire::parse_selected_labels(&labels)?;
            let listed = node
                .folder_conversations(
                    match selection {
                        FolderSelection::All => FolderSelection::All,
                        FolderSelection::Unfiled => FolderSelection::Unfiled,
                        FolderSelection::Folder(folder) => FolderSelection::Folder(folder),
                    },
                    &labels,
                    match mode {
                        wire::LabelMatchInput::Any => LabelMatchMode::Any,
                        wire::LabelMatchInput::All => LabelMatchMode::All,
                    },
                )
                .map_err(fail)?;
            Ok(wire::folder_conversation_list_json(&listed))
        }
        Op::FolderStale => Ok(json!({
            "stale": node
                .stale_folder_assignments()
                .map_err(fail)?
                .iter()
                .map(wire::stale_folder_json)
                .collect::<Vec<_>>(),
        })),
        Op::FolderStaleCleanup { folder, target } => {
            let folder = wire::parse_folder(&folder)?;
            let target = wire::parse_label_target(&target)?;
            let changed = node
                .cleanup_stale_folder_assignment(&folder, &target)
                .map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "folder": wire::hex_encode(&folder),
                "target": wire::label_target_json(&target),
            }))
        }
        Op::LabelCreate { name, color } => {
            wire::validate_label_write(&name, &color)?;
            let label = node.create_label(&name, &color, &mut OsRng).map_err(fail)?;
            Ok(wire::label_json(&label))
        }
        Op::Labels => Ok(json!({
            "labels": node
                .labels()
                .map_err(fail)?
                .iter()
                .map(wire::label_json)
                .collect::<Vec<_>>(),
        })),
        Op::LabelGet { label } => {
            let label = wire::parse_label(&label)?;
            Ok(wire::label_json(&node.label(&label).map_err(fail)?))
        }
        Op::LabelUpdate { label, name, color } => {
            wire::validate_label_write(&name, &color)?;
            let label = wire::parse_label(&label)?;
            let updated = node
                .update_label(&label, &name, &color, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::label_json(&updated))
        }
        Op::LabelDeletePreview { label } => {
            let label = wire::parse_label(&label)?;
            let assignments = node.label_delete_assignment_count(&label).map_err(fail)?;
            Ok(json!({
                "id": wire::hex_encode(&label),
                "assignments": assignments,
            }))
        }
        Op::LabelDelete { label, confirm } => {
            if !confirm {
                return Err("label deletion requires explicit confirmation".to_owned());
            }
            let label = wire::parse_label(&label)?;
            let assignments = node.delete_label(&label).map_err(fail)?;
            Ok(json!({
                "id": wire::hex_encode(&label),
                "assignments_deleted": assignments,
            }))
        }
        Op::LabelAssign { label, target } => {
            let label = wire::parse_label(&label)?;
            let target = wire::parse_label_target(&target)?;
            let changed = node
                .assign_label(&label, &target, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "label": wire::hex_encode(&label),
                "target": wire::label_target_json(&target),
            }))
        }
        Op::LabelUnassign { label, target } => {
            let label = wire::parse_label(&label)?;
            let target = wire::parse_label_target(&target)?;
            let changed = node.unassign_label(&label, &target).map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "label": wire::hex_encode(&label),
                "target": wire::label_target_json(&target),
            }))
        }
        Op::LabelMembership { label } => {
            let label = wire::parse_label(&label)?;
            let members = node.label_members(&label).map_err(fail)?;
            Ok(json!({
                "label": wire::hex_encode(&label),
                "members": members.iter().map(wire::label_conversation_json).collect::<Vec<_>>(),
            }))
        }
        Op::LabelsForConversation { target } => {
            let target = wire::parse_label_target(&target)?;
            let labels = node.labels_for_conversation(&target).map_err(fail)?;
            Ok(json!({
                "target": wire::label_target_json(&target),
                "labels": labels.iter().map(wire::label_json).collect::<Vec<_>>(),
            }))
        }
        Op::LabelStale => Ok(json!({
            "stale": node
                .stale_label_assignments()
                .map_err(fail)?
                .iter()
                .map(wire::stale_label_json)
                .collect::<Vec<_>>(),
        })),
        Op::LabelStaleCleanup { label, target } => {
            let label = wire::parse_label(&label)?;
            let target = wire::parse_label_target(&target)?;
            let changed = node
                .cleanup_stale_label_assignment(&label, &target)
                .map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "label": wire::hex_encode(&label),
                "target": wire::label_target_json(&target),
            }))
        }
        Op::LabelFilter { labels, mode } => {
            let labels = wire::parse_selected_labels(&labels)?;
            let filtered = node
                .filter_label_conversations(
                    &labels,
                    match mode {
                        wire::LabelMatchInput::Any => LabelMatchMode::Any,
                        wire::LabelMatchInput::All => LabelMatchMode::All,
                    },
                )
                .map_err(fail)?;
            Ok(wire::label_filter_json(&filtered))
        }
        Op::Pin { target } => {
            let target = wire::parse_label_target(&target)?;
            let changed = node.pin_conversation(&target, &mut OsRng).map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "target": wire::label_target_json(&target),
                "pin": node.pin_state(&target).map_err(fail)?.as_ref().map(wire::pin_json),
            }))
        }
        Op::Unpin { target } => {
            let target = wire::parse_label_target(&target)?;
            let changed = node.unpin_conversation(&target).map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "target": wire::label_target_json(&target),
            }))
        }
        Op::PinState { target } => {
            let target = wire::parse_label_target(&target)?;
            Ok(json!({
                "target": wire::label_target_json(&target),
                "pin": node.pin_state(&target).map_err(fail)?.as_ref().map(wire::pin_json),
            }))
        }
        Op::Pins => Ok(json!({
            "pins": node
                .pins()
                .map_err(fail)?
                .iter()
                .map(wire::pin_json)
                .collect::<Vec<_>>(),
        })),
        Op::PinReorder { targets } => {
            let targets = wire::parse_pin_order(&targets)?;
            Ok(json!({
                "pins": node
                    .reorder_pins(&targets, &mut OsRng)
                    .map_err(fail)?
                    .iter()
                    .map(wire::pin_json)
                    .collect::<Vec<_>>(),
            }))
        }
        Op::PinStale => Ok(json!({
            "stale": node
                .stale_pins()
                .map_err(fail)?
                .iter()
                .map(wire::pin_json)
                .collect::<Vec<_>>(),
        })),
        Op::PinStaleCleanup { target } => {
            let target = wire::parse_label_target(&target)?;
            let changed = node.cleanup_stale_pin(&target).map_err(fail)?;
            Ok(json!({
                "changed": changed,
                "target": wire::label_target_json(&target),
            }))
        }
        Op::PinConversations {
            selection,
            labels,
            mode,
        } => {
            let selection = wire::parse_folder_selection(&selection)?;
            let labels = wire::parse_selected_labels(&labels)?;
            let listed = node
                .pin_conversations(
                    selection,
                    &labels,
                    match mode {
                        wire::LabelMatchInput::Any => LabelMatchMode::Any,
                        wire::LabelMatchInput::All => LabelMatchMode::All,
                    },
                )
                .map_err(fail)?;
            Ok(wire::pin_conversation_list_json(&listed))
        }
        Op::GroupCreate { name, members } => {
            let members = members
                .iter()
                .map(|peer| wire::parse_peer(peer))
                .collect::<Result<Vec<_>, _>>()?;
            let group = node
                .create_group(&name, &members, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "group": wire::hex_encode(&group) }))
        }
        Op::GroupSend { group, body } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_send(&group, body.as_bytes(), now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupMentionCapability { group } => {
            let group = wire::parse_group(&group)?;
            let capability = node.group_mention_capability(&group).map_err(fail)?;
            Ok(wire::group_mention_capability_json(&capability))
        }
        Op::GroupMentionSend {
            group,
            text,
            spans,
            review_token,
        } => {
            let group = wire::parse_group(&group)?;
            let review_token = wire::parse_review_token(&review_token)?;
            let spans = spans
                .iter()
                .map(|span| {
                    Ok(kult_node::MentionSpan {
                        start: span.start,
                        end: span.end,
                        target: wire::parse_peer(&span.target)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let id = node
                .group_send_mention(&group, &text, &spans, review_token, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupAdd { group, peer } => {
            let group = wire::parse_group(&group)?;
            let peer = wire::parse_peer(&peer)?;
            node.group_add(&group, &peer, &mut OsRng).map_err(fail)?;
            Ok(json!({}))
        }
        Op::GroupRemove { group, peer } => {
            let group = wire::parse_group(&group)?;
            let peer = wire::parse_peer(&peer)?;
            node.group_remove(&group, &peer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::GroupLeave { group } => {
            let group = wire::parse_group(&group)?;
            node.group_leave(&group, now(), &mut OsRng).map_err(fail)?;
            Ok(json!({}))
        }
        Op::Groups => {
            let groups = node
                .groups()
                .map_err(fail)?
                .iter()
                .map(wire::group_json)
                .collect::<Vec<_>>();
            Ok(json!({ "groups": groups }))
        }
        Op::GroupMessages { group } => {
            let group = wire::parse_group(&group)?;
            let messages = node
                .group_messages(&group)
                .map_err(fail)?
                .iter()
                .map(wire::group_message_json)
                .collect::<Vec<_>>();
            Ok(json!({ "messages": messages }))
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
        Op::CarrierCapabilities => {
            let snapshots = node
                .carrier_capabilities(now())
                .map_err(fail)?
                .iter()
                .map(wire::carrier_json)
                .collect::<Vec<_>>();
            Ok(json!({ "capabilities": snapshots }))
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
        Op::Backup { path } => {
            let (file, mnemonic) = node.export_backup(now(), &mut OsRng).map_err(fail)?;
            write_private(std::path::Path::new(&path), &file)
                .map_err(|e| format!("backup write: {e}"))?;
            Ok(json!({ "path": path, "mnemonic": &*mnemonic }))
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
    let bridging = cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
    if bridging && cfg.serve_mailbox {
        // Now that an address is bound, mesh-heard transit can also be
        // deposited into this node's own mailbox service (resolved locally
        // by the transport — no self-dial).
        if let Some(addr) = net.listen_addrs().into_iter().next() {
            let relays = bridge_relays(&cfg, Some(&addr));
            let _ = node_tx.send(NodeMsg::BridgeRelays(relays)).await;
        }
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
                match wire::parse_request(&line) {
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
