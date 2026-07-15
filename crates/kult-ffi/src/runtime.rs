//! The embedded runtime behind the FFI surface: one [`Node`] owned by an
//! actor task, a delivery-engine tick loop, and the same connectivity
//! lifecycle `kultd` runs (DHT bootstrap + bundle publication, NAT probing
//! with relay reservation, mailbox check-ins) — composed in-process, with
//! events handed to the application's listener instead of a socket
//! (ADR-0010).
//!
//! This module composes what the lower layers already provide and adds no
//! protocol behavior (docs/03-architecture.md §2). It deliberately mirrors
//! `kultd`'s daemon structure — the two are the same runtime with different
//! front doors, and a change to one almost always belongs in the other.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::rngs::OsRng;
use tokio::sync::{mpsc, oneshot, watch};

use kult_crypto::{KdfProfile, SafetyNumber};
use kult_node::{
    AttachmentInfo, AttachmentMetadata, CarrierCapabilitySnapshot, Event, GroupInfo,
    GroupMentionCapability, LabelConversationInfo, LabelFilterInfo, LabelInfo, LabelMatchMode,
    MentionSpan, Node, ScheduledMessageInfo, StaleLabelInfo,
};
use kult_store::{
    ContactRecord, ConversationId, GroupMessageRecord, MessageRecord, NoteMessageRecord,
};
use kult_transport::{
    DeliveryHint, Discovery, Libp2pTransport, MailboxConfig, Transport, TransportOptions,
};

/// A backup to restore from on first start (docs/07-storage.md §4).
#[derive(Clone)]
pub(crate) struct RestoreSource {
    /// The encrypted backup file's bytes.
    pub backup: Vec<u8>,
    /// The 24-word mnemonic sealing it.
    pub mnemonic: String,
}

/// Everything the runtime needs, already validated and converted from the
/// FFI-facing [`crate::Config`].
#[derive(Clone)]
pub(crate) struct RuntimeConfig {
    pub db_path: PathBuf,
    pub passphrase: Vec<u8>,
    pub kdf: KdfProfile,
    /// Restore the store from a backup instead of creating a fresh
    /// identity. Refused when the store already exists.
    pub restore: Option<RestoreSource>,
    pub listen: Vec<String>,
    pub bootstrap: Vec<String>,
    pub relay: Option<String>,
    pub mailboxes: Vec<String>,
    pub serve_mailbox: bool,
    pub mdns: bool,
    pub spool: Option<PathBuf>,
    pub meshtastic_serial: Option<String>,
    pub meshtastic_tcp: Option<String>,
    pub bridge: bool,
    pub tick_interval: Duration,
    pub checkin_interval: Duration,
    pub nat_interval: Duration,
}

/// One typed reply channel. Errors are the node's own messages, verbatim —
/// nothing is downgraded to a fake success (implementation guide rule 4).
type Resp<T> = oneshot::Sender<Result<T, String>>;

/// What the actor task is asked to do. One variant per node operation the
/// FFI exposes — the typed equivalent of `kultd`'s wire ops.
pub(crate) enum Msg {
    HandshakeBundle {
        resp: Resp<Vec<u8>>,
    },
    AddContact {
        name: String,
        bundle: Vec<u8>,
        hints: Vec<DeliveryHint>,
        resp: Resp<[u8; 32]>,
    },
    AddByAddress {
        name: String,
        address: String,
        resp: Resp<[u8; 32]>,
    },
    Send {
        peer: [u8; 32],
        body: Vec<u8>,
        resp: Resp<[u8; 16]>,
    },
    AttachmentSend {
        peer: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        resp: Resp<[u8; 16]>,
    },
    GroupAttachmentSend {
        group: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        resp: Resp<[u8; 16]>,
    },
    Attachments {
        resp: Resp<Vec<AttachmentInfo>>,
    },
    AttachmentAccept {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentReject {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentCancel {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentPause {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentResume {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentExport {
        transfer: [u8; 16],
        path: PathBuf,
        preview: bool,
        resp: Resp<()>,
    },
    Schedule {
        peer: [u8; 32],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<[u8; 16]>,
    },
    GroupSchedule {
        group: [u8; 32],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<[u8; 16]>,
    },
    ScheduledEdit {
        id: [u8; 16],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<()>,
    },
    ScheduledCancel {
        id: [u8; 16],
        resp: Resp<()>,
    },
    ScheduledMessages {
        resp: Resp<Vec<ScheduledMessageInfo>>,
    },
    NoteToSelfSend {
        body: String,
        resp: Resp<[u8; 16]>,
    },
    NoteToSelfMessages {
        resp: Resp<Vec<NoteMessageRecord>>,
    },
    LabelCreate {
        name: String,
        color: String,
        resp: Resp<LabelInfo>,
    },
    Labels {
        resp: Resp<Vec<LabelInfo>>,
    },
    LabelGet {
        label: [u8; 16],
        resp: Resp<LabelInfo>,
    },
    LabelUpdate {
        label: [u8; 16],
        name: String,
        color: String,
        resp: Resp<LabelInfo>,
    },
    LabelDeletePreview {
        label: [u8; 16],
        resp: Resp<usize>,
    },
    LabelDelete {
        label: [u8; 16],
        resp: Resp<usize>,
    },
    LabelAssign {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelUnassign {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelMembership {
        label: [u8; 16],
        resp: Resp<Vec<LabelConversationInfo>>,
    },
    LabelsForConversation {
        target: ConversationId,
        resp: Resp<Vec<LabelInfo>>,
    },
    LabelStale {
        resp: Resp<Vec<StaleLabelInfo>>,
    },
    LabelStaleCleanup {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelFilter {
        labels: Vec<[u8; 16]>,
        mode: LabelMatchMode,
        resp: Resp<LabelFilterInfo>,
    },
    GroupCreate {
        name: String,
        members: Vec<[u8; 32]>,
        resp: Resp<[u8; 32]>,
    },
    GroupSend {
        group: [u8; 32],
        body: Vec<u8>,
        resp: Resp<[u8; 16]>,
    },
    GroupMentionCapability {
        group: [u8; 32],
        resp: Resp<GroupMentionCapability>,
    },
    GroupMentionSend {
        group: [u8; 32],
        text: String,
        spans: Vec<MentionSpan>,
        review_token: [u8; 16],
        resp: Resp<[u8; 16]>,
    },
    GroupAdd {
        group: [u8; 32],
        peer: [u8; 32],
        resp: Resp<()>,
    },
    GroupRemove {
        group: [u8; 32],
        peer: [u8; 32],
        resp: Resp<()>,
    },
    GroupLeave {
        group: [u8; 32],
        resp: Resp<()>,
    },
    Groups {
        resp: Resp<Vec<GroupInfo>>,
    },
    GroupMessages {
        group: [u8; 32],
        resp: Resp<Vec<GroupMessageRecord>>,
    },
    Contacts {
        resp: Resp<Vec<ContactRecord>>,
    },
    CarrierCapabilities {
        resp: Resp<Vec<CarrierCapabilitySnapshot>>,
    },
    Messages {
        peer: [u8; 32],
        resp: Resp<Vec<MessageRecord>>,
    },
    SafetyNumber {
        peer: [u8; 32],
        resp: Resp<SafetyNumber>,
    },
    MarkVerified {
        peer: [u8; 32],
        resp: Resp<()>,
    },
    SetHints {
        peer: [u8; 32],
        hints: Vec<DeliveryHint>,
        resp: Resp<()>,
    },
    Publish {
        resp: Resp<()>,
    },
    Backup {
        path: PathBuf,
        resp: Resp<String>,
    },
    Counts {
        resp: Resp<Counts>,
    },
    Tokens {
        resp: oneshot::Sender<Vec<[u8; 32]>>,
    },
    BridgeRelays(Vec<DeliveryHint>),
}

/// Queue depths and contact count for the status report.
pub(crate) struct Counts {
    pub queued: u64,
    pub scheduled: u64,
    pub transit: u64,
    pub contacts: u64,
}

/// A running embedded node. Owns its tokio runtime; every task stops on
/// [`Runtime::stop`] (or best-effort on drop).
pub(crate) struct Runtime {
    pub address: String,
    pub peer: [u8; 32],
    pub tx: mpsc::Sender<Msg>,
    pub net: Arc<Libp2pTransport>,
    rt: tokio::runtime::Runtime,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    dispatcher: Option<std::thread::JoinHandle<()>>,
}

impl Runtime {
    /// Open (or create) the node, attach the configured carriers, and start
    /// the actor, lifecycle, and event-dispatch tasks. Blocking: Argon2id
    /// key derivation and transport binding happen before this returns, so
    /// a wrong passphrase or unreachable radio is a startup error, not a
    /// broken half-running node.
    pub(crate) fn start(
        cfg: RuntimeConfig,
        listener: Box<dyn Fn(Event) + Send>,
    ) -> Result<Self, String> {
        let mut node = if let Some(restore) = &cfg.restore {
            // Restore is a first-run operation: an existing store holds an
            // identity, and silently replacing it would destroy keys.
            if cfg.db_path.exists() {
                return Err(format!(
                    "refusing to restore over the existing store {}",
                    cfg.db_path.display()
                ));
            }
            Node::restore(
                &cfg.db_path,
                &restore.backup,
                &restore.mnemonic,
                &cfg.passphrase,
                cfg.kdf,
                &mut OsRng,
            )
        } else if cfg.db_path.exists() {
            Node::open(&cfg.db_path, &cfg.passphrase)
        } else {
            Node::create(&cfg.db_path, &cfg.passphrase, cfg.kdf, &mut OsRng)
        }
        .map_err(|e| format!("store: {e}"))?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;

        // Bridging needs both sides: it activates only when a radio is
        // configured (and startup fails hard if that radio is unreachable,
        // so "bridging" is never claimed without a mesh).
        let bridging =
            cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
        let net = {
            let listen: Vec<&str> = cfg.listen.iter().map(String::as_str).collect();
            let options = TransportOptions {
                mailbox: cfg.serve_mailbox.then(MailboxConfig::default),
                lan_discovery: cfg.mdns,
                bridge_deposits: bridging,
            };
            rt.block_on(Libp2pTransport::with_options(&listen, options))
                .map_err(|e| format!("internet transport: {e}"))?
        };
        let net = Arc::new(net);
        node.add_transport(Arc::clone(&net) as Arc<dyn Transport>);
        node.add_discovery(Arc::clone(&net) as Arc<dyn Discovery>);
        if let Some(spool) = &cfg.spool {
            let sneaker = kult_transport::SneakernetTransport::new(spool)
                .map_err(|e| format!("spool: {e}"))?;
            node.add_transport(Arc::new(sneaker));
        }
        // A radio that was asked for but cannot be reached is a hard startup
        // error, same contract as kultd: silently running without the
        // configured off-grid carrier would be a lie about coverage.
        #[cfg(feature = "meshtastic")]
        {
            use kult_transport::{MeshtasticOptions, MeshtasticTransport};
            if let Some(port) = &cfg.meshtastic_serial {
                let radio = rt
                    .block_on(MeshtasticTransport::connect_serial(
                        port,
                        None,
                        MeshtasticOptions::default(),
                    ))
                    .map_err(|e| format!("meshtastic serial {port}: {e}"))?;
                node.add_transport(Arc::new(radio));
            }
            if let Some(addr) = &cfg.meshtastic_tcp {
                let radio = rt
                    .block_on(MeshtasticTransport::connect_tcp(
                        addr,
                        MeshtasticOptions::default(),
                    ))
                    .map_err(|e| format!("meshtastic tcp {addr}: {e}"))?;
                node.add_transport(Arc::new(radio));
            }
        }
        #[cfg(not(feature = "meshtastic"))]
        if cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some() {
            return Err(
                "this build has no Meshtastic support (enable kult-ffi's `meshtastic` feature)"
                    .to_owned(),
            );
        }
        if bridging {
            node.set_bridge(Some(bridge_relays(&cfg, None)));
        }

        let address = node.address();
        let peer = node.peer_id();

        let (shutdown, _) = watch::channel(false);
        let (tx, rx) = mpsc::channel::<Msg>(64);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel::<Event>();

        let mut tasks = Vec::new();
        // The node's store is single-threaded by design (one SQLite
        // connection), so its futures are not `Send`: the actor gets its
        // own current-thread runtime on a blocking thread, exactly like
        // kultd's daemon. Channels bridge the two runtimes safely.
        let actor_inputs = (
            cfg.clone(),
            Arc::clone(&net),
            events_tx,
            shutdown.subscribe(),
        );
        tasks.push(rt.spawn_blocking(move || {
            let (cfg, net, events, shutdown) = actor_inputs;
            let local = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("actor runtime");
            local.block_on(actor(node, cfg, net, rx, events, shutdown));
        }));
        tasks.push(rt.spawn(lifecycle(
            cfg,
            Arc::clone(&net),
            tx.clone(),
            shutdown.subscribe(),
        )));
        // The listener runs on its own plain thread: a callback into
        // application code may block, and must never stall the tick loop or
        // a tokio worker. Exits when the actor (sole sender) does.
        let dispatcher = std::thread::spawn(move || {
            while let Some(event) = events_rx.blocking_recv() {
                listener(event);
            }
        });

        Ok(Self {
            address,
            peer,
            tx,
            net,
            rt,
            shutdown,
            tasks,
            dispatcher: Some(dispatcher),
        })
    }

    /// Run a future on this runtime from a foreign (non-tokio) thread.
    pub(crate) fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    /// Stop every task and wait for them.
    pub(crate) fn stop(mut self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks.drain(..) {
            let _ = self.rt.block_on(task);
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.join();
        }
    }
}

impl Drop for Runtime {
    /// Best-effort shutdown signal, so dropping without [`Runtime::stop`]
    /// (an application that forgot) still lets the tokio runtime's own drop
    /// — which waits for blocking tasks — terminate rather than hang.
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
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
/// Kept in lockstep with `kultd`'s equivalent.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    open_private(path)?.write_all(bytes)
}

/// Create a protected caller-selected destination without overwriting.
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
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
fn bridge_relays(cfg: &RuntimeConfig, own_addr: Option<&str>) -> Vec<DeliveryHint> {
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
    cfg: RuntimeConfig,
    net: Arc<Libp2pTransport>,
    mut rx: mpsc::Receiver<Msg>,
    events: mpsc::UnboundedSender<Event>,
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
                        for event in batch {
                            let _ = events.send(event);
                        }
                    }
                    Err(e) => eprintln!("kult-ffi: tick failed: {e}"),
                }
            }
            msg = rx.recv() => match msg {
                None => break,
                Some(msg) => handle(&mut node, &cfg, &net, msg).await,
            },
        }
    }
}

/// Execute one operation against the node.
async fn handle(node: &mut Node, cfg: &RuntimeConfig, net: &Libp2pTransport, msg: Msg) {
    let now = now();
    let fail = |e: kult_node::NodeError| e.to_string();
    match msg {
        Msg::HandshakeBundle { resp } => {
            let _ = resp.send(node.handshake_bundle(now, &mut OsRng).map_err(fail));
        }
        Msg::AddContact {
            name,
            bundle,
            hints,
            resp,
        } => {
            let _ = resp.send(
                node.add_contact(&name, &bundle, &hints, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AddByAddress {
            name,
            address,
            resp,
        } => {
            let _ = resp.send(
                node.add_contact_by_address(&name, &address, now, &mut OsRng)
                    .await
                    .map_err(fail),
            );
        }
        Msg::Send { peer, body, resp } => {
            let _ = resp.send(
                node.send_message(&peer, &body, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentSend {
            peer,
            metadata,
            path,
            preview,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_attachment_with_preview(
                        &peer,
                        &metadata,
                        &mut source,
                        preview,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::GroupAttachmentSend {
            group,
            metadata,
            path,
            preview,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_group_attachment_with_preview(
                        &group,
                        &metadata,
                        &mut source,
                        preview,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::Attachments { resp } => {
            let _ = resp.send(node.attachments().map_err(fail));
        }
        Msg::AttachmentAccept { transfer, resp } => {
            let _ = resp.send(
                node.accept_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentReject { transfer, resp } => {
            let _ = resp.send(
                node.reject_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentCancel { transfer, resp } => {
            let _ = resp.send(
                node.cancel_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentPause { transfer, resp } => {
            let _ = resp.send(
                node.pause_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentResume { transfer, resp } => {
            let _ = resp.send(
                node.resume_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentExport {
            transfer,
            path,
            preview,
            resp,
        } => {
            let result = match open_private(&path) {
                Ok(mut destination) => {
                    let result = node
                        .export_attachment_object(&transfer, preview, &mut destination)
                        .map_err(fail);
                    drop(destination);
                    if result.is_err() {
                        let _ = std::fs::remove_file(&path);
                    }
                    result
                }
                Err(error) => Err(format!("attachment export: {error}")),
            };
            let _ = resp.send(result);
        }
        Msg::Schedule {
            peer,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.schedule_message(&peer, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupSchedule {
            group,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.schedule_group_message(&group, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::ScheduledEdit {
            id,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.edit_scheduled_message(&id, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::ScheduledCancel { id, resp } => {
            let _ = resp.send(node.cancel_scheduled_message(&id).map_err(fail));
        }
        Msg::ScheduledMessages { resp } => {
            let _ = resp.send(node.scheduled_messages().map_err(fail));
        }
        Msg::NoteToSelfSend { body, resp } => {
            let _ = resp.send(node.note_to_self_send(&body, now, &mut OsRng).map_err(fail));
        }
        Msg::NoteToSelfMessages { resp } => {
            let _ = resp.send(node.note_to_self_messages().map_err(fail));
        }
        Msg::LabelCreate { name, color, resp } => {
            let _ = resp.send(node.create_label(&name, &color, &mut OsRng).map_err(fail));
        }
        Msg::Labels { resp } => {
            let _ = resp.send(node.labels().map_err(fail));
        }
        Msg::LabelGet { label, resp } => {
            let _ = resp.send(node.label(&label).map_err(fail));
        }
        Msg::LabelUpdate {
            label,
            name,
            color,
            resp,
        } => {
            let _ = resp.send(
                node.update_label(&label, &name, &color, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::LabelDeletePreview { label, resp } => {
            let _ = resp.send(node.label_delete_assignment_count(&label).map_err(fail));
        }
        Msg::LabelDelete { label, resp } => {
            let _ = resp.send(node.delete_label(&label).map_err(fail));
        }
        Msg::LabelAssign {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(node.assign_label(&label, &target, &mut OsRng).map_err(fail));
        }
        Msg::LabelUnassign {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(node.unassign_label(&label, &target).map_err(fail));
        }
        Msg::LabelMembership { label, resp } => {
            let _ = resp.send(node.label_members(&label).map_err(fail));
        }
        Msg::LabelsForConversation { target, resp } => {
            let _ = resp.send(node.labels_for_conversation(&target).map_err(fail));
        }
        Msg::LabelStale { resp } => {
            let _ = resp.send(node.stale_label_assignments().map_err(fail));
        }
        Msg::LabelStaleCleanup {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(
                node.cleanup_stale_label_assignment(&label, &target)
                    .map_err(fail),
            );
        }
        Msg::LabelFilter { labels, mode, resp } => {
            let _ = resp.send(node.filter_label_conversations(&labels, mode).map_err(fail));
        }
        Msg::GroupCreate {
            name,
            members,
            resp,
        } => {
            let _ = resp.send(node.create_group(&name, &members, &mut OsRng).map_err(fail));
        }
        Msg::GroupSend { group, body, resp } => {
            let _ = resp.send(
                node.group_send(&group, &body, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupMentionCapability { group, resp } => {
            let _ = resp.send(node.group_mention_capability(&group).map_err(fail));
        }
        Msg::GroupMentionSend {
            group,
            text,
            spans,
            review_token,
            resp,
        } => {
            let _ = resp.send(
                node.group_send_mention(&group, &text, &spans, review_token, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupAdd { group, peer, resp } => {
            let _ = resp.send(node.group_add(&group, &peer, &mut OsRng).map_err(fail));
        }
        Msg::GroupRemove { group, peer, resp } => {
            let _ = resp.send(
                node.group_remove(&group, &peer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupLeave { group, resp } => {
            let _ = resp.send(node.group_leave(&group, now, &mut OsRng).map_err(fail));
        }
        Msg::Groups { resp } => {
            let _ = resp.send(node.groups().map_err(fail));
        }
        Msg::GroupMessages { group, resp } => {
            let _ = resp.send(node.group_messages(&group).map_err(fail));
        }
        Msg::Contacts { resp } => {
            let _ = resp.send(node.contacts().map_err(fail));
        }
        Msg::CarrierCapabilities { resp } => {
            let _ = resp.send(node.carrier_capabilities(now).map_err(fail));
        }
        Msg::Messages { peer, resp } => {
            let _ = resp.send(node.messages_with(&peer).map_err(fail));
        }
        Msg::SafetyNumber { peer, resp } => {
            let _ = resp.send(node.safety_number_with(&peer).map_err(fail));
        }
        Msg::MarkVerified { peer, resp } => {
            let _ = resp.send(node.mark_verified(&peer, &mut OsRng).map_err(fail));
        }
        Msg::SetHints { peer, hints, resp } => {
            let _ = resp.send(node.set_hints(&peer, &hints, &mut OsRng).map_err(fail));
        }
        Msg::Publish { resp } => {
            let hints = own_hints(net, &cfg.mailboxes);
            let _ = resp.send(node.publish_bundle(&hints, now).await.map_err(fail));
        }
        Msg::Backup { path, resp } => {
            let result = node
                .export_backup(now, &mut OsRng)
                .map_err(|e| e.to_string())
                .and_then(|(file, mnemonic)| {
                    write_private(&path, &file)
                        .map(|()| (*mnemonic).clone())
                        .map_err(|e| format!("backup write: {e}"))
                });
            let _ = resp.send(result);
        }
        Msg::Counts { resp } => {
            let result = node
                .queued()
                .and_then(|queued| {
                    node.scheduled_messages().and_then(|scheduled| {
                        node.contacts().map(|contacts| Counts {
                            queued: queued as u64,
                            scheduled: scheduled.len() as u64,
                            transit: node.transit_queued() as u64,
                            contacts: contacts.len() as u64,
                        })
                    })
                })
                .map_err(|e| e.to_string());
            let _ = resp.send(result);
        }
        Msg::Tokens { resp } => {
            let _ = resp.send(node.mailbox_tokens(now));
        }
        Msg::BridgeRelays(relays) => node.set_bridge(Some(relays)),
    }
}

/// Ask the actor to publish the prekey bundle, ignoring the outcome — the
/// lifecycle retries on its own schedule.
async fn publish_quiet(tx: &mpsc::Sender<Msg>) {
    let (resp, _rx) = oneshot::channel();
    let _ = tx.send(Msg::Publish { resp }).await;
}

/// Background lifecycle: bootstrap, publish, NAT probing + relay
/// reservation, mailbox check-ins. Everything here is best-effort and
/// retried on its interval — the node works without connectivity and picks
/// these up when it appears. Kept in lockstep with `kultd`'s lifecycle.
async fn lifecycle(
    cfg: RuntimeConfig,
    net: Arc<Libp2pTransport>,
    tx: mpsc::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
) {
    if net.wait_listen_addr().await.is_err() {
        eprintln!("kult-ffi: no listen address bound");
    }
    let bridging = cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
    if bridging && cfg.serve_mailbox {
        // Now that an address is bound, mesh-heard transit can also be
        // deposited into this node's own mailbox service (resolved locally
        // by the transport — no self-dial).
        if let Some(addr) = net.listen_addrs().into_iter().next() {
            let relays = bridge_relays(&cfg, Some(&addr));
            let _ = tx.send(Msg::BridgeRelays(relays)).await;
        }
    }
    if !cfg.bootstrap.is_empty() {
        let peers: Vec<&str> = cfg.bootstrap.iter().map(String::as_str).collect();
        if let Err(e) = net.bootstrap(&peers).await {
            eprintln!("kult-ffi: DHT bootstrap failed: {e}");
        }
        // Publish once the DHT has peers (a lone node has nowhere to put
        // records; contacts then come from out-of-band bundles instead).
        publish_quiet(&tx).await;
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
                if let Ok(kult_transport::NatStatus::Private) = net.nat_status().await {
                    match net.reserve_relay(relay).await {
                        Ok(_) => {
                            circuit_reserved = true;
                            // The circuit is a new listen address — republish.
                            publish_quiet(&tx).await;
                        }
                        Err(e) => eprintln!("kult-ffi: relay reservation failed: {e}"),
                    }
                }
            }
            _ = checkin_tick.tick() => {
                if cfg.mailboxes.is_empty() {
                    continue;
                }
                let (resp, rx) = oneshot::channel();
                if tx.send(Msg::Tokens { resp }).await.is_err() {
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
                                eprintln!("kult-ffi: mailbox check-in at {mailbox} failed: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
