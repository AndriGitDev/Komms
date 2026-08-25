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

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use kult_crypto::KdfProfile;
use kult_node::{DeviceLinkSelection, FolderSelection, LabelMatchMode, Node, NodeError};
use kult_transport::{
    DeliveryHint, Discovery, HttpsRendezvousClient, HttpsWakeClient, Libp2pTransport,
    MailboxConfig, MailboxServiceConfig, ManualProviderSet, MeshtasticOptions, MeshtasticStats,
    MeshtasticTransport, NatStatus, OperatingMode, ProviderDirectoryStatus, ProviderRendezvous,
    RendezvousClient, RendezvousProvider, Transport, TransportOptions, WakeClient,
    MAX_MAILBOX_CHECKIN_TOKENS,
};

use crate::wire::{self, Hint, Op, Request};

/// Bound one lifecycle pass even when an operator configures many or hostile
/// mailbox endpoints. Remaining work waits for the next check-in interval.
const MAX_MAILBOXES_PER_CHECKIN_TICK: usize = 8;
const MAX_MAILBOX_BACKOFF: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy)]
struct MailboxRetry {
    failures: u8,
    next_at: Instant,
}

fn jittered_mailbox_delay(base: Duration, failures: u8, draw: u64) -> Duration {
    let multiplier = 1u32 << failures.min(6);
    let backed_off = base.saturating_mul(multiplier).min(MAX_MAILBOX_BACKOFF);
    let percent = 75u128 + u128::from(draw % 51);
    let millis = backed_off
        .as_millis()
        .saturating_mul(percent)
        .saturating_div(100)
        .max(250);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

fn log_mailbox_page_collected(count: usize) {
    tracing::debug!(count, "mailbox page collected");
}

fn log_mailbox_checkin_failed() {
    tracing::warn!("mailbox check-in failed");
}

/// Return one contiguous bounded page and advance a persistent cursor.
///
/// The final short page resets to the front for the following call. This
/// avoids both front-of-list starvation and needless duplicates while a full
/// mailbox/token set is being refreshed over multiple lifecycle intervals.
fn rotating_batch<T: Clone>(items: &[T], cursor: &mut usize, limit: usize) -> Vec<T> {
    if items.is_empty() || limit == 0 {
        *cursor = 0;
        return Vec::new();
    }
    *cursor %= items.len();
    let end = cursor.saturating_add(limit).min(items.len());
    let batch = items[*cursor..end].to_vec();
    *cursor = if end == items.len() { 0 } else { end };
    batch
}

/// Explicit one-time Alpha authority upgrade selected at daemon startup.
#[derive(Clone)]
pub enum AuthorityStartup {
    /// Remove an undistributed legacy root in place while retaining identity.
    Migrate {
        /// Protected offline authority package prepared from this profile.
        package: PathBuf,
        /// Separately confirmed 24-word phrase.
        mnemonic: zeroize::Zeroizing<String>,
    },
    /// Replace a copied-root profile with a fresh identity and local archive.
    Reset {
        /// Protected fresh-identity offline authority package.
        package: PathBuf,
        /// Separately confirmed 24-word phrase.
        mnemonic: zeroize::Zeroizing<String>,
    },
}

impl std::fmt::Debug for AuthorityStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Migrate { package, .. } => f
                .debug_struct("Migrate")
                .field("package", package)
                .field("mnemonic", &"<redacted>")
                .finish(),
            Self::Reset { package, .. } => f
                .debug_struct("Reset")
                .field("package", package)
                .field("mnemonic", &"<redacted>")
                .finish(),
        }
    }
}

/// Everything the daemon needs to run. Built by the CLI in `bin/kultd.rs`,
/// or directly by tests.
#[derive(Clone)]
pub struct DaemonConfig {
    /// The encrypted store (created on first run).
    pub db_path: PathBuf,
    /// The RPC socket path (stale files are replaced).
    pub socket_path: PathBuf,
    /// Store passphrase. Zeroized on drop.
    pub passphrase: zeroize::Zeroizing<Vec<u8>>,
    /// Argon2id cost profile for store creation.
    pub kdf: KdfProfile,
    /// First run only: restore the store from this encrypted backup file
    /// instead of creating a fresh identity (docs/07-storage.md §4).
    /// Refused when `db_path` already exists.
    pub restore_from: Option<PathBuf>,
    /// The 24-word mnemonic sealing `restore_from`. Zeroized on drop.
    pub restore_mnemonic: Option<zeroize::Zeroizing<String>>,
    /// Separately held encrypted offline account authority required for a
    /// stable-identity recovery.
    pub recovery_authority_from: Option<PathBuf>,
    /// The separate 24-word phrase opening `recovery_authority_from`.
    pub recovery_authority_mnemonic: Option<zeroize::Zeroizing<String>>,
    /// Explicit legacy-root migration or copied-root reset to complete before
    /// any network service starts.
    pub authority_startup: Option<AuthorityStartup>,
    /// Standard, Private, or Sovereign behavior.
    pub mode: OperatingMode,
    /// User confirmed the Standard provider disclosure before first use.
    pub standard_disclosure_confirmed: bool,
    /// Advanced Sovereign-only acknowledgement for public direct routes.
    pub sovereign_publish_direct_routes: bool,
    /// Candidate signed, user-editable provider-directory JSON.
    pub provider_directory: Option<PathBuf>,
    /// Trusted offline provider-directory Ed25519 keys.
    pub provider_directory_roots: Vec<[u8; 32]>,
    /// User-selected rendezvous providers, independent of directory defaults.
    pub rendezvous: Vec<ProviderRendezvous>,
    /// Explicit loopback Tor SOCKS5 ingress for Private rendezvous.
    pub tor_proxy: Option<std::net::SocketAddr>,
    provider_directory_status: Option<ProviderDirectoryStatus>,
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

// Hand-written so the config stays printable without ever printing the
// passphrase or mnemonic a derive would happily emit.
impl std::fmt::Debug for DaemonConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonConfig")
            .field("db_path", &self.db_path)
            .field("socket_path", &self.socket_path)
            .field("passphrase", &"<redacted>")
            .field("kdf", &self.kdf)
            .field("restore_from", &self.restore_from)
            .field(
                "restore_mnemonic",
                &self.restore_mnemonic.as_ref().map(|_| "<redacted>"),
            )
            .field("recovery_authority_from", &self.recovery_authority_from)
            .field(
                "recovery_authority_mnemonic",
                &self
                    .recovery_authority_mnemonic
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("authority_startup", &self.authority_startup)
            .field("mode", &self.mode)
            .field(
                "standard_disclosure_confirmed",
                &self.standard_disclosure_confirmed,
            )
            .field(
                "sovereign_publish_direct_routes",
                &self.sovereign_publish_direct_routes,
            )
            .field("provider_directory", &self.provider_directory)
            .field(
                "provider_directory_roots",
                &self.provider_directory_roots.len(),
            )
            .field("rendezvous", &self.rendezvous)
            .field("tor_proxy", &self.tor_proxy)
            .field("provider_directory_status", &self.provider_directory_status)
            .field("listen", &self.listen)
            .field("bootstrap", &self.bootstrap)
            .field("relay", &self.relay)
            .field("mailboxes", &self.mailboxes)
            .field("serve_mailbox", &self.serve_mailbox)
            .field("mdns", &self.mdns)
            .field("spool", &self.spool)
            .field("meshtastic_serial", &self.meshtastic_serial)
            .field("meshtastic_tcp", &self.meshtastic_tcp)
            .field("bridge", &self.bridge)
            .field("tick_interval", &self.tick_interval)
            .field("checkin_interval", &self.checkin_interval)
            .field("nat_interval", &self.nat_interval)
            .finish()
    }
}

impl DaemonConfig {
    /// Sensible defaults rooted in a data directory: QUIC + TCP on
    /// OS-assigned ports, desktop KDF profile, no bootstrap peers.
    /// The passphrase is held zeroized-on-drop; plain `Vec<u8>` input is
    /// wrapped, so callers need no zeroize types of their own.
    pub fn new(
        data_dir: &std::path::Path,
        passphrase: impl Into<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            db_path: data_dir.join("node.db"),
            socket_path: data_dir.join("kultd.sock"),
            passphrase: passphrase.into(),
            kdf: kult_crypto::KDF_PROFILE_DESKTOP,
            restore_from: None,
            restore_mnemonic: None,
            recovery_authority_from: None,
            recovery_authority_mnemonic: None,
            authority_startup: None,
            mode: OperatingMode::Standard,
            standard_disclosure_confirmed: false,
            sovereign_publish_direct_routes: false,
            provider_directory: None,
            provider_directory_roots: Vec::new(),
            rendezvous: Vec::new(),
            tor_proxy: None,
            provider_directory_status: None,
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
    meshtastic: Vec<Arc<MeshtasticTransport>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    socket_guard: RpcSocketGuard,
}

impl Daemon {
    /// Open (or create) the node and start all daemon tasks.
    pub async fn start(mut cfg: DaemonConfig) -> Result<Self, DaemonError> {
        let directory_configured = cfg.provider_directory.is_some();
        let directory_cache = cfg
            .db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("provider-directory-cache.json");
        let resolution = kult_transport::resolve_provider_directory(
            cfg.mode,
            cfg.provider_directory.as_deref(),
            &directory_cache,
            &cfg.provider_directory_roots,
            &ManualProviderSet {
                bootstrap: cfg.bootstrap.clone(),
                relay: cfg.relay.clone(),
                mailboxes: cfg.mailboxes.clone(),
                rendezvous: cfg.rendezvous.clone(),
            },
            now(),
        )
        .map_err(|error| DaemonError::Io(io::Error::other(error.to_string())))?;
        if cfg.mode == OperatingMode::Standard
            && resolution.directory.is_some()
            && !cfg.standard_disclosure_confirmed
        {
            return Err(DaemonError::Io(io::Error::other(
                "confirm the Standard provider disclosure before using directory defaults",
            )));
        }
        if cfg.mode == OperatingMode::Private
            && !resolution.providers.rendezvous.is_empty()
            && cfg.tor_proxy.is_none()
        {
            return Err(DaemonError::Io(io::Error::other(
                "Private rendezvous requires an explicit loopback Tor proxy",
            )));
        }
        if let Some(proxy) = cfg.tor_proxy {
            HttpsRendezvousClient::tor(proxy)
                .map_err(|_| DaemonError::Io(io::Error::other("invalid loopback Tor proxy")))?;
        }
        cfg.provider_directory_status = directory_configured.then_some(resolution.status);
        cfg.bootstrap = resolution.providers.bootstrap;
        cfg.relay = resolution.providers.relay;
        cfg.mailboxes = resolution.providers.mailboxes;
        cfg.rendezvous = resolution
            .providers
            .rendezvous
            .into_iter()
            .map(|provider| ProviderRendezvous {
                origin: provider.origin().to_owned(),
                static_key: lower_hex(&provider.static_key()),
                standard: true,
                private_via_tor: true,
            })
            .collect();

        // Argon2id is deliberately slow — keep it off the async threads.
        let mut node = {
            let cfg = cfg.clone();
            tokio::task::spawn_blocking(move || -> Result<Node, DaemonError> {
                if cfg.authority_startup.is_some() && cfg.restore_from.is_some() {
                    return Err(DaemonError::Io(io::Error::other(
                        "authority upgrade and backup restore are mutually exclusive",
                    )));
                }
                if let Some(authority) = &cfg.authority_startup {
                    if !cfg.db_path.exists() {
                        return Err(DaemonError::Io(io::Error::other(format!(
                            "authority upgrade requires the existing store {}",
                            cfg.db_path.display()
                        ))));
                    }
                    let (package_path, mnemonic, reset) = match authority {
                        AuthorityStartup::Migrate { package, mnemonic } => {
                            (package, mnemonic.as_str(), false)
                        }
                        AuthorityStartup::Reset { package, mnemonic } => {
                            (package, mnemonic.as_str(), true)
                        }
                    };
                    let package = std::fs::read(package_path)?;
                    if reset {
                        Ok(Node::complete_authority_reset(
                            &cfg.db_path,
                            &cfg.passphrase,
                            &package,
                            mnemonic,
                            now(),
                            &mut OsRng,
                        )?)
                    } else {
                        Ok(Node::complete_authority_migration(
                            &cfg.db_path,
                            &cfg.passphrase,
                            &package,
                            mnemonic,
                            now(),
                            &mut OsRng,
                        )?)
                    }
                } else if let Some(backup_path) = &cfg.restore_from {
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
                    let recovery_path = cfg.recovery_authority_from.as_ref().ok_or_else(|| {
                        DaemonError::Io(io::Error::other(
                            "restore needs the offline recovery authority",
                        ))
                    })?;
                    let recovery_mnemonic =
                        cfg.recovery_authority_mnemonic.as_deref().ok_or_else(|| {
                            DaemonError::Io(io::Error::other(
                                "restore needs the recovery authority mnemonic",
                            ))
                        })?;
                    let recovery_package = std::fs::read(recovery_path)?;
                    Ok(Node::restore_with_recovery_authority(
                        &cfg.db_path,
                        &backup,
                        mnemonic,
                        &recovery_package,
                        recovery_mnemonic,
                        now(),
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
        let mailbox_dir = cfg.db_path.parent().unwrap_or_else(|| Path::new("."));
        let options = TransportOptions {
            mailbox: cfg
                .serve_mailbox
                .then(|| MailboxServiceConfig::in_directory(mailbox_dir, MailboxConfig::default())),
            lan_discovery: cfg.mdns,
            bridge_deposits: bridging,
        };
        let net = Libp2pTransport::with_options(&listen, options)
            .await
            .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
        let net = Arc::new(net);
        node.add_transport(Arc::clone(&net) as Arc<dyn Transport>);
        node.add_discovery(Arc::clone(&net) as Arc<dyn Discovery>);
        let mut meshtastic = Vec::new();
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
            tracing::info!("meshtastic serial radio connected");
            let radio = Arc::new(radio);
            node.add_transport(Arc::clone(&radio) as Arc<dyn Transport>);
            meshtastic.push(radio);
        }
        if let Some(addr) = &cfg.meshtastic_tcp {
            let radio = MeshtasticTransport::connect_tcp(addr, MeshtasticOptions::default())
                .await
                .map_err(|e| DaemonError::Io(io::Error::other(e.to_string())))?;
            tracing::info!("meshtastic TCP radio connected");
            let radio = Arc::new(radio);
            node.add_transport(Arc::clone(&radio) as Arc<dyn Transport>);
            meshtastic.push(radio);
        }
        if bridging {
            // Mesh-heard transit is offered to the same relays this node
            // checks in with; once a listen address is bound, the lifecycle
            // task adds this node's own mailbox service to the set.
            node.set_bridge(Some(bridge_relays(&cfg, None)));
            tracing::info!("bridging mesh↔internet (--no-bridge to opt out)");
        }
        let rendezvous_providers = cfg
            .rendezvous
            .iter()
            .map(|provider| {
                let key = parse_lower_hex_32(&provider.static_key)
                    .map_err(|error| DaemonError::Io(io::Error::other(error)))?;
                RendezvousProvider::new(provider.origin.clone(), key)
                    .map_err(|error| DaemonError::Io(io::Error::other(error.to_string())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rendezvous_client: Option<Arc<dyn RendezvousClient>> =
            if rendezvous_providers.is_empty() {
                None
            } else {
                Some(match cfg.mode {
                    OperatingMode::Standard => Arc::new(HttpsRendezvousClient::direct()),
                    OperatingMode::Private => Arc::new(
                        HttpsRendezvousClient::tor(cfg.tor_proxy.ok_or_else(|| {
                            DaemonError::Io(io::Error::other("Private rendezvous has no Tor proxy"))
                        })?)
                        .map_err(|error| DaemonError::Io(io::Error::other(error.to_string())))?,
                    ),
                    OperatingMode::Sovereign => {
                        return Err(DaemonError::Io(io::Error::other(
                            "Sovereign mode cannot configure rendezvous",
                        )))
                    }
                })
            };
        node.reconcile_rendezvous(
            publication_policy(&cfg).mode,
            rendezvous_client,
            rendezvous_providers,
        )?;
        let wake_client: Option<Arc<dyn WakeClient>> = match cfg.mode {
            OperatingMode::Standard => Some(Arc::new(HttpsWakeClient::direct())),
            OperatingMode::Private => match cfg.tor_proxy {
                Some(proxy) => {
                    Some(Arc::new(HttpsWakeClient::tor(proxy).map_err(|error| {
                        DaemonError::Io(io::Error::other(error.to_string()))
                    })?))
                }
                // Native wake is optional. Never fall back to direct ingress
                // in Private mode, and do not make ordinary delivery depend
                // on an unavailable anonymizing proxy.
                None => None,
            },
            OperatingMode::Sovereign => None,
        };
        node.configure_wake(publication_policy(&cfg).mode, wake_client)?;

        let address = node.address();
        let peer = node.peer_id();

        let (shutdown, _) = watch::channel(false);
        let (node_tx, node_rx) = mpsc::channel::<NodeMsg>(64);
        let (events_tx, _) = broadcast::channel::<String>(256);

        // Refuse to displace a live daemon. Only a socket that cannot accept
        // a connection is treated as stale and removed.
        let (listener, socket_guard) = bind_rpc_socket(&cfg.socket_path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o600))
            {
                socket_guard.remove_owned();
                return Err(DaemonError::Io(error));
            }
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
        let (actor_ready, actor_ready_rx) = oneshot::channel();
        tasks.push(tokio::task::spawn_blocking(move || {
            let (cfg, net, events, shutdown) = actor_inputs;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("actor runtime");
            rt.block_on(actor(
                node,
                cfg,
                net,
                node_rx,
                events,
                shutdown,
                actor_ready,
            ));
        }));
        tasks.push(tokio::spawn(lifecycle(
            cfg.clone(),
            Arc::clone(&net),
            node_tx.clone(),
            shutdown.subscribe(),
        )));
        let (serve_ready, serve_ready_rx) = oneshot::channel();
        tasks.push(tokio::spawn(serve(
            listener,
            node_tx,
            events_tx,
            shutdown.subscribe(),
            serve_ready,
        )));

        // Binding the socket is not sufficient startup readiness: the OS can
        // accept a connection into its backlog before either the accept loop
        // or the blocking-thread node actor has received its first scheduler
        // poll. Returning in that window made an immediate status/bundle RPC
        // intermittently sit unanswered until the client timed out.
        let ready = async {
            actor_ready_rx
                .await
                .map_err(|_| io::Error::other("node actor stopped during startup"))?;
            serve_ready_rx
                .await
                .map_err(|_| io::Error::other("RPC server stopped during startup"))
        };
        if let Err(error) = tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .map_err(|_| io::Error::other("daemon tasks were not ready within 5s"))
            .and_then(|result| result)
        {
            let _ = shutdown.send(true);
            for task in tasks {
                let _ = task.await;
            }
            socket_guard.remove_owned();
            return Err(DaemonError::Io(error));
        }

        Ok(Self {
            address,
            peer,
            socket_path: cfg.socket_path,
            net,
            meshtastic,
            shutdown,
            tasks,
            socket_guard,
        })
    }

    /// Content-free aggregate radio snapshots, in configuration order.
    pub fn meshtastic_stats(&self) -> Vec<MeshtasticStats> {
        self.meshtastic
            .iter()
            .map(|transport| transport.stats())
            .collect()
    }

    /// Stop every task and remove the socket.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        self.socket_guard.remove_owned();
    }
}

#[derive(Debug)]
struct RpcSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
    _lock: File,
}

impl RpcSocketGuard {
    /// Remove only the socket inode this daemon originally bound.
    fn remove_owned(&self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn rpc_lock_path(path: &Path) -> io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "RPC socket path has no file name",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(std::fs::canonicalize(parent)?.join(lock_name))
}

fn acquire_rpc_lock(path: &Path) -> io::Result<File> {
    let lock_path = rpc_lock_path(path)?;
    if std::fs::symlink_metadata(&lock_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("RPC lock path is a symlink: {}", lock_path.display()),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let lock = options.open(lock_path)?;
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => Ok(lock),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("another daemon owns RPC socket {}", path.display()),
        )),
        Err(error) => Err(error),
    }
}

fn socket_identity(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to replace non-socket path {}", path.display()),
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn guarded_listener(
    path: &Path,
    lock: File,
    listener: UnixListener,
) -> io::Result<(UnixListener, RpcSocketGuard)> {
    let (device, inode) = socket_identity(path)?;
    Ok((
        listener,
        RpcSocketGuard {
            path: path.to_path_buf(),
            device,
            inode,
            _lock: lock,
        },
    ))
}

/// Bind the RPC socket without unlinking a live daemon's pathname.
///
/// A no-follow socket-specific sidecar lock serializes cooperative stale
/// probing, unlink, bind, and the daemon lifetime. Observed non-socket path
/// replacements fail closed. Deployment still requires a daemon-owned parent
/// directory because portable Unix APIs cannot atomically recheck and unlink a
/// hostile replacement.
async fn bind_rpc_socket(path: &Path) -> io::Result<(UnixListener, RpcSocketGuard)> {
    let lock = acquire_rpc_lock(path)?;
    match UnixListener::bind(path) {
        Ok(listener) => guarded_listener(path, lock, listener),
        Err(bind_error) if bind_error.kind() == io::ErrorKind::AddrInUse => {
            let stale_identity = socket_identity(path)?;
            match tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(path)).await
            {
                Err(_) => Err(bind_error),
                Ok(Ok(_)) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another daemon is listening on {}", path.display()),
                )),
                Ok(Err(connect_error))
                    if matches!(
                        connect_error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    match socket_identity(path) {
                        Ok(current) if current == stale_identity => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        _ => return Err(bind_error),
                    }
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    let listener = UnixListener::bind(path)?;
                    guarded_listener(path, lock, listener)
                }
                Ok(Err(_)) => Err(bind_error),
            }
        }
        Err(error) => Err(error),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn publication_policy(cfg: &DaemonConfig) -> kult_node::DiscoveryPublicationPolicy {
    kult_node::DiscoveryPublicationPolicy {
        mode: match cfg.mode {
            OperatingMode::Standard => kult_node::DiscoveryMode::Standard,
            OperatingMode::Private => kult_node::DiscoveryMode::Private,
            OperatingMode::Sovereign => kult_node::DiscoveryMode::Sovereign,
        },
        publish_direct_routes: cfg.sovereign_publish_direct_routes,
    }
}

fn parse_lower_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("provider key must be exactly 64 lowercase hex characters".to_owned());
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
    ready: oneshot::Sender<()>,
) {
    // Tokio intervals tick immediately by default. Give startup RPCs a
    // bounded window before the first potentially transport-bound heartbeat;
    // subsequent ticks retain the configured cadence.
    let started = tokio::time::Instant::now();
    let first_tick = started + cfg.tick_interval.max(Duration::from_millis(250));
    let mut tick = tokio::time::interval_at(first_tick, cfg.tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut media_tick = tokio::time::interval_at(
        started + Duration::from_millis(20),
        Duration::from_millis(20),
    );
    media_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut discovery_retry_at = started;
    let _ = ready.send(());
    loop {
        let mut check_discovery = false;
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                check_discovery = true;
                match node.tick(now(), &mut OsRng).await {
                    Ok(batch) => {
                        for event in &batch {
                            let _ = events.send(wire::event_line(event));
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "tick failed"),
                }
            }
            _ = media_tick.tick() => {
                if let Err(e) = node.pump_call_media(now()).await {
                    tracing::warn!(error = %e, "call media pump failed");
                }
                for event in node.drain_events() {
                    let _ = events.send(wire::event_line(&event));
                }
            }
            msg = rx.recv() => {
                match msg {
                    None => break,
                    Some(NodeMsg::Tokens { resp }) => {
                        let _ = resp.send(node.mailbox_tokens(now()));
                    }
                    Some(NodeMsg::Publish) => {
                        let hints = own_hints(&net, &cfg.mailboxes);
                        if let Err(e) = node
                            .publish_bundle_with_policy(&hints, publication_policy(&cfg), now())
                            .await
                        {
                            tracing::warn!(error = %e, "bundle publish failed");
                        }
                    }
                    Some(NodeMsg::BridgeRelays(relays)) => {
                        node.set_bridge(Some(relays));
                    }
                    Some(NodeMsg::Op { op, resp }) => {
                        let result = handle_op(&mut node, &cfg, &net, &events, op).await;
                        let _ = resp.send(result);
                    }
                }
            }
        }
        let discovery_now = tokio::time::Instant::now();
        if check_discovery && discovery_now >= discovery_retry_at {
            let hints = own_hints(&net, &cfg.mailboxes);
            if node
                .discovery_publication_needed_with_policy(&hints, publication_policy(&cfg))
                .unwrap_or(false)
            {
                match node
                    .publish_bundle_with_policy(&hints, publication_policy(&cfg), now())
                    .await
                {
                    Ok(()) => discovery_retry_at = discovery_now,
                    Err(error) => {
                        tracing::warn!(%error, "discovery refresh failed");
                        discovery_retry_at = discovery_now + Duration::from_secs(60);
                    }
                }
            }
        }
    }
}

/// Execute one RPC operation against the node.
async fn handle_op(
    node: &mut Node,
    cfg: &DaemonConfig,
    net: &Libp2pTransport,
    events: &broadcast::Sender<String>,
    op: Op,
) -> Result<Value, String> {
    let fail = |e: NodeError| e.to_string();
    match op {
        Op::Status => {
            // Status is a local UI/health request and must not hang behind a
            // slow or wedged transport command loop. NAT starts as unknown
            // already, so a bounded diagnostic miss has the same honest
            // meaning and leaves the actor available for real node work.
            let nat = match tokio::time::timeout(Duration::from_secs(1), net.nat_status()).await {
                Ok(Ok(NatStatus::Public)) => "public",
                Ok(Ok(NatStatus::Private)) => "private",
                _ => "unknown",
            };
            let mailbox = net.mailbox_metrics().map(|metrics| {
                json!({
                    "stored_items": metrics.stored_items,
                    "stored_bytes": metrics.stored_bytes,
                    "capacity_items": metrics.capacity_items,
                    "capacity_bytes": metrics.capacity_bytes,
                    "retention_secs": metrics.retention_secs,
                    "request_capacity_per_minute": metrics.request_capacity_per_minute,
                    "request_capacity_per_client_per_minute": metrics.request_capacity_per_client_per_minute,
                    "disk_available_bytes": metrics.disk_available_bytes,
                    "registrations": metrics.registrations,
                    "live_leases": metrics.live_leases,
                    "lease_capacity": metrics.lease_capacity,
                    "oldest_lease_age_secs": metrics.oldest_lease_age_secs,
                    "rejected_deposits": metrics.rejected_deposits,
                    "rejected_requests": metrics.rejected_requests,
                    "expired_rows": metrics.expired_rows,
                    "schema_version": metrics.schema_version,
                })
            });
            Ok(json!({
                "address": node.address(),
                "connect_code": node.connect_code().map_err(fail)?,
                "legacy_discovery": node.legacy_discovery_enabled(),
                "peer": wire::hex_encode(&node.peer_id()),
                "listen": net.listen_addrs(),
                "lan_peers": net.lan_peers(),
                "nat": nat,
                "mode": match cfg.mode {
                    OperatingMode::Standard => "standard",
                    OperatingMode::Private => "private",
                    OperatingMode::Sovereign => "sovereign",
                },
                "provider_directory": match cfg.provider_directory_status {
                    None => "not_configured",
                    Some(ProviderDirectoryStatus::Current) => "current",
                    Some(ProviderDirectoryStatus::RetainedLastValid) => "retained_last_valid",
                    Some(ProviderDirectoryStatus::Stale) => "stale",
                    Some(ProviderDirectoryStatus::Conflict) => "conflict",
                    Some(ProviderDirectoryStatus::Unavailable) => "unavailable",
                },
                "connection": if net.connected_peer_count() > 0 {
                    "connected"
                } else if !cfg.mailboxes.is_empty()
                    || cfg.relay.is_some()
                    || cfg.mdns
                    || cfg.spool.is_some()
                    || cfg.meshtastic_serial.is_some()
                    || cfg.meshtastic_tcp.is_some()
                {
                    "fallback_ready"
                } else {
                    "waiting_for_route"
                },
                "connected_peers": net.connected_peer_count(),
                "queued": node.queued().map_err(fail)?,
                "scheduled": node.scheduled_messages().map_err(fail)?.len(),
                "transit": node.transit_queued(),
                "contacts": node.contacts().map_err(fail)?.len(),
                "mailbox": mailbox,
            }))
        }
        Op::Bundle => {
            let hints = own_hints(net, &cfg.mailboxes);
            let bundle = node
                .handshake_bundle_with_hints(&hints, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "bundle": wire::hex_encode(&bundle) }))
        }
        Op::ConnectCodeRotate => {
            let connect_code = node.rotate_connect_code(&mut OsRng).map_err(fail)?;
            let hints = own_hints(net, &cfg.mailboxes);
            let published = node
                .publish_bundle_with_policy(&hints, publication_policy(cfg), now())
                .await
                .is_ok();
            Ok(json!({
                "connect_code": connect_code,
                "legacy_discovery": false,
                "published": published,
            }))
        }
        Op::ConnectCodeRetireLegacy => {
            node.retire_legacy_discovery(&mut OsRng).map_err(fail)?;
            let hints = own_hints(net, &cfg.mailboxes);
            let published = node
                .publish_bundle_with_policy(&hints, publication_policy(cfg), now())
                .await
                .is_ok();
            Ok(json!({
                "connect_code": node.connect_code().map_err(fail)?,
                "legacy_discovery": false,
                "published": published,
            }))
        }
        Op::DeviceId => Ok(json!({ "device": wire::hex_encode(&node.device_id()) })),
        Op::LinkedDevices => Ok(json!({
            "devices": node.linked_devices().into_iter().map(|device| json!({
                "id": wire::hex_encode(&device.id),
                "name": device.name,
                "last_seen": device.last_seen,
                "revoked_at": device.revoked_at,
                "current": device.current,
            })).collect::<Vec<_>>()
        })),
        Op::DeviceAuthorityConflicts => Ok(json!({
            "conflicts": node.device_authority_conflicts().into_iter().map(|conflict| json!({
                "kind": match conflict.kind {
                    kult_node::DeviceAuthorityConflictType::Fork => "fork",
                    kult_node::DeviceAuthorityConflictType::Recovery => "recovery",
                },
                "accepted": wire::hex_encode(&conflict.accepted),
                "conflicting": wire::hex_encode(&conflict.conflicting),
                "recovery_epoch": conflict.recovery_epoch,
                "observed_at": conflict.observed_at,
            })).collect::<Vec<_>>()
        })),
        Op::ContactAuthorityConflicts => Ok(json!({
            "conflicts": node.contact_authority_conflicts().map_err(fail)?.into_iter().map(|conflict| json!({
                "account": wire::hex_encode(&conflict.account),
                "kind": match conflict.kind {
                    kult_node::DeviceAuthorityConflictType::Fork => "fork",
                    kult_node::DeviceAuthorityConflictType::Recovery => "recovery",
                },
                "accepted": wire::hex_encode(&conflict.accepted),
                "conflicting": wire::hex_encode(&conflict.conflicting),
                "recovery_epoch": conflict.recovery_epoch,
                "observed_at": conflict.observed_at,
            })).collect::<Vec<_>>()
        })),
        Op::AuthorityResetHistory => Ok(json!({
            "history": node.authority_reset_history().map_err(fail)?.map(|history| json!({
                "former_peer": wire::hex_encode(&history.former_account),
                "new_peer": wire::hex_encode(&history.new_account),
                "reset_at": history.reset_at,
                "preserved_contacts": history.preserved_contacts,
                "preserved_pairwise_messages": history.preserved_pairwise_messages,
                "preserved_note_messages": history.preserved_note_messages,
                "omitted_groups": history.omitted_groups,
                "omitted_group_messages": history.omitted_group_messages,
                "pending_reverification": history.pending_reverification
                    .iter()
                    .map(|peer| wire::hex_encode(peer))
                    .collect::<Vec<_>>(),
            }))
        })),
        Op::DeviceAuthorityApprovalRequest => {
            let request = node.device_authority_approval_request().map_err(fail)?;
            Ok(json!({ "request": wire::hex_encode(&request) }))
        }
        Op::DeviceAuthorityApprove { request } => {
            let request = wire::hex_decode(&request).ok_or("request must be hex")?;
            let approval = node
                .approve_device_authority_request(&request)
                .map_err(fail)?;
            Ok(json!({ "approval": wire::hex_encode(&approval) }))
        }
        Op::DeviceAuthorityAccept { approval } => {
            let approval = wire::hex_decode(&approval).ok_or("approval must be hex")?;
            let committed = node
                .accept_device_authority_approval(&approval, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "committed": committed }))
        }
        Op::MessageDeviceDeliveries { message } => {
            let message = wire::parse_message(&message)?;
            let deliveries = node
                .message_device_deliveries(&message)
                .map_err(fail)?
                .into_iter()
                .map(|delivery| {
                    json!({
                        "device": wire::hex_encode(&delivery.device),
                        "name": delivery.name,
                        "state": match delivery.state {
                            kult_store::DeliveryState::Queued => "queued",
                        kult_store::DeliveryState::Sent => "sent",
                        kult_store::DeliveryState::Delivered => "delivered",
                        kult_store::DeliveryState::Received => "received",
                        kult_store::DeliveryState::Failed => "failed",
                        },
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({ "deliveries": deliveries }))
        }
        Op::DeviceRename { device, name } => {
            let device = wire::parse_peer(&device)?;
            node.rename_linked_device(&device, &name, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "renamed": wire::hex_encode(&device) }))
        }
        Op::DeviceRevoke { device } => {
            let device = wire::parse_peer(&device)?;
            node.revoke_linked_device(&device, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "revoked": wire::hex_encode(&device) }))
        }
        Op::DeviceLinkBegin => {
            let offer = node.begin_device_link(now(), &mut OsRng).map_err(fail)?;
            Ok(json!({ "offer": wire::hex_encode(&offer) }))
        }
        Op::DeviceLinkAccept { offer, name } => {
            let offer = wire::hex_decode(&offer).ok_or("offer must be hex")?;
            let (response, code) = node
                .accept_device_link(&offer, &name, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "response": wire::hex_encode(&response), "code": code }))
        }
        Op::DeviceLinkCode { response } => {
            let response = wire::hex_decode(&response).ok_or("response must be hex")?;
            let code = node
                .device_link_confirmation_code(&response)
                .map_err(fail)?;
            Ok(json!({ "code": code }))
        }
        Op::DeviceLinkApprove {
            response,
            selection,
            confirmed,
        } => {
            let response = wire::hex_decode(&response).ok_or("response must be hex")?;
            let package = node
                .approve_device_link(
                    &response,
                    DeviceLinkSelection {
                        contacts: selection.contacts,
                        organization: selection.organization,
                        history: selection.history,
                    },
                    confirmed,
                    now(),
                    &mut OsRng,
                )
                .map_err(fail)?;
            Ok(json!({ "package": wire::hex_encode(&package) }))
        }
        Op::DeviceLinkApprovalRequest => {
            let request = node.device_link_approval_request().map_err(fail)?;
            Ok(json!({ "request": wire::hex_encode(&request) }))
        }
        Op::DeviceLinkApproveRequest { request } => {
            let request = wire::hex_decode(&request).ok_or("request must be hex")?;
            let approval = node.approve_device_link_request(&request).map_err(fail)?;
            Ok(json!({ "approval": wire::hex_encode(&approval) }))
        }
        Op::DeviceLinkAcceptApproval { approval } => {
            let approval = wire::hex_decode(&approval).ok_or("approval must be hex")?;
            let package = node
                .accept_device_link_approval(&approval, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "complete": package.is_some(),
                "package": package.map(|bytes| wire::hex_encode(&bytes)),
            }))
        }
        Op::DeviceLinkComplete { package, confirmed } => {
            let package = wire::hex_decode(&package).ok_or("package must be hex")?;
            node.complete_device_link(&package, confirmed, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({
                "account": wire::hex_encode(&node.peer_id()),
                "device": wire::hex_encode(&node.device_id()),
            }))
        }
        Op::DeviceSyncExport { device } => {
            let device = wire::parse_peer(&device)?;
            let bundle = node.export_device_sync(&device, &mut OsRng).map_err(fail)?;
            Ok(json!({ "bundle": wire::hex_encode(&bundle) }))
        }
        Op::DeviceSyncImport { bundle } => {
            let bundle = wire::hex_decode(&bundle).ok_or("bundle must be hex")?;
            let inserted = node.import_device_sync(&bundle, &mut OsRng).map_err(fail)?;
            Ok(json!({ "inserted": inserted }))
        }
        Op::FormatText { source, highlights } => {
            let highlights = highlights.into_iter().map(Into::into).collect::<Vec<_>>();
            let formatted = kult_node::format_text(&source, &highlights).map_err(fail)?;
            Ok(wire::formatted_text_json(&formatted))
        }
        Op::AttachmentFilePresentation {
            media_type,
            filename,
        } => Ok(wire::attachment_file_presentation_json(
            &kult_node::classify_attachment_file(&media_type, filename.as_deref()),
        )),
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
        Op::MessageRequests => Ok(json!({
            "requests": node
                .message_requests()
                .map_err(fail)?
                .iter()
                .map(wire::message_request_json)
                .collect::<Vec<_>>()
        })),
        Op::MessageRequestAccept { request, name } => {
            let request = wire::parse_request_id(&request)?;
            let peer = node
                .accept_message_request(&request, &name, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "peer": wire::hex_encode(&peer) }))
        }
        Op::MessageRequestDelete { request } => {
            let request = wire::parse_request_id(&request)?;
            node.delete_message_request(&request, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::MessageRequestBlock { request } => {
            let request = wire::parse_request_id(&request)?;
            node.block_message_request(&request, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::GroupInvitations => Ok(json!({
            "invitations": node
                .group_invitations()
                .map_err(fail)?
                .iter()
                .map(wire::group_invitation_json)
                .collect::<Vec<_>>()
        })),
        Op::GroupInvitationAccept { invitation } => {
            let invitation = wire::parse_request_id(&invitation)?;
            let group = node
                .accept_group_invitation(&invitation, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "group": wire::hex_encode(&group) }))
        }
        Op::GroupInvitationDelete { invitation } => {
            let invitation = wire::parse_request_id(&invitation)?;
            node.delete_group_invitation(&invitation, &mut OsRng)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::ContactNameAssessment { peer, name } => {
            let peer = wire::parse_peer(&peer)?;
            let assessment = node.assess_contact_name(&peer, &name).map_err(fail)?;
            Ok(wire::contact_name_assessment_json(&assessment))
        }
        Op::RenameContact {
            peer,
            name,
            accept_warnings,
        } => {
            let peer = wire::parse_peer(&peer)?;
            let assessment = node
                .rename_contact(&peer, &name, accept_warnings, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::contact_name_assessment_json(&assessment))
        }
        Op::Send { peer, body } => {
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .send_message(&peer, body.as_bytes(), now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::SendDisappearing {
            peer,
            body,
            lifetime_secs,
        } => {
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .send_disappearing_message(&peer, &body, lifetime_secs, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::EditMessage {
            peer,
            target_author,
            target_content_id,
            text,
        } => {
            let peer = wire::parse_peer(&peer)?;
            let target_author = wire::parse_peer(&target_author)?;
            let target_content_id = wire::parse_message(&target_content_id)?;
            let id = node
                .edit_message(
                    &peer,
                    target_author,
                    target_content_id,
                    &text,
                    now(),
                    &mut OsRng,
                )
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
        Op::AttachmentSendViewOnce {
            peer,
            path,
            media_type,
            filename,
            preview_path,
            preview_media_type,
            lifetime_secs,
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
                .send_view_once_attachment_with_preview(
                    &peer,
                    &metadata,
                    &mut source,
                    preview,
                    lifetime_secs,
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
        Op::GroupAttachmentSendViewOnce {
            group,
            path,
            media_type,
            filename,
            preview_path,
            preview_media_type,
            lifetime_secs,
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
                .send_group_view_once_attachment_with_preview(
                    &group,
                    &metadata,
                    &mut source,
                    preview,
                    lifetime_secs,
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
        Op::AttachmentConsumeViewOnce { transfer, path } => {
            let transfer = wire::parse_transfer(&transfer)?;
            let destination_path = std::path::Path::new(&path);
            let mut destination =
                open_private(destination_path).map_err(|e| format!("view-once open: {e}"))?;
            if let Err(error) =
                node.consume_view_once_attachment(&transfer, &mut destination, now(), &mut OsRng)
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
        Op::ScreenSecurityPolicy { platform } => {
            let platform = wire::parse_screen_security_platform(&platform)?;
            Ok(wire::screen_security_policy_json(
                &kult_node::screen_security_policy(platform),
            ))
        }
        Op::IncognitoKeyboardPolicy { platform } => {
            let platform = wire::parse_incognito_keyboard_platform(&platform)?;
            Ok(wire::incognito_keyboard_policy_json(
                &kult_node::incognito_keyboard_policy(platform),
            ))
        }
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
        Op::GroupSecurity { group } => {
            let group = wire::parse_group(&group)?;
            Ok(wire::group_security_json(
                &node.group_security_info(&group).map_err(fail)?,
            ))
        }
        Op::GroupUpgradeSecurity { group } => {
            let group = wire::parse_group(&group)?;
            node.group_upgrade_security(&group, &mut OsRng)
                .map_err(fail)?;
            Ok(wire::group_security_json(
                &node.group_security_info(&group).map_err(fail)?,
            ))
        }
        Op::GroupSend { group, body } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_send(&group, body.as_bytes(), now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupSendDisappearing {
            group,
            body,
            lifetime_secs,
        } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_send_disappearing_message(&group, &body, lifetime_secs, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupEditMessage {
            group,
            target_author,
            target_content_id,
            text,
        } => {
            let group = wire::parse_group(&group)?;
            let target_author = wire::parse_peer(&target_author)?;
            let target_content_id = wire::parse_message(&target_content_id)?;
            let id = node
                .group_edit_message(
                    &group,
                    target_author,
                    target_content_id,
                    &text,
                    now(),
                    &mut OsRng,
                )
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
        Op::GroupPollCreate {
            group,
            question,
            options,
        } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_create_poll(&group, &question, &options, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupPolls { group } => {
            let group = wire::parse_group(&group)?;
            Ok(json!({
                "polls": node
                    .group_polls(&group)
                    .map_err(fail)?
                    .iter()
                    .map(wire::poll_json)
                    .collect::<Vec<_>>(),
            }))
        }
        Op::GroupPollVote {
            group,
            poll_author,
            poll_id,
            option_id,
        } => {
            let group = wire::parse_group(&group)?;
            let poll_author = wire::parse_peer(&poll_author)?;
            let poll_id = wire::parse_message(&poll_id)?;
            let option_id = wire::parse_message(&option_id)?;
            let id = node
                .group_vote_poll(&group, poll_author, poll_id, option_id, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupPollClose {
            group,
            poll_author,
            poll_id,
        } => {
            let group = wire::parse_group(&group)?;
            let poll_author = wire::parse_peer(&poll_author)?;
            let poll_id = wire::parse_message(&poll_id)?;
            let id = node
                .group_close_poll(&group, poll_author, poll_id, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupPollModerateClose {
            group,
            poll_author,
            poll_id,
        } => {
            let group = wire::parse_group(&group)?;
            let poll_author = wire::parse_peer(&poll_author)?;
            let poll_id = wire::parse_message(&poll_id)?;
            let id = node
                .group_moderate_poll_close(&group, poll_author, poll_id, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupAuthority { group } => {
            let group = wire::parse_group(&group)?;
            Ok(wire::group_authority_json(
                &node.group_authority(&group).map_err(fail)?,
            ))
        }
        Op::GroupUpgradeAuthority { group } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_upgrade_authority(&group, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupRename { group, name } => {
            let group = wire::parse_group(&group)?;
            let id = node
                .group_rename(&group, &name, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupSetRole { group, peer, role } => {
            let group = wire::parse_group(&group)?;
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .group_set_role(&group, peer, role.into(), now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupTransferOwner { group, peer } => {
            let group = wire::parse_group(&group)?;
            let peer = wire::parse_peer(&peer)?;
            let id = node
                .group_transfer_owner(&group, peer, now(), &mut OsRng)
                .map_err(fail)?;
            Ok(json!({ "id": wire::hex_encode(&id) }))
        }
        Op::GroupAdd { group, peer } => {
            let group = wire::parse_group(&group)?;
            let peer = wire::parse_peer(&peer)?;
            node.group_add(&group, &peer, now(), &mut OsRng)
                .map_err(fail)?;
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
                .resolved_group_messages(&group)
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
        Op::Calls => Ok(json!({
            "calls": node.calls().iter().map(wire::call_json).collect::<Vec<_>>()
        })),
        Op::CallAvailability { peer } => {
            let peer = wire::parse_peer(&peer)?;
            let availability = node.call_availability(&peer, now()).map_err(fail)?;
            Ok(wire::call_availability_json(&availability))
        }
        Op::CallStart { peer } => {
            let peer = wire::parse_peer(&peer)?;
            let call = node.start_call(&peer, now(), &mut OsRng).map_err(fail)?;
            Ok(json!({ "call": wire::hex_encode(&call) }))
        }
        Op::CallAnswer { call } => {
            let call = wire::parse_call(&call)?;
            node.answer_call(&call, now(), &mut OsRng).map_err(fail)?;
            Ok(call_state_json(node, &call)?)
        }
        Op::CallDecline { call } => {
            let call = wire::parse_call(&call)?;
            node.decline_call(&call, now(), &mut OsRng).map_err(fail)?;
            Ok(call_state_json(node, &call)?)
        }
        Op::CallCancel { call } => {
            let call = wire::parse_call(&call)?;
            node.cancel_call(&call, now(), &mut OsRng).map_err(fail)?;
            Ok(call_state_json(node, &call)?)
        }
        Op::CallHangup { call } => {
            let call = wire::parse_call(&call)?;
            node.hangup_call(&call, now(), &mut OsRng).map_err(fail)?;
            Ok(call_state_json(node, &call)?)
        }
        Op::CallAudioSend {
            call,
            timestamp_ms,
            opus,
        } => {
            let call = wire::parse_call(&call)?;
            let opus = wire::hex_decode(&opus).ok_or("Opus packet must be hex")?;
            let accepted = node
                .send_call_audio(&call, timestamp_ms, &opus)
                .map_err(fail)?;
            Ok(json!({ "accepted": accepted }))
        }
        Op::CallAudioTake { call } => {
            let call = wire::parse_call(&call)?;
            let frame = node.take_call_audio(&call).map_err(fail)?;
            Ok(json!({ "frame": frame.as_ref().map(wire::call_audio_json) }))
        }
        Op::Messages { peer } => {
            let peer = wire::parse_peer(&peer)?;
            let messages: Vec<Value> = node
                .resolved_messages_with(&peer)
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
        Op::RendezvousRefresh { peer } => {
            let peer = wire::parse_peer(&peer)?;
            node.request_rendezvous_refresh(&peer).map_err(fail)?;
            Ok(json!({}))
        }
        Op::RendezvousConversationActive { peer, active } => {
            let peer = wire::parse_peer(&peer)?;
            node.set_rendezvous_conversation_active(&peer, active)
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::WakeCollect { budget_ms } => {
            if budget_ms == 0 {
                return Err("native-wake collection budget must be positive".to_owned());
            }
            let started = Instant::now();
            let budget = Duration::from_millis(u64::from(budget_ms))
                .min(kult_node::MAX_WAKE_COLLECTION_DURATION);
            let tokens = node.mailbox_tokens(now());
            for mailbox in cfg.mailboxes.iter().take(MAX_MAILBOXES_PER_CHECKIN_TICK) {
                let remaining = budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                let _ = tokio::time::timeout(
                    remaining,
                    net.mailbox_checkin(
                        mailbox,
                        &tokens[..tokens.len().min(MAX_MAILBOX_CHECKIN_TOKENS)],
                    ),
                )
                .await;
            }
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(json!({ "events": 0 }));
            }
            let batch = node
                .wake_tick(now(), remaining, &mut OsRng)
                .await
                .map_err(fail)?;
            for event in &batch {
                let _ = events.send(wire::event_line(event));
            }
            Ok(json!({ "events": batch.len() }))
        }
        Op::Publish => {
            let hints = own_hints(net, &cfg.mailboxes);
            node.publish_bundle_with_policy(&hints, publication_policy(cfg), now())
                .await
                .map_err(fail)?;
            Ok(json!({}))
        }
        Op::Backup { path } => {
            let (file, mnemonic) = node.export_backup(now(), &mut OsRng).map_err(fail)?;
            write_private(std::path::Path::new(&path), &file)
                .map_err(|e| format!("backup write: {e}"))?;
            Ok(json!({ "path": path, "mnemonic": &*mnemonic }))
        }
        Op::RecoveryAuthorityExport { path } => {
            let mnemonic = node
                .export_account_recovery_authority(std::path::Path::new(&path))
                .map_err(fail)?;
            Ok(json!({ "path": path, "mnemonic": &*mnemonic }))
        }
        // Handled at the connection layer; reaching the actor is a bug.
        Op::Subscribe => Err("subscribe is connection-level".to_owned()),
    }
}

fn call_state_json(node: &Node, call_id: &[u8; 16]) -> Result<Value, String> {
    let call = node
        .calls()
        .into_iter()
        .find(|call| &call.id == call_id)
        .ok_or_else(|| "call does not exist on this installation".to_owned())?;
    Ok(json!({ "call": wire::call_json(&call) }))
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
        tracing::warn!("no listen address bound");
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
            tracing::warn!(error = %e, "DHT bootstrap failed");
        }
        // Publish once the DHT has peers (a lone node has nowhere to put
        // records; contacts then come from out-of-band bundles instead).
        let _ = node_tx.send(NodeMsg::Publish).await;
    }

    let relay_candidate = cfg.relay.clone().or_else(|| cfg.bootstrap.first().cloned());
    let mut circuit_reserved = false;
    let mut nat_tick = tokio::time::interval(cfg.nat_interval);
    let mut checkin_tick = tokio::time::interval(cfg.checkin_interval);
    // Bootstrap-less LAN operation has no publish trigger above, yet peers
    // resolving this node's current (OS-assigned, per-run) ports depend on
    // the republished bundle. Republish whenever mDNS shows a new LAN peer:
    // the routing table just gained somewhere to put the record, and that
    // peer may hold a queued message stuck on this node's previous address.
    // Kept in lockstep with kult-ffi's lifecycle.
    let mut lan_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut lan_tick = tokio::time::interval(Duration::from_secs(15));
    let mut mailbox_cursor = 0usize;
    let mut mailbox_token_cursors: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut mailbox_retry: std::collections::HashMap<String, MailboxRetry> =
        std::collections::HashMap::new();
    let mut jitter_rng = OsRng;
    let discovery_day = Duration::from_secs(24 * 60 * 60);
    let discovery_offset = Duration::from_secs(jitter_rng.next_u64() % discovery_day.as_secs());
    let mut discovery_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + discovery_offset,
        discovery_day,
    );
    discovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = discovery_tick.tick() => {
                let _ = node_tx.send(NodeMsg::Publish).await;
            }
            _ = lan_tick.tick() => {
                let peers: std::collections::HashSet<String> =
                    net.lan_peers().into_iter().collect();
                if peers.difference(&lan_seen).next().is_some() {
                    let _ = node_tx.send(NodeMsg::Publish).await;
                }
                lan_seen = peers;
            }
            _ = nat_tick.tick() => {
                if circuit_reserved {
                    continue;
                }
                let Some(relay) = &relay_candidate else { continue };
                if let Ok(NatStatus::Private) = net.nat_status().await {
                    match net.reserve_relay(relay).await {
                        Ok(circuit) => {
                            tracing::info!(%circuit, "NAT-ed; reserved relay circuit");
                            circuit_reserved = true;
                            // The circuit is a new listen address — republish.
                            let _ = node_tx.send(NodeMsg::Publish).await;
                        }
                        Err(e) => tracing::warn!(error = %e, "relay reservation failed"),
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
                let mailboxes = rotating_batch(
                    &cfg.mailboxes,
                    &mut mailbox_cursor,
                    MAX_MAILBOXES_PER_CHECKIN_TICK,
                );
                for mailbox in mailboxes {
                    if mailbox_retry
                        .get(&mailbox)
                        .is_some_and(|retry| retry.next_at > Instant::now())
                    {
                        continue;
                    }
                    let token_cursor = mailbox_token_cursors
                        .entry(mailbox.clone())
                        .or_default();
                    let token_batch =
                        rotating_batch(&tokens, token_cursor, MAX_MAILBOX_CHECKIN_TOKENS);
                    // One bounded page per mailbox and lifecycle interval.
                    // A relay that never returns empty cannot monopolize this
                    // task or grow the local receive queue without a limit.
                    let result = net.mailbox_checkin(&mailbox, &token_batch).await;
                    let retry = mailbox_retry.entry(mailbox.clone()).or_insert(MailboxRetry {
                        failures: 0,
                        next_at: Instant::now(),
                    });
                    match result {
                        Ok(count) if count > 0 => {
                            retry.failures = 0;
                            retry.next_at = Instant::now()
                                + jittered_mailbox_delay(
                                    cfg.checkin_interval,
                                    0,
                                    jitter_rng.next_u64(),
                                );
                            log_mailbox_page_collected(count);
                        }
                        Ok(_) => {
                            retry.failures = 0;
                            retry.next_at = Instant::now()
                                + jittered_mailbox_delay(
                                    cfg.checkin_interval,
                                    0,
                                    jitter_rng.next_u64(),
                                );
                        }
                        Err(_) => {
                            retry.failures = retry.failures.saturating_add(1);
                            retry.next_at = Instant::now()
                                + jittered_mailbox_delay(
                                    cfg.checkin_interval,
                                    retry.failures,
                                    jitter_rng.next_u64(),
                                );
                            log_mailbox_checkin_failed();
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
    ready: oneshot::Sender<()>,
) {
    let _ = ready.send(());
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

#[cfg(test)]
mod socket_tests {
    use super::*;

    #[tokio::test]
    async fn live_rpc_socket_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kultd.sock");
        let (listener, guard) = bind_rpc_socket(&path).await.unwrap();

        let error = bind_rpc_socket(&path).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);

        // The original listener remains reachable at the same pathname.
        let client = UnixStream::connect(&path).await.unwrap();
        drop(client);
        drop(listener);
        guard.remove_owned();
    }

    #[tokio::test]
    async fn stale_rpc_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kultd.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists());

        let (listener, guard) = bind_rpc_socket(&path).await.unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        drop(client);
        drop(listener);
        guard.remove_owned();
    }

    #[tokio::test]
    async fn regular_file_at_rpc_path_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kultd.sock");
        std::fs::write(&path, b"operator-owned").unwrap();

        assert!(bind_rpc_socket(&path).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"operator-owned");
    }

    #[tokio::test]
    async fn concurrent_stale_recovery_has_one_reachable_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kultd.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);

        let (left, right) = tokio::join!(bind_rpc_socket(&path), bind_rpc_socket(&path));
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let (listener, guard) = left.or(right).unwrap();
        let client = UnixStream::connect(&path).await.unwrap();
        drop(client);
        drop(listener);
        guard.remove_owned();
    }

    #[test]
    fn rpc_lock_refuses_a_symlink_and_normalizes_existing_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("kultd.sock");
        let lock_path = dir.path().join("kultd.sock.lock");
        let target = dir.path().join("unrelated");
        std::fs::write(&target, b"preserve").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &lock_path).unwrap();
        assert!(acquire_rpc_lock(&socket).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );

        std::fs::remove_file(&lock_path).unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let lock = acquire_rpc_lock(&socket).unwrap();
        assert_eq!(lock.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::io::Write;

    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn rotating_batches_cover_large_mailbox_and_token_sets_without_starvation() {
        let mailboxes: Vec<usize> = (0..10).collect();
        let mut mailbox_cursor = 0;
        assert_eq!(
            rotating_batch(
                &mailboxes,
                &mut mailbox_cursor,
                MAX_MAILBOXES_PER_CHECKIN_TICK
            ),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(
            rotating_batch(
                &mailboxes,
                &mut mailbox_cursor,
                MAX_MAILBOXES_PER_CHECKIN_TICK
            ),
            vec![8, 9]
        );

        let tokens: Vec<usize> = (0..(MAX_MAILBOX_CHECKIN_TOKENS + 17)).collect();
        let mut token_cursor = 0;
        let first = rotating_batch(&tokens, &mut token_cursor, MAX_MAILBOX_CHECKIN_TOKENS);
        let second = rotating_batch(&tokens, &mut token_cursor, MAX_MAILBOX_CHECKIN_TOKENS);
        assert_eq!(first.len(), MAX_MAILBOX_CHECKIN_TOKENS);
        assert_eq!(second, tokens[MAX_MAILBOX_CHECKIN_TOKENS..]);
        assert_eq!(token_cursor, 0);
    }

    #[test]
    fn mailbox_backoff_is_jittered_bounded_and_exponential() {
        let base = Duration::from_secs(10);
        let first = jittered_mailbox_delay(base, 0, 0);
        let second = jittered_mailbox_delay(base, 1, 0);
        assert_eq!(first, Duration::from_millis(7_500));
        assert_eq!(second, Duration::from_secs(15));
        assert!(
            jittered_mailbox_delay(base, 8, 50) <= MAX_MAILBOX_BACKOFF.saturating_mul(125) / 100
        );
        assert_ne!(
            jittered_mailbox_delay(base, 2, 0),
            jittered_mailbox_delay(base, 2, 50)
        );
    }

    #[test]
    fn mailbox_operational_logs_are_aggregate_only() {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_mailbox_page_collected(7);
            log_mailbox_checkin_failed();
        });

        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("mailbox page collected"));
        assert!(output.contains("count=7"));
        assert!(output.contains("mailbox check-in failed"));
        assert_eq!(output.matches('=').count(), 1);
        for forbidden in [
            "/p2p/",
            "token",
            "locator",
            "ciphertext",
            "row_id",
            "identity",
            "contact",
        ] {
            assert!(!output.contains(forbidden));
        }
    }
}
