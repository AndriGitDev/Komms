use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{Config, RoleSelection};
use crate::dht::DhtService;
use crate::http::{probe_health as probe, run_health, RendezvousNetwork};
use crate::keys::{inspect_selected_service_keys, load_libp2p_identity, load_tls_server_config};

/// One aggregate, content-free service health snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Cached Kademlia rows.
    pub dht_records: usize,
    /// Cached Kademlia value bytes.
    pub dht_value_bytes: usize,
    /// Retained rendezvous rows.
    pub rendezvous_records: usize,
    /// Conservatively accounted rendezvous mutable bytes.
    pub rendezvous_mutable_bytes: usize,
}

/// Configuration, key, listener, or runtime failure without request metadata.
#[derive(Debug)]
pub struct ServiceError {
    message: String,
}

impl ServiceError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn io(context: &str, error: std::io::Error) -> Self {
        Self::invalid(format!("{context}: {error}"))
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Run the original combined two-role profile until SIGINT or SIGTERM, then
/// tear down all mutable in-memory state within the configured grace period.
pub async fn run(config: Config) -> Result<(), ServiceError> {
    run_selected(config, RoleSelection::Both).await
}

/// Run only the selected bounded role set. A one-role process does not load,
/// open, or require the other role's service credential.
pub async fn run_selected(config: Config, roles: RoleSelection) -> Result<(), ServiceError> {
    config.validate()?;
    let key_info = inspect_selected_service_keys(&config, roles)?;
    let dht = if roles.includes_dht() {
        let identity = load_libp2p_identity(&config.libp2p_identity_file)?;
        Some(DhtService::new(config.dht.clone(), identity)?)
    } else {
        None
    };
    let dht_metrics = dht.as_ref().map(DhtService::metrics);
    let (rendezvous, rendezvous_metrics, tls) = if roles.includes_rendezvous() {
        let network = RendezvousNetwork::new(config.rendezvous.clone())?;
        let metrics = network.service();
        let tls = load_tls_server_config(&config)?;
        (Some(network), Some(metrics), Some(tls))
    } else {
        (None, None, None)
    };
    let health_address = config.rendezvous.health_listen;
    let shutdown_grace = Duration::from_secs(config.runtime.shutdown_grace_seconds);
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    if let Some(dht) = dht {
        tasks.spawn(dht.run(shutdown_receiver.clone()));
    }
    if let (Some(rendezvous), Some(tls)) = (rendezvous, tls) {
        tasks.spawn(rendezvous.run(tls, shutdown_receiver.clone()));
    }
    tasks.spawn(run_health(
        health_address,
        roles,
        dht_metrics,
        rendezvous_metrics,
        shutdown_receiver,
    ));

    eprintln!(
        "reference service starting: roles={} peer_id={} libp2p_public_key_sha256={} tls_certificate_sha256={}",
        roles.log_label(),
        present_or_disabled(&key_info.libp2p_peer_id),
        present_or_disabled(&key_info.libp2p_public_key_sha256),
        present_or_disabled(&key_info.tls_certificate_sha256),
    );

    let mut early_failure = None;
    tokio::select! {
        () = shutdown_signal() => {}
        result = tasks.join_next() => {
            early_failure = Some(join_result(result));
        }
    }
    let _ = shutdown_sender.send(true);

    let drain = async {
        while let Some(result) = tasks.join_next().await {
            let result = join_result(Some(result));
            if early_failure.is_none() && result.is_err() {
                early_failure = Some(result);
            }
        }
    };
    if tokio::time::timeout(shutdown_grace, drain).await.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        return Err(ServiceError::invalid(
            "reference service exceeded shutdown grace",
        ));
    }
    if let Some(result) = early_failure {
        result?;
    }
    Ok(())
}

fn present_or_disabled(value: &str) -> &str {
    if value.is_empty() {
        "disabled"
    } else {
        value
    }
}

/// Probe the loopback-only aggregate health endpoint.
pub async fn probe_health(address: SocketAddr) -> Result<(), ServiceError> {
    probe(address).await
}

fn join_result(
    result: Option<Result<Result<(), ServiceError>, tokio::task::JoinError>>,
) -> Result<(), ServiceError> {
    match result {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(ServiceError::invalid(format!(
            "reference service task stopped: {error}"
        ))),
        None => Err(ServiceError::invalid(
            "reference service stopped before shutdown",
        )),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
