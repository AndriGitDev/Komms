use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::DEFAULT_SOURCE_REVISION;
use crate::network::run_tls_relay;
use crate::relay::RelayService;
use crate::tls::{
    load_gateway_ca_bytes, load_gateway_config, load_leaf_certificate, load_server_config,
};
use crate::{Config, RelayError, Result};

const HEALTH_REQUEST_BYTES: usize = 2048;
const HEALTH_RESPONSE_MAX_BYTES: usize = 4096;
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Non-secret service and fixed-mapping fingerprints for an operator record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayServiceKeyInfo {
    /// SHA-256 of the first relay TLS certificate's DER encoding.
    pub tls_certificate_sha256: String,
    /// SHA-256 of the exact configured gateway CA bundle bytes.
    pub gateway_ca_bundle_sha256: String,
    /// SHA-256 of the canonical public-resource to fixed-gateway mapping.
    pub mapping_sha256: String,
}

/// Load and validate configuration plus all TLS material without opening a
/// listener or contacting the gateway.
pub fn check_configuration(path: &Path) -> Result<RelayServiceKeyInfo> {
    let config = Config::open(path)?;
    inspect_configuration(&config)
}

/// Inspect validated service credentials and return only non-secret metadata.
pub fn inspect_configuration(config: &Config) -> Result<RelayServiceKeyInfo> {
    config.validate()?;
    let _server = load_server_config(config)?;
    let _gateway = load_gateway_config(config)?;
    let leaf = load_leaf_certificate(config)?;
    let gateway_ca = load_gateway_ca_bytes(config)?;
    let mapping = config.public_mapping();
    Ok(RelayServiceKeyInfo {
        tls_certificate_sha256: hex::encode(Sha256::digest(leaf.as_ref())),
        gateway_ca_bundle_sha256: hex::encode(Sha256::digest(&*gateway_ca)),
        mapping_sha256: hex::encode(Sha256::digest(mapping.as_bytes())),
    })
}

/// Run the bounded fixed-mapping OHTTP relay until SIGINT or SIGTERM.
pub async fn run(config: Config) -> Result<()> {
    config.validate()?;
    let key_info = inspect_configuration(&config)?;
    let tls = load_server_config(&config)?;
    let relay = Arc::new(RelayService::open(&config)?);
    let network = config.network.clone();
    let request_bytes = config.upstream.encapsulated_request_bytes;
    let exchange_bytes = request_bytes
        .checked_add(config.upstream.encapsulated_response_bytes)
        .ok_or(RelayError::Invalid("fixed OHTTP exchange size overflows"))?;
    let health_address = config.network.health_listen;
    let shutdown_grace = config.runtime.shutdown_grace();
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut tasks = JoinSet::new();
    tasks.spawn(run_tls_relay(
        network,
        request_bytes,
        exchange_bytes,
        tls,
        Arc::clone(&relay),
        shutdown_receiver.clone(),
    ));
    tasks.spawn(run_health(health_address, relay, shutdown_receiver));

    eprintln!(
        "OHTTP relay starting: tls_certificate_sha256={} gateway_ca_bundle_sha256={} mapping_sha256={} source_revision={}",
        key_info.tls_certificate_sha256,
        key_info.gateway_ca_bundle_sha256,
        key_info.mapping_sha256,
        safe_revision(DEFAULT_SOURCE_REVISION),
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
        return Err(RelayError::Invalid(
            "OHTTP relay exceeded its shutdown grace",
        ));
    }
    if let Some(result) = early_failure {
        result?;
    }
    Ok(())
}

/// Query the loopback-only aggregate health endpoint.
pub async fn probe_health(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() {
        return Err(RelayError::Invalid(
            "relay health probe address must be loopback",
        ));
    }
    let mut socket = tokio::time::timeout(HEALTH_REQUEST_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| RelayError::Invalid("relay health probe connection deadline"))??;
    socket
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let response = tokio::time::timeout(HEALTH_REQUEST_TIMEOUT, async {
        let mut response = Vec::with_capacity(HEALTH_RESPONSE_MAX_BYTES);
        let mut chunk = [0u8; 256];
        loop {
            let read = socket.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            if response.len().saturating_add(read) > HEALTH_RESPONSE_MAX_BYTES {
                return Err(RelayError::Invalid(
                    "relay health probe response exceeds its bound",
                ));
            }
            response.extend_from_slice(&chunk[..read]);
        }
        Ok::<_, RelayError>(response)
    })
    .await
    .map_err(|_| RelayError::Invalid("relay health probe response deadline"))??;
    if !response.starts_with(b"HTTP/1.1 200 OK\r\n")
        || !response
            .windows(b"\"status\":\"ready\"".len())
            .any(|window| window == b"\"status\":\"ready\"")
    {
        return Err(RelayError::Invalid("relay health probe was not ready"));
    }
    Ok(())
}

async fn run_health(
    address: SocketAddr,
    relay: Arc<RelayService>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !address.ip().is_loopback() {
        return Err(RelayError::Invalid(
            "relay health listener escaped the loopback boundary",
        ));
    }
    let listener = TcpListener::bind(address).await?;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut socket, remote) = accepted?;
                if !remote.ip().is_loopback() {
                    drop(socket);
                    continue;
                }
                let metrics = relay.metrics().snapshot();
                let _ = tokio::time::timeout(
                    HEALTH_REQUEST_TIMEOUT,
                    serve_health_request(&mut socket, metrics),
                ).await;
            }
        }
    }
    Ok(())
}

async fn serve_health_request(
    socket: &mut TcpStream,
    metrics: crate::relay::RelayMetricsSnapshot,
) -> Result<()> {
    let mut request = [0u8; HEALTH_REQUEST_BYTES];
    let read = socket.read(&mut request).await?;
    let valid = request[..read].starts_with(b"GET /healthz HTTP/1.1\r\n")
        && request[..read]
            .windows(4)
            .any(|window| window == b"\r\n\r\n");
    if !valid {
        socket
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    let body = format!(
        concat!(
            "{{\"status\":\"ready\",\"role\":\"ohttp-relay\",",
            "\"source_revision\":\"{}\",",
            "\"accepted_connections\":{},\"overload_refusals\":{},",
            "\"tls_failures\":{},\"malformed_requests\":{},",
            "\"forwarded_requests\":{},\"successful_responses\":{},",
            "\"gateway_failures\":{}}}\n"
        ),
        safe_revision(DEFAULT_SOURCE_REVISION),
        metrics.accepted_connections,
        metrics.overload_refusals,
        metrics.tls_failures,
        metrics.malformed_requests,
        metrics.forwarded_requests,
        metrics.successful_responses,
        metrics.gateway_failures,
    );
    if body.len() > HEALTH_RESPONSE_MAX_BYTES {
        return Err(RelayError::Invalid(
            "relay health response exceeds its bound",
        ));
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(body.as_bytes()).await?;
    Ok(())
}

fn join_result(
    result: Option<core::result::Result<Result<()>, tokio::task::JoinError>>,
) -> Result<()> {
    match result {
        Some(Ok(result)) => result,
        Some(Err(_)) => Err(RelayError::Invalid("OHTTP relay task stopped unexpectedly")),
        None => Err(RelayError::Invalid("OHTTP relay stopped before shutdown")),
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

fn safe_revision(revision: &str) -> &str {
    if !revision.is_empty()
        && revision.len() <= 64
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        revision
    } else {
        "invalid-build-revision"
    }
}
