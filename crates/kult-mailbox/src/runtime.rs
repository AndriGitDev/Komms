use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use kult_transport::{
    initialize_mailbox_service, inspect_mailbox_service, MailboxServiceMetrics, MailboxV2Service,
};

use crate::config::DEFAULT_SOURCE_REVISION;
use crate::Config;

const HEALTH_REQUEST_MAX_BYTES: usize = 2048;
const HEALTH_RESPONSE_MAX_BYTES: usize = 4096;
const HEALTH_DEADLINE: Duration = Duration::from_secs(3);

/// Result type for the standalone mailbox service.
pub type Result<T> = std::result::Result<T, MailboxError>;

/// Configuration, durable-state, listener, or runtime failure.
#[derive(Debug)]
pub struct MailboxError {
    message: String,
}

impl MailboxError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for MailboxError {}

impl From<std::io::Error> for MailboxError {
    fn from(error: std::io::Error) -> Self {
        Self::invalid(error.to_string())
    }
}

impl From<kult_transport::TransportError> for MailboxError {
    fn from(error: kult_transport::TransportError) -> Self {
        Self::invalid(error.to_string())
    }
}

/// Non-secret inspection result for an operator record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxServiceInspection {
    /// Stable transport-only libp2p peer id.
    pub peer_id: String,
    /// Durable mailbox schema version.
    pub schema_version: u32,
}

/// Initialize new service-only key material and an empty durable database.
pub fn initialize(config: &Config) -> Result<MailboxServiceInspection> {
    config.validate()?;
    let info = initialize_mailbox_service(&config.service_config())?;
    Ok(MailboxServiceInspection {
        peer_id: info.peer_id,
        schema_version: info.schema_version,
    })
}

/// Inspect existing service-only key material and durable schema.
pub fn inspect(config: &Config) -> Result<MailboxServiceInspection> {
    config.validate()?;
    let info = inspect_mailbox_service(&config.service_config())?;
    Ok(MailboxServiceInspection {
        peer_id: info.peer_id,
        schema_version: info.schema_version,
    })
}

/// Run the mailbox-only libp2p service and loopback aggregate health endpoint
/// until SIGINT or SIGTERM.
pub async fn run(config: Config) -> Result<()> {
    config.validate()?;
    let inspection = inspect(&config)?;
    let service = MailboxV2Service::start(config.listen(), config.service_config()).await?;
    let metrics = service.metrics();
    let (health_shutdown, health_receiver) = watch::channel(false);
    let health_address = config.health_listen();
    let health_task = tokio::spawn(run_health(health_address, metrics, health_receiver));

    eprintln!(
        "mailbox service starting: peer_id={} schema_version={} source_revision={}",
        inspection.peer_id,
        inspection.schema_version,
        safe_revision(DEFAULT_SOURCE_REVISION)
    );

    let service_stopped_early = loop {
        tokio::select! {
            () = shutdown_signal() => break false,
            () = tokio::time::sleep(Duration::from_millis(250)) => {
                if service.is_finished() {
                    break true;
                }
                if health_task.is_finished() {
                    break false;
                }
            }
        }
    };
    let _ = health_shutdown.send(true);
    let shutdown = async {
        service.shutdown().await?;
        health_task.await.map_err(|error| {
            MailboxError::invalid(format!("mailbox health task stopped: {error}"))
        })??;
        Ok::<_, MailboxError>(())
    };
    tokio::time::timeout(config.shutdown_grace(), shutdown)
        .await
        .map_err(|_| MailboxError::invalid("mailbox service exceeded its shutdown grace"))??;
    if service_stopped_early {
        return Err(MailboxError::invalid(
            "mailbox network service stopped before shutdown",
        ));
    }
    Ok(())
}

/// Query the loopback-only aggregate health endpoint.
pub async fn probe_health(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() {
        return Err(MailboxError::invalid(
            "mailbox health probe address must be loopback",
        ));
    }
    let mut stream = tokio::time::timeout(HEALTH_DEADLINE, TcpStream::connect(address))
        .await
        .map_err(|_| MailboxError::invalid("mailbox health probe connection deadline"))??;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let response = tokio::time::timeout(HEALTH_DEADLINE, async {
        let mut bytes = Vec::with_capacity(HEALTH_RESPONSE_MAX_BYTES);
        let mut chunk = [0u8; 256];
        loop {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > HEALTH_RESPONSE_MAX_BYTES {
                return Err(MailboxError::invalid(
                    "mailbox health response exceeds its bound",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok::<_, MailboxError>(bytes)
    })
    .await
    .map_err(|_| MailboxError::invalid("mailbox health probe response deadline"))??;
    if !response.starts_with(b"HTTP/1.1 200 OK\r\n")
        || !response
            .windows(b"\"status\":\"ready\"".len())
            .any(|window| window == b"\"status\":\"ready\"")
    {
        return Err(MailboxError::invalid(
            "mailbox health endpoint did not report ready",
        ));
    }
    Ok(())
}

async fn run_health(
    address: SocketAddr,
    metrics: MailboxServiceMetrics,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let _ = tokio::time::timeout(
                    HEALTH_DEADLINE,
                    serve_health(stream, &metrics),
                ).await;
            }
        }
    }
    Ok(())
}

async fn serve_health(mut stream: TcpStream, metrics: &MailboxServiceMetrics) -> Result<()> {
    let mut request = [0u8; HEALTH_REQUEST_MAX_BYTES];
    let count = stream.read(&mut request).await?;
    let valid = count > 0
        && request[..count].starts_with(b"GET /healthz HTTP/1.1\r\n")
        && request[..count]
            .windows(b"\r\n\r\n".len())
            .any(|window| window == b"\r\n\r\n");
    if !valid {
        stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    let snapshot = metrics.snapshot()?;
    let body = serde_json::json!({
        "status": "ready",
        "schema_version": snapshot.schema_version,
        "stored_items": snapshot.stored_items,
        "stored_bytes": snapshot.stored_bytes,
        "capacity_items": snapshot.capacity_items,
        "capacity_bytes": snapshot.capacity_bytes,
        "registrations": snapshot.registrations,
        "live_leases": snapshot.live_leases,
        "lease_capacity": snapshot.lease_capacity,
        "rejected_deposits": snapshot.rejected_deposits,
        "rejected_requests": snapshot.rejected_requests,
        "expired_rows": snapshot.expired_rows,
        "disk_available_bytes": snapshot.disk_available_bytes,
        "source_revision": safe_revision(DEFAULT_SOURCE_REVISION),
    })
    .to_string();
    if body.len() > HEALTH_RESPONSE_MAX_BYTES / 2 {
        return Err(MailboxError::invalid(
            "mailbox health body exceeds its fixed bound",
        ));
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn safe_revision(revision: &str) -> &str {
    if !revision.is_empty()
        && revision.len() <= 128
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        revision
    } else {
        "invalid-build-revision"
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
