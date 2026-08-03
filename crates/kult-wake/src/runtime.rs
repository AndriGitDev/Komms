use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use crate::config::DEFAULT_SOURCE_REVISION;
use crate::native_provider::HttpNativePushProvider;
use crate::{
    run_tls_gateway, Config, FileCapabilityKeyring, GatewayMetrics, GatewayStateStore, Result,
    WakeError, WakeGateway,
};

const MAX_TLS_CERTIFICATE_BYTES: u64 = 128 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES: u64 = 32 * 1024;
const MAX_CERTIFICATES: usize = 8;
const HEALTH_REQUEST_BYTES: usize = 2048;
const HEALTH_RESPONSE_MAX_BYTES: usize = 4096;
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Non-secret service-key fingerprints for an operator record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeServiceKeyInfo {
    /// SHA-256 of the first TLS certificate's DER encoding.
    pub tls_certificate_sha256: String,
    /// Non-zero active capability-encryption key id.
    pub active_capability_key_id: u32,
    /// Loaded capability key ids and SHA-256 fingerprints, sorted by id.
    pub capability_keys: Vec<String>,
}

/// Load and validate configuration plus all credential material without
/// opening a listener or contacting a native provider.
pub fn check_configuration(path: &Path) -> Result<WakeServiceKeyInfo> {
    let config = Config::open(path)?;
    inspect_configuration(&config)
}

/// Inspect validated service credentials and return only non-secret metadata.
pub fn inspect_configuration(config: &Config) -> Result<WakeServiceKeyInfo> {
    config.validate()?;
    let keyring = FileCapabilityKeyring::open(
        config.active_capability_key_id,
        &config.capability_key_files,
    )?;
    let (certificates, private_key) = load_tls_material(config)?;
    build_server_config(certificates.clone(), private_key)?;
    let _provider = HttpNativePushProvider::open(&config.provider)?;
    let leaf = certificates
        .first()
        .ok_or(WakeError::Invalid("wake TLS certificate chain is empty"))?;
    Ok(WakeServiceKeyInfo {
        tls_certificate_sha256: hex::encode(Sha256::digest(leaf.as_ref())),
        active_capability_key_id: config.active_capability_key_id,
        capability_keys: keyring
            .metadata()
            .iter()
            .map(|metadata| format!("{}:{}", metadata.key_id, hex::encode(metadata.fingerprint)))
            .collect(),
    })
}

/// Run the bounded native-wake gateway until SIGINT or SIGTERM.
pub async fn run(config: Config) -> Result<()> {
    config.validate()?;
    let key_info = inspect_configuration(&config)?;
    let keys = Arc::new(FileCapabilityKeyring::open(
        config.active_capability_key_id,
        &config.capability_key_files,
    )?);
    let state = GatewayStateStore::open(
        &config.state_file,
        config.state.max_revocations,
        config.state.max_replays,
    )?;
    let provider = Arc::new(HttpNativePushProvider::open(&config.provider)?);
    let gateway = Arc::new(WakeGateway::new(
        keys,
        state,
        provider,
        config.gateway_limits()?,
        &mut OsRng,
    )?);
    let tls = load_tls_server_config(&config)?;
    let network = config.network_config()?;
    let health_address = config.network.health_listen;
    let shutdown_grace = Duration::from_secs(config.runtime.shutdown_grace_seconds);
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut tasks = JoinSet::new();
    tasks.spawn(run_tls_gateway(
        network,
        tls,
        Arc::clone(&gateway),
        shutdown_receiver.clone(),
    ));
    tasks.spawn(run_health(health_address, gateway, shutdown_receiver));

    eprintln!(
        "wake gateway starting: tls_certificate_sha256={} active_capability_key_id={} source_revision={}",
        key_info.tls_certificate_sha256,
        key_info.active_capability_key_id,
        safe_revision(DEFAULT_SOURCE_REVISION)
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
        return Err(WakeError::Invalid(
            "wake gateway exceeded its shutdown grace",
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
        return Err(WakeError::Invalid(
            "wake health probe address must be loopback",
        ));
    }
    let mut socket = tokio::time::timeout(HEALTH_REQUEST_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| WakeError::Invalid("wake health probe connection deadline"))??;
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
                return Err(WakeError::Invalid(
                    "wake health probe response exceeds its bound",
                ));
            }
            response.extend_from_slice(&chunk[..read]);
        }
        Ok::<_, WakeError>(response)
    })
    .await
    .map_err(|_| WakeError::Invalid("wake health probe response deadline"))??;
    if !response.starts_with(b"HTTP/1.1 200 OK\r\n")
        || !response
            .windows(b"\"status\":\"ready\"".len())
            .any(|window| window == b"\"status\":\"ready\"")
    {
        return Err(WakeError::Invalid("wake health probe was not ready"));
    }
    Ok(())
}

fn load_tls_server_config(config: &Config) -> Result<Arc<rustls::ServerConfig>> {
    let (certificates, private_key) = load_tls_material(config)?;
    build_server_config(certificates, private_key).map(Arc::new)
}

fn load_tls_material(
    config: &Config,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certificate_bytes = read_bounded_regular(
        &config.tls_certificate_file,
        MAX_TLS_CERTIFICATE_BYTES,
        false,
        "wake TLS certificate",
    )?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| WakeError::Invalid("wake TLS certificate encoding is invalid"))?;
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
        return Err(WakeError::Invalid(
            "wake TLS certificate chain count is outside 1..=8",
        ));
    }
    let private_bytes = read_bounded_regular(
        &config.tls_private_key_file,
        MAX_TLS_PRIVATE_KEY_BYTES,
        true,
        "wake TLS private key",
    )?;
    let mut private_keys = PrivatePkcs8KeyDer::pem_slice_iter(&private_bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| WakeError::Invalid("wake TLS private key encoding is invalid"))?;
    if private_keys.len() != 1 {
        return Err(WakeError::Invalid(
            "wake TLS private key file must contain exactly one PKCS#8 key",
        ));
    }
    Ok((certificates, PrivateKeyDer::Pkcs8(private_keys.remove(0))))
}

fn build_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| WakeError::Invalid("wake TLS 1.3 configuration failed"))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| WakeError::Invalid("wake TLS certificate/key mismatch"))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok(server)
}

fn read_bounded_regular(
    path: &Path,
    max_bytes: u64,
    secret: bool,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WakeError::Configuration(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(WakeError::Configuration(format!(
            "{label} size is outside its bound"
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > max_bytes {
        return Err(WakeError::Configuration(format!(
            "{label} must remain a bounded regular file"
        )));
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            return Err(WakeError::Configuration(format!(
                "{label} must not be group- or world-accessible"
            )));
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
    file.by_ref().take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(WakeError::Configuration(format!(
            "{label} size is outside its bound"
        )));
    }
    Ok(bytes)
}

async fn run_health(
    address: SocketAddr,
    gateway: Arc<WakeGateway>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !address.ip().is_loopback() {
        return Err(WakeError::Invalid(
            "wake health listener escaped the loopback boundary",
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
                let metrics = gateway.metrics();
                let counts = gateway.state_counts(unix_now())?;
                let _ = tokio::time::timeout(
                    HEALTH_REQUEST_TIMEOUT,
                    serve_health_request(&mut socket, metrics, counts.revocations, counts.replays),
                ).await;
            }
        }
    }
    Ok(())
}

async fn serve_health_request(
    socket: &mut TcpStream,
    metrics: GatewayMetrics,
    revocations: usize,
    replays: usize,
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
    let revision = safe_revision(DEFAULT_SOURCE_REVISION);
    let body = format!(
        concat!(
            "{{\"status\":\"ready\",\"role\":\"native-wake\",",
            "\"source_revision\":\"{}\",",
            "\"durable_revocations\":{},\"durable_replays\":{},",
            "\"capabilities_issued\":{},\"registrations_refused\":{},",
            "\"malformed_requests\":{},\"invalid_capabilities\":{},",
            "\"expired_capabilities\":{},\"revoked_capabilities\":{},",
            "\"replayed_requests\":{},\"coalesced_requests\":{},",
            "\"rate_limited_requests\":{},\"provider_successes\":{},",
            "\"provider_unavailable\":{},\"provider_rate_limited\":{},",
            "\"provider_authentication\":{},\"provider_invalid_destination\":{},",
            "\"provider_other\":{},\"capabilities_revoked\":{}}}\n"
        ),
        revision,
        revocations,
        replays,
        metrics.capabilities_issued,
        metrics.registrations_refused,
        metrics.malformed_requests,
        metrics.invalid_capabilities,
        metrics.expired_capabilities,
        metrics.revoked_capabilities,
        metrics.replayed_requests,
        metrics.coalesced_requests,
        metrics.rate_limited_requests,
        metrics.provider_successes,
        metrics.provider_unavailable,
        metrics.provider_rate_limited,
        metrics.provider_authentication,
        metrics.provider_invalid_destination,
        metrics.provider_other,
        metrics.capabilities_revoked,
    );
    if body.len() > HEALTH_RESPONSE_MAX_BYTES {
        return Err(WakeError::Invalid("wake health response exceeds its bound"));
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
        Some(Err(_)) => Err(WakeError::Invalid("wake gateway task stopped unexpectedly")),
        None => Err(WakeError::Invalid("wake gateway stopped before shutdown")),
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_health_value_cannot_inject_json() {
        assert_eq!(safe_revision("abc123"), "abc123");
        assert_eq!(
            safe_revision("revision\"with-json"),
            "invalid-build-revision"
        );
    }
}
