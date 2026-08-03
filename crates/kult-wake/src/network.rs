use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use kult_protocol::{
    wake_generic_response, WAKE_GENERIC_RESPONSE_LEN, WAKE_MEDIA_TYPE, WAKE_REGISTER_PATH,
    WAKE_REGISTER_REQUEST_LEN, WAKE_REGISTER_RESPONSE_LEN, WAKE_REVOKE_PATH, WAKE_TRIGGER_PATH,
    WAKE_TRIGGER_REQUEST_LEN,
};

use crate::{Result, WakeError, WakeGateway};

type HmacSha256 = Hmac<Sha256>;

const MAX_HTTP_HEADER_BYTES: usize = 4 * 1024;
const RATE_WINDOW_SECS: u64 = 60;

/// Strict bounded TLS listener policy for the wake gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeNetworkConfig {
    /// TLS listener address.
    pub listen: SocketAddr,
    /// Maximum concurrent TLS/request tasks.
    pub max_connections: usize,
    /// Accepted connections across the listener in one fixed minute.
    pub max_connections_per_minute: u32,
    /// Accepted connections per ephemeral source bucket in one fixed minute.
    pub max_connections_per_source_per_minute: u32,
    /// Maximum in-memory source rate buckets.
    pub max_source_buckets: usize,
    /// TLS handshake deadline.
    pub tls_handshake_timeout: Duration,
    /// Complete single-request deadline after TLS.
    pub request_timeout: Duration,
}

impl Default for WakeNetworkConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7444".parse().expect("literal address"),
            max_connections: 256,
            max_connections_per_minute: 30_000,
            max_connections_per_source_per_minute: 120,
            max_source_buckets: 65_536,
            tls_handshake_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
        }
    }
}

impl WakeNetworkConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.listen.port() == 0
            || self.max_connections == 0
            || self.max_connections > 16_384
            || self.max_connections_per_minute == 0
            || self.max_connections_per_source_per_minute == 0
            || self.max_source_buckets == 0
            || self.max_source_buckets > 1_000_000
            || self.tls_handshake_timeout.is_zero()
            || self.tls_handshake_timeout > Duration::from_secs(60)
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(60)
        {
            return Err(WakeError::Invalid("wake network limits are invalid"));
        }
        Ok(())
    }
}

/// Run the in-process TLS wake listener until shutdown.
///
/// Request bodies and source addresses are never logged or returned in an
/// error. Malformed requests receive the same fixed 202 response.
pub async fn run_tls_gateway(
    config: WakeNetworkConfig,
    tls: Arc<rustls::ServerConfig>,
    gateway: Arc<WakeGateway>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    config.validate()?;
    let listener = TcpListener::bind(config.listen).await?;
    let acceptor = TlsAcceptor::from(tls);
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut source_secret = [0u8; 32];
    OsRng.fill_bytes(&mut source_secret);
    if source_secret == [0u8; 32] {
        return Err(WakeError::Key);
    }
    let admission = Arc::new(Mutex::new(IngressAdmission::new(
        source_secret,
        config.max_connections_per_minute,
        config.max_connections_per_source_per_minute,
        config.max_source_buckets,
    )));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                let _ = completed;
            }
            accepted = listener.accept() => {
                let (socket, remote) = accepted?;
                if !admission.lock().await.admit(remote.ip(), unix_now()) {
                    drop(socket);
                    continue;
                }
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    drop(socket);
                    continue;
                };
                let acceptor = acceptor.clone();
                let gateway = Arc::clone(&gateway);
                let handshake_timeout = config.tls_handshake_timeout;
                let request_timeout = config.request_timeout;
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = serve_connection(
                        socket,
                        acceptor,
                        gateway,
                        handshake_timeout,
                        request_timeout,
                    )
                    .await;
                });
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn serve_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    gateway: Arc<WakeGateway>,
    handshake_timeout: Duration,
    request_timeout: Duration,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let mut tls = tokio::time::timeout(handshake_timeout, acceptor.accept(socket))
        .await
        .map_err(|_| WakeError::Invalid("wake TLS handshake deadline"))?
        .map_err(|_| WakeError::Invalid("wake TLS handshake failed"))?;
    tokio::time::timeout(request_timeout, serve_one(&mut tls, &gateway))
        .await
        .map_err(|_| WakeError::Invalid("wake request deadline"))??;
    let _ = tls.shutdown().await;
    Ok(())
}

async fn serve_one<S>(stream: &mut S, gateway: &WakeGateway) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let parsed = read_request(stream).await;
    let now = unix_now();
    match parsed {
        Ok(request) if request.path == WAKE_REGISTER_PATH => {
            let mut rng = OsRng;
            let response = gateway.register(&request.body, now, &mut rng);
            write_response(stream, "HTTP/1.1 200 OK", &response).await
        }
        Ok(request) if request.path == WAKE_TRIGGER_PATH => {
            let response = gateway.trigger(&request.body, now).await;
            write_response(stream, "HTTP/1.1 202 Accepted", &response).await
        }
        Ok(request) if request.path == WAKE_REVOKE_PATH => {
            let response = gateway.revoke(&request.body, now);
            write_response(stream, "HTTP/1.1 202 Accepted", &response).await
        }
        _ => {
            let response = wake_generic_response();
            write_response(stream, "HTTP/1.1 202 Accepted", &response).await
        }
    }
}

struct ParsedRequest {
    path: &'static str,
    body: Vec<u8>,
}

async fn read_request<S>(stream: &mut S) -> core::result::Result<ParsedRequest, ()>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; MAX_HTTP_HEADER_BYTES];
    let mut filled = 0usize;
    let header_end = loop {
        if filled == header.len() {
            return Err(());
        }
        let read = stream.read(&mut header[filled..]).await.map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        filled += read;
        if let Some(position) = header[..filled]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break position + 4;
        }
    };
    let (path, content_length) = parse_header(&header[..header_end])?;
    let already_read = filled.saturating_sub(header_end);
    if already_read > content_length {
        return Err(());
    }
    let mut body = vec![0u8; content_length];
    body[..already_read].copy_from_slice(&header[header_end..filled]);
    if already_read < content_length {
        stream
            .read_exact(&mut body[already_read..])
            .await
            .map_err(|_| ())?;
    }
    Ok(ParsedRequest { path, body })
}

fn parse_header(bytes: &[u8]) -> core::result::Result<(&'static str, usize), ()> {
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(());
    }
    let text = core::str::from_utf8(&bytes[..bytes.len() - 2]).map_err(|_| ())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let (path, expected_length) = match request_line {
        "POST /v1/wake/register HTTP/1.1" => (WAKE_REGISTER_PATH, WAKE_REGISTER_REQUEST_LEN),
        "POST /v1/wake/trigger HTTP/1.1" => (WAKE_TRIGGER_PATH, WAKE_TRIGGER_REQUEST_LEN),
        "POST /v1/wake/revoke HTTP/1.1" => (WAKE_REVOKE_PATH, WAKE_TRIGGER_REQUEST_LEN),
        _ => return Err(()),
    };
    let mut host = false;
    let mut content_type = false;
    let mut content_length = false;
    let mut close = false;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) || line.contains('\t') {
            return Err(());
        }
        let (name, value) = line.split_once(": ").ok_or(())?;
        match name.to_ascii_lowercase().as_str() {
            "host" if !host && !value.is_empty() && value.len() <= 512 => host = true,
            "content-type" if !content_type && value == WAKE_MEDIA_TYPE => content_type = true,
            "content-length"
                if !content_length
                    && value.parse::<usize>().ok() == Some(expected_length)
                    && value == expected_length.to_string() =>
            {
                content_length = true;
            }
            "connection" if !close && value.eq_ignore_ascii_case("close") => close = true,
            _ => return Err(()),
        }
    }
    if !host || !content_type || !content_length || !close {
        return Err(());
    }
    Ok((path, expected_length))
}

async fn write_response<S>(stream: &mut S, status: &str, body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if !matches!(
        body.len(),
        WAKE_REGISTER_RESPONSE_LEN | WAKE_GENERIC_RESPONSE_LEN
    ) {
        return Err(WakeError::Invalid("wake response length"));
    }
    let header = format!(
        "{status}\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Clone, Copy)]
struct RateWindow {
    minute: u64,
    count: u32,
}

struct IngressAdmission {
    secret: [u8; 32],
    global_limit: u32,
    source_limit: u32,
    max_sources: usize,
    global: Option<RateWindow>,
    sources: HashMap<[u8; 32], RateWindow>,
}

impl IngressAdmission {
    fn new(secret: [u8; 32], global_limit: u32, source_limit: u32, max_sources: usize) -> Self {
        Self {
            secret,
            global_limit,
            source_limit,
            max_sources,
            global: None,
            sources: HashMap::new(),
        }
    }

    fn admit(&mut self, address: IpAddr, now: u64) -> bool {
        let minute = now / RATE_WINDOW_SECS;
        let key = self.source_key(address);
        let global = self.global.get_or_insert(RateWindow { minute, count: 0 });
        if global.minute != minute {
            *global = RateWindow { minute, count: 0 };
        }
        if global.count >= self.global_limit {
            return false;
        }
        self.sources
            .retain(|_, window| window.minute.saturating_add(1) >= minute);
        if !self.sources.contains_key(&key) && self.sources.len() >= self.max_sources {
            return false;
        }
        let source = self
            .sources
            .entry(key)
            .or_insert(RateWindow { minute, count: 0 });
        if source.minute != minute {
            *source = RateWindow { minute, count: 0 };
        }
        if source.count >= self.source_limit {
            return false;
        }
        global.count = global.count.saturating_add(1);
        source.count = source.count.saturating_add(1);
        true
    }

    fn source_key(&self, address: IpAddr) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts 32-byte keys");
        mac.update(b"Komms-Wake-Ingress-v1");
        match address {
            IpAddr::V4(address) => {
                mac.update(&[4]);
                mac.update(&address.octets());
            }
            IpAddr::V6(address) => {
                mac.update(&[6]);
                mac.update(&address.octets());
            }
        }
        mac.finalize().into_bytes().into()
    }
}

impl Drop for IngressAdmission {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        generate_capability_key, FileCapabilityKeyring, GatewayLimits, GatewayStateStore,
        NativePushProvider, NativePushRequest, ProviderErrorClass,
    };

    use super::*;

    struct NoopProvider;

    #[async_trait]
    impl NativePushProvider for NoopProvider {
        async fn send(
            &self,
            _request: NativePushRequest,
        ) -> core::result::Result<(), ProviderErrorClass> {
            Ok(())
        }
    }

    fn gateway() -> (tempfile::TempDir, WakeGateway) {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("wake.key");
        let state = directory.path().join("wake.db");
        let mut rng = StdRng::seed_from_u64(44);
        generate_capability_key(&key, 1, 1, &mut rng).unwrap();
        let keys = Arc::new(FileCapabilityKeyring::open(1, &[key]).unwrap());
        let state = GatewayStateStore::open(&state, 100, 100).unwrap();
        let gateway = WakeGateway::new(
            keys,
            state,
            Arc::new(NoopProvider),
            GatewayLimits::default(),
            &mut rng,
        )
        .unwrap();
        (directory, gateway)
    }

    #[tokio::test]
    async fn malformed_requests_receive_one_uniform_fixed_response() {
        let (_directory, gateway) = gateway();
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            serve_one(&mut reader, &gateway).await.unwrap();
        });
        writer
            .write_all(b"GET /secret HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let mut response = Vec::new();
        writer.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
        assert!(response.ends_with(&wake_generic_response()));
        assert_eq!(
            response
                .windows(wake_generic_response().len())
                .filter(|window| *window == wake_generic_response())
                .count(),
            1
        );
    }

    #[test]
    fn ingress_rate_state_is_ephemeral_hashed_and_bounded() {
        let mut admission = IngressAdmission::new([7u8; 32], 3, 2, 1);
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(admission.admit(first, 120));
        assert!(admission.admit(first, 120));
        assert!(!admission.admit(first, 120));
        assert!(!admission.admit(second, 120));
        assert!(admission.admit(second, 240));
        assert_eq!(admission.sources.len(), 1);
        assert!(!admission
            .sources
            .keys()
            .any(|key| key.starts_with(&[192, 0, 2])));
    }

    #[test]
    fn parser_accepts_only_exact_fixed_shape_headers() {
        let valid = format!(
            "POST /v1/wake/trigger HTTP/1.1\r\nHost: wake.example\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {WAKE_TRIGGER_REQUEST_LEN}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            parse_header(valid.as_bytes()).unwrap(),
            (WAKE_TRIGGER_PATH, WAKE_TRIGGER_REQUEST_LEN)
        );
        for invalid in [
            valid.replace("Connection: close", "Connection: keep-alive"),
            valid.replace("Host: wake.example\r\n", ""),
            valid.replace(
                &format!("Content-Length: {WAKE_TRIGGER_REQUEST_LEN}"),
                "Content-Length: 1025",
            ),
            valid.replace("Connection: close", "Connection: close\r\nCookie: stable=1"),
        ] {
            assert!(parse_header(invalid.as_bytes()).is_err());
        }
    }
}
