use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use zeroize::{Zeroize, Zeroizing};

use crate::config::NetworkPolicy;
use crate::relay::{RelayService, REQUEST_MEDIA_TYPE, RESPONSE_MEDIA_TYPE};
use crate::{RelayError, Result};

const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
const RATE_WINDOW_SECONDS: u64 = 60;

#[derive(Clone)]
struct ConnectionPolicy {
    authority: String,
    resource: String,
    expected_request_bytes: usize,
    handshake_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
}

pub(crate) async fn run_tls_relay(
    config: NetworkPolicy,
    expected_request_bytes: usize,
    reserved_exchange_bytes: usize,
    tls: Arc<rustls::ServerConfig>,
    relay: Arc<RelayService>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    let acceptor = TlsAcceptor::from(tls);
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let metrics = relay.metrics();
    let mut source_secret = [0u8; 32];
    OsRng.fill_bytes(&mut source_secret);
    if source_secret == [0u8; 32] {
        return Err(RelayError::Invalid(
            "relay source-admission key generation failed",
        ));
    }
    let mut admission = IngressAdmission::new(
        source_secret,
        config.max_requests_per_minute,
        config.max_requests_per_source_per_minute,
        config.max_bytes_per_minute,
        config.max_source_buckets,
    );
    let connection_policy = ConnectionPolicy {
        authority: config.public_authority.clone(),
        resource: config.public_resource.clone(),
        expected_request_bytes,
        handshake_timeout: config.handshake_timeout(),
        request_timeout: config.request_timeout(),
    };
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
                if !admission.admit(
                    remote.ip(),
                    reserved_exchange_bytes,
                    unix_now(),
                ) {
                    metrics.overload();
                    drop(socket);
                    continue;
                }
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    metrics.overload();
                    drop(socket);
                    continue;
                };
                metrics.accepted();
                let acceptor = acceptor.clone();
                let relay = Arc::clone(&relay);
                let policy = connection_policy.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = serve_connection(socket, acceptor, relay, policy).await;
                    let _ = result;
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
    relay: Arc<RelayService>,
    policy: ConnectionPolicy,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let mut tls =
        match tokio::time::timeout(policy.handshake_timeout, acceptor.accept(socket)).await {
            Ok(Ok(tls)) => tls,
            _ => {
                relay.metrics().tls_failure();
                return Ok(());
            }
        };
    let result = tokio::time::timeout(
        policy.request_timeout,
        serve_one(
            &mut tls,
            &relay,
            &policy.authority,
            &policy.resource,
            policy.expected_request_bytes,
        ),
    )
    .await;
    if result.is_err() {
        let _ = write_error(&mut tls, "502 Bad Gateway").await;
    }
    let _ = tls.shutdown().await;
    Ok(())
}

async fn serve_one<S>(
    stream: &mut S,
    relay: &RelayService,
    authority: &str,
    resource: &str,
    expected_request_bytes: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match read_request(stream, authority, resource, expected_request_bytes).await {
        Ok(request) => request,
        Err(()) => {
            relay.metrics().malformed();
            write_error(stream, "400 Bad Request").await?;
            return Ok(());
        }
    };
    match relay.forward(&request).await {
        Ok(response) => write_success(stream, &response).await,
        Err(_) => write_error(stream, "502 Bad Gateway").await,
    }
}

async fn read_request<S>(
    stream: &mut S,
    authority: &str,
    resource: &str,
    expected_body_bytes: usize,
) -> core::result::Result<Zeroizing<Vec<u8>>, ()>
where
    S: AsyncRead + Unpin,
{
    let mut received = Vec::with_capacity(
        MAX_HTTP_HEADER_BYTES
            .saturating_add(expected_body_bytes)
            .min(16 * 1024),
    );
    let max_total = MAX_HTTP_HEADER_BYTES
        .checked_add(expected_body_bytes)
        .and_then(|value| value.checked_add(1))
        .ok_or(())?;
    let header_end = loop {
        if let Some(end) = find_header_end(&received) {
            if end > MAX_HTTP_HEADER_BYTES {
                return Err(());
            }
            break end;
        }
        if received.len() >= max_total {
            return Err(());
        }
        let mut chunk = [0u8; 1024];
        let allowance = (max_total - received.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..allowance]).await.map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        received.extend_from_slice(&chunk[..read]);
    };
    parse_request_header(
        &received[..header_end],
        authority,
        resource,
        expected_body_bytes,
    )?;
    let already_read = received.len().saturating_sub(header_end);
    if already_read > expected_body_bytes {
        return Err(());
    }
    let mut body = Zeroizing::new(vec![0u8; expected_body_bytes]);
    body[..already_read].copy_from_slice(&received[header_end..]);
    if already_read < expected_body_bytes {
        stream
            .read_exact(&mut body[already_read..])
            .await
            .map_err(|_| ())?;
    }
    Ok(body)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_request_header(
    bytes: &[u8],
    authority: &str,
    resource: &str,
    expected_body_bytes: usize,
) -> core::result::Result<(), ()> {
    if bytes.len() < 4 || !bytes.ends_with(b"\r\n\r\n") {
        return Err(());
    }
    let text = core::str::from_utf8(&bytes[..bytes.len() - 2]).map_err(|_| ())?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some(format!("POST {resource} HTTP/1.1").as_str()) {
        return Err(());
    }
    let mut names = BTreeSet::new();
    let mut host = None;
    let mut content_type = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) || line.contains('\t') {
            return Err(());
        }
        let (name, raw_value) = line.split_once(':').ok_or(())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(());
        }
        let normalized = name.to_ascii_lowercase();
        if !names.insert(normalized.clone()) {
            return Err(());
        }
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);
        if value.is_empty()
            || value.starts_with(' ')
            || value.ends_with(' ')
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(());
        }
        match normalized.as_str() {
            "host" => host = Some(value),
            "content-type" => content_type = Some(value),
            "content-length" => {
                if !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(());
                }
                content_length = Some(value.parse::<usize>().map_err(|_| ())?);
            }
            "connection" => connection = Some(value),
            "transfer-encoding" | "content-encoding" | "expect" | "trailer" | "upgrade" => {
                return Err(());
            }
            _ => {}
        }
    }
    if !host.is_some_and(|value| value.eq_ignore_ascii_case(authority))
        || !content_type.is_some_and(|value| value.eq_ignore_ascii_case(REQUEST_MEDIA_TYPE))
        || content_length != Some(expected_body_bytes)
        || connection.is_some_and(|value| !value.eq_ignore_ascii_case("close"))
    {
        return Err(());
    }
    Ok(())
}

async fn write_success<S>(stream: &mut S, body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let header = format!(
        concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "Cache-Control: no-store\r\n",
            "Connection: close\r\n\r\n"
        ),
        RESPONSE_MEDIA_TYPE,
        body.len(),
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_error<S>(stream: &mut S, status: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if !matches!(status, "400 Bad Request" | "502 Bad Gateway") {
        return Err(RelayError::Invalid("unsupported relay error status"));
    }
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

struct RateWindow {
    minute: u64,
    requests: u32,
    bytes: u64,
}

struct IngressAdmission {
    secret: [u8; 32],
    global_request_limit: u32,
    source_request_limit: u32,
    global_byte_limit: u64,
    max_sources: usize,
    global: Option<RateWindow>,
    sources: HashMap<[u8; 16], RateWindow>,
}

impl IngressAdmission {
    fn new(
        secret: [u8; 32],
        global_request_limit: u32,
        source_request_limit: u32,
        global_byte_limit: u64,
        max_sources: usize,
    ) -> Self {
        Self {
            secret,
            global_request_limit,
            source_request_limit,
            global_byte_limit,
            max_sources,
            global: None,
            sources: HashMap::new(),
        }
    }

    fn admit(&mut self, address: IpAddr, request_bytes: usize, now: u64) -> bool {
        let minute = now / RATE_WINDOW_SECONDS;
        let key = self.source_key(address, minute);
        let global = self.global.get_or_insert(RateWindow {
            minute,
            requests: 0,
            bytes: 0,
        });
        if global.minute != minute {
            *global = RateWindow {
                minute,
                requests: 0,
                bytes: 0,
            };
            self.sources.clear();
        }
        if global.requests >= self.global_request_limit
            || global
                .bytes
                .checked_add(request_bytes as u64)
                .is_none_or(|bytes| bytes > self.global_byte_limit)
        {
            return false;
        }
        if !self.sources.contains_key(&key) && self.sources.len() >= self.max_sources {
            return false;
        }
        let source = self.sources.entry(key).or_insert(RateWindow {
            minute,
            requests: 0,
            bytes: 0,
        });
        if source.requests >= self.source_request_limit {
            return false;
        }
        global.requests = global.requests.saturating_add(1);
        global.bytes = global.bytes.saturating_add(request_bytes as u64);
        source.requests = source.requests.saturating_add(1);
        source.bytes = source.bytes.saturating_add(request_bytes as u64);
        true
    }

    fn source_key(&self, address: IpAddr, minute: u64) -> [u8; 16] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("fixed HMAC key");
        mac.update(b"Komms-OHTTP-Relay-Source-v1");
        mac.update(&minute.to_be_bytes());
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
        let digest = mac.finalize().into_bytes();
        let mut output = [0u8; 16];
        output.copy_from_slice(&digest[..16]);
        output
    }
}

impl Drop for IngressAdmission {
    fn drop(&mut self) {
        self.secret.zeroize();
        for (mut key, _) in self.sources.drain() {
            key.zeroize();
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY: &str = "relay.example";
    const RESOURCE: &str = "/ohttp";

    #[test]
    fn request_parser_accepts_then_strips_optional_client_fields() {
        let request = concat!(
            "POST /ohttp HTTP/1.1\r\n",
            "Host: relay.example\r\n",
            "Content-Type: message/ohttp-req\r\n",
            "Content-Length: 4\r\n",
            "Connection: close\r\n",
            "Authorization: private-to-relay-only\r\n",
            "Cookie: relay-only=1\r\n",
            "User-Agent: identifying-client\r\n",
            "X-Forwarded-For: 192.0.2.1\r\n\r\n"
        );
        parse_request_header(request.as_bytes(), AUTHORITY, RESOURCE, 4).unwrap();
    }

    #[test]
    fn request_parser_rejects_smuggling_and_variable_shape() {
        let chunked = concat!(
            "POST /ohttp HTTP/1.1\r\n",
            "Host: relay.example\r\n",
            "Content-Type: message/ohttp-req\r\n",
            "Content-Length: 4\r\n",
            "Transfer-Encoding: chunked\r\n\r\n"
        );
        assert!(parse_request_header(chunked.as_bytes(), AUTHORITY, RESOURCE, 4).is_err());

        let wrong_size = concat!(
            "POST /ohttp HTTP/1.1\r\n",
            "Host: relay.example\r\n",
            "Content-Type: message/ohttp-req\r\n",
            "Content-Length: 5\r\n\r\n"
        );
        assert!(parse_request_header(wrong_size.as_bytes(), AUTHORITY, RESOURCE, 4).is_err());

        let target = concat!(
            "POST /ohttp?gateway=other HTTP/1.1\r\n",
            "Host: relay.example\r\n",
            "Content-Type: message/ohttp-req\r\n",
            "Content-Length: 4\r\n\r\n"
        );
        assert!(parse_request_header(target.as_bytes(), AUTHORITY, RESOURCE, 4).is_err());
    }

    #[test]
    fn rate_buckets_are_bounded_rotating_and_source_scoped() {
        let mut admission = IngressAdmission::new([7u8; 32], 3, 2, 12, 2);
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(admission.admit(first, 4, 60));
        assert!(admission.admit(first, 4, 60));
        assert!(!admission.admit(first, 4, 60));
        assert!(admission.admit(second, 4, 60));
        assert!(!admission.admit(second, 4, 60));
        assert!(admission.admit(first, 4, 120));
    }

    #[test]
    fn metrics_are_aggregate_counts_only() {
        let metrics = crate::relay::RelayMetrics::default();
        metrics.accepted();
        metrics.overload();
        metrics.tls_failure();
        metrics.malformed();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.accepted_connections, 1);
        assert_eq!(snapshot.overload_refusals, 1);
        assert_eq!(snapshot.tls_failures, 1);
        assert_eq!(snapshot.malformed_requests, 1);
    }

    #[tokio::test]
    async fn error_responses_are_empty_no_store_and_category_uniform() {
        for status in ["400 Bad Request", "502 Bad Gateway"] {
            let (mut writer, mut reader) = tokio::io::duplex(1024);
            write_error(&mut writer, status).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut response = Vec::new();
            reader.read_to_end(&mut response).await.unwrap();
            let text = String::from_utf8(response).unwrap();
            assert!(text.starts_with(&format!("HTTP/1.1 {status}\r\n")));
            assert!(text.contains("\r\nContent-Length: 0\r\n"));
            assert!(text.contains("\r\nCache-Control: no-store\r\n"));
            assert!(text.ends_with("\r\n\r\n"));
        }
    }
}
