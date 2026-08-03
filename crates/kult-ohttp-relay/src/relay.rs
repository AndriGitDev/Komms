use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::config::UpstreamPolicy;
use crate::tls::load_gateway_config;
use crate::{Config, RelayError, Result};

pub(crate) const REQUEST_MEDIA_TYPE: &str = "message/ohttp-req";
pub(crate) const RESPONSE_MEDIA_TYPE: &str = "message/ohttp-res";

#[derive(Default)]
pub(crate) struct RelayMetrics {
    accepted_connections: AtomicU64,
    overload_refusals: AtomicU64,
    tls_failures: AtomicU64,
    malformed_requests: AtomicU64,
    forwarded_requests: AtomicU64,
    successful_responses: AtomicU64,
    gateway_failures: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelayMetricsSnapshot {
    pub(crate) accepted_connections: u64,
    pub(crate) overload_refusals: u64,
    pub(crate) tls_failures: u64,
    pub(crate) malformed_requests: u64,
    pub(crate) forwarded_requests: u64,
    pub(crate) successful_responses: u64,
    pub(crate) gateway_failures: u64,
}

impl RelayMetrics {
    pub(crate) fn snapshot(&self) -> RelayMetricsSnapshot {
        RelayMetricsSnapshot {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            overload_refusals: self.overload_refusals.load(Ordering::Relaxed),
            tls_failures: self.tls_failures.load(Ordering::Relaxed),
            malformed_requests: self.malformed_requests.load(Ordering::Relaxed),
            forwarded_requests: self.forwarded_requests.load(Ordering::Relaxed),
            successful_responses: self.successful_responses.load(Ordering::Relaxed),
            gateway_failures: self.gateway_failures.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn accepted(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn overload(&self) {
        self.overload_refusals.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn tls_failure(&self) {
        self.tls_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn malformed(&self) {
        self.malformed_requests.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct RelayService {
    upstream: UpstreamPolicy,
    gateway_tls: Arc<rustls::ClientConfig>,
    metrics: Arc<RelayMetrics>,
}

impl RelayService {
    pub(crate) fn open(config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            upstream: config.upstream.clone(),
            gateway_tls: load_gateway_config(config)?,
            metrics: Arc::new(RelayMetrics::default()),
        })
    }

    pub(crate) fn metrics(&self) -> Arc<RelayMetrics> {
        Arc::clone(&self.metrics)
    }

    pub(crate) async fn forward(&self, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if body.len() != self.upstream.encapsulated_request_bytes {
            return Err(RelayError::Invalid(
                "encapsulated request does not match the fixed mapping",
            ));
        }
        self.metrics
            .forwarded_requests
            .fetch_add(1, Ordering::Relaxed);
        let result = tokio::time::timeout(self.upstream.timeout(), async {
            let tcp = TcpStream::connect((self.upstream.connect_host.as_str(), self.upstream.port))
                .await
                .map_err(|_| RelayError::Upstream)?;
            tcp.set_nodelay(true).map_err(|_| RelayError::Upstream)?;
            let server_name = ServerName::try_from(self.upstream.tls_server_name.clone())
                .map_err(|_| RelayError::Upstream)?;
            let mut tls = TlsConnector::from(Arc::clone(&self.gateway_tls))
                .connect(server_name, tcp)
                .await
                .map_err(|_| RelayError::Upstream)?;
            let response = exchange_gateway(&mut tls, &self.upstream, body).await?;
            let _ = tls.shutdown().await;
            Ok(response)
        })
        .await
        .map_err(|_| RelayError::Upstream)
        .and_then(|result| result);

        match result {
            Ok(response) => {
                self.metrics
                    .successful_responses
                    .fetch_add(1, Ordering::Relaxed);
                Ok(response)
            }
            Err(_) => {
                self.metrics
                    .gateway_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(RelayError::Upstream)
            }
        }
    }
}

async fn exchange_gateway<S>(
    stream: &mut S,
    upstream: &UpstreamPolicy,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if body.len() != upstream.encapsulated_request_bytes {
        return Err(RelayError::Invalid(
            "encapsulated request does not match the fixed mapping",
        ));
    }
    let header = build_gateway_request_header(upstream)?;
    stream
        .write_all(&header)
        .await
        .map_err(|_| RelayError::Upstream)?;
    stream
        .write_all(body)
        .await
        .map_err(|_| RelayError::Upstream)?;
    stream.flush().await.map_err(|_| RelayError::Upstream)?;
    read_gateway_response(
        stream,
        upstream.encapsulated_response_bytes,
        upstream.max_response_header_bytes,
    )
    .await
}

fn build_gateway_request_header(upstream: &UpstreamPolicy) -> Result<Vec<u8>> {
    let header = format!(
        concat!(
            "POST {} HTTP/1.1\r\n",
            "Host: {}\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n\r\n"
        ),
        upstream.resource,
        upstream.authority(),
        REQUEST_MEDIA_TYPE,
        upstream.encapsulated_request_bytes,
    );
    if header.len() > 2048 {
        return Err(RelayError::Invalid(
            "fixed gateway request header exceeds its bound",
        ));
    }
    Ok(header.into_bytes())
}

async fn read_gateway_response<S>(
    stream: &mut S,
    expected_body_bytes: usize,
    max_header_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let max_total = max_header_bytes
        .checked_add(expected_body_bytes)
        .and_then(|value| value.checked_add(1))
        .ok_or(RelayError::Upstream)?;
    let mut received = Vec::with_capacity(max_total.min(16 * 1024));
    let header_end = loop {
        if let Some(end) = find_header_end(&received) {
            if end > max_header_bytes {
                return Err(RelayError::Upstream);
            }
            break end;
        }
        if received.len() >= max_total {
            return Err(RelayError::Upstream);
        }
        let mut chunk = [0u8; 1024];
        let allowance = (max_total - received.len()).min(chunk.len());
        let read = stream
            .read(&mut chunk[..allowance])
            .await
            .map_err(|_| RelayError::Upstream)?;
        if read == 0 {
            return Err(RelayError::Upstream);
        }
        received.extend_from_slice(&chunk[..read]);
    };
    parse_gateway_header(&received[..header_end], expected_body_bytes)?;
    let already_read = received.len().saturating_sub(header_end);
    if already_read > expected_body_bytes {
        return Err(RelayError::Upstream);
    }
    let mut body = Zeroizing::new(vec![0u8; expected_body_bytes]);
    body[..already_read].copy_from_slice(&received[header_end..]);
    if already_read < expected_body_bytes {
        stream
            .read_exact(&mut body[already_read..])
            .await
            .map_err(|_| RelayError::Upstream)?;
    }
    Ok(body)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_gateway_header(bytes: &[u8], expected_body_bytes: usize) -> Result<()> {
    if bytes.len() < 4 || !bytes.ends_with(b"\r\n\r\n") {
        return Err(RelayError::Upstream);
    }
    let text = core::str::from_utf8(&bytes[..bytes.len() - 2]).map_err(|_| RelayError::Upstream)?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(RelayError::Upstream);
    }
    let mut names = BTreeSet::new();
    let mut content_type = None;
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) || line.contains('\t') {
            return Err(RelayError::Upstream);
        }
        let (name, raw_value) = line.split_once(':').ok_or(RelayError::Upstream)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(RelayError::Upstream);
        }
        let normalized = name.to_ascii_lowercase();
        if !names.insert(normalized.clone()) {
            return Err(RelayError::Upstream);
        }
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);
        if value.is_empty()
            || value.starts_with(' ')
            || value.ends_with(' ')
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RelayError::Upstream);
        }
        match normalized.as_str() {
            "content-type" => content_type = Some(value),
            "content-length" => {
                if !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(RelayError::Upstream);
                }
                content_length = Some(value.parse::<usize>().map_err(|_| RelayError::Upstream)?);
            }
            "transfer-encoding" | "content-encoding" | "trailer" | "upgrade" => {
                return Err(RelayError::Upstream);
            }
            _ => {}
        }
    }
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case(RESPONSE_MEDIA_TYPE))
        || content_length != Some(expected_body_bytes)
    {
        return Err(RelayError::Upstream);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream() -> UpstreamPolicy {
        UpstreamPolicy {
            connect_host: "192.0.2.10".into(),
            port: 443,
            tls_server_name: "gateway.example".into(),
            resource: "/ohttp-gateway".into(),
            encapsulated_request_bytes: 4,
            encapsulated_response_bytes: 4,
            max_response_header_bytes: 8192,
            timeout_seconds: 10,
        }
    }

    #[test]
    fn gateway_request_contains_only_minimal_fixed_fields() {
        let header = String::from_utf8(build_gateway_request_header(&upstream()).unwrap()).unwrap();
        assert_eq!(
            header,
            concat!(
                "POST /ohttp-gateway HTTP/1.1\r\n",
                "Host: gateway.example\r\n",
                "Content-Type: message/ohttp-req\r\n",
                "Content-Length: 4\r\n",
                "Connection: close\r\n\r\n"
            )
        );
        for forbidden in [
            "Forwarded:",
            "Via:",
            "User-Agent:",
            "Cookie:",
            "Authorization:",
            "X-Forwarded-For:",
        ] {
            assert!(!header.contains(forbidden));
        }
    }

    #[test]
    fn gateway_response_header_is_fixed_shape_and_stripped() {
        let valid = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: message/ohttp-res\r\n",
            "Content-Length: 4\r\n",
            "Date: Thu, 31 Jul 2026 12:00:00 GMT\r\n",
            "Set-Cookie: ignored=1\r\n\r\n"
        );
        parse_gateway_header(valid.as_bytes(), 4).unwrap();

        let wrong_type =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n";
        assert!(parse_gateway_header(wrong_type, 4).is_err());

        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: message/ohttp-res\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_gateway_header(chunked, 4).is_err());
    }

    #[tokio::test]
    async fn gateway_response_reader_is_bounded_and_exact() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            writer
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: message/ohttp-res\r\nContent-Length: 4\r\n\r\npong",
                )
                .await
                .unwrap();
        });
        let response = read_gateway_response(&mut reader, 4, 1024).await.unwrap();
        assert_eq!(response.as_slice(), b"pong");
        task.await.unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            writer
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: message/ohttp-res\r\nContent-Length: 5\r\n\r\nwrong",
                )
                .await
                .unwrap();
        });
        assert!(read_gateway_response(&mut reader, 4, 1024).await.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn one_exchange_reconstructs_headers_and_copies_only_ciphertext() {
        let policy = upstream();
        let (mut relay_side, mut gateway_side) = tokio::io::duplex(4096);
        let gateway = tokio::spawn(async move {
            let expected = concat!(
                "POST /ohttp-gateway HTTP/1.1\r\n",
                "Host: gateway.example\r\n",
                "Content-Type: message/ohttp-req\r\n",
                "Content-Length: 4\r\n",
                "Connection: close\r\n\r\n",
                "ping"
            );
            let mut request = vec![0u8; expected.len()];
            gateway_side.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected.as_bytes());
            gateway_side
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: message/ohttp-res\r\nContent-Length: 4\r\nSet-Cookie: stripped=1\r\n\r\npong",
                )
                .await
                .unwrap();
            gateway_side.shutdown().await.unwrap();
        });
        let response = exchange_gateway(&mut relay_side, &policy, b"ping")
            .await
            .unwrap();
        assert_eq!(response.as_slice(), b"pong");
        gateway.await.unwrap();
    }
}
