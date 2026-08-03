//! Fixed-shape ADR-0019 wake-gateway client boundary.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand_core::{OsRng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use kult_protocol::{
    canonical_wake_https_origin, verify_wake_generic_response, wake_provider_id,
    WakeRegisterRequest, WakeRegisterResponse, WakeTriggerRequest, WAKE_GENERIC_RESPONSE_LEN,
    WAKE_MEDIA_TYPE, WAKE_REGISTER_PATH, WAKE_REGISTER_RESPONSE_LEN, WAKE_REVOKE_PATH,
    WAKE_TRIGGER_PATH,
};

use crate::{Result, TransportError};

/// Maximum recipient-selected wake gateways retained by one client.
pub const MAX_WAKE_PROVIDERS: usize = 4;
const MAX_WAKE_HTTP_HEADER_BYTES: usize = 4 * 1024;
const WAKE_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WAKE_HTTP_RESPONSE_BYTES: usize = MAX_WAKE_HTTP_HEADER_BYTES + WAKE_REGISTER_RESPONSE_LEN;

/// Canonical recipient-selected wake gateway descriptor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WakeProvider {
    origin: String,
    static_key: [u8; 32],
    provider_id: [u8; 32],
}

impl WakeProvider {
    /// Validate one canonical HTTPS origin and bind its leaf-certificate pin.
    pub fn new(origin: String, static_key: [u8; 32]) -> Result<Self> {
        if !canonical_wake_https_origin(&origin) || static_key == [0u8; 32] {
            return Err(TransportError::UnsupportedHint);
        }
        let provider_id = wake_provider_id(origin.as_bytes(), &static_key)
            .map_err(|_| TransportError::UnsupportedHint)?;
        Ok(Self {
            origin,
            static_key,
            provider_id,
        })
    }

    /// Canonical HTTPS origin with no request path or capability.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Exact leaf-certificate SHA-256 pin.
    pub fn static_key(&self) -> [u8; 32] {
        self.static_key
    }

    /// Provider-separation identifier.
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
}

/// Fixed-width gateway operations.
#[async_trait]
pub trait WakeClient: Send + Sync {
    /// Register one native destination and receive a fresh opaque capability.
    async fn register(
        &self,
        provider: &WakeProvider,
        request: &WakeRegisterRequest,
    ) -> Result<WakeRegisterResponse>;

    /// Request one generic best-effort wake.
    async fn trigger(&self, provider: &WakeProvider, request: &WakeTriggerRequest) -> Result<()>;

    /// Revoke one capability by possession.
    async fn revoke(&self, provider: &WakeProvider, request: &WakeTriggerRequest) -> Result<()>;
}

/// Network ingress used by the wake client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeIngress {
    /// Direct TCP/TLS for the disclosed Standard-mode path.
    Direct,
    /// Loopback Tor SOCKS5 with per-request stream isolation.
    Tor(SocketAddr),
}

/// Strict TLS 1.3 fixed-shape wake client.
#[derive(Clone, Debug)]
pub struct HttpsWakeClient {
    ingress: WakeIngress,
    timeout: Duration,
}

impl HttpsWakeClient {
    /// Build a Standard-mode direct client.
    pub fn direct() -> Self {
        Self {
            ingress: WakeIngress::Direct,
            timeout: WAKE_HTTP_TIMEOUT,
        }
    }

    /// Build a Private-mode Tor client with no direct fallback.
    pub fn tor(proxy: SocketAddr) -> Result<Self> {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(TransportError::UnsupportedHint);
        }
        Ok(Self {
            ingress: WakeIngress::Tor(proxy),
            timeout: WAKE_HTTP_TIMEOUT,
        })
    }

    /// Inspect only the configured ingress.
    pub fn ingress(&self) -> WakeIngress {
        self.ingress
    }

    async fn request(
        &self,
        provider: &WakeProvider,
        path: &str,
        body: &[u8],
        status: &'static str,
        expected_response_len: usize,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout(
            self.timeout,
            self.request_inner(provider, path, body, status, expected_response_len),
        )
        .await
        .map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "wake request deadline",
            ))
        })?
    }

    async fn request_inner(
        &self,
        provider: &WakeProvider,
        path: &str,
        body: &[u8],
        status: &'static str,
        expected_response_len: usize,
    ) -> Result<Vec<u8>> {
        if !matches!(
            path,
            WAKE_REGISTER_PATH | WAKE_TRIGGER_PATH | WAKE_REVOKE_PATH
        ) {
            return Err(TransportError::UnsupportedHint);
        }
        let authority = parse_origin(provider.origin()).ok_or(TransportError::UnsupportedHint)?;
        let socket = match self.ingress {
            WakeIngress::Direct => {
                TcpStream::connect((authority.host.as_str(), authority.port)).await?
            }
            WakeIngress::Tor(proxy) => {
                let mut socket = TcpStream::connect(proxy).await?;
                tor_connect(&mut socket, &authority.host, authority.port).await?;
                socket
            }
        };
        socket.set_nodelay(true)?;
        let verifier = Arc::new(PinnedCertificateVerifier::new(provider.static_key()));
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| {
                TransportError::Io(io::Error::other(format!("wake TLS configuration: {error}")))
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let server_name = ServerName::try_from(authority.host.clone())
            .map_err(|_| TransportError::UnsupportedHint)?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(server_name, socket)
            .await
            .map_err(|error| {
                TransportError::Io(io::Error::other(format!("wake TLS handshake: {error}")))
            })?;
        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            authority.http_authority,
            body.len()
        );
        tls.write_all(header.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await?;
        let response = read_http_response(&mut tls, status, expected_response_len).await?;
        let _ = tls.shutdown().await;
        Ok(response)
    }
}

#[async_trait]
impl WakeClient for HttpsWakeClient {
    async fn register(
        &self,
        provider: &WakeProvider,
        request: &WakeRegisterRequest,
    ) -> Result<WakeRegisterResponse> {
        let body = request.encode().map_err(TransportError::Protocol)?;
        let response = self
            .request(
                provider,
                WAKE_REGISTER_PATH,
                &body,
                "HTTP/1.1 200 OK",
                WAKE_REGISTER_RESPONSE_LEN,
            )
            .await?;
        WakeRegisterResponse::decode(&response).map_err(TransportError::Protocol)
    }

    async fn trigger(&self, provider: &WakeProvider, request: &WakeTriggerRequest) -> Result<()> {
        let body = request.encode().map_err(TransportError::Protocol)?;
        let response = self
            .request(
                provider,
                WAKE_TRIGGER_PATH,
                &body,
                "HTTP/1.1 202 Accepted",
                WAKE_GENERIC_RESPONSE_LEN,
            )
            .await?;
        verify_wake_generic_response(&response).map_err(TransportError::Protocol)
    }

    async fn revoke(&self, provider: &WakeProvider, request: &WakeTriggerRequest) -> Result<()> {
        let body = request.encode().map_err(TransportError::Protocol)?;
        let response = self
            .request(
                provider,
                WAKE_REVOKE_PATH,
                &body,
                "HTTP/1.1 202 Accepted",
                WAKE_GENERIC_RESPONSE_LEN,
            )
            .await?;
        verify_wake_generic_response(&response).map_err(TransportError::Protocol)
    }
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    expected_leaf_digest: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertificateVerifier {
    fn new(expected_leaf_digest: [u8; 32]) -> Self {
        Self {
            expected_leaf_digest,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.is_empty()
            || intermediates.len() > 8
            || Sha256::digest(end_entity.as_ref()).as_slice() != self.expected_leaf_digest
        {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

struct OriginAuthority {
    host: String,
    port: u16,
    http_authority: String,
}

fn parse_origin(origin: &str) -> Option<OriginAuthority> {
    if !canonical_wake_https_origin(origin) {
        return None;
    }
    let authority = origin.strip_prefix("https://")?;
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = bracketed[..close].to_owned();
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            443
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        Some(OriginAuthority {
            host,
            port,
            http_authority: authority.to_owned(),
        })
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, 443), |(host, port)| {
                (host, port.parse().unwrap_or(0))
            });
        (port != 0).then(|| OriginAuthority {
            host: host.to_owned(),
            port,
            http_authority: authority.to_owned(),
        })
    }
}

async fn tor_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(TransportError::UnsupportedHint);
    }
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor proxy refused wake stream isolation",
        )));
    }
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let username = hex_lower(&random[..16]);
    let password = hex_lower(&random[16..]);
    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.extend_from_slice(&[1, username.len() as u8]);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    random.fill(0);
    stream.write_all(&auth).await?;
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [1, 0] {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor proxy authentication refused",
        )));
    }
    let mut request = Vec::with_capacity(7 + host.len());
    request.extend_from_slice(&[5, 1, 0, 3, host.len() as u8]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Tor wake connection refused",
        )));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        _ => {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed Tor proxy response",
            )))
        }
    };
    let mut remainder = vec![0u8; address_len + 2];
    stream.read_exact(&mut remainder).await?;
    Ok(())
}

async fn read_http_response<S>(
    stream: &mut S,
    expected_status: &str,
    expected_body: usize,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    if expected_body > WAKE_REGISTER_RESPONSE_LEN {
        return Err(TransportError::UnsupportedHint);
    }
    let mut response = Vec::with_capacity(MAX_WAKE_HTTP_RESPONSE_BYTES);
    let header_end = loop {
        if response.len() >= MAX_WAKE_HTTP_HEADER_BYTES {
            return Err(invalid_http("wake response header exceeds bound"));
        }
        let mut chunk = [0u8; 1024];
        let remaining = MAX_WAKE_HTTP_HEADER_BYTES - response.len();
        let chunk_len = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..chunk_len]).await?;
        if read == 0 {
            return Err(invalid_http("truncated wake response header"));
        }
        response.extend_from_slice(&chunk[..read]);
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let already_read = response.len() - header_end;
    if already_read > expected_body {
        return Err(invalid_http("oversized wake response body"));
    }
    parse_response_header(&response[..header_end], expected_status, expected_body)?;
    response.resize(header_end + expected_body, 0);
    stream
        .read_exact(&mut response[header_end + already_read..])
        .await?;
    let body = response.split_off(header_end);
    let mut trailing = [0u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(invalid_http("oversized wake response body"));
    }
    Ok(body)
}

fn parse_response_header(bytes: &[u8], expected_status: &str, expected_body: usize) -> Result<()> {
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(invalid_http("malformed wake response header"));
    }
    let text = core::str::from_utf8(&bytes[..bytes.len() - 2])
        .map_err(|_| invalid_http("non-UTF-8 wake response header"))?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some(expected_status) {
        return Err(invalid_http("unexpected wake HTTP status"));
    }
    let mut content_type = false;
    let mut content_length = false;
    let mut no_store = false;
    let mut close = false;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) || line.contains('\t') {
            return Err(invalid_http("folded wake response header"));
        }
        let (name, value) = line
            .split_once(": ")
            .ok_or_else(|| invalid_http("malformed wake response field"))?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" if !content_type && value == WAKE_MEDIA_TYPE => content_type = true,
            "content-length"
                if !content_length
                    && value.parse::<usize>().ok() == Some(expected_body)
                    && value == expected_body.to_string() =>
            {
                content_length = true;
            }
            "cache-control" if !no_store && value.eq_ignore_ascii_case("no-store") => {
                no_store = true;
            }
            "connection" if !close && value.eq_ignore_ascii_case("close") => close = true,
            _ => return Err(invalid_http("unsafe wake response field")),
        }
    }
    if !content_type || !content_length || !no_store || !close {
        return Err(invalid_http("incomplete wake response policy"));
    }
    Ok(())
}

fn invalid_http(reason: &'static str) -> TransportError {
    TransportError::Io(io::Error::new(io::ErrorKind::InvalidData, reason))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn providers_are_canonical_key_bound_and_path_free() {
        let provider = WakeProvider::new("https://wake.example:8443".into(), [1u8; 32]).unwrap();
        assert_eq!(provider.origin(), "https://wake.example:8443");
        assert_ne!(provider.provider_id(), [0u8; 32]);
        assert_ne!(
            provider.provider_id(),
            WakeProvider::new("https://wake.example:8443".into(), [2u8; 32])
                .unwrap()
                .provider_id()
        );
        for invalid in [
            "http://wake.example",
            "https://WAKE.example",
            "https://wake.example/",
            "https://user@wake.example",
            "https://wake.example/v1/wake/trigger",
            "https://wake.example?cap=x",
            "https://wake.example:443",
        ] {
            assert!(WakeProvider::new(invalid.into(), [1u8; 32]).is_err());
        }
    }

    #[tokio::test]
    async fn strict_https_trigger_uses_fixed_path_body_and_response() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let digest: [u8; 32] = Sha256::digest(cert.der().as_ref()).into();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(Arc::new(server))
                .accept(socket)
                .await
                .unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let count = tls.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let present = request.len() - header_end;
            request.resize(header_end + kult_protocol::WAKE_TRIGGER_REQUEST_LEN, 0);
            tls.read_exact(&mut request[header_end + present..])
                .await
                .unwrap();
            assert!(request.starts_with(b"POST /v1/wake/trigger HTTP/1.1\r\n"));
            assert!(!request[..header_end]
                .windows(4)
                .any(|window| window == b"cap="));
            let header = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {WAKE_GENERIC_RESPONSE_LEN}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            );
            tls.write_all(header.as_bytes()).await.unwrap();
            tls.write_all(&kult_protocol::wake_generic_response())
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });
        let provider =
            WakeProvider::new(format!("https://127.0.0.1:{}", address.port()), digest).unwrap();
        let capability = kult_protocol::WakeCapability::from_parts(
            1,
            [1u8; 24],
            &[2u8; kult_protocol::WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
        )
        .unwrap();
        HttpsWakeClient::direct()
            .trigger(
                &provider,
                &WakeTriggerRequest {
                    capability,
                    request_nonce: [3u8; 16],
                },
            )
            .await
            .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn response_parser_rejects_extra_fields_trailing_bytes_and_header_flood() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let header = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {WAKE_GENERIC_RESPONSE_LEN}\r\nCache-Control: no-store\r\nConnection: close\r\nSet-Cookie: x=y\r\n\r\n"
            );
            writer.write_all(header.as_bytes()).await.unwrap();
            writer
                .write_all(&vec![0u8; WAKE_GENERIC_RESPONSE_LEN])
                .await
                .unwrap();
        });
        assert!(read_http_response(
            &mut reader,
            "HTTP/1.1 202 Accepted",
            WAKE_GENERIC_RESPONSE_LEN
        )
        .await
        .is_err());
        task.await.unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let header = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: {WAKE_MEDIA_TYPE}\r\nContent-Length: {WAKE_GENERIC_RESPONSE_LEN}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            );
            writer.write_all(header.as_bytes()).await.unwrap();
            writer
                .write_all(&vec![0u8; WAKE_GENERIC_RESPONSE_LEN + 1])
                .await
                .unwrap();
        });
        assert!(read_http_response(
            &mut reader,
            "HTTP/1.1 202 Accepted",
            WAKE_GENERIC_RESPONSE_LEN
        )
        .await
        .is_err());
        task.await.unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_WAKE_HTTP_HEADER_BYTES])
                .await
                .unwrap();
        });
        assert!(read_http_response(
            &mut reader,
            "HTTP/1.1 202 Accepted",
            WAKE_GENERIC_RESPONSE_LEN
        )
        .await
        .is_err());
        task.await.unwrap();
    }
}
