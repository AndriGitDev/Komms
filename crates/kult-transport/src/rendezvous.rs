//! Provider descriptors and a fixed-shape ADR-0018 client boundary.

use async_trait::async_trait;
use rand_core::{OsRng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io;
use std::net::SocketAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use kult_crypto::{
    rendezvous_provider_id, MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES, RENDEZVOUS_SEALED_RECORD_LEN,
};
use kult_protocol::{
    RendezvousLookupRequest, RendezvousRegisterRequest, RendezvousRoute, RendezvousRouteKind,
    RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_LOOKUP_RESPONSE_LEN, RENDEZVOUS_MEDIA_TYPE,
    RENDEZVOUS_REGISTER_ACK_LEN, RENDEZVOUS_REGISTER_PATH,
};

use crate::{internet::parse_addr, DeliveryHint, Result, TransportError};

/// Maximum configured rendezvous providers consumed by one client.
pub const MAX_RENDEZVOUS_PROVIDERS: usize = 8;
const MAX_RENDEZVOUS_HTTP_HEADER_BYTES: usize = 4 * 1024;
const RENDEZVOUS_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RENDEZVOUS_HTTP_RESPONSE_BYTES: usize =
    MAX_RENDEZVOUS_HTTP_HEADER_BYTES + RENDEZVOUS_SEALED_RECORD_LEN;

/// Canonical, authenticated provider descriptor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RendezvousProvider {
    origin: String,
    static_key: [u8; 32],
    provider_id: [u8; 32],
}

impl RendezvousProvider {
    /// Validate one canonical HTTPS origin and bind its service static key.
    ///
    /// The origin is lower-case `https://authority` with no path, trailing
    /// slash, query, fragment, user information or whitespace. Bracketed IPv6
    /// and an explicit decimal port are permitted.
    pub fn new(origin: String, static_key: [u8; 32]) -> Result<Self> {
        if !canonical_https_origin(&origin) || static_key == [0u8; 32] {
            return Err(TransportError::UnsupportedHint);
        }
        let provider_id = rendezvous_provider_id(origin.as_bytes(), &static_key)
            .map_err(|_| TransportError::UnsupportedHint)?;
        Ok(Self {
            origin,
            static_key,
            provider_id,
        })
    }

    /// Canonical HTTPS origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Service static key bound into the provider id.
    pub fn static_key(&self) -> [u8; 32] {
        self.static_key
    }

    /// Provider-separation id.
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
}

/// Fixed binary register/lookup transport.
///
/// Implementations terminate TLS in the dedicated rendezvous component and
/// must not place a slot in a URL, redirect, compress, attach cookies, reflect
/// request ids or expose hit/miss through response shape.
#[async_trait]
pub trait RendezvousClient: Send + Sync {
    /// Submit one fixed register body. The opaque acknowledgement confirms
    /// only service processing; callers must self-lookup before recording a
    /// successful registration.
    async fn register(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousRegisterRequest,
    ) -> Result<[u8; RENDEZVOUS_REGISTER_ACK_LEN]>;

    /// Submit one fixed lookup body and return exactly 4,136 bytes for both
    /// hits and misses.
    async fn lookup(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousLookupRequest,
    ) -> Result<[u8; RENDEZVOUS_SEALED_RECORD_LEN]>;
}

/// Network ingress used by the fixed-shape HTTPS rendezvous client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendezvousIngress {
    /// Direct TCP/TLS. This is the disclosed Standard-mode path.
    Direct,
    /// Tor SOCKS5 with remote DNS and per-request stream isolation.
    ///
    /// Only a loopback proxy is accepted so a configuration mistake cannot
    /// disclose the random isolation credential to a network peer.
    Tor(SocketAddr),
}

/// Fixed-shape TLS 1.3 rendezvous client with signed-directory certificate
/// pinning and an optional Tor-only ingress.
#[derive(Clone, Debug)]
pub struct HttpsRendezvousClient {
    ingress: RendezvousIngress,
    timeout: Duration,
}

impl HttpsRendezvousClient {
    /// Build the disclosed Standard-mode direct HTTPS client.
    pub fn direct() -> Self {
        Self {
            ingress: RendezvousIngress::Direct,
            timeout: RENDEZVOUS_HTTP_TIMEOUT,
        }
    }

    /// Build a Private-mode Tor client.
    ///
    /// The proxy must be an explicit loopback SOCKS5 endpoint. Requests use
    /// SOCKS username/password isolation, remote DNS, and never fall back to a
    /// direct socket.
    pub fn tor(proxy: SocketAddr) -> Result<Self> {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(TransportError::UnsupportedHint);
        }
        Ok(Self {
            ingress: RendezvousIngress::Tor(proxy),
            timeout: RENDEZVOUS_HTTP_TIMEOUT,
        })
    }

    /// Inspect the configured ingress without exposing any request state.
    pub fn ingress(&self) -> RendezvousIngress {
        self.ingress
    }

    async fn request(
        &self,
        provider: &RendezvousProvider,
        path: &str,
        body: &[u8],
        expected_response_len: usize,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout(
            self.timeout,
            self.request_inner(provider, path, body, expected_response_len),
        )
        .await
        .map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "rendezvous request deadline",
            ))
        })?
    }

    async fn request_inner(
        &self,
        provider: &RendezvousProvider,
        path: &str,
        body: &[u8],
        expected_response_len: usize,
    ) -> Result<Vec<u8>> {
        let authority = parse_origin(provider.origin()).ok_or(TransportError::UnsupportedHint)?;
        let socket = match self.ingress {
            RendezvousIngress::Direct => {
                TcpStream::connect((authority.host.as_str(), authority.port)).await?
            }
            RendezvousIngress::Tor(proxy) => {
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
                TransportError::Io(io::Error::other(format!(
                    "rendezvous TLS configuration: {error}"
                )))
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
                TransportError::Io(io::Error::other(format!(
                    "rendezvous TLS handshake: {error}"
                )))
            })?;

        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            authority.http_authority,
            body.len()
        );
        tls.write_all(header.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await?;
        let response = read_http_response(&mut tls, expected_response_len).await?;
        let _ = tls.shutdown().await;
        Ok(response)
    }
}

#[async_trait]
impl RendezvousClient for HttpsRendezvousClient {
    async fn register(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousRegisterRequest,
    ) -> Result<[u8; RENDEZVOUS_REGISTER_ACK_LEN]> {
        let body = request.encode().map_err(TransportError::Protocol)?;
        let response = self
            .request(
                provider,
                RENDEZVOUS_REGISTER_PATH,
                &body,
                RENDEZVOUS_REGISTER_ACK_LEN,
            )
            .await?;
        response.try_into().map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "rendezvous register response length",
            ))
        })
    }

    async fn lookup(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousLookupRequest,
    ) -> Result<[u8; RENDEZVOUS_SEALED_RECORD_LEN]> {
        let response = self
            .request(
                provider,
                RENDEZVOUS_LOOKUP_PATH,
                &request.encode(),
                RENDEZVOUS_LOOKUP_RESPONSE_LEN,
            )
            .await?;
        response.try_into().map_err(|_| {
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "rendezvous lookup response length",
            ))
        })
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
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
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
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
    if !canonical_https_origin(origin) {
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
    // Username/password is deliberately the only offered method. Tor accepts
    // arbitrary credentials and, with IsolateSOCKSAuth, gives each request a
    // separate circuit identity.
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor proxy refused stream isolation",
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
            "Tor rendezvous connection refused",
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

async fn read_http_response<S>(stream: &mut S, expected_body: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    if expected_body > RENDEZVOUS_SEALED_RECORD_LEN {
        return Err(TransportError::UnsupportedHint);
    }
    let mut response = Vec::with_capacity(MAX_RENDEZVOUS_HTTP_RESPONSE_BYTES);
    let header_end = loop {
        if response.len() >= MAX_RENDEZVOUS_HTTP_HEADER_BYTES {
            return Err(invalid_http("rendezvous response header exceeds bound"));
        }
        let mut chunk = [0u8; 1024];
        let remaining = MAX_RENDEZVOUS_HTTP_HEADER_BYTES - response.len();
        let chunk_len = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..chunk_len]).await?;
        if read == 0 {
            return Err(invalid_http("truncated rendezvous response header"));
        }
        response.extend_from_slice(&chunk[..read]);
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let already_read = response.len() - header_end;
    if already_read > expected_body {
        return Err(invalid_http("oversized rendezvous response body"));
    }
    parse_response_header(&response[..header_end], expected_body)?;
    response.resize(header_end + expected_body, 0);
    stream
        .read_exact(&mut response[header_end + already_read..])
        .await?;
    let body = response.split_off(header_end);
    let mut trailing = [0u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(invalid_http("oversized rendezvous response body"));
    }
    Ok(body)
}

fn parse_response_header(bytes: &[u8], expected_body: usize) -> Result<()> {
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(invalid_http("malformed rendezvous response header"));
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 2])
        .map_err(|_| invalid_http("non-UTF-8 rendezvous response header"))?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(invalid_http("unexpected rendezvous HTTP status"));
    }
    let mut content_type = false;
    let mut content_length = false;
    let mut no_store = false;
    let mut close = false;
    for line in lines.filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) || line.contains('\t') {
            return Err(invalid_http("folded rendezvous response header"));
        }
        let (name, value) = line
            .split_once(": ")
            .ok_or_else(|| invalid_http("malformed rendezvous response field"))?;
        match name.to_ascii_lowercase().as_str() {
            "content-type" if !content_type && value == RENDEZVOUS_MEDIA_TYPE => {
                content_type = true
            }
            "content-length"
                if !content_length
                    && value.parse::<usize>().ok() == Some(expected_body)
                    && value == expected_body.to_string() =>
            {
                content_length = true
            }
            "cache-control" if !no_store && value.eq_ignore_ascii_case("no-store") => {
                no_store = true
            }
            "connection" if !close && value.eq_ignore_ascii_case("close") => close = true,
            _ => return Err(invalid_http("unsafe rendezvous response field")),
        }
    }
    if !content_type || !content_length || !no_store || !close {
        return Err(invalid_http("incomplete rendezvous response policy"));
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

/// Convert an authenticated record route into the existing transport hint,
/// rejecting non-canonical or non-addressable multiaddresses.
pub fn rendezvous_route_hint(route: &RendezvousRoute) -> Result<DeliveryHint> {
    if parse_addr(&route.value).is_none() {
        return Err(TransportError::UnsupportedHint);
    }
    Ok(match route.kind {
        RendezvousRouteKind::Multiaddr => DeliveryHint::Multiaddr(route.value.clone()),
        RendezvousRouteKind::MailboxRelay => DeliveryHint::Relay(route.value.clone()),
    })
}

/// Convert a local transport hint into a canonical rendezvous route.
pub fn rendezvous_record_route(hint: &DeliveryHint) -> Result<RendezvousRoute> {
    let (kind, value) = match hint {
        DeliveryHint::Multiaddr(value) => (RendezvousRouteKind::Multiaddr, value),
        DeliveryHint::Relay(value) => (RendezvousRouteKind::MailboxRelay, value),
        DeliveryHint::Spool(_) | DeliveryHint::MeshNode(_) => {
            return Err(TransportError::UnsupportedHint);
        }
    };
    if parse_addr(value).is_none() {
        return Err(TransportError::UnsupportedHint);
    }
    Ok(RendezvousRoute {
        kind,
        value: value.clone(),
    })
}

fn canonical_https_origin(origin: &str) -> bool {
    const PREFIX: &str = "https://";
    if origin.len() <= PREFIX.len()
        || origin.len() > MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES
        || !origin.starts_with(PREFIX)
        || origin.ends_with('/')
    {
        return false;
    }
    let authority = &origin[PREFIX.len()..];
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_uppercase()
                || matches!(byte, b'/' | b'?' | b'#' | b'@' | 0)
        })
    {
        return false;
    }
    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        if host.is_empty()
            || !Ipv6Addr::from_str(host).is_ok_and(|address| address.to_string() == host)
        {
            return false;
        }
        if suffix.is_empty() {
            None
        } else {
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            Some(port)
        }
    } else {
        if authority.matches(':').count() > 1 {
            return false;
        }
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if !canonical_host(host) {
            return false;
        }
        port
    };
    port.is_none_or(canonical_nondefault_port)
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if let Ok(address) = Ipv4Addr::from_str(host) {
        return address.to_string() == host;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn canonical_nondefault_port(port: &str) -> bool {
    port.parse::<u16>()
        .is_ok_and(|value| value != 0 && value != 443 && value.to_string() == port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn provider_origins_are_canonical_and_key_bound() {
        let provider =
            RendezvousProvider::new("https://rv.example:8443".into(), [1u8; 32]).unwrap();
        assert_eq!(provider.origin(), "https://rv.example:8443");
        assert_ne!(provider.provider_id(), [0u8; 32]);
        assert_ne!(
            provider.provider_id(),
            RendezvousProvider::new("https://rv.example:8443".into(), [2u8; 32])
                .unwrap()
                .provider_id()
        );
        for invalid in [
            "http://rv.example",
            "https://RV.example",
            "https://rv.example/",
            "https://user@rv.example",
            "https://rv.example/path",
            "https://rv.example?q",
            "https://rv example",
            "https://rv.example:443",
            "https://rv.example:0443",
            "https://rv.example:0",
            "https://-rv.example",
            "https://rv-.example",
            "https://rv..example",
            "https://:",
            "https://2001:db8::1",
            "https://[2001:0db8::1]",
        ] {
            assert!(RendezvousProvider::new(invalid.into(), [1u8; 32]).is_err());
        }
        assert!(RendezvousProvider::new("https://[2001:db8::1]:8443".into(), [1u8; 32]).is_ok());
    }

    #[tokio::test]
    async fn strict_https_client_pins_leaf_and_accepts_only_fixed_response_policy() {
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
        let expected = [0x5au8; RENDEZVOUS_SEALED_RECORD_LEN];
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
            request.resize(header_end + 64, 0);
            tls.read_exact(&mut request[header_end + present..])
                .await
                .unwrap();
            assert!(request.starts_with(b"POST /v1/rendezvous/lookup HTTP/1.1\r\n"));
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: {RENDEZVOUS_SEALED_RECORD_LEN}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            );
            tls.write_all(header.as_bytes()).await.unwrap();
            tls.write_all(&expected).await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let provider =
            RendezvousProvider::new(format!("https://127.0.0.1:{}", address.port()), digest)
                .unwrap();
        let response = HttpsRendezvousClient::direct()
            .lookup(
                &provider,
                &RendezvousLookupRequest {
                    slot: [1u8; 32],
                    epoch: 7,
                },
            )
            .await
            .unwrap();
        assert_eq!(response, expected);
        task.await.unwrap();

        let verifier = PinnedCertificateVerifier::new([9u8; 32]);
        assert!(verifier
            .verify_server_cert(
                cert.der(),
                &[],
                &ServerName::try_from("localhost").unwrap(),
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(1)),
            )
            .is_err());
    }

    #[tokio::test]
    async fn tor_path_uses_isolated_auth_and_remote_dns_without_direct_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            socket.write_all(&[5, 2]).await.unwrap();

            let mut auth_head = [0u8; 2];
            socket.read_exact(&mut auth_head).await.unwrap();
            assert_eq!(auth_head, [1, 32]);
            let mut username = [0u8; 32];
            socket.read_exact(&mut username).await.unwrap();
            assert!(username.iter().all(u8::is_ascii_hexdigit));
            let mut password_len = [0u8; 1];
            socket.read_exact(&mut password_len).await.unwrap();
            assert_eq!(password_len, [32]);
            let mut password = [0u8; 32];
            socket.read_exact(&mut password).await.unwrap();
            assert!(password.iter().all(u8::is_ascii_hexdigit));
            assert_ne!(username, password);
            socket.write_all(&[1, 0]).await.unwrap();

            let mut request_head = [0u8; 5];
            socket.read_exact(&mut request_head).await.unwrap();
            assert_eq!(&request_head[..4], &[5, 1, 0, 3]);
            let mut host = vec![0u8; usize::from(request_head[4])];
            socket.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"rv.private.example");
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 8443);
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x20, 0xfb])
                .await
                .unwrap();
        });
        let mut client = TcpStream::connect(proxy).await.unwrap();
        tor_connect(&mut client, "rv.private.example", 8443)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn response_parser_rejects_extra_headers_and_wrong_shape() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            writer
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/komms-rendezvous-v1\r\nContent-Length: 64\r\nCache-Control: no-store\r\nConnection: close\r\nSet-Cookie: x=y\r\n\r\n",
                )
                .await
                .unwrap();
            writer.write_all(&[0u8; 64]).await.unwrap();
        });
        assert!(read_http_response(&mut reader, 64).await.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn response_parser_enforces_header_bound_and_exact_end_of_response() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: 64\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            );
            writer.write_all(header.as_bytes()).await.unwrap();
            writer.write_all(&[0u8; 65]).await.unwrap();
        });
        assert!(read_http_response(&mut reader, 64).await.is_err());
        task.await.unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_RENDEZVOUS_HTTP_HEADER_BYTES])
                .await
                .unwrap();
        });
        assert!(read_http_response(&mut reader, 64).await.is_err());
        task.await.unwrap();
    }
}
