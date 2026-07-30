use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

use kult_protocol::{
    RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_LOOKUP_REQUEST_LEN, RENDEZVOUS_MEDIA_TYPE,
    RENDEZVOUS_REGISTER_PATH, RENDEZVOUS_REGISTER_REQUEST_LEN,
};
use kult_rendezvous::{ClientAdmissionKey, RendezvousService, ServiceResponse};

use crate::config::{RendezvousConfig, DEFAULT_SOURCE_REVISION};
use crate::dht::DhtMetrics;
use crate::runtime::{HealthSnapshot, ServiceError};

const MAX_HTTP_HEADER_BYTES: usize = 4 * 1024;
const RATE_WINDOW_SECONDS: u64 = 60;
const HEALTH_REQUEST_BYTES: usize = 1024;
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTH_RESPONSE_MAX_BYTES: usize = 1024;

pub(crate) struct RendezvousNetwork {
    config: RendezvousConfig,
    service: Arc<RendezvousService>,
}

impl RendezvousNetwork {
    pub(crate) fn new(config: RendezvousConfig) -> Result<Self, ServiceError> {
        let service = RendezvousService::new(config.service_config())
            .ok_or_else(|| ServiceError::invalid("rendezvous component limits are inconsistent"))?;
        Ok(Self {
            config,
            service: Arc::new(service),
        })
    }

    pub(crate) fn service(&self) -> Arc<RendezvousService> {
        Arc::clone(&self.service)
    }

    pub(crate) async fn run(
        self,
        tls: Arc<rustls::ServerConfig>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ServiceError> {
        let listener = TcpListener::bind(self.config.listen)
            .await
            .map_err(|error| ServiceError::io("bind rendezvous TLS listener", error))?;
        let acceptor = TlsAcceptor::from(tls);
        let semaphore = Arc::new(Semaphore::new(self.config.max_tls_connections));
        let mut ingress_secret = [0u8; 32];
        OsRng.fill_bytes(&mut ingress_secret);
        let mut ingress = IngressAdmission::new(
            ingress_secret,
            self.config.max_connections_per_minute,
            self.config.max_connections_per_address_per_minute,
            self.config.max_ingress_rate_buckets,
        );
        let handshake_timeout = Duration::from_secs(self.config.tls_handshake_timeout_seconds);
        let request_timeout = Duration::from_secs(self.config.request_timeout_seconds);
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
                    let (socket, remote) = accepted
                        .map_err(|error| ServiceError::io("accept rendezvous connection", error))?;
                    let Some(client) = ingress.admit(remote.ip()) else {
                        drop(socket);
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                        drop(socket);
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let service = Arc::clone(&self.service);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = serve_tls_connection(
                            socket,
                            acceptor,
                            service,
                            client,
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
}

async fn serve_tls_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    service: Arc<RendezvousService>,
    client: ClientAdmissionKey,
    handshake_timeout: Duration,
    request_timeout: Duration,
) -> Result<(), ServiceError> {
    socket
        .set_nodelay(true)
        .map_err(|error| ServiceError::io("configure rendezvous socket", error))?;
    let mut tls = tokio::time::timeout(handshake_timeout, acceptor.accept(socket))
        .await
        .map_err(|_| ServiceError::invalid("rendezvous TLS handshake deadline"))?
        .map_err(|error| ServiceError::invalid(format!("rendezvous TLS handshake: {error}")))?;
    tokio::time::timeout(
        request_timeout,
        serve_one_request(&mut tls, &service, client),
    )
    .await
    .map_err(|_| ServiceError::invalid("rendezvous request deadline"))??;
    let _ = tls.shutdown().await;
    Ok(())
}

async fn serve_one_request<S>(
    stream: &mut S,
    service: &RendezvousService,
    client: ClientAdmissionKey,
) -> Result<(), ServiceError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let parsed = read_request(stream).await;
    let mut rng = OsRng;
    let response = match parsed {
        Ok(request) => service.handle(
            request.path,
            RENDEZVOUS_MEDIA_TYPE,
            &request.body,
            client,
            unix_now(),
            &mut rng,
        ),
        Err(()) => service.handle(
            "/malformed",
            RENDEZVOUS_MEDIA_TYPE,
            &[],
            client,
            unix_now(),
            &mut rng,
        ),
    };
    write_response(stream, &response).await
}

struct ParsedRequest {
    path: &'static str,
    body: Vec<u8>,
}

async fn read_request<S>(stream: &mut S) -> Result<ParsedRequest, ()>
where
    S: tokio::io::AsyncRead + Unpin,
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
        if let Some(end) = find_header_end(&header[..filled]) {
            break end;
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

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_header(bytes: &[u8]) -> Result<(&'static str, usize), ()> {
    if bytes.len() < 4 || !bytes.ends_with(b"\r\n\r\n") {
        return Err(());
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 2]).map_err(|_| ())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let path = match request_line {
        "POST /v1/rendezvous/register HTTP/1.1" => RENDEZVOUS_REGISTER_PATH,
        "POST /v1/rendezvous/lookup HTTP/1.1" => RENDEZVOUS_LOOKUP_PATH,
        _ => return Err(()),
    };
    let expected_length = match path {
        RENDEZVOUS_REGISTER_PATH => RENDEZVOUS_REGISTER_REQUEST_LEN,
        RENDEZVOUS_LOOKUP_PATH => RENDEZVOUS_LOOKUP_REQUEST_LEN,
        _ => return Err(()),
    };
    let mut host = None;
    let mut media_type = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
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
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);
        if value.is_empty()
            || value.starts_with(' ')
            || value.ends_with(' ')
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(());
        }
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() || value.len() > 255 {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case("content-type") {
            if media_type.replace(value).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(());
            }
            content_length = Some(value.parse::<usize>().map_err(|_| ())?);
        } else if name.eq_ignore_ascii_case("connection") {
            if connection.replace(value).is_some() {
                return Err(());
            }
        } else {
            return Err(());
        }
    }
    if host.is_none()
        || media_type != Some(RENDEZVOUS_MEDIA_TYPE)
        || content_length != Some(expected_length)
        || connection.is_some_and(|value| !value.eq_ignore_ascii_case("close"))
    {
        return Err(());
    }
    Ok((path, expected_length))
}

async fn write_response<S>(stream: &mut S, response: &ServiceResponse) -> Result<(), ServiceError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let status = match response.status {
        200 => "200 OK",
        400 => "400 Bad Request",
        _ => {
            return Err(ServiceError::invalid(
                "unsupported rendezvous response status",
            ))
        }
    };
    if response.media_type != RENDEZVOUS_MEDIA_TYPE || !response.no_store {
        return Err(ServiceError::invalid(
            "rendezvous component returned an unsafe response policy",
        ));
    }
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| ServiceError::io("write rendezvous response", error))?;
    stream
        .write_all(&response.body)
        .await
        .map_err(|error| ServiceError::io("write rendezvous response body", error))
}

struct IngressAdmission {
    secret: [u8; 32],
    max_global: u32,
    max_per_address: u32,
    max_buckets: usize,
    window: u64,
    global: u32,
    buckets: HashMap<[u8; 16], u32>,
}

impl IngressAdmission {
    fn new(secret: [u8; 32], max_global: u32, max_per_address: u32, max_buckets: usize) -> Self {
        Self {
            secret,
            max_global,
            max_per_address,
            max_buckets,
            window: unix_now() / RATE_WINDOW_SECONDS,
            global: 0,
            buckets: HashMap::new(),
        }
    }

    fn admit(&mut self, address: IpAddr) -> Option<ClientAdmissionKey> {
        let window = unix_now() / RATE_WINDOW_SECONDS;
        if window != self.window {
            self.window = window;
            self.global = 0;
            self.buckets.clear();
        }
        if self.global >= self.max_global {
            return None;
        }
        let key = keyed_ip(&self.secret, address, window);
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_buckets {
            return None;
        }
        let count = self.buckets.entry(key).or_default();
        if *count >= self.max_per_address {
            return None;
        }
        *count = count.saturating_add(1);
        self.global = self.global.saturating_add(1);
        Some(ClientAdmissionKey(key))
    }
}

impl Drop for IngressAdmission {
    fn drop(&mut self) {
        self.secret.zeroize();
        for (mut key, _) in self.buckets.drain() {
            key.zeroize();
        }
    }
}

fn keyed_ip(secret: &[u8; 32], address: IpAddr, window: u64) -> [u8; 16] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("fixed HMAC key");
    mac.update(b"komms-rendezvous-ingress-v1");
    mac.update(&window.to_be_bytes());
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

pub(crate) async fn run_health(
    address: SocketAddr,
    dht: DhtMetrics,
    rendezvous: Arc<RendezvousService>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    if !address.ip().is_loopback() {
        return Err(ServiceError::invalid(
            "health listener escaped the loopback boundary",
        ));
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| ServiceError::io("bind health listener", error))?;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (mut socket, remote) = accepted
                    .map_err(|error| ServiceError::io("accept health connection", error))?;
                if !remote.ip().is_loopback() {
                    drop(socket);
                    continue;
                }
                let snapshot = HealthSnapshot {
                    dht_records: dht.record_count(),
                    dht_value_bytes: dht.value_bytes(),
                    rendezvous_records: rendezvous.record_count(),
                    rendezvous_mutable_bytes: rendezvous.accounted_mutable_bytes(),
                };
                let _ = tokio::time::timeout(
                    HEALTH_REQUEST_TIMEOUT,
                    serve_health_request(&mut socket, &snapshot),
                )
                .await;
            }
        }
    }
    Ok(())
}

async fn serve_health_request(
    socket: &mut TcpStream,
    snapshot: &HealthSnapshot,
) -> Result<(), ServiceError> {
    let mut request = [0u8; HEALTH_REQUEST_BYTES];
    let read = socket
        .read(&mut request)
        .await
        .map_err(|error| ServiceError::io("read health request", error))?;
    let valid = request[..read].starts_with(b"GET /healthz HTTP/1.1\r\n")
        && find_header_end(&request[..read]).is_some();
    if !valid {
        socket
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            )
            .await
            .map_err(|error| ServiceError::io("write health refusal", error))?;
        return Ok(());
    }
    let revision = safe_revision(DEFAULT_SOURCE_REVISION);
    let body = format!(
        "{{\"status\":\"ready\",\"roles\":[\"bootstrap-kad-cache\",\"pairwise-rendezvous\"],\"source_revision\":\"{revision}\",\"dht_records\":{},\"dht_value_bytes\":{},\"rendezvous_records\":{},\"rendezvous_mutable_bytes\":{}}}\n",
        snapshot.dht_records,
        snapshot.dht_value_bytes,
        snapshot.rendezvous_records,
        snapshot.rendezvous_mutable_bytes
    );
    if body.len() > HEALTH_RESPONSE_MAX_BYTES {
        return Err(ServiceError::invalid("health response exceeds its bound"));
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket
        .write_all(header.as_bytes())
        .await
        .map_err(|error| ServiceError::io("write health response", error))?;
    socket
        .write_all(body.as_bytes())
        .await
        .map_err(|error| ServiceError::io("write health response body", error))
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

pub(crate) async fn probe_health(address: SocketAddr) -> Result<(), ServiceError> {
    if !address.ip().is_loopback() {
        return Err(ServiceError::invalid(
            "health probe address must be loopback",
        ));
    }
    let mut socket = tokio::time::timeout(HEALTH_REQUEST_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| ServiceError::invalid("health probe connection deadline"))?
        .map_err(|error| ServiceError::io("connect health probe", error))?;
    socket
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| ServiceError::io("write health probe", error))?;
    let response = tokio::time::timeout(HEALTH_REQUEST_TIMEOUT, async {
        let mut response = Vec::with_capacity(HEALTH_RESPONSE_MAX_BYTES);
        let mut chunk = [0u8; 256];
        loop {
            let read = socket
                .read(&mut chunk)
                .await
                .map_err(|error| ServiceError::io("read health probe", error))?;
            if read == 0 {
                break;
            }
            if response.len().saturating_add(read) > HEALTH_RESPONSE_MAX_BYTES {
                return Err(ServiceError::invalid("health probe response exceeds bound"));
            }
            response.extend_from_slice(&chunk[..read]);
        }
        Ok::<_, ServiceError>(response)
    })
    .await
    .map_err(|_| ServiceError::invalid("health probe response deadline"))??;
    if !response.starts_with(b"HTTP/1.1 200 OK\r\n")
        || !response
            .windows(b"\"status\":\"ready\"".len())
            .any(|window| window == b"\"status\":\"ready\"")
    {
        return Err(ServiceError::invalid("health probe was not ready"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_protocol::RENDEZVOUS_MALFORMED_RESPONSE_LEN;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio_rustls::TlsConnector;

    #[test]
    fn canonical_headers_only_and_fixed_lengths() {
        let valid = format!(
            "POST {RENDEZVOUS_LOOKUP_PATH} HTTP/1.1\r\nHost: rendezvous.example\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: {RENDEZVOUS_LOOKUP_REQUEST_LEN}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            parse_header(valid.as_bytes()),
            Ok((RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_LOOKUP_REQUEST_LEN))
        );
        for invalid in [
            valid.replace("Connection: close\r\n", "Transfer-Encoding: chunked\r\n"),
            valid.replace(
                &format!("Content-Length: {RENDEZVOUS_LOOKUP_REQUEST_LEN}"),
                "Content-Length: 4096",
            ),
            valid.replace("\r\n\r\n", "\r\nAuthorization: secret\r\n\r\n"),
            valid.replace(" HTTP/1.1", "?trace=1 HTTP/1.1"),
        ] {
            assert!(parse_header(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn malformed_body_shape_is_fixed() {
        let service = RendezvousService::new(
            RendezvousConfig {
                listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8081".parse().unwrap(),
                max_tls_connections: 1,
                max_connections_per_minute: 4,
                max_connections_per_address_per_minute: 2,
                max_ingress_rate_buckets: 4,
                tls_handshake_timeout_seconds: 2,
                request_timeout_seconds: 2,
                max_records: 1,
                max_memory_bytes: 8 * 1024 * 1024,
                max_concurrent_requests: 1,
                max_global_operations_per_minute: 4,
                max_global_bytes_per_minute: 1_000_000,
                max_slot_operations_per_minute: 2,
                max_slot_buckets: 2,
                max_client_operations_per_minute: 2,
                max_client_buckets: 2,
            }
            .service_config(),
        )
        .unwrap();
        let mut rng = OsRng;
        let response = service.handle(
            "/malformed",
            RENDEZVOUS_MEDIA_TYPE,
            &[],
            ClientAdmissionKey([0u8; 16]),
            unix_now(),
            &mut rng,
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.body.len(), RENDEZVOUS_MALFORMED_RESPONSE_LEN);
    }

    #[tokio::test]
    async fn tls_listener_serves_one_strict_fixed_shape_request() {
        let address = unused_loopback_address().await;
        let config = test_rendezvous_config(address);
        let network = RendezvousNetwork::new(config).unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];

        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(network.run(Arc::new(server), shutdown_receiver));
        let response = send_tls_request(address, Arc::new(client)).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(!response
            .windows(b"\r\nServer:".len())
            .any(|window| window.eq_ignore_ascii_case(b"\r\nServer:")));
        assert!(!response
            .windows(b"\r\nDate:".len())
            .any(|window| window.eq_ignore_ascii_case(b"\r\nDate:")));
        let header_end = find_header_end(&response).unwrap();
        assert_eq!(
            response.len() - header_end,
            kult_crypto::RENDEZVOUS_SEALED_RECORD_LEN
        );
        shutdown_sender.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn aggregate_health_is_loopback_only_and_probeable() {
        let address = unused_loopback_address().await;
        let dht = DhtMetrics::default();
        let rendezvous = Arc::new(
            RendezvousService::new(
                test_rendezvous_config("127.0.0.1:8443".parse().unwrap()).service_config(),
            )
            .unwrap(),
        );
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(run_health(address, dht, rendezvous, shutdown_receiver));
        for _ in 0..50 {
            if probe_health(address).await.is_ok() {
                shutdown_sender.send(true).unwrap();
                task.await.unwrap().unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("health listener did not become ready");
    }

    async fn send_tls_request(address: SocketAddr, client: Arc<rustls::ClientConfig>) -> Vec<u8> {
        let socket = loop {
            match TcpStream::connect(address).await {
                Ok(socket) => break socket,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let connector = TlsConnector::from(client);
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, socket).await.unwrap();
        let header = format!(
            "POST {RENDEZVOUS_LOOKUP_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {RENDEZVOUS_MEDIA_TYPE}\r\nContent-Length: {RENDEZVOUS_LOOKUP_REQUEST_LEN}\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(header.as_bytes()).await.unwrap();
        tls.write_all(&[0u8; RENDEZVOUS_LOOKUP_REQUEST_LEN])
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        response
    }

    async fn unused_loopback_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    fn test_rendezvous_config(listen: SocketAddr) -> RendezvousConfig {
        RendezvousConfig {
            listen,
            health_listen: "127.0.0.1:8081".parse().unwrap(),
            max_tls_connections: 4,
            max_connections_per_minute: 32,
            max_connections_per_address_per_minute: 16,
            max_ingress_rate_buckets: 16,
            tls_handshake_timeout_seconds: 2,
            request_timeout_seconds: 2,
            max_records: 2,
            max_memory_bytes: 8 * 1024 * 1024,
            max_concurrent_requests: 2,
            max_global_operations_per_minute: 32,
            max_global_bytes_per_minute: 1_000_000,
            max_slot_operations_per_minute: 8,
            max_slot_buckets: 8,
            max_client_operations_per_minute: 16,
            max_client_buckets: 8,
        }
    }
}
