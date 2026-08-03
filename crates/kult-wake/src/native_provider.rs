use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use zeroize::{Zeroize, Zeroizing};

use kult_protocol::{WakeEnvironment, WakePlatform, WakeProfile};

use crate::config::{ApnsPolicy, FcmPolicy, ProviderPolicy};
use crate::provider::{NativePushProvider, NativePushRequest, ProviderErrorClass};
use crate::{Result, WakeError};

const APNS_PRODUCTION_HOST: &str = "api.push.apple.com";
const APNS_DEVELOPMENT_HOST: &str = "api.sandbox.push.apple.com";
const FCM_HOST: &str = "fcm.googleapis.com";
const FCM_TOKEN_HOST: &str = "oauth2.googleapis.com";
const FCM_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const MAX_CA_BYTES: u64 = 2 * 1024 * 1024;
const MAX_APNS_KEY_BYTES: u64 = 32 * 1024;
const MAX_FCM_CREDENTIAL_BYTES: u64 = 128 * 1024;
const MAX_CA_CERTIFICATES: usize = 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 8192;

pub(crate) struct HttpNativePushProvider {
    tls: Arc<ClientConfig>,
    timeout: Duration,
    max_response_bytes: usize,
    apns: Option<ApnsCredentials>,
    fcm: Option<FcmCredentials>,
    fcm_token: Mutex<Option<CachedAccessToken>>,
}

struct ApnsCredentials {
    signing_key: Arc<EcdsaKeyPair>,
    key_id: String,
    team_id: String,
    allowed_topics: BTreeSet<Vec<u8>>,
}

struct FcmCredentials {
    signing_key: Arc<RsaKeyPair>,
    private_key_id: String,
    project_id: String,
    client_email: String,
    allowed_topics: BTreeSet<Vec<u8>>,
}

struct CachedAccessToken {
    value: Zeroizing<String>,
    expires_at: u64,
}

impl HttpNativePushProvider {
    pub(crate) fn open(config: &ProviderPolicy) -> Result<Self> {
        let tls = load_provider_tls(&config.ca_certificate_file)?;
        let apns = config.apns.as_ref().map(load_apns).transpose()?;
        let fcm = config.fcm.as_ref().map(load_fcm).transpose()?;
        Ok(Self {
            tls,
            timeout: Duration::from_secs(config.request_timeout_seconds),
            max_response_bytes: config.max_response_bytes,
            apns,
            fcm,
            fcm_token: Mutex::new(None),
        })
    }

    async fn send_apns(
        &self,
        request: &NativePushRequest,
    ) -> core::result::Result<(), ProviderErrorClass> {
        let credentials = self.apns.as_ref().ok_or(ProviderErrorClass::Other)?;
        if !credentials.allowed_topics.contains(request.app_topic()) {
            return Err(ProviderErrorClass::InvalidDestination);
        }
        let host = match request.environment() {
            WakeEnvironment::Development => APNS_DEVELOPMENT_HOST,
            WakeEnvironment::Production => APNS_PRODUCTION_HOST,
        };
        let provider_request = build_apns_request(credentials, request, host, unix_now())?;
        let (status, body) = self.send_http2(host, provider_request).await?;
        classify_apns(status, &body)
    }

    async fn send_fcm(
        &self,
        request: &NativePushRequest,
    ) -> core::result::Result<(), ProviderErrorClass> {
        let credentials = self.fcm.as_ref().ok_or(ProviderErrorClass::Other)?;
        if request.environment() != WakeEnvironment::Production
            || !credentials.allowed_topics.contains(request.app_topic())
        {
            return Err(ProviderErrorClass::InvalidDestination);
        }
        let now = unix_now();
        let access_token = self.fcm_access_token(credentials, now).await?;
        let provider_request = build_fcm_request(credentials, request, &access_token)?;
        let (status, body) = self.send_http2(FCM_HOST, provider_request).await?;
        classify_fcm(status, &body)
    }

    async fn fcm_access_token(
        &self,
        credentials: &FcmCredentials,
        now: u64,
    ) -> core::result::Result<Zeroizing<String>, ProviderErrorClass> {
        let mut cache = self.fcm_token.lock().await;
        if let Some(token) = cache.as_ref() {
            if token.expires_at.saturating_sub(60) > now {
                return Ok(Zeroizing::new(token.value.to_string()));
            }
        }
        *cache = None;
        let assertion = fcm_assertion(credentials, now)?;
        let mut body = Zeroizing::new(
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
                assertion.as_str()
            )
            .into_bytes(),
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri(FCM_TOKEN_URI)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::copy_from_slice(&body)))
            .map_err(|_| ProviderErrorClass::Other)?;
        body.zeroize();
        let (status, response) = self.send_http2(FCM_TOKEN_HOST, request).await?;
        if !status.is_success() {
            return Err(classify_oauth(status));
        }
        let mut decoded: OAuthTokenResponse =
            serde_json::from_slice(&response).map_err(|_| ProviderErrorClass::Authentication)?;
        if !decoded.token_type.eq_ignore_ascii_case("bearer")
            || decoded.access_token.is_empty()
            || decoded.access_token.len() > MAX_ACCESS_TOKEN_BYTES
            || !(120..=7200).contains(&decoded.expires_in)
        {
            decoded.access_token.zeroize();
            return Err(ProviderErrorClass::Authentication);
        }
        let value = Zeroizing::new(core::mem::take(&mut decoded.access_token));
        let expires_at = now.saturating_add(decoded.expires_in);
        *cache = Some(CachedAccessToken {
            value: Zeroizing::new(value.to_string()),
            expires_at,
        });
        Ok(value)
    }

    async fn send_http2(
        &self,
        host: &'static str,
        request: Request<Full<Bytes>>,
    ) -> core::result::Result<(StatusCode, Zeroizing<Vec<u8>>), ProviderErrorClass> {
        tokio::time::timeout(self.timeout, async {
            let tcp = TcpStream::connect((host, 443))
                .await
                .map_err(|_| ProviderErrorClass::Unavailable)?;
            tcp.set_nodelay(true)
                .map_err(|_| ProviderErrorClass::Unavailable)?;
            let name = ServerName::try_from(host)
                .map_err(|_| ProviderErrorClass::Other)?
                .to_owned();
            let tls = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await
                .map_err(|_| ProviderErrorClass::Unavailable)?;
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .map_err(|_| ProviderErrorClass::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| ProviderErrorClass::Unavailable)?;
            let status = response.status();
            let body = collect_bounded(response.into_body(), self.max_response_bytes).await?;
            drop(sender);
            driver.abort();
            let _ = driver.await;
            Ok((status, body))
        })
        .await
        .map_err(|_| ProviderErrorClass::Unavailable)?
    }
}

#[async_trait]
impl NativePushProvider for HttpNativePushProvider {
    async fn send(
        &self,
        request: NativePushRequest,
    ) -> core::result::Result<(), ProviderErrorClass> {
        match request.platform() {
            WakePlatform::Apns => self.send_apns(&request).await,
            WakePlatform::Fcm => self.send_fcm(&request).await,
        }
    }
}

fn build_apns_request(
    credentials: &ApnsCredentials,
    request: &NativePushRequest,
    host: &str,
    now: u64,
) -> core::result::Result<Request<Full<Bytes>>, ProviderErrorClass> {
    let token = canonical_apns_token(request.provider_token())
        .ok_or(ProviderErrorClass::InvalidDestination)?;
    let topic = core::str::from_utf8(request.app_topic())
        .map_err(|_| ProviderErrorClass::InvalidDestination)?;
    let bearer = apns_bearer(credentials, now)?;
    let uri = format!("https://{host}/3/device/{}", token.as_str());
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("bearer {}", bearer.as_str()))
        .header("apns-topic", topic)
        .header(
            "apns-push-type",
            request.apns_push_type().ok_or(ProviderErrorClass::Other)?,
        )
        .header(
            "apns-priority",
            request
                .apns_priority()
                .ok_or(ProviderErrorClass::Other)?
                .to_string(),
        )
        .header("apns-expiration", "0")
        .header("apns-collapse-id", hex::encode(request.collapse_id()))
        .body(Full::new(Bytes::from_static(request.payload())))
        .map_err(|_| ProviderErrorClass::Other)
}

fn build_fcm_request(
    credentials: &FcmCredentials,
    request: &NativePushRequest,
    access_token: &str,
) -> core::result::Result<Request<Full<Bytes>>, ProviderErrorClass> {
    let token = core::str::from_utf8(request.provider_token())
        .map_err(|_| ProviderErrorClass::InvalidDestination)?;
    if token.is_empty()
        || token.len() > kult_protocol::MAX_WAKE_PROVIDER_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProviderErrorClass::InvalidDestination);
    }
    let collapse = hex::encode(request.collapse_id());
    let android_priority = if request.fcm_high_priority() {
        "HIGH"
    } else {
        "NORMAL"
    };
    let notification = match request.profile() {
        WakeProfile::BackgroundOnly => serde_json::Value::Null,
        WakeProfile::GenericVisible => json!({
            "title": "Komms",
            "body": "New activity"
        }),
    };
    let mut message = json!({
        "token": token,
        "data": {"wake": "1"},
        "android": {
            "priority": android_priority,
            "collapse_key": collapse,
            "ttl": "60s"
        }
    });
    if notification != serde_json::Value::Null {
        message["notification"] = notification;
        message["android"]["notification"] = json!({"tag": collapse});
    }
    let mut body = Zeroizing::new(
        serde_json::to_vec(&json!({"message": message})).map_err(|_| ProviderErrorClass::Other)?,
    );
    if body.len() > 4096 {
        return Err(ProviderErrorClass::Other);
    }
    let uri = format!(
        "https://{FCM_HOST}/v1/projects/{}/messages:send",
        credentials.project_id
    );
    let built = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Full::new(Bytes::copy_from_slice(&body)))
        .map_err(|_| ProviderErrorClass::Other);
    body.zeroize();
    built
}

fn apns_bearer(
    credentials: &ApnsCredentials,
    now: u64,
) -> core::result::Result<Zeroizing<String>, ProviderErrorClass> {
    let header = json!({"alg": "ES256", "kid": credentials.key_id});
    let claims = json!({"iss": credentials.team_id, "iat": now});
    let header = serde_json::to_vec(&header).map_err(|_| ProviderErrorClass::Authentication)?;
    let claims = serde_json::to_vec(&claims).map_err(|_| ProviderErrorClass::Authentication)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = credentials
        .signing_key
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| ProviderErrorClass::Authentication)?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )))
}

fn fcm_assertion(
    credentials: &FcmCredentials,
    now: u64,
) -> core::result::Result<Zeroizing<String>, ProviderErrorClass> {
    let expires_at = now
        .checked_add(3600)
        .ok_or(ProviderErrorClass::Authentication)?;
    let header = json!({
        "alg": "RS256",
        "kid": credentials.private_key_id,
        "typ": "JWT"
    });
    let claims = json!({
        "iss": credentials.client_email,
        "scope": FCM_SCOPE,
        "aud": FCM_TOKEN_URI,
        "iat": now,
        "exp": expires_at
    });
    let header = serde_json::to_vec(&header).map_err(|_| ProviderErrorClass::Authentication)?;
    let claims = serde_json::to_vec(&claims).map_err(|_| ProviderErrorClass::Authentication)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let mut signature = vec![0u8; credentials.signing_key.public().modulus_len()];
    credentials
        .signing_key
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| ProviderErrorClass::Authentication)?;
    let assertion = Zeroizing::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    ));
    signature.zeroize();
    Ok(assertion)
}

fn canonical_apns_token(token: &[u8]) -> Option<Zeroizing<String>> {
    if token.len() == 32 {
        return Some(Zeroizing::new(hex::encode(token)));
    }
    if token.len() == 64 && token.iter().all(u8::is_ascii_hexdigit) {
        let value = core::str::from_utf8(token).ok()?.to_ascii_lowercase();
        return Some(Zeroizing::new(value));
    }
    None
}

fn classify_apns(status: StatusCode, body: &[u8]) -> core::result::Result<(), ProviderErrorClass> {
    if status.is_success() {
        return Ok(());
    }
    match status.as_u16() {
        401 | 403 => Err(ProviderErrorClass::Authentication),
        429 => Err(ProviderErrorClass::RateLimited),
        500 | 503 => Err(ProviderErrorClass::Unavailable),
        410 => Err(ProviderErrorClass::InvalidDestination),
        400 if apns_invalid_destination(body) => Err(ProviderErrorClass::InvalidDestination),
        _ => Err(ProviderErrorClass::Other),
    }
}

fn classify_fcm(status: StatusCode, body: &[u8]) -> core::result::Result<(), ProviderErrorClass> {
    if status.is_success() {
        return Ok(());
    }
    match status.as_u16() {
        401 | 403 => Err(ProviderErrorClass::Authentication),
        429 => Err(ProviderErrorClass::RateLimited),
        500..=599 => Err(ProviderErrorClass::Unavailable),
        404 => Err(ProviderErrorClass::InvalidDestination),
        400 if fcm_invalid_destination(body) => Err(ProviderErrorClass::InvalidDestination),
        _ => Err(ProviderErrorClass::Other),
    }
}

fn classify_oauth(status: StatusCode) -> ProviderErrorClass {
    match status.as_u16() {
        400 | 401 | 403 => ProviderErrorClass::Authentication,
        429 => ProviderErrorClass::RateLimited,
        500..=599 => ProviderErrorClass::Unavailable,
        _ => ProviderErrorClass::Other,
    }
}

fn apns_invalid_destination(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct ApnsError<'a> {
        reason: &'a str,
    }
    serde_json::from_slice::<ApnsError<'_>>(body).is_ok_and(|error| {
        matches!(
            error.reason,
            "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered"
        )
    })
}

fn fcm_invalid_destination(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value
        .pointer("/error/details")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|details| {
            details.iter().any(|detail| {
                detail
                    .get("errorCode")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|code| matches!(code, "UNREGISTERED" | "INVALID_ARGUMENT"))
            })
        })
}

async fn collect_bounded(
    mut body: Incoming,
    max_bytes: usize,
) -> core::result::Result<Zeroizing<Vec<u8>>, ProviderErrorClass> {
    let mut output = Zeroizing::new(Vec::with_capacity(max_bytes.min(4096)));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ProviderErrorClass::Unavailable)?;
        if let Some(data) = frame.data_ref() {
            if output.len().saturating_add(data.len()) > max_bytes {
                return Err(ProviderErrorClass::Other);
            }
            output.extend_from_slice(data);
        }
    }
    Ok(output)
}

fn load_provider_tls(path: &Path) -> Result<Arc<ClientConfig>> {
    let bytes = read_bounded_regular(path, MAX_CA_BYTES, false, "provider CA certificate")?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| WakeError::Invalid("provider CA certificate encoding is invalid"))?;
    if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
        return Err(WakeError::Invalid(
            "provider CA certificate count is outside 1..=1024",
        ));
    }
    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(certificates);
    if accepted == 0 {
        return Err(WakeError::Invalid(
            "provider CA file contains no accepted certificates",
        ));
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| WakeError::Invalid("provider TLS 1.3 configuration failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.enable_early_data = false;
    Ok(Arc::new(tls))
}

fn load_apns(config: &ApnsPolicy) -> Result<ApnsCredentials> {
    let bytes = read_bounded_regular(
        &config.signing_key_file,
        MAX_APNS_KEY_BYTES,
        true,
        "APNs signing key",
    )?;
    let mut keys = PrivatePkcs8KeyDer::pem_slice_iter(&bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| WakeError::Invalid("APNs signing key encoding is invalid"))?;
    if keys.len() != 1 {
        return Err(WakeError::Invalid(
            "APNs signing key file must contain one PKCS#8 key",
        ));
    }
    let key = keys.remove(0);
    let signing_key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        key.secret_pkcs8_der(),
        &SystemRandom::new(),
    )
    .map_err(|_| WakeError::Invalid("APNs signing key is not P-256"))?;
    Ok(ApnsCredentials {
        signing_key: Arc::new(signing_key),
        key_id: config.key_id.clone(),
        team_id: config.team_id.clone(),
        allowed_topics: config
            .allowed_topics
            .iter()
            .map(|topic| topic.as_bytes().to_vec())
            .collect(),
    })
}

fn load_fcm(config: &FcmPolicy) -> Result<FcmCredentials> {
    let bytes = read_bounded_regular(
        &config.service_account_file,
        MAX_FCM_CREDENTIAL_BYTES,
        true,
        "FCM service account",
    )?;
    let mut account: ServiceAccount = serde_json::from_slice(&bytes)
        .map_err(|_| WakeError::Invalid("FCM service account encoding is invalid"))?;
    if account.kind != "service_account"
        || account.token_uri != FCM_TOKEN_URI
        || account.project_id.is_empty()
        || account.project_id.len() > 256
        || account.private_key_id.is_empty()
        || account.private_key_id.len() > 256
        || account.client_email.is_empty()
        || account.client_email.len() > 512
    {
        account.private_key.zeroize();
        return Err(WakeError::Invalid("FCM service account fields are invalid"));
    }
    let key_bytes = Zeroizing::new(account.private_key.as_bytes().to_vec());
    account.private_key.zeroize();
    let mut keys = PrivatePkcs8KeyDer::pem_slice_iter(&key_bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| WakeError::Invalid("FCM private key encoding is invalid"))?;
    if keys.len() != 1 {
        return Err(WakeError::Invalid(
            "FCM service account must contain one PKCS#8 key",
        ));
    }
    let key = keys.remove(0);
    let signing_key = RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
        .map_err(|_| WakeError::Invalid("FCM private key is not RSA PKCS#8"))?;
    Ok(FcmCredentials {
        signing_key: Arc::new(signing_key),
        private_key_id: account.private_key_id.clone(),
        project_id: account.project_id.clone(),
        client_email: account.client_email.clone(),
        allowed_topics: config
            .allowed_topics
            .iter()
            .map(|topic| topic.as_bytes().to_vec())
            .collect(),
    })
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAccount {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: Option<String>,
    auth_uri: Option<String>,
    token_uri: String,
    auth_provider_x509_cert_url: Option<String>,
    client_x509_cert_url: Option<String>,
    universe_domain: Option<String>,
}

impl Drop for ServiceAccount {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.client_id.zeroize();
        self.auth_uri.zeroize();
        self.auth_provider_x509_cert_url.zeroize();
        self.client_x509_cert_url.zeroize();
        self.universe_domain.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SecureRandom;

    use super::*;

    fn apns_credentials() -> ApnsCredentials {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let signing_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_ref(), &rng).unwrap();
        ApnsCredentials {
            signing_key: Arc::new(signing_key),
            key_id: "KEY123".into(),
            team_id: "TEAM123".into(),
            allowed_topics: BTreeSet::from([b"is.komms.app".to_vec()]),
        }
    }

    fn request(platform: WakePlatform, profile: WakeProfile) -> NativePushRequest {
        NativePushRequest::new(
            platform,
            WakeEnvironment::Production,
            profile,
            vec![7u8; 32],
            match platform {
                WakePlatform::Apns => b"is.komms.app".to_vec(),
                WakePlatform::Fcm => b"is.komms.android".to_vec(),
            },
            [9u8; 16],
        )
    }

    #[test]
    fn apns_request_has_only_static_profile_and_required_headers() {
        let credentials = apns_credentials();
        let built = build_apns_request(
            &credentials,
            &request(WakePlatform::Apns, WakeProfile::BackgroundOnly),
            APNS_PRODUCTION_HOST,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(built.headers()["apns-push-type"], "background");
        assert_eq!(built.headers()["apns-priority"], "5");
        assert_eq!(built.headers()["apns-topic"], "is.komms.app");
        assert_eq!(
            built.headers()["apns-collapse-id"],
            "09090909090909090909090909090909"
        );
        assert!(built.uri().path().ends_with(&hex::encode([7u8; 32])));
    }

    #[test]
    fn provider_errors_are_reduced_without_returning_provider_text() {
        assert_eq!(
            classify_apns(StatusCode::BAD_REQUEST, br#"{"reason":"BadDeviceToken"}"#),
            Err(ProviderErrorClass::InvalidDestination)
        );
        assert_eq!(
            classify_fcm(
                StatusCode::BAD_REQUEST,
                br#"{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}"#
            ),
            Err(ProviderErrorClass::InvalidDestination)
        );
        assert_eq!(
            classify_fcm(StatusCode::SERVICE_UNAVAILABLE, b"provider detail"),
            Err(ProviderErrorClass::Unavailable)
        );
    }

    #[test]
    fn apns_tokens_are_strict_and_canonical() {
        assert_eq!(
            canonical_apns_token(&[0xabu8; 32]).unwrap().as_str(),
            "ab".repeat(32)
        );
        assert_eq!(
            canonical_apns_token(
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .unwrap()
            .as_str(),
            "a".repeat(64)
        );
        assert!(canonical_apns_token(b"native-token-secret").is_none());
    }

    #[test]
    fn system_random_is_available_for_provider_signatures() {
        let mut byte = [0u8; 1];
        SystemRandom::new().fill(&mut byte).unwrap();
    }
}
