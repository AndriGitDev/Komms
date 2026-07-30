//! ADR-0019 fixed-width native-wake capability and HTTP-body codecs.
//!
//! Native provider tokens appear only in the encrypted capability plaintext
//! and the registration request used to mint it. Trigger and revoke requests
//! carry the opaque fixed-width capability and a random replay nonce.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::FromStr;
use sha2::{Digest, Sha256};

use crate::{ProtocolError, Result};

/// Native-wake wire version.
pub const WAKE_VERSION: u8 = 1;
/// Maximum native provider-token bytes carried by one capability.
pub const MAX_WAKE_PROVIDER_TOKEN_BYTES: usize = 512;
/// Maximum application-topic bytes carried by one capability.
pub const MAX_WAKE_APP_TOPIC_BYTES: usize = 128;
/// Exact encrypted capability plaintext length.
pub const WAKE_CAPABILITY_PLAINTEXT_LEN: usize = 704;
/// Exact public opaque capability length.
pub const WAKE_CAPABILITY_LEN: usize = 4 + 24 + WAKE_CAPABILITY_PLAINTEXT_LEN + 16;
/// Exact capability-registration request length.
pub const WAKE_REGISTER_REQUEST_LEN: usize = 768;
/// Exact capability-registration response length.
pub const WAKE_REGISTER_RESPONSE_LEN: usize = 1024;
/// Exact trigger and revoke request length.
pub const WAKE_TRIGGER_REQUEST_LEN: usize = 1024;
/// Exact generic trigger and revoke response length.
pub const WAKE_GENERIC_RESPONSE_LEN: usize = 256;
/// Maximum lifetime of one issued capability.
pub const WAKE_CAPABILITY_MAX_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Capability AEAD associated data.
pub const WAKE_CAPABILITY_ASSOCIATED_DATA: &[u8] = b"Komms-Wake-Capability-v1";
/// Normative HTTP media type.
pub const WAKE_MEDIA_TYPE: &str = "application/komms-wake-v1";
/// Capability-registration endpoint path.
pub const WAKE_REGISTER_PATH: &str = "/v1/wake/register";
/// Trigger endpoint path.
pub const WAKE_TRIGGER_PATH: &str = "/v1/wake/trigger";
/// Possession-authorized revocation endpoint path.
pub const WAKE_REVOKE_PATH: &str = "/v1/wake/revoke";
/// Authenticated pairwise capability-control magic.
pub const WAKE_CAPABILITY_CONTROL_MAGIC: &[u8; 4] = b"KWC1";
/// Authenticated pairwise capability-control version.
pub const WAKE_CAPABILITY_CONTROL_VERSION: u8 = 1;
/// Maximum complete capabilities issued to one remote device.
pub const MAX_WAKE_CONTROL_CAPABILITIES: usize = 4;
/// Maximum canonical wake-gateway origin bytes in one control.
pub const MAX_WAKE_CONTROL_ORIGIN_BYTES: usize = 512;
/// Maximum encoded authenticated pairwise capability-control bytes.
pub const MAX_WAKE_CAPABILITY_CONTROL_BYTES: usize = 4
    + 1
    + 32 * 4
    + 8
    + 8
    + 1
    + MAX_WAKE_CONTROL_CAPABILITIES
        * (2 + MAX_WAKE_CONTROL_ORIGIN_BYTES + 32 + 8 + WAKE_CAPABILITY_LEN);

const CAPABILITY_PAYLOAD_HEADER_LEN: usize = 1 + 1 + 1 + 1 + 8 + 16 + 2;
const CAPABILITY_TOPIC_LEN_OFFSET: usize =
    CAPABILITY_PAYLOAD_HEADER_LEN + MAX_WAKE_PROVIDER_TOKEN_BYTES;
const REGISTER_TOPIC_LEN_OFFSET: usize = 1 + 1 + 1 + 1 + 2 + MAX_WAKE_PROVIDER_TOKEN_BYTES;
const REGISTER_NONCE_OFFSET: usize = REGISTER_TOPIC_LEN_OFFSET + 1 + MAX_WAKE_APP_TOPIC_BYTES;
const REGISTER_RESPONSE_CAPABILITY_OFFSET: usize = 1 + 1 + 8 + 2;
const TRIGGER_CAPABILITY_OFFSET: usize = 1 + 2;
const TRIGGER_NONCE_OFFSET: usize = TRIGGER_CAPABILITY_OFFSET + WAKE_CAPABILITY_LEN;
const CAPABILITY_CONTROL_HEADER_LEN: usize = 4 + 1 + 32 * 4 + 8 + 8 + 1;

/// Validate the single canonical HTTPS-origin grammar shared by storage,
/// authenticated controls, and network clients.
pub fn canonical_wake_https_origin(origin: &str) -> bool {
    const PREFIX: &str = "https://";
    if origin.len() <= PREFIX.len()
        || origin.len() > MAX_WAKE_CONTROL_ORIGIN_BYTES
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
        if !canonical_wake_host(host) {
            return false;
        }
        port
    };
    port.is_none_or(canonical_wake_nondefault_port)
}

fn canonical_wake_host(host: &str) -> bool {
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

fn canonical_wake_nondefault_port(port: &str) -> bool {
    port.parse::<u16>()
        .is_ok_and(|value| value != 0 && value != 443 && value.to_string() == port)
}

/// Derive a provider-separation id from a canonical origin and TLS pin.
pub fn wake_provider_id(origin: &[u8], static_key: &[u8; 32]) -> Result<[u8; 32]> {
    let origin_text = core::str::from_utf8(origin).map_err(|_| ProtocolError::Malformed)?;
    if !canonical_wake_https_origin(origin_text) || static_key == &[0u8; 32] {
        return Err(ProtocolError::Malformed);
    }
    let mut digest = Sha256::new();
    digest.update(b"Komms-Wake-Provider-v1");
    digest.update(
        u16::try_from(origin.len())
            .map_err(|_| ProtocolError::TooLarge)?
            .to_be_bytes(),
    );
    digest.update(origin);
    digest.update(static_key);
    Ok(digest.finalize().into())
}

/// Native provider selected by one capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WakePlatform {
    /// Apple Push Notification service.
    Apns = 1,
    /// Firebase Cloud Messaging for the Google Play Android flavor.
    Fcm = 2,
}

impl WakePlatform {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Apns),
            2 => Ok(Self::Fcm),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Native provider environment selected by one capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WakeEnvironment {
    /// Development or sandbox provider environment.
    Development = 1,
    /// Production provider environment.
    Production = 2,
}

impl WakeEnvironment {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Development),
            2 => Ok(Self::Production),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Static native-notification shape chosen by the receiving device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WakeProfile {
    /// Content-free background hint. Delivery and execution are not assured.
    BackgroundOnly = 1,
    /// Static visible “New activity” notification plus bounded collection.
    GenericVisible = 2,
}

impl WakeProfile {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::BackgroundOnly),
            2 => Ok(Self::GenericVisible),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Fixed-width plaintext opened only inside the configured wake gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeCapabilityPayload {
    /// Native provider.
    pub platform: WakePlatform,
    /// Provider environment.
    pub environment: WakeEnvironment,
    /// Static notification profile.
    pub profile: WakeProfile,
    /// Absolute expiry as Unix seconds.
    pub expires_at: u64,
    /// Random capability identifier used only for bounded quota/revocation state.
    pub capability_id: [u8; 16],
    /// Native provider routing token.
    pub provider_token: Vec<u8>,
    /// Native application topic or package identifier.
    pub app_topic: Vec<u8>,
}

impl WakeCapabilityPayload {
    /// Encode the exact zero-padded capability plaintext.
    pub fn encode(&self) -> Result<[u8; WAKE_CAPABILITY_PLAINTEXT_LEN]> {
        validate_target(
            self.platform,
            self.environment,
            self.profile,
            &self.provider_token,
            &self.app_topic,
        )?;
        if self.expires_at == 0 || self.capability_id == [0u8; 16] {
            return Err(ProtocolError::Malformed);
        }
        let token_len =
            u16::try_from(self.provider_token.len()).map_err(|_| ProtocolError::TooLarge)?;
        let mut out = [0u8; WAKE_CAPABILITY_PLAINTEXT_LEN];
        out[0] = WAKE_VERSION;
        out[1] = self.platform as u8;
        out[2] = self.environment as u8;
        out[3] = self.profile as u8;
        out[4..12].copy_from_slice(&self.expires_at.to_be_bytes());
        out[12..28].copy_from_slice(&self.capability_id);
        out[28..30].copy_from_slice(&token_len.to_be_bytes());
        out[30..30 + self.provider_token.len()].copy_from_slice(&self.provider_token);
        out[CAPABILITY_TOPIC_LEN_OFFSET] =
            u8::try_from(self.app_topic.len()).map_err(|_| ProtocolError::TooLarge)?;
        let topic_start = CAPABILITY_TOPIC_LEN_OFFSET + 1;
        out[topic_start..topic_start + self.app_topic.len()].copy_from_slice(&self.app_topic);
        Ok(out)
    }

    /// Decode one exact canonical capability plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WAKE_CAPABILITY_PLAINTEXT_LEN || bytes[0] != WAKE_VERSION {
            return Err(ProtocolError::Malformed);
        }
        let platform = WakePlatform::decode(bytes[1])?;
        let environment = WakeEnvironment::decode(bytes[2])?;
        let profile = WakeProfile::decode(bytes[3])?;
        let expires_at = read_u64(&bytes[4..12])?;
        let mut capability_id = [0u8; 16];
        capability_id.copy_from_slice(&bytes[12..28]);
        let token_len = usize::from(read_u16(&bytes[28..30])?);
        let topic_len = usize::from(bytes[CAPABILITY_TOPIC_LEN_OFFSET]);
        if token_len == 0
            || token_len > MAX_WAKE_PROVIDER_TOKEN_BYTES
            || topic_len == 0
            || topic_len > MAX_WAKE_APP_TOPIC_BYTES
            || expires_at == 0
            || capability_id == [0u8; 16]
        {
            return Err(ProtocolError::Malformed);
        }
        let token_end = 30 + token_len;
        if bytes[token_end..CAPABILITY_TOPIC_LEN_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let topic_start = CAPABILITY_TOPIC_LEN_OFFSET + 1;
        let topic_end = topic_start + topic_len;
        if bytes[topic_end..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::Malformed);
        }
        let payload = Self {
            platform,
            environment,
            profile,
            expires_at,
            capability_id,
            provider_token: bytes[30..token_end].to_vec(),
            app_topic: bytes[topic_start..topic_end].to_vec(),
        };
        validate_target(
            payload.platform,
            payload.environment,
            payload.profile,
            &payload.provider_token,
            &payload.app_topic,
        )?;
        if payload.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(payload)
    }
}

/// Public fixed-width encrypted wake capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeCapability([u8; WAKE_CAPABILITY_LEN]);

impl WakeCapability {
    /// Construct from exact bytes after validating the public frame.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WAKE_CAPABILITY_LEN {
            return Err(ProtocolError::Malformed);
        }
        let mut encoded = [0u8; WAKE_CAPABILITY_LEN];
        encoded.copy_from_slice(bytes);
        if encoded[..4] == [0u8; 4]
            || encoded[4..28].iter().all(|byte| *byte == 0)
            || encoded[28..].iter().all(|byte| *byte == 0)
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self(encoded))
    }

    /// Construct from gateway-produced parts.
    pub fn from_parts(key_id: u32, nonce: [u8; 24], sealed_payload: &[u8]) -> Result<Self> {
        if key_id == 0
            || nonce == [0u8; 24]
            || sealed_payload.len() != WAKE_CAPABILITY_PLAINTEXT_LEN + 16
            || sealed_payload.iter().all(|byte| *byte == 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let mut out = [0u8; WAKE_CAPABILITY_LEN];
        out[..4].copy_from_slice(&key_id.to_be_bytes());
        out[4..28].copy_from_slice(&nonce);
        out[28..].copy_from_slice(sealed_payload);
        Ok(Self(out))
    }

    /// Gateway encryption-key id.
    pub fn key_id(&self) -> u32 {
        u32::from_be_bytes(self.0[..4].try_into().expect("fixed capability key id"))
    }

    /// Capability AEAD nonce.
    pub fn nonce(&self) -> [u8; 24] {
        self.0[4..28].try_into().expect("fixed capability nonce")
    }

    /// Capability ciphertext and authentication tag.
    pub fn sealed_payload(&self) -> &[u8] {
        &self.0[28..]
    }

    /// Exact public bytes.
    pub fn as_bytes(&self) -> &[u8; WAKE_CAPABILITY_LEN] {
        &self.0
    }
}

/// One opaque provider-scoped capability issued to an authenticated remote
/// physical device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeCapabilityDescriptor {
    /// Canonical gateway HTTPS origin.
    pub origin: String,
    /// Exact gateway leaf-certificate SHA-256 pin.
    pub static_key: [u8; 32],
    /// Authenticated capability expiry.
    pub expires_at: u64,
    /// Opaque fixed-width encrypted capability.
    pub capability: WakeCapability,
}

/// Complete capability generation transported inside one authenticated
/// pairwise device session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeCapabilityControl {
    /// Stable sending account.
    pub sender_account: [u8; 32],
    /// Exact sending physical device.
    pub sender_device: [u8; 32],
    /// Stable intended recipient account.
    pub recipient_account: [u8; 32],
    /// Exact intended recipient physical device.
    pub recipient_device: [u8; 32],
    /// Accepted sending device-authority generation.
    pub authority_generation: u64,
    /// Strictly increasing complete capability-set generation.
    pub generation: u64,
    /// Complete sorted capability set; empty explicitly revokes the prior set.
    pub capabilities: Vec<WakeCapabilityDescriptor>,
}

impl WakeCapabilityControl {
    /// Encode the complete canonical authenticated control.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(CAPABILITY_CONTROL_HEADER_LEN);
        out.extend_from_slice(WAKE_CAPABILITY_CONTROL_MAGIC);
        out.push(WAKE_CAPABILITY_CONTROL_VERSION);
        out.extend_from_slice(&self.sender_account);
        out.extend_from_slice(&self.sender_device);
        out.extend_from_slice(&self.recipient_account);
        out.extend_from_slice(&self.recipient_device);
        out.extend_from_slice(&self.authority_generation.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(u8::try_from(self.capabilities.len()).map_err(|_| ProtocolError::TooLarge)?);
        for capability in &self.capabilities {
            out.extend_from_slice(
                &u16::try_from(capability.origin.len())
                    .map_err(|_| ProtocolError::TooLarge)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(capability.origin.as_bytes());
            out.extend_from_slice(&capability.static_key);
            out.extend_from_slice(&capability.expires_at.to_be_bytes());
            out.extend_from_slice(capability.capability.as_bytes());
        }
        if out.len() > MAX_WAKE_CAPABILITY_CONTROL_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(out)
    }

    /// Decode exact canonical authenticated control bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CAPABILITY_CONTROL_HEADER_LEN
            || bytes.len() > MAX_WAKE_CAPABILITY_CONTROL_BYTES
            || &bytes[..4] != WAKE_CAPABILITY_CONTROL_MAGIC
            || bytes[4] != WAKE_CAPABILITY_CONTROL_VERSION
        {
            return Err(ProtocolError::Malformed);
        }
        let mut sender_account = [0u8; 32];
        sender_account.copy_from_slice(&bytes[5..37]);
        let mut sender_device = [0u8; 32];
        sender_device.copy_from_slice(&bytes[37..69]);
        let mut recipient_account = [0u8; 32];
        recipient_account.copy_from_slice(&bytes[69..101]);
        let mut recipient_device = [0u8; 32];
        recipient_device.copy_from_slice(&bytes[101..133]);
        let authority_generation = read_u64(&bytes[133..141])?;
        let generation = read_u64(&bytes[141..149])?;
        let count = usize::from(bytes[149]);
        if count > MAX_WAKE_CONTROL_CAPABILITIES {
            return Err(ProtocolError::Malformed);
        }
        let mut cursor = CAPABILITY_CONTROL_HEADER_LEN;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            if cursor.checked_add(2).is_none_or(|end| end > bytes.len()) {
                return Err(ProtocolError::Malformed);
            }
            let origin_len = usize::from(read_u16(&bytes[cursor..cursor + 2])?);
            cursor += 2;
            let entry_end = cursor
                .checked_add(origin_len)
                .and_then(|end| end.checked_add(32 + 8 + WAKE_CAPABILITY_LEN))
                .ok_or(ProtocolError::Malformed)?;
            if origin_len == 0
                || origin_len > MAX_WAKE_CONTROL_ORIGIN_BYTES
                || entry_end > bytes.len()
            {
                return Err(ProtocolError::Malformed);
            }
            let origin_bytes = &bytes[cursor..cursor + origin_len];
            let origin = core::str::from_utf8(origin_bytes)
                .map_err(|_| ProtocolError::Malformed)?
                .into();
            cursor += origin_len;
            let mut static_key = [0u8; 32];
            static_key.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            let expires_at = read_u64(&bytes[cursor..cursor + 8])?;
            cursor += 8;
            let capability =
                WakeCapability::from_bytes(&bytes[cursor..cursor + WAKE_CAPABILITY_LEN])?;
            cursor += WAKE_CAPABILITY_LEN;
            capabilities.push(WakeCapabilityDescriptor {
                origin,
                static_key,
                expires_at,
                capability,
            });
        }
        if cursor != bytes.len() {
            return Err(ProtocolError::Malformed);
        }
        let control = Self {
            sender_account,
            sender_device,
            recipient_account,
            recipient_device,
            authority_generation,
            generation,
            capabilities,
        };
        control.validate()?;
        if control.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(control)
    }

    fn validate(&self) -> Result<()> {
        if self.sender_account == [0u8; 32]
            || self.sender_device == [0u8; 32]
            || self.recipient_account == [0u8; 32]
            || self.recipient_device == [0u8; 32]
            || self.authority_generation == 0
            || self.generation == 0
            || self.capabilities.len() > MAX_WAKE_CONTROL_CAPABILITIES
        {
            return Err(ProtocolError::Malformed);
        }
        for (index, capability) in self.capabilities.iter().enumerate() {
            let origin = capability.origin.as_bytes();
            if !canonical_wake_https_origin(&capability.origin)
                || capability.static_key == [0u8; 32]
                || capability.expires_at == 0
                || self.capabilities[..index].last().is_some_and(|prior| {
                    (prior.origin.as_bytes(), prior.static_key)
                        >= (capability.origin.as_bytes(), capability.static_key)
                })
            {
                return Err(ProtocolError::Malformed);
            }
            wake_provider_id(origin, &capability.static_key)?;
        }
        Ok(())
    }
}

/// Whether bytes claim the authenticated wake capability-control namespace.
pub fn is_wake_capability_control(bytes: &[u8]) -> bool {
    bytes.starts_with(WAKE_CAPABILITY_CONTROL_MAGIC)
}

/// Fixed-width request for one fresh per-contact capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeRegisterRequest {
    /// Native provider.
    pub platform: WakePlatform,
    /// Provider environment.
    pub environment: WakeEnvironment,
    /// Static notification profile.
    pub profile: WakeProfile,
    /// Native provider routing token.
    pub provider_token: Vec<u8>,
    /// Native application topic or package identifier.
    pub app_topic: Vec<u8>,
    /// Random request separation nonce.
    pub request_nonce: [u8; 16],
}

impl WakeRegisterRequest {
    /// Encode the exact fixed-width registration body.
    pub fn encode(&self) -> Result<[u8; WAKE_REGISTER_REQUEST_LEN]> {
        validate_target(
            self.platform,
            self.environment,
            self.profile,
            &self.provider_token,
            &self.app_topic,
        )?;
        if self.request_nonce == [0u8; 16] {
            return Err(ProtocolError::Malformed);
        }
        let mut out = [0u8; WAKE_REGISTER_REQUEST_LEN];
        out[0] = WAKE_VERSION;
        out[1] = self.platform as u8;
        out[2] = self.environment as u8;
        out[3] = self.profile as u8;
        out[4..6].copy_from_slice(
            &u16::try_from(self.provider_token.len())
                .map_err(|_| ProtocolError::TooLarge)?
                .to_be_bytes(),
        );
        out[6..6 + self.provider_token.len()].copy_from_slice(&self.provider_token);
        out[REGISTER_TOPIC_LEN_OFFSET] =
            u8::try_from(self.app_topic.len()).map_err(|_| ProtocolError::TooLarge)?;
        let topic_start = REGISTER_TOPIC_LEN_OFFSET + 1;
        out[topic_start..topic_start + self.app_topic.len()].copy_from_slice(&self.app_topic);
        out[REGISTER_NONCE_OFFSET..REGISTER_NONCE_OFFSET + 16].copy_from_slice(&self.request_nonce);
        Ok(out)
    }

    /// Decode one exact canonical registration body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WAKE_REGISTER_REQUEST_LEN || bytes[0] != WAKE_VERSION {
            return Err(ProtocolError::Malformed);
        }
        let platform = WakePlatform::decode(bytes[1])?;
        let environment = WakeEnvironment::decode(bytes[2])?;
        let profile = WakeProfile::decode(bytes[3])?;
        let token_len = usize::from(read_u16(&bytes[4..6])?);
        let topic_len = usize::from(bytes[REGISTER_TOPIC_LEN_OFFSET]);
        if token_len == 0
            || token_len > MAX_WAKE_PROVIDER_TOKEN_BYTES
            || topic_len == 0
            || topic_len > MAX_WAKE_APP_TOPIC_BYTES
        {
            return Err(ProtocolError::Malformed);
        }
        let token_end = 6 + token_len;
        if bytes[token_end..REGISTER_TOPIC_LEN_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let topic_start = REGISTER_TOPIC_LEN_OFFSET + 1;
        let topic_end = topic_start + topic_len;
        if bytes[topic_end..REGISTER_NONCE_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
            || bytes[REGISTER_NONCE_OFFSET + 16..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let request = Self {
            platform,
            environment,
            profile,
            provider_token: bytes[6..token_end].to_vec(),
            app_topic: bytes[topic_start..topic_end].to_vec(),
            request_nonce: bytes[REGISTER_NONCE_OFFSET..REGISTER_NONCE_OFFSET + 16]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?,
        };
        validate_target(
            request.platform,
            request.environment,
            request.profile,
            &request.provider_token,
            &request.app_topic,
        )?;
        if request.request_nonce == [0u8; 16] || request.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(request)
    }
}

/// Fixed-width registration result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeRegisterResponse {
    /// Whether a capability was issued.
    pub accepted: bool,
    /// Issued capability expiry, or zero on uniform refusal.
    pub expires_at: u64,
    /// Issued capability, absent on uniform refusal.
    pub capability: Option<WakeCapability>,
}

impl WakeRegisterResponse {
    /// Construct a successful registration result.
    pub fn issued(expires_at: u64, capability: WakeCapability) -> Result<Self> {
        if expires_at == 0 {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self {
            accepted: true,
            expires_at,
            capability: Some(capability),
        })
    }

    /// Construct the fixed-shape refusal result.
    pub fn refused() -> Self {
        Self {
            accepted: false,
            expires_at: 0,
            capability: None,
        }
    }

    /// Encode the exact fixed-width registration response.
    pub fn encode(&self) -> Result<[u8; WAKE_REGISTER_RESPONSE_LEN]> {
        if self.accepted != self.capability.is_some() || self.accepted != (self.expires_at != 0) {
            return Err(ProtocolError::Malformed);
        }
        let mut out = [0u8; WAKE_REGISTER_RESPONSE_LEN];
        out[0] = WAKE_VERSION;
        out[1] = u8::from(self.accepted);
        out[2..10].copy_from_slice(&self.expires_at.to_be_bytes());
        if let Some(capability) = &self.capability {
            out[10..12].copy_from_slice(&(WAKE_CAPABILITY_LEN as u16).to_be_bytes());
            out[REGISTER_RESPONSE_CAPABILITY_OFFSET
                ..REGISTER_RESPONSE_CAPABILITY_OFFSET + WAKE_CAPABILITY_LEN]
                .copy_from_slice(capability.as_bytes());
        }
        Ok(out)
    }

    /// Decode one exact canonical registration response.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WAKE_REGISTER_RESPONSE_LEN
            || bytes[0] != WAKE_VERSION
            || !matches!(bytes[1], 0 | 1)
        {
            return Err(ProtocolError::Malformed);
        }
        let accepted = bytes[1] == 1;
        let expires_at = read_u64(&bytes[2..10])?;
        let capability_len = usize::from(read_u16(&bytes[10..12])?);
        let capability_end = REGISTER_RESPONSE_CAPABILITY_OFFSET + WAKE_CAPABILITY_LEN;
        let capability = if accepted {
            if expires_at == 0 || capability_len != WAKE_CAPABILITY_LEN {
                return Err(ProtocolError::Malformed);
            }
            Some(WakeCapability::from_bytes(
                &bytes[REGISTER_RESPONSE_CAPABILITY_OFFSET..capability_end],
            )?)
        } else {
            if expires_at != 0
                || capability_len != 0
                || bytes[REGISTER_RESPONSE_CAPABILITY_OFFSET..capability_end]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(ProtocolError::Malformed);
            }
            None
        };
        if bytes[capability_end..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::Malformed);
        }
        let response = Self {
            accepted,
            expires_at,
            capability,
        };
        if response.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(response)
    }
}

/// Fixed-width wake trigger or possession-authorized revocation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeTriggerRequest {
    /// Opaque per-contact capability.
    pub capability: WakeCapability,
    /// Random short-lived replay nonce.
    pub request_nonce: [u8; 16],
}

impl WakeTriggerRequest {
    /// Encode the exact fixed-width request.
    pub fn encode(&self) -> Result<[u8; WAKE_TRIGGER_REQUEST_LEN]> {
        if self.request_nonce == [0u8; 16] {
            return Err(ProtocolError::Malformed);
        }
        let mut out = [0u8; WAKE_TRIGGER_REQUEST_LEN];
        out[0] = WAKE_VERSION;
        out[1..3].copy_from_slice(&(WAKE_CAPABILITY_LEN as u16).to_be_bytes());
        out[TRIGGER_CAPABILITY_OFFSET..TRIGGER_NONCE_OFFSET]
            .copy_from_slice(self.capability.as_bytes());
        out[TRIGGER_NONCE_OFFSET..TRIGGER_NONCE_OFFSET + 16].copy_from_slice(&self.request_nonce);
        Ok(out)
    }

    /// Decode one exact canonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WAKE_TRIGGER_REQUEST_LEN
            || bytes[0] != WAKE_VERSION
            || usize::from(read_u16(&bytes[1..3])?) != WAKE_CAPABILITY_LEN
            || bytes[TRIGGER_NONCE_OFFSET + 16..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let request = Self {
            capability: WakeCapability::from_bytes(
                &bytes[TRIGGER_CAPABILITY_OFFSET..TRIGGER_NONCE_OFFSET],
            )?,
            request_nonce: bytes[TRIGGER_NONCE_OFFSET..TRIGGER_NONCE_OFFSET + 16]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?,
        };
        if request.request_nonce == [0u8; 16] || request.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(request)
    }
}

/// Construct the only trigger/revoke response body.
pub fn wake_generic_response() -> [u8; WAKE_GENERIC_RESPONSE_LEN] {
    let mut out = [0u8; WAKE_GENERIC_RESPONSE_LEN];
    out[0] = WAKE_VERSION;
    out
}

/// Validate the exact generic response body.
pub fn verify_wake_generic_response(bytes: &[u8]) -> Result<()> {
    if bytes != wake_generic_response() {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

fn validate_target(
    platform: WakePlatform,
    environment: WakeEnvironment,
    profile: WakeProfile,
    provider_token: &[u8],
    app_topic: &[u8],
) -> Result<()> {
    let _ = (platform, environment, profile);
    if provider_token.is_empty()
        || provider_token.len() > MAX_WAKE_PROVIDER_TOKEN_BYTES
        || app_topic.is_empty()
        || app_topic.len() > MAX_WAKE_APP_TOPIC_BYTES
        || app_topic.contains(&0)
        || core::str::from_utf8(app_topic).is_err()
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| ProtocolError::Malformed)?,
    ))
}

fn read_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ProtocolError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_origin_grammar_is_canonical_and_shared() {
        for valid in [
            "https://wake.example",
            "https://wake.example:8443",
            "https://127.0.0.1:8443",
            "https://[::1]:8443",
        ] {
            assert!(canonical_wake_https_origin(valid), "{valid}");
        }
        for invalid in [
            "http://wake.example",
            "https://WAKE.example",
            "https://wake.example/",
            "https://user@wake.example",
            "https://wake.example/path",
            "https://wake.example?cap=x",
            "https://wake.example:443",
            "https://01.2.3.4",
        ] {
            assert!(!canonical_wake_https_origin(invalid), "{invalid}");
        }
    }

    fn capability() -> WakeCapability {
        WakeCapability::from_parts(7, [3u8; 24], &[9u8; WAKE_CAPABILITY_PLAINTEXT_LEN + 16])
            .unwrap()
    }

    #[test]
    fn capability_payload_is_fixed_canonical_and_roundtrips() {
        let payload = WakeCapabilityPayload {
            platform: WakePlatform::Apns,
            environment: WakeEnvironment::Production,
            profile: WakeProfile::BackgroundOnly,
            expires_at: 1_800_000_000,
            capability_id: [4u8; 16],
            provider_token: vec![5u8; 32],
            app_topic: b"is.komms.app".to_vec(),
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(encoded.len(), WAKE_CAPABILITY_PLAINTEXT_LEN);
        assert_eq!(WakeCapabilityPayload::decode(&encoded).unwrap(), payload);

        let mut noncanonical = encoded;
        noncanonical[100] = 1;
        assert_eq!(
            WakeCapabilityPayload::decode(&noncanonical),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn register_trigger_and_response_shapes_roundtrip() {
        let register = WakeRegisterRequest {
            platform: WakePlatform::Fcm,
            environment: WakeEnvironment::Production,
            profile: WakeProfile::GenericVisible,
            provider_token: b"fixed-test-token".to_vec(),
            app_topic: b"is.komms.android".to_vec(),
            request_nonce: [8u8; 16],
        };
        let encoded = register.encode().unwrap();
        assert_eq!(encoded.len(), WAKE_REGISTER_REQUEST_LEN);
        assert_eq!(WakeRegisterRequest::decode(&encoded).unwrap(), register);

        let issued = WakeRegisterResponse::issued(1_800_000_000, capability()).unwrap();
        let encoded = issued.encode().unwrap();
        assert_eq!(encoded.len(), WAKE_REGISTER_RESPONSE_LEN);
        assert_eq!(WakeRegisterResponse::decode(&encoded).unwrap(), issued);

        let refused = WakeRegisterResponse::refused();
        assert_eq!(
            WakeRegisterResponse::decode(&refused.encode().unwrap()).unwrap(),
            refused
        );

        let trigger = WakeTriggerRequest {
            capability: capability(),
            request_nonce: [6u8; 16],
        };
        let encoded = trigger.encode().unwrap();
        assert_eq!(encoded.len(), WAKE_TRIGGER_REQUEST_LEN);
        assert_eq!(WakeTriggerRequest::decode(&encoded).unwrap(), trigger);
        verify_wake_generic_response(&wake_generic_response()).unwrap();
    }

    #[test]
    fn malformed_lengths_padding_and_zero_nonces_fail_closed() {
        assert_eq!(
            WakeCapability::from_parts(1, [1u8; 24], &[1u8; WAKE_CAPABILITY_PLAINTEXT_LEN],),
            Err(ProtocolError::Malformed)
        );
        let request = WakeTriggerRequest {
            capability: capability(),
            request_nonce: [2u8; 16],
        };
        let mut encoded = request.encode().unwrap();
        encoded[WAKE_TRIGGER_REQUEST_LEN - 1] = 1;
        assert_eq!(
            WakeTriggerRequest::decode(&encoded),
            Err(ProtocolError::Malformed)
        );
        let zero_nonce = WakeTriggerRequest {
            capability: capability(),
            request_nonce: [0u8; 16],
        };
        assert_eq!(zero_nonce.encode(), Err(ProtocolError::Malformed));
    }

    #[test]
    fn fixed_shape_vector_is_stable() {
        let request = WakeTriggerRequest {
            capability: WakeCapability::from_parts(
                0x0102_0304,
                [0x11; 24],
                &[0x22; WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
            )
            .unwrap(),
            request_nonce: [0x33; 16],
        };
        let encoded = request.encode().unwrap();
        assert_eq!(&encoded[..7], &[1, 2, 236, 1, 2, 3, 4]);
        assert_eq!(&encoded[7..31], &[0x11; 24]);
        assert_eq!(
            &encoded[TRIGGER_NONCE_OFFSET..TRIGGER_NONCE_OFFSET + 16],
            &[0x33; 16]
        );
        assert!(encoded[TRIGGER_NONCE_OFFSET + 16..]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn authenticated_capability_control_is_recipient_and_generation_bound() {
        let control = WakeCapabilityControl {
            sender_account: [1u8; 32],
            sender_device: [2u8; 32],
            recipient_account: [3u8; 32],
            recipient_device: [4u8; 32],
            authority_generation: 9,
            generation: 11,
            capabilities: vec![WakeCapabilityDescriptor {
                origin: "https://wake.example".into(),
                static_key: [5u8; 32],
                expires_at: 1_800_000_000,
                capability: capability(),
            }],
        };
        let encoded = control.encode().unwrap();
        assert!(is_wake_capability_control(&encoded));
        assert_eq!(WakeCapabilityControl::decode(&encoded).unwrap(), control);

        let revoked = WakeCapabilityControl {
            generation: 12,
            capabilities: Vec::new(),
            ..control
        };
        assert_eq!(
            WakeCapabilityControl::decode(&revoked.encode().unwrap()).unwrap(),
            revoked
        );
    }

    #[test]
    fn capability_control_rejects_reordering_trailing_data_and_wrong_recipient_shape() {
        let descriptor = |origin: &str, byte: u8| WakeCapabilityDescriptor {
            origin: origin.into(),
            static_key: [byte; 32],
            expires_at: 1_800_000_000,
            capability: capability(),
        };
        let base = WakeCapabilityControl {
            sender_account: [1u8; 32],
            sender_device: [2u8; 32],
            recipient_account: [3u8; 32],
            recipient_device: [4u8; 32],
            authority_generation: 1,
            generation: 1,
            capabilities: vec![
                descriptor("https://wake-a.example", 5),
                descriptor("https://wake-b.example", 6),
            ],
        };
        let mut reordered = base.clone();
        reordered.capabilities.reverse();
        assert_eq!(reordered.encode(), Err(ProtocolError::Malformed));

        let mut trailing = base.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            WakeCapabilityControl::decode(&trailing),
            Err(ProtocolError::Malformed)
        );

        let mut missing_recipient = base;
        missing_recipient.recipient_device = [0u8; 32];
        assert_eq!(missing_recipient.encode(), Err(ProtocolError::Malformed));
    }
}
