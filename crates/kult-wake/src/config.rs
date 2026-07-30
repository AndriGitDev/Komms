use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::{GatewayLimits, Result, WakeError, WakeNetworkConfig};

/// Only configuration schema accepted by the standalone wake gateway.
pub const CONFIG_VERSION: u32 = 1;
/// Source revision embedded by a reproducible build. Local builds remain
/// visibly unbound.
pub const DEFAULT_SOURCE_REVISION: &str = match option_env!("KOMMS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unbound-local-build",
};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_CAPABILITY_KEYS: usize = 8;
const MAX_ALLOWED_TOPICS: usize = 16;
const MAX_STATE_ROWS: usize = 1_000_000;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 60;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;

/// Strict versioned standalone wake-gateway configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub(crate) version: u32,
    pub(crate) tls_certificate_file: PathBuf,
    pub(crate) tls_private_key_file: PathBuf,
    pub(crate) active_capability_key_id: u32,
    pub(crate) capability_key_files: Vec<PathBuf>,
    pub(crate) state_file: PathBuf,
    pub(crate) network: NetworkPolicy,
    pub(crate) gateway: GatewayPolicy,
    pub(crate) state: StatePolicy,
    pub(crate) provider: ProviderPolicy,
    pub(crate) runtime: RuntimePolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkPolicy {
    pub(crate) listen: SocketAddr,
    pub(crate) health_listen: SocketAddr,
    pub(crate) max_connections: usize,
    pub(crate) max_connections_per_minute: u32,
    pub(crate) max_connections_per_source_per_minute: u32,
    pub(crate) max_source_buckets: usize,
    pub(crate) tls_handshake_timeout_seconds: u64,
    pub(crate) request_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayPolicy {
    pub(crate) capability_lifetime_seconds: u64,
    pub(crate) per_capability_per_minute: u32,
    pub(crate) per_destination_per_minute: u32,
    pub(crate) global_per_minute: u32,
    pub(crate) max_capability_buckets: usize,
    pub(crate) max_destination_buckets: usize,
    pub(crate) coalesce_seconds: u64,
    pub(crate) provider_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatePolicy {
    pub(crate) max_revocations: usize,
    pub(crate) max_replays: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderPolicy {
    pub(crate) ca_certificate_file: PathBuf,
    pub(crate) request_timeout_seconds: u64,
    pub(crate) max_response_bytes: usize,
    pub(crate) apns: Option<ApnsPolicy>,
    pub(crate) fcm: Option<FcmPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApnsPolicy {
    pub(crate) signing_key_file: PathBuf,
    pub(crate) key_id: String,
    pub(crate) team_id: String,
    pub(crate) allowed_topics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FcmPolicy {
    pub(crate) service_account_file: PathBuf,
    pub(crate) allowed_topics: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePolicy {
    pub(crate) shutdown_grace_seconds: u64,
}

impl Config {
    /// Open, bound, decode, and validate a regular non-symlink TOML file.
    pub fn open(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WakeError::Invalid(
                "wake configuration must be a regular non-symlink file",
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(WakeError::Invalid(
                "wake configuration size is outside its bound",
            ));
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
        if !opened.is_file() || opened.len() == 0 || opened.len() > MAX_CONFIG_BYTES {
            return Err(WakeError::Invalid(
                "wake configuration must remain a bounded regular file",
            ));
        }
        let mut text = String::with_capacity(opened.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(WakeError::Invalid(
                "wake configuration size is outside its bound",
            ));
        }
        let config: Self = toml::from_str(&text)
            .map_err(|error| WakeError::Configuration(format!("wake configuration: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every credential, listener, and resource boundary.
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(WakeError::Configuration(format!(
                "wake configuration version {} is unsupported",
                self.version
            )));
        }
        let mut all_paths = Vec::with_capacity(8 + self.capability_key_files.len());
        for (label, path) in [
            ("TLS certificate", &self.tls_certificate_file),
            ("TLS private key", &self.tls_private_key_file),
            ("wake state", &self.state_file),
            (
                "provider CA certificate",
                &self.provider.ca_certificate_file,
            ),
        ] {
            require_absolute(label, path)?;
            all_paths.push(path);
        }
        if self.active_capability_key_id == 0
            || self.capability_key_files.is_empty()
            || self.capability_key_files.len() > MAX_CAPABILITY_KEYS
        {
            return Err(WakeError::Invalid(
                "wake capability key policy is outside its bound",
            ));
        }
        for path in &self.capability_key_files {
            require_absolute("wake capability key", path)?;
            all_paths.push(path);
        }
        if let Some(apns) = &self.provider.apns {
            require_absolute("APNs signing key", &apns.signing_key_file)?;
            all_paths.push(&apns.signing_key_file);
            validate_identifier("APNs key id", &apns.key_id, 64)?;
            validate_identifier("APNs team id", &apns.team_id, 64)?;
            validate_topics("APNs", &apns.allowed_topics)?;
        }
        if let Some(fcm) = &self.provider.fcm {
            require_absolute("FCM service account", &fcm.service_account_file)?;
            all_paths.push(&fcm.service_account_file);
            validate_topics("FCM", &fcm.allowed_topics)?;
        }
        if self.provider.apns.is_none() && self.provider.fcm.is_none() {
            return Err(WakeError::Invalid(
                "wake gateway must configure at least one native provider",
            ));
        }
        let distinct = all_paths
            .iter()
            .map(|path| path.as_os_str())
            .collect::<BTreeSet<_>>();
        if distinct.len() != all_paths.len() {
            return Err(WakeError::Invalid(
                "wake TLS, capability, state, CA, and provider files must be separate",
            ));
        }
        self.network.validate()?;
        self.gateway.limits()?;
        self.state.validate()?;
        self.provider.validate()?;
        self.runtime.validate()?;
        if self
            .gateway
            .provider_timeout_seconds
            .checked_add(1)
            .is_none_or(|provider_deadline| {
                provider_deadline > self.network.request_timeout_seconds
            })
        {
            return Err(WakeError::Invalid(
                "wake request deadline must exceed the native-provider deadline",
            ));
        }
        if self.provider.request_timeout_seconds > self.gateway.provider_timeout_seconds {
            return Err(WakeError::Invalid(
                "wake provider transport deadline exceeds the gateway provider deadline",
            ));
        }
        Ok(())
    }

    pub(crate) fn network_config(&self) -> Result<WakeNetworkConfig> {
        self.network.network_config()
    }

    pub(crate) fn gateway_limits(&self) -> Result<GatewayLimits> {
        self.gateway.limits()
    }
}

impl NetworkPolicy {
    fn validate(&self) -> Result<()> {
        self.network_config()?;
        if !self.health_listen.ip().is_loopback()
            || self.health_listen.port() == 0
            || self.health_listen == self.listen
        {
            return Err(WakeError::Invalid(
                "wake health listener must be a separate explicit loopback address",
            ));
        }
        if self.max_connections_per_source_per_minute > self.max_connections_per_minute {
            return Err(WakeError::Invalid(
                "wake source connection rate exceeds the global rate",
            ));
        }
        Ok(())
    }

    fn network_config(&self) -> Result<WakeNetworkConfig> {
        let config = WakeNetworkConfig {
            listen: self.listen,
            max_connections: self.max_connections,
            max_connections_per_minute: self.max_connections_per_minute,
            max_connections_per_source_per_minute: self.max_connections_per_source_per_minute,
            max_source_buckets: self.max_source_buckets,
            tls_handshake_timeout: Duration::from_secs(self.tls_handshake_timeout_seconds),
            request_timeout: Duration::from_secs(self.request_timeout_seconds),
        };
        config.validate()?;
        Ok(config)
    }
}

impl GatewayPolicy {
    fn limits(&self) -> Result<GatewayLimits> {
        let limits = GatewayLimits {
            capability_lifetime_secs: self.capability_lifetime_seconds,
            per_capability_per_minute: self.per_capability_per_minute,
            per_destination_per_minute: self.per_destination_per_minute,
            global_per_minute: self.global_per_minute,
            max_capability_buckets: self.max_capability_buckets,
            max_destination_buckets: self.max_destination_buckets,
            coalesce_seconds: self.coalesce_seconds,
            provider_timeout: Duration::from_secs(self.provider_timeout_seconds),
        };
        limits.validate()?;
        if limits.per_capability_per_minute > limits.per_destination_per_minute
            || limits.per_destination_per_minute > limits.global_per_minute
        {
            return Err(WakeError::Invalid(
                "wake capability, destination, and global rates are inconsistent",
            ));
        }
        Ok(limits)
    }
}

impl StatePolicy {
    fn validate(&self) -> Result<()> {
        if self.max_revocations == 0
            || self.max_replays == 0
            || self.max_revocations > MAX_STATE_ROWS
            || self.max_replays > MAX_STATE_ROWS
        {
            return Err(WakeError::Invalid(
                "wake durable state limits are outside 1..=1000000",
            ));
        }
        Ok(())
    }
}

impl ProviderPolicy {
    fn validate(&self) -> Result<()> {
        if self.request_timeout_seconds == 0
            || self.request_timeout_seconds > 60
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_PROVIDER_RESPONSE_BYTES
        {
            return Err(WakeError::Invalid(
                "wake native-provider bounds are invalid",
            ));
        }
        Ok(())
    }
}

impl RuntimePolicy {
    fn validate(&self) -> Result<()> {
        if self.shutdown_grace_seconds == 0
            || self.shutdown_grace_seconds > MAX_SHUTDOWN_GRACE_SECONDS
        {
            return Err(WakeError::Invalid(
                "wake shutdown grace is outside 1..=60 seconds",
            ));
        }
        Ok(())
    }
}

fn require_absolute(label: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(WakeError::Configuration(format!(
            "{label} path must be absolute"
        )));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(WakeError::Configuration(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_topics(label: &str, topics: &[String]) -> Result<()> {
    if topics.is_empty() || topics.len() > MAX_ALLOWED_TOPICS {
        return Err(WakeError::Configuration(format!(
            "{label} allowed topic count is outside 1..={MAX_ALLOWED_TOPICS}"
        )));
    }
    let mut distinct = BTreeSet::new();
    for topic in topics {
        validate_identifier(&format!("{label} topic"), topic, 128)?;
        if !distinct.insert(topic.as_str()) {
            return Err(WakeError::Configuration(format!(
                "{label} allowed topics contain a duplicate"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config {
            version: CONFIG_VERSION,
            tls_certificate_file: "/run/keys/tls.crt".into(),
            tls_private_key_file: "/run/keys/tls.key".into(),
            active_capability_key_id: 2,
            capability_key_files: vec![
                "/run/keys/wake-1.key".into(),
                "/run/keys/wake-2.key".into(),
            ],
            state_file: "/var/lib/komms-wake/state.db".into(),
            network: NetworkPolicy {
                listen: "0.0.0.0:8444".parse().unwrap(),
                health_listen: "127.0.0.1:8082".parse().unwrap(),
                max_connections: 256,
                max_connections_per_minute: 30_000,
                max_connections_per_source_per_minute: 120,
                max_source_buckets: 65_536,
                tls_handshake_timeout_seconds: 5,
                request_timeout_seconds: 15,
            },
            gateway: GatewayPolicy {
                capability_lifetime_seconds: 30 * 24 * 60 * 60,
                per_capability_per_minute: 6,
                per_destination_per_minute: 12,
                global_per_minute: 10_000,
                max_capability_buckets: 65_536,
                max_destination_buckets: 65_536,
                coalesce_seconds: 30,
                provider_timeout_seconds: 11,
            },
            state: StatePolicy {
                max_revocations: 200_000,
                max_replays: 500_000,
            },
            provider: ProviderPolicy {
                ca_certificate_file: "/etc/ssl/certs/ca-certificates.crt".into(),
                request_timeout_seconds: 10,
                max_response_bytes: 16 * 1024,
                apns: Some(ApnsPolicy {
                    signing_key_file: "/run/keys/apns.p8".into(),
                    key_id: "KEY123".into(),
                    team_id: "TEAM123".into(),
                    allowed_topics: vec!["is.komms.app".into()],
                }),
                fcm: Some(FcmPolicy {
                    service_account_file: "/run/keys/fcm.json".into(),
                    allowed_topics: vec!["is.komms.android".into()],
                }),
            },
            runtime: RuntimePolicy {
                shutdown_grace_seconds: 10,
            },
        }
    }

    #[test]
    fn strict_configuration_enforces_separation_and_bounds() {
        let config = valid();
        config.validate().unwrap();

        let mut same_key = config.clone();
        same_key.provider.apns.as_mut().unwrap().signing_key_file =
            same_key.tls_private_key_file.clone();
        assert!(same_key.validate().is_err());

        let mut public_health = config.clone();
        public_health.network.health_listen = "0.0.0.0:8082".parse().unwrap();
        assert!(public_health.validate().is_err());

        let mut inconsistent_rate = config;
        inconsistent_rate.gateway.per_capability_per_minute = 13;
        assert!(inconsistent_rate.validate().is_err());
    }
}
