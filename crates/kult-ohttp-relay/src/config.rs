use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde::Deserialize;

use crate::{RelayError, Result};

/// Only configuration schema accepted by the relay.
pub const CONFIG_VERSION: u32 = 1;
/// Source revision embedded by a reproducible build. Local builds remain
/// visibly unbound.
pub const DEFAULT_SOURCE_REVISION: &str = match option_env!("KOMMS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unbound-local-build",
};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 16_384;
const MAX_RATE_BUCKETS: usize = 1_000_000;
const MAX_REQUESTS_PER_MINUTE: u32 = 1_000_000;
const MAX_BYTES_PER_MINUTE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 60;

/// Strict versioned standalone OHTTP-relay configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub(crate) version: u32,
    pub(crate) tls_certificate_file: PathBuf,
    pub(crate) tls_private_key_file: PathBuf,
    pub(crate) gateway_ca_certificate_file: PathBuf,
    pub(crate) network: NetworkPolicy,
    pub(crate) upstream: UpstreamPolicy,
    pub(crate) runtime: RuntimePolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkPolicy {
    pub(crate) listen: SocketAddr,
    pub(crate) health_listen: SocketAddr,
    pub(crate) public_authority: String,
    pub(crate) public_resource: String,
    pub(crate) max_connections: usize,
    pub(crate) max_requests_per_minute: u32,
    pub(crate) max_requests_per_source_per_minute: u32,
    pub(crate) max_bytes_per_minute: u64,
    pub(crate) max_source_buckets: usize,
    pub(crate) tls_handshake_timeout_seconds: u64,
    pub(crate) request_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamPolicy {
    pub(crate) connect_host: String,
    pub(crate) port: u16,
    pub(crate) tls_server_name: String,
    pub(crate) resource: String,
    pub(crate) encapsulated_request_bytes: usize,
    pub(crate) encapsulated_response_bytes: usize,
    pub(crate) max_response_header_bytes: usize,
    pub(crate) timeout_seconds: u64,
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
            return Err(RelayError::Invalid(
                "OHTTP configuration must be a regular non-symlink file",
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(RelayError::Invalid(
                "OHTTP configuration size is outside its bound",
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
            return Err(RelayError::Invalid(
                "OHTTP configuration must remain a bounded regular file",
            ));
        }
        let mut text = String::with_capacity(opened.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(RelayError::Invalid(
                "OHTTP configuration size is outside its bound",
            ));
        }
        let config: Self = toml::from_str(&text)
            .map_err(|error| RelayError::Configuration(format!("OHTTP configuration: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every credential, mapping, listener, and resource boundary.
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(RelayError::Configuration(format!(
                "OHTTP configuration version {} is unsupported",
                self.version
            )));
        }
        let paths = [
            &self.tls_certificate_file,
            &self.tls_private_key_file,
            &self.gateway_ca_certificate_file,
        ];
        for (label, path) in [
            ("relay TLS certificate", &self.tls_certificate_file),
            ("relay TLS private key", &self.tls_private_key_file),
            ("gateway CA certificate", &self.gateway_ca_certificate_file),
        ] {
            if !path.is_absolute() {
                return Err(RelayError::Configuration(format!(
                    "{label} path must be absolute"
                )));
            }
        }
        if paths
            .iter()
            .map(|path| path.as_os_str())
            .collect::<BTreeSet<_>>()
            .len()
            != paths.len()
        {
            return Err(RelayError::Invalid(
                "relay TLS key, certificate, and gateway CA files must be separate",
            ));
        }
        self.upstream.validate()?;
        let exchange_bytes = self
            .upstream
            .encapsulated_request_bytes
            .checked_add(self.upstream.encapsulated_response_bytes)
            .ok_or(RelayError::Invalid("fixed OHTTP exchange size overflows"))?;
        self.network.validate(exchange_bytes)?;
        self.runtime.validate()?;
        if self.upstream.timeout_seconds >= self.network.request_timeout_seconds {
            return Err(RelayError::Invalid(
                "relay request deadline must exceed the fixed-gateway deadline",
            ));
        }
        Ok(())
    }

    pub(crate) fn public_mapping(&self) -> String {
        format!(
            concat!(
                "v=1\n",
                "public_authority={}\n",
                "public_resource={}\n",
                "connect_host={}\n",
                "port={}\n",
                "tls_server_name={}\n",
                "gateway_resource={}\n",
                "request_bytes={}\n",
                "response_bytes={}\n"
            ),
            self.network.public_authority,
            self.network.public_resource,
            self.upstream.connect_host,
            self.upstream.port,
            self.upstream.tls_server_name,
            self.upstream.resource,
            self.upstream.encapsulated_request_bytes,
            self.upstream.encapsulated_response_bytes,
        )
    }
}

impl NetworkPolicy {
    fn validate(&self, exchange_bytes: usize) -> Result<()> {
        if self.listen.port() == 0
            || !self.health_listen.ip().is_loopback()
            || self.health_listen.port() == 0
            || self.health_listen == self.listen
        {
            return Err(RelayError::Invalid(
                "relay listeners require a public non-zero port and separate loopback health",
            ));
        }
        validate_authority(&self.public_authority)?;
        validate_resource("public relay", &self.public_resource)?;
        if self.max_connections == 0
            || self.max_connections > MAX_CONNECTIONS
            || self.max_requests_per_minute == 0
            || self.max_requests_per_minute > MAX_REQUESTS_PER_MINUTE
            || self.max_requests_per_source_per_minute == 0
            || self.max_requests_per_source_per_minute > self.max_requests_per_minute
            || self.max_source_buckets == 0
            || self.max_source_buckets > MAX_RATE_BUCKETS
            || self.max_bytes_per_minute == 0
            || self.max_bytes_per_minute > MAX_BYTES_PER_MINUTE
        {
            return Err(RelayError::Invalid(
                "relay connection, request, byte, or source-bucket limits are invalid",
            ));
        }
        if self.max_bytes_per_minute < exchange_bytes as u64 {
            return Err(RelayError::Invalid(
                "relay byte budget cannot admit one fixed exchange",
            ));
        }
        for (label, seconds) in [
            ("relay TLS handshake", self.tls_handshake_timeout_seconds),
            ("relay request", self.request_timeout_seconds),
        ] {
            if seconds == 0 || seconds > 60 {
                return Err(RelayError::Configuration(format!(
                    "{label} timeout is outside 1..=60 seconds"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.tls_handshake_timeout_seconds)
    }

    pub(crate) fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }
}

impl UpstreamPolicy {
    fn validate(&self) -> Result<()> {
        validate_connect_host(&self.connect_host)?;
        if self.port == 0 {
            return Err(RelayError::Invalid("fixed gateway port must be non-zero"));
        }
        ServerName::try_from(self.tls_server_name.clone())
            .map_err(|_| RelayError::Invalid("fixed gateway TLS server name is invalid"))?;
        validate_resource("fixed gateway", &self.resource)?;
        if self.encapsulated_request_bytes == 0
            || self.encapsulated_request_bytes > MAX_BODY_BYTES
            || self.encapsulated_response_bytes == 0
            || self.encapsulated_response_bytes > MAX_BODY_BYTES
        {
            return Err(RelayError::Invalid(
                "fixed encapsulated request/response size is outside 1..=65536",
            ));
        }
        if self.max_response_header_bytes < 1024
            || self.max_response_header_bytes > MAX_HEADER_BYTES
        {
            return Err(RelayError::Invalid(
                "fixed gateway response-header bound is outside 1024..=16384",
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > 59 {
            return Err(RelayError::Invalid(
                "fixed gateway timeout is outside 1..=59 seconds",
            ));
        }
        Ok(())
    }

    pub(crate) fn authority(&self) -> String {
        let host = if self.tls_server_name.parse::<IpAddr>().is_ok()
            && self.tls_server_name.contains(':')
        {
            format!("[{}]", self.tls_server_name)
        } else {
            self.tls_server_name.clone()
        };
        if self.port == 443 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

impl RuntimePolicy {
    fn validate(&self) -> Result<()> {
        if self.shutdown_grace_seconds == 0
            || self.shutdown_grace_seconds > MAX_SHUTDOWN_GRACE_SECONDS
        {
            return Err(RelayError::Invalid(
                "relay shutdown grace is outside 1..=60 seconds",
            ));
        }
        Ok(())
    }

    pub(crate) fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_seconds)
    }
}

fn validate_connect_host(value: &str) -> Result<()> {
    if value.parse::<IpAddr>().is_err() && !valid_dns_name(value) {
        return Err(RelayError::Invalid("fixed gateway connect host is invalid"));
    }
    Ok(())
}

fn validate_authority(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 {
        return Err(RelayError::Invalid("public relay authority is invalid"));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let Some((address, suffix)) = rest.split_once(']') else {
            return Err(RelayError::Invalid("public relay authority is invalid"));
        };
        if address.parse::<std::net::Ipv6Addr>().is_err()
            || (!suffix.is_empty() && (!suffix.starts_with(':') || !valid_port(&suffix[1..])))
        {
            return Err(RelayError::Invalid("public relay authority is invalid"));
        }
        return Ok(());
    }
    if value.matches(':').count() > 1 {
        return Err(RelayError::Invalid("public relay authority is invalid"));
    }
    let (host, port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| !valid_port(port))
        || (host.parse::<std::net::Ipv4Addr>().is_err() && !valid_dns_name(host))
    {
        return Err(RelayError::Invalid("public relay authority is invalid"));
    }
    Ok(())
}

fn valid_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
        && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_resource(label: &str, value: &str) -> Result<()> {
    if !value.starts_with('/')
        || value.len() > 512
        || value.contains(['?', '#'])
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'\\')
    {
        return Err(RelayError::Configuration(format!(
            "{label} resource is invalid or contains a URL capability"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config {
            version: CONFIG_VERSION,
            tls_certificate_file: "/run/relay/tls.crt".into(),
            tls_private_key_file: "/run/relay/tls.key".into(),
            gateway_ca_certificate_file: "/run/gateway/roots.pem".into(),
            network: NetworkPolicy {
                listen: "0.0.0.0:8445".parse().unwrap(),
                health_listen: "127.0.0.1:8083".parse().unwrap(),
                public_authority: "relay.example".into(),
                public_resource: "/ohttp".into(),
                max_connections: 256,
                max_requests_per_minute: 30_000,
                max_requests_per_source_per_minute: 120,
                max_bytes_per_minute: 256 * 1024 * 1024,
                max_source_buckets: 65_536,
                tls_handshake_timeout_seconds: 5,
                request_timeout_seconds: 15,
            },
            upstream: UpstreamPolicy {
                connect_host: "gateway.example".into(),
                port: 443,
                tls_server_name: "gateway.example".into(),
                resource: "/ohttp-gateway".into(),
                encapsulated_request_bytes: 4096,
                encapsulated_response_bytes: 4096,
                max_response_header_bytes: 8192,
                timeout_seconds: 10,
            },
            runtime: RuntimePolicy {
                shutdown_grace_seconds: 10,
            },
        }
    }

    #[test]
    fn strict_configuration_binds_one_fixed_mapping() {
        let config = valid();
        config.validate().unwrap();
        assert_eq!(
            config.public_mapping(),
            concat!(
                "v=1\n",
                "public_authority=relay.example\n",
                "public_resource=/ohttp\n",
                "connect_host=gateway.example\n",
                "port=443\n",
                "tls_server_name=gateway.example\n",
                "gateway_resource=/ohttp-gateway\n",
                "request_bytes=4096\n",
                "response_bytes=4096\n"
            )
        );

        let mut capability_url = config.clone();
        capability_url.upstream.resource = "/ohttp?target=other".into();
        assert!(capability_url.validate().is_err());

        let mut public_health = config.clone();
        public_health.network.health_listen = "0.0.0.0:8083".parse().unwrap();
        assert!(public_health.validate().is_err());

        let mut shared_key = config;
        shared_key.gateway_ca_certificate_file = shared_key.tls_private_key_file.clone();
        assert!(shared_key.validate().is_err());

        let mut invalid_authority = valid();
        invalid_authority.network.public_authority = "::::".into();
        assert!(invalid_authority.validate().is_err());

        let mut invalid_connect_host = valid();
        invalid_connect_host.upstream.connect_host = "-bad.example".into();
        assert!(invalid_connect_host.validate().is_err());
    }

    #[test]
    fn subordinate_budgets_and_deadlines_fail_closed() {
        let mut config = valid();
        config.network.max_requests_per_source_per_minute =
            config.network.max_requests_per_minute + 1;
        assert!(config.validate().is_err());

        let mut config = valid();
        config.network.max_bytes_per_minute = 4095;
        assert!(config.validate().is_err());

        let mut config = valid();
        config.upstream.timeout_seconds = config.network.request_timeout_seconds;
        assert!(config.validate().is_err());
    }
}
