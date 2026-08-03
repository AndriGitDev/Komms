use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use kult_transport::{MailboxConfig, MailboxServiceConfig};

use crate::{MailboxError, Result};

/// Only configuration schema accepted by the standalone mailbox service.
pub const CONFIG_VERSION: u32 = 1;
/// Source revision embedded by a reproducible build. Local builds remain
/// visibly unbound.
pub const DEFAULT_SOURCE_REVISION: &str = match option_env!("KOMMS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unbound-local-build",
};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_LISTENERS: usize = 4;
const MAX_ITEMS: usize = 1_000_000;
const MAX_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_REQUESTS_PER_MINUTE: usize = 1_000_000;
const MAX_RETENTION_SECONDS: u64 = 90 * 86_400;
const MAX_REGISTRATION_SECONDS: u64 = 90 * 86_400;
const MAX_LEASE_SECONDS: u64 = 10 * 60;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 60;

/// Strict versioned standalone mailbox-service configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    version: u32,
    database_file: PathBuf,
    row_key_file: PathBuf,
    transport_identity_file: PathBuf,
    network: NetworkPolicy,
    mailbox: MailboxPolicy,
    runtime: RuntimePolicy,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicy {
    listen: Vec<String>,
    health_listen: SocketAddr,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MailboxPolicy {
    max_tokens: usize,
    max_tokens_per_client: usize,
    max_per_token: usize,
    max_bytes_per_token: usize,
    max_per_client: usize,
    max_bytes_per_client: usize,
    max_total_items: usize,
    max_total_bytes: usize,
    envelope_ttl_seconds: u64,
    registration_ttl_seconds: u64,
    lease_ttl_seconds: u64,
    max_live_leases_per_client: usize,
    max_live_leases_per_token: usize,
    max_live_leases: usize,
    max_requests_per_client_per_minute: usize,
    max_requests_per_minute: usize,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicy {
    shutdown_grace_seconds: u64,
}

impl Config {
    /// Open, bound, decode, and validate a regular non-symlink TOML file.
    pub fn open(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(MailboxError::invalid(
                "mailbox configuration must be a regular non-symlink file",
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(MailboxError::invalid(
                "mailbox configuration size is outside its bound",
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
            return Err(MailboxError::invalid(
                "mailbox configuration must remain a bounded regular file",
            ));
        }
        let mut text = String::with_capacity(opened.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(MailboxError::invalid(
                "mailbox configuration size is outside its bound",
            ));
        }
        let config: Self = toml::from_str(&text)
            .map_err(|error| MailboxError::invalid(format!("mailbox configuration: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every role, path, capacity, retention, and lifecycle bound.
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(MailboxError::invalid(format!(
                "mailbox configuration version {} is unsupported",
                self.version
            )));
        }
        for (label, path) in [
            ("mailbox database", &self.database_file),
            ("mailbox row key", &self.row_key_file),
            ("mailbox transport identity", &self.transport_identity_file),
        ] {
            if !path.is_absolute() {
                return Err(MailboxError::invalid(format!(
                    "{label} path must be absolute"
                )));
            }
        }
        if self.database_file == self.row_key_file
            || self.database_file == self.transport_identity_file
            || self.row_key_file == self.transport_identity_file
        {
            return Err(MailboxError::invalid(
                "mailbox database, row key, and transport identity must be separate files",
            ));
        }
        self.network.validate()?;
        self.mailbox.validate()?;
        self.runtime.validate()?;
        Ok(())
    }

    pub(crate) fn service_config(&self) -> MailboxServiceConfig {
        MailboxServiceConfig {
            database_path: self.database_file.clone(),
            key_path: self.row_key_file.clone(),
            transport_key_path: self.transport_identity_file.clone(),
            limits: self.mailbox.config(),
            allow_v1_compat: false,
        }
    }

    pub(crate) fn listen(&self) -> &[String] {
        &self.network.listen
    }

    pub(crate) fn health_listen(&self) -> SocketAddr {
        self.network.health_listen
    }

    pub(crate) fn shutdown_grace(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.runtime.shutdown_grace_seconds)
    }
}

impl NetworkPolicy {
    fn validate(&self) -> Result<()> {
        if self.listen.is_empty() || self.listen.len() > MAX_LISTENERS {
            return Err(MailboxError::invalid(
                "mailbox listener count is outside 1..=4",
            ));
        }
        if self
            .listen
            .iter()
            .any(|address| address.is_empty() || address.len() > 512)
        {
            return Err(MailboxError::invalid(
                "mailbox listen multiaddress length is outside its bound",
            ));
        }
        if !self.health_listen.ip().is_loopback() || self.health_listen.port() == 0 {
            return Err(MailboxError::invalid(
                "mailbox health listener must be an explicit loopback address",
            ));
        }
        Ok(())
    }
}

impl MailboxPolicy {
    fn validate(&self) -> Result<()> {
        let counts = [
            self.max_tokens,
            self.max_tokens_per_client,
            self.max_per_token,
            self.max_per_client,
            self.max_total_items,
            self.max_live_leases_per_client,
            self.max_live_leases_per_token,
            self.max_live_leases,
            self.max_requests_per_client_per_minute,
            self.max_requests_per_minute,
        ];
        let bytes = [
            self.max_bytes_per_token,
            self.max_bytes_per_client,
            self.max_total_bytes,
        ];
        if counts.iter().any(|value| *value == 0 || *value > MAX_ITEMS)
            || bytes.iter().any(|value| *value == 0 || *value > MAX_BYTES)
        {
            return Err(MailboxError::invalid(
                "mailbox item or byte capacity is outside its fixed bound",
            ));
        }
        if self.max_requests_per_minute > MAX_REQUESTS_PER_MINUTE
            || self.max_requests_per_client_per_minute > self.max_requests_per_minute
        {
            return Err(MailboxError::invalid(
                "mailbox request-rate policy is outside its bound",
            ));
        }
        if self.max_tokens_per_client > self.max_tokens
            || self.max_per_token > self.max_total_items
            || self.max_per_client > self.max_total_items
            || self.max_bytes_per_token > self.max_total_bytes
            || self.max_bytes_per_client > self.max_total_bytes
            || self.max_live_leases_per_client > self.max_live_leases
            || self.max_live_leases_per_token > self.max_live_leases
        {
            return Err(MailboxError::invalid(
                "mailbox subordinate capacity exceeds its global capacity",
            ));
        }
        if self.envelope_ttl_seconds == 0
            || self.envelope_ttl_seconds > MAX_RETENTION_SECONDS
            || self.registration_ttl_seconds == 0
            || self.registration_ttl_seconds > MAX_REGISTRATION_SECONDS
            || self.lease_ttl_seconds == 0
            || self.lease_ttl_seconds > MAX_LEASE_SECONDS
        {
            return Err(MailboxError::invalid(
                "mailbox retention or lease lifetime is outside its bound",
            ));
        }
        Ok(())
    }

    fn config(self) -> MailboxConfig {
        MailboxConfig {
            max_tokens: self.max_tokens,
            max_tokens_per_client: self.max_tokens_per_client,
            max_per_token: self.max_per_token,
            max_bytes_per_token: self.max_bytes_per_token,
            max_per_client: self.max_per_client,
            max_bytes_per_client: self.max_bytes_per_client,
            max_total_items: self.max_total_items,
            max_total_bytes: self.max_total_bytes,
            envelope_ttl_secs: self.envelope_ttl_seconds,
            registration_ttl_secs: self.registration_ttl_seconds,
            lease_ttl_secs: self.lease_ttl_seconds,
            max_live_leases_per_client: self.max_live_leases_per_client,
            max_live_leases_per_token: self.max_live_leases_per_token,
            max_live_leases: self.max_live_leases,
            max_requests_per_client_per_minute: self.max_requests_per_client_per_minute,
            max_requests_per_minute: self.max_requests_per_minute,
        }
    }
}

impl RuntimePolicy {
    fn validate(&self) -> Result<()> {
        if self.shutdown_grace_seconds == 0
            || self.shutdown_grace_seconds > MAX_SHUTDOWN_GRACE_SECONDS
        {
            return Err(MailboxError::invalid(
                "mailbox shutdown grace is outside 1..=60 seconds",
            ));
        }
        Ok(())
    }
}
