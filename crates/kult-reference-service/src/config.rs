use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use kult_rendezvous::{RendezvousService, RendezvousServiceConfig};

use crate::runtime::ServiceError;

/// Only configuration schema accepted by this binary.
pub const CONFIG_VERSION: u32 = 1;
/// Source revision embedded by the reproducible build. Local builds remain
/// visibly unbound instead of inventing a revision.
pub const DEFAULT_SOURCE_REVISION: &str = match option_env!("KOMMS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unbound-local-build",
};

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_DHT_LISTENERS: usize = 8;
const MAX_BOOTSTRAP_PEERS: usize = 32;
const MAX_DHT_RECORDS: usize = 256;
const MAX_DHT_VALUE_MEMORY: usize = 320 * 1024 * 1024;
const MAX_RENDEZVOUS_MEMORY: usize = 192 * 1024 * 1024;
const MAX_COMBINED_MUTABLE_MEMORY: usize = 384 * 1024 * 1024;
const MAX_NETWORK_CONNECTIONS: u32 = 512;
const MAX_RATE_BUCKETS: usize = 65_536;

/// Which subset of the reference service's two least-authority roles a
/// process enables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleSelection {
    /// Bootstrap and bounded Komms Kademlia cache only.
    BootstrapKadCache,
    /// Fixed-shape post-pairing rendezvous only.
    PairwiseRendezvous,
    /// Both roles in the original combined reference profile.
    Both,
}

impl RoleSelection {
    /// Whether the process enables the bootstrap/Kademlia role.
    pub fn includes_dht(self) -> bool {
        matches!(self, Self::BootstrapKadCache | Self::Both)
    }

    /// Whether the process enables the pairwise-rendezvous role.
    pub fn includes_rendezvous(self) -> bool {
        matches!(self, Self::PairwiseRendezvous | Self::Both)
    }

    pub(crate) fn log_label(self) -> &'static str {
        match self {
            Self::BootstrapKadCache => "bootstrap-kad-cache",
            Self::PairwiseRendezvous => "pairwise-rendezvous",
            Self::Both => "bootstrap-kad-cache,pairwise-rendezvous",
        }
    }

    pub(crate) fn health_json(self) -> &'static str {
        match self {
            Self::BootstrapKadCache => "\"bootstrap-kad-cache\"",
            Self::PairwiseRendezvous => "\"pairwise-rendezvous\"",
            Self::Both => "\"bootstrap-kad-cache\",\"pairwise-rendezvous\"",
        }
    }
}

/// Strict versioned service configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration schema. Must be exactly [`CONFIG_VERSION`].
    pub version: u32,
    /// Stable service-only libp2p Ed25519 key in protobuf encoding.
    pub libp2p_identity_file: PathBuf,
    /// TLS certificate chain in PEM form. Its first certificate digest is the
    /// rendezvous provider static key published to clients.
    pub tls_certificate_file: PathBuf,
    /// TLS private key in owner-only PKCS#8 PEM form.
    pub tls_private_key_file: PathBuf,
    /// Bootstrap and Kademlia-cache policy.
    pub dht: DhtConfig,
    /// Fixed-shape rendezvous and local health policy.
    pub rendezvous: RendezvousConfig,
    /// Process lifecycle bounds.
    pub runtime: RuntimeLimits,
}

/// Bounded libp2p bootstrap/Kademlia cache policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhtConfig {
    /// TCP and/or QUIC multiaddresses opened by the service.
    pub listen: Vec<String>,
    /// Optional upstream peers, each ending in `/p2p/<peer-id>`.
    pub bootstrap: Vec<String>,
    /// Maximum number of cached value records.
    pub max_records: usize,
    /// Maximum combined cached value bytes.
    pub max_value_bytes: usize,
    /// Local upper bound applied to every cached record.
    pub record_ttl_seconds: u64,
    /// Simultaneous pending inbound handshakes.
    pub max_pending_incoming: u32,
    /// Simultaneous pending outbound handshakes.
    pub max_pending_outgoing: u32,
    /// Established inbound connections.
    pub max_established_incoming: u32,
    /// All established connections.
    pub max_established: u32,
    /// Established connections sharing one libp2p peer id.
    pub max_established_per_peer: u32,
    /// Accepted inbound transport attempts in one fixed minute.
    pub max_inbound_connections_per_minute: u32,
    /// Accepted inbound transport attempts from one exact network address in
    /// one fixed minute. Addresses are retained only as keyed volatile
    /// buckets and are never logged.
    pub max_inbound_connections_per_address_per_minute: u32,
    /// Maximum live volatile address-rate buckets.
    pub max_inbound_rate_buckets: usize,
}

/// Bounded HTTPS rendezvous and aggregate health policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendezvousConfig {
    /// Public in-process TLS listener.
    pub listen: SocketAddr,
    /// Loopback-only aggregate health listener.
    pub health_listen: SocketAddr,
    /// Maximum accepted TLS connections in flight.
    pub max_tls_connections: usize,
    /// Maximum TLS connections accepted in one fixed minute.
    pub max_connections_per_minute: u32,
    /// Maximum TLS connections from one exact network address per fixed
    /// minute.
    pub max_connections_per_address_per_minute: u32,
    /// Maximum live volatile address-rate buckets.
    pub max_ingress_rate_buckets: usize,
    /// TLS handshake deadline.
    pub tls_handshake_timeout_seconds: u64,
    /// One complete fixed-shape request deadline after TLS.
    pub request_timeout_seconds: u64,
    /// Maximum retained opaque rendezvous rows.
    pub max_records: usize,
    /// Conservative total mutable rendezvous accounting.
    pub max_memory_bytes: usize,
    /// Simultaneous decoded rendezvous operations.
    pub max_concurrent_requests: usize,
    /// Accepted decoded operations per fixed minute.
    pub max_global_operations_per_minute: u32,
    /// Fixed request and response bytes per fixed minute.
    pub max_global_bytes_per_minute: u64,
    /// Operations on one opaque slot per fixed minute.
    pub max_slot_operations_per_minute: u32,
    /// Maximum live opaque slot-rate buckets.
    pub max_slot_buckets: usize,
    /// Operations in one volatile ingress bucket per fixed minute.
    pub max_client_operations_per_minute: u32,
    /// Maximum live volatile ingress buckets.
    pub max_client_buckets: usize,
}

/// Process lifecycle limits.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLimits {
    /// Time allowed for listener tasks to stop on SIGINT or SIGTERM.
    pub shutdown_grace_seconds: u64,
}

impl Config {
    /// Open, bound, decode, and validate one regular non-symlink TOML file.
    pub fn open(path: &Path) -> Result<Self, ServiceError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| ServiceError::io("open configuration", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ServiceError::invalid(
                "configuration must be a regular non-symlink file",
            ));
        }
        if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(ServiceError::invalid(
                "configuration size is outside its bound",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(path)
            .map_err(|error| ServiceError::io("open configuration", error))?;
        let opened_metadata = file
            .metadata()
            .map_err(|error| ServiceError::io("inspect configuration", error))?;
        if !opened_metadata.is_file()
            || opened_metadata.len() == 0
            || opened_metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(ServiceError::invalid(
                "configuration must be a bounded regular file",
            ));
        }
        let mut text = String::with_capacity(opened_metadata.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|error| ServiceError::io("read configuration", error))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ServiceError::invalid(
                "configuration size is outside its bound",
            ));
        }
        let config: Self = toml::from_str(&text)
            .map_err(|error| ServiceError::invalid(format!("configuration: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every hard role and resource boundary.
    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.version != CONFIG_VERSION {
            return Err(ServiceError::invalid(format!(
                "configuration version {} is unsupported",
                self.version
            )));
        }
        for (label, path) in [
            ("libp2p identity", &self.libp2p_identity_file),
            ("TLS certificate", &self.tls_certificate_file),
            ("TLS private key", &self.tls_private_key_file),
        ] {
            if !path.is_absolute() {
                return Err(ServiceError::invalid(format!(
                    "{label} path must be absolute"
                )));
            }
        }
        if self.libp2p_identity_file == self.tls_private_key_file
            || self.libp2p_identity_file == self.tls_certificate_file
            || self.tls_private_key_file == self.tls_certificate_file
        {
            return Err(ServiceError::invalid(
                "libp2p identity, TLS key, and TLS certificate must be separate files",
            ));
        }
        self.dht.validate()?;
        self.rendezvous.validate()?;
        self.runtime.validate()?;
        let combined = self
            .dht
            .max_value_bytes
            .checked_add(self.rendezvous.max_memory_bytes)
            .ok_or_else(|| ServiceError::invalid("combined mutable memory overflows"))?;
        if combined > MAX_COMBINED_MUTABLE_MEMORY {
            return Err(ServiceError::invalid(
                "combined DHT and rendezvous mutable memory exceeds 384 MiB",
            ));
        }
        Ok(())
    }
}

impl DhtConfig {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.listen.is_empty() || self.listen.len() > MAX_DHT_LISTENERS {
            return Err(ServiceError::invalid("DHT listener count is outside 1..=8"));
        }
        if self.bootstrap.len() > MAX_BOOTSTRAP_PEERS {
            return Err(ServiceError::invalid("DHT bootstrap peer count exceeds 32"));
        }
        if self.listen.iter().any(|value| value.len() > 512)
            || self.bootstrap.iter().any(|value| value.len() > 1024)
        {
            return Err(ServiceError::invalid("DHT multiaddress is too long"));
        }
        if self.max_records == 0 || self.max_records > MAX_DHT_RECORDS {
            return Err(ServiceError::invalid("DHT max_records is outside 1..=256"));
        }
        if self.max_value_bytes < kult_crypto::DISCOVERY_RECORD_SIZE
            || self.max_value_bytes > MAX_DHT_VALUE_MEMORY
        {
            return Err(ServiceError::invalid(
                "DHT value memory is outside the protocol and 320 MiB hard bounds",
            ));
        }
        if !(3_600..=259_200).contains(&self.record_ttl_seconds) {
            return Err(ServiceError::invalid(
                "DHT record TTL is outside 1 hour..=3 days",
            ));
        }
        for (label, value) in [
            ("pending incoming", self.max_pending_incoming),
            ("pending outgoing", self.max_pending_outgoing),
            ("established incoming", self.max_established_incoming),
            ("established", self.max_established),
            ("established per peer", self.max_established_per_peer),
        ] {
            if value == 0 || value > MAX_NETWORK_CONNECTIONS {
                return Err(ServiceError::invalid(format!(
                    "DHT {label} connection limit is outside 1..=512"
                )));
            }
        }
        if self.max_established_incoming > self.max_established
            || self.max_established_per_peer > self.max_established
        {
            return Err(ServiceError::invalid(
                "DHT subordinate connection limit exceeds total connections",
            ));
        }
        if self.max_inbound_connections_per_minute == 0
            || self.max_inbound_connections_per_address_per_minute == 0
            || self.max_inbound_connections_per_address_per_minute
                > self.max_inbound_connections_per_minute
        {
            return Err(ServiceError::invalid(
                "DHT inbound connection rate limits are inconsistent",
            ));
        }
        if self.max_inbound_rate_buckets == 0 || self.max_inbound_rate_buckets > MAX_RATE_BUCKETS {
            return Err(ServiceError::invalid(
                "DHT inbound rate bucket count is outside 1..=65536",
            ));
        }
        Ok(())
    }
}

impl RendezvousConfig {
    pub(crate) fn service_config(&self) -> RendezvousServiceConfig {
        RendezvousServiceConfig {
            max_records: self.max_records,
            max_memory_bytes: self.max_memory_bytes,
            max_concurrent_requests: self.max_concurrent_requests,
            max_global_operations_per_minute: self.max_global_operations_per_minute,
            max_global_bytes_per_minute: self.max_global_bytes_per_minute,
            max_slot_operations_per_minute: self.max_slot_operations_per_minute,
            max_slot_buckets: self.max_slot_buckets,
            max_client_operations_per_minute: self.max_client_operations_per_minute,
            max_client_buckets: self.max_client_buckets,
        }
    }

    fn validate(&self) -> Result<(), ServiceError> {
        if !self.health_listen.ip().is_loopback() {
            return Err(ServiceError::invalid(
                "health listener must use an explicit loopback address",
            ));
        }
        if self.listen == self.health_listen {
            return Err(ServiceError::invalid(
                "public rendezvous and health listeners must be separate",
            ));
        }
        if self.max_tls_connections == 0 || self.max_tls_connections > 512 {
            return Err(ServiceError::invalid(
                "rendezvous TLS concurrency is outside 1..=512",
            ));
        }
        if self.max_connections_per_minute == 0
            || self.max_connections_per_address_per_minute == 0
            || self.max_connections_per_address_per_minute > self.max_connections_per_minute
        {
            return Err(ServiceError::invalid(
                "rendezvous connection rate limits are inconsistent",
            ));
        }
        if self.max_ingress_rate_buckets == 0 || self.max_ingress_rate_buckets > MAX_RATE_BUCKETS {
            return Err(ServiceError::invalid(
                "rendezvous ingress bucket count is outside 1..=65536",
            ));
        }
        if !(1..=30).contains(&self.tls_handshake_timeout_seconds)
            || !(1..=30).contains(&self.request_timeout_seconds)
        {
            return Err(ServiceError::invalid(
                "rendezvous deadlines are outside 1..=30 seconds",
            ));
        }
        if self.max_memory_bytes > MAX_RENDEZVOUS_MEMORY {
            return Err(ServiceError::invalid(
                "rendezvous mutable memory exceeds 192 MiB",
            ));
        }
        if RendezvousService::new(self.service_config()).is_none() {
            return Err(ServiceError::invalid(
                "rendezvous component limits are inconsistent",
            ));
        }
        Ok(())
    }
}

impl RuntimeLimits {
    fn validate(&self) -> Result<(), ServiceError> {
        if !(1..=60).contains(&self.shutdown_grace_seconds) {
            return Err(ServiceError::invalid(
                "shutdown grace is outside 1..=60 seconds",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_must_be_loopback_and_roles_cannot_be_added() {
        let unknown = r#"
version = 1
libp2p_identity_file = "/run/keys/libp2p"
tls_certificate_file = "/run/keys/tls.crt"
tls_private_key_file = "/run/keys/tls.key"
mailbox = true
"#;
        assert!(toml::from_str::<Config>(unknown).is_err());
    }

    #[test]
    fn role_selection_has_an_exact_health_and_key_scope() {
        assert!(RoleSelection::BootstrapKadCache.includes_dht());
        assert!(!RoleSelection::BootstrapKadCache.includes_rendezvous());
        assert_eq!(
            RoleSelection::BootstrapKadCache.health_json(),
            "\"bootstrap-kad-cache\""
        );
        assert!(!RoleSelection::PairwiseRendezvous.includes_dht());
        assert!(RoleSelection::PairwiseRendezvous.includes_rendezvous());
        assert_eq!(
            RoleSelection::PairwiseRendezvous.health_json(),
            "\"pairwise-rendezvous\""
        );
        assert!(RoleSelection::Both.includes_dht());
        assert!(RoleSelection::Both.includes_rendezvous());
    }

    #[test]
    fn explicit_two_role_limits_validate_and_memory_is_combined() {
        let mut config = complete_config();
        config.validate().unwrap();
        config.rendezvous.health_listen = "0.0.0.0:8081".parse().unwrap();
        assert!(config.validate().is_err());

        let mut config = complete_config();
        config.dht.max_value_bytes = 300 * 1024 * 1024;
        config.rendezvous.max_memory_bytes = 100 * 1024 * 1024;
        assert!(config.validate().is_err());
    }

    #[test]
    fn configuration_open_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("reference-service.toml");
        std::fs::write(
            &config_path,
            include_str!("../../../deploy/reference-service/reference-service.toml"),
        )
        .unwrap();
        Config::open(&config_path).unwrap();

        #[cfg(unix)]
        {
            let symlink_path = directory.path().join("linked.toml");
            std::os::unix::fs::symlink(&config_path, &symlink_path).unwrap();
            assert!(Config::open(&symlink_path).is_err());
        }
    }

    fn complete_config() -> Config {
        Config {
            version: CONFIG_VERSION,
            libp2p_identity_file: "/run/komms-reference/libp2p.key".into(),
            tls_certificate_file: "/run/komms-reference/tls.crt".into(),
            tls_private_key_file: "/run/komms-reference/tls.key".into(),
            dht: DhtConfig {
                listen: vec![
                    "/ip4/0.0.0.0/tcp/4405".into(),
                    "/ip4/0.0.0.0/udp/4405/quic-v1".into(),
                ],
                bootstrap: Vec::new(),
                max_records: 128,
                max_value_bytes: 192 * 1024 * 1024,
                record_ttl_seconds: 172_800,
                max_pending_incoming: 32,
                max_pending_outgoing: 16,
                max_established_incoming: 64,
                max_established: 96,
                max_established_per_peer: 4,
                max_inbound_connections_per_minute: 4_096,
                max_inbound_connections_per_address_per_minute: 120,
                max_inbound_rate_buckets: 8_192,
            },
            rendezvous: RendezvousConfig {
                listen: "0.0.0.0:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8081".parse().unwrap(),
                max_tls_connections: 256,
                max_connections_per_minute: 120_000,
                max_connections_per_address_per_minute: 600,
                max_ingress_rate_buckets: 16_384,
                tls_handshake_timeout_seconds: 5,
                request_timeout_seconds: 5,
                max_records: 16_384,
                max_memory_bytes: 96 * 1024 * 1024,
                max_concurrent_requests: 256,
                max_global_operations_per_minute: 120_000,
                max_global_bytes_per_minute: 512 * 1024 * 1024,
                max_slot_operations_per_minute: 24,
                max_slot_buckets: 65_536,
                max_client_operations_per_minute: 600,
                max_client_buckets: 16_384,
            },
            runtime: RuntimeLimits {
                shutdown_grace_seconds: 10,
            },
        }
    }
}
