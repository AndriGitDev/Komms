use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config::{Config, RoleSelection};
use crate::runtime::ServiceError;

const MAX_LIBP2P_KEY_BYTES: u64 = 1024;
const MAX_TLS_CERTIFICATE_BYTES: u64 = 128 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES: u64 = 32 * 1024;
const MAX_CERTIFICATES: usize = 8;

/// Non-secret fingerprints needed by a provider directory and public operator
/// record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKeyInfo {
    /// Stable libp2p service peer id, or empty when that role is disabled.
    pub libp2p_peer_id: String,
    /// SHA-256 of the protobuf-encoded libp2p public key, or empty when that
    /// role is disabled.
    pub libp2p_public_key_sha256: String,
    /// SHA-256 of the first TLS certificate's DER encoding, or empty when
    /// rendezvous is disabled.
    pub tls_certificate_sha256: String,
    /// ADR-0018 provider static key, currently the same 32-byte digest as the
    /// leaf TLS certificate, or empty when rendezvous is disabled.
    pub provider_static_key: String,
}

/// Generate an Ed25519 identity in an explicitly named new owner-only file.
///
/// This is a runtime service credential only. The operation never overwrites
/// an existing path and the generated key grants no Komms user, directory, or
/// release authority.
pub fn generate_libp2p_identity(path: &Path) -> Result<ServiceKeyInfo, ServiceError> {
    if !path.is_absolute() {
        return Err(ServiceError::invalid(
            "libp2p identity output path must be absolute",
        ));
    }
    let key = libp2p::identity::Keypair::generate_ed25519();
    let mut encoded = Zeroizing::new(
        key.to_protobuf_encoding()
            .map_err(|_| ServiceError::invalid("encode libp2p service identity"))?,
    );
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| ServiceError::io("create libp2p identity", error))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| ServiceError::io("commit libp2p identity", error))?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ServiceError::io("commit identity directory", error))?;
    }
    encoded.zeroize();
    Ok(key_info(Some(&key), None))
}

/// Load a distinct owner-only Ed25519 service identity.
pub fn load_libp2p_identity(path: &Path) -> Result<libp2p::identity::Keypair, ServiceError> {
    let encoded = read_bounded_regular(path, MAX_LIBP2P_KEY_BYTES, true, "libp2p identity")?;
    let key = libp2p::identity::Keypair::from_protobuf_encoding(&encoded)
        .map_err(|_| ServiceError::invalid("libp2p identity encoding is invalid"))?;
    if key.key_type() != libp2p::identity::KeyType::Ed25519 {
        return Err(ServiceError::invalid(
            "libp2p identity must be an Ed25519 service key",
        ));
    }
    Ok(key)
}

/// Load and cross-check all service credentials, returning only non-secret
/// fingerprints.
pub fn inspect_service_keys(config: &Config) -> Result<ServiceKeyInfo, ServiceError> {
    inspect_selected_service_keys(config, RoleSelection::Both)
}

/// Load only the credential domains required by the selected role set.
///
/// A one-role process neither opens nor requires the other role's private-key
/// file.
pub fn inspect_selected_service_keys(
    config: &Config,
    roles: RoleSelection,
) -> Result<ServiceKeyInfo, ServiceError> {
    config.validate()?;
    let identity = roles
        .includes_dht()
        .then(|| load_libp2p_identity(&config.libp2p_identity_file))
        .transpose()?;
    let certificates = if roles.includes_rendezvous() {
        let (certificates, private_key) = load_tls_material(config)?;
        build_server_config(certificates.clone(), private_key)?;
        Some(certificates)
    } else {
        None
    };
    Ok(key_info(
        identity.as_ref(),
        certificates.as_ref().and_then(|chain| chain.first()),
    ))
}

pub(crate) fn load_tls_server_config(
    config: &Config,
) -> Result<Arc<rustls::ServerConfig>, ServiceError> {
    let (certificates, private_key) = load_tls_material(config)?;
    build_server_config(certificates, private_key).map(Arc::new)
}

fn load_tls_material(
    config: &Config,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServiceError> {
    let certificate_bytes = read_bounded_regular(
        &config.tls_certificate_file,
        MAX_TLS_CERTIFICATE_BYTES,
        false,
        "TLS certificate",
    )?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServiceError::invalid(format!("parse TLS certificate: {error}")))?;
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
        return Err(ServiceError::invalid(
            "TLS certificate chain count is outside 1..=8",
        ));
    }

    let private_bytes = read_bounded_regular(
        &config.tls_private_key_file,
        MAX_TLS_PRIVATE_KEY_BYTES,
        true,
        "TLS private key",
    )?;
    let mut private_keys = PrivatePkcs8KeyDer::pem_slice_iter(&private_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServiceError::invalid(format!("parse TLS private key: {error}")))?;
    if private_keys.len() != 1 {
        return Err(ServiceError::invalid(
            "TLS private key file must contain exactly one PKCS#8 key",
        ));
    }
    let private_key = PrivateKeyDer::Pkcs8(private_keys.remove(0));
    Ok((certificates, private_key))
}

fn build_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, ServiceError> {
    let provider = rustls::crypto::ring::default_provider();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ServiceError::invalid(format!("TLS 1.3 configuration: {error}")))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| ServiceError::invalid(format!("TLS certificate/key mismatch: {error}")))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok(server)
}

fn key_info(
    identity: Option<&libp2p::identity::Keypair>,
    leaf: Option<&CertificateDer<'static>>,
) -> ServiceKeyInfo {
    let (libp2p_peer_id, libp2p_public_key_sha256) = identity
        .map(|identity| {
            let public = identity.public();
            (
                public.to_peer_id().to_string(),
                hex::encode(Sha256::digest(public.encode_protobuf())),
            )
        })
        .unwrap_or_default();
    let certificate_digest = leaf
        .map(|certificate| hex::encode(Sha256::digest(certificate.as_ref())))
        .unwrap_or_default();
    ServiceKeyInfo {
        libp2p_peer_id,
        libp2p_public_key_sha256,
        tls_certificate_sha256: certificate_digest.clone(),
        provider_static_key: certificate_digest,
    }
}

fn read_bounded_regular(
    path: &Path,
    max_bytes: u64,
    secret: bool,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ServiceError::io(&format!("open {label}"), error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ServiceError::invalid(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(ServiceError::invalid(format!(
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
    let mut file = options
        .open(path)
        .map_err(|error| ServiceError::io(&format!("open {label}"), error))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| ServiceError::io(&format!("inspect {label}"), error))?;
    if !opened_metadata.is_file() || opened_metadata.len() == 0 || opened_metadata.len() > max_bytes
    {
        return Err(ServiceError::invalid(format!(
            "{label} must be a bounded regular file"
        )));
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        if opened_metadata.permissions().mode() & 0o077 != 0 {
            return Err(ServiceError::invalid(format!(
                "{label} must not be group- or world-accessible"
            )));
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened_metadata.len() as usize));
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ServiceError::io(&format!("read {label}"), error))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(ServiceError::invalid(format!(
            "{label} size is outside its bound"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DhtConfig, RendezvousConfig, RuntimeLimits, CONFIG_VERSION};
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    #[test]
    fn identity_generation_is_owner_only_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service.key");
        let first = generate_libp2p_identity(&path).unwrap();
        let loaded = load_libp2p_identity(&path).unwrap();
        assert_eq!(
            first.libp2p_peer_id,
            loaded.public().to_peer_id().to_string()
        );
        assert!(generate_libp2p_identity(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_libp2p_identity(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(load_libp2p_identity(&path).is_ok());
        }
    }

    #[test]
    fn tls_key_matches_certificate_and_provider_digest() {
        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("libp2p.key");
        generate_libp2p_identity(&identity).unwrap();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = directory.path().join("tls.crt");
        let private_key = directory.path().join("tls.key");
        std::fs::write(&certificate, cert.pem()).unwrap();
        std::fs::write(&private_key, key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = credential_config(identity, certificate, private_key.clone());
        let info = inspect_service_keys(&config).unwrap();
        assert_eq!(info.provider_static_key, info.tls_certificate_sha256);
        assert_eq!(info.provider_static_key.len(), 64);

        let CertifiedKey {
            key_pair: wrong_key,
            ..
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&private_key, wrong_key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(inspect_service_keys(&config).is_err());
    }

    #[test]
    fn one_role_inspection_never_requires_the_other_roles_key() {
        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("libp2p.key");
        generate_libp2p_identity(&identity).unwrap();
        let missing_certificate = directory.path().join("absent-tls.crt");
        let missing_tls_key = directory.path().join("absent-tls.key");
        let dht_only = credential_config(identity.clone(), missing_certificate, missing_tls_key);
        let dht =
            inspect_selected_service_keys(&dht_only, RoleSelection::BootstrapKadCache).unwrap();
        assert!(!dht.libp2p_peer_id.is_empty());
        assert!(dht.tls_certificate_sha256.is_empty());
        assert!(
            inspect_selected_service_keys(&dht_only, RoleSelection::PairwiseRendezvous).is_err()
        );

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = directory.path().join("tls.crt");
        let private_key = directory.path().join("tls.key");
        std::fs::write(&certificate, cert.pem()).unwrap();
        std::fs::write(&private_key, key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let rendezvous_only = credential_config(
            directory.path().join("absent-libp2p.key"),
            certificate,
            private_key,
        );
        let rendezvous =
            inspect_selected_service_keys(&rendezvous_only, RoleSelection::PairwiseRendezvous)
                .unwrap();
        assert!(rendezvous.libp2p_peer_id.is_empty());
        assert!(!rendezvous.tls_certificate_sha256.is_empty());
        assert!(
            inspect_selected_service_keys(&rendezvous_only, RoleSelection::BootstrapKadCache)
                .is_err()
        );
    }

    fn credential_config(
        identity: std::path::PathBuf,
        certificate: std::path::PathBuf,
        private_key: std::path::PathBuf,
    ) -> Config {
        Config {
            version: CONFIG_VERSION,
            libp2p_identity_file: identity,
            tls_certificate_file: certificate,
            tls_private_key_file: private_key,
            dht: DhtConfig {
                listen: vec!["/ip4/127.0.0.1/tcp/0".into()],
                bootstrap: Vec::new(),
                max_records: 1,
                max_value_bytes: kult_crypto::DISCOVERY_RECORD_SIZE,
                record_ttl_seconds: 3_600,
                max_pending_incoming: 1,
                max_pending_outgoing: 1,
                max_established_incoming: 1,
                max_established: 1,
                max_established_per_peer: 1,
                max_inbound_connections_per_minute: 1,
                max_inbound_connections_per_address_per_minute: 1,
                max_inbound_rate_buckets: 1,
            },
            rendezvous: RendezvousConfig {
                listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8081".parse().unwrap(),
                max_tls_connections: 1,
                max_connections_per_minute: 1,
                max_connections_per_address_per_minute: 1,
                max_ingress_rate_buckets: 1,
                tls_handshake_timeout_seconds: 1,
                request_timeout_seconds: 1,
                max_records: 1,
                max_memory_bytes: 8 * 1024 * 1024,
                max_concurrent_requests: 1,
                max_global_operations_per_minute: 1,
                max_global_bytes_per_minute: 16 * 1024,
                max_slot_operations_per_minute: 1,
                max_slot_buckets: 1,
                max_client_operations_per_minute: 1,
                max_client_buckets: 1,
            },
            runtime: RuntimeLimits {
                shutdown_grace_seconds: 1,
            },
        }
    }
}
