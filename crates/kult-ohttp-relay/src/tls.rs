use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use zeroize::Zeroizing;

use crate::{Config, RelayError, Result};

const MAX_TLS_CERTIFICATE_BYTES: u64 = 128 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES: u64 = 32 * 1024;
const MAX_GATEWAY_CA_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CERTIFICATES: usize = 8;
const MAX_CA_CERTIFICATES: usize = 1024;

pub(crate) fn load_server_config(config: &Config) -> Result<Arc<ServerConfig>> {
    let (certificates, private_key) = load_server_material(config)?;
    let provider = rustls::crypto::ring::default_provider();
    let mut server = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::Invalid("relay TLS 1.3 configuration failed"))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| RelayError::Invalid("relay TLS certificate/key mismatch"))?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok(Arc::new(server))
}

pub(crate) fn load_gateway_config(config: &Config) -> Result<Arc<ClientConfig>> {
    let bytes = read_bounded_regular(
        &config.gateway_ca_certificate_file,
        MAX_GATEWAY_CA_BYTES,
        false,
        "gateway CA certificate",
    )?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| RelayError::Invalid("gateway CA certificate encoding is invalid"))?;
    if certificates.is_empty() || certificates.len() > MAX_CA_CERTIFICATES {
        return Err(RelayError::Invalid(
            "gateway CA certificate count is outside 1..=1024",
        ));
    }
    let mut roots = RootCertStore::empty();
    let (accepted, ignored) = roots.add_parsable_certificates(certificates);
    if accepted == 0 || ignored != 0 {
        return Err(RelayError::Invalid(
            "gateway CA file must contain only accepted certificates",
        ));
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| RelayError::Invalid("gateway TLS 1.3 configuration failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    client.enable_early_data = false;
    Ok(Arc::new(client))
}

pub(crate) fn load_leaf_certificate(config: &Config) -> Result<CertificateDer<'static>> {
    let (certificates, _) = load_server_material(config)?;
    certificates
        .into_iter()
        .next()
        .ok_or(RelayError::Invalid("relay TLS certificate chain is empty"))
}

pub(crate) fn load_gateway_ca_bytes(config: &Config) -> Result<Zeroizing<Vec<u8>>> {
    read_bounded_regular(
        &config.gateway_ca_certificate_file,
        MAX_GATEWAY_CA_BYTES,
        false,
        "gateway CA certificate",
    )
}

fn load_server_material(
    config: &Config,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certificate_bytes = read_bounded_regular(
        &config.tls_certificate_file,
        MAX_TLS_CERTIFICATE_BYTES,
        false,
        "relay TLS certificate",
    )?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| RelayError::Invalid("relay TLS certificate encoding is invalid"))?;
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
        return Err(RelayError::Invalid(
            "relay TLS certificate chain count is outside 1..=8",
        ));
    }
    let private_bytes = read_bounded_regular(
        &config.tls_private_key_file,
        MAX_TLS_PRIVATE_KEY_BYTES,
        true,
        "relay TLS private key",
    )?;
    let mut private_keys = PrivatePkcs8KeyDer::pem_slice_iter(&private_bytes)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|_| RelayError::Invalid("relay TLS private key encoding is invalid"))?;
    if private_keys.len() != 1 {
        return Err(RelayError::Invalid(
            "relay TLS private key file must contain exactly one PKCS#8 key",
        ));
    }
    Ok((certificates, PrivateKeyDer::Pkcs8(private_keys.remove(0))))
}

fn read_bounded_regular(
    path: &Path,
    max_bytes: u64,
    secret: bool,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RelayError::Configuration(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(RelayError::Configuration(format!(
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
        return Err(RelayError::Configuration(format!(
            "{label} must remain a bounded regular file"
        )));
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        if opened.permissions().mode() & 0o077 != 0 {
            return Err(RelayError::Configuration(format!(
                "{label} must not be group- or world-accessible"
            )));
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
    file.by_ref().take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(RelayError::Configuration(format!(
            "{label} size is outside its bound"
        )));
    }
    Ok(bytes)
}
