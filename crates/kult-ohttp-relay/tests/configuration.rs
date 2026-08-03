use std::fs;

use kult_ohttp_relay::check_configuration;
use rcgen::{generate_simple_self_signed, CertifiedKey};

#[test]
fn check_loads_separate_tls_material_without_contacting_gateway() {
    let directory = tempfile::tempdir().unwrap();
    let certificate_path = directory.path().join("relay.crt");
    let private_key_path = directory.path().join("relay.key");
    let gateway_ca_path = directory.path().join("gateway-ca.pem");
    let config_path = directory.path().join("relay.toml");
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.pem();
    fs::write(&certificate_path, &certificate).unwrap();
    fs::write(&private_key_path, key_pair.serialize_pem()).unwrap();
    fs::write(&gateway_ca_path, &certificate).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = format!(
        r#"
version = 1
tls_certificate_file = "{}"
tls_private_key_file = "{}"
gateway_ca_certificate_file = "{}"

[network]
listen = "127.0.0.1:8445"
health_listen = "127.0.0.1:8083"
public_authority = "localhost"
public_resource = "/ohttp"
max_connections = 4
max_requests_per_minute = 32
max_requests_per_source_per_minute = 8
max_bytes_per_minute = 1048576
max_source_buckets = 16
tls_handshake_timeout_seconds = 2
request_timeout_seconds = 4

[upstream]
connect_host = "127.0.0.1"
port = 9443
tls_server_name = "localhost"
resource = "/ohttp-gateway"
encapsulated_request_bytes = 4096
encapsulated_response_bytes = 4096
max_response_header_bytes = 4096
timeout_seconds = 2

[runtime]
shutdown_grace_seconds = 2
"#,
        certificate_path.display(),
        private_key_path.display(),
        gateway_ca_path.display(),
    );
    fs::write(&config_path, config).unwrap();

    let information = check_configuration(&config_path).unwrap();
    for digest in [
        information.tls_certificate_sha256,
        information.gateway_ca_bundle_sha256,
        information.mapping_sha256,
    ] {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    fs::write(
        &gateway_ca_path,
        format!("{certificate}-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    assert!(check_configuration(&config_path).is_err());
}
