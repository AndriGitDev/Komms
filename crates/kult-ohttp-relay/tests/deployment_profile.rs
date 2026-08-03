use std::fs;
use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn container_profile_is_ephemeral_least_privilege_and_logless() {
    let root = repository_root();
    let compose = fs::read_to_string(root.join("deploy/ohttp-relay/compose.yaml")).unwrap();
    for required in [
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "memswap_limit: 256m",
        "mem_swappiness: 0",
        "logging:",
        "driver: none",
        "ulimits:",
        "core:",
        "/run/komms-ohttp:rw,noexec,nosuid,nodev",
        "KOMMS_OHTTP_RELAY_KEYS_DIR",
        "KOMMS_OHTTP_GATEWAY_CA_FILE",
    ] {
        assert!(compose.contains(required), "missing {required}");
    }
    for forbidden in [
        "privileged: true",
        "/var/run/docker.sock",
        "/var/lib/",
        "KOMMS_OHTTP_GATEWAY_KEYS",
    ] {
        assert!(!compose.contains(forbidden), "unexpected {forbidden}");
    }

    let dockerfile = fs::read_to_string(root.join("deploy/ohttp-relay/Dockerfile")).unwrap();
    assert!(dockerfile.contains("USER 10004:10004"));
    assert!(dockerfile.contains("cargo build --locked --release --package kult-ohttp-relay"));
    assert!(!dockerfile.contains("kultd"));
    assert!(!dockerfile.contains("kult-wake"));
    assert!(!dockerfile.contains("kult-reference-service"));
}

#[test]
fn example_configuration_is_one_fixed_bounded_mapping() {
    let root = repository_root();
    let text = fs::read_to_string(root.join("deploy/ohttp-relay/ohttp-relay.toml")).unwrap();
    let config: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(config["version"].as_integer(), Some(1));
    assert_ne!(
        config["tls_private_key_file"],
        config["gateway_ca_certificate_file"]
    );
    assert_eq!(
        config["network"]["public_resource"].as_str(),
        Some("/ohttp")
    );
    assert_eq!(
        config["upstream"]["resource"].as_str(),
        Some("/ohttp-gateway")
    );
    assert!(!text.contains("target="));
    assert_eq!(
        config["upstream"]["encapsulated_request_bytes"].as_integer(),
        Some(4096)
    );
    assert_eq!(
        config["upstream"]["encapsulated_response_bytes"].as_integer(),
        Some(4096)
    );
    assert!(
        config["upstream"]["timeout_seconds"].as_integer()
            < config["network"]["request_timeout_seconds"].as_integer()
    );
}
