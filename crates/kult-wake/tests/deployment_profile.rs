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
fn container_profile_is_least_privilege_and_logless() {
    let root = repository_root();
    let compose = fs::read_to_string(root.join("deploy/wake-gateway/compose.yaml")).unwrap();
    for required in [
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "memswap_limit: 384m",
        "mem_swappiness: 0",
        "logging:",
        "driver: none",
        "ulimits:",
        "core:",
        "/run/komms-wake:rw,noexec,nosuid,nodev",
        "WAKE_SERVICE_KEYS_DIR",
        "WAKE_NATIVE_CREDENTIALS_DIR",
        "WAKE_PROVIDER_CA_FILE",
        "WAKE_STATE_DIR",
    ] {
        assert!(compose.contains(required), "missing {required}");
    }
    assert!(!compose.contains("privileged: true"));
    assert!(!compose.contains("/var/run/docker.sock"));

    let dockerfile = fs::read_to_string(root.join("deploy/wake-gateway/Dockerfile")).unwrap();
    assert!(dockerfile.contains("USER 10003:10003"));
    assert!(dockerfile.contains("cargo build --locked --release --package kult-wake"));
    assert!(!dockerfile.contains("kultd"));
    assert!(!dockerfile.contains("kult-reference-service"));
}

#[test]
fn example_configuration_keeps_all_authorities_separate_and_bounded() {
    let root = repository_root();
    let text = fs::read_to_string(root.join("deploy/wake-gateway/wake-gateway.toml")).unwrap();
    let config: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(config["version"].as_integer(), Some(1));
    assert_ne!(
        config["tls_private_key_file"],
        config["provider"]["apns"]["signing_key_file"]
    );
    assert_ne!(
        config["tls_private_key_file"],
        config["provider"]["fcm"]["service_account_file"]
    );
    assert_ne!(config["state_file"], config["capability_key_files"][0]);
    let request = config["network"]["request_timeout_seconds"]
        .as_integer()
        .unwrap();
    let gateway_provider = config["gateway"]["provider_timeout_seconds"]
        .as_integer()
        .unwrap();
    let provider = config["provider"]["request_timeout_seconds"]
        .as_integer()
        .unwrap();
    assert!(provider <= gateway_provider);
    assert!(gateway_provider < request);
    assert_eq!(
        config["gateway"]["capability_lifetime_seconds"].as_integer(),
        Some(30 * 24 * 60 * 60)
    );
}
