use std::fs;
use std::path::PathBuf;

use kult_mailbox::Config;
use kult_transport::MAILBOX_SERVICE_PROTOCOLS;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn artifact_exposes_only_the_dedicated_mailbox_role() {
    assert_eq!(MAILBOX_SERVICE_PROTOCOLS, &["/komms/mailbox/2"]);
    let root = repository_root();
    let dockerfile = fs::read_to_string(root.join("deploy/mailbox-service/Dockerfile")).unwrap();
    assert!(dockerfile.contains("cargo build --locked --release --package kult-mailbox"));
    assert!(dockerfile.contains("USER 10004:10004"));
    for forbidden in ["kultd", "kult-reference-service", "kult-wake", "kult-node"] {
        assert!(
            !dockerfile.contains(forbidden),
            "mailbox image includes forbidden artifact {forbidden}"
        );
    }
}

#[test]
fn container_profile_is_read_only_logless_and_separates_state_from_keys() {
    let root = repository_root();
    let compose = fs::read_to_string(root.join("deploy/mailbox-service/compose.yaml")).unwrap();
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
        "MAILBOX_SERVICE_KEYS_DIR",
        "MAILBOX_SERVICE_STATE_DIR",
        "read_only: true",
    ] {
        assert!(compose.contains(required), "missing {required}");
    }
    assert!(!compose.contains("privileged: true"));
    assert!(!compose.contains("/var/run/docker.sock"));
    assert!(!compose.contains("network_mode: host"));
}

#[test]
fn example_configuration_is_strict_bounded_and_has_no_v1_switch() {
    let root = repository_root();
    let path = root.join("deploy/mailbox-service/mailbox-service.toml");
    Config::open(&path).unwrap();
    let text = fs::read_to_string(path).unwrap();
    assert!(!text.contains("allow_v1"));
    assert!(text.contains("max_total_items = 65536"));
    assert!(text.contains("max_total_bytes = 67108864"));
    assert!(text.contains("envelope_ttl_seconds = 2592000"));
    assert!(text.contains("health_listen = \"127.0.0.1:8083\""));
}

#[test]
fn publication_workflow_requires_an_explicit_reusable_push_input() {
    let root = repository_root();
    let workflow =
        fs::read_to_string(root.join(".github/workflows/mailbox-service-container.yml")).unwrap();
    let ci = fs::read_to_string(root.join(".github/workflows/mailbox-service-container-ci.yml"))
        .unwrap();
    assert!(workflow.contains("push: ${{ inputs.push }}"));
    assert!(workflow.contains("provenance: ${{ inputs.push"));
    assert!(workflow.contains("sbom: ${{ inputs.push }}"));
    assert!(ci.contains("push: false"));
}
