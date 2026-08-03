use std::fs;
use std::path::{Path, PathBuf};

use kult_mailbox::{initialize, inspect, Config};

fn configuration(root: &Path) -> String {
    format!(
        r#"version = 1
database_file = "{database}"
row_key_file = "{row_key}"
transport_identity_file = "{transport_key}"

[network]
listen = ["/ip4/0.0.0.0/udp/4406/quic-v1", "/ip4/0.0.0.0/tcp/4406"]
health_listen = "127.0.0.1:8083"

[mailbox]
max_tokens = 65536
max_tokens_per_client = 4096
max_per_token = 256
max_bytes_per_token = 16777216
max_per_client = 4096
max_bytes_per_client = 33554432
max_total_items = 65536
max_total_bytes = 67108864
envelope_ttl_seconds = 2592000
registration_ttl_seconds = 5184000
lease_ttl_seconds = 120
max_live_leases_per_client = 4
max_live_leases_per_token = 2
max_live_leases = 4096
max_requests_per_client_per_minute = 2048
max_requests_per_minute = 8192

[runtime]
shutdown_grace_seconds = 10
"#,
        database = root.join("state/mailbox-v2.db").display(),
        row_key = root.join("keys/mailbox-v2.key").display(),
        transport_key = root.join("keys/mailbox-v2.transport.key").display(),
    )
}

fn write_config(root: &Path, text: &str) -> PathBuf {
    let path = root.join("mailbox.toml");
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn strict_configuration_initializes_and_inspects_dedicated_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = write_config(directory.path(), &configuration(directory.path()));
    let config = Config::open(&path).unwrap();
    let initialized = initialize(&config).unwrap();
    assert_eq!(initialized.schema_version, 2);
    assert!(!initialized.peer_id.is_empty());
    assert_eq!(inspect(&config).unwrap(), initialized);
    assert!(
        initialize(&config).is_err(),
        "existing service state is never overwritten"
    );
}

#[test]
fn configuration_rejects_unknown_fields_and_unbounded_subordinate_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let unknown = configuration(directory.path()).replace(
        "version = 1",
        "version = 1\nendpoint_identity_file = \"/forbidden\"",
    );
    let path = write_config(directory.path(), &unknown);
    assert!(Config::open(&path)
        .unwrap_err()
        .to_string()
        .contains("unknown field"));

    let invalid = configuration(directory.path()).replace(
        "max_tokens_per_client = 4096",
        "max_tokens_per_client = 70000",
    );
    fs::write(&path, invalid).unwrap();
    assert!(Config::open(&path)
        .unwrap_err()
        .to_string()
        .contains("subordinate capacity"));
}

#[cfg(unix)]
#[test]
fn configuration_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.toml");
    fs::write(&target, configuration(directory.path())).unwrap();
    let link = directory.path().join("mailbox.toml");
    symlink(target, &link).unwrap();
    assert!(Config::open(&link)
        .unwrap_err()
        .to_string()
        .contains("non-symlink"));
}
