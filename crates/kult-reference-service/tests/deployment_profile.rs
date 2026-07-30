#![forbid(unsafe_code)]

const DOCKERFILE: &str = include_str!("../../../deploy/reference-service/Dockerfile");
const COMPOSE: &str = include_str!("../../../deploy/reference-service/compose.yaml");
const CONFIG: &str = include_str!("../../../deploy/reference-service/reference-service.toml");

#[test]
fn container_profile_has_no_persistent_or_privileged_role() {
    for required in [
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "pids_limit:",
        "mem_limit:",
        "memswap_limit:",
        "mem_swappiness: 0",
        "driver: none",
        "ulimits:",
        "core:",
        "tmpfs:",
        "read_only: true",
    ] {
        assert!(
            COMPOSE.contains(required),
            "missing deployment control: {required}"
        );
    }
    for forbidden in [
        "privileged: true",
        "/var/lib/komms",
        "volume:",
        "mailbox",
        "wake",
        "KULTD_",
    ] {
        assert!(
            !COMPOSE.contains(forbidden),
            "forbidden role or persistence boundary: {forbidden}"
        );
    }
    assert!(!DOCKERFILE.contains("VOLUME "));
    assert!(DOCKERFILE.contains("USER 10002:10002"));
    assert!(DOCKERFILE.contains("rust:1.88-bookworm@sha256:"));
    assert!(DOCKERFILE.contains("debian:bookworm-slim@sha256:"));
}

#[test]
fn configuration_exposes_exactly_the_two_service_roles() {
    for required in [
        "[dht]",
        "[rendezvous]",
        "health_listen = \"127.0.0.1:8081\"",
        "record_ttl_seconds = 172800",
        "max_records = ",
        "max_memory_bytes = ",
        "max_concurrent_requests = ",
        "max_inbound_connections_per_minute = ",
    ] {
        assert!(
            CONFIG.contains(required),
            "missing explicit bound: {required}"
        );
    }
    for forbidden in [
        "mailbox",
        "wake",
        "endpoint",
        "directory",
        "updater",
        "analytics",
        "bridge",
    ] {
        assert!(
            !CONFIG.contains(forbidden),
            "configuration can name a forbidden role: {forbidden}"
        );
    }
}
