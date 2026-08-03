#!/bin/sh
set -eu

compose_file=${COMPOSE_FILE:-deploy/mailbox-service/compose.yaml}
image=${MAILBOX_SERVICE_IMAGE:-ghcr.io/andrigitdev/komms-mailbox:mailbox-ci}
project_root=$(unset CDPATH; cd "$(dirname "$0")/../.." && pwd -P)
temp_root=${MAILBOX_SERVICE_TEMP_ROOT:-$project_root/target}
mkdir -p "$temp_root"
smoke_root=$(mktemp -d "$temp_root/komms-mailbox-smoke.XXXXXX")
smoke_root=$(cd "$smoke_root" && pwd -P)
keys_dir="$smoke_root/keys"
state_dir="$smoke_root/state"
config_file="$smoke_root/config.toml"
mkdir -p "$keys_dir" "$state_dir"

if docker compose version >/dev/null 2>&1; then
    compose() {
        docker compose "$@"
    }
elif command -v docker-compose >/dev/null 2>&1; then
    compose() {
        docker-compose "$@"
    }
else
    echo "Docker Compose is required" >&2
    exit 2
fi

cleanup() {
    MAILBOX_SERVICE_CONFIG="$config_file" \
    MAILBOX_SERVICE_KEYS_DIR="$keys_dir" \
    MAILBOX_SERVICE_STATE_DIR="$state_dir" \
    MAILBOX_SERVICE_IMAGE="$image" \
    compose -f "$compose_file" down --timeout 15 >/dev/null 2>&1 || true
    rm -rf "$smoke_root"
}
trap cleanup EXIT INT TERM

export MAILBOX_SERVICE_UID="${MAILBOX_SERVICE_UID:-$(id -u)}"
export MAILBOX_SERVICE_GID="${MAILBOX_SERVICE_GID:-$(id -g)}"
export MAILBOX_SERVICE_CONFIG="$config_file"
export MAILBOX_SERVICE_KEYS_DIR="$keys_dir"
export MAILBOX_SERVICE_STATE_DIR="$state_dir"
export MAILBOX_SERVICE_IMAGE="$image"
export KOMMS_SOURCE_REVISION="${KOMMS_SOURCE_REVISION:-$(git rev-parse HEAD)}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

cat > "$config_file" <<EOF
version = 1
database_file = "/var/lib/komms-mailbox/mailbox-v2.db"
row_key_file = "/run/komms-mailbox-keys/mailbox-v2.key"
transport_identity_file = "/run/komms-mailbox-keys/mailbox-v2.transport.key"

[network]
listen = ["/ip4/0.0.0.0/udp/4406/quic-v1", "/ip4/0.0.0.0/tcp/4406"]
health_listen = "127.0.0.1:8083"

[mailbox]
max_tokens = 1024
max_tokens_per_client = 64
max_per_token = 16
max_bytes_per_token = 1048576
max_per_client = 128
max_bytes_per_client = 4194304
max_total_items = 1024
max_total_bytes = 16777216
envelope_ttl_seconds = 3600
registration_ttl_seconds = 7200
lease_ttl_seconds = 120
max_live_leases_per_client = 2
max_live_leases_per_token = 2
max_live_leases = 128
max_requests_per_client_per_minute = 120
max_requests_per_minute = 1000

[runtime]
shutdown_grace_seconds = 10
EOF

docker run --rm \
    --user "$MAILBOX_SERVICE_UID:$MAILBOX_SERVICE_GID" \
    --mount "type=bind,source=$config_file,target=/etc/komms-mailbox/config.toml,readonly" \
    --mount "type=bind,source=$keys_dir,target=/run/komms-mailbox-keys" \
    --mount "type=bind,source=$state_dir,target=/var/lib/komms-mailbox" \
    "$image" initialize --config /etc/komms-mailbox/config.toml

compose -f "$compose_file" config --quiet
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T mailbox \
    kult-mailbox probe --address 127.0.0.1:8083
peer_before=$(compose -f "$compose_file" exec -T mailbox \
    kult-mailbox inspect --config /etc/komms-mailbox/config.toml |
    sed -n 's/^peer_id=//p')
compose -f "$compose_file" restart --timeout 15 mailbox
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T mailbox \
    kult-mailbox probe --address 127.0.0.1:8083
peer_after=$(compose -f "$compose_file" exec -T mailbox \
    kult-mailbox inspect --config /etc/komms-mailbox/config.toml |
    sed -n 's/^peer_id=//p')
if [ -z "$peer_before" ] || [ "$peer_before" != "$peer_after" ]; then
    echo "mailbox service identity did not survive restart" >&2
    exit 1
fi

container_id=$(compose -f "$compose_file" ps -q mailbox)
if [ -z "$container_id" ] ||
    [ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_id")" != none ] ||
    [ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" != true ]; then
    echo "mailbox container hardening profile is incomplete" >&2
    exit 1
fi
