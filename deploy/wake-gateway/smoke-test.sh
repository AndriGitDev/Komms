#!/bin/sh
set -eu

compose_file=${COMPOSE_FILE:-deploy/wake-gateway/compose.yaml}
image=${WAKE_GATEWAY_IMAGE:-ghcr.io/andrigitdev/komms-wake:wake-ci}
project_root=$(CDPATH= cd "$(dirname "$0")/../.." && pwd -P)
temp_root=${WAKE_GATEWAY_TEMP_ROOT:-$project_root/target}
mkdir -p "$temp_root"
smoke_root=$(mktemp -d "$temp_root/komms-wake-smoke.XXXXXX")
smoke_root=$(cd "$smoke_root" && pwd -P)
service_keys="$smoke_root/service-keys"
native_credentials="$smoke_root/native-credentials"
state_dir="$smoke_root/state"
config_file="$smoke_root/config.toml"
mkdir -p "$service_keys" "$native_credentials" "$state_dir"

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
    WAKE_GATEWAY_CONFIG="$config_file" \
    WAKE_SERVICE_KEYS_DIR="$service_keys" \
    WAKE_NATIVE_CREDENTIALS_DIR="$native_credentials" \
    WAKE_PROVIDER_CA_FILE="$service_keys/tls.crt" \
    WAKE_STATE_DIR="$state_dir" \
    WAKE_GATEWAY_IMAGE="$image" \
    compose -f "$compose_file" down --timeout 15 >/dev/null 2>&1 || true
    rm -rf "$smoke_root"
}
trap cleanup EXIT INT TERM

export WAKE_GATEWAY_UID="${WAKE_GATEWAY_UID:-$(id -u)}"
export WAKE_GATEWAY_GID="${WAKE_GATEWAY_GID:-$(id -g)}"
export WAKE_GATEWAY_CONFIG="$config_file"
export WAKE_SERVICE_KEYS_DIR="$service_keys"
export WAKE_NATIVE_CREDENTIALS_DIR="$native_credentials"
export WAKE_PROVIDER_CA_FILE="$service_keys/tls.crt"
export WAKE_STATE_DIR="$state_dir"
export WAKE_GATEWAY_IMAGE="$image"
export KOMMS_SOURCE_REVISION="${KOMMS_SOURCE_REVISION:-$(git rev-parse HEAD)}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

docker run --rm \
    --user "$WAKE_GATEWAY_UID:$WAKE_GATEWAY_GID" \
    --mount "type=bind,source=$service_keys,target=/keys" \
    "$image" generate-capability-key \
    --output /keys/capability-1.key \
    --key-id 1
openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -nodes \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$service_keys/tls.key" \
    -out "$service_keys/tls.crt" \
    -days 1 >/dev/null 2>&1
openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$native_credentials/apns-signing.p8" >/dev/null 2>&1
chmod 600 \
    "$service_keys/capability-1.key" \
    "$service_keys/tls.key" \
    "$native_credentials/apns-signing.p8"
chmod 644 "$service_keys/tls.crt"

cat > "$config_file" <<EOF
version = 1
tls_certificate_file = "/run/komms-wake-service-keys/tls.crt"
tls_private_key_file = "/run/komms-wake-service-keys/tls.key"
active_capability_key_id = 1
capability_key_files = ["/run/komms-wake-service-keys/capability-1.key"]
state_file = "/var/lib/komms-wake/state.db"

[network]
listen = "0.0.0.0:8444"
health_listen = "127.0.0.1:8082"
max_connections = 32
max_connections_per_minute = 1000
max_connections_per_source_per_minute = 120
max_source_buckets = 1024
tls_handshake_timeout_seconds = 5
request_timeout_seconds = 15

[gateway]
capability_lifetime_seconds = 3600
per_capability_per_minute = 6
per_destination_per_minute = 12
global_per_minute = 1000
max_capability_buckets = 1024
max_destination_buckets = 1024
coalesce_seconds = 30
provider_timeout_seconds = 11

[state]
max_revocations = 1024
max_replays = 4096

[provider]
ca_certificate_file = "/run/komms-wake-ca/roots.pem"
request_timeout_seconds = 10
max_response_bytes = 16384

[provider.apns]
signing_key_file = "/run/komms-wake-native-credentials/apns-signing.p8"
key_id = "SMOKEKEY"
team_id = "SMOKETEAM"
allowed_topics = ["is.andri.komms"]

[runtime]
shutdown_grace_seconds = 10
EOF

compose -f "$compose_file" config --quiet
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T wake-gateway \
    kult-wake probe --address 127.0.0.1:8082
compose -f "$compose_file" restart --timeout 15 wake-gateway
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T wake-gateway \
    kult-wake probe --address 127.0.0.1:8082

container_id=$(compose -f "$compose_file" ps -q wake-gateway)
if [ -z "$container_id" ] ||
    [ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_id")" != none ]; then
    echo "wake-gateway container does not use the disabled log driver" >&2
    exit 1
fi
