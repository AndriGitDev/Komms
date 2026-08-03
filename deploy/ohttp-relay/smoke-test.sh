#!/bin/sh
set -eu

compose_file=${COMPOSE_FILE:-deploy/ohttp-relay/compose.yaml}
image=${KOMMS_OHTTP_RELAY_IMAGE:-ghcr.io/andrigitdev/komms-ohttp-relay:ohttp-relay-ci}
project_root=$(unset CDPATH; cd "$(dirname "$0")/../.." && pwd -P)
temp_root=${KOMMS_OHTTP_RELAY_TEMP_ROOT:-$project_root/target}
mkdir -p "$temp_root"
smoke_root=$(mktemp -d "$temp_root/komms-ohttp-relay-smoke.XXXXXX")
smoke_root=$(cd "$smoke_root" && pwd -P)
service_keys="$smoke_root/service-keys"
gateway_ca="$smoke_root/gateway-ca.pem"
config_file="$smoke_root/config.toml"
mkdir -p "$service_keys"

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
    KOMMS_OHTTP_RELAY_CONFIG="$config_file" \
    KOMMS_OHTTP_RELAY_KEYS_DIR="$service_keys" \
    KOMMS_OHTTP_GATEWAY_CA_FILE="$gateway_ca" \
    KOMMS_OHTTP_RELAY_IMAGE="$image" \
    compose -f "$compose_file" down --timeout 15 >/dev/null 2>&1 || true
    rm -rf "$smoke_root"
}
trap cleanup EXIT INT TERM

export KOMMS_OHTTP_RELAY_UID="${KOMMS_OHTTP_RELAY_UID:-$(id -u)}"
export KOMMS_OHTTP_RELAY_GID="${KOMMS_OHTTP_RELAY_GID:-$(id -g)}"
export KOMMS_OHTTP_RELAY_CONFIG="$config_file"
export KOMMS_OHTTP_RELAY_KEYS_DIR="$service_keys"
export KOMMS_OHTTP_GATEWAY_CA_FILE="$gateway_ca"
export KOMMS_OHTTP_RELAY_IMAGE="$image"
export KOMMS_SOURCE_REVISION="${KOMMS_SOURCE_REVISION:-$(git rev-parse HEAD)}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -nodes \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$service_keys/tls.key" \
    -out "$service_keys/tls.crt" \
    -days 1 >/dev/null 2>&1
chmod 600 "$service_keys/tls.key"
chmod 644 "$service_keys/tls.crt"
cp "$service_keys/tls.crt" "$gateway_ca"
chmod 644 "$gateway_ca"

cat > "$config_file" <<EOF
version = 1
tls_certificate_file = "/run/komms-ohttp-service-keys/tls.crt"
tls_private_key_file = "/run/komms-ohttp-service-keys/tls.key"
gateway_ca_certificate_file = "/run/komms-ohttp-gateway-ca/roots.pem"

[network]
listen = "0.0.0.0:8445"
health_listen = "127.0.0.1:8083"
public_authority = "localhost"
public_resource = "/ohttp"
max_connections = 32
max_requests_per_minute = 1000
max_requests_per_source_per_minute = 120
max_bytes_per_minute = 4194304
max_source_buckets = 1024
tls_handshake_timeout_seconds = 5
request_timeout_seconds = 5

[upstream]
connect_host = "127.0.0.1"
port = 9443
tls_server_name = "localhost"
resource = "/ohttp-gateway"
encapsulated_request_bytes = 4096
encapsulated_response_bytes = 4096
max_response_header_bytes = 8192
timeout_seconds = 3

[runtime]
shutdown_grace_seconds = 10
EOF

compose -f "$compose_file" config --quiet
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T ohttp-relay \
    kult-ohttp-relay check --config /etc/komms-ohttp/config.toml
compose -f "$compose_file" exec -T ohttp-relay \
    kult-ohttp-relay probe --address 127.0.0.1:8083
compose -f "$compose_file" restart --timeout 15 ohttp-relay
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T ohttp-relay \
    kult-ohttp-relay probe --address 127.0.0.1:8083

container_id=$(compose -f "$compose_file" ps -q ohttp-relay)
if [ -z "$container_id" ] ||
    [ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_id")" != none ]; then
    echo "OHTTP-relay container does not use the disabled log driver" >&2
    exit 1
fi
