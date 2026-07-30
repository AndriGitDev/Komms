#!/bin/sh
set -eu

compose_file=${COMPOSE_FILE:-deploy/reference-service/compose.yaml}
image=${REFERENCE_SERVICE_IMAGE:-ghcr.io/andrigitdev/komms-reference-service:reference-service-ci}
temp_root=${REFERENCE_SERVICE_TEMP_ROOT:-${TMPDIR:-/tmp}}
keys_dir=$(mktemp -d "$temp_root/komms-reference-smoke.XXXXXX")

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
    REFERENCE_SERVICE_KEYS_DIR="$keys_dir" \
    REFERENCE_SERVICE_IMAGE="$image" \
    compose -f "$compose_file" down --timeout 15 >/dev/null 2>&1 || true
    rm -rf "$keys_dir"
}
trap cleanup EXIT INT TERM

export REFERENCE_SERVICE_UID="${REFERENCE_SERVICE_UID:-$(id -u)}"
export REFERENCE_SERVICE_GID="${REFERENCE_SERVICE_GID:-$(id -g)}"
export REFERENCE_SERVICE_KEYS_DIR="$keys_dir"
export REFERENCE_SERVICE_IMAGE="$image"
export KOMMS_SOURCE_REVISION="${KOMMS_SOURCE_REVISION:-$(git rev-parse HEAD)}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

docker run --rm \
    --user "$REFERENCE_SERVICE_UID:$REFERENCE_SERVICE_GID" \
    --mount "type=bind,source=$keys_dir,target=/keys" \
    "$image" generate-libp2p-identity --output /keys/libp2p.key
openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:P-256 \
    -nodes \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$keys_dir/tls.key" \
    -out "$keys_dir/tls.crt" \
    -days 1 >/dev/null 2>&1
chmod 600 "$keys_dir/libp2p.key" "$keys_dir/tls.key"
chmod 644 "$keys_dir/tls.crt"

compose -f "$compose_file" config --quiet
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T reference-service \
    kult-reference-service probe --address 127.0.0.1:8081
compose -f "$compose_file" restart --timeout 15 reference-service
compose -f "$compose_file" up -d --wait --wait-timeout 90
compose -f "$compose_file" exec -T reference-service \
    kult-reference-service probe --address 127.0.0.1:8081

container_id=$(compose -f "$compose_file" ps -q reference-service)
if [ -z "$container_id" ] ||
    [ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container_id")" != none ]; then
    echo "reference-service container does not use the disabled log driver" >&2
    exit 1
fi
