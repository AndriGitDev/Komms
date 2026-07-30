# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.88-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
FROM ${RUST_IMAGE} AS builder

ARG KOMMS_SOURCE_REVISION=unbound-local-build
ARG SOURCE_DATE_EPOCH=0

ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    KOMMS_SOURCE_REVISION=${KOMMS_SOURCE_REVISION} \
    LC_ALL=C \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC

WORKDIR /src
COPY . .

RUN RUSTFLAGS="-C debuginfo=0 -C link-arg=-Wl,--build-id=none" \
    cargo build --locked --release --package kult-reference-service \
    && install -m 0755 target/release/kult-reference-service \
        /tmp/kult-reference-service \
    && strip --strip-unneeded /tmp/kult-reference-service \
    && rm -rf target

FROM ${DEBIAN_IMAGE} AS runtime

ARG KOMMS_SOURCE_REVISION=unbound-local-build
ARG SOURCE_DATE_EPOCH=0

COPY --from=builder /tmp/kult-reference-service /usr/local/bin/kult-reference-service

LABEL org.opencontainers.image.title="Komms reference service" \
      org.opencontainers.image.description="Operator-minimized Komms bootstrap, DHT cache, and pairwise rendezvous" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/AndriGitDev/Komms" \
      org.opencontainers.image.revision="${KOMMS_SOURCE_REVISION}"

ENV KOMMS_SOURCE_REVISION=${KOMMS_SOURCE_REVISION}

USER 10002:10002
WORKDIR /run/komms-reference

EXPOSE 4405/tcp 4405/udp 8443/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["kult-reference-service", "probe", "--address", "127.0.0.1:8081"]

ENTRYPOINT ["kult-reference-service"]
CMD ["run", "--config", "/etc/komms-reference/config.toml"]
