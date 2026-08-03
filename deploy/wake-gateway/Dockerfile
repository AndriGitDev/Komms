# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

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
    cargo build --locked --release --package kult-wake \
    && install -m 0755 target/release/kult-wake /tmp/kult-wake \
    && strip --strip-unneeded /tmp/kult-wake \
    && rm -rf target

FROM ${DEBIAN_IMAGE} AS runtime

ARG KOMMS_SOURCE_REVISION=unbound-local-build

COPY --from=builder /tmp/kult-wake /usr/local/bin/kult-wake

LABEL org.opencontainers.image.title="Komms native-wake gateway" \
      org.opencontainers.image.description="Least-authority fixed-shape APNs and FCM wake gateway" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/AndriGitDev/Komms" \
      org.opencontainers.image.revision="${KOMMS_SOURCE_REVISION}"

ENV KOMMS_SOURCE_REVISION=${KOMMS_SOURCE_REVISION}

USER 10003:10003
WORKDIR /run/komms-wake

EXPOSE 8444/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["kult-wake", "probe", "--address", "127.0.0.1:8082"]

ENTRYPOINT ["kult-wake"]
CMD ["run", "--config", "/etc/komms-wake/config.toml"]
