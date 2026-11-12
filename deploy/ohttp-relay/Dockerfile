# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_IMAGE=rust:1.89-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff
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
    cargo build --locked --release --package kult-ohttp-relay \
    && install -m 0755 target/release/kult-ohttp-relay /tmp/kult-ohttp-relay \
    && strip --strip-unneeded /tmp/kult-ohttp-relay \
    && rm -rf target

FROM ${DEBIAN_IMAGE} AS runtime

ARG KOMMS_SOURCE_REVISION=unbound-local-build

COPY --from=builder /tmp/kult-ohttp-relay /usr/local/bin/kult-ohttp-relay

LABEL org.opencontainers.image.title="Komms OHTTP relay" \
      org.opencontainers.image.description="Least-authority fixed-mapping RFC 9458 Oblivious HTTP relay" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/AndriGitDev/Komms" \
      org.opencontainers.image.revision="${KOMMS_SOURCE_REVISION}"

ENV KOMMS_SOURCE_REVISION=${KOMMS_SOURCE_REVISION}

USER 10004:10004
WORKDIR /run/komms-ohttp

EXPOSE 8445/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["kult-ohttp-relay", "probe", "--address", "127.0.0.1:8083"]

ENTRYPOINT ["kult-ohttp-relay"]
CMD ["run", "--config", "/etc/komms-ohttp/config.toml"]
