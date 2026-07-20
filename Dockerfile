# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libudev-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --release --package kultd \
    && install -m 0755 target/release/kultd /tmp/kultd \
    && install -m 0755 target/release/kult /tmp/kult

FROM debian:bookworm-slim AS runtime

ARG KOMMS_UID=10001
ARG KOMMS_GID=10001

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libudev1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "$KOMMS_GID" komms \
    && useradd --uid "$KOMMS_UID" --gid "$KOMMS_GID" \
        --home-dir /var/lib/komms --no-create-home --shell /usr/sbin/nologin komms \
    && install -d -m 0700 -o komms -g komms \
        /var/lib/komms /run/komms-secrets

COPY --from=builder /tmp/kultd /usr/local/bin/kultd
COPY --from=builder /tmp/kult /usr/local/bin/kult
COPY --chmod=0755 deploy/kultd-init-passphrase.sh /usr/local/bin/kultd-init-passphrase

LABEL org.opencontainers.image.title="Komms kultd" \
      org.opencontainers.image.description="Self-hosted Komms headless node" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/AndriGitDev/Komms"

ENV KULTD_PASSPHRASE_FILE=/run/komms-secrets/passphrase \
    KULTD_SOCKET=/var/lib/komms/kultd.sock \
    RUST_LOG=info

USER komms:komms
WORKDIR /var/lib/komms

EXPOSE 4404/tcp 4404/udp
VOLUME ["/var/lib/komms", "/run/komms-secrets"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["kult", "status"]

ENTRYPOINT ["kultd", "--data-dir", "/var/lib/komms"]
CMD ["--listen", "/ip4/0.0.0.0/udp/4404/quic-v1", "--listen", "/ip4/0.0.0.0/tcp/4404", "--no-mdns"]
