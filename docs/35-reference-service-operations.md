# 35: Operator-minimized reference service

The `kult-reference-service` artifact implements the narrow service boundary in
[ADR-0034](adr/0034-operator-minimized-reference-discovery.md). It exposes
exactly two possible roles:

1. libp2p bootstrap and a bounded, ordinary Kademlia cache for Komms discovery
   records; and
2. the short-lived, fixed-shape post-pairing rendezvous service from
   [ADR-0018](adr/0018-pairwise-rendezvous.md).

The original combined profile enables both. The split profile runs one
least-authority process per role: `--roles bootstrap-kad-cache` does not open
or require the TLS private key, and `--roles pairwise-rendezvous` does not open
or require the libp2p private key. A process cannot enable any third role.

It cannot be configured as a Komms endpoint, mailbox, wake gateway, account
directory, updater, analytics collector, or plaintext bridge. It has no API or
dependency for user identity private keys, contacts, messages, delivery state,
or message authority. The identity-bearing `kultd` image remains a separate
product with a different storage and trust boundary.

The service can still observe source network addresses, timing, volume, opaque
DHT locators, opaque rendezvous slots, and availability. Its operator, hosting
provider, or a compromised host can log or correlate those observations after
changing the deployment, inspect live memory, replay valid ciphertext, suppress
records, or deny service. RAM-only operation reduces retained local state; it
does not make an operator unable to observe or interfere.

## 1. Build and artifact identity

The dedicated Dockerfile pins multi-platform Rust 1.88 and Debian Bookworm
inputs by index digest. It builds only `kult-reference-service`, embeds the
complete source revision, removes the ELF build id, and adds no endpoint
daemon or persistent data directory to the pinned Debian slim runtime. Its
entrypoint invokes the dedicated binary directly; no shell, package manager,
or wrapper participates in service startup.

Build a Linux binary evidence bundle from a clean, exactly checked-out
revision:

```sh
deploy/reference-service/build-artifact.sh "$(git rev-parse HEAD)"
```

The output contains the binary, SHA-256 manifest, normalized source date,
target triple, compiler version, and a normalized tar archive. A second
controlled environment must run the same command before any reproducibility
claim is made.

The container workflow builds `linux/amd64` and `linux/arm64`, records the
source revision, and attaches BuildKit provenance and an SBOM to a published
OCI index. Publication is maintainer-only. Record the immutable result as:

```text
ghcr.io/andrigitdev/komms-reference-service@sha256:<index-digest>
```

Do not deploy a moving Alpha tag. Verify the revision label, index digest, SBOM,
and provenance before promotion.

## 2. Runtime service credentials

Create a dedicated owner-only key directory. The production container uses
numeric uid/gid `10002`; a local non-root test can override those values
without adding capabilities.

```sh
install -d -m 0700 -o 10002 -g 10002 /etc/komms-reference/keys
kult-reference-service generate-libp2p-identity \
  --output /etc/komms-reference/keys/libp2p.key
```

Obtain a TLS certificate without placing a logging proxy, CDN, or WAF in front
of the rendezvous listener. A DNS-01 ACME flow can issue the certificate
without terminating public HTTP elsewhere. Store the certificate as `tls.crt`
and its PKCS#8 private key as `tls.key`; the private key and libp2p identity
must be regular non-symlink files with no group or world access. The
certificate may be public.

```sh
chown 10002:10002 /etc/komms-reference/keys/libp2p.key \
  /etc/komms-reference/keys/tls.key \
  /etc/komms-reference/keys/tls.crt
chmod 0600 /etc/komms-reference/keys/libp2p.key \
  /etc/komms-reference/keys/tls.key
chmod 0644 /etc/komms-reference/keys/tls.crt
kult-reference-service inspect \
  --config /etc/komms-reference/config.toml
```

The inspection output is non-secret:

- the libp2p PeerId and SHA-256 public-key fingerprint;
- the TLS leaf-certificate SHA-256 fingerprint; and
- the 32-byte ADR-0018 provider static key, encoded as hex. In this profile it
  is the TLS leaf-certificate digest, so a certificate change is an
  authenticated provider-key change.

The libp2p private key and TLS private key are distinct service credentials.
The published ADR-0018 provider key is deliberately the TLS leaf-certificate
digest rather than a third private key. None may be reused as a Komms
account/recovery key, provider-directory signing key, or software-release key.
No production credential belongs in the repository, container image, build
log, issue, or support transcript.

## 3. Host preflight

The host boundary matters. Before starting the container:

1. dedicate a small host or VM to the selected role set; distinct operators
   should use distinct hosts and administrative domains;
2. disable swap and verify `swapon --show` is empty;
3. disable hibernation and suspend targets;
4. set `kernel.core_pattern`/systemd-coredump policy so no core body is
   retained, and verify the service unit has `LimitCORE=0`;
5. disable provider snapshots, crash-memory capture, filesystem backups, and
   backup discovery for this host;
6. do not install an access-logging reverse proxy, CDN software, WAF, packet
   capture, application profiler, or distributed tracing collector;
7. restrict administrative access and record the hosting provider and
   administrative domain; and
8. open only `4405/tcp`, `4405/udp`, and `8443/tcp`. Port `8081` stays inside
   the container network and binds loopback in the process.

The committed Compose profile then adds a read-only root filesystem, numeric
unprivileged user, all-capability drop, `no-new-privileges`, 128-process limit,
512 MiB memory and equal memory-plus-swap limit, zero core ulimit, bounded file
descriptors and CPU, disabled container logs, read-only key/config mounts, and
small `noexec,nosuid,nodev` tmpfs mounts. It declares no persistent volume.
Routing tables, DHT rows, rate buckets, and rendezvous rows exist only in
process memory and disappear on restart.

## 4. Configure and start

Copy the example config and Compose file, then edit only documented values.
The combined profile retains the ADR-0034 two-role deployment:

```sh
install -d -m 0755 /opt/komms-reference
install -m 0644 deploy/reference-service/reference-service.toml \
  /opt/komms-reference/reference-service.toml
install -m 0644 deploy/reference-service/compose.yaml \
  /opt/komms-reference/compose.yaml
export REFERENCE_SERVICE_KEYS_DIR=/etc/komms-reference/keys
export REFERENCE_SERVICE_IMAGE=ghcr.io/andrigitdev/komms-reference-service@sha256:<digest>
docker compose -f /opt/komms-reference/compose.yaml config --quiet
docker compose -f /opt/komms-reference/compose.yaml up -d --wait
```

For independent process authority, use
[`compose-split.yaml`](../deploy/reference-service/compose-split.yaml). Give
the bootstrap container a key directory containing only `libp2p.key`, and give
the rendezvous container a different key directory containing only `tls.crt`
and `tls.key`:

```sh
export REFERENCE_DHT_CONFIG=/opt/komms-reference/reference-service.toml
export REFERENCE_DHT_KEYS_DIR=/etc/komms-reference/dht-keys
export REFERENCE_RENDEZVOUS_CONFIG=/opt/komms-reference/reference-service.toml
export REFERENCE_RENDEZVOUS_KEYS_DIR=/etc/komms-reference/rendezvous-keys
docker compose -f /opt/komms-reference/compose-split.yaml config --quiet
docker compose -f /opt/komms-reference/compose-split.yaml up -d --wait
```

The strict configuration retains bounds for both possible roles, but a
one-role command ignores the other listener and does not inspect or require
the other credential. Keep the unused file absent from that container rather
than mounting extra authority.

The default bounds are:

| Axis | Bound |
|---|---:|
| DHT namespaces | `/kk/prekeys/1/` compatibility and `/kk/prekeys/2/` |
| DHT v2 value | exactly 1,179,648 bytes |
| DHT rows / combined values | 128 / 160 MiB |
| DHT local TTL | 48 hours |
| DHT established connections / one peer | 64 / 2 |
| DHT inbound connections | 4,096/minute global; 120/minute per exact address |
| Rendezvous opaque rows | 16,384 |
| Rendezvous accounted mutable state | 96 MiB |
| Rendezvous row TTL | at most 2 hours, enforced by ADR-0018 |
| TLS / decoded request concurrency | 256 / 256 |
| Rendezvous connections | 120,000/minute global; 600/minute per exact address |
| One opaque slot | 24 operations/minute |
| Process memory / process count | 512 MiB / 128 |

The DHT rejects unrelated key namespaces, malformed key widths, variable-width
v2 values, provider records, row-count overflow, and combined-value overflow.
The HTTPS listener permits TLS 1.3 and one canonical HTTP/1.1 request per
connection. It rejects chunking, compression, cookies, credentials,
request identifiers, extra headers, variable bodies, overlong/slow requests,
and any pipelined bytes already received with the request. It never processes
a second request on the connection. Valid misses and overloads retain the
normative fixed shape.

## 5. Health, overload, restart, and blackhole checks

The only health response is loopback-only aggregate JSON. It reports the exact
enabled role name or names, source revision, DHT row/value totals, and
rendezvous row/accounting totals. Disabled-role totals are zero. It contains
no peer id, client address, capability, locator, slot,
ciphertext, identity, or social label.

```sh
docker compose -f /opt/komms-reference/compose.yaml exec -T reference-service \
  kult-reference-service probe --address 127.0.0.1:8081
```

Run the committed smoke test against every candidate image. It validates the
Compose profile, starts with separate temporary credentials, checks aggregate
health, restarts, checks health again, and verifies the disabled log driver:

```sh
REFERENCE_SERVICE_IMAGE=<immutable-image> \
  deploy/reference-service/smoke-test.sh
```

The smoke test also starts the split profile with mutually exclusive key
mounts and verifies each process can inspect only its selected credential.
The Rust matrix additionally covers exact HTTP/TLS shapes, malformed requests,
memory/row/rate/concurrency overload, expiry, state loss on restart, and a
blackholed bootstrap peer. Blackholing an optional upstream must not prevent
the service from listening; it only reduces the DHT paths currently known.
Abrupt container termination discards RAM state but cannot promise allocator,
kernel-buffer, hypervisor, or live-memory erasure.

## 6. Rotation, revocation, and compromise

Treat each runtime credential as a separate incident domain:

- **libp2p identity:** create a new service-only key and new PeerId. Publish
  both old and new bootstrap addresses during a bounded overlap. Remove the old
  address from the signed provider directory, then destroy the old key.
- **TLS/provider key:** obtain a new key and certificate on a parallel origin
  or port. Publish its new provider static key through the signed directory and
  authenticated paired-contact controls before traffic moves. Keep the old
  origin only for the declared overlap, then revoke and remove it.
- **Directory or release key:** follow their offline incident procedures.
  Never solve compromise by copying either key onto this host.

On suspected runtime-key or host compromise, remove the service from defaults,
publish an incident with start/end estimates and residual metadata risk,
rotate the affected service key, rebuild from a reviewed revision and pinned
image digest, and preserve no memory dump or request capture. A compromised
operator can impersonate or suppress the service and observe metadata, but the
service key cannot forge a client-accepted account/device record or decrypt
message content.

## 7. Self-hosting and replacement

Any operator can build the same image, choose independent service keys and
domain, and publish its PeerId, bootstrap multiaddresses, HTTPS origin,
provider static key, limits, revision, and image digest. Clients must be able
to remove the project default, add this operator, retain a last-valid signed
directory, or use QR/file/LAN/mesh/sneakernet without either service.

An operator leaving service publishes an end date, stops accepting new
defaults, provides the replacement record if one exists, waits the advertised
DHT/rendezvous TTL overlap, and then destroys runtime keys. It does not retain
DHT or rendezvous state as a backup.

## 8. Deployment status and remaining action

No reference service was deployed while preparing these artifacts. No Hetzner
target or production credential was authorized, and no default provider record
was changed. The one remaining deployment action is: after an exact host,
administrative domain, immutable image digest, service-key fingerprints, and
rollback digest are shown and explicitly authorized, apply this validated
Compose profile to that named host and publish the completed
[operator record](reference-service-operator.md).

Rollback is to remove the candidate provider record, restore the previously
approved immutable image/config digest, and restart with the preserved
service-only credentials. All mutable discovery/rendezvous state is expected
to be empty after either restart; clients republish and retry within their
bounded schedules.
