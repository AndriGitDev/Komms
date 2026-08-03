# 50: Dedicated Mailbox-v2 Service Operations

`kult-mailbox` is the least-authority operator artifact for durable
`/komms/mailbox/2` custody. Its libp2p behavior tree negotiates only that
protocol. It has no account, endpoint-envelope, Kademlia, identify, relay,
call, rendezvous, wake, directory, update, analytics, plaintext-bridge, or
mailbox-v1 role.

The service sees source network addresses and transport pseudonyms while
connections are live, opaque rotating delivery-token indexes in its sealed
store, timing, padded ciphertext size, expiry, quota outcomes, and
availability. A host administrator can inspect memory, alter the service,
record future traffic, correlate network observations, suppress deposits, or
destroy custody. The service design minimizes authority; it does not make the
operator unable to observe or interfere.

No public or project mailbox described here is deployed or qualified as of
2026-07-31.

## 1. Artifact and protocol boundary

The dedicated crate and image are:

- [`crates/kult-mailbox`](../crates/kult-mailbox);
- [`deploy/mailbox-service/Dockerfile`](../deploy/mailbox-service/Dockerfile);
- [`deploy/mailbox-service/compose.yaml`](../deploy/mailbox-service/compose.yaml);
  and
- the strict example
  [`mailbox-service.toml`](../deploy/mailbox-service/mailbox-service.toml).

The process owns three service-only files:

| File | Purpose | Backup rule |
|---|---|---|
| `mailbox-v2.db` | row-bound encrypted SQLite custody, registrations, leases, quotas, expiry | capture only with the matching row key and transport identity |
| `mailbox-v2.key` | derives opaque indexes and row-sealing keys | never reuse as any user, recovery, release, directory, TLS, wake, or rendezvous key |
| `mailbox-v2.transport.key` | stable Ed25519 libp2p service identity | rotate only with an explicit mailbox-address migration |

The row key and transport identity are mounted read-only during normal service.
The database has the only writable persistent mount. The image contains only
`kult-mailbox`, runs unprivileged with a read-only root, drops all capabilities,
disables swap and core dumps in the committed Compose profile, disables the
container log driver, and exposes QUIC/TCP port 4406. The aggregate health
listener stays on loopback. QUIC TLS and TCP Noise terminate in process; do not
put a request-logging proxy, CDN, WAF, or TLS terminator in front of it.

## 2. Initialize and inspect

Copy the example configuration and replace host paths only through the bind
mounts. Every capacity and lifetime is explicit; unknown fields, relative
secret/state paths, path reuse, non-loopback health, v1 compatibility, and
values outside compiled bounds fail closed.

Create owner-only directories, then initialize exactly once:

```sh
install -d -m 0700 /srv/komms-mailbox/keys /srv/komms-mailbox/state

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount type=bind,source=/etc/komms-mailbox/config.toml,target=/etc/komms-mailbox/config.toml,readonly \
  --mount type=bind,source=/srv/komms-mailbox/keys,target=/run/komms-mailbox-keys \
  --mount type=bind,source=/srv/komms-mailbox/state,target=/var/lib/komms-mailbox \
  IMAGE_DIGEST \
  initialize --config /etc/komms-mailbox/config.toml
```

Initialization refuses any existing target. Record the printed peer id without
recording secret files. If initialization is interrupted, inspect the three
targets and remove the incomplete, never-published set deliberately before
trying again.

Validate configuration without opening state:

```sh
kult-mailbox check --config /etc/komms-mailbox/config.toml
```

Inspect the existing peer id and physical schema without opening network
listeners:

```sh
kult-mailbox inspect --config /etc/komms-mailbox/config.toml
```

Do not start if the peer id differs from the published operator record. A
missing key is not permission to generate a replacement during normal startup.

## 3. Run and monitor

Pin `MAILBOX_SERVICE_IMAGE` to an immutable digest and set the three host bind
paths:

```sh
MAILBOX_SERVICE_IMAGE=registry.example/komms-mailbox@sha256:... \
MAILBOX_SERVICE_CONFIG=/etc/komms-mailbox/config.toml \
MAILBOX_SERVICE_KEYS_DIR=/srv/komms-mailbox/keys \
MAILBOX_SERVICE_STATE_DIR=/srv/komms-mailbox/state \
docker compose -f deploy/mailbox-service/compose.yaml up -d
```

The health endpoint publishes content-free aggregate counts and configured
capacities: schema, stored items/bytes, registrations, live leases,
refusals, expiry work, available database-filesystem bytes, and source
revision. It never includes tokens, locators, row ids, ciphertext, transport
peer ids, IP addresses, identities, contact labels, or request timelines.

```sh
docker compose -f deploy/mailbox-service/compose.yaml exec -T mailbox \
  kult-mailbox probe --address 127.0.0.1:8083
```

Monitor aggregate saturation, disk reserve, refusal rate, expiry progress,
restart count, and image/config revision. Keep access logs and per-client
traces disabled. Network-level volumetric controls may use short-lived source
buckets but must not become a retained identity or social-graph database.

The committed default stores at most 65,536 rows or 64 MiB of ciphertext,
retains envelopes for at most 30 days, registrations for 60 days, and leases
for 120 seconds. Per-token, per-client, global, byte, request, and live-lease
bounds apply independently. Provision at least 1 GiB persistent storage until
measured database, index, WAL, and reserve behavior justifies another bound.
Record CPU, RAM, disk, network, requests, refusals, expiry, incidents, human
time, and actual expense under the operator program; do not infer a user count
from rotating transport clients.

## 4. Backup, restore, and custody

A backup is operator custody, not a Komms user backup. It can contain live
opaque delivery tokens, ciphertext, expiry, and pseudonymous client indexes.
Encrypt it under a dedicated operator backup authority, limit access, declare
its retention, and never include it in endpoint recovery packages.

For a consistent snapshot:

1. stop accepting traffic and stop the service cleanly;
2. verify no process has the database open;
3. capture `mailbox-v2.db`, any SQLite sidecars that remain, the exact row key,
   the exact transport identity, configuration, source revision, and image
   digest as one encrypted set;
4. verify recovery on an isolated host without opening public listeners; and
5. restart or retire the original service deliberately.

Restore only a matched set. Restoring a database without its row key loses
custody; restoring a different key fails authentication. Restoring an older
database can re-offer already acknowledged ciphertext and roll back
registrations, leases, quotas, or expiry. Endpoints deduplicate end to end, but
an operator must disclose the rollback window and must not describe it as
lossless continuity.

## 5. Upgrade and rollback

Before an upgrade, retain the old image digest, config digest, peer id,
aggregate snapshot, and tested encrypted state snapshot. Exercise:

```sh
cargo test -p kult-mailbox
cargo test -p kult-transport --test mailbox_service
actionlint .github/workflows/mailbox-service-container*.yml
deploy/mailbox-service/smoke-test.sh
```

The second command requires permission to bind localhost QUIC/TCP sockets.
The container smoke initializes state, starts the hardened image, probes
aggregate health, restarts it, and verifies the service peer id survives.

Stop old ingress, upgrade one exact snapshot, confirm schema/peer id/health,
then reopen traffic. Roll back only the whole matched snapshot and image. Do
not independently roll back the database, row key, transport identity, or
configuration. Keep sender custody semantics honest during maintenance:
service unavailability is not accepted, sent, or delivered state.

## 6. Abuse, compromise, and end of life

On overload, refuse new deposits or leases before exceeding a bound and
preserve unrelated committed rows. Never delete unrelated rows to make room.
Do not add content parsing or identity fields for abuse handling.

For row-key or database compromise:

1. stop new custody;
2. preserve bounded aggregate and revision evidence;
3. identify the affected backup/host/time window;
4. disclose possible ciphertext, token-index, timing, and availability
   exposure without claiming plaintext compromise or non-observability;
5. publish a replacement mailbox address through authenticated contact/provider
   control;
6. let senders retain and retry ciphertext; and
7. retire the compromised matched state/key set after the declared window.

For transport-identity compromise, publish a new peer id and authenticated
address migration; do not silently reuse the old address claim. Never reuse a
directory or release key to repair a mailbox.

End of life removes the service from defaults before stopping new
registrations, keeps an announced drain window at least as long as applicable
retention, preserves sender retry/fallback, discloses rows that may remain,
exports or destroys custody according to the published policy, and destroys
retired service keys after the window.

## 7. Publication and qualification

The reusable container workflow publishes only when its caller explicitly sets
`push: true`; normal pull-request CI builds and exercises without publishing.
Published images require an immutable source revision, multi-architecture
digest, provenance, SBOM, and source offer for the deployed AGPL-covered
version.

Local tests and an image are not operator qualification. A real operator record
still needs a named administrative domain, immutable digest, service-key
fingerprint, observed capacity/cost/retention, source offer, backup/restore,
overload, upgrade/rollback, incident, and independent conformance evidence.
