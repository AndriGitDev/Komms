# 26: Self-hosting `kultd`

Komms 0.3 Alpha publishes a Linux container for `kultd`, the runnable headless
service built around the `kult-node` library. It is intended for people who want
their own always-on peer, volunteer mailbox, relay-aware node, or
internet-to-Meshtastic bridge. It is not a central Komms server and other users
do not need it in order to communicate.

The [public Alpha package](https://github.com/AndriGitDev/Komms/pkgs/container/komms-kultd)
supports `linux/amd64` and `linux/arm64`. Pull the immutable release tag with:

```sh
docker pull ghcr.io/andrigitdev/komms-kultd:0.3.0
```

> **Artifact boundary:** the historical `0.3.0` image shown below predates
> mailbox v2 and must not be used to claim durable custody. Builds from a source
> revision that includes accepted ADR-0032 use persistent leased
> `/komms/mailbox/2`; verify the image revision and reported mailbox schema
> rather than relying on an Alpha tag. No current public operator has been
> qualified as stable infrastructure.

The `0.3-alpha` and `alpha` tags are moving Alpha aliases; the committed Compose
file tracks `0.3-alpha`, while automation should pin `0.3.0` or an image digest.
The image runs the daemon as numeric user/group `10001`, stores its sealed
database in `/var/lib/komms`, and listens on TCP and QUIC/UDP port `4404` by
default. There is intentionally no `latest` tag during the Alpha series.

## Start with Docker Compose

The committed [`compose.yaml`](../compose.yaml) uses named volumes for both the
encrypted node data and an owner-only passphrase file. Initialize the secret
interactively, then start the node:

```sh
docker compose run --rm --no-deps --entrypoint kultd-init-passphrase kultd
docker compose up -d
docker compose ps
docker compose logs -f kultd
```

The first command writes the passphrase directly into the private secrets
volume; it does not put the value in the Compose file, shell history, or
container environment. Back up the passphrase separately. Losing it makes the
encrypted node database unusable. Anyone who obtains both it and the data
volume can decrypt the node, so do not back them up together.

The image health check calls the local Unix-socket RPC. Inspect the node or
export its pairing bundle with:

```sh
docker compose exec kultd kult status
docker compose exec kultd kult bundle
```

Stop with `docker compose down`. The named volumes remain. Adding `--volumes`
deletes the node database and passphrase and is therefore destructive.

## Network and operating modes

Open and forward both `4404/tcp` and `4404/udp` on the host and firewall. The
TCP listener provides the Noise/Yamux fallback; UDP carries the primary QUIC
transport. AutoNAT, relay reservations, and hole punching still apply, so a
port-forward is helpful but not a claim that every NAT permits inbound traffic.
The default disables mDNS because a bridged container does not represent the
host LAN. Komms operates no mandatory bootstrap service: add trusted bootstrap
or relay addresses, or distribute explicit reachable peer hints, when the node
must discover peers beyond its container network.

The current daemon shares the same operating-mode contract as every client:

```text
--mode standard|private|sovereign
--confirm-standard-provider-disclosure
--sovereign-publish-direct-routes
--provider-directory FILE
--provider-directory-root 64_LOWERCASE_HEX
--rendezvous ORIGIN,LEAF_SHA256,standard|private|both
--tor-proxy 127.0.0.1:9050
```

A signed provider directory is optional. It augments manual configuration and
never replaces it. A configured but unavailable candidate retains the bounded
last-valid generation visibly; rollback or fork candidates cannot replace that
authenticated chain. Corrupt retained state, or expiry beyond the bounded
grace, disables directory defaults. Removing `--provider-directory` is an
explicit opt-out even if a verified cache remains on disk. A configured
directory requires at least one trusted offline root. Standard directory
defaults require the disclosure acknowledgement; Private rendezvous requires
a numeric loopback Tor SOCKS5 endpoint and never falls back to direct access.

No production directory, root key, or qualified default provider ships in the
repository. For a pure-core service, omit the directory and rendezvous options
and use explicit bootstrap/mailbox/relay routes as needed. See
[Operating modes and provider configuration](36-operating-modes-and-provider-directory.md)
for the complete bounds, status vocabulary, and local journey gate.

This `kultd` profile is **not** the RAM-only reference discovery/rendezvous
service. It is a full identity-bearing Komms endpoint with a persistent
encrypted database and passphrase. Mounting its data directory on tmpfs would
rotate or destroy endpoint state and would not establish the least-authority
claim in [ADR-0034](adr/0034-operator-minimized-reference-discovery.md).

The separate `kult-reference-service` daemon and image cannot enable endpoint,
mailbox, native-wake, directory, update, analytics, or plaintext-bridge roles.
Its DHT cache and pairwise rendezvous state are bounded and memory-only. See
the [reference-service runbook](35-reference-service-operations.md) and
[current operator record](reference-service-operator.md). No project reference
service is deployed at the time of that record.

The separate `kult-wake` image is also not an endpoint or part of
`kult-reference-service`. It has one capability-gated APNs/FCM wake role,
dedicated TLS/capability/native-provider credentials, and bounded durable
replay/revocation state. Official-app APNs/FCM credentials are not shared with
self-hosters; a custom app uses its own topics and credentials. See the
[native-wake runbook](37-native-wake-operations.md) and
[current wake operator record](wake-gateway-operator.md). No project wake
gateway is deployed at the time of that record.

To add daemon flags, replace the Compose service's command while retaining both
listen addresses. For example, a volunteer mailbox with an explicit bootstrap
peer can use:

```yaml
services:
  kultd:
    command:
      - --listen
      - /ip4/0.0.0.0/udp/4404/quic-v1
      - --listen
      - /ip4/0.0.0.0/tcp/4404
      - --bootstrap
      - /dns4/example.net/tcp/4404/p2p/PEER_ID
      - --serve-mailbox
      - --no-mdns
```

`--serve-mailbox` creates three owner-only files beside `node.db`:
`mailbox-v2.db`, `mailbox-v2.key`, and
`mailbox-v2.transport.key`. They form a separate service role. The row/index
key protects the relay database, while the transport key keeps the published
libp2p mailbox address stable across restart. Neither is a user account,
directory, recovery, or release key, and neither enters a Komms `KKR10` user
backup. Startup rejects final-component symlinks for these service files and
keeps the database, WAL/shared-memory sidecars, and keys owner-only.

For a network-attached Meshtastic radio, append `--meshtastic-tcp HOST:4403`.
For USB serial, pass the device through to the container and append
`--meshtastic-serial /dev/ttyACM0`; device names and host permissions vary by
OS. Bridging sealed third-party traffic is enabled when a radio is configured
unless `--no-bridge` is supplied. Review the airtime and bridge limits in the
[transport specification](05-transports.md) before volunteering bandwidth.

Run `docker compose run --rm kultd --help` for every daemon option. Do not place
the passphrase in `KULTD_PASSPHRASE` for long-lived deployments: environment
variables can be exposed by process and container inspection tools. A direct
`docker run` deployment should instead mount an owner-only file at
`/run/komms-secrets/passphrase` and persistent storage at `/var/lib/komms`.

## Mailbox v2 custody and limits

The current source profile returns deposit acceptance only after a durable
SQLite commit with full synchronization. Check-in creates a 120-second
idempotent lease. A recipient commits each complete envelope to its bounded
sealed pending domain before acknowledging the exact lease and row ids; the
relay then deletes only those ids transactionally. Response loss, duplicate
pages, duplicate acknowledgements, receiver refusal, or a process stop does not
delete unacknowledged rows. The sender retains its original ciphertext until an
authenticated end-to-end receipt or the terminal retry deadline.

Bridge transit is deliberately weaker. An unregistered deposit may be copied
into the bounded in-memory mesh queue, but the service returns refusal and the
sender retains custody. Do not count best-effort bridge forwarding as a
mailbox deposit, sent state, or durable capacity.

Default limits are:

| Axis | Default |
|---|---:|
| Envelope retention | 30 days maximum, shortened by an authenticated earlier retention bucket |
| Registration without refresh | 60 days |
| Lease lifetime | 120 seconds |
| One lease page | 128 rows and 1 MiB ciphertext |
| One check-in | 4,096 token filters |
| Registrations | 65,536 total; 4,096 per transport client |
| One token | 256 rows; 16 MiB |
| One depositing transport client | 4,096 rows; 32 MiB |
| Whole relay | 65,536 rows; 64 MiB ciphertext |
| Live leases | 4,096 relay-wide; 4 per client; 2 covering one token |
| Request budget | 2,048 per client and 8,192 relay-wide per fixed minute |
| Protocol concurrency | 8 mailbox streams; 128 total pending outbound operations |

Request/response codecs, command queues, endpoint collection inboxes, local
pending rows, and lifecycle work have independent bounds. One lifecycle
interval requests one page from at most eight selected mailboxes, rotates
larger mailbox/token sets, and applies jittered backoff capped at one hour. A
hostile relay cannot force a loop-until-empty.

“Per client” means the pseudonymous libp2p transport peer observed by this
operator, not a Komms account or a Sybil-resistant identity. A caller can
rotate it; relay-wide item/byte/lease/request and connection bounds remain the
hard containment boundary.

`kult status` reports only aggregate mailbox fields: stored/capacity
items and bytes, configured retention and request budgets, current filesystem
reserve, registration and live-lease counts, oldest lease age,
rejection/expiry counters, and schema version. Mailbox logs contain only an
aggregate collected row count or a context-free failure; they omit tokens,
locators, ciphertext, row/lease ids, peer identities, and social labels.

Destructive `/komms/mailbox/1` compatibility is disabled by default and the
packaged daemon has no flag to enable it. A custom embedding that explicitly
sets `allow_v1_compat` accepts the known delete-before-response risk; clients
do not fall back automatically, and v1 never satisfies durable-custody
evidence.

## Capacity and cost model

The 64 MiB limit counts encoded ciphertext, not SQLite indexes, seals, WAL,
filesystem metadata, container layers, logs, or backup copies. Reserve at
least 256 MiB of persistent writable space for the default mailbox role and
monitor the reported filesystem reserve. The service rejects work rather than
claim custody when any item, byte, rate, registration, lease, codec, stream, or
disk write bound is reached.

Memory is bounded principally by active protocol pages and connections; the
database remains the durable queue. CPU cost scales with accepted requests,
AEAD verification/sealing, keyed-index work, and synchronous SQLite commits.
Network cost is ingress plus repeated leased egress until acknowledgement;
multi-operator deposits intentionally multiply both durability and cost.

Before volunteering, record the operator-specific monthly figures rather than
publishing a guessed universal price:

| Cost input | Record |
|---|---|
| Compute | Instance/host price and reserved CPU/RAM |
| Persistent storage | Allocated GiB, snapshot GiB, and IOPS charges |
| Network | Included transfer, metered ingress/egress, and overage |
| Operations | Monitoring, incident response, upgrades, abuse handling, and on-call time |

P0-08 remains open until a revision-bound deployment records observed
utilization, overload behavior, backup/restore, upgrade/rollback, incidents,
and multi-operator behavior.

## Backup, restore, upgrade, and rollback

Mailbox custody and endpoint recovery are different promises. A `KKR10` export
backs up eligible user history and authority state only. It intentionally
excludes the mailbox database, both mailbox service keys, live delivery
tokens, deposits, leases, queues, and resumable custody.

For an operator custody backup:

1. Stop `kultd` cleanly and confirm the process has closed the SQLite files.
2. Copy `mailbox-v2.db`, `mailbox-v2.key`, and
   `mailbox-v2.transport.key` as one encrypted snapshot. If `-wal` or `-shm`
   files remain, include them rather than copying only the main database.
3. Keep that snapshot separate from endpoint passphrases and user backups.
   Restrict it as relay-visible metadata and ciphertext, not harmless cache.
4. Restore the complete set into an owner-only directory before startup.
   Confirm schema 2, the expected libp2p peer id, aggregate row/byte counts,
   and a lease/ack smoke test.

Restoring only a database or only one key fails closed. Generating a new
transport key changes the mailbox address and requires clients to learn the
replacement; generating a new row key makes old rows unreadable. Starting with
an empty directory is a new service and must not be described as preserving
old custody.

For an upgrade, pin the old and new source revisions/image digests, stop the
service, take the complete snapshot, start the new build, and verify the schema
and smoke test before reopening traffic. An unknown schema is refused. If the
new build fails before a schema migration, stop it and restore the old
revision with the exact snapshot. No rolling downgrade or hot-copy guarantee
is made.

## Incidents and service replacement

- **Disk full or overload:** acceptance is false; do not report the envelope
  as sent. Restore reserve or capacity, verify integrity and metrics, then
  resume. Unacknowledged leased rows remain relay work.
- **Database corruption or lost row key:** isolate the service, retain the
  failed files for investigation, restore the last complete snapshot if its
  custody window is acceptable, and disclose the possible row-loss interval.
  Otherwise publish a replacement address and state that old relay custody was
  lost.
- **Transport-key compromise:** withdraw the old mailbox address, generate a
  new dedicated service identity, distribute the replacement through
  authenticated configuration, and treat the old address as attacker
  controlled. Do not reuse directory or release keys.
- **Database plus row-key disclosure:** assume tokens, timing relationships,
  and stored end-to-end ciphertext were exposed. The ciphertext is not message
  plaintext, but that does not erase the metadata incident. Rotate to a new
  service set, preserve sender retry semantics, notify affected users through
  the published incident channel, and record scope and dates.
- **Operator seizure or hostile control:** an operator can inspect live
  memory, correlate network activity, suppress, delay, replay, or destroy
  work. Multi-operator redundancy and sender retention improve recovery; they
  do not make an operator unable to observe or interfere.

## Alpha limits and upgrades

The container is built from the same tagged AGPL source as the application
artifacts and carries OCI provenance and an SBOM. It is still Alpha software:
back up before upgrading, pin a versioned tag for automation, and verify the
image digest shown by GHCR. Multi-host orchestration, remote administration,
automatic backups, and a stable migration/support promise are not provided.
The RPC socket is deliberately local to the container and must not be exposed
over TCP.
