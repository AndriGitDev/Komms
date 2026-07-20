# 26: Self-hosting `kultd`

Komms 0.1 Alpha publishes a Linux container for `kultd`, the runnable headless
service built around the `kult-node` library. It is intended for people who want
their own always-on peer, volunteer mailbox, relay-aware node, or
internet-to-Meshtastic bridge. It is not a central Komms server and other users
do not need it in order to communicate.

The [public Alpha package](https://github.com/AndriGitDev/Komms/pkgs/container/komms-kultd)
supports `linux/amd64` and `linux/arm64`. Pull the immutable release tag with:

```sh
docker pull ghcr.io/andrigitdev/komms-kultd:0.1.0
```

The `0.1-alpha` and `alpha` tags are moving Alpha aliases; the committed Compose
file tracks `0.1-alpha`, while automation should pin `0.1.0` or an image digest.
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

## Alpha limits and upgrades

The container is built from the same tagged AGPL source as the application
artifacts and carries OCI provenance and an SBOM. It is still Alpha software:
back up before upgrading, pin a versioned tag for automation, and verify the
image digest shown by GHCR. Multi-host orchestration, remote administration,
automatic backups, and a stable migration/support promise are not provided.
The RPC socket is deliberately local to the container and must not be exposed
over TCP.
