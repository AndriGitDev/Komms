# KommsKult

[![CI](https://github.com/AndriGitDev/KommsKult/actions/workflows/ci.yml/badge.svg)](https://github.com/AndriGitDev/KommsKult/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![No servers](https://img.shields.io/badge/servers-none-success)
![Post-quantum](https://img.shields.io/badge/key_agreement-X25519_%2B_ML--KEM--768-blueviolet)

**Sovereign messaging: end-to-end encrypted, serverless, and functional off the grid.**

*Messages nobody in the middle can read, scan, or block — because there is no middle.
Works over the internet, commodity LoRa radios, or a USB stick in a pocket.*

**New here?** Read [Start Here](docs/00-start-here.md) — the whole idea in plain words,
no cryptography knowledge required. Then try the demo:

```sh
git clone https://github.com/AndriGitDev/KommsKult && cd KommsKult
cargo run --example sneakernet_demo
```

> Status: **M3 complete — the full internet-era node is in.** The design framework
> (M0), the crypto core (M1), the protocol/storage layer (M2: sealed envelopes,
> LoRa-sized fragmentation with NACK retransmission, encrypted local store,
> sneakernet bundles), the `kult-node` runtime (delivery engine with honest
> queued→sent→delivered states, transport scheduler, encrypted receipts,
> out-of-order stash), the libp2p internet transport (QUIC primary, TCP+Noise
> fallback), Kademlia prekey discovery (whole-bundle-signed records; add a contact
> from a kult address alone), volunteer mailbox relays (store-and-forward of
> sealed envelopes for offline recipients), NAT traversal (AutoNAT reachability
> probes, Circuit Relay v2 reservations at any public peer, DCUtR hole punching),
> and mDNS LAN auto-discovery (an in-tree hardened responder: two nodes on one
> Wi-Fi discover each other and deliver with zero configuration and no internet)
> are implemented and tested, and `kultd` runs it all headless behind local JSON
> RPC on a Unix socket (with the `kult` CLI client). M4 (the Meshtastic LoRa
> off-grid bridge) is under way: the carrier core is in — sealed envelopes ride
> a private app port on stock-firmware radios with duty-cycle accounting — and
> the delivery engine now enforces the mesh policies: priority classes (text >
> receipts > handshakes), a 4 KiB airtime ceiling with honest "will send when a
> faster link exists" feedback, and selective retransmission (missing fragment
> indices are NACKed and only those fragments resent). Next per the
> [roadmap](docs/08-roadmap.md): `kultd` mesh wiring and internet↔mesh bridging.

KommsKult is a decentralized messenger built on four principles:

1. **No one in the middle.** No servers, no accounts, no company operating your
   communications. Peers talk directly, via volunteer relays holding only sealed
   ciphertext, or over radio. There is no checkpoint at which scanning, filtering, or
   interception can be mandated — by architecture, not by policy.
2. **Cryptography at the state of the art.** Hybrid post-quantum key agreement
   (X25519 + ML-KEM-768), Double Ratchet sessions with encrypted headers, and
   XChaCha20-Poly1305 everywhere — assembled strictly from published, audited designs.
3. **Off-grid is a first-class citizen.** When networks are down or shut off, the same
   sealed messages travel over commodity Meshtastic LoRa radios (kilometers of range,
   multi-hop, ~€30 hardware), local links, or file/QR sneakernet.
4. **Your keys, your data, your hardware.** Identity is a keypair you mint yourself — no
   phone number, no email. History is stored locally, encrypted, exportable, and
   deletable for real.

Why this project exists — including its answer to the EU's ChatControl regime — is set
out plainly in [Why KommsKult](docs/01-why.md).

## Design documents

| Doc | Contents |
|---|---|
| [00 — Start Here](docs/00-start-here.md) | The whole project in plain words, for any knowledge level |
| [01 — Why](docs/01-why.md) | Motivation, position, commitments |
| [02 — Threat Model](docs/02-threat-model.md) | Adversaries, security goals, honest limits |
| [03 — Architecture](docs/03-architecture.md) | Layers, crates, message lifecycle, store-and-forward |
| [04 — Cryptography](docs/04-cryptography.md) | Normative crypto spec: PQXDH, Double Ratchet, envelopes |
| [05 — Transports](docs/05-transports.md) | Internet (libp2p), proximity, Meshtastic/LoRa, sneakernet |
| [06 — Identity & Trust](docs/06-identity-trust.md) | Keypair identity, verification, petnames |
| [07 — Storage](docs/07-storage.md) | Local-first encrypted storage, backup, portability |
| [08 — Roadmap](docs/08-roadmap.md) | Milestones M0–M6 with acceptance criteria |
| [09 — Implementation Guide](docs/09-implementation-guide.md) | Build order, API sketches, standards, review gates |
| [ADRs](docs/adr/) | Recorded decisions and the alternatives they beat |

## Stack

Rust workspace (`kult-crypto` / `kult-protocol` / `kult-transport` / `kult-store` /
`kult-node` / `kultd` / `kult-ffi`), UniFFI bindings, Tauri desktop app, native
mobile shells.
Layout in [Architecture §7](docs/03-architecture.md). Implemented so far:
`kult-crypto` (hybrid PQXDH, Double Ratchet with encrypted headers, anonymous sealed
boxes, sealed state), `kult-protocol` (envelopes, padding buckets, fragmentation +
NACKs, delivery tokens, `.kkb` bundles), and `kult-store` (encrypted SQLite, key
hierarchy, persistent queue), `kult-transport` (the `Transport` contract, the
sneakernet spool-directory carrier, and the libp2p internet carrier — QUIC primary,
TCP+Noise+Yamux fallback, envelope request-response protocol with honest next-hop
acks, a Kademlia discovery plane serving signed prekey-bundle records, volunteer
mailbox relays storing only sealed envelopes, and NAT traversal via AutoNAT +
Circuit Relay v2 + DCUtR), and `kult-node` (session lifecycle, delivery
engine with per-message state machine and retry/backoff, transport scheduler
with mesh priority classes and the 4 KiB airtime ceiling, end-to-end
encrypted delivery receipts, fragmentation over small-MTU links with
selective-retransmission NACKs, contact-by-address via DHT lookup,
command/event API), and `kultd` (headless
daemon: tick loop, DHT bootstrap + bundle publication, automatic NAT/relay
lifecycle, mailbox check-ins, local JSON RPC over a Unix socket, `kult` CLI).
`kult-ffi` lands in M5.

```sh
cargo test --workspace          # KATs, property tests, 10k-message soak
cargo build -p kult-crypto --no-default-features   # no_std build
cargo fuzz run envelope_decode  # fuzzing (nightly, from crates/kult-crypto)
```

## Contributing

Design review is the most valuable contribution right now — see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[AGPLv3](LICENSE). Anyone may run, study, modify, and share every component — and
modified network services must publish their source. Rationale:
[ADR-0006](docs/adr/0006-agplv3.md).
