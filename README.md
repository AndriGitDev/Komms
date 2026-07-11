# KommsKult

**Sovereign messaging: end-to-end encrypted, serverless, and functional off the grid.**

> Status: **M0 — design phase.** This repository currently contains the complete design
> framework; implementation milestones are specified in the [roadmap](docs/08-roadmap.md).

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

## Planned stack

Rust core (`kult-crypto` / `kult-protocol` / `kult-transport` / `kult-store` /
`kult-node`), UniFFI bindings, Tauri desktop app, native mobile shells. Target layout in
[Architecture §7](docs/03-architecture.md).

## Contributing

Design review is the most valuable contribution right now — see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[AGPLv3](LICENSE). Anyone may run, study, modify, and share every component — and
modified network services must publish their source. Rationale:
[ADR-0006](docs/adr/0006-agplv3.md).
