<p align="center">
  <img src="docs/assets/komms-logo.png" alt="Komms Protocol Logo" width="200">
</p>

# Komms

[![CI](https://github.com/AndriGitDev/Komms/actions/workflows/ci.yml/badge.svg)](https://github.com/AndriGitDev/Komms/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![No servers](https://img.shields.io/badge/servers-none-success)
![Post-quantum](https://img.shields.io/badge/key_agreement-X25519_%2B_ML--KEM--768-blueviolet)

**Sovereign messaging: end-to-end encrypted, serverless, and functional on & off the grid.**

*Messages nobody in the middle can read, scan, or block, because there is no middle.
Works over the internet, commodity LoRa radios, or a USB stick in a pocket.*

**New here?** Read [Start Here](docs/00-start-here.md): the whole idea in plain words,
no cryptography knowledge required. Then try the demo:

```sh
git clone https://github.com/AndriGitDev/Komms && cd Komms
cargo run --example sneakernet_demo
```

> Status: **M3 complete: the full internet-era node is in.** The design framework
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
> off-grid bridge) is nearly complete: sealed envelopes ride a private app port
> on stock-firmware radios with duty-cycle accounting (`kultd
> --meshtastic-serial /dev/ttyUSB0` attaches a radio as a carrier); the delivery
> engine enforces the mesh policies: priority classes (text > receipts >
> handshakes), a 4 KiB airtime ceiling with honest "will send when a faster
> link exists" feedback, and selective retransmission (missing fragment indices
> are NACKed and only those fragments resent); and a node with both a radio and
> internet now bridges third-party sealed traffic between them, token-blind and
> bounded (ADR-0009): a mesh-only village and an internet-only correspondent
> exchange verified-delivery messages through one volunteer bridge. The
> hardware-in-loop nightly is in as code: an acceptance test drives two
> daemons over real USB radios, run nightly on a self-hosted bench runner
> ([bench runbook](docs/10-hil-bench.md)). M5 (applications) has begun:
> `kult-ffi` exposes the node's command/event API to Kotlin/Swift/desktop
> shells via UniFFI: a single constructor starts the full node in-process
> (same composition as `kultd`, ADR-0010), with typed blocking calls and
> events pushed to an app-registered listener; its e2e test drives two nodes
> to verified delivery through the bindings surface alone. The desktop app
> is in (`apps/desktop`): a Tauri shell over that runtime covering the M5
> UX end to end: create/unlock/restore gate, QR/hex/address pairing,
> honest delivery states, safety-number verification, transport
> indicators, and mnemonic-shown-once backup. The Android alpha shell is
> in (`apps/android`): Kotlin over the same runtime through generated
> UniFFI bindings, camera QR pairing and verification (CameraX +
> pure-Java ZXing, no Google services), the same honest delivery ladder
> and settings file as desktop, and a foreground service for background
> delivery: the whole behavior layer pinned by a JVM two-node e2e that
> needs no emulator, native libraries cross-compiled per ABI via
> cargo-ndk in CI. The iOS alpha shell is in (`apps/ios`): SwiftUI over
> the same runtime through generated bindings, camera QR pairing and
> verification with zero third-party dependencies (CoreImage +
> AVFoundation), the same honest delivery ladder and settings file as
> the other shells. Its behavior layer (the `KommsCore` Swift package)
> pinned by a two-node e2e that runs on plain Linux in CI, no Xcode.
> M6 has opened as well: sender-key group messaging v1 is in through the
> core stack (ADR-0012): per-member forward-ratcheting chains in
> `kult-crypto`, group bodies whose only routing metadata (`key_id ‖
> iteration`) is sealed under a members-only header key so intermediaries
> see uniformly random bytes, and one ciphertext fanned out in ordinary
> per-member envelopes, so relays, mailboxes, receipts, NACKs, and
> bridging carry group traffic without knowing it is group traffic.
> Membership is creator-managed with a monotonic generation counter and
> announce-until-acked distribution (a member served late still reads
> everything since they were entitled; removal re-keys and rotates every
> remaining chain); backups are now `KKR4` (older `KKR1`/`KKR2`/`KKR3` files
> still restore) and carry group identities, history, sealed local metadata,
> and sealed note-to-self history but
> never chains: a
> restored node announces a fresh chain and co-members redistribute
> theirs on the re-handshake, both directions pinned by the `kult-node`
> group e2e suite (`groups_e2e.rs`). The shared group front door is now
> shipped too: `kultd` RPC, the `kult` CLI, and `kult-ffi` expose group
> records, history, events, membership operations, and honest per-member
> delivery states, pinned by RPC and bindings e2e tests. Desktop, Android,
> and iOS group UX are shipped with truthful partial-delivery rows. The local
> note-to-self conversation is shipped through storage, node, RPC/CLI, UniFFI,
> desktop, Android, and iOS under the same reserved `note_to_self` identity; it
> never creates envelopes, queue entries, receipts, or transport work. The shared
> versioned message-content foundation is shipped too
> ([ADR-0014](docs/adr/0014-versioned-message-content.md), Accepted): bounded
> encrypted `Text` frames negotiate conservatively while legacy text remains
> permanently readable and unknown authenticated content stays durable.
> The F5 local-metadata foundation is shipped as well: typed folders, pins,
> labels, drafts, preferences, and custom icons remain sealed and strictly local.
> Durable scheduled messaging is now in through the shared core and front doors:
> pairwise/group text stays sealed in a device-local scheduled outbox until its
> absolute UTC instant, remains editable/cancellable without advancing a ratchet,
> and then enters the ordinary queued→sent→delivered ladder. RPC/CLI, UniFFI, and
> all three shells expose the same lifecycle with local-time composer controls and
> visibly distinct scheduled history rows.
> Recorded audio messages are shipped across desktop, Android, and iOS as one
> metadata-free mono PCM WAV profile, bounded to 60 seconds. Each shell provides
> foreground-only record→stop→review→explicit send/discard, protected local
> playback with duration/waveform, pairwise and sender-key group F3 delivery, and
> current F4 carrier explanations. ADR-0015 remains absolute: mesh-only audio
> waits for a faster link and emits zero bulk airtime frames.
> Still-image editing is shipped across the same three shells and unchanged F3
> path. Content-verified bounded JPEG/PNG selections are orientation-normalized,
> cropped, rotated, manually blurred or pixelated, and re-encoded by one shared
> Rust helper as metadata-free PNG before an exact final review. Only that final
> asset can be imported. Generic files skip the editor but now receive the same
> authoritative F4 explanation, fresh recheck, and explicit send/discard flow.
> Images and files with only a mesh route wait and emit zero bulk airtime frames.
> Group mentions are shipped end to end under
> [ADR-0016](docs/adr/0016-group-mention-content.md): every shell composes from an
> explicit current-roster picker, preserves the exact visible fallback text, and
> seals stable peer targets plus canonical UTF-8 byte ranges inside the existing
> padded typed-content frame. A semantic mention is sent only when every current
> co-member has freshly authenticated support; otherwise the user may explicitly
> send the same visible text as ordinary text, with no mention notification.
> Historic mentions never retarget after petname or roster changes. Notifications
> are private, endpoint-local hints only—there is no server push or online-delivery
> guarantee.
> Remaining per the [roadmap](docs/08-roadmap.md): the physical two-radio bench (M4); a
> hands-on device pass of the iOS app layer (M5); the wider M6 hardening list;
> and the external security audit.

Komms is a decentralized messenger built on four principles:

1. **No one in the middle.** No servers, no accounts, no company operating your
   communications. Peers talk directly, via volunteer relays holding only sealed
   ciphertext, or over radio. There is no checkpoint at which scanning, filtering, or
   interception can be mandated, by architecture, not by policy.
2. **Cryptography at the state of the art.** Hybrid post-quantum key agreement
   (X25519 + ML-KEM-768), Double Ratchet sessions with encrypted headers, and
   XChaCha20-Poly1305 everywhere, assembled strictly from published, audited designs.
3. **Off-grid is a first-class citizen.** When networks are down or shut off, the same
   sealed messages travel over commodity Meshtastic LoRa radios (kilometers of range,
   multi-hop, ~€30 hardware), local links, or file/QR sneakernet.
4. **Your keys, your data, your hardware.** Identity is a keypair you mint yourself: no
   phone number, no email. History is stored locally, encrypted, exportable, and
   deletable for real.

Why this project exists, including its answer to the EU's ChatControl regime, is set
out plainly in [Why Komms](docs/01-why.md).

## Design documents

| Doc | Contents |
|---|---|
| [00: Start Here](docs/00-start-here.md) | The whole project in plain words, for any knowledge level |
| [01: Why](docs/01-why.md) | Motivation, position, commitments |
| [02: Threat Model](docs/02-threat-model.md) | Adversaries, security goals, honest limits |
| [03: Architecture](docs/03-architecture.md) | Layers, crates, message lifecycle, store-and-forward |
| [04: Cryptography](docs/04-cryptography.md) | Normative crypto spec: PQXDH, Double Ratchet, envelopes |
| [05: Transports](docs/05-transports.md) | Internet (libp2p), proximity, Meshtastic/LoRa, sneakernet |
| [06: Identity & Trust](docs/06-identity-trust.md) | Keypair identity, verification, petnames |
| [07: Storage](docs/07-storage.md) | Local-first encrypted storage, backup, portability |
| [08: Roadmap](docs/08-roadmap.md) | Milestones M0–M6 with acceptance criteria |
| [09: Implementation Guide](docs/09-implementation-guide.md) | Build order, API sketches, standards, review gates |
| [10: HIL Bench](docs/10-hil-bench.md) | Hardware-in-loop nightly: two-radio bench runbook |
| [11: Feature Scope](docs/11-feature-scope.md) | Which product features fit the model, and under what constraints |
| [12: Feature Delivery Plan](docs/12-feature-delivery-plan.md) | Sequenced implementation plan for every approved product feature |
| [ADRs](docs/adr/) | Recorded decisions and the alternatives they beat |

## Stack

Rust workspace (`kult-crypto` / `kult-protocol` / `kult-transport` / `kult-store` /
`kult-node` / `kultd` / `kult-ffi`), UniFFI bindings, Tauri desktop app, native
mobile shells.
Layout in [Architecture §7](docs/03-architecture.md). Implemented so far:
`kult-crypto` (hybrid PQXDH, Double Ratchet with encrypted headers, anonymous sealed
boxes, sealed state, sender-key group chains), `kult-protocol` (envelopes, padding
buckets, fragmentation + NACKs, delivery tokens, sealed group headers, `.kkb`
bundles), and `kult-store` (encrypted SQLite, key
hierarchy, persistent queue), `kult-transport` (the `Transport` contract, the
sneakernet spool-directory carrier, and the libp2p internet carrier: QUIC primary,
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
lifecycle, mailbox check-ins, local JSON RPC over a Unix socket, `kult` CLI),
and `kult-ffi` (UniFFI bindings: the node's command/event API as typed
records/enums with an embedded in-process runtime, for the M5 app shells),
plus the M5 apps so far: `apps/desktop` (Tauri shell), `apps/android`
(Kotlin alpha shell over the generated bindings), and `apps/ios`
(SwiftUI alpha shell over the same bindings).

```sh
cargo test --workspace          # KATs, property tests, 10k-message soak
cargo build -p kult-crypto --no-default-features   # no_std build
cargo fuzz run envelope_decode  # fuzzing (nightly, from crates/kult-crypto)
```

## Contributing

Design review is the most valuable contribution right now; see
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[AGPLv3](LICENSE). Anyone may run, study, modify, and share every component, and
modified network services must publish their source. Rationale:
[ADR-0006](docs/adr/0006-agplv3.md).
