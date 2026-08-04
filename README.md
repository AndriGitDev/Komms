<p align="center">
  <img src="docs/assets/komms-logo.png" alt="Komms Protocol Logo" width="200">
</p>

# Komms

[![CI](https://github.com/AndriGitDev/Komms/actions/workflows/ci.yml/badge.svg)](https://github.com/AndriGitDev/Komms/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Server-independent core](https://img.shields.io/badge/core_server-required_no-success)
![Post-quantum](https://img.shields.io/badge/key_agreement-X25519_%2B_ML--KEM--768-blueviolet)

**Private messaging that keeps working.**

*Komms aims to make ordinary conversations feel familiar while user-owned
identity, strong end-to-end encryption, and resilient internet, local, radio,
and sneakernet paths stay underneath. Its pure core has no mandatory exclusive
provider. Standard mode can consume disclosed, signed, replaceable optional
defaults for easy first use, although no qualified default operator currently
ships; those services must never receive message plaintext or identity private
keys belonging to Komms users.*

Komms has a nonprofit public-benefit mission: private, resilient communication
should be useful to ordinary people without surveillance or exclusive-provider
lock-in. The project is founder-directed, and accountability remains with the
human maintainer.

**New here?** Read [Start Here](docs/00-start-here.md): the whole idea in plain
words, with no cryptography knowledge required.

## Komms 0.4 Beta interface preview

<p align="center">
  <img src="docs/assets/screenshots/ios-unlock-preview.png" alt="Komms unlock screen with the yellow K mark and private messaging introduction" width="300">
  &nbsp;&nbsp;
  <img src="docs/assets/screenshots/ios-inbox-preview.png" alt="Komms conversation-first inbox showing node health, pairing, note to self, private conversations, and groups" width="300">
</p>

<p align="center"><em>The Komms 0.4 Beta interface. Android, iOS, and desktop share the same brand and conversation-first information hierarchy.</em></p>

## Download the 0.4.2 Beta test release

Komms 0.4.2 is publicly available as an explicitly **unsigned,
pre-production test release** on the
[`v0.4.2` release page](https://github.com/AndriGitDev/Komms/releases/tag/v0.4.2).
It is bound to tag `v0.4.2` and commit
`5a09190cfef9cfef92703672517bc008b6e8cc1f`. The hosted validation run passed,
but the release is not production-signed, independently reproduced, qualified
for stable, or suitable for emergency, safety-critical, or production
communication.

| System | Public 0.4.2 test asset |
|---|---|
| Windows 10/11 x64 | unsigned MSI or setup EXE |
| macOS Intel or Apple silicon | unsigned and unnotarized universal DMG |
| Linux x86-64 | unsigned AppImage, DEB, or RPM |
| Android 8.0+ | Google-free APK signed with a test/debug certificate |
| iOS | unsigned Simulator ZIP only; no physical-device IPA |

Verify every download against `UNSIGNED-TEST-SHA256SUMS`. The attached
validation archive and `VALIDATION-SHA256SUMS` preserve the exact hosted build
record, including `production_signed: false`, `qualified_for_stable: false`,
and `independently_reproduced: false`; they are not an offline production
signature. The [Beta testing guide](docs/53-beta-testing.md) has the exact asset
names, Android certificate fingerprint, migration, installation, acceptance,
and issue-reporting steps. The
[0.4.2 release record](docs/54-v0.4.2-unsigned-test-release.md) documents the
one-version exception without weakening the signing policy for later releases.

## What changed in 0.4 Beta

The complete compatibility-oriented record is in the
[changelog](CHANGELOG.md).

- **Revocable device authority.** Routine profiles and backups no longer carry
  the stable account private key. Strict-majority manifests, visible conflicts,
  root-authorized recovery epochs, and an honest copied-root reset replace the
  former shared-root design.
- **Authenticated group origins.** Sender-key groups still encrypt content once,
  while each recipient verifies the claimed account/device origin before chain
  advance or decryption. Security-sensitive group events use the same boundary.
- **Consent before contact.** Unknown senders and group invitations enter a
  bounded Message Request domain with explicit Accept, Delete, and Block actions
  and admission work budgets.
- **Capability-scoped discovery and delivery.** Rotatable Connect codes,
  fixed-size encrypted DHT records, durable leased mailbox v2, and rotating
  pairwise rendezvous replace stable identity lookup and delete-on-check-in
  custody.
- **Replaceable optional services.** Standard, Private, and Sovereign now share
  one signed provider contract. Dedicated reference, mailbox, rendezvous, wake,
  and OHTTP components keep their roles separate and preserve ordinary fallback
  when unavailable.
- **Mobile wake without delivery inflation.** Direct APNs and Play-only FCM use
  content-free capabilities and bounded collection. The Google-free Android
  flavor contains no FCM SDK, and wake never changes queued/sent/delivered state.
- **Release and stewardship foundations.** A stand-alone stable-v1 conformance
  kit, security-review package, field evidence matrix, reproducible-release
  controls, English/Icelandic localization, accessibility gates, contributor
  profiles, operator runbooks, and incident/legal policy are source-controlled.

## Current implementation status

Komms 0.4.2 Beta is a public unsigned test prerelease, not an independently
audited, production-signed, or stable release. The repository contains a broad
implemented core and three application shells, with substantial automated
evidence. Simulator builds and
self-round-trip tests are not physical-device qualification or independent
interoperability.

| Area | Current state |
|---|---|
| **Core security and storage** | Hybrid PQXDH, Double Ratchet sessions, sealed envelopes, opaque keyed SQLite indexes, row-bound local records, released-schema migration, backup/recovery, RPC/CLI, and UniFFI paths are implemented with repeatable tests. SQLite still reveals approximate row counts/sizes, order, within-domain equality, access patterns, and change timing. Storage has Linux/ext4 test evidence, but independent review and physical macOS, Windows, Android, iOS, power-loss, backup-exclusion, and forensic qualification remain open. |
| **Internet, LAN, and delayed delivery** | libp2p QUIC/TCP, Kademlia discovery, NAT traversal, mDNS, and durable leased mailbox v2 are implemented. Mailbox deposits commit before acceptance; exact relay rows remain until endpoint staging and acknowledgement. A dedicated `/komms/mailbox/2`-only artifact, hardened image, restart tests, failpoints, overload/multi-operator tests, and aggregate-only health are implemented locally. Fresh installs still lack a qualified distinct-NAT golden path: bootstrap/mailbox defaults require deliberate configuration, and no public mailbox operator, observed upgrade/backup/cost record, or real-network matrix is qualified. |
| **Off-grid delivery** | Sneakernet and the Meshtastic carrier, duty-cycle controls, retransmission, and internet↔mesh bridge paths are implemented with automated evidence. The physical two-radio bench is not yet field-qualified. |
| **Applications and messaging** | Desktop, Android, and iOS shells expose pairwise/group text and a broad Beta feature set, including attachments, local organization, linked devices, message requests, ephemeral content, polls, roles, and direct audio-call paths. CI and simulator evidence exist; hands-on device, background lifecycle, NAT, accessibility, and independent qualification remain. |
| **Distribution** | Version-aligned desktop, Android, and iOS Simulator validation builds plus bounded revision-bound evidence are implemented. The exact `v0.4.2` validation set was published as an explicitly unsigned test-only Beta exception. Production credentials, signed platform artifacts, authenticated updates, external reproduction, store distribution, upgrade/rollback qualification, and stable support remain open; the public test release closes none of those gates. |
| **Optional mobile convenience** | ADR-0018 rotating post-pairing rendezvous and ADR-0019 content-free native wake are implemented locally across core, services, and clients. Standard, Private, and Sovereign share one mode contract; Private currently uses loopback Tor. A dedicated fixed-mapping RFC 9458 relay artifact is implemented, but no compatible gateway/client path, deployment, distinct administrative domains, or non-collusion evidence exists, so OHTTP is not selectable or qualified. The Play flavor contains FCM support, the Google-free flavor advertises none, and Apple uses APNs directly. No reference/wake/OHTTP service or production provider credential is deployed, and no physical background/force-quit/Doze row is qualified. None of these optional services is required by the Sovereign core. |
| **Trust and governance** | The project is founder-directed by design during construction and stabilization under a nonprofit public-benefit mission. The founder retains product and release authority. Independent security and interoperability evidence is still missing. The [stabilization program](docs/29-stabilization-program.md) defines the evidence required before stable claims. |
| **Stable-beta readiness** | A consent, aggregate-only pilot contract and fail-closed P0/candidate decision record are implemented. No pilot has run, all P0 gates remain open, production signing is unenrolled, and no stable-beta or stable claim is authorized. The 0.4.2 unsigned test publication is not stable-beta evidence. |

Older `KKR1` through legacy copied-root `KKR7` backups remain explicit
migration/reset inputs: they never resume the former account, and the guided
flow publishes a fresh identity containing only cleared petnames, accurately
labelled non-ephemeral pairwise history, notes, and eligible local
organization. They are decode-only compatibility formats: production APIs
cannot mint or publish a new copied-root backup. Root-free `KKR8` and `KKR9`
backups remain directly restorable compatibility inputs; current routine
backups are root-free `KKR10`. KKR6
added signed group authority state, KKR7 added the former linked-device
authority/convergence layout, KKR8 introduced the accepted offline-root
authority proof, KKR9 added durable local block rules, and KKR10 adds the
rotatable Connect-code discovery capability and generation. No root-free
format contains an account root or reusable device, ratchet, prekey,
sender-chain, link, invitation, rendezvous, wake, or delivery-resumption
secret. Stable-identity KKR8/KKR9/KKR10 restore requires the separately held offline
recovery-authority file and phrase, creates one fresh recovery device, and
rejects descendants of the old epoch. Restoring KKR8 naturally restores no
later block rows; restoring KKR8 or KKR9 generates a fresh discovery
capability. Current backups also exclude provisional requests, replay
tombstones, and live ephemeral plaintext/media, while terminal ephemeral
tombstones remain so restore does not recreate those records in Komms. This is
local implementation evidence, not a promise to erase copies retained by
peers, screenshots, exported backups, or compromised endpoints.

The [stabilization program](docs/29-stabilization-program.md) now takes priority
over feature expansion. It defines exact evidence levels, owners, P0/P1/P2
gates, and the first 90 days. The [roadmap](docs/08-roadmap.md) remains the
engineering inventory, the [feature delivery plan](docs/12-feature-delivery-plan.md)
remains the product backlog, and the
[local release gate](docs/24-local-release-gate.md) describes existing build
checks. The [stable-v1 product profile](docs/30-stable-v1-product-profile.md)
freezes the release target, the
[release evidence ledger](docs/31-release-evidence-ledger.md) records every P0
gate and stable claim, and the
[name-risk decision](docs/32-name-risk-decision.md) records the founder's
keep-and-monitor decision without claiming legal clearance.

Komms is built on four principles:

1. **Everyday messenger first.** Installation, pairing, sending, recovery, and
   delivery state should make sense without transport or cryptography knowledge.
2. **No mandatory exclusive provider.** Peers may communicate directly, through
   chosen volunteer mailbox operators holding sealed ciphertext, or over local,
   radio, and sneakernet paths. Standard mode may use disclosed, replaceable
   defaults. Optional rendezvous and native wake receive no message plaintext or
   identity private keys and remain removable.
3. **Strong cryptographic building blocks, honestly qualified.** The
   implementation combines published constructions including X25519 +
   ML-KEM-768, Double Ratchet sessions with encrypted headers, and
   XChaCha20-Poly1305. That combination still requires independent review and
   interoperability evidence before it can be called audited or stable.
4. **Your keys and local data stay yours.** Identity needs no phone number or
   email. Komms can delete its local encrypted history and exclude expiring
   content from its own current backups, but it cannot erase copies another
   person, export, screenshot, operating system, or compromised device retains.

[Why Komms](docs/01-why.md) explains the social motivation, including concern
about policy proposals and laws that seek or allow private communications to be
scanned. It distinguishes that position from claims about the current legal
status of any particular proposal.

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
| [13: Screen Security](docs/13-screen-security.md) | B14 platform guarantees, limitations, behavior, and qualification matrix |
| [14: Incognito Keyboard](docs/14-incognito-keyboard.md) | B15 input-field guarantees, native controls, honest limits, and qualification matrix |
| [15: Private Contact Names](docs/15-contact-petnames.md) | B5 local petname rename contract, warnings, privacy boundary, and qualification matrix |
| [16: Safe Text Formatting](docs/16-safe-text-formatting.md) | B9 source subset, active-content boundary, limits, compatibility, and qualification matrix |
| [17: Safe File Presentation](docs/17-safe-file-presentation.md) | C1 filename/type policy, open/export boundary, lifecycle, and qualification matrix |
| [18: Authenticated Message Editing](docs/18-message-editing.md) | C3 immutable edit events, pairwise and recipient-authenticated group authorship, convergence, retained versions, compatibility, and qualification |
| [19: Disappearing Messages and View-Once Attachments](docs/19-ephemeral-messages.md) | C4 exact local expiry, coarse relay retention, tombstones, KKR10 exclusion, honest limits, and qualification |
| [20: Group Polls](docs/20-group-polls.md) | C5 visible recipient-authenticated votes, fixed electorate, deterministic convergence, creator closure, and qualification |
| [21: Group Roles, Ownership, and Moderation](docs/21-group-roles.md) | C6 signed owner/admin/member authority, transfer, rotation, moderation, backup, and qualification |
| [22: Linked Devices](docs/22-linked-devices.md) | C2 strict-majority device authority, confirmed linking, per-device delivery, sync, offline recovery, revocation, and honest Alpha migration |
| [23: Live Audio Calls](docs/23-live-audio-calls.md) | C7 direct-QUIC gating, transient signaling, authenticated Opus media, platform behavior, privacy limits, and qualification |
| [24: Local Release Gate](docs/24-local-release-gate.md) | Toolchains, complete local validation, CI/advisory evidence, SDK deferrals, signing boundary, and publication discipline |
| [25: Release Runbook](docs/25-release-runbook.md) | Versioning, retained validation builds, protected signing/qualification, immutable completed assets, and explicit publication |
| [26: Self-hosting](docs/26-self-hosting.md) | Hardened Docker Compose deployment, ports, secret initialization, node modes, and Beta limits |
| [27: Alpha Testing](docs/27-alpha-testing.md) | Historical 0.3 Alpha package verification, installation, and smoke testing |
| [28: Brand System](docs/28-brand-system.md) | Cross-shell product character, tokens, hierarchy, and pragmatic name-risk monitoring |
| [29: Stabilization Program](docs/29-stabilization-program.md) | Canonical evidence vocabulary, trust gates, owners, and 90-day sequence |
| [30: Stable-v1 Product Profile](docs/30-stable-v1-product-profile.md) | Frozen install, messaging, bounds, recovery, delivery, platform, service, and exclusion contract |
| [31: Release Evidence Ledger](docs/31-release-evidence-ledger.md) | P0 and stable-claim owners, evidence, revisions, gaps, and review dates |
| [32: Name-risk Decision](docs/32-name-risk-decision.md) | Dated keep-and-monitor decision, observed overlap, migration cost, cadence, and advice triggers |
| [33: Opaque Store Qualification](docs/33-opaque-store-qualification.md) | Opaque-indexed store migration, remnant controls, scale evidence, and open physical/forensic gates |
| [34: Atomic Transition Inventory](docs/34-atomic-transition-inventory.md) | Typed protocol/store transitions, crash ownership, and side-effect ordering |
| [35: Reference Service Operations](docs/35-reference-service-operations.md) | Least-authority bootstrap/DHT/rendezvous image, hardening, rotation, and replacement |
| [36: Operating Modes and Provider Directory](docs/36-operating-modes-and-provider-directory.md) | Canonical Standard, Private, and Sovereign behavior with replaceable signed providers |
| [37: Native Wake Operations](docs/37-native-wake-operations.md) | Fixed-shape least-authority wake service, credentials, state, and incident response |
| [38: Native Wake Mobile Qualification](docs/38-native-wake-mobile-qualification.md) | Android/iOS lifecycle matrix and strict physical-evidence boundary |
| [39: Release Security and Recovery](docs/39-release-security-and-recovery.md) | Signing roles, key rotation, compromise, updater, and rollback policy |
| [40: Release Evidence Bundles](docs/40-release-evidence-bundles.md) | Revision/digest-bound SBOM, provenance, reproducibility, and qualification records |
| [41: Protocol Conformance](docs/41-protocol-conformance.md) | Stand-alone stable-v1 specification, fixtures, runner, and independence limits |
| [42: Independent Security Review](docs/42-independent-security-review.md) | External-review scope, evidence archive, RFP, findings, and current unassigned status |
| [43: Field Qualification](docs/43-field-qualification.md) | Named platform/network/radio matrix, capture format, and retained simulator evidence |
| [44: Contributor Path](docs/44-contributor-path.md) | Bounded target profiles, sensitive review boundaries, and focused handoff |
| [45: Localization and Accessibility](docs/45-localization-accessibility.md) | Shared English/Icelandic catalogs, semantics, contrast, and open external evidence |
| [46: Operator Program](docs/46-operator-program.md) | Service roles, capacity/cost, support, abuse, upgrade, and two-operator qualification |
| [47: License, Trademark, and Assets](docs/47-license-trademark-assets.md) | AGPL scope, section 13, contributions, names, identifiers, and third-party inventory |
| [48: Funding and Transparency](docs/48-funding-transparency.md) | Mission-aligned funding, conflicts, reporting cadence, and legal-entity limits |
| [49: Privacy, Legal, and Incident Readiness](docs/49-privacy-legal-incident-readiness.md) | Provider data flows, lawful requests, key incidents, advisories, and dry-runs |
| [50: Mailbox Service Operations](docs/50-mailbox-service-operations.md) | Dedicated mailbox-v2 artifact, custody, backup, upgrade, incident, and qualification rules |
| [51: Stable-Beta Pilot and Release Decision](docs/51-stable-beta-pilot-and-release-decision.md) | Consent boundary, aggregate pilot metrics, final matrix, P0 audit, support, rollback, and founder decision |
| [52: Oblivious HTTP Relay Operations](docs/52-ohttp-relay-operations.md) | Fixed-mapping RFC 9458 relay, metadata stripping, hardening, rotation, and non-collusion boundary |
| [53: Beta Testing](docs/53-beta-testing.md) | 0.4 migration, package/evidence verification, acceptance walk-through, and honest test reporting |
| [54: 0.4.2 Unsigned Test Release](docs/54-v0.4.2-unsigned-test-release.md) | Immutable release identity, validation result, public asset boundary, Android test certificate, exception decision, and gates that remain open |
| [ADRs](docs/adr/README.md) | Decision index, status, and the alternatives each decision beat |

## Stack

Rust workspace (`kult-crypto` / `kult-protocol` / `kult-transport` / `kult-store` /
`kult-node` / `kultd` / `kult-reference-service` / `kult-mailbox` /
`kult-wake` / `kult-ohttp-relay` / `kult-ffi`), UniFFI bindings, Tauri desktop app, native
mobile shells.
Layout in [Architecture §7](docs/03-architecture.md). Implemented so far:
`kult-crypto` (hybrid PQXDH, Double Ratchet with encrypted headers,
sender-anonymous sealed envelopes, sealed state, sender-key group chains),
`kult-protocol` (envelopes, padding
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
records/enums with an embedded in-process runtime, for the application shells),
plus `apps/desktop` (Tauri shell), `apps/android`
(Kotlin Beta shell over the generated bindings), and `apps/ios`
(SwiftUI Beta shell over the same bindings). The daemon writes structured,
content-free diagnostics to stderr (`RUST_LOG`, default `info`) and supports
owner-only passphrase/mnemonic files for service deployment; run `kultd --help`
for the complete operator surface.

## Build and validation

Rust **1.88 or newer** is required by the locked dependency graph and verified
as the minimum supported Rust version in CI. A current stable toolchain is the
normal developer choice; the complete fuzz gate additionally needs nightly
Rust and `cargo-fuzz`. Platform SDK requirements live in the
[desktop](apps/desktop/README.md), [Android](apps/android/README.md), and
[iOS](apps/ios/README.md) guides.

```sh
cargo test --workspace --all-features          # KATs, properties, e2e, soak
cargo build -p kult-crypto --no-default-features   # no_std build
cd crates/kult-crypto && cargo +nightly fuzz run envelope_decode -- -max_total_time=60
```

Before a publication candidate, run `scripts/local-release-matrix.sh` from the
repository root and record every explicit `DEFERRED` platform gate. The exact
division between local checks, per-push CI, weekly advisory evidence, physical
qualification, and signing is documented in the
[local release gate](docs/24-local-release-gate.md).

The public **Komms 0.4.2 Beta** is the unsigned test-only prerelease at source
tag `v0.4.2`. Use the [Beta testing guide](docs/53-beta-testing.md) for the exact
migration, package, and evidence boundary. Container publication and moving
`0.4-beta`/`beta` tags remain separate authorized operations and were not part
of the desktop/mobile release. See the
[release runbook](docs/25-release-runbook.md) for the unchanged production
signing, qualification, and publication controls, or the
[self-hosting guide](docs/26-self-hosting.md) to run `kultd` from source.

## Contributing

Security review, hands-on platform testing, and focused implementation of the
remaining roadmap are especially valuable; see [CONTRIBUTING.md](CONTRIBUTING.md).
Project decisions and ownership: [GOVERNANCE.md](GOVERNANCE.md) and
[MAINTAINERS.md](MAINTAINERS.md). Security issues: [SECURITY.md](SECURITY.md).
Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Komms software is licensed under [AGPL-3.0-only](LICENSE). Under AGPLv3 section
13, a modified covered version that supports remote network interaction must
prominently offer its remote users an opportunity to receive that version's
Corresponding Source. The AGPL permits commercial use; Komms's nonprofit
mission governs official project activity, not independent licensees. See
[ADR-0006](docs/adr/0006-agplv3.md) and
[ADR-0033](docs/adr/0033-nonprofit-founder-stewardship.md). Repository scope,
contribution terms, trademark use, package identifiers, and third-party
material are in the
[license, trademark, and asset policy](docs/47-license-trademark-assets.md) and
[third-party notices](THIRD_PARTY_NOTICES.md). This summary is not legal advice.
