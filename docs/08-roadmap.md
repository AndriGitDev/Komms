# 08: Roadmap

Milestones are strictly ordered by dependency; each has acceptance criteria that gate the
next. Build order details per crate: [09: Implementation Guide](09-implementation-guide.md).

## M0: Design framework *(done)*

**Deliverable**: the documentation set in `docs/`: threat model, architecture, crypto
spec, transport spec, identity model, storage model, ADRs, implementation guide.

**Acceptance**: docs internally consistent; every architectural decision has an ADR;
implementation guide sufficient for a competent Rust developer (or coding agent) to start
M1 without design questions.

## M1: Cryptographic core (`kult-crypto`) *(done)*

Workspace scaffolding + the full crypto layer: primitives wiring, hybrid PQXDH handshake,
Double Ratchet with header encryption, fingerprints, key serialization.

**Acceptance**:
- All test obligations of [04: Cryptography §11](04-cryptography.md) green in CI
  (KATs, ratchet property tests, fuzz targets running, `cargo-deny` clean).
- `#![forbid(unsafe_code)]`; every secret type zeroizes; API compiles as `no_std`+alloc.
- Two in-memory parties complete handshake and exchange 10 000 messages under random
  loss/reorder within `MAX_SKIP`.

## M2: Protocol & storage (`kult-protocol`, `kult-store`) *(done)*

Envelope codec, padding buckets, fragmentation/reassembly, delivery tokens, sealed
sender; encrypted SQLite storage with the full key hierarchy; sneakernet bundle
import/export (first working transport, needs no networking).

**Acceptance**:
- Two nodes exchange messages via **bundle files** end-to-end (write → export → import →
  read), surviving process restarts (queue persistence).
- Fragmentation round-trips at MTU 180 B with 30 % random fragment loss via NACK/retry.
- Fuzzers on envelope + bundle parsers; storage passes "copied DB file leaks nothing but
  sizes" review checklist.

## M3: Internet transport & headless node (`kult-transport`, `kult-node`) *(done)*

The `kult-node` runtime is implemented per the build order in
[09: Implementation Guide §2](09-implementation-guide.md): delivery engine
(queued→sent→delivered on encrypted receipts, retry with backoff, dedup,
out-of-order stash), transport scheduler, session lifecycle, command/event API,
running over the sneakernet carrier. The libp2p carrier's first slice is also in:
QUIC (primary) and TCP+Noise+Yamux (fallback) with an envelope request-response
protocol reporting honest next-hop acks; two nodes exchange messages and receipts
over localhost, and the scheduler prefers it over slower carriers. The discovery
plane is in: a Kademlia DHT (bootstrap from any user-supplied peer, nothing
hardcoded) carrying whole-bundle-signed prekey records under the kult-address
digest, so a node adds a contact from the address string alone and the delivery
engine resolves missing return paths (sealed sender reveals none) from the
peer's record. Mailbox relays are in: any node can volunteer bounded
store-and-forward on `/komms/mailbox/1`; recipients register rotating
delivery tokens as accept-filters and collect on reconnect, senders deposit
sealed envelopes the scheduler ranks below direct paths, and the "relay stores
only sealed envelopes" acceptance criterion is pinned by an inspection test
(collection-deletes required making tokens recipient-scoped, ADR-0007).
NAT traversal is in as the pinned trio: AutoNAT dial-back probes report each
node's reachability (`nat_status`), a private node reserves a Circuit Relay v2
slot at any public peer (`reserve_relay`, every node volunteers bounded relay
service, and a fresh relay self-confirms its own address via AutoNAT seconds
after its first peer connects), the returned circuit address is handed out as
an ordinary multiaddr hint, and DCUtR upgrades relayed connections to direct
ones by hole punching. The headless daemon is in: `kultd` (its own crate,
application A3) runs the full node over the internet carrier: tick loop,
DHT bootstrap and bundle publication, automatic NAT probing with relay
reservation, mailbox check-ins, optional mailbox serving and sneakernet
spool, and exposes the node's command/event API as newline-delimited JSON
RPC on a mode-0600 local Unix socket, with `kult` as the matching CLI
client; the RPC acceptance test drives two daemons to verified delivery
through their sockets alone. mDNS LAN auto-discovery closes out M3: since
`libp2p-mdns` still pins the RUSTSEC-flagged `hickory-proto 0.25` (and this
workspace ignores no vulnerabilities), the libp2p mDNS discovery profile is
implemented in-tree (ADR-0008), a strict, bounded DNS responder whose
discoveries seed the Kademlia routing table, so two nodes on one LAN
deliver messages *and* run the whole discovery plane (prekey
publish/lookup) with zero bootstrap configuration and no internet at all.

libp2p integration (QUIC, TCP fallback, Kademlia, relay v2, DCUtR), prekey bundles on
DHT, mailbox relays, transport scheduler, headless daemon with local RPC.

**Acceptance**:
- Two nodes behind distinct NATs exchange messages with no manual configuration beyond
  sharing kult addresses.
- Recipient offline → message deposited at relay → delivered on reconnect; relay
  observably stores only sealed envelopes (verified by inspection test).
- LAN-only (no internet) delivery works via mDNS.

## M4: Off-grid Meshtastic bridge *(in progress)*

BLE + USB-serial Meshtastic client integration, private app port, runtime MTU
computation, priority classes, selective retransmission, internet↔mesh bridging.

The carrier core is in: `MeshtasticTransport` (behind the `meshtastic` feature
of `kult-transport`) speaks the standard client protocol to a stock-firmware
radio over any byte stream (USB-serial, TCP, or an in-memory duplex in tests)
via the official `meshtastic` crate (the published protobuf definitions through
a generated client, per the implementation guide). Sealed envelopes ride the
private application port; the frame budget is the protobuf-pinned 233-byte
`Data.payload` cap, so the delivery engine's existing fragmentation path needs
no mesh-specific logic, and a ratcheted 192-bucket text message crosses the
mesh in ≤ 2 LoRa frames, pinned end-to-end (encrypt → fragment → framed
client protocol → fake radio → reassemble → decrypt) by an integration test.
Airtime is its own reviewed unit (`airtime`): the Semtech time-on-air formula
under known-answer tests, and a rolling one-hour duty-cycle budget sized from
the radio's reported region (EU868/EU433/UA433/UA868 → 10 %) that refuses
over-budget sends honestly with a retry hint instead of silently hogging the
mesh. The delivery engine's mesh policies are in (§4.2 rules 2–3 of the
transport spec): the outbound queue flushes in priority order (text >
receipts > handshakes), payloads over 4 KiB are held off airtime-budgeted
links with honest feedback (`AwaitingFasterLink`, "will send when a faster
link exists") and go out the first tick a faster carrier appears, and
selective retransmission works end to end: a receiver stuck missing
fragment indices NACKs them (inside an ordinary encrypted receipt, paced to
respect airtime), and the sender retransmits exactly the missing fragments,
never the whole message. The daemon is wired: `kultd --meshtastic-serial
/dev/ttyUSB0` (or `--meshtastic-tcp host:4403`) attaches a stock radio as a
carrier (an unreachable configured radio is a hard startup error), `kult …
--mesh broadcast` sets mesh delivery hints, and an end-to-end test drives
two daemons (mDNS off, no bootstrap, mesh hints only) to verified
delivery through their RPC sockets with the (fake) radios as the sole
shared medium. Internet↔mesh bridging is in (§4.2 rule 5, mechanism in
ADR-0009): a node with both carriers forwards sealed envelopes it cannot
claim by delivery token: mesh-heard foreign traffic becomes mailbox
deposits at its configured relays (its own mailbox service deposited into
locally), internet-side deposits for unregistered tokens enter a bounded
transit buffer and are flooded over LoRa after the bridge's own traffic,
with content-id dedup, split horizon, and caps on every axis; `kultd`
bridges by default whenever a radio is attached (`--no-bridge` opts out),
and the acceptance test drives the full village topology (a mesh-only
node, an internet-only node, and a token-blind bridge between them) to
verified `delivered` states in both directions through RPC sockets alone.
The hardware-in-loop nightly is in as code: an `#[ignore]`d acceptance test
(`crates/kultd/tests/hil.rs`) drives two daemons attached to **real**
stock-firmware radios on USB-serial (mDNS off, no bootstrap, radios the
only shared medium) through handshake, delivery, receipts, and a ratcheted
reply, failing loudly (never green) on a misconfigured bench; a nightly
workflow runs it on a self-hosted bench runner, armed by the `HIL_BENCH`
repository variable so it skips cleanly until the bench exists. The bench
runbook (hardware, radio prep, runner registration, security posture) is
[10: HIL Bench](10-hil-bench.md). Remaining: standing up the physical
two-radio bench and letting the nightly measure the on-air acceptance
criteria below.

**Acceptance**:
- Two phones/laptops with stock-firmware Meshtastic radios, all other networking
  disabled, exchange verified E2EE messages multi-hop.
- Text message in the 192 B bucket fits ≤ 2 LoRa frames (measured).
- A node with both mesh and internet bridges queued traffic in both directions.
- Duty-cycle accounting respects EU868 limits (logged and enforced).

## M5: Applications (`kult-ffi`, desktop, mobile alpha) *(in progress)*

UniFFI bindings; Tauri desktop app; Android/iOS alpha shells. UX for verification
(QR safety numbers), contact requests, delivery states, transport indicators,
QR sneakernet.

The bindings layer is in: `kult-ffi` exposes exactly the node's command/event
API (implementation guide §3.5) through UniFFI proc-macros: typed records and
enums for contacts, messages, delivery states, status, and events; blocking
methods a shell dispatches off its UI thread; events pushed to an
application-registered listener on a dedicated thread. Behind the surface sits
an embedded in-process runtime (ADR-0010): one constructor opens the encrypted
store and starts the same composition `kultd` runs (internet carrier with
mDNS, DHT bootstrap and bundle publication, NAT probing with relay
reservation, mailbox check-ins, optional sneakernet spool and (feature-gated)
Meshtastic radio with bridging) so iOS/Android, where no separate daemon can
run, get the full node from a library call. Ids cross the boundary as hex
strings, prekey bundles as bytes (QR payloads), and errors verbatim, never a
fake success. The crate's e2e test drives two nodes through the public FFI
surface alone: pairing by bundle exchange, verified `delivered` states via
listener events, history, safety numbers, restart persistence, honest
errors, and `cargo run -p kult-ffi --features bindgen --bin uniffi-bindgen`
generates the Kotlin/Swift sources. Backup/restore is in (ADR-0011): one
encrypted `KKR1` file carries identity + contacts + history + session-reset
markers, sealed via Argon2id under a 24-word BIP-39 mnemonic (wordlist and
codec in-tree in `kult-crypto`, KAT-tested against the reference vectors);
ratchet sessions and prekey secrets are deliberately excluded, and a restored
node (fresh store, fresh vault, resumed identity) turns each reset marker
into a proactive OPK-less re-handshake on its first tick, so messaging
resumes in both directions without the user sending first. Exposed at every
front door: `kult backup` / `Op::Backup` (file written 0600, mnemonic shown
exactly once), `kultd --restore` on first run, and `kult-ffi`'s
`export_backup` + `restore` constructor, each pinned by its own layer's
round-trip test (store, node, RPC, FFI). The desktop app is in
(application A1, `apps/desktop`): a Tauri shell over `kult-ffi`'s embedded
runtime (the exact surface the mobile shells will consume, dogfooded on
the desktop) with a dependency-free HTML/CSS/JS frontend (no bundler, no
npm) behind a strict CSP with zero plugins or webview capabilities. It
covers the M5 UX list end to end: create/unlock/restore at the gate,
out-of-band pairing by prekey-bundle QR or pasteable hex (interoperable
with `kult bundle`/`kult add`; large bundles ride the QR alphanumeric
mode) or by kult address via DHT lookup, conversations with the node's
honest delivery ladder rendered verbatim (`queued` → `sent` → `delivered`
plus the mesh "held, will send when a faster link exists" verdict),
safety-number verification with matching digits + QR on both ends and a
visible verified badge, key-change surfacing on session re-establishment,
transport indicators (NAT verdict, mDNS LAN peers, queue and
bridge-transit depths, live listen addresses), delivery-hint editing
(multiaddr/relay/spool/mesh-broadcast), and backup export with the
mnemonic shown exactly once. Network settings persist as secret-free
`settings.json` (the same knobs as `kultd` flags, radios included). The
app is its own cargo workspace so the GUI dependency tree stays out of
the core's lockfile and cargo-deny surface (it carries its own, equally
strict deny config, and its own CI job); all shell behavior lives in a
webview-agnostic layer pinned by a two-node end-to-end test: pairing by
scanned-style hex, events as the webview receives them, verification,
and the backup → mnemonic → restore flow. The Android alpha is in
(application A2, `apps/android`): a Kotlin shell over the same `kult-ffi`
runtime, generated bindings compiled fresh from the crate at build time
(never committed). Its structure mirrors the desktop split: every
behavior lives in a plain-JVM `:core` module (session layer + bindings)
pinned by JVM tests including a two-node e2e against the host-built
library (pairing by scanned bundle hex, verified `delivered` states via
listener events, safety numbers, backup → restore → automatic
re-handshake, no emulator involved); the `:app` module is UI only. It
covers the M5 UX list: create/unlock/restore gate, pairing by camera-
scanned QR (CameraX + pure-Java ZXing, no Google services, F-Droid
friendly), pasted hex, or kult address via DHT, conversations rendering
the node's honest delivery ladder (including the mesh "held" verdict),
safety-number verification with matching digits + QR across platforms,
key-change surfacing, transport indicators, hint editing, secret-free
`settings.json` (same file format as desktop), mnemonic-shown-once backup
export with OS cloud backup disabled, and a foreground service keeping
delivery alive in the background. Native libraries cross-compile via
cargo-ndk; CI runs the `:core` e2e and assembles the debug APK. Android
sender-key group UX is also shipped: a distinct group list/create flow,
dedicated history/chat/member surface, truthful per-recipient outbound
delivery rows, and a JVM acceptance scenario with a real offline member.
The iOS alpha is in (application A2, `apps/ios`): a Swift shell over the same
`kult-ffi` runtime, generated bindings compiled fresh from the crate at
build time (never committed). Its structure mirrors the other shells'
split: every behavior lives in the `KommsCore` Swift package (session
layer + bindings) pinned by tests that run on plain Linux or macOS with
no Xcode, including a two-node e2e against the host-built library
(pairing by scanned bundle hex, verified `delivered` states via listener
events, safety numbers, backup → restore → automatic re-handshake, no
simulator involved); the SwiftUI `KommsApp` is UI only. It covers the M5
UX list: create/unlock/restore gate, pairing by camera-scanned QR,
pasted hex, or kult address via DHT, conversations rendering the node's
honest delivery ladder (including the mesh "held" verdict),
safety-number verification with matching digits + QR across platforms,
key-change surfacing, transport indicators, hint editing, secret-free
`settings.json` (same file format as the other shells), and
mnemonic-shown-once backup export via the share sheet with the data
directory excluded from iCloud backup. The sender-key group front door is
also shipped: a distinct group list/create flow, dedicated history/chat and
member-management surfaces, truthful per-recipient outbound delivery rows,
and a host acceptance scenario with a real offline member. QR rendering is
CoreImage and scanning is AVFoundation. The app has zero third-party dependencies;
the only library it links is the workspace's own Rust core, built into
`KultFFI.xcframework` by a script for device/simulator targets. CI runs
the `KommsCore` e2e on Linux (official Swift container) on every push;
a gated macOS job (`IOS_APP_CI` repository variable, mirroring the HIL
bench's arming pattern) assembles the xcframework and builds the app
for the simulator. That gated build was run locally on macOS for the
first time (Xcode 26.6, iOS 26.5): it surfaced two latent breaks in the
never-CI'd app target, a SwiftUI `Section` title-plus-footer form with no
matching initializer and a missing `SystemConfiguration.framework` link
the Rust libp2p FFI needs, both fixed, after which the simulator build
succeeds and `KommsApp` boots to its first-run gate in the simulator.
Remaining: arming that macOS job in CI, and a full hands-on pass of the
SwiftUI shell (the messaging flow end to end, and an on-device run)
beyond that first-launch smoke test; background delivery and store
distribution stay M6.

**Acceptance**: a non-technical user can install desktop + mobile builds, exchange QR
verification with a friend, and message over internet, LAN, and mesh with truthful
delivery/security indicators. Backup/restore round-trips.

## M6: Hardening & reach *(in progress)*

Sender-key groups polish → OpenMLS for large groups; censorship-resistant transports
(obfuscation, arti/Tor); multi-device (Sesame-style); panic wipe; reproducible builds;
**external security audit** of `kult-crypto` + `kult-protocol`; F-Droid and store
distribution.

Sender-key groups v1 is in through the core stack (ADR-0012, construction pinned
in [04: Cryptography §6](04-cryptography.md)): per-member forward-ratcheting
chains in `kult-crypto` with the pairwise delay-tolerance bounds, group message
bodies whose only routing metadata (`key_id ‖ iteration`) is sealed under a
members-only header key so intermediaries see uniformly random bytes, and the
single ciphertext fanned out in ordinary per-member envelopes: relays,
mailboxes, receipts, NACKs, and bridging carry group traffic without knowing it
is group traffic. Membership is creator-managed with a monotonic generation
counter; every control message is one **announce** shape (group state + the
sender's chain snapshot frozen at entitlement time) that resends on a paced
timer until the ordinary encrypted receipt acknowledges it, so an envelope lost
on a lossy carrier never leaves a member permanently deaf to a sender. Removal
re-keys the group secret and rotates every remaining chain (the removed member
gets a notice that deliberately carries nothing else); rotation also triggers
on leave, on a message-count threshold (PCS), and on restore. Backups (now
`KKR2`; `KKR1` files still restore) carry group identities and history but
never chains: a restored node announces a fresh chain, and co-members
redistribute theirs on the re-handshake, both directions pinned by the
`kult-node` e2e suite (`groups_e2e.rs`) alongside encrypt-once-on-the-wire,
per-member delivery ladders, newcomer-reads-no-history, and removed-member
exclusion. The shared front door is also in: `kultd` RPC, the `kult` CLI, and
`kult-ffi` expose group records, history, events, membership operations, and
honest per-member delivery state, pinned by `rpc_e2e.rs` and `ffi_e2e.rs`.
Desktop, Android, and iOS group UX are shipped, including truthful
per-recipient partial-delivery rows and shell-level acceptance coverage.
Remaining for groups is the M6 list above.

**Acceptance**: audit findings triaged with public report; reproducible-build attestation
for all release artifacts.

## Near horizon: real-time calls

Live voice and video calls are in scope as a near-horizon capability, strictly
confined to high-bandwidth carriers (internet libp2p and LAN/mDNS) and disabled
over any airtime-budgeted mesh link. The transport core already negotiates the
direct connections a call needs (QUIC, DCUtR hole punching), and identity keys
authenticate the peer with no central coordinator. Because this adds a real-time
media path to the transports, it is pinned by ADR-0013 (Proposed) (media
transport, metadata-blind call setup, carrier-gating rule) ahead of
implementation. Recorded
audio/video clips are already in scope as ordinary asynchronous payloads. Details
and constraints: [11: Feature Scope](11-feature-scope.md).

## Explicitly not scheduled

Cryptocurrency anything, federation with other networks, and any feature requiring
project-operated infrastructure. Each would need a compelling ADR.

For the wider product-feature triage (which messenger-app features fit the model
and under what constraints, and where each maps onto these milestones), see
[11: Feature Scope](11-feature-scope.md).
