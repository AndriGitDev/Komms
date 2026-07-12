# 08 — Roadmap

Milestones are strictly ordered by dependency; each has acceptance criteria that gate the
next. Build order details per crate: [09 — Implementation Guide](09-implementation-guide.md).

## M0 — Design framework *(done)*

**Deliverable**: the documentation set in `docs/` — threat model, architecture, crypto
spec, transport spec, identity model, storage model, ADRs, implementation guide.

**Acceptance**: docs internally consistent; every architectural decision has an ADR;
implementation guide sufficient for a competent Rust developer (or coding agent) to start
M1 without design questions.

## M1 — Cryptographic core (`kult-crypto`) *(done)*

Workspace scaffolding + the full crypto layer: primitives wiring, hybrid PQXDH handshake,
Double Ratchet with header encryption, fingerprints, key serialization.

**Acceptance**:
- All test obligations of [04 — Cryptography §11](04-cryptography.md) green in CI
  (KATs, ratchet property tests, fuzz targets running, `cargo-deny` clean).
- `#![forbid(unsafe_code)]`; every secret type zeroizes; API compiles as `no_std`+alloc.
- Two in-memory parties complete handshake and exchange 10 000 messages under random
  loss/reorder within `MAX_SKIP`.

## M2 — Protocol & storage (`kult-protocol`, `kult-store`) *(done)*

Envelope codec, padding buckets, fragmentation/reassembly, delivery tokens, sealed
sender; encrypted SQLite storage with the full key hierarchy; sneakernet bundle
import/export (first working transport, needs no networking).

**Acceptance**:
- Two nodes exchange messages via **bundle files** end-to-end (write → export → import →
  read), surviving process restarts (queue persistence).
- Fragmentation round-trips at MTU 180 B with 30 % random fragment loss via NACK/retry.
- Fuzzers on envelope + bundle parsers; storage passes "copied DB file leaks nothing but
  sizes" review checklist.

## M3 — Internet transport & headless node (`kult-transport`, `kult-node`) *(done)*

The `kult-node` runtime is implemented per the build order in
[09 — Implementation Guide §2](09-implementation-guide.md): delivery engine
(queued→sent→delivered on encrypted receipts, retry with backoff, dedup,
out-of-order stash), transport scheduler, session lifecycle, command/event API —
running over the sneakernet carrier. The libp2p carrier's first slice is also in:
QUIC (primary) and TCP+Noise+Yamux (fallback) with an envelope request-response
protocol reporting honest next-hop acks; two nodes exchange messages and receipts
over localhost, and the scheduler prefers it over slower carriers. The discovery
plane is in: a Kademlia DHT (bootstrap from any user-supplied peer — nothing
hardcoded) carrying whole-bundle-signed prekey records under the kult-address
digest, so a node adds a contact from the address string alone and the delivery
engine resolves missing return paths (sealed sender reveals none) from the
peer's record. Mailbox relays are in: any node can volunteer bounded
store-and-forward on `/kommskult/mailbox/1`; recipients register rotating
delivery tokens as accept-filters and collect on reconnect, senders deposit
sealed envelopes the scheduler ranks below direct paths, and the "relay stores
only sealed envelopes" acceptance criterion is pinned by an inspection test
(collection-deletes required making tokens recipient-scoped — ADR-0007).
NAT traversal is in as the pinned trio: AutoNAT dial-back probes report each
node's reachability (`nat_status`), a private node reserves a Circuit Relay v2
slot at any public peer (`reserve_relay` — every node volunteers bounded relay
service, and a fresh relay self-confirms its own address via AutoNAT seconds
after its first peer connects), the returned circuit address is handed out as
an ordinary multiaddr hint, and DCUtR upgrades relayed connections to direct
ones by hole punching. The headless daemon is in: `kultd` (its own crate,
application A3) runs the full node over the internet carrier — tick loop,
DHT bootstrap and bundle publication, automatic NAT probing with relay
reservation, mailbox check-ins, optional mailbox serving and sneakernet
spool — and exposes the node's command/event API as newline-delimited JSON
RPC on a mode-0600 local Unix socket, with `kult` as the matching CLI
client; the RPC acceptance test drives two daemons to verified delivery
through their sockets alone. mDNS LAN auto-discovery closes out M3: since
`libp2p-mdns` still pins the RUSTSEC-flagged `hickory-proto 0.25` (and this
workspace ignores no vulnerabilities), the libp2p mDNS discovery profile is
implemented in-tree (ADR-0008) — a strict, bounded DNS responder whose
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

## M4 — Off-grid: Meshtastic bridge *(in progress)*

BLE + USB-serial Meshtastic client integration, private app port, runtime MTU
computation, priority classes, selective retransmission, internet↔mesh bridging.

The carrier core is in: `MeshtasticTransport` (behind the `meshtastic` feature
of `kult-transport`) speaks the standard client protocol to a stock-firmware
radio over any byte stream — USB-serial, TCP, or an in-memory duplex in tests —
via the official `meshtastic` crate (the published protobuf definitions through
a generated client, per the implementation guide). Sealed envelopes ride the
private application port; the frame budget is the protobuf-pinned 233-byte
`Data.payload` cap, so the delivery engine's existing fragmentation path needs
no mesh-specific logic, and a ratcheted 192-bucket text message crosses the
mesh in ≤ 2 LoRa frames — pinned end-to-end (encrypt → fragment → framed
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
selective retransmission works end to end — a receiver stuck missing
fragment indices NACKs them (inside an ordinary encrypted receipt, paced to
respect airtime), and the sender retransmits exactly the missing fragments,
never the whole message. The daemon is wired: `kultd --meshtastic-serial
/dev/ttyUSB0` (or `--meshtastic-tcp host:4403`) attaches a stock radio as a
carrier (an unreachable configured radio is a hard startup error), `kult …
--mesh broadcast` sets mesh delivery hints, and an end-to-end test drives
two daemons — mDNS off, no bootstrap, mesh hints only — to verified
delivery through their RPC sockets with the (fake) radios as the sole
shared medium. Internet↔mesh bridging is in (ADR-0009): bridge mode is an
opt-in destination-blind forwarder — envelopes that provably aren't the
node's own (unknown delivery token, unopenable handshake) are forwarded
once to each configured hint (mesh broadcast on the radio side, mailbox
relays on the internet side; `kultd --bridge-mesh` / `--bridge-relay`),
bounded, own-traffic-first, with the airtime ceiling applied to third-party
bytes too — and the village topology (radio-only node ↔ bridge ↔
internet-only node) is pinned by a test carrying handshake, message,
receipt, and reply across both directions while the bridge holds zero
contacts or sessions. Remaining: the hardware-in-loop nightly.

**Acceptance**:
- Two phones/laptops with stock-firmware Meshtastic radios, all other networking
  disabled, exchange verified E2EE messages multi-hop.
- Text message in the 192 B bucket fits ≤ 2 LoRa frames (measured).
- A node with both mesh and internet bridges queued traffic in both directions.
- Duty-cycle accounting respects EU868 limits (logged and enforced).

## M5 — Applications (`kult-ffi`, desktop, mobile alpha)

UniFFI bindings; Tauri desktop app; Android/iOS alpha shells. UX for verification
(QR safety numbers), contact requests, delivery states, transport indicators,
QR sneakernet.

**Acceptance**: a non-technical user can install desktop + mobile builds, exchange QR
verification with a friend, and message over internet, LAN, and mesh with truthful
delivery/security indicators. Backup/restore round-trips.

## M6 — Hardening & reach

Sender-key groups polish → OpenMLS for large groups; censorship-resistant transports
(obfuscation, arti/Tor); multi-device (Sesame-style); panic wipe; reproducible builds;
**external security audit** of `kult-crypto` + `kult-protocol`; F-Droid and store
distribution.

**Acceptance**: audit findings triaged with public report; reproducible-build attestation
for all release artifacts.

## Explicitly not scheduled

Voice/video calls, cryptocurrency anything, federation with other networks, and any
feature requiring project-operated infrastructure. Each would need a compelling ADR.
