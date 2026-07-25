# ADR-0025: Optional epoch-scoped Freenet carrier

- **Status**: Proposed
- **Date**: 2026-07-25

## Context

Komms already carries the same padded sealed envelope over direct libp2p,
recipient-selected mailboxes, LAN, Meshtastic, and sneakernet. The
`kult-transport` boundary deliberately keeps plaintext, identity secrets,
ratchet state, and delivery truth out of every carrier. Adding another
store-and-forward network should therefore extend that boundary rather than
replace the cryptographic protocol, encrypted local store, native shells, or
existing delivery paths.

The current Freenet project exposes a replicated application model built from
[contracts](https://freenet.org/build/manual/components/contracts/), local
[delegates](https://freenet.org/build/manual/components/delegates/), and
browser-delivered user interfaces. Contract state is application-defined,
validated by WebAssembly, synchronized through deterministic summaries and
deltas, and readable by peers that retrieve or host it. Subscriptions can make
state changes available promptly, making a bounded ciphertext inbox a plausible
Komms carrier.

Freenet is not merely another point-to-point socket. Contract state must merge
deterministically, contract identifiers depend on exact code and parameters,
and network retention is not recipient-controlled deletion. Freenet's own
[River threat disclosure](https://freenet.org/river/) says that room existence,
size, and message timing remain observable. Its current
[public quickstart](https://freenet.org/quickstart/) is desktop-only, and
delegate cross-device synchronization is not yet available. A direct port of
the full Komms runtime into contracts, delegates, and a browser UI would also
replace the reviewed SQLite, UniFFI, native-shell, transport-scheduler, and
linked-device boundaries rather than reuse them.

The decision needed now is whether and how to investigate Freenet without
making it an availability authority, weakening sealed-sender claims, or
presenting an alpha external network as suitable for high-threat use.

## Decision

### 1. Freenet is an optional carrier, not the Komms backend

Komms will investigate a feature- and configuration-gated Freenet carrier
behind the existing `Transport` contract. It is disabled by default and may be
enabled or removed without rotating a Komms identity, migrating local history,
changing message encodings, or disabling any existing carrier.

The native Komms process talks to a user-installed or explicitly bundled local
Freenet Core through its supported local API. Freenet Core is another local
runtime dependency, not a trusted Komms service. A future browser-distributed
Komms UI or Freenet delegate port is a separate product decision and cannot be
introduced as an implementation detail of this carrier.

The carrier handles durable sealed envelopes and their encrypted receipts. It
does not carry C7 live-call media, claim direct reachability, replace DHT/QR
first-contact discovery, or reinterpret a Freenet subscription or update
acknowledgement as end-to-end delivery.

### 2. Inbox contracts are per endpoint, direction, and bounded epoch

There is no permanent public Freenet inbox for an account, contact, or
conversation. An inbox instance is scoped to:

- one exact sending physical device;
- one exact receiving physical device;
- one direction; and
- one bounded time epoch.

For ordinary post-handshake epochs, the two authenticated Komms endpoints
derive the opaque contract parameters and epoch-scoped write capability from
pairwise mailbox material under a new domain-separated KDF. The resulting
parameters contain only a random-looking slot value, protocol version, epoch
class, strict capacity class, and an unlinkable capability verification key.
They contain no Komms account key, device certificate, contact name, group id,
kult address, delivery token, or network address.

The write capability authorizes admission to one contract instance; it does
not authenticate a Komms message or peer. The ordinary PQXDH/Double Ratchet
path remains the only message authentication boundary. Compromise of a slot
capability can fill, fork, reorder, or observe that carrier slot but cannot
decrypt content, forge an accepted Komms message, or produce its encrypted
delivery receipt.

The exact epoch duration and capacity classes remain prototype measurements,
not constants chosen in this ADR. They must cover realistic offline windows
without producing a durable cross-epoch identifier. Clients derive a bounded
look-behind and look-ahead window, stop publishing to expired epochs, and stop
subscribing after a documented grace period. Local expiry never claims that
every Freenet peer erased an older contract state.

### 3. Contract state is a bounded authenticated set of opaque records

Contract state is a canonical bounded map from one monotonically increasing
writer sequence to one record. Each record contains only:

- a carrier-record version and capacity class;
- the epoch-local writer sequence;
- a bounded padded sealed Komms envelope;
- the envelope digest used for carrier-level deduplication;
- the envelope's already permitted coarse retention bucket, when present; and
- a signature from the epoch write capability over the complete record and
  contract parameters.

For a conflicting authorized fork at one sequence, the lexicographically lower
complete record digest is the deterministic winner. Merge unions both maps,
applies that winner rule, and retains only the capacity class's highest
sequences. This makes merge commutative, associative, and idempotent while
ensuring two individually valid full states still produce a valid bounded
state. A compromised writer can skip forward and evict its own older carrier
records, but the sender's ordinary durable Komms queue retains every
unreceipted ciphertext and can retry it in a later epoch or over another
carrier.

Validation rejects unknown versions, invalid signatures, parameter mismatch,
oversized records, out-of-capacity or non-canonical states, digest mismatch,
and non-canonical ordering. A Freenet contract does not treat wall clock as a
trusted input: the sender refuses to publish already expired envelopes, the
receiver refuses them before ordinary processing, and epoch rotation bounds
new use, but remote peers may retain old ciphertext. The contract never
decrypts an envelope, evaluates Komms identity, or decides which record is
delivered.

One capability writer per endpoint/direction/epoch avoids an unauthenticated
public append surface and maps concurrent linked devices to separate contracts.
Deterministic byte and record ceilings limit a compromised authorized writer.
The prototype must still model contract-key discovery, subscription abuse,
state amplification, replay, divergent-state merge, and malicious hosting
peers before selecting capacities.

Acknowledgements are not mutable flags in the inbox contract. The receiver
feeds every new record into the ordinary Komms receive path; deduplication,
decryption, persistence, and an encrypted receipt proceed unchanged. That
receipt travels as another sealed envelope over any eligible reverse carrier.
The sender retains its durable queue until that receipt arrives or the normal
30-day failure policy expires.

### 4. Pairing can convey a bounded bootstrap descriptor

Freenet does not replace kult-address DHT lookup or public prekey publication.
For a physical QR/paste pairing where Freenet is the only shared online
carrier, the recipient may include one signed, bounded bootstrap descriptor in
the existing pairing bundle. The descriptor identifies only the current
recipient-device ingress epoch and its capability material; it is authenticated
by the existing pairing bundle and is not a stable public address.

After the first authenticated exchange, endpoints derive and rotate their
ordinary per-device, per-direction epochs inside the encrypted session. A
Freenet descriptor learned from an unsigned network record never establishes a
contact, changes verification, or replaces a signed delivery hint.

### 5. Attachments use ordinary fragmentation and stricter quotas

The first desktop spike carries text-sized envelopes only. A later alpha may
carry attachment chunks only through the existing encrypted attachment and
fragmentation pipeline, under a carrier MTU and aggregate contract quota
selected from measured Freenet behavior.

No attachment plaintext, filename, media type, preview, manifest key, or
conversation identifier enters contract state. Oversized media remains queued
for a faster carrier with honest UI rather than expanding a Freenet inbox
without bound. C7 live-call media is permanently excluded from this carrier.

### 6. Metadata exposure is explicit and carrier-specific

Freenet adds availability and routing diversity; it does not add a Komms
anonymity guarantee. Depending on network position and use, an observer may
learn:

- that a Freenet contract exists and is retrieved or updated;
- padded record sizes, state size, update timing, and coarse activity volume;
- the network address and behavior of its immediate Freenet peers; and
- correlations caused by repeatedly accessing related contracts or running
  Komms and Freenet together.

Epoch-scoped unlinkable contracts reduce stable application-layer linkage but
do not defeat timing analysis, a global observer, a compromised endpoint, or a
peer that correlates network traffic. Product UI must label the carrier
**Experimental**, expose whether it is enabled and connected, and link to this
disclosure. It must not describe Freenet as anonymous, metadata-free, audited
for Komms, or appropriate for sensitive use merely because content remains
encrypted.

Freenet Core telemetry, update behavior, peer selection, local API exposure,
and packaging become part of Komms qualification when bundled or recommended.
The carrier cannot silently enable external telemetry, widen a local API beyond
loopback, or inherit an auto-update policy without a separate reviewed
distribution decision.

### 7. Contract and delegate evolution is release work

Freenet derives a contract identifier from the exact WebAssembly and
parameters. Before a public carrier contract is durable, its crate must have a
separate pinned lockfile and toolchain, reproducible build inputs, committed
artifact hashes, and a CI guard that requires registration of every predecessor
code hash.

For every still-live epoch, clients probe the current contract code and the
bounded registered predecessor lineage during an upgrade grace window. State
is accepted only after the current validator revalidates every record. If a
future delegate stores Komms-derived secrets, its first public version must
ship a fail-closed export/migration handler; this carrier ADR does not authorize
moving Komms identity or ratchet secrets into a delegate.

These requirements follow Freenet's documented
[contract and delegate upgrade model](https://freenet.org/build/manual/upgrading-contracts/).
An application update that strands unread envelopes or silently rotates an
inbox is a release-blocking failure.

### 8. Failure collapses to the existing Komms core

Freenet API errors, subscription loss, unavailable contracts, incompatible
Core versions, quota exhaustion, invalid states, and complete network
blackholing produce bounded retry and an honest carrier status. They do not
erase the durable Komms queue, advance `sent` beyond the transport's real
next-hop evidence, advance `delivered`, rotate identity, or prevent another
carrier from being scheduled.

Fresh user actions retain priority over Freenet subscription and retry
maintenance. Disabling the carrier removes its active subscriptions and local
capability cache after confirmation but preserves ordinary queued envelopes for
other paths. Uninstalling Freenet Core cannot make Komms history or keys
unreadable.

### 9. Adoption is gated in phases

The ADR remains Proposed while the architecture is reviewed. Acceptance of the
ADR permits only a desktop research implementation:

1. **Local spike**: two native Komms test nodes and two separate local Freenet
   Core instances exchange text-sized sealed envelopes and encrypted receipts.
2. **Adversarial contract tests**: validation, merge, replay, capacity,
   predecessor, malformed-state, and retention behavior are property-tested
   and fuzzed.
3. **Failure qualification**: restart, offline store-and-forward, duplicate
   subscription events, Core upgrade mismatch, API loss, quota exhaustion, and
   total Freenet blackhole preserve queue truth and fallback.
4. **Metadata review**: packet/contract observations document actual identifiers,
   state shape, timing, local API behavior, telemetry, and update behavior.
5. **Desktop experimental alpha**: explicit opt-in, status/disclosure UI,
   reproducible contract artifact, and independent local build instructions.

Android and iOS integration waits for a supportable Freenet mobile Core,
background-execution evidence, bounded battery/storage measurements, and the
ordinary Komms simulator plus human visual gates. Production or high-threat
recommendation additionally requires public-network operational evidence and
an independent review covering the contract, adapter, metadata model, and
Freenet-specific supply chain.

## Alternatives considered

### Rewrite Komms as a Freenet contract, delegate, and browser UI

Deferred. It could eventually create a native Freenet edition, but today it
would replace the encrypted SQLite, native shell, UniFFI, transport scheduler,
linked-device, off-grid, and direct-call boundaries. It also inherits current
desktop-only distribution and delegate migration/synchronization limitations.

### Use one permanent inbox contract per Komms account

Rejected. It creates a stable recipient handle, links contacts and devices,
centralizes spam pressure, and makes activity correlation substantially easier.

### Use one shared contract per conversation or group

Rejected for the first carrier. Shared room state exposes a stronger common
activity shape and does not map cleanly to Komms' independently encrypted
per-device delivery rows, sealed-sender fan-out, and end-to-end receipts.

### Publish Freenet hints in the public DHT prekey record

Rejected as the default. A long-lived public mapping would connect a kult
address to Freenet contract activity. A bounded signed bootstrap descriptor may
travel in an explicitly exchanged pairing bundle instead.

### Treat Freenet state synchronization as message delivery

Rejected. A hosting peer or local Core accepting state proves neither endpoint
decryption nor durable recipient persistence. Only the existing encrypted Komms
receipt advances `delivered`.

### Store acknowledgements or deletion markers in the same inbox

Rejected. Mutable status increases correlation and merge complexity without
improving delivery truth. Receipts and local queue expiry already provide
authenticated bounded lifecycle semantics.

### Send large attachments and call media through Freenet immediately

Rejected. Unmeasured large-state behavior could reproduce the attachment
latency and resource problems this carrier is meant to avoid. Calls require the
existing direct authenticated QUIC path.

## Consequences

- Komms gains a plausible decentralized global store-and-forward path without
  depending on project-operated infrastructure.
- Existing crypto, storage, queue, linked-device, UI, and multipath behavior
  remain authoritative; Freenet integration is narrow and removable.
- Per-endpoint directional epochs create more contracts and subscription work
  than a permanent inbox, trading efficiency for metadata minimization and
  bounded compromise.
- Freenet becomes part of the dependency, packaging, supply-chain, telemetry,
  update, resource, and compatibility review for users who enable it.
- Contract ciphertext may persist on remote peers beyond local queue expiry;
  Komms can stop addressing and subscribing to an epoch but cannot promise
  global erasure.
- Full Freenet-native UI/delegate reuse remains possible later, but it requires
  its own ADR and cannot silently weaken the native high-threat boundary.
- The decision must be revisited if Freenet cannot support bounded private
  capability writes, deterministic state convergence, reliable subscriptions,
  reproducible upgrades, acceptable metadata, or a supportable mobile Core.
