# ADR-0034: Operator-minimized reference discovery

- **Status**: Accepted; reference service implemented for Beta; deployment gate open
- **Date**: 2026-07-26
- **Depends on**:
  [ADR-0017](0017-optional-hybrid-modes.md),
  [ADR-0018](0018-pairwise-rendezvous.md), and
  [ADR-0031](0031-capability-scoped-dht-discovery.md)

## Context

Ordinary users need a working default path to join the internet discovery plane.
The initial reference deployment may run on founder-operated Hetzner
infrastructure, but it must remain a replaceable convenience rather than an
identity, trust, or availability authority.

The desired deployment uses RAM-backed mutable state, receives no message
plaintext or user identity private keys, and minimizes retained metadata. Those
are valuable controls, but they have different strengths:

- end-to-end cryptography can make content decryption and accepted-record
  forgery unavailable to the service;
- client verification can make tampering detectable and rejectable;
- RAM-only state and disabled logging reduce operator retention; and
- a host administrator, cloud provider, or network observer can still inspect
  live memory, addresses, timing, volume, and availability.

A mailbox cannot use the same profile: durable delayed delivery requires
encrypted persistent custody under ADR-0032. A native-wake gateway also needs
protected durable service keys under ADR-0019.

## Decision

### 1. The first reference service has two bounded roles

The initial Standard-mode Beta deployment may provide:

1. libp2p bootstrap and an ordinary Kademlia DHT cache; and
2. the short-lived post-pairing rendezvous role in ADR-0018.

It does not provide a durable mailbox, native wake, user endpoint, account
directory, update authority, analytics service, or plaintext bridge. A later
mailbox is a separately deployed ADR-0032 service with encrypted persistent
storage. Native wake is a later separately keyed service.

The existing `kultd` endpoint container is not this service: it owns a Komms
identity and persistent encrypted database. A dedicated daemon, image, and
runbook must enforce the narrower role.

### 2. Guarantees and controls are labelled by enforcement source

| Property | Enforcement | Honest limit |
|---|---|---|
| No message/media plaintext | End-to-end envelopes and encrypted rendezvous/DHT values | The operator still sees network metadata and bounded ciphertext |
| No user Komms identity private keys | Clients never transmit them; service APIs have no field for them | Runtime TLS, libp2p, and provider service keys still exist |
| No accepted user-record forgery | Complete client-side account/device signatures and context-bound AEAD verification | The service can replay still-valid data, suppress data, or return garbage |
| Bounded record contents | Fixed-size formats, strict candidate/byte limits, capability-derived locators | The operator observes queried or stored opaque locators |
| Reduced local retention | tmpfs, short TTLs, disabled logs/swap/dumps/snapshots | This is deployment policy, not cryptographic erasure |
| Replaceability | Editable bootstrap/provider configuration and self-hosted implementation | One default can censor or degrade a user's first attempt |

Project control of official client signing and updates is a separate
supply-chain boundary. A content-blind service does not protect users if a
malicious client build exports their keys or plaintext.

### 3. Mutable service state is RAM-backed and short-lived

All DHT record cache, routing tables, rate-limit buckets, rendezvous slots,
temporary files, and application scratch state live on dedicated tmpfs mounts.
The service has:

- a read-only root filesystem and unprivileged runtime user;
- no swap or hibernation;
- core dumps, host snapshots, backups, and crash-body capture disabled;
- TLS or Noise termination in the service process rather than a logging
  reverse proxy, CDN, or WAF;
- no request/body/access logs, query identifiers, full client-address metrics,
  capability metrics, locator metrics, or distributed traces;
- aggregate-only health and capacity metrics;
- fixed request/response sizes, strict memory/concurrency/rate caps, and short
  protocol TTLs; and
- restart, clean-shutdown, crash, overload, and default-blackhole tests.

Clean shutdown performs best-effort zeroization before tmpfs teardown. Abrupt
termination, allocator copies, kernel buffers, live memory inspection, provider
telemetry, and forensic host control remain outside the guarantee.

DHT records replicate to other peers. RAM-only storage controls only the
project node's local cache; it cannot erase replicas held elsewhere before
their protocol expiry.

### 4. Service keys are distinct from user keys

“No identity private keys” means no **user Komms identity private keys**. A
stable libp2p PeerId needs a service identity key, HTTPS needs a TLS key, and
provider authentication may require other service credentials. These keys:

- are domain-separated and grant no user identity or message authority;
- are stored separately from mutable runtime state;
- have documented rotation, revocation, and compromise procedures; and
- are never reused as offline directory-signing or software-release keys.

The directory and release signing keys remain offline. A compromised runtime
service key may impersonate or disrupt that service, but cannot forge a
client-accepted account record or decrypt messages.

### 5. The first Hetzner deployment is Standard Beta evidence

The operator publishes the administrative domain, hosting provider, enabled
roles, source revision, image digest, configuration, retention policy, service
key fingerprints, uptime history, and material incidents. The deployment is
explicitly a founder-operated convenience default.

It does not demonstrate:

- Private-mode non-collusion;
- plural independent infrastructure;
- anonymity from Hetzner or a network observer;
- durable mailbox delivery;
- forensic erasure; or
- inability of the operator to log, suppress, correlate, or selectively deny
  requests after changing the deployment.

Private mode requires non-colluding administrative domains and never
co-locates its OHTTP ingress with the protected gateway while claiming that
property.

### 6. Clients retain sovereign alternatives

The default provider list is signed and versioned but user-editable. A client
can add manual/community bootstrap peers, replace the reference rendezvous,
disable it, or use direct QR/file/LAN/mesh/sneakernet paths. The implementation
retains the last valid configuration and never removes sovereign routes because
the project service or directory is unavailable.

Acceptance blackholes the project domain and proves alternate bootstrap,
self-hosted replacement, and pure-core operation. A second independently
operated service is required before any plural-operator claim.

## Alternatives considered

### Run every server role on one RAM disk

Rejected. Mailbox custody and native-wake service keys have durability
requirements that conflict with a fully ephemeral host.

### Use the existing full `kultd` container

Rejected for this claim. It is an identity-bearing endpoint with a persistent
database and passphrase, not a least-authority discovery/rendezvous service.

### Claim that root cannot behave maliciously

Rejected. A root operator can replace code, inspect live state, log traffic, or
deny service. The design removes message-decryption and accepted-record-forgery
capabilities, minimizes everything else, and publishes the residual trust.

### Make the project service mandatory

Rejected. It would turn founder-operated infrastructure into a first-contact
availability authority and contradict the server-independent core.

## Consequences

- The project can provide a practical ordinary-user default without possessing
  message plaintext or user identity keys.
- A dedicated service binary and deployment profile must be implemented before
  making the RAM-only claim.
- Operator minimization, reproducible artifacts, public configuration, and
  incident transparency supplement cryptography; they do not become
  cryptographic guarantees.
- Durable mailboxes, native wake, Private-mode non-collusion, and plural
  operation remain separate qualification tracks.

## Implementation status

The dedicated `kult-reference-service` crate, pinned image, strict versioned
configuration, hardened Compose profile, smoke path, and operator runbook
implement the two-role boundary locally. The DHT store admits only bounded
Komms discovery namespaces and the rendezvous listener terminates TLS 1.3 in
process with canonical fixed-shape HTTP. Both roles retain mutable state only
in memory and expose aggregate loopback health.

No reference service is deployed and no default provider record has changed.
Deployment, real-host hardening evidence, public uptime/incident history,
default blackhole/replacement journeys, independent operation, and external
review remain open evidence gates.
