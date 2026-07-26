# ADR-0031: Capability-scoped DHT first-contact discovery

- **Status**: Proposed
- **Date**: 2026-07-26

## Context

The current DHT key is a stable hash of the account identity. Its signed value
is plaintext and may contain every current direct address and mailbox route.
Anybody who learns an account address can poll that stable key and recover an
identity-to-route timeline. Rotating a locator derived only from the public
identity changes the key but not that capability: every address holder can
derive the same rotation.

Komms must retain DHT first contact and offline mailbox reachability without
making a public identity fingerprint a permanent global route lookup. Normal
users should still scan, tap, or paste one familiar connect artifact; the
network mechanism remains hidden.

## Decision

### 1. Identity and discovery capability are separate

The existing account fingerprint remains the stable identity and safety-number
input. A new versioned **Connect code** additionally carries a random 32-byte
discovery capability and checksum. The capability is generated locally, stored
sealed, included in encrypted recovery, and normally exchanged by QR, link, or
file rather than typed.

The capability is a bearer reachability secret, not an anonymity promise.
Publishing a Connect code publicly intentionally makes that identity publicly
contactable. It can nevertheless be rotated without changing identity or
safety numbers.

### 2. Weekly DHT locators are capability-derived

For weekly epoch `e`:

```text
locator(e) = HMAC-SHA-256(
  discovery_cap,
  "Komms-DHT-Locator-v2" || u64_be(e)
)
```

The record key is `/kk/prekeys/2/ || locator(e)`. A distinct HKDF-SHA-256 key
derived from the capability, locator, and domain seals the value with
XChaCha20-Poly1305. Identity hashes, delivery tokens, mailbox keys, and
post-pairing rendezvous exporters are never reused for this purpose.

For `e = floor(unix_time / 604800)`, clients publish exactly epochs
`e-1..=e+4`: one previous grace record, the current record, and four future
records. A record is client-valid only from 24 hours before its encoded epoch
through 24 hours after that epoch ends. A lookup tries only its local epoch and
the adjacent epoch on either side, so one operation requests at most three
locators.

Daily jittered maintenance republishes the six-record window and republishes
immediately after prekey, device-authority, admission-policy, mailbox, or
capability changes. DHT record TTL must preserve a future record through its
encoded validity end. The four-week offline publication promise is qualified by
DHT availability: malicious peers may still suppress a record, and a client
uses introduction mailboxes, alternate bootstrap peers, or out-of-band exchange
when lookup fails.

### 3. Records are fixed-size, signed, and bounded

Every v2 value has one exact outer size and binds:

- record version, locator, epoch, generation, issue and expiry time;
- account identity and the accepted ADR-0026 device-authority proof;
- at most two bounded ingress-device prekey bundles;
- at most three introduction-mailbox routes;
- the ADR-0030 admission descriptor; and
- zero padding plus an account/device-authority signature over the complete
  canonical record digest.

The exact size and authority encoding are frozen only after ADR-0026 is
accepted. Records carry no one-time prekey, detailed feature fingerprint, local
path, mesh node, spool path, or unrestricted address list.

Kademlia peers cannot validate the sealed inner record. For each locator, a
lookup retains at most eight distinct candidate values and at most eight times
the frozen record size before decrypting or verifying. It rejects wrong-sized,
wrong-locator, expired, unauthenticated, or invalid-authority candidates without
mutating identity/session state. Among valid records it selects the highest
authority generation, then newest issue time, then smallest record digest.
Invalid candidates crowding out a valid value produce an unavailable lookup,
never acceptance of attacker state.

Publishers store the same current record with multiple closest peers and query
through more than one bootstrap/routing path. Those measures improve
availability but cannot prevent an adversarial DHT region from overwriting,
eclipsing, delaying, or suppressing a record.

### 4. Public and relationship routes are different products

Standard and Private modes publish only recipient-selected introduction
mailboxes in public DHT records. Direct IP, LAN, relay-circuit, mesh, and spool
routes may appear in context-specific QR/file pairing or in authenticated
post-pairing route updates and ADR-0018 rendezvous.

Sovereign mode may expose an explicit advanced switch to publish a direct
route, with a warning that every Connect-code holder can poll it. A default
consumer build never silently publishes one.

After pairing, ordinary failed sends do not return to identity-indexed public
DHT lookup. They use stored mailboxes, authenticated route updates, optional
pairwise rendezvous, and the ordinary transport fallback ladder. Group state
distributes member connection capabilities through authenticated group
control; identity alone no longer implies global resolvability.

### 5. Offline introductions use a separate capability

A distinct HKDF key derived from the discovery capability creates rotating,
device-scoped introduction mailbox tokens. A Connect-code holder can address a
bounded provisional request; somebody holding only the public identity
fingerprint cannot.

Recipients pre-register the bounded future token window at their chosen
mailboxes. Deposits enter ADR-0030's message-request flow and ADR-0032's leased
mailbox protocol. Native wake remains post-pairing unless a separate
capability-gated introduction-wake decision is accepted.

### 6. Migration is explicit

New clients accept both Connect-code v2 and legacy account addresses. Existing
identities generate a capability without changing identity. During a
time-bounded Alpha migration they may dual-publish:

- capability-scoped v2 records; and
- legacy v1 records containing mailbox-only routes, never direct IP.

New identities publish only v2. Existing paired contacts receive the
capability and routes through an authenticated upgrade. Existing groups receive
them through authenticated group control.

There is no v1 redirect containing the new capability: publishing it below the
stable identity key recreates the tracking oracle. A printed legacy account
address must be replaced with a Connect code or knowingly retain legacy
reachability.

## Alternatives considered

### Rotate or encrypt records using only the public identity

Rejected as the final design. It reduces blind crawling but every address
holder can still calculate and poll the record, and the capability cannot be
rotated independently.

### Remove the DHT and require a project directory

Rejected. It creates a first-contact authority and violates the replaceable
core architecture.

### Publish direct routes everywhere for convenience

Rejected. Introduction mailboxes can provide offline first contact without
turning the public discovery record into a current-IP oracle.

## Consequences

- DHT first contact remains a core protocol role; normal users see a Connect
  code rather than DHT terminology.
- Identity fingerprints and safety numbers remain stable.
- Public Connect codes remain trackable by their holders, and DHT peers may
  observe publisher/query network metadata unless another transport hides it.
- RAM-backed operation affects only one node's local cache. Records are
  replicated to other DHT peers and may survive there until network expiry.
- Backup, linked-device, group, daemon, FFI, QR, and compatibility formats
  change before wire v1.
- Acceptance requires fixed-record vectors, epoch/clock tests, capability
  rotation/revocation, mailbox-offline tests, invalid-candidate crowding,
  overwrite/flood/suppression, multi-bootstrap recovery, bounded DHT
  storage/query behavior, and proof that Standard/Private records contain no
  direct route.
- The project-operated reference deployment is separately bounded by
  [ADR-0034](0034-operator-minimized-reference-discovery.md).
