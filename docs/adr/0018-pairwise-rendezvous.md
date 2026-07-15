# ADR-0018: Rotating pairwise rendezvous for post-pairing reachability

- **Status**: Proposed
- **Date**: 2026-07-15

## Context

Komms currently publishes signed prekey bundles under `H(IK)` in the Kademlia
DHT. That path is necessary for first contact by kult address and remains
self-authenticating, but the signed bundle can contain current delivery hints
associated with the public identity. Once two peers have an authenticated
session, they can discover each other's changing internet routes through a
pairwise capability that a public-key scraper cannot calculate.

A naive fixed slot `H(shared_secret || "locator")` is insufficient. It remains
linkable for the life of the relationship, lets the service correlate repeated
online periods, underspecifies key extraction, and gives no replay or downgrade
rules. A `GET` query also places the capability in URLs and common log paths.
The design must not reuse the existing daily delivery token: doing so would
link rendezvous activity to mailbox deposits and on-wire envelope tokens.

The service is not a mailbox. It stores no messages, prekey bundles, identity
records, notification tokens, or contact data. It only returns a short-lived,
fixed-size encrypted route record for an already paired direction.

## Decision

### 1. Rendezvous is post-pairing and direction-scoped

The DHT, direct QR/file exchange, and mesh announcements remain the ways to
obtain and authenticate an initial prekey bundle. Rendezvous capability material
is derived only after a verified PQXDH session exists and is never placed in a
public prekey bundle or kult address.

During session establishment `kult-crypto` derives a 32-byte
`hybrid_service_exporter` alongside, but not from, the mailbox key:

```text
hybrid_service_exporter = HKDF-SHA-256(
    salt = handshake_transcript_hash,
    ikm  = initial_root_key,
    info = "Komms-Hybrid-Service-Exporter-v1"
)
```

All expansions use the existing
[HKDF-SHA-256](https://www.rfc-editor.org/rfc/rfc5869.html) primitive and the
exact labels above; bare hash concatenation is not an interoperable substitute.

The exporter is stored as separately sealed service state, excluded from KKR
backups, and deleted with the contact/session. Restore or identity migration
requires a fresh authenticated handshake and exporter. A legacy session has no
implicit exporter; enabling rendezvous for it uses the existing authenticated
session to negotiate a re-handshake rather than deriving from an unauthenticated
or one-sided value.

For each recipient direction and rendezvous provider:

```text
provider_id = SHA-256(canonical_provider_origin || provider_static_key)

K_locator = HKDF-SHA-256(
    salt = provider_id,
    ikm  = hybrid_service_exporter,
    info = "Komms-Rendezvous-Locator-v1" || IK_recipient
)

K_payload = HKDF-SHA-256(
    salt = provider_id,
    ikm  = hybrid_service_exporter,
    info = "Komms-Rendezvous-Payload-v1" || IK_recipient
)

slot(epoch) = HMAC-SHA-256(
    K_locator,
    "Komms-Rendezvous-Slot-v1" || u64_be(epoch)
)

E_epoch = HKDF-SHA-256(
    salt = u64_be(epoch),
    ikm  = K_payload,
    info = "Komms-Rendezvous-Epoch-Key-v1"
)
```

An epoch is 3,600 Unix seconds. Registrations expire no later than two hours
after receipt. Clients may register and query the current and next epoch and may
query the immediately previous epoch for clock skew; no other window is valid.
Provider-specific derivation prevents two operators from comparing slot values.
Direction scoping prevents one peer's two receive directions from sharing a
slot sequence.

Both paired endpoints can calculate a direction's slot and AEAD key. A malicious
contact can therefore publish a valid value only into the unique slot used for
its own view of that recipient; it cannot poison another contact's slot. This
per-contact denial is accepted and ends when the contact is removed and the
session exporter is discarded. Adding server-visible publisher identities or
stable write keys would make epoch rotation linkable and is rejected for v1.

### 2. Route records are canonical, bounded, padded, and replay-resistant

The plaintext route record uses a fixed binary encoding with big-endian integers:

```text
version(1)         = 01
flags(1)           = 00
epoch(8)
generation(8)
issued_at(8)
expires_at(8)
route_count(1)     = 0..8
repeated route_count times:
    kind(1)        = 01 multiaddr | 02 mailbox relay
    value_len(2)   = 1..512
    value(value_len)
zero padding to exactly 4,096 bytes
```

Unused bytes must be zero and the complete plaintext is always 4,096 bytes.
Routes use the existing canonical `DeliveryHint` interpretation. Duplicate
routes, invalid UTF-8, embedded NUL, unsupported kinds, invalid multiaddresses,
more than eight routes, or trailing non-zero data fail closed. A route record
contains no public Komms identity, petname, group information, push capability,
or message state.

`generation` is a strictly increasing per `(contact, direction, provider)`
counter held in sealed core service state. `epoch` must match the queried slot,
`issued_at <= expires_at`, lifetime is at most 7,200 seconds, and a client
rejects an authenticated generation lower than the greatest it has accepted.
Generation state expires only when the corresponding epoch can no longer be
served. Wall-clock rollback never revives an expired accepted record.

The record is sealed with XChaCha20-Poly1305 under `E_epoch` and a fresh random
24-byte nonce. Associated data is:

```text
"Komms-Rendezvous-Record-v1" || provider_id || slot || u64_be(epoch)
```

The wire payload is exactly `nonce(24) || ciphertext(4,096 + 16)`. Nonce reuse
under one epoch key is forbidden. The service cannot forge or modify a record;
it can replay, replace, suppress, or return random bytes, all of which the
client handles through AEAD, generation, epoch, and expiry validation.

### 3. The HTTP surface does not reveal hit/miss through shape

The normative media type is `application/komms-rendezvous-v1`; JSON is not a
production wire format. TLS terminates in the rendezvous process, not a general
reverse proxy that logs bodies. Capabilities never appear in a URL.

```text
POST /v1/rendezvous/register
request  = slot(32) || epoch(8) || ttl_seconds(4) || sealed_record(4,136)
response = fixed 64-byte acknowledgement body

POST /v1/rendezvous/lookup
request  = slot(32) || epoch(8) || zero_pad(24)
response = sealed_record(4,136)
```

Every syntactically valid lookup returns HTTP 200 and exactly 4,136 bytes. A
miss returns fresh random bytes. The client alone distinguishes a valid record
by AEAD and semantic validation. Register responses have one fixed shape whether
the value was inserted, replaced, capped, or rejected by local capacity policy;
clients confirm success only by a subsequent valid lookup and never treat a
registration acknowledgement as reachability.

Malformed length/version requests fail before allocation with a uniform 400
body. Responses use `Cache-Control: no-store`. Compression, redirects, cookies,
authentication headers, request IDs reflected to the client, and third-party
scripts are forbidden.

### 4. Server storage and abuse controls are bounded on every axis

The primary key is the 32-byte slot; the value is the fixed sealed record plus
an absolute server receipt expiry. Storage is a fixed-capacity in-process map
or equivalently constrained RAM store with persistence, replication, snapshots,
append-only logs, swap, hibernation, and core dumps disabled. TTL is capped at
7,200 seconds and cannot be extended by a lookup. Replacement never increases
the number of records.

The service enforces global concurrent-request, record-count, memory, bandwidth,
per-slot operation, and body-size ceilings before work. Network rate limits are
adaptive signals, not the sole authorization boundary: a fixed 60-per-minute
`/24` or `/48` policy is forbidden because carrier NATs, campuses, and Tor exits
would become shared denial domains. Direct and anonymized ingress may have
different admission policies. A bounded client puzzle or anonymous admission
token may be activated under load, but it cannot encode identity and requires a
versioned extension before becoming mandatory.

Clean shutdown attempts to zero map storage. This is defense in depth, not a
claim that abrupt host seizure or termination leaves no recoverable bytes.

### 5. Clients query on demand, not once per F4 heartbeat per contact

`kult-node` retains delivery hints by source:

- manually supplied/out-of-band hints, until the user removes them;
- signed DHT bundle hints, until their signed expiry;
- rendezvous hints, until the authenticated route-record expiry; and
- LAN observations, until the existing LAN expiry.

One source never overwrites another. The node queries rendezvous only when a
peer has queued work without a fresh usable route, the user opens an active
conversation, call setup needs a fresh route, a native wake tells the recipient
to collect, or the current rendezvous record nears expiry while the app is
active. Queries use jitter, coalescing, exponential backoff, and a per-peer
single-flight guard. F4 probes the merged fresh hint set and remains advisory;
the rendezvous service never declares `realtime`, `bulk`, or delivery success.

Rendezvous configuration, exporters, generation counters, and leases are sealed
core service state. The user's mode/provider preference may use F5, but network
leases and pending operations must not be implemented as F5 UI metadata or B8
scheduled messages.

## Alternatives considered

### Static `H(shared_secret || label)` slots

Rejected. The service can link the same relationship and online pattern for its
entire lifetime, and the construction lacks provider and direction separation.

### Reuse daily mailbox delivery tokens

Rejected. Tokens are already visible in envelopes and mailbox registration.
Reuse would join otherwise separate metadata surfaces and let a relay recognize
rendezvous lookups for tokens it serves.

### Publish encrypted routes under `H(IK)`

Rejected. Encryption hides route contents but preserves a globally enumerable,
stable public-identity locator and lets observers track updates.

### Return 404 for a missing slot with a fixed delay

Rejected. Status, body length, cache behavior, server scheduling, and network
jitter still distinguish paths. An indistinguishable fixed-size dummy is simpler
and does not deliberately hold resources for a timer.

### Replace the DHT and initial invite path

Rejected. A pairwise slot does not exist before an authenticated relationship,
and making a convenience provider the first-contact authority would violate
ADR-0017.

## Consequences

- Established contacts gain private, rapidly expiring route discovery without
  exposing a public identity lookup to the provider.
- Each relationship costs multiple registrations across adjacent epochs;
  clients must stagger and coalesce work rather than burst every contact at
  launch.
- Fixed 4 KiB records trade bandwidth for bounded parsing and response-shape
  privacy. This path is internet-only and never rides an airtime transport.
- A service still observes slot activity and connection metadata; Private mode
  reduces but does not eliminate correlation.
- Existing contacts require an authenticated exporter upgrade/re-handshake, and
  restore rotates all rendezvous state just as it rotates live session state.
