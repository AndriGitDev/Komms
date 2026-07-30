# ADR-0018: Rotating pairwise rendezvous for post-pairing reachability

- **Status**: Accepted; implemented for Alpha
- **Date**: 2026-07-15

## Context

Komms currently publishes signed prekey bundles under `H(IK)` in the Kademlia
DHT. That path is necessary for first contact by kult address and remains
self-authenticating. A public bundle may contain recipient-selected
mailbox/relay introduction paths, but ADR-0017 no longer permits Standard or
Private mode to publish a current direct IP route under the stable account
lookup by default. Sovereign users may make that explicit tradeoff. Once two
peers have an authenticated session, they can discover each other's changing
internet routes through a pairwise capability that a public-key scraper cannot
calculate.

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

The device first-flight wrapper is versioned as `KDI2` and carries one of three
session intents:

- `Establish` has no predecessor. If both devices establish concurrently, the
  lower immutable physical-device id's locally initiated flight wins. The
  retaining side still authenticates and persists the other first payload and
  returns its end-to-end acknowledgement over the winning ratchet; the other
  side installs that same winning ratchet. Queued ciphertext bound to the
  losing ratchet is deleted in that installation transaction, and each exact
  nonterminal device-delivery promise returns to `Queued` with no wire id so a
  later bounded pass encrypts it on the winner. This is session convergence,
  never an account-authority or manifest fork tiebreaker.
- `Replace(prior_session_id)` is accepted only when the exact transcript-bound
  predecessor is still current. A stale, reordered, or replayed replacement
  fails closed.
- `Reset` identifies a sender-side durable session-reset/recovery path and
  installs only after the ordinary device certificate and accepted authority
  chain verify.

Released `KDI1` flights remain decodable as an explicit legacy intent. They do
not gain a synthetic exporter or predecessor binding.

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
- Standard first contact normally reaches a recipient-selected
  mailbox/introduction path from the signed DHT bundle; rendezvous becomes
  available only after that first authenticated handshake.
- Each relationship costs multiple registrations across adjacent epochs;
  clients must stagger and coalesce work rather than burst every contact at
  launch.
- Fixed 4 KiB records trade bandwidth for bounded parsing and response-shape
  privacy. This path is internet-only and never rides an airtime transport.

## Implemented Alpha profile

The verified PQXDH transcript now derives the exporter exactly once beside the
mailbox key. Ratchet serialization deliberately omits it. `kult-store` keeps
the exporter, session id, provider roles, generations, clock floor, route
source, retry state, and conflict floors in a separate store-v2 row; routine
backup never encodes that row. Removing a session or device removes the
corresponding service authority. A restored or legacy ratchet without this row
cannot synthesize an exporter: an authenticated provider control may request a
fresh PQXDH exchange, and rendezvous remains disabled until both endpoints
complete that exchange.

`kult-crypto` implements the provider/recipient/epoch-separated schedule and
fixed XChaCha20-Poly1305 protection. `kult-protocol` owns the strict 4,096-byte
route record, 4,136-byte seal, 4,180-byte register request, 64-byte lookup
request, 64-byte register response, and fixed malformed response codecs.
Decoders reject invalid versions, lengths, bounds, route ordering, duplicate
routes, non-canonical routes, non-zero padding, and invalid time/generation
state without variable-size allocation.

The dedicated `kult-rendezvous` component is an in-memory, persistence-free
service boundary, not an identity-bearing endpoint or mailbox. It enforces
explicit record, accounted-memory, concurrency, global operation/byte,
per-slot, client-bucket, bucket-count, epoch, TTL, and bounded-expiry-sweep
limits. Valid hits, misses, capacity refusal, overload, and rate refusal retain
the same success status and body shape. A register acknowledgement is random
and becomes locally confirmed only after a self-lookup returns the exact
authenticated record. Mutable ciphertext and opaque admission keys are
zeroized on orderly teardown. The HTTPS/TLS process wrapper, image, and
deployment hardening remain the separate ADR-0034 reference-service work.

Recipient-selected provider sets are complete authenticated pairwise controls
bound to the sender account, certified device, device-authority generation, and
their own monotonic generation. The complete local set is sealed separately
and survives restart; rollback and same-generation replacement fail closed.
Two different authenticated complete remote sets at one generation disable all
lookup roles, clear their routes, emit a visible conflict, and remain disabled
across restart until a strictly newer set arrives. Likewise, two different
valid route records at one generation clear that provider source and establish
a durable conflict floor; ordering never chooses authority.

`kult-node` retains manual, authenticated discovery, LAN, and rendezvous routes
as independent sources. It registers current and next epochs and queries only
previous/current/next. Work begins only for queued content lacking a fresh
route, an explicit active-conversation request, direct-call setup, or
near-expiry active state. Per-device/provider single-flight keys, coalescing,
initial jitter, exponential backoff, an operation/time budget, and a
five-failure circuit breaker bound hostile or unavailable providers. RPC,
UniFFI, desktop, Android, and iOS expose only bounded refresh and foreground
conversation-state controls plus a visible conflict; no surface treats service
processing as registration, reachability, sent, or delivered.

### Compact normative vector

The in-tree known-answer test fixes these inputs:

| Field | Value |
|---|---|
| Recipient identity seed | 64 bytes of `01` |
| Canonical provider origin | `https://vector.example` |
| Provider static key | 32 bytes of `02` |
| Hybrid service exporter | 32 bytes of `03` |
| Epoch | `42` |
| Plaintext | `Komms vector v1!` followed by zeroes to 4,096 bytes |
| Provider id | `9935516320b17996593eb230fc34e0937209e308feaaa7ebb91fe370c15118fd` |
| Recipient Ed25519 key | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| Recipient X25519 key | `a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209` |
| Slot | `b80ca6f4d326fefb8477f342f06c7bb16adbf8056d25ef88c2552bd39ffc87d6` |
| Nonce | `0b4b6e38ee282f373c44950b4f4942f2c41253afab011f1b` |
| SHA-256 of the 4,136-byte seal | `43424dfcf7f0cf4c190cc88f52e1feff4139c1f252838198415f137082b2723e` |

Alpha implementation and local tests are not deployed-service, independent
interoperability, independent security-review, hostile real-network, or
physical-device evidence. Private-mode Tor/non-colluding-OHTTP ingress and the
complete Standard/Private/Sovereign mode contract also remain later sessions.
- A service still observes slot activity and connection metadata; Private mode
  reduces but does not eliminate correlation.
- Existing contacts require an authenticated exporter upgrade/re-handshake, and
  restore rotates all rendezvous state just as it rotates live session state.
