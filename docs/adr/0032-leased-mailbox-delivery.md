# ADR-0032: Leased, crash-safe mailbox delivery

- **Status**: Accepted; implemented for Beta
- **Date**: 2026-07-26

## Context

The original mailbox check-in removed queued ciphertext while constructing its
response. If the response could not be written, the recipient process stopped,
or local admission failed, neither relay nor endpoint necessarily retained that
copy. Repeated locally initiated responses could also accumulate outside the
direct-inbox budget.

Mailboxes are a core durable store-and-forward role. They remain content-blind
and replaceable, but “accepted” and “collected” must describe durable custody,
not a best-effort in-memory handoff.

## Decision

### 1. Mailbox v2 stores durable, idempotent deposits

`/komms/mailbox/2` validates the canonical envelope bound and admission token
before writing a sealed mailbox row. The row has a relay-local random id,
opaque token index, ciphertext, expiry, and content-id dedup index. The relay
returns `accepted` only after that row commits durably.

Per-token, per-client, global item, global byte, request-rate, and retention
limits are explicit. A refusal never claims custody. Relay storage follows the
opaque-index and row-binding rules in ADR-0027 and never receives plaintext or
identity private keys.

### 2. Check-in leases; it does not delete

A bounded check-in response contains one random lease id, an expiry, and a
bounded page of mailbox rows. Creating or retransmitting a lease does not
delete those rows. The same live lease is returned idempotently until it is
acknowledged or expires.

The recipient transactionally stages each valid envelope in its durable inbound
admission inbox. Only after that commit does it send `AckLease` naming the lease
and exact accepted row ids. The relay deletes only those named rows in one
transaction. Rejected, unknown, over-quota, or locally corrupt rows remain
leased until policy expiry or receive an explicit protocol refusal that cannot
delete unrelated work.

If the response, endpoint, acknowledgement, or relay stops, the rows return to
the available state after lease expiry. Duplicate pages and acknowledgements
are harmless.

### 3. Every collection axis is bounded

Protocol constants limit:

- request and response bytes before CBOR or equivalent allocation;
- concurrent streams;
- filters per check-in;
- rows and ciphertext bytes per page;
- live leases per client/token;
- pages and bytes admitted during one endpoint lifecycle pass; and
- total durable endpoint admission rows.

The daemon never loops until a hostile relay returns zero. It processes a fixed
page/time budget, then uses jittered backoff. More mail appears as ordinary
background progress, not an unbounded foreground loop.

### 4. Retention and operator behavior are observable without content

Relay restart preserves deposits, registrations, leases, quotas, and expiry.
Content-free metrics expose capacity, rejected deposits, lease age, expiry,
disk reserve, and schema version. Logs never contain tokens, ciphertext,
identity material, record locators, or peer social-graph labels.

Operators publish retention, capacity, software version, and contact policy.
Clients use more than one selected operator when configured, deduplicate at the
endpoint, and keep the sender's original ciphertext until an encrypted
end-to-end receipt.

### 5. Migration does not overclaim v1

Current clients negotiate v2 only and do not silently fall back. The packaged
daemon serves v2 only. Destructive `/komms/mailbox/1` service compatibility
exists solely behind the library-level `allow_v1_compat` switch, which defaults
off and is not exposed by `kultd`. Enabling it requires a separate operator
decision and disclosure that a response can be lost after relay deletion but
before endpoint custody. A v1 response never counts as stable durable custody.

Historical 0.3.0 artifacts predate this implementation. Operators must verify
the exact source revision and schema rather than infer v2 behavior from an
Alpha image tag.

### 6. The implemented Beta profile is explicit

The default profile retains an envelope for at most 30 days, a registration
for 60 days without refresh, and a live lease for 120 seconds. It caps one
lease page at 128 rows and 1 MiB, one request at 4,096 filters, one client at
4,096 registered tokens and 4,096 deposits / 32 MiB, one token at 256 deposits
/ 16 MiB, and the complete relay at 65,536 deposits / 64 MiB. A client may
hold four live leases, a token may occur in two, and one transport client has
a persisted 2,048-request fixed-window minute budget inside a persisted
8,192-request relay-wide minute budget. The relay holds at most 4,096 live
leases. Protocol codecs,
connection streams, pending operations, response allocation, and the endpoint
collection inbox have separate fixed bounds.

`mailbox-v2.db`, `mailbox-v2.key`, and
`mailbox-v2.transport.key` are owner-only service state. The first key derives
opaque indexes and row seals; the second is a dedicated stable libp2p service
identity. Neither is an account, directory, release, recovery, or endpoint
backup key. The endpoint's routine encrypted backup reads only its core store
and cannot include these sibling service files. Database and service-key opens
reject final-component symlinks; the database, WAL/shared-memory sidecars, and
both keys remain owner-only.

The endpoint processes one page per selected mailbox in a lifecycle interval,
at most eight mailboxes, and rotates both mailbox and token cursors. Success
and failure use jittered backoff; no relay can force a loop-until-empty.
Operational output is limited to aggregate counts, bytes, lease age,
rejection/expiry counters, and schema version.

## Alternatives considered

### Delete when serializing the response

Rejected. Serialization and socket write are not evidence that the recipient
durably retained the ciphertext.

### Keep retrying from the sender

Rejected as the sole safety mechanism. It eventually repairs some losses, but
cannot make a relay custody claim true and wastes battery, bandwidth, and
operator capacity.

### Let collection bypass every local cap

Rejected. A locally initiated request does not make a remote response trusted
or bounded.

## Consequences

- The mailbox wire protocol, relay schema, endpoint admission API, and
  operator runbook change.
- Relay storage becomes persistent instead of an in-memory map.
- Delivery adds one acknowledgement round trip, but crash behavior becomes
  deterministic and pages remain small.
- Release evidence must inject failure before/after lease creation, response
  write, endpoint commit, acknowledgement, relay delete, restart, disk-full,
  and lease expiry.
- Local implementation and simulator evidence do not by themselves qualify a
  public operator, physical platform, real network, or stable release.
