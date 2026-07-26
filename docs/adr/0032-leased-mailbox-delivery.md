# ADR-0032: Leased, crash-safe mailbox delivery

- **Status**: Proposed
- **Date**: 2026-07-26

## Context

The current mailbox check-in removes queued ciphertext while constructing its
response. If the response cannot be written, the recipient process stops, or
local admission fails, neither relay nor endpoint necessarily retains the only
copy. Repeated locally initiated responses can also accumulate outside the
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

Mailbox v1 remains Alpha-only during a coordinated transition. V2 clients
prefer v2 and may fall back to v1 only behind an explicit compatibility policy
that describes delete-before-response risk. Standard defaults qualify as
durable only after v2 restart, disk-full, crash, overload, lease-expiry, and
multi-operator tests pass.

The interim v1 implementation limits a page to 512 rows / 2 MiB, limits a
filter request to 4,096 tokens, rotates larger token and mailbox lists, and
bounds one daemon pass to eight pages / 4,096 rows / 16 MiB. Those controls
close ordinary resource/starvation failures only; they cannot repair custody
loss between destructive relay collection and endpoint admission.

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
