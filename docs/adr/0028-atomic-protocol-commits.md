# ADR-0028: Atomic protocol-state commits

- **Status**: Proposed
- **Date**: 2026-07-26

## Context

Double Ratchet, handshake, and sender-key steps destroy or replace secrets as
they progress. The current node persists that advanced cryptographic state in
separate SQLite autocommits from message history, replay markers, receipt
routes, delivery rows, and outbound queue entries. A process stop or disk error
between writes can make a valid inbound ciphertext permanently undecryptable or
advance an outbound chain without retaining the only ciphertext produced by
that step.

Deferred inbox rows also need at-least-once processing: removing a row before
all durable consequences commit turns an ordinary crash into message loss.

The runtime is intentionally single-writer, but that property is not enough.
One logical protocol transition must become one durable transaction, and
in-memory state and user-visible events must never get ahead of that commit.

## Decision

### 1. The node prepares immutable typed commit plans

Before changing live state, `kult-node` clones the relevant session, prekey
vault, group chain, group record, and delivery state. It performs cryptographic
work only on those candidate values and creates one bounded typed commit plan:

- `PairwiseSend`;
- `PairwiseReceive`;
- `HandshakeReceive`;
- `GroupSend`;
- `GroupReceive`;
- `ReceiptReceive`; or
- `Maintenance`.

Each plan contains the complete before-state identity/version, resulting sealed
logical records, exact queue mutations, replay/seen mutations, source pending
row if any, and events to emit after success. A generic collection of arbitrary
SQL statements is not a public node API.

The plan validates internal invariants before opening a SQLite transaction:
every produced envelope has one queue/delivery owner, every advanced chain has
its ciphertext or accepted plaintext consequence, and every consumed one-time
secret has the session whose establishment consumed it.

### 2. One `BEGIN IMMEDIATE` transaction owns every durable consequence

The store applies a plan in one `BEGIN IMMEDIATE` transaction.

`PairwiseSend` commits together:

- the advanced sending session;
- immutable local history, when the operation creates history;
- one durable envelope per target device;
- per-device and aggregate delivery state; and
- any capability or scheduled-message transition consumed by the send.

`PairwiseReceive` commits together:

- the advanced receiving session;
- accepted immutable history or typed control state;
- seen/replay state;
- the encrypted receipt and its corresponding sending-session advancement;
- expiry/tombstone state; and
- acknowledgement of the exact deferred-inbox row, if present.

`HandshakeReceive` additionally commits one-time-prekey removal and the new
session. An unknown sender enters the bounded contact-request quarantine; it
does not become a trusted contact merely because the cryptographic handshake
was valid.

Group plans commit the group sender/receiver chain, group generation or pending
announcement state, immutable history/control state, all fan-out envelopes and
delivery rows, replay state, and deferred-row acknowledgement together.

Transport I/O, native wake, rendezvous lookup, filesystem export, UI callbacks,
and event fan-out never occur inside the database transaction.

### 3. Memory and events change only after commit

The live node replaces its in-memory candidate state only after the store
returns a successful commit receipt containing the committed transaction id and
record ids. User-visible events are emitted from that receipt.

Any serialization, sealing, quota, constraint, disk, or commit error discards
candidate state and produces no success event. Retrying the original ciphertext
starts from the unchanged durable state.

The store transaction may commit successfully while the process stops before
memory/event update. On restart, durable state is authoritative. A bounded
post-commit event outbox or snapshot resynchronization reproduces presentation
without replaying a ratchet step.

### 4. Deferred work is leased and acknowledged after consequence commit

Reading a pending envelope never removes or rewrites it. Processing names its
stable row id in the commit plan, and the same transaction that stores the
message/session consequences deletes that one row.

Retryable rows remain durable under their original id. Expired or permanently
invalid rows use a bounded maintenance plan that records the terminal reason
where diagnostics require it and deletes only the named row. Pending work is
read in bounded pages; one corrupt row is quarantined rather than preventing
later valid rows from being considered.

### 5. The store is one writer across processes

Opening or creating a store requires a non-blocking exclusive advisory lock
held for the complete `Store` lifetime. A second daemon or embedded runtime
receives a typed already-open failure before it loads mutable protocol state.
The daemon also refuses to unlink a socket that accepts a live connection.

The advisory lock complements SQLite transactions; it does not replace them.
On Unix, the implementation combines the canonical no-follow sidecar with a
lock on the opened database inode, so a hardlink alias cannot create a second
cooperative writer. Equivalent file-identity qualification remains required on
other supported platforms.

### 6. Crash injection is release evidence

Tests insert deterministic failures:

- before and after every candidate cryptographic step;
- before each transaction statement;
- before commit, after commit, and before in-memory replacement;
- during disk-full/constraint failures; and
- during restart with deferred, duplicated, reordered, or partially delivered
  carrier input.

For every injected point, restart must produce exactly one of two states:

1. the complete transition is absent and the original input remains safely
   retryable; or
2. the complete transition is durable and replay is idempotently absorbed.

No accepted state may contain a ratchet/chain step without its only ciphertext
or plaintext consequence.

The first implementation slice covers ordinary retained pairwise text: the
candidate receiving ratchet, optional history row, seen marker, sealed receipt
replay route, and exact deferred-row acknowledgement commit together. It is
deliberately not evidence that handshake, receipt, attachment, ephemeral,
call-control, group-control, group-message, or outbound transitions are atomic;
each still needs a typed plan and crash matrix.

## Alternatives considered

### Repair individual failure windows with compensating writes

Rejected. A compensating write cannot reconstruct a destroyed message key after
a crash, and each new feature would create another unreviewed ordering graph.

### Persist the advanced session before doing anything else

Rejected. It prevents key reuse but loses messages. Safety requires the state
advance and its consequence to be one commit.

### Queue ciphertext in memory and rely on transport retries

Rejected. A process stop loses the only ciphertext produced by an advanced
sending chain.

### Put the entire node tick in one database transaction

Rejected. Network and carrier work can block, transaction latency becomes
unbounded, and unrelated conversations interfere. Transactions are scoped to
one logical protocol transition.

## Consequences

- Store APIs become transition-oriented rather than a collection of unrelated
  row setters.
- Node code must separate candidate state from live state and delay events.
- Receipt generation is part of receive-state planning instead of a later
  best-effort write.
- Group fan-out may create larger but explicitly bounded transactions.
- Deferred processing, restore, and presentation recovery gain deterministic
  crash semantics.
- Acceptance requires failpoint and restart evidence, not only happy-path
  round trips.
