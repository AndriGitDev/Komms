# ADR-0028: Atomic protocol-state commits

- **Status**: Proposed; stable-profile implementation inventory recorded
- **Date**: 2026-07-27

## Context

Double Ratchet, handshake, and sender-key steps destroy or replace secrets as
they progress. Before the pairwise commit-plan slice, the node persisted
advanced cryptographic state in separate SQLite autocommits from message
history, replay markers, receipt routes, delivery rows, and outbound queue
entries. A process stop or disk error between writes could make a valid inbound
ciphertext permanently undecryptable or advance an outbound chain without
retaining the only ciphertext produced by that step.

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
- `PrekeyPublish`;
- `HandshakeReceive`;
- `GroupSend`;
- `GroupReceive`;
- `GroupState`;
- `AttachmentStage`;
- `AttachmentState`;
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
- before and after each transaction statement;
- before and after commit, in-memory replacement, and event delivery;
- during disk-full/constraint failures; and
- during restart with deferred, duplicated, reordered, or partially delivered
  carrier input.

For every injected point, restart must produce exactly one of two states:

1. the complete transition is absent and the original input remains safely
   retryable; or
2. the complete transition is durable and replay is idempotently absorbed.

No accepted state may contain a ratchet/chain step without its only ciphertext
or plaintext consequence.

### 7. Implementation and evidence status

The implementation now provides all eleven plan kinds above. They cover
pairwise and group text, edits, polls, roles, authority changes, group
announcements and bounded fan-out, pairwise and group attachments, missing
ranges, ephemeral/view-once state, scheduled activation, call signalling,
late-device delivery, exact deferred-control acknowledgement, retry/expiry,
session repair, media reconciliation, and presentation recovery. Fresh
out-of-band one-time-prekey issuance uses `PrekeyPublish`; inbound consumption
uses `HandshakeReceive` and cannot commit without the established session.

Each plan validates its bounded before/after relationships before
`BEGIN IMMEDIATE`. The transaction writes the detached candidate and every
paired ciphertext or accepted plaintext consequence. Complete fresh envelopes
enter the durable pending inbox before parsing or cryptographic work. Top-level
fragments are the bounded exception: assembly advances no ratchet, the
completed inner envelope is staged before deferral, and refused assembly leaves
the fragments unseen for carrier retry.

A sealed presentation marker is written in the same transaction as every
visible transition. If the process stops after commit but before event
delivery, reopening the node emits `StateResyncRequired`; the marker is removed
only after a later tick acknowledges delivery. The FFI and daemon surfaces
preserve that signal, and the desktop shell responds by re-reading its visible
snapshots.

The deterministic crash suite in `crates/kult-node/src/atomic_tests.rs`
exercises before/after cryptographic steps, every logical transaction
statement, commit, memory replacement, event delivery, disk-full, constraint,
duplicate, reorder, deferred-input, expiry, session-repair, scheduled
activation, maximum stable-v1 group fan-out, and restart cases for every plan
kind. Group end-to-end evidence covers partial carrier handoff and restart;
media evidence covers duplicate chunks, interrupted files and full quotas;
backup evidence covers each replacement phase and fresh-secret initialization.
The complete path-by-path disposition is the
[atomic transition inventory](../34-atomic-transition-inventory.md).

This is not full ADR acceptance. The current linked-device Alpha implementation
uses the authority design that ADR-0026 must replace and retains quarantined
multi-write link/sync paths. The current automatic-contact flow remains outside
stable-v1 pending ADR-0030. Interrupted initial profile creation can leave an
unusable partial path, mailbox-v1 cannot yet acknowledge leased relay custody
after endpoint commit, and live call state remains intentionally process-local.
Independent review and supported-platform sudden-power-loss qualification are
also absent. These gaps keep this ADR Proposed and prevent the implemented
matrix from being presented as universal protocol atomicity.

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
