# ADR-0020: Authenticated immutable message-edit events

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

ADR-0014 gives every typed event an author-minted content id and fixes the
same-conversation reference shape `target_author(32) || target_content_id(16)`.
Komms now needs message editing across pairwise and sender-key group
conversations, offline delivery, backups, and eventually multiple devices.
Mutating a stored row in place would erase authenticated history, make
edit-before-original delivery impossible, and let clients disagree after
partitions or concurrent same-author device edits.

The first edit format must remain bounded under the v1 content ceiling, stay
invisible to transports, reject cross-author changes, converge independent of
arrival order, preserve old-client behavior, and avoid inventing shared ids for
legacy text. Scheduled messages already have a separate local edit-before-send
operation and are not part of this replicated event.

## Decision

Assign content-v1 kind `0x0004` to `Edit`. An edit is a new immutable,
authenticated event; the original record and every accepted edit remain sealed
in history and backups. Applications derive the visible current text and an
`edited` marker without rewriting authenticated source rows.

### Canonical payload

All integers are little-endian. The common content header's `content_id` is the
edit-event id. Its payload is:

```text
target_author(32)
target_content_id(16)
revision(8)             # u64, >= 1
text_len(4)             # u32, 1..=16,384
text(text_len)          # exact valid UTF-8
```

The payload consumes the entire frame. Empty text, invalid UTF-8, revision zero,
length overflow, trailing bytes, and text over 16,384 UTF-8 bytes are malformed.
No normalization occurs. The event has no timestamp in its authenticated
payload; local receive/send timestamps are presentation metadata and never
participate in convergence.

Only canonical v1 `Text` may be targeted in this slice. Legacy text has no
interoperable content id. Attachment, Mention, Edit, unsupported, and malformed
events are not editable. Editing a sent scheduled item remains the existing
local scheduled-message operation until activation creates an ordinary message.

### Authorization and resolution

The authenticated event sender must equal `target_author`. Resolution is scoped
to the same exact pairwise or group conversation. The target must decode as
canonical v1 `Text` and have that author and content id. A cross-author,
cross-conversation, self-referential, or wrong-kind edit is retained as an
invalid edit event for diagnostics but never changes presentation.

An edit may arrive before its original. Clients store it durably, acknowledge
it after storage, and resolve it if the exact target later arrives. Duplicate
edit ids from the same author/conversation are idempotent.

For one target, the visible winner is the maximum lexicographic tuple
`(revision, edit_content_id)`. A local author chooses one plus the greatest
known revision for that target. Concurrent linked devices may mint the same
revision; the random edit id is the deterministic tie-breaker. Lower or stale
events remain inspectable but cannot regress the visible text. This rule does
not claim causal ordering between devices.

### Capability and compatibility

Endpoints advertise `(content v1, Edit)` through ADR-0014's authenticated
capability control. Pairwise send is refused until the peer advertises the exact
kind. Group edit is refused until every current co-member advertises it and the
author is still a current member. One canonical edit plaintext is encrypted
once through the existing sender-key fan-out.

A pre-edit client never receives an edit through the supported send path. If a
capability race or future source delivers one anyway, ADR-0014 requires durable
`Unsupported` handling; it must not display the replacement as a standalone
message or damaged text. No envelope, receipt, padding, transport, mailbox,
mesh, or group-control format changes.

### Storage, API, and lifecycle

Raw originals and edits stay individually sealed in the existing message/group
history tables and ride `KKR5` unchanged. Derived views are recomputed from
authenticated records after restart/restore; no plaintext index or mutable
"current body" column is added. Search and notifications use the derived winner
only after authorization succeeds. An inbound edit emits a typed local event so
shells refresh the exact target rather than append a chat row.

Every API targets exact author and content-id bytes. RPC/CLI, UniFFI, desktop,
Android, and iOS expose send, derived history, edited marker, winning revision,
and prior-version inspection. Display names never authorize or resolve edits.

## Alternatives considered

- **Overwrite the original row.** Rejected because it destroys authenticated
  history, fails edit-before-original, and makes backup/partition convergence
  dependent on arrival order.
- **Last local timestamp wins.** Rejected because clocks are unauthenticated,
  skewed, and non-deterministic across offline devices.
- **Highest revision without a tie-breaker.** Rejected because two linked
  devices can legitimately mint the same next revision.
- **Editable legacy text or synthesized ids.** Rejected because identical
  legacy messages are distinct and ADR-0014 forbids inventing shared ids from
  plaintext.
- **Delete prior versions.** Rejected for the first slice because it weakens
  auditability and complicates backup/linked-device convergence. A later local
  retention policy may hide or expire versions but cannot rewrite this event.
- **Allow edits to mentions or attachments.** Rejected because their semantic
  payloads and consent/lifecycle state require separate immutable events.

## Consequences

Edits converge under loss, duplication, reordering, partitions, restore, and
future linked-device concurrency while retaining exact provenance. Storage grows
with edit count, so node APIs enforce at most 64 locally authored edit events per
target and reject further local sends. Every authenticated edit received from a
peer remains durable and participates in the same deterministic maximum; a local
admission limit cannot change convergence based on arrival order. History
derivation scans sealed local conversation records at alpha scale and can later
gain a sealed rebuildable index without changing the wire rule.

Acceptance requires golden/fuzz/proptest coverage; edit-before-original,
duplicate, stale, same-revision tie, cross-author, wrong-kind, removed-member,
backup/restart, and old-client tests; exact RPC/CLI/UniFFI parity; all three
shells; accessibility; and proof that edit traffic uses the ordinary encrypted
lane with no new mesh or relay behavior.
