# 18: Authenticated Message Editing

C3 message editing is shipped for canonical pairwise and sender-key group text
across `kult-protocol`, `kult-node`, `kultd` RPC/CLI, UniFFI, desktop, Android,
and iOS. It follows [ADR-0020](adr/0020-authenticated-message-edits.md): an edit
is a new encrypted authenticated event, never an invisible rewrite of history.

## User promise

- Only the author of a canonical Komms `Text` event can edit it.
- A successful edit keeps the original message row, shows an **edited** marker,
  and offers the original plus every valid version for inspection.
- Pairwise and group edits work through the ordinary queued → sent → delivered
  path and can arrive before the original or after a long offline interval.
- Every peer derives the same winner regardless of delivery order. The highest
  `(revision, edit event id)` wins; local clocks and receive timestamps do not.
- An edit is available only when the exact peer capability is authenticated.
  A group edit additionally requires every current co-member to support edits.
- Scheduled-message editing remains the separate local pre-activation operation.
  Legacy text, mentions, attachments, malformed content, and edits themselves
  are not editable.

Komms does not promise that an edit erases a prior version. Recipients may have
already read, copied, exported, captured, or backed up any version. C3 explicitly
retains valid versions on each endpoint so provenance and offline convergence do
not depend on arrival order.

## Canonical encrypted content

Content-v1 kind `0x0004` is permanently assigned to `Edit`. The common content
header carries the random 16-byte edit-event id. Its payload is:

```text
target_author(32)
target_content_id(16)
revision(8 little-endian, >= 1)
text_len(4 little-endian, 1..=16,384)
text(text_len, exact UTF-8)
```

The payload must consume the frame. There is no normalization, timestamp, display
name, conversation name, or transport hint in it. The whole content frame stays
inside the existing pairwise Double Ratchet or group sender-key ciphertext and
the existing padding buckets. Relays, mailboxes, bridges, mesh repeaters, and
sneakernet carriers cannot distinguish an edit from another encrypted message.

An accepted edit must satisfy all of these conditions:

1. its authenticated event sender equals `target_author`;
2. target author and content id identify an exact canonical `Text` in the same
   pairwise or group conversation;
3. revision and replacement text obey the canonical bounds; and
4. the event arrived through the appropriate authenticated conversation lane.

Cross-author, cross-conversation, wrong-kind, malformed, and self-referential
attempts never alter presentation. Generic raw-content send APIs also reject
pre-encoded `Edit`, so callers cannot bypass the dedicated authorization path.

## Offline ordering and convergence

Originals and edits are immutable records. Resolution first collects the exact
target plus every authenticated valid edit, sorts versions by
`(revision, edit_event_id)`, and presents the maximum tuple. The original is
revision zero. This gives the same result for:

- edit before original;
- duplicate delivery;
- stale revisions arriving late;
- two same-revision edits minted by future linked devices;
- restart and `KKR4` backup/restore; and
- different carrier paths delivering records in different orders.

The random id is only a deterministic tie-breaker; it does not claim causal or
wall-clock order. A local author chooses one plus the greatest revision already
known for the target and may create at most 64 edits per target. Authenticated
inbound edits are not truncated at an arrival-dependent local cap, because doing
so would make endpoints disagree.

## Storage, backup, search, and events

The existing sealed pairwise/group history rows retain exact originals and edit
events. No plaintext `current_body` column, mutable source row, or new backup
format exists. `KKR4` carries those sealed history records unchanged and the
derived winner is rebuilt after open or restore. A copied database continues to
leak only the already accepted sealed-row count and approximate sizes.

Normal history APIs hide edit events as standalone chat rows. Each returned
message instead includes:

- the winning body;
- `edited`;
- `edit_revision`; and
- ordered `versions` with id, revision, local presentation timestamp, and body.

An inbound pairwise edit emits `MessageEdited(peer, target_content_id)`; an
inbound group edit emits `GroupMessageEdited(group, sender,
target_content_id)`. Shells refresh that exact conversation/target. The signal
contains no replacement text, petname, group name, or notification preview.
Any local search or notification projection must consume only the authorized
derived winner, never a raw or rejected edit event.

## Compatibility and front doors

Edit support is advertised by authenticated content capability `(v1, Edit)`.
The supported sender refuses pairwise edits to a peer that has not advertised
it and refuses group edits unless the current roster is fully capable. An older
content-aware client that nevertheless receives kind `0x0004` follows
ADR-0014's durable `Unsupported` behavior and must not render the replacement as
text. No envelope, receipt, mailbox, fragment, transport, or backup version
changed.

Strict front doors use exact stable identifiers:

```text
RPC:  edit_message(peer, target_author, target_content_id, text)
RPC:  group_edit_message(group, target_author, target_content_id, text)
CLI:  kult edit PEER_HEX AUTHOR_HEX CONTENT_ID TEXT...
CLI:  kult group-edit GROUP_HEX AUTHOR_HEX CONTENT_ID TEXT...
FFI:  edit_message(...) / edit_group_message(...)
```

Unknown RPC fields and malformed hex are rejected. Display names are never an
authorization or lookup input. Desktop, Android, and iOS expose Edit only on an
outbound canonical text row, use their incognito input controls for replacement
text, retain an accessible edited marker, and provide explicit version history.

## Qualification

Automated coverage includes:

- strict golden, malformed-boundary, property, arbitrary-input, and dedicated
  `edit_decode` fuzz coverage;
- a shared cross-platform fixture for edit-before-original, stale revisions,
  same-revision tie-breaking, and wrong-author rejection;
- real encrypted pairwise and group lanes, exact typed events, capability
  refusal, raw-send bypass rejection, restart, and backup/restore;
- strict RPC/CLI wire parsing, UniFFI models/events, and desktop/Android/iOS
  session parity; and
- proof that raw edit records remain durable while rendered histories contain
  only the resolved original row.

Manual release qualification must still exercise screen readers, keyboard-only
operation, Dynamic Type/font scaling, Unicode and bidirectional replacement
text, lifecycle interruption, old-client interop, and real Android/iOS devices.
Android APK/device validation waits for the local Android SDK; this does not
justify hosted CI or weaken the shared-core and host-JVM acceptance evidence.
