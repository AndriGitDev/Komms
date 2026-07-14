# ADR-0016: Canonical group-mention content with stable encrypted peer targets

- **Status**: Proposed
- **Date**: 2026-07-14

## Context

[ADR-0014](0014-versioned-message-content.md) fixes Komms' encrypted typed-content
frame, permanent legacy-text path, random content ids, authenticated per-peer
capability snapshots, conservative sender-key group intersection, and durable
unknown/malformed retention. It deliberately leaves every payload except `Text`
to a later accepted ADR. [ADR-0015](0015-encrypted-attachment-pipeline.md) assigns
kind `0x0002` to `Attachment`; `Mention` remains unassigned.

Group mentions need semantics that cannot be recovered safely from display text.
Petnames are local presentation, may collide, change, contain arbitrary Unicode or
bidirectional controls, and may be reused after a member leaves. Parsing `@name`
would therefore let different endpoints target different identities, silently
retarget history after a rename, and create false local notifications. At the
same time, a message must remain ordinary readable text when its target cannot be
resolved locally or semantic mentions are unavailable in a mixed-version group.

The mention payload is authenticated plaintext inside the existing ADR-0014
frame, existing padding, and existing pairwise or sender-key encryption. This
decision must:

- preserve the author's exact UTF-8 fallback message without normalization;
- identify each semantic target by the exact stable group peer identity;
- define one cross-language range unit and canonical byte encoding;
- bound text, targets, and spans before allocation;
- retain ordinary group authentication, fan-out, delivery, storage, backup,
  padding, and metadata-blindness behavior;
- fail closed across roster and authenticated capability races;
- keep old clients useful through an explicit plain-text send path; and
- derive notification relevance only at the receiving endpoint without adding
  transport-visible fields or a server-push promise.

This ADR assigns and freezes only the B17 `Mention` content payload and its
required endpoint behavior. It does not add replies, edits, formatting syntax,
roles, presence, global usernames, contact discovery, push infrastructure,
analytics, crypto, transport behavior, or a generic rich-text model.

## Decision

### 1. `Mention` permanently owns content kind `0x0003`

ADR-0014 content format v1 assigns kind `0x0003` to `Mention`. A mention is valid
only as the authenticated content of an existing `GroupMessage`. Pairwise send
APIs reject it before encryption, and a receiver that encounters it outside a
group classifies it as malformed application content rather than rendering or
notifying.

The ADR-0014 `content_id` remains the single author-minted id for the logical
message. It is unchanged across retries and every member copy, and receivers
deduplicate it on the existing `(group, author, content_id)` scope. No mention id,
target, range, or notification bit is added to an envelope, delivery token,
transport header, DHT record, or attachment record.

### 2. Mention payload v1 is fixed-width around exact UTF-8 text

All integers are unsigned little-endian. The complete kind-`0x0003` payload is:

```text
mention_version(1) = 01
flags(1)           = 00
target_count(1)    = 1..64
span_count(1)      = 1..64
text_len(4)        = 1..16,384

targets(target_count * 32), strictly lexicographically increasing:
    peer(32)       = exact Ed25519 group peer identity key bytes

text(text_len)     = exact valid UTF-8 fallback message

spans(span_count * 9), strictly increasing by start:
    start(4)       = inclusive UTF-8 byte offset into text
    end(4)         = exclusive UTF-8 byte offset into text
    target_index(1)= zero-based index into targets
```

The payload version is independent of the ADR-0014 frame version. `flags` is
reserved and must be zero. A structurally complete payload with an unknown
mention version or non-zero flags is retained as unsupported kind `0x0003`; an
impossible length, count, range, index, or canonical form is malformed. A later
incompatible mention layout requires a new content kind or an explicitly
accepted version rule; this v1 byte interpretation never changes.

The payload consumes the complete ADR-0014 payload. No trailing bytes, padding,
alternate integer widths, duplicate tables, or ignored fields are permitted.
The largest valid v1 payload is 19,016 bytes:
`8 + (64 * 32) + 16,384 + (64 * 9)`. It therefore remains well below the common
65,507-byte v1 payload ceiling and uses the existing padding buckets unchanged.

### 3. Ranges are half-open UTF-8 byte offsets and never rewrite text

`start..end` addresses bytes in the exact authenticated `text` field. Each range
must satisfy all of the following:

- `start < end <= text_len`;
- both offsets are Rust `str::is_char_boundary` boundaries in the exact text;
- spans are encoded in strictly increasing `start` order; and
- each `start` is greater than or equal to the preceding `end`.

Spans may be adjacent but never overlap. These rules reject duplicate ranges as
well as ambiguous ordering. Every `target_index` must exist, and every target
table entry must be referenced by at least one span. The sorted unique target
table is the sole canonical representation when one peer is mentioned repeatedly.
Multiple spans may therefore reference the same target, while duplicate target
entries and unused targets are malformed.

The range's text slice is the authenticated fallback display text for that
occurrence. The protocol does not require an `@` prefix and does not interpret,
case-fold, trim, normalize, reorder, or replace any code point. Combining marks,
emoji sequences, grapheme clusters, right-to-left text, directional controls,
confusables, and unusual whitespace remain byte-for-byte authored text. A picker
should create whole user-perceived tokens, but the immutable wire validity rule is
UTF-8 scalar boundary safety, not a changing platform grapheme algorithm.

Applications use ordinary readable `text` for copy, select, search, export, and
accessibility. Highlighting and navigation are an additional semantic view over
the ranges; they never substitute a local petname into authenticated history.

### 4. Stable target identity is separate from presentation

Each target is the exact 32-byte Ed25519 identity key already used by ADR-0012 as
the group roster peer id. It is carried only inside the encrypted and padded
content frame. A target is not a petname, username, contact row id, safety-number
string, envelope id, hash of visible text, or truncated display fingerprint.

Composition starts only from the current authenticated local group roster. The
picker stores the selected peer bytes with the draft span and separately stores a
local presentation snapshot used for review. Immediately before send, the shared
node API reloads the group and rejects the request unless every target is still an
exact roster member. Each shell also compares its review snapshot with the current
roster and current local target-to-display mapping. Removal, replacement, or a
mapping change invalidates confirmation and requires a fresh exact-text review;
the shell must not silently bind the range to a different peer or same-named
contact.

The receiver interprets target bytes independently of its current petnames. A
known current member may be presented using local contact context while the
authenticated range text stays visible. If a target is unknown or has since left,
the same fallback range remains highlighted as a historic unresolved mention and
never resolves to a different peer with a matching name. Roster-dependent
resolution is presentation state, not part of payload validity, so later roster
changes cannot turn durable valid history into malformed content.

ADR-0012's existing sender-key authentication and membership rules remain the
authority for who could author a group message. This ADR does not claim stronger
per-author signatures than sender-key groups already provide. A sender-provided
target is semantic content, not proof that any visible name belongs to that peer.

### 5. Encoding and decoding are bounded, canonical, and total

The canonical encoder validates the complete request before allocating the
output. The decoder first checks the eight-byte header, then uses checked
multiplication and addition to compute the one exact expected payload size before
allocating or copying anything. It rejects before allocation when any count or
length exceeds its cap. The Rust decoder returns borrowed text, target, and span
views where practical so authenticated bytes remain the durable source of truth.

Encoders and decoders reject:

- empty or oversized text, zero or more-than-64 targets/spans, and total-size
  overflow;
- invalid UTF-8, non-boundary offsets, empty ranges, out-of-range offsets or
  target indexes;
- duplicate, unsorted, unused, or non-canonical target entries;
- duplicate, unsorted, overlapping, or non-canonical spans;
- unknown mandatory values, reserved flag bits, truncation, and trailing bytes;
- a pairwise Mention request or group send request containing a target outside
  the immediately reloaded roster; and
- any wrapper request whose declared UTF-8 byte ranges do not reproduce the
  Rust canonical bytes exactly.

Arbitrary input, integer boundaries, malicious counts, and arbitrary Unicode must
produce a bounded valid/unsupported/malformed result without panics. Decoders do
not apply lossy UTF-8 conversion. Raw malformed or unsupported bytes remain sealed
and durable under ADR-0014 but do not enter search, notifications, analytics,
logs, crash reports, links, or OS previews.

### 6. Authenticated capabilities gate one group plaintext

Once complete support ships, upgraded endpoints advertise exact capability
`(format_version = 1, kind = 0x0003)` in ADR-0014's encrypted pairwise snapshot.
The design-only ADR does not advertise the kind. An implementation must add the
advertisement only in the same delivery that can encode, decode, retain, render,
and safely notify for this exact immutable shape.

A sender-key group may emit `Mention` only when every current co-member has a
current-session authenticated snapshot supporting exact kind `0x0003`. Missing,
malformed, reset, stale, or downgraded snapshots are unsupported. The node reloads
the roster and all snapshots atomically with the send decision; any roster or
snapshot change makes the request fail closed and returns the exact incompatible
or unknown peers for local explanation. Adding or removing a member and resetting
or re-establishing any pairwise session immediately recomputes the usable group
intersection.

One sender-key ciphertext is fanned out unchanged to every co-member. Komms never
creates per-member Mention/plain-text variants. A solo group has an empty
co-member intersection and may use Mention because its local implementation is
authoritative; its target still has to be in the roster.

When the intersection does not support Mention, the composer offers an explicit
plain-text send path after explaining which current members are incompatible or
unknown. That path preserves the exact visible UTF-8 text but carries no target
table or spans. It uses framed `Text` only if the whole current roster supports
ADR-0014 Text; otherwise it uses permanent legacy UTF-8. In either case it is
semantically plain text and can never emit a mention notification.

### 7. Mixed versions fail visibly without retargeting

A pre-ADR-0014 endpoint never advertises Mention, so an upgraded sender offers the
plain-text path and sends readable legacy UTF-8 if the user accepts it. An
ADR-0014 endpoint without B17 also never advertises Mention and receives framed
Text or legacy text through that same path. No display name is parsed into a
target on any version.

If a capability race, restored bug, or implementation downgrade nevertheless
delivers kind `0x0003` to a client that does not implement it, ADR-0014 requires
the authenticated frame to remain a durable generic unsupported row. It must not
fall back to interpreting payload bytes as text. After a supporting upgrade, the
same retained body is re-decoded into the exact original text and spans.

A malformed Mention is retained as malformed, acknowledged after durable storage
with the ordinary encrypted receipt, and never partially rendered or notified.
`Delivered` continues to mean durable authenticated acceptance, not semantic
render support.

### 8. Storage, history, delivery, and backup formats do not change

Pairwise Mention sends are forbidden. A valid group Mention uses the existing
`GroupMessageRecord`: its exact ADR-0014 frame stays in the sealed `body`, its
group and sender keep the existing conversation/author scope, and outbound state
keeps the same per-member `Queued` → `Sent` → `Delivered` truth. The existing
sender-key encryption, deduplication, encrypted receipts, queue class, padding,
fan-out, mailbox, sneakernet, LAN, internet, and mesh scheduling behavior is
unchanged. Mention is ordinary text-sized `QueueClass::Normal` content; it gets no
special airtime or priority rule.

KKR4 already backs up sealed group message bodies as opaque bytes, so no backup
format bump or migration is needed. Restored valid, unknown, and malformed
Mention bodies retain exact bytes and re-decode locally. As required by ADR-0011
and ADR-0012, live pairwise sessions, capability snapshots, and group chains are
not trusted across restore; new sessions and authenticated capability exchange
must complete before any new typed Mention send. Historic fallback text and target
bytes remain renderable even if the current roster no longer contains a target.

Search indexes only exact fallback text. Copy/select/export yields the same text,
not local petname substitutions or raw target ids. Unknown and malformed raw
payloads remain excluded from indexing.

### 9. Application APIs expose render-safe structured mentions

The shared node API, RPC, CLI, and UniFFI expose a decoded Mention record containing
the ADR-0014 content id, exact fallback text, and ordered spans with `start`, `end`,
and the full target peer id. Conversation and authenticated author remain fields
of the surrounding group message. Raw authenticated payload bytes, group secrets,
sender chains, capability controls, and encryption state never cross those
render-safe APIs.

Send APIs accept the group id, exact UTF-8 text, and explicit spans whose targets
are full peer ids. RPC and CLI offsets are UTF-8 byte offsets. UniFFI uses the same
unsigned byte-offset contract; Kotlin and Swift adapters must convert native
UTF-16/String indices explicitly and reject a non-exact conversion before calling
Rust. No wrapper accepts a display name as a target or scans text for `@` tokens.
All wrappers use the Rust encoder as the byte authority and reject the same
invalid requests before any network send.

The node also exposes a current group Mention capability verdict with exact
incompatible/unknown peer ids and a revalidation token or equivalent immutable
snapshot binding. A send confirmed against an obsolete roster/capability snapshot
returns a review-required error instead of silently falling back.

### 10. Mention notification signals are endpoint-local and opportunistic

After sender-key authentication, durable storage, and full canonical Mention
decode, the receiving node emits a render-safe local mention signal only if at
least one target peer equals this node's exact Ed25519 identity bytes. The signal
identifies the already stored group-message record locally; it does not contain
message text, target lists, group membership, raw payload, or a public preview.
Repeated spans for the local peer produce one signal for the message.

Fallback text containing `@name`, a similar petname, duplicate display names,
local name changes, an unresolved historic target, malformed/unsupported content,
pairwise content, and the explicit plain-text fallback path never signal. Roster
name reuse cannot retarget a signal because only exact peer bytes are compared.

Shells apply their existing mute, notification, lock-screen, preview, and
user-authorization policy after receiving this local signal. If no such policy
exists, the feature remains an in-app indicator and requests no new permission.
OS-facing notification metadata is generic and protected by default: no plaintext
message, target id, group roster, or other sensitive content is placed in logs,
crash reports, analytics, public notification fields, or unprotected previews.
There is no server push, offline wakeup, presence, or online-delivery guarantee;
the signal is opportunistic when an endpoint actually receives and processes the
message.

### 11. Composer and history behavior is consistent across shells

Desktop, Android, and iOS use an explicit current-roster picker. Duplicate
petnames are disambiguated with existing local context and a minimal local
fingerprint only when necessary; raw identifiers are not exposed by default.
Picker insertion/replacement is deterministic, retains an exact peer binding,
and displays a focused token or equivalent semantic range. Editing or deleting
through any part of a token removes its semantic span or requires explicit
replacement; it never leaves a range silently bound to changed text or another
peer. The final exact fallback text and target bindings are reviewed before send.

History highlights valid spans with a non-color-only treatment while retaining
ordinary text selection, copy, search, and bidirectional layout. Mention
navigation and accessibility announce the authenticated fallback slice plus
locally resolved context without replacing the slice. Focus order, Escape,
arrow/Enter selection, live-region announcements, reduced motion, sufficient
contrast, scalable text, and screen-reader traversal are platform acceptance
requirements.

Android uses semantic annotated text and the current group roster without
clipboard or broad-storage/contacts shortcuts. Draft state stores exact text,
byte ranges, peer targets, and review snapshot in protected app-private storage
across rotation, activity recreation, and process restart. IME composition cannot
partially retarget an existing token; an intersecting composition/edit removes
the span until the picker recreates it. TalkBack, font scaling, bidi text, and
notification privacy are required. B15 incognito-keyboard behavior is unchanged.

iOS uses the same semantic draft model in protected local storage across scene
and background restoration. VoiceOver, Dynamic Type, hardware-keyboard navigation
where applicable, bidi text, and notification privacy are required. Rendering or
composing mentions requests no Contacts, notification, or other permission;
notification authorization remains only in an existing user-controlled path.

## Verification gates

The implementation cannot advertise kind `0x0003` until all applicable gates are
green:

- golden canonical vectors for minimum, maximum, repeated-target, multi-target,
  emoji, combining-mark, grapheme-cluster, and bidirectional payloads;
- arbitrary-input and boundary property tests plus a dedicated Mention decoder
  fuzz target covering every count, length, offset, index, order, overlap,
  reserved field, truncation, trailing-byte, and oversized case;
- byte-for-byte Rust, RPC, CLI, UniFFI, Kotlin, and Swift encoding/decoding parity,
  with native-index conversion failures pinned;
- pairwise capability negotiation feeding the exact all-current-co-member group
  intersection, including first session, add/remove, restore, session reset,
  stale snapshot, downgrade, and changed support immediately before send;
- duplicate petnames, renamed petnames, removed-member name reuse, Unicode/bidi
  names, multiple spans, repeated targets, deletion across tokens, and exact final
  review behavior;
- plain-text fallback through framed Text and legacy UTF-8 with zero semantic
  mention signals, plus exact-local-target signaling and no signal for similar
  names, visible `@text`, malformed spans, or non-local/old reused identities;
- group history, search, copy, selection, navigation, accessibility, protected
  draft restart, process/scene restoration, and backup/restore with later
  re-decode of retained unsupported bytes;
- unchanged pairwise text, attachments, recorded audio, edited images, unknown and
  malformed retention, content-id scoping, deduplication, queued/sent/delivered
  ladders, and exact per-member group fan-out truth;
- mesh, mailbox, sneakernet, LAN, and internet delivery proving the existing
  ordinary text queue class, padding buckets, and airtime policy are unchanged;
- ciphertext-boundary inspection proving kind, content id, exact text, targets,
  ranges, and local notification relevance occur only inside encrypted padded
  plaintext; and
- privacy assertions that logs, crash reports, analytics, public OS notification
  metadata, envelopes, tokens, DHT records, and transport traces contain none of
  the mention plaintext or semantic fields.

The final repository matrix includes Rust format, clippy for all targets/features,
all tests, no-std builds, dependency/license checks, content/capability and Mention
fuzz matrices, legacy/fixture interoperability, RPC/CLI, desktop, Android core and
real app assembly, iOS core and a real simulator application build, syntax,
accessibility, backup/restore, mixed-version, metadata-leakage, and diff checks.

## Alternatives considered

- **Parse free-form `@name`.** Rejected: petnames are local, mutable, colliding,
  Unicode-rich presentation and cannot authenticate a unique group peer.
- **Carry only target peer ids and reconstruct visible text locally.** Rejected:
  history would change after rename/removal, clients would disagree about the
  authenticated message, and mixed-version fallback would be unintelligible.
- **Carry a petname or global username as identity.** Rejected: Komms has neither
  global usernames nor a server authority; adding one would expand discovery,
  privacy, collision, and impersonation scope far beyond B17.
- **Use Unicode scalar, UTF-16, or grapheme indexes.** Rejected: Rust, Kotlin, and
  Swift do not share one stable native index model, while UTF-8 bytes are already
  the authenticated wire representation. Boundary validation keeps slicing safe.
- **Repeat the 32-byte peer in every span.** Rejected: a sorted unique target table
  is smaller for repeated mentions and gives one canonical representation with an
  explicit target cap.
- **Store a second fallback label per span.** Rejected: the exact range slice
  already is the authenticated fallback display text; a second copy could
  disagree and create two renderings for one message.
- **Allow overlapping rich-text annotations.** Rejected: B17 needs one simple
  semantic mention layer. Overlap creates ambiguous editing, navigation, and
  notification behavior and would begin a generic rich-text framework.
- **Put targets or a notification hint in the envelope.** Rejected: relays and
  transports would learn private group semantics and membership-related metadata.
  Endpoint-local exact-id comparison is sufficient.
- **Send Mention to supporting members and text to others.** Rejected: it violates
  ADR-0012's encrypt-once group fan-out and gives members different authenticated
  messages. The user chooses one honest plain-text message for the whole group.
- **Treat capability absence as optimistic support.** Rejected: old clients would
  show binary damage or unsupported rows and roster/session races could silently
  lose readable communication. Authenticated exact support fails closed.
- **Add a roster generation to the payload or group wire header.** Rejected for
  B17: it changes broader group/wire semantics, does not by itself authenticate a
  historic roster snapshot, and is unnecessary when local send revalidation and
  stable target bytes preserve safe history. Such a change needs its own ADR.
- **Add push servers or server-routed mention notifications.** Rejected: it adds
  infrastructure, online metadata, membership routing, permissions, and delivery
  promises unrelated to the existing delay-tolerant endpoint model.

## Consequences

- Mention identity is exact, encrypted, stable across local presentation changes,
  and still readable when resolution fails.
- A valid mention costs 8 bytes, 32 bytes per distinct target, and 9 bytes per
  span in addition to the ADR-0014 header and text. This can move a message into a
  larger existing padding bucket but introduces no new bucket or traffic class.
- Group Mention availability progresses at the least-capable current co-member.
  Users retain an explicit readable plain-text path with honestly reduced
  semantics and zero mention notification.
- Storage and KKR4 need no format migration because exact bodies are already
  sealed opaque bytes; APIs and shells do need new render-safe structured records.
- Native shells must maintain byte-accurate semantic drafts despite UTF-16/String
  editing models, IME composition, restoration, accessibility, and bidi layout.
- Local notifications become more relevant without creating a delivery guarantee
  or revealing semantic fields outside end-to-end encryption.
- This decision should be revisited only through a new ADR if measured message
  limits are inadequate, stable identity changes under a future multi-device
  model, or a separately accepted generic annotation model replaces B17's single
  non-overlapping mention layer.
