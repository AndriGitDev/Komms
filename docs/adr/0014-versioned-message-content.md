# ADR-0014: Versioned, encrypted message-content frames with legacy text fallback

- **Status**: Accepted
- **Date**: 2026-07-13

## Context

Komms currently treats an application message as opaque `Vec<u8>` in
`kult-node` and `kult-store`, then exposes it as UTF-8 text through RPC and
`kult-ffi`. That was a useful M2–M6 baseline, but it cannot distinguish text
from an attachment, edit, poll, vote, or mention. Adding those shapes as ad hoc
byte layouts would make old history ambiguous, let decoders allocate from
attacker-controlled lengths, and cause the three shells to disagree about what
the same authenticated plaintext means.

The content format sits **inside** the existing pairwise Double Ratchet or
sender-key group encryption and inside the existing padding. It must therefore:

- keep every existing UTF-8 text message readable without rewriting history;
- let a new client retain an unknown future kind as an honest unsupported
  record instead of corrupting, dropping, or guessing at it;
- keep content kind, content id, and references invisible to transports,
  relays, mailboxes, and mesh observers;
- preserve the current padding buckets and 65,535-byte plaintext ceiling;
- give future replicated events stable, author-generated ids without making
  envelope ciphertext ids into application ids;
- bound every parse before allocation or recursion; and
- avoid sending typed bytes to a pre-content-model client that would render
  them as damaged text.

This ADR decided the common frame and compatibility contract and initially
introduced only `Text`. Later accepted feature decisions now allocate the
additional v1 kinds listed below. Attachment chunks and live call media remain
outside the content frame even though their manifests/control use typed content.

## Decision

### 1. Legacy text is a permanent decode path

After ratchet/group decryption and ISO/IEC 7816-4 unpadding, a plaintext that
does **not** begin with the four-byte content magic is a legacy message. If it
is valid UTF-8, clients expose it as `LegacyText` and preserve its exact bytes
at rest and in backups. There is no eager database migration.

The magic is `ff 4b 4d 43` (`0xff || "KMC"`). `0xff` can never begin valid
UTF-8, so a message produced by any existing public RPC/FFI text API cannot
collide with a typed frame. A plaintext beginning with the magic is always
parsed as a frame: a malformed or unsupported frame must never fall back to
legacy text, because that would create parser-confusion and downgrade paths.
Legacy non-UTF-8 bytes are retained as an unsupported legacy record rather than
being irreversibly converted with lossy UTF-8 replacement characters.

New text-capable APIs continue to accept and render legacy text forever.
Pre-ADR clients receive legacy text from upgraded peers unless authenticated
capability negotiation has completed as described below.

### 2. Content frame v1 is a small canonical binary header

All integers are little-endian. The v1 plaintext layout is:

```text
magic(4)          = ff 4b 4d 43
format_version(1) = 01
kind(2)
flags(1)          = 00
content_id(16)
payload_len(4)
payload(payload_len)
```

The fixed header is 28 bytes. The frame must consume the entire unpadded
plaintext: no trailing bytes, alternate integer encodings, or ignored fields
are permitted. `content_id` is 16 cryptographically random bytes minted by the
author once per logical content event. It remains identical across retries and
across every recipient of one group fan-out. It is scoped to its conversation;
receivers deduplicate on `(conversation, author, content_id)`.

`kind = 0x0001` is `Text`. Its payload is UTF-8 text, with no embedded schema or
normalization performed by the protocol. Unicode normalization, bidirectional
rendering, and confusable warnings are presentation concerns; clients must not
rewrite authenticated text while decoding it. Kind `0x0000` is invalid. Every
other kind is unassigned until a later accepted ADR fixes its payload shape.
Once assigned, a `(format_version, kind)` payload shape is immutable.

Subsequent fixed allocations are:

| Kind | Content | Governing decision |
|---:|---|---|
| `0x0001` | Text | this ADR |
| `0x0002` | Attachment manifest | ADR-0015 implementation contract |
| `0x0003` | Group Mention | ADR-0016 |
| `0x0004` | Authenticated Edit | ADR-0020 |
| `0x0005` | Ephemeral text/view-once manifest | ADR-0021 |
| `0x0006` | Fixed-electorate Poll event | ADR-0022 |
| `0x0007` | Signed GroupAuthority state | ADR-0023 |
| `0x0008` | Transient pairwise CallControl | ADR-0013 |

These allocations do not change the common header or legacy-text path. Unknown
future kinds retain the same durable unsupported behavior.

`flags` is reserved and must be zero in v1. A decoder that sees a non-zero v1
flag value retains the frame as unsupported instead of attempting a partial
interpretation. A breaking change to the common header, id semantics, or
reference rules requires a new `format_version`; adding a kind with its own
fixed payload does not.

### 3. Limits are checked before interpretation

The common decoder enforces all of these limits before dispatching a payload:

| Limit | Value |
|---|---:|
| Unpadded content frame | 65,535 bytes |
| Fixed v1 header | 28 bytes |
| v1 payload | 65,507 bytes |
| Collection entries in any future payload | 64 |
| Nested container/reference depth in any future payload | 4 |
| Capability format entries | 4 |
| Capability kinds per format | 64 |

The largest frame plus the mandatory `0x80` padding marker fits the existing
65,536-byte bucket. Decoders reject a declared length larger than the remaining
slice or the limit before allocating; reject length overflow, duplicate map
keys, non-canonical ordering where a future shape defines ordering, and trailing
bytes; and never recurse past the shared depth limit. A future kind may set
smaller field/count limits but cannot raise these common ceilings without a new
ADR and format version.

For v1 `Text`, `payload_len` must exactly equal the remaining bytes and the
payload must be valid UTF-8. Invalid UTF-8 is a malformed typed record, not
legacy text.

### 4. Unknown and malformed authenticated content remains durable

Once an envelope decrypts, authenticates, and unpads successfully, the receiver
stores its exact plaintext bytes sealed at rest before acknowledging it. Decode
results exposed to applications are one of:

- `LegacyText(text)`;
- `Text { id, text }`;
- `Unsupported { format_version?, kind? }`; or
- `Malformed`.

Raw unsupported bytes never cross into notifications, search indexing, link
handling, or OS previews. The UI renders a generic “unsupported message — update
Komms” row. Known header fields may aid local diagnostics, but the UI must not
guess a media/content label from an unknown kind.

Unknown versions, kinds, and flags are `Unsupported`; truncated headers,
impossible lengths, invalid required fields, and invalid UTF-8 `Text` are
`Malformed`. Both results remain in history and backups so a later client can
re-decode the original bytes. Both are acknowledged with the ordinary encrypted
delivery receipt after durable storage: `Delivered` means the recipient durably
accepted the authenticated record, not that its current client could render it.

### 5. References use the encrypted content id

Every future content event that refers to another event (edit, reply context,
poll vote, attachment relation) carries
`target_author(32) || target_content_id(16)` inside its own encrypted payload.
Resolution is restricted to the same conversation and exact author. Including
the author prevents a malicious group member from making a colliding id
ambiguous. A reference never uses an envelope `content_id`, ciphertext hash,
store row id, timestamp, or plaintext hash.

Legacy messages have local store ids but no interoperable content id and cannot
be the target of a network-replicated edit or vote. A later reply-UX slice may
define an explicitly local legacy reference, but must not synthesize a shared id
from text: identical messages are distinct events. Content ids are random
identifiers, not signatures, and add no authorship guarantee beyond the
ratchet/sender-key channel that carried them.

### 6. Capability negotiation is encrypted and conservative

Typed content is negotiated per peer over the existing `EnvelopeKind::Receipt`
lane. Its body is an ordinary pairwise ratchet message, padded and encrypted
exactly like a delivery receipt. A decrypted body beginning with capability
magic `00 00 ff 4b 43 43` (`empty receipt || 0xff || "KCC"`) is a capability
control; every other body continues through the existing `ReceiptPayload`
decoder. The first two bytes are the complete canonical Postcard encoding of an
empty receipt. The currently shipped `postcard::from_bytes` receipt path ignores
the unused suffix, so an old endpoint accepts the control as a harmless empty
receipt without allocating from an attacker-controlled count. A stricter old
decoder would merely reject it, which is equally terminal and invisible to the
chat UI. This property is pinned by a golden compatibility test.

Reusing the receipt lane is deliberate: deployed transports and volunteer
relays already accept and forward that outer kind, while a pre-ADR endpoint
decrypts the body, fails closed in its receipt decoder, and surfaces no bogus
chat message. Intermediaries cannot distinguish the capability control from an
ordinary padded receipt. Publishing capabilities in prekey/DHT bundles is
forbidden because it would make a long-lived software fingerprint publicly
queryable.

The decrypted capability payload is canonical:

```text
magic(6)           = 00 00 ff 4b 43 43
control_version(1) = 01
format_count(1)     <= 4
repeated format_count times, sorted by format_version:
    format_version(1)
    kind_count(1)   <= 64
    kinds(kind_count * 2), sorted unique u16 LE
```

A content-aware node sends this terminal control once after a pairwise session
is established or loaded, again when its supported set changes, and in reply to
a valid capability control if it has not advertised on that session. Like a
receipt, it is never itself receipted. It uses the ordinary durable outbound
queue until a transport accepts it; loss after next-hop acceptance can only
delay typed features, never break legacy text. The received snapshot is
authenticated by the pairwise ratchet, stored sealed, and cleared whenever that
session is reset or re-established; stale support must not survive a peer
restore. A malformed control is a terminal no-op.

Until the peer advertises `(v1, Text)`, outgoing text uses the legacy UTF-8
encoding. Once both sides have authenticated support, new text uses the v1
frame. A future typed feature is enabled only after its exact version and kind
are advertised. Unsupported content is still handled safely if reachability or
software changes race the cached verdict.

For a sender-key group, the usable set is the intersection of the authenticated
pairwise capability snapshots for every current co-member. Legacy text remains
available unconditionally. A typed group feature stays disabled, with the
incompatible/unknown members identified locally, until the whole roster
supports it; the sender must not produce different plaintexts for different
members because ADR-0012 requires encrypt-once fan-out. Adding a member
immediately recomputes this intersection.

### 7. Framing stays inside encryption and padding

The canonical content frame is built first, padded with the existing buckets,
then encrypted by the pairwise ratchet or sender-key group chain. The outer
envelope remains `Message` or `GroupMessage`, so relays cannot observe content
version, kind, id, references, or capability result. No kind gets a distinct
padding policy, no content frame is compressed, and no content metadata moves
into delivery tokens or transport headers.

Application and storage APIs evolve from a bare `body: Vec<u8>` / `body: String`
to a typed content result while keeping the existing text send methods as
compatibility wrappers. Stores and `KKR2`-and-later backups preserve message bodies
as sealed opaque bytes, so this ADR does not require a backup-format bump. Each
future kind must explicitly revisit backup behavior before shipping.

### 8. Verification gates

The implementation PR must include:

- golden byte vectors for v1 `Text` and capability controls;
- old-to-new and new-to-old pairwise and group text tests, including a first
  message that creates the session;
- new-to-new negotiation tests proving legacy text is used before capability
  receipt and typed text after it;
- unknown version/kind/flags retention and re-decode tests;
- malformed/truncated/overflow/trailing-byte tests with zero panics;
- duplicate content-id tests scoped by conversation and author;
- proof that both legacy and framed short text retain the existing truthful
  queued/sent/delivered ladder over every carrier;
- proof that content kind/id/reference bytes occur only inside encrypted,
  padded plaintext; and
- dedicated content-frame and capability fuzz targets whose corpora include
  legacy UTF-8, the magic prefix, every boundary length, and arbitrary bytes.

## Alternatives considered

- **Serialize a Rust enum with Postcard.** Rejected: enum discriminants and
  field evolution would become an implicit wire standard, and an unknown
  variant fails the whole decode instead of yielding a durable unsupported
  record. Postcard remains appropriate for sealed local records, not this
  cross-version application contract.
- **JSON, generic CBOR, or Protobuf for all content.** Rejected for the common
  header: they add LoRa-relevant overhead or canonicalization/unknown-field
  behavior we do not need. Future complex payloads may choose a bounded
  canonical sub-codec in their own ADR while retaining this fixed outer frame.
- **Put the content kind in `EnvelopeKind`.** Rejected: every intermediary
  would learn whether an envelope is text, an edit, or a poll, defeating the
  existing metadata posture and coupling application evolution to transports.
- **Add a dedicated capability `EnvelopeKind`.** Rejected: old volunteer relays
  parse the envelope header and would reject the unknown kind before two
  upgraded endpoints could negotiate through them. Multiplexing under the
  existing encrypted receipt lane preserves relay and endpoint compatibility.
- **Use an ASCII magic prefix.** Rejected: an existing valid text message could
  collide with it. The invalid-UTF-8 leading byte makes collision impossible
  for all text emitted by the shipped public APIs.
- **Send framed text to everyone immediately.** Rejected: pre-ADR clients would
  lossy-render binary framing as text. Conservative authenticated negotiation
  preserves useful messaging across versions.
- **Advertise capabilities in signed prekey bundles.** Rejected: DHT records are
  public and long-lived enough to become a queryable client-version
  fingerprint. Pairwise ratchet control confines the detail to the peer.
- **Hash plaintext to create content ids.** Rejected: repeated identical text
  would collapse distinct events, and future references could become an
  equality oracle at endpoints. Random ids model events directly.
- **Rewrite all existing history into v1 frames.** Rejected: it adds migration
  and backup risk without creating interoperable ids for messages whose remote
  copies already have unrelated local record ids. Lazy legacy decode is exact
  and permanent.

## Consequences

- Existing clients and histories continue exchanging readable text; typed
  features fail closed until authenticated support is known.
- B9 formatting remains a local interpretation of exact text source rather than
  a content kind. Formatting-capable endpoints derive the bounded inert model;
  older endpoints display readable markers. No capability or frame change is
  permitted for this source subset.
- A v1 frame costs 28 bytes before padding. Most short messages remain in the
  192-byte bucket, but text near a bucket edge can move to the next bucket.
- One small encrypted capability control is added per pairwise session (and
  when support changes). It has the same outer kind and padding behavior as a
  receipt, so observers cannot distinguish the two from envelope metadata.
- Stores, RPC, UniFFI, and all shells must represent unsupported/malformed
  content honestly and retain exact bytes even when they cannot render them.
- Group features progress at the least-capable current member. This is the cost
  of keeping ADR-0012's one-ciphertext fan-out and avoiding silent exclusion.
- The kind registry and decoder limits become compatibility law. New content
  ADRs must allocate a kind, freeze its canonical shape, define smaller bounds
  where necessary, extend capabilities, add unknown-client tests, and state
  backup behavior.
- This decision should be revisited only if measured overhead makes the fixed
  header untenable on the physical LoRa bench, or if a later ADR needs
  capability convergence beyond ADR-0024's per-device pairwise sessions.
