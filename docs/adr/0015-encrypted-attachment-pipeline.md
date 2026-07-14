# ADR-0015: Encrypted, resumable attachment chunks over a bounded bulk lane

- **Status**: Proposed
- **Date**: 2026-07-13

## Context

[ADR-0014](0014-versioned-message-content.md) gives Komms a versioned encrypted
content frame, stable content ids, authenticated capability negotiation, and an
honest unsupported-content path.
It deliberately defines only `Text`. Files, recorded audio, images, video, and
their previews need a second design because the existing message path is capped
at one 65,535-byte unpadded plaintext and its fragmentation layer reassembles at
most 128 KiB. Treating that fragmentation layer as file transport would retain
an entire object in message/reassembly state, make restart and cancellation
ambiguous, and risk spending scarce LoRa airtime on an unbounded transfer.

The attachment path must preserve Komms's existing promises:

- attachment keys, filenames, media types, hashes, and chunk positions remain
  inside authenticated encryption;
- a random attachment key is distributed only by an ADR-0014 content frame
  carried through the pairwise ratchet or sender-key group message;
- each bounded chunk authenticates independently and can survive restart,
  duplication, loss, and reordering;
- sender-key group content is encrypted once, while each member may consent,
  resume, reject, or complete independently;
- endpoint schedulers enforce carrier policy without exposing attachment
  metadata, while old relays continue forwarding known outer envelope kinds;
- no plaintext media, thumbnail, filename, or transfer index touches disk;
- every decoder and durable queue has a fixed count and byte ceiling; and
- old or downgraded clients either decline the feature before send or retain an
  honest unsupported content record. They never render binary data as text.

This ADR decides the F3 wire, cryptographic, storage, compatibility, and carrier
contract. It does not implement file-picker UI, media codecs, editing, malware
scanning, expiry, remote deletion, or real-time call media.

## Decision

### 1. `Attachment` is content kind `0x0002`

ADR-0014 content format v1 assigns kind `0x0002` to `Attachment`. Its payload is
a canonical manifest; the ADR-0014 `content_id` identifies the attachment offer
as a conversation event. A separate random `object_id` identifies each byte
object described by that offer. References to the attachment use the author and
manifest `content_id`, never an object hash, chunk address, filename, or outer
envelope id.

All integers below are little-endian. The manifest payload is:

```text
manifest_version(1) = 01
flags(1)            = 00
attachment_key(32)
object_count(1)     = 01 or 02
repeated object_count times, ordered by role:
    role(1)              = 00 primary | 01 preview
    object_id(16)
    total_len(8)
    chunk_data_len(4)    = 49,152
    chunk_count(4)
    content_hash(32)     = BLAKE3 of the exact unpadded object bytes
    media_type_len(1)
    media_type(media_type_len)
    filename_len(2)
    filename(filename_len)
```

The payload consumes the complete ADR-0014 frame and is at most 1,024 bytes.
`attachment_key` and every `object_id` are independently random. Object ids are
unique within the manifest. The primary descriptor is mandatory and first. A
single optional preview descriptor follows it and means “preview of the primary
object”; previews cannot refer to another preview or contain a filename. This
two-object limit is intentionally below ADR-0014's common collection cap of 64
and nesting cap of four.

`chunk_count` is exactly `ceil(total_len / 49,152)`; a zero-length primary has
zero chunks and the BLAKE3 hash of an empty input. A primary is at most
536,870,912 bytes (512 MiB), therefore at most 10,923 chunks. A preview is at
most 262,144 bytes (256 KiB), therefore at most six chunks, and its media type
must be exactly `image/jpeg` or `image/png`. Receivers still use a sandboxed
decoder. These are v1 protocol limits, not suggested UI defaults.

`media_type` is 1–127 ASCII bytes containing a lowercase IANA-style `type/subtype`
without parameters. It is a display/decoder hint, not trusted authority; the
receiver still sniffs only inside a sandbox after authentication and never
auto-opens an executable. `filename` is absent when its length is zero and is
otherwise at most 255 valid UTF-8 bytes. Senders strip directory components.
Decoders reject NUL, C0/C1 controls, `/`, `\\`, the names `.` and `..`, and
invalid UTF-8. Receivers display a safe generated name if the field is absent or
cannot be represented safely on the local platform. Paths are always chosen by
the receiving application, never by the manifest.

An implementation advertises `(content v1, Attachment)` only when it implements
this complete manifest and the bulk-lane v1 contract below. The existing text
send APIs remain unchanged; a new attachment API must not smuggle bytes into a
`Text` frame.

### 2. Chunks are fixed, independently sealed records

Each object is split into 49,152-byte data chunks. The final chunk may contain
fewer bytes. Before chunk encryption, the sender constructs exactly 49,156
bytes:

```text
actual_len(4) || data(actual_len) || zero_pad(49,152 - actual_len)
```

`actual_len` is 1–49,152 and must equal the manifest-derived length for that
index. Empty objects have no chunk record. Fixed records make retry ciphertext
stable and prevent a short final chunk from bypassing the bulk carrier policy.

The 32-byte attachment key is never used directly as an AEAD key. For each
object and index:

```text
K_object = HKDF-SHA-256(
    salt = object_id,
    ikm  = attachment_key,
    info = "KAT-object-v1" || scope || scope_id || manifest_author ||
           manifest_content_id || role
)
K_chunk = HKDF-SHA-256(
    salt = u32_le(index),
    ikm  = K_object,
    info = "KAT-chunk-v1"
)
```

The chunk record is XChaCha20-Poly1305 ciphertext under `K_chunk` with the
all-zero 24-byte nonce. This is safe because every conversation, manifest,
object, and chunk index uses a distinct derived key; that full tuple must never
be reused with different plaintext. The associated data is the exact
concatenation of:

```text
"KAT-chunk-ad-v1" || scope || scope_id || manifest_author ||
manifest_content_id || object_id || role || u32_le(index) ||
u64_le(total_len) || u32_le(actual_len) || u32_le(chunk_count) ||
content_hash
```

The sealed chunk is always 49,172 bytes. A receiver checks all manifest-derived
fields before AEAD open, writes no plaintext to disk, and hashes the streamed
unpadded bytes. Completion requires both every chunk AEAD to verify and the
final BLAKE3 hash to equal `content_hash`. An AEAD or final-hash failure marks
the transfer corrupt, deletes partial plaintext buffers, retains no renderable
file, and requests no automatic retry until the user or policy explicitly does
so.

The local chunk address is `BLAKE3(sealed_chunk)`. Deduplication is deliberately
limited to identical ciphertext: random attachment keys and object ids prevent
cross-message or cross-sender plaintext-equality leakage. The transfer map from
`(manifest content id, object id, index)` to this address is sealed metadata.
Intermediaries never receive plaintext hashes or local addresses as routing
fields.

### 3. A receipt-compatible bulk lane carries control and chunk records

The manifest is an ordinary ADR-0014 content frame. Chunks and transfer control
are terminal protocol records, not chat messages, and travel through a separate
bulk lane tunneled inside the existing encrypted `EnvelopeKind::Receipt` path.
They are pairwise-ratchet encrypted and padded before entering the ordinary
durable envelope queue.

A decrypted receipt body beginning with `00 00 ff 4b 41 42`
(`empty receipt || 0xff || "KAB"`) is a bulk record; other bodies continue to
the existing capability or receipt decoders. The leading `00 00` is the complete
canonical Postcard encoding of an empty current `ReceiptPayload`. A pre-F3
endpoint therefore accepts the record as a harmless empty receipt or rejects it
terminally, while old transports and relays forward the already-known outer
kind. Bulk records are never acknowledged with an ordinary delivery receipt.

The canonical common header is:

```text
magic(6)             = 00 00 ff 4b 41 42
bulk_version(1)      = 01
operation(1)
flags(1)             = 00
scope(1)             = 00 pairwise | 01 group
scope_id(32)         = pairwise conversation hash | group id for group
manifest_author(32)
manifest_content_id(16)
object_id(16)
payload_len(4)
payload(payload_len)
```

The complete unpadded bulk body is at most 65,535 bytes and must be consumed
exactly. Unknown versions, operations, flags, or scopes are terminally ignored
after authentication; malformed lengths are rejected before allocation. The
session peer, scope, author, manifest id, and object id must resolve to one
stored Attachment manifest before any operation changes state.

An inbound `Chunk` or `Cancel` that acts as the serving side is accepted only
from the manifest author's pairwise session. In a group, `RequestMissing`,
`Complete`, `Cancel`, or `Reject` from a receiver is accepted only from a member
who was entitled to the manifest when it was sent. These checks are durable
transfer metadata, not inferred from the current roster alone.

For a pairwise scope, `scope_id` is
`BLAKE3("KAT-pairwise-scope-v1" || min(IK_A, IK_B) || max(IK_A, IK_B))`, with
the two 32-byte identity keys sorted bytewise. For a group it is the 32-byte
group id. This scope remains inside the pairwise ratchet and exists only to stop
a valid bulk record from being transplanted between conversations.

Operations are:

| Value | Name | Canonical payload |
|---:|---|---|
| `0x01` | `RequestMissing` | `role(1) || range_count(1) || range_count * (start(4) || count(4))` |
| `0x02` | `Chunk` | `role(1) || index(4) || sealed_len(4) || sealed_chunk` |
| `0x03` | `Complete` | `role(1) || content_hash(32)` |
| `0x04` | `Cancel` | `reason(1)` |
| `0x05` | `Reject` | `reason(1)` |

At most 64 missing ranges appear in one request. Ranges are sorted, disjoint,
non-empty, within `chunk_count`, and canonicalized by merging adjacent ranges.
More gaps require another request. `sealed_len` is exactly 49,172 and `index`
must belong to the selected object. `Complete` is valid only after the receiver
has durably committed every verified chunk and the final object hash. Reason
codes are a fixed enum (`user`, `unsupported`, `quota`, `low_storage`,
`policy`, `corrupt`); free-form remote error text is forbidden.

The manifest is the offer. Receiver consent creates `RequestMissing`; the same
operation resumes after restart and retries loss. The receiver persists a chunk
and its bitmap bit atomically before its next request or `Complete`. Duplicate
and reordered chunks are idempotent. `Cancel` stops the sender and releases
unreferenced partial data; a later explicit request may start again. `Reject`
is a durable receiver decision for that manifest until the user changes it.
Senders pace requests and chunks with bounded exponential backoff and stop
automatic retry after 30 days without authenticated progress; the manifest
remains in history and the user may resume later.

All bulk-lane records are placed in at least the existing 4,096-byte padding
bucket, and `Chunk` records use the 65,536-byte bucket. Updated schedulers also
tag them as bulk independently of size. The size floor is defense in depth for
older bridges whose existing 4 KiB airtime ceiling cannot inspect the encrypted
bulk marker.

### 4. Pairwise and group transfers share one blob encryption

In a pairwise conversation, the manifest travels in the ordinary Double Ratchet
message and the two peers exchange bulk records over that same pairwise session.

In a sender-key group, the Attachment manifest is encrypted once as an ordinary
group message and fanned out under
[ADR-0012](0012-sender-key-groups.md). The attachment key is therefore
available to every member entitled to that group message, just like its text.
Each member consents and requests missing chunks independently over its pairwise
ratchet with the original manifest author. The author reuses the exact same
sealed chunk bytes for every member; neither the file nor a chunk is encrypted
again per recipient. Pairwise wrappers, delivery tokens, and retry state differ,
but the bulk ciphertext does not.

Only the original manifest author serves v1 chunks. Peer-assisted group seeding
would reveal possession and needs a separate authorization and abuse design.
Adding a member does not replay old manifests or attachment keys. Removing a
member cannot revoke bytes or keys already delivered to that member; a member
entitled to the manifest may finish or resume that object after removal. Removal
only prevents future group content under ADR-0012's rotated state. A group
Attachment offer is enabled only when every current co-member advertises `(v1,
Attachment)`, preserving the existing capability intersection and honest
encrypt-once fan-out.

### 5. Carrier policy is enforced before airtime

Attachment activation depends on [F4's fresh per-peer carrier
verdict](../12-feature-delivery-plan.md#f4-per-peer-carrier-capabilities). A
sender may create and seal local state while offline, but it must not enqueue
the manifest or any bulk record until every intended recipient has both exact
Attachment support and a fresh `bulk` verdict:

- direct internet or LAN: eligible for offer and transfer;
- mailbox or sneakernet with configured capacity: eligible, subject to local
  and carrier quotas;
- `mesh_only`: held with `AwaitingFasterLink` and zero bulk records offered to
  an airtime transport;
- `offline_or_unknown` or an expired verdict: held, never guessed eligible.

The manifest queue item and every bulk-lane item are tagged as bulk. The
scheduler rejects them for every `CostClass::Airtime` transport even when they
would fit a link MTU. It does not fragment a file as one envelope. Existing
envelope fragmentation may split one already-bounded bulk record for a
non-airtime link with a smaller MTU, but transfer progress and retry remain
chunk-based.

This rule is origin-enforced because intermediaries remain metadata-blind. An
old opaque relay cannot identify a small manifest it received over another
carrier, but chunk and bulk-control size floors exceed the shipped bridge
airtime ceiling. The unavoidable residual is at most the ordinary padded
manifest envelope, never media bytes. Acceptance tests measure the updated
origin and require an attachment attempt under a fresh `mesh_only` verdict to
emit zero frames on its mesh transports. Any future tiny LoRa allowance needs
measured HIL airtime, a new carrier-policy decision, and a smaller protocol
profile; v1 has no exception for recorded clips or previews.

### 6. Consent, quotas, and lifecycle are explicit

Receiving a valid manifest creates history plus a sealed `Offered` transfer
record; it does not allocate the declared total size or download automatically.
Defaults are:

- explicit consent for every file;
- optional user-configured auto-download only for previews or primary objects
  at most 262,144 bytes while a fresh direct internet/LAN `bulk` verdict exists;
- at most eight active inbound and eight active outbound objects per peer;
- at most 32 active objects globally;
- at most 1 GiB of incomplete sealed chunks globally;
- a 2 GiB default media-store quota, configurable up to a 64 GiB hard ceiling;
  and
- at least 256 MiB of filesystem free space retained after any chunk commit.

The lowest applicable cap wins. Counts and bytes are checked with overflow-safe
arithmetic before creating rows, files, bitmaps, or buffers. A receiver may
lower limits and reject an offer; raising the 512 MiB per-object or 64 GiB store
ceiling requires a later ADR. Quota or low-storage failure is visible locally
and sends only its fixed reason code.

Transfer states are `Offered`, `AwaitingConsent`, `Queued`, `Transferring`,
`Paused`, `Complete`, `Rejected`, `Cancelled`, `Corrupt`, and `Unavailable`.
RPC, CLI, UniFFI, desktop, Android, and iOS expose these states, verified byte
progress, total bytes, safe filename/media-type hints, and the carrier hold
reason. They never expose attachment keys, raw unsupported frames, local chunk
paths, relay addresses, missing-range bitmaps, or ciphertext hashes.

Previews are generated or decoded locally in a sandbox, stored sealed, and
governed by the same quota and cleanup rules. No plaintext temporary file is
used: import, hashing, chunking, assembly, thumbnail generation, playback, and
export use bounded streams or OS-protected handles. If a platform API requires
a plaintext export, it is an explicit user action to a user-selected location;
Komms closes the handle promptly and cannot promise deletion from that external
location.

### 7. Media uses sealed files plus transactional metadata

Large media blobs do not live in SQLite. `kult-store` adds a `media` domain key,
sealed transfer/object metadata tables, and a private media directory beside
the database. Each already end-to-end-encrypted chunk is sealed again under the
local media-domain key with a fresh random XChaCha20-Poly1305 nonce and
`chunk_address || "KAT-store-chunk-v1"` as associated data. The filename is the
hex chunk address, so a copied directory leaks only ciphertext equality and
approximate fixed chunk counts/sizes, never plaintext equality, names, types,
keys, positions, contacts, or conversations. SQLite maps those addresses to
sealed transfer state.

The schema migration is additive: existing message and group-message record
shapes do not change, and opening an old store creates only the new media tables
and private directory. Every new sealed metadata record begins with a `u8`
record version and is length/count checked before Postcard decoding; an unknown
record version is quarantined as unavailable rather than partially decoded. The
directory is created with owner-only permissions where the platform supports
them. No migration reads or rewrites old message bodies eagerly.

A chunk commit writes and fsyncs a same-directory temporary file, atomically
renames it, then transactionally records the address and bitmap bit. Startup
removes stale temporary files and unreferenced chunk files; a missing referenced
file moves the object to `Unavailable` rather than inventing completion.
Cancellation, rejection, corruption, message deletion, and quota eviction drop
references transactionally, then garbage-collect unreferenced files. Completed
media remains until explicit local deletion or quota policy evicts it. Remote
deletion and expiry remain later ADRs.

The mnemonic backup (`KKR2` when this ADR was accepted; current `KKR4`)
continues carrying message and group-message bodies, therefore it carries
Attachment manifests and their keys, but it excludes media files,
incomplete-transfer state, bitmaps, and bulk queues. No backup-format bump is
needed for F3. After restore, manifests render as `Unavailable`; once sessions
and capabilities recover, the user may request the bytes again if the original
author still has them. Outbound attachments may likewise become unavailable
after restore. A future optional media-inclusive backup must be streaming,
quota-bounded, and versioned separately; it must not silently append gigabytes
to the current mnemonic backup. Plaintext export includes only complete media
the user explicitly chooses and warns that the destination is unencrypted.

### 8. Compatibility fails closed and preserves history

A peer that has not authenticated exact `(v1, Attachment)` support is
ineligible before send. Pairwise UI names the incompatible/unknown peer; group
UI names every blocking member. No legacy text placeholder is sent because it
would create a false attachment event on one side only.

If stale capability state, downgrade, restore, or a race nevertheless delivers
an Attachment frame to an ADR-0014 client that does not implement it, that
client stores the exact frame, acknowledges durable receipt, and renders the
generic unsupported row required by ADR-0014. A pre-ADR client never advertises
support and interprets an accidental bulk record as an empty receipt or terminal
decode failure, not chat text. The upgraded sender receives no `Complete`, holds
or expires transfer activity, and retains its local manifest.

Malformed manifests are stored as ADR-0014 `Malformed` content and never create
media state. Unsupported manifest versions or flags remain `Unsupported`.
Malformed or unknown bulk records are terminal no-ops and are never reflected
to chat UI, notifications, search, or previews.

### 9. Verification gates

Implementation is not accepted until it includes:

- golden vectors for the Attachment manifest, bulk common header, every
  operation, HKDF outputs, chunk AEAD, and empty/final/full chunk boundaries;
- boundary tests at 0, 1, 49,151, 49,152, 49,153, 262,144, and 512 MiB logical
  lengths without allocating the largest object in one buffer;
- arbitrary-input property tests and dedicated manifest, bulk-record, range,
  and transfer-state fuzz targets with allocation and recursion assertions;
- pairwise and group tests for consent, encrypt-once chunk reuse, independent
  member progress, member add/remove, missing pairwise sessions, and original
  author unavailability;
- restart/partition tests for every durable boundary: before temp-file fsync,
  after rename, before/after SQLite commit, after chunk receipt, and before
  `Complete`;
- loss, duplicate, reorder, missing-range canonicalization, cancellation,
  rejection, corruption, final-hash mismatch, quota, low-storage, and garbage
  collection tests;
- compatibility tests with pre-ADR, ADR-0014-only, downgraded, and restored
  peers, including old receipt parsing of the bulk prefix;
- carrier matrices for direct internet, LAN, mailbox, sneakernet, bridge, and
  LoRa proving bulk-tagged work never reaches an airtime transport and a file is
  never handed to whole-envelope reassembly;
- copied-database/media-directory inspection proving plaintext names, types,
  hashes, keys, bytes, transfer ranges, and conversation links are absent;
- KKR4 backup/restore tests proving manifests survive while media and transfer
  state are intentionally absent; and
- cross-surface tests proving identical states and safe errors in RPC/CLI,
  UniFFI, desktop, Android, and iOS, including background interruption and
  platform temporary-file cleanup.

## Alternatives considered

- **Use existing envelope fragmentation for the whole file.** Rejected: its
  128 KiB reassembly cap and 24-hour partial state are for bounded envelopes,
  not files. Raising them would invite memory/disk denial of service and give no
  consent, restart, quota, or cancellation boundary.
- **Put chunks directly in Attachment content messages.** Rejected: history
  would fill with transport records, each chunk would need chat-content ids and
  receipts, and an old client could surface thousands of unsupported rows. The
  terminal bulk lane keeps transfer state out of conversation presentation.
- **Add a new outer `EnvelopeKind::AttachmentChunk`.** Rejected: deployed relays
  reject unknown outer kinds, and every intermediary would learn which traffic
  is media. The encrypted receipt-compatible lane preserves known routing
  behavior and hides operations and metadata.
- **Use plaintext hashes as global chunk addresses.** Rejected: equal files or
  chunks from unrelated conversations would become a copied-store and endpoint
  equality oracle. Addresses hash randomized ciphertext and deduplicate only an
  identical sealed chunk.
- **Random nonce stored with every attachment chunk.** Rejected for the transfer
  ciphertext: retry and group fan-out need byte-identical chunks. A unique
  HKDF-derived key per object/index makes a fixed nonce safe. Local at-rest
  sealing still uses fresh random nonces.
- **One giant encrypted media blob.** Rejected: one lost byte forces a full
  retry, completion requires whole-file buffering, and crash cleanup cannot
  distinguish verified progress.
- **Per-member group attachment encryption.** Rejected: it breaks ADR-0012's
  encrypt-once scaling and makes one logical attachment consume N full
  encryptions and N distinct stores. Pairwise request wrappers are small;
  sealed chunk bytes remain identical.
- **Automatic download based only on MIME or filename.** Rejected: both are
  authenticated sender claims, not safety verdicts, and carrier/storage state
  can change immediately. Consent, byte caps, sandboxing, and F4 gating remain
  authoritative.
- **Store media as SQLite BLOBs or plaintext files.** Rejected: large BLOBs
  amplify database copies and backups; plaintext files violate the storage
  promise. Sealed files plus transactional sealed metadata bound both risks.
- **Include all media in the mnemonic backup.** Rejected: current backup construction is a
  single bounded file assembled in memory, and silently adding up to 64 GiB
  changes its operational contract. Manifests remain portable; media backup is
  a future explicit streaming format.
- **Allow tiny LoRa attachments immediately.** Rejected until physical HIL
  measurements allocate an airtime budget and F4 can report it honestly. The
  first F3 profile has one simple rule: bulk never uses airtime-class links.

## Consequences

- Attachments become resumable, cancellable, quota-bounded, and compatible with
  pairwise, group, mailbox, sneakernet, internet, and LAN delivery without
  turning message fragmentation into file transport.
- A manifest costs at most 1,024 bytes inside the existing content frame. Each
  chunk carries fixed-record and double-encryption overhead and small control
  records use a 4 KiB padding bucket; this intentionally trades bandwidth on
  bulk-capable links for restart safety, metadata protection, and a mesh guard.
- Group manifests and file bytes are encrypted once, but the original author
  maintains independent per-member request/progress state and must remain
  available to serve v1 downloads.
- The store gains filesystem lifecycle and crash-consistency obligations beyond
  SQLite. Backups remain small and compatible at the cost of media being
  re-downloadable rather than restored.
- F3 implementation cannot activate before F4 provides fresh `bulk` carrier
  verdicts. Local codec, crypto, and store work may land earlier behind a
  disabled API, but no shell may offer sending based on transport guesswork.
- The fixed kind, manifest, chunk size, limits, key schedule, bulk prefix, state
  model, and backup exclusion become compatibility law. Revisit them only with
  a new version if HIL measurements justify a bounded mesh profile, files above
  512 MiB become a product requirement, peer-assisted group seeding is designed,
  or streaming media-inclusive backup is accepted.
