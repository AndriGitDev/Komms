# 07: Storage & Data Sovereignty

Local-first is a security property, an availability property, and a political statement:
your history lives on your hardware, encrypted under your keys, exportable at will, and
locally deletable within explicit endpoint and copy-retention limits.

## 1. Principles

1. **Owned devices are the source of truth.** There is no authoritative
   provider-hosted history database. Optional mailbox and delayed-delivery
   carriers may temporarily retain bounded sealed envelopes, and users may
   create encrypted exports, but neither becomes readable message history for
   an operator. Implemented C2 sync is explicit device-to-device,
   end-to-end encrypted, and accepted only between account-authorized physical
   devices.
2. **Durable records and sensitive equality keys at rest are sealed.** The core
   database does not persist message, draft, or media plaintext. Contact,
   group, delivery-token, message, media, device, and other guessable equality
   identifiers appear only inside row ciphertext or as database- and
   domain-separated keyed indexes. SQLite still reveals static schema
   structure, approximate row counts and sizes, insertion order, and access
   patterns.
   Bounded protected transients required by OS picker, recording, editing,
   playback, or explicit export workflows are temporary exceptions with
   lifecycle cleanup, never durable sources of truth.
3. **Export is a right.** Full history exports to a documented, versioned format at any
   time. Lock-in is a bug.
4. **Local deletion has a precise boundary.** Deleting a message removes the
   live logical row and application references from that Komms history;
   retention policies (per-conversation disappearing messages) are enforced on
   that endpoint. SQLite cleanup can reduce remnants but does not establish
   per-record cryptographic or forensic erasure. Komms cannot erase a
   recipient's copy, screenshot, export, operating-system artifact, previously
   copied backup, carrier ciphertext, filesystem snapshot, or data recovered
   from a compromised endpoint. A deletion hint is a request another endpoint
   may honor, not proof of remote erasure.

## 2. Layout

SQLite database, accessed only through `kult-store`. Key hierarchy per
[04: Cryptography §8](04-cryptography.md): Argon2id-derived KEK → master key `SK` →
HKDF per-domain keys.

| Domain | Contents | Notes |
|---|---|---|
| `identity` | Own keys (wrapped), device settings | Smallest, most sensitive; extra wrap layer |
| `sessions` | Serialized ratchet states, skipped-key store | Body sealed and rewrapped on persist; peer lookup is a keyed opaque locator |
| `contacts` | Peer keys, verification state, petnames, relay hints | Body sealed; peer lookup is a keyed opaque locator; selected fields may enter authenticated own-device sync |
| `devices` | Own and contact device certificates, signed manifests, revocation tombstones | Bounded authority state; exact physical identities |
| `device_sync` | Per-device channels, counters, Lamport winners, terminal convergence tombstones | Direction-bound, replay-protected, never a cloud log |
| `messages` | Envelope plaintexts post-decrypt, delivery state | Per-blob AEAD, random nonces |
| `queue` | Outbound envelopes pending delivery per transport | Ciphertext only, survives crash/restart |
| `scheduled_messages` | Pairwise/group text held until an absolute UTC instant | Plaintext fields exist only inside independently sealed blobs; no ratchet or envelope is created early |
| `prekeys` | Own signed/PQ/one-time prekey secrets | One-time prekeys deleted on use |
| `pending` | Inbound envelopes not yet readable (arrived before their session) | Individually sealed; stable row ids; exact-duplicate suppression in the node; 2,048-row / 64 MiB sealed-byte ceiling; TTL-bounded |
| `media` | Attachment blobs, chunked | Each chunk sealed; keys stored in `messages` |
| `ephemeral` | Exact local deadlines, mode, transfer references, active/terminal lifecycle | Sealed separately; terminal tombstones block resurrection after plaintext/media deletion |
| `local_metadata` | Conversation types, folders, pins, labels, drafts, UI preferences, custom icons | Endpoint-private; only the C2 allowlist can sync to another owned device |

Every database has a random identity. Every record body is individually
AEAD-sealed with XChaCha20-Poly1305 and a random 24-byte nonce. Associated data
binds the row to that database identity, physical schema version, logical table
domain, and final locator. The decoded envelope repeats its logical key and
secondary keys; opening recomputes and verifies the keyed locator and every
opaque SQLite index before returning the payload.

The physical schema is generic: metadata plus one record table and fixed opaque
index slots serve all 25 sensitive logical domains. Pairwise and group history
use keyed message-id and conversation indexes, bounded authenticated cursor
pages, and indexed exact edit/delete. A copied locked database can still reveal
row counts, approximate sizes, insertion order, equality and access patterns
within one index domain, and change timing; it does not provide plaintext
relationship identifiers as SQLite keys. See
[ADR-0027](adr/0027-opaque-indexed-store.md) and the
[opaque-store qualification](33-opaque-store-qualification.md).

Opening a released plaintext-index schema validates it against the retained
release fixture, decrypts and verifies bounded rows, and copies logical records
in 256-row transactions into a fresh-id sibling database. A sealed checkpoint
supports restart. Counts, references, SQLite integrity, every opaque row, and a
complete reopen are checked before the synced sibling atomically replaces the
active path. A synced rollback copy remains until that reopen succeeds.

Deletion removes the live logical row. An explicit bounded maintenance call can
enable SQLite full secure-delete, incrementally vacuum at most 4,096 pages, and
truncate an observed WAL no larger than the caller's bound. The operation
reports deferral and always reports that forensic erasure is not guaranteed.
These controls reduce live-file remnants but cannot control prior copies,
snapshots, flash remapping, recipient devices, or operating-system artifacts.

B9 formatting creates no additional durable state. The `messages`,
`scheduled_messages`, group history, and note-to-self rows retain exact source
bytes under their existing seals; formatting markers are not rewritten and no
rendered HTML/attributed text or cache is persisted. `KKR7` therefore carries
the same source it already carried and needs no format or migration change.

C3 edits also add no mutable plaintext projection. Canonical originals and edit
events remain separate individually sealed pairwise/group history rows; derived
history hides edit rows and returns the winning text, marker, revision, and
ordered versions. The winner is rebuilt from accepted rows after restart or
restore, including edit-before-original order. Pairwise rows have authenticated
individual origins; current group rows have only membership-level origin until
ADR-0029. `KKR7` carries those
history rows, so no backup version or migration changes. The node caps locally
authored edits at 64 per target; it retains every accepted inbound edit so
admission order cannot change convergence. See
[18: Authenticated Message Editing](18-message-editing.md).

C4 keeps lifecycle state separate from history. Every disappearing/view-once id
is keyed by exact conversation, accepted author field, and content id. Pairwise
authors are individually authenticated; current sender-key group authors are
only membership-authenticated until ADR-0029. The node
sweeps due rows before receive, scheduled activation, attachment work, or queue
flush. Expiry/first reveal deletes exact history and queue rows plus every
associated media object/chunk, then retains only a sealed terminal tombstone.
Duplicate, delayed, reordered, and expiry-before-original delivery cannot
rehydrate it. Ordinary export/preview refuses any transfer referenced by a
view-once row; terminal consume commits the tombstone before the first output
byte. See [19: Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md).

C5 polls add no mutable tally or plaintext projection. Creation, vote, and
closure remain separate individually sealed group-history rows. The node
rebuilds the fixed electorate, maximum `(revision, event id)` vote per member,
winning creator-claimed closure, and tally on read, so restart and reordered
admission cannot change the result. Local authors are capped at 64 vote
revisions per poll; membership-authenticated inbound history is retained for
convergence. That retention does not repair member-forged origins; ADR-0029 is
required before stable. See [20: Group Polls](20-group-polls.md).

C7 live calls add no durable domain. Decoded call control, call/device
arbitration, master secrets, derived media keys, replay state, Opus queues, and
decoded PCM are transient memory-only state. Call controls do not enter ordinary
history, search, scheduled/queued tables, C2 sync, or notification previews;
terminal transitions erase secrets and shells clear their protected media
buffers. See [23: Live Audio Calls](23-live-audio-calls.md).

B12 stores only the canonical `system`, `light`, or `dark` bytes under the sealed
UI-preference key `appearance.theme`. Missing or unknown legacy values render as
System without a read-time rewrite. The small shell cache used before unlock is
non-sensitive presentation state; after unlock the sealed F5 value is
authoritative. `KKR7` backup and C2 own-device sync carry only that canonical
value, never the pre-unlock cache.

### Protected application transients

Desktop and mobile shells sometimes must materialize plaintext because native
recorders, decoders, document providers, media players, or user-selected exports
operate on files. Those copies are bounded, app-private, backup-excluded where the
platform supports it, and named independently of protocol IDs. They are removed on
the feature-specific success, discard, denial, failure, lock/background, shutdown,
and startup-orphan paths documented in each app README. They never enter SQLite,
logs, analytics, notification metadata, or a remote service. This is a bounded
endpoint exposure, not a weakening of the sealed durable-store contract.

### Private local conversation folders (B10)

`FolderRecord` stores a locally minted random 16-byte ID, an exact UTF-8 name,
and a persisted manual order. `FolderAssignment` is keyed by the stable typed
`ConversationId` for a pairwise peer, group, or note-to-self, so replacing the
row enforces at most one active folder per conversation. All and Unfiled are
virtual views, not definitions. Names retain their exact bytes and follow the
same 256-byte fixed Pattern White Space rule as labels; duplicates are allowed.

Create, rename, complete-set reorder, move/unfile, and delete cascade use local
transactions. Deleting a folder removes only its assignments, making those
conversations Unfiled without changing messages or conversations. The shared
limits are 128 live folders and 8,192 assignments. Missing definitions or
conversation targets remain sealed and appear only through render-safe stale
diagnostics until explicit cleanup. Folder classification runs before the
independent label filter and never changes delivery, notifications, unread
truth, search, queue work, or history.

### Private contact and conversation labels (B18)

`LabelRecord` stores a locally minted random 16-byte ID, an exact UTF-8 name,
and a canonical color token. `LabelAssignment` maps that ID to the stable
`ConversationId` for a pairwise peer, group, or note-to-self. Identity never
comes from visible text, color, petname, group name, timestamp, or ordering.
Renaming and recoloring preserve the ID, membership, and insertion order;
deletion atomically removes every assignment in the same storage transaction.

Names are retained byte-for-byte without normalization, trimming, case folding,
or rewriting. The front-door limit is 256 UTF-8 bytes. Empty names and names
made only from U+0009–U+000D, U+0020, U+0085, U+200E, U+200F, U+2028, and
U+2029 are rejected. New writes use only `neutral`, `red`, `orange`, `yellow`,
`green`, `teal`, `blue`, `purple`, or `pink`; a legacy unknown token renders as
`neutral` and is never evaluated as platform code or a resource name.

The shared limits are 128 live definitions, 8,192 live assignments, and 32
labels per conversation. Existing rows above a newer aggregate limit stay
readable and removable, while operations that would increase that dimension
fail. Assignment and unassignment are idempotent. Unavailable definitions or
conversation targets remain available to a render-safe diagnostic and cleanup
path but do not participate in active filters. Match-any and match-all filtering
is deterministic, local presentation only; it never changes message receipt,
delivery, notifications, unread truth, search indexing, queue work, or history.

### Private local conversation pins (B11)

Each durable pin is keyed by the exact typed `ConversationId`: pairwise peer,
group, or note-to-self. Visible names never define identity, and one conversation
has at most one pin. Pin and unpin are idempotent. New pins append to persisted
manual order; when the `u32` order space is exhausted, the store transactionally
compacts the complete durable set before appending. The fixed front-door limit is
8,192 pins.

Reorder accepts exactly the complete durable pin set, including unavailable
targets, and replaces its order atomically. Missing conversations remain sealed
and diagnosable rather than being discarded: the exact typed identity reactivates
if that conversation becomes available again, while explicit stale cleanup
removes only that unavailable pin. No display-name matching or cross-kind
substitution is permitted.

Conversation navigation composes in one deterministic order: folder selection,
then label any/all filtering, then a leading pinned block. Eligible pins sort by
manual order, recent activity for an otherwise tied legacy order, and stable
typed bytes; unpinned rows sort by recent activity and the same stable typed
tie-breaker. Pin operations never change messages, folders, labels, search,
unread truth, notifications, queues, cryptographic state, or transport work.
Message pins remain deferred until stable message-reference semantics are
designed separately.

## 3. Search (planned)

The current Alpha does not ship a durable full-text index. A future design may
use a
separately keyed, bounded local index in which tokenized terms are HMAC'd under
a search-domain key before insertion. That design avoids plaintext vocabulary
at rest but still leaks repeated-term equality and access patterns inside one
database; those trade-offs require implementation, migration, and measurement
before search is described as available.

## 4. Backup & portability

- **Encrypted backup file**: single-file export (identity + contacts + ordinary history +
  local organization/drafts/preferences/icons + note-to-self history +
  terminal ephemeral tombstones + signed group authority + linked-device authority,
  convergence winners, and session-reset markers), sealed under a key derived from a BIP-39-style
  mnemonic via Argon2id. `KKR3` added the sealed local metadata domain and
  `KKR4` added sealed note-to-self history, `KKR5` added terminal ephemeral
  tombstones while excluding every active ephemeral history row, manifest,
  transfer, and media chunk, `KKR6` added signed group authority plus bounded
  consumed admin-request ids, and current `KKR7` adds linked-device manifests,
  certified endpoints, convergence winners, and recovery state. Older `KKR1`
  through `KKR6` files remain restorable. Restoring resumes the stable account,
  revokes every device active in the backup, and mints a fresh sole active
  physical device; sessions re-handshake (ratchet states and reusable device
  private credentials are deliberately *not* portable). Format
  and mechanism: ADR-0011. After outer backup decryption, the payload is a
  bounded stream of logical records; it contains no source database id, opaque
  index, SQLite page, or wrapped database-row ciphertext. Restore validates the
  complete logical payload and references, writes a fresh-id sibling database,
  syncs and atomically installs it, and then fully reopens it. It never exposes
  a partially restored destination as a valid store.
- **B18 label backup behavior**: `KKR7` preserves exact label IDs, names, color
  tokens, insertion order, assignments, and stale-reference behavior. Labels
  have no cloud, server, contact, or taxonomy-sharing path; C2 may converge them
  only between account-authorized owned devices.
- **B10 folder backup behavior**: `KKR7` preserves exact folder IDs, names,
  manual order, single-membership assignments, and stale-reference behavior.
  Folders have no cloud, server, or contact synchronization; C2 may converge
  them only between account-authorized owned devices.
- **B11 pin backup behavior**: `KKR7` preserves exact typed targets, durable
  order, and stale/reactivation behavior. Pins have no cloud, server, or contact
  synchronization; C2 may converge them only between authorized owned devices.
- **B13 custom-icon backup behavior**: `KKR7` preserves each canonical sealed
  PNG under its exact typed contact/group/folder/note-to-self target. Restore
  reuses the same strict read verification and generated-initials fallback.
  Icons have no avatar URL, cloud, server, or peer synchronization path; C2 may
  converge them only between authorized owned devices. The shared caps are
  512 KiB per icon, 1,024 records, and 64 MiB total.
- **Scheduled outbox state is not a backup payload.** Like the live encrypted
  delivery queue, it is device runtime state rather than conversation history;
  it survives ordinary process/app restarts on that device but is not resurrected
  by a later identity restore.
- **C3 edit backup behavior**: originals and accepted edit records ride with
  ordinary sealed history. Restore recomputes the deterministic
  winner and prior-version list; it never imports a mutable current-body cache
  or discards stale losing revisions. Pairwise origin authorization survives
  restore; current group origin remains membership-level pending ADR-0029.
- **C4 ephemeral backup behavior**: no live disappearing plaintext, view-once
  manifest, or associated media enters KKR6. Terminal tombstones do, so restore
  cannot resurrect a removed content id. Active ephemeral content is
  intentionally non-portable and there is no remote-erasure claim.
- **C5 poll backup behavior**: immutable create, vote, and creator-close rows
  ride with ordinary sealed group history. Restore derives the same stable IDs,
  fixed electorate, visible vote heads, closed state, and tally; no mutable
  counter, new KKR version, or schema migration is involved.
- **C6 authority backup behavior**: `KKR6` introduced the winning canonical signed
  authority payload, authority event id, owner-transfer chain, and bounded
  consumed request ids; `KKR7` carries it forward. `KKR1`-`KKR5` restore with no authority record and remain
  legacy creator-managed until a capability-gated upgrade. Sender/receiver
  chains remain excluded and are refreshed after restore.
- **C2 linked-device backup behavior**: `KKR7` carries the stable account, signed
  manifest, local device id, certified contact endpoints, convergence winners,
  and terminal tombstones, but never exports ratchets or a reusable physical
  device private credential. Current recovery excludes the known device ids
  active in the backup and mints a fresh device. It does **not** establish
  permanent adversarial revocation because an already linked device may retain
  a copied account root and mint a new id. ADR-0026's offline-root authority
  reset is required before that stronger claim.
- **C7 call backup behavior**: no offer/answer/terminal row, call id, device
  arbitration, secret, media key, Opus packet, or decoded audio enters any KKR
  version. Restore never resumes or reveals a prior call.
- **Plaintext export**: JSON-lines + media directory, clearly warned as plaintext.
  The user's data is the user's.
- **Panic wipe** (roadmap M6): duress passphrase unlocking a decoy profile while
  destroying the real KEK wrap, recorded here so the key hierarchy keeps the KEK-wrap
  layer that makes O(1) destruction possible.

## 5. What never becomes durable or remote state

- Message, draft, contact-name, and media plaintext outside sealed record
  bodies in the core database or encrypted Komms backups, or intentionally in
  logs, analytics, crash metadata, or notification metadata. Explicit warned
  plaintext export and protected lifecycle-bound application transients are the
  narrow exceptions described above. Keyed equality values and row ciphertext
  remain inside Komms-owned storage; logs remain structured and content-free by
  policy.
- Message keys after use; chain keys after advancing (zeroize-on-drop).
- Plaintext contact graphs intentionally uploaded to a remote system. Optional
  relay queues hold only sealed envelopes under rotating tokens with TTLs, but
  their operators may still observe network and token-access metadata described
  in the transport threat model.
