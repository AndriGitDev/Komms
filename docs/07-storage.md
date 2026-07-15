# 07: Storage & Data Sovereignty

Local-first is a security property, an availability property, and a political statement:
your history lives on your hardware, encrypted under your keys, exportable at will, and
deletable for real.

## 1. Principles

1. **The device is the source of truth.** No cloud copy exists unless the user creates an
   encrypted export. Sync between own devices (M6) is device-to-device, E2E-encrypted.
2. **Everything at rest is sealed.** No plaintext ever touches disk, including drafts,
   media thumbnails, and search indexes.
3. **Export is a right.** Full history exports to a documented, versioned format at any
   time. Lock-in is a bug.
4. **Deletion is real.** Deleting a message deletes the ciphertext row and its keys;
   retention policies (per-conversation disappearing messages) are enforced locally.
   We are honest that the *recipient's* copy is theirs, no fake "remote delete" theater
   beyond a polite delete-request the peer may honor.

## 2. Layout

SQLite database, accessed only through `kult-store`. Key hierarchy per
[04: Cryptography §8](04-cryptography.md): Argon2id-derived KEK → master key `SK` →
HKDF per-domain keys.

| Domain | Contents | Notes |
|---|---|---|
| `identity` | Own keys (wrapped), device settings | Smallest, most sensitive; extra wrap layer |
| `sessions` | Serialized ratchet states, skipped-key store | Rewrapped on every persist; zeroized in memory after |
| `contacts` | Peer keys, verification state, petnames, relay hints | Never leaves the device |
| `messages` | Envelope plaintexts post-decrypt, delivery state | Per-blob AEAD, random nonces |
| `queue` | Outbound envelopes pending delivery per transport | Ciphertext only, survives crash/restart |
| `scheduled_messages` | Pairwise/group text held until an absolute UTC instant | Plaintext fields exist only inside independently sealed blobs; no ratchet or envelope is created early |
| `prekeys` | Own signed/PQ/one-time prekey secrets | One-time prekeys deleted on use |
| `pending` | Inbound envelopes not yet readable (arrived before their session) | Ciphertext only; TTL-bounded |
| `media` | Attachment blobs, chunked | Each chunk sealed; keys stored in `messages` |
| `local_metadata` | Conversation types, folders, pins, labels, drafts, UI preferences, custom icons | Local-only; keys and relationships are inside sealed blobs |

Every blob is individually AEAD-sealed (XChaCha20-Poly1305, random 24-byte nonce, table
name + row purpose as associated data), a copied database file leaks only row counts and
approximate sizes; rows can't be transplanted across tables or databases.

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

## 3. Search

Full-text search runs over a **sealed local index**: tokenized terms are HMAC'd under a
search-domain key before insertion, so the index file leaks no vocabulary. Query =
HMAC the query terms, look up. (Trades fuzzy matching for sealed storage, the right
trade for this project.)

## 4. Backup & portability

- **Encrypted backup file**: single-file export (identity + contacts + history +
  local organization/drafts/preferences/icons + note-to-self history +
  session-reset markers), sealed under a key derived from a BIP-39-style
  mnemonic via Argon2id. `KKR3` added the sealed local metadata domain and
  `KKR4` adds sealed note-to-self history; older `KKR1`, `KKR2`, and `KKR3`
  files remain restorable. Restoring on a new
  device resumes identity; sessions re-handshake (ratchet states are deliberately *not*
  portable, importing stale ratchet state is a correctness and security hazard). Format
  and mechanism: ADR-0011.
- **B18 label backup behavior**: `KKR4` preserves exact label IDs, names, color
  tokens, insertion order, assignments, and stale-reference behavior. Labels
  have no independent cloud, server, or linked-device synchronization path.
- **Scheduled outbox state is not a backup payload.** Like the live encrypted
  delivery queue, it is device runtime state rather than conversation history;
  it survives ordinary process/app restarts on that device but is not resurrected
  by a later identity restore.
- **Plaintext export**: JSON-lines + media directory, clearly warned as plaintext.
  The user's data is the user's.
- **Panic wipe** (roadmap M6): duress passphrase unlocking a decoy profile while
  destroying the real KEK wrap, recorded here so the key hierarchy keeps the KEK-wrap
  layer that makes O(1) destruction possible.

## 5. What never gets stored

- Plaintext of anything, anywhere, ever (including logs: log lines are structured and
  content-free by policy, enforced by a lint in CI).
- Message keys after use; chain keys after advancing (zeroize-on-drop).
- Contact graphs on any remote system. Relay queues hold only sealed envelopes under
  rotating tokens with TTLs.
