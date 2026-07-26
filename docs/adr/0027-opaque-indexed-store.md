# ADR-0027: Versioned opaque indexes and row-bound sealed storage

- **Status**: Proposed; inactive v2 foundation implemented
- **Date**: 2026-07-26

## Context

Komms seals record bodies, but the current SQLite schema uses plaintext account
public keys and group ids as primary keys. A copied locked database therefore
reveals exact contact and group relationships. Several tables also seal every
row under constant associated data, so a local database writer can transplant
valid ciphertext between identifiers without the store proving that the inner
record belongs to the requested row.

The schema has no versioned migration ledger. Additive `CREATE TABLE IF NOT
EXISTS` calls cannot safely express index replacement, authenticated row
identity, or large-history query plans. Updating or deleting a message scans
and decrypts the full history.

SQLite row deletion and flash storage do not support an honest guarantee that
deleted bytes are physically unrecoverable. The design must protect a locked
copy, resist row substitution, scale to ordinary histories, and state deletion
limits accurately without inventing forensic erasure.

## Decision

### 1. Every database has a random identity and explicit schema version

Creation writes a random 32-byte `database_id`, `schema_version`, and completed
migration ledger inside authenticated metadata. The database id is not a user
identifier and is never copied during restore. Backups contain logical records,
not database ids, indexes, SQLite pages, or wrapped row ciphertext.

Opening refuses unknown future schemas, incomplete migrations, duplicate
migration ids, or metadata whose authenticated version disagrees with the
physical schema. Released migration fixtures cover every public schema
version.

### 2. Sensitive equality keys become domain-separated keyed indexes

The storage master derives a non-exported index root. Each table derives a
separate key and computes:

```text
table_index = HMAC-SHA-256(
    K_index_table,
    "Komms-Store-Index-v2" || canonical_logical_key
)
```

Canonical keys include a type/domain byte and fixed-width fields. Examples are
account public key, group id, `(group id, account key)`, message id, and
conversation direction. The same logical value produces unrelated indexes in
different tables and unrelated databases.

SQLite stores only these 32-byte indexes, random row ids, sealed blobs, and the
minimum integer ordering needed for pagination. Static schema metadata and
approximate row counts/sizes remain observable. No contact key, group id,
delivery token, message id, media id, or search term is a plaintext index.

### 3. AEAD binds a row to its database, schema, table, and index

Every sealed row uses canonical associated data:

```text
"Komms-Store-Row-v2" ||
database_id ||
u32_be(schema_version) ||
table_domain ||
row_locator
```

`row_locator` is the keyed index for equality tables and a random 16-byte row id
for append-only tables. A decoded record must reproduce the expected canonical
logical key before it is returned. Index mismatch, inner-key mismatch, unknown
record version, duplicate unique index, or cross-database/table transplant is
corrupt state.

Record plaintext starts with its own version and logical key. This permits
bounded record migrations without asking the caller to infer which historical
layout happened to decode.

This prevents undetected substitution and transplantation. It does not prevent
an attacker with write access from deleting the newest database, restoring an
older complete snapshot, or denying access. Rollback detection needs an
optional platform monotonic anchor and remains a separate capability.

### 4. Migration builds a new sibling database

The plaintext-index schema is not migrated in place. After unlocking the old
store, Komms:

1. creates a private sibling database with a fresh database id;
2. validates and decrypts each old row under strict limits;
3. verifies every inner logical identity;
4. writes the v2 representation in bounded transactions;
5. validates counts, referential rules, and a complete reopen;
6. fsyncs the new database and containing directory; and
7. atomically replaces the active path while retaining an explicitly named,
   user-removable rollback copy until the new version has opened successfully.

WAL/SHM files are checkpointed and excluded from the replacement. The old file
may still exist in filesystem snapshots, backups, SSD remapping, or recovered
blocks; UI and documentation do not describe migration as secure deletion.

Restore uses the same new-sibling, validate, fsync, and atomic-rename process.
It never leaves a partially restored path that looks like a valid store.

### 5. Query indexes are private and bounded

Messages and group history gain keyed conversation and message-id indexes plus
cursor pagination. Exact update/delete is one indexed lookup, not a full-table
decrypt. Lists decrypt only the requested bounded page and use a stable opaque
cursor.

A future full-text index uses separately keyed HMAC terms, fixed limits, and an
explicit leakage statement. Until that implementation ships, documentation
labels sealed search as planned.

Benchmarks cover at least 100,000 and 1,000,000 message rows with budgets for
unlock, conversation-page latency, exact update/delete, migration memory, and
database growth.

### 6. Deletion claims are logical and best-effort locally

Deleting a record removes the live logical row and all application references.
Komms enables SQLite secure-delete behavior where supported, checkpoints and
truncates its WAL at bounded maintenance points, protects database/WAL/SHM and
lock files with owner-only permissions, and excludes them from platform cloud
backup unless the user explicitly exports an encrypted Komms backup.

These measures reduce remnants; they do not promise forensic erasure from
flash, filesystem snapshots, an adversary's prior copy, relay ciphertext, or a
recipient device. User copy therefore says “removed from this Komms history”
rather than “deleted for real.”

## Alternatives considered

### Encrypt only the whole SQLite file

Rejected as the sole control. Page encryption is useful defense in depth, but
does not by itself define authenticated logical identities, portable record
versions, safe migrations, or query leakage. A reviewed page-encryption layer
may be added underneath this design.

### Store SHA-256 of public identifiers

Rejected. Account keys and group ids are known or guessable to an attacker, so
an unkeyed hash preserves the social-graph oracle.

### Keep plaintext indexes because record bodies are sealed

Rejected. The social graph is an explicit protected asset, not harmless
database metadata.

### Drop old tables and `VACUUM` in place

Rejected. It creates complex failure states and cannot establish that old
plaintext keys have left WAL, freelist, snapshot, or physical storage.

### Promise cryptographic erasure through per-record keys

Rejected for v2. Deleting a wrapped per-record key from the same copy-on-write
storage has the same remanence problem. A future hardware-backed key ledger may
offer stronger local guarantees, but it must be measured and narrowly stated.

## Consequences

- A locked copied database no longer exposes exact account and group
  identifiers through its schema.
- Equality queries and history pagination become efficient without plaintext
  social-graph indexes.
- Every store operation and backup/restore path must handle explicit record and
  schema versions.
- Migration requires temporary space approximately equal to another database
  and must surface that requirement before starting.
- Database replacement and old-file cleanup need platform-specific
  qualification.
- Marketing loses an absolute deletion slogan and gains a claim the
implementation can defend.

## Implementation status

The first independently safe slice is implemented as an inactive v2 migration
destination in `kult-store`. It provides authenticated metadata with a fresh
database id, an explicit physical and authenticated schema version, and a
completed migration ledger. Its typed contact, capability, and message fixture
domains exercise table- and database-separated HMAC-SHA-256 equality indexes,
random append-row locators, versioned logical records, and the canonical
database/schema/table/locator AEAD binding above.

Opening that destination validates the complete physical schema and every row.
Fixtures cover future or disagreeing schemas, incomplete or duplicate
migrations, invalid inner logical keys and record versions, duplicate indexes,
cross-database/table/row transplantation, wrong keys, and locked-copy
inspection. The legacy `Store` entry points refuse a v2 destination before
running legacy schema statements.

This slice does **not** convert any current user table or activate a mixed
format. The all-table logical mapping, backup/restore integration, sibling-file
fsync and atomic replacement, rollback-copy lifecycle, private history query
indexes, large-history benchmarks, remnant reduction, and supported-platform
qualification remain required before ADR-0027 can be accepted.
