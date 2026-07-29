# 33: Opaque Store Qualification

This record separates implemented storage guarantees from filesystem and
forensic claims that still need real platform evidence. It covers the
ADR-0027 schema, legacy migration, encrypted backup restore, local remnant
maintenance, and large-history budgets.

## 1. Locked-database contract

The active schema has three application tables: `store_bootstrap`,
`store_metadata`, and `store_records`. The six application indexes cover a
domain plus locator, unique lookup, or one of four secondary index slots.
Sensitive logical domains do not have their own SQLite columns or indexes.

The record table serves these 25 domains:

- identity, sessions, capabilities, messages, queue, seen ids, receipt replay,
  contacts, prekeys, pending envelopes, and session resets;
- groups, group authority, group chains, and group messages;
- media transfers, media objects, local metadata, note messages, scheduled
  messages, and ephemeral state; and
- device state, device sync, contact devices, and per-device message delivery.

An equality locator is HMAC-SHA-256 under a key separated by database, table,
and locator purpose. Append-style rows use random 16-byte locators. Secondary
indexes use separately derived purposes, so a value cannot be correlated
between databases, domains, or index slots.

Every row's XChaCha20-Poly1305 associated data includes the final database id,
physical schema version, logical table domain, and final locator. The sealed
logical envelope repeats its record version, logical key, secondary keys, and
payload. Opening a store checks that the decoded key reproduces its locator,
that decoded secondary keys reproduce every SQLite index, and that the decoded
payload agrees with the key for that record type.

Pairwise and group history use keyed unique message-id indexes and keyed
conversation indexes. Pages are limited to 512 records and use a 57-byte
authenticated cursor bound to the database, domain, conversation, and last
row. Exact edit and delete first use the unique index, then verify the decoded
logical identity before changing the located row.

Retained tests cover locked-copy identifier inspection, valid-ciphertext
logical-key and secondary-index mismatch, database/table/locator transplant,
cursor forgery and cross-context reuse, stale cursors, and SQLite query plans
for page and exact-id lookups. Arbitrary bounded logical-envelope bytes are
also decoded under a no-panic property test.

## 2. Released-schema migration

Released SQL fixtures are retained for `v0.1.0`, `v0.2.0`, and `v0.3.0`.
Migration accepts only an exact released layout. Each table has a strict row
count and value-type contract; individual ciphertexts, total rows, and decoded
records are bounded before allocation or insertion. Plaintext legacy keys must
equal the identities inside their decoded records.

The source is validated and fingerprinted before replacement. A new private
sibling database receives a fresh random database id. Copying uses 256-row
transactions and a sealed checkpoint containing the source fingerprint, next
table, last row id, and copied counts. A restart resumes only if the current
source and checkpoint still agree.

Group authority and chains, media object ownership, contact devices, and
per-device delivery rows receive referential validation. Completion verifies
per-table counts, SQLite integrity, absence of the checkpoint, the authenticated
migration ledger, every opaque row, and a complete reopen.

Before work starts, free space must cover three times the source database and
WAL size, 1,024 bytes per source row, and a 64 MiB reserve. The completed
sibling is checkpointed out of WAL mode, synced, and directory-synced. The
source is separately checkpointed and copied to a synced rollback sibling.
Replacement then uses the platform's atomic replace operation. The containing
directory is synced before the new database is reopened and fully validated;
only then is the rollback copy removed and that removal directory-synced.

Five replacement interruption points cover:

1. completed sibling before rollback creation;
2. synced rollback before replacement;
3. replacement before directory sync;
4. directory sync before reopen; and
5. validated reopen before rollback cleanup.

Restart tests prove that each phase either resumes migration, opens the complete
new store, or restores the valid rollback copy. Malformed type, oversized row,
logical-key mismatch, missing reference, changed source, incomplete checkpoint,
count mismatch, and replacement-recovery tests fail closed. Early validation
failure leaves the active legacy path untouched and does not create a rollback
copy.

These tests exercise process interruption at each named boundary. They are not
evidence of behavior under sudden power loss, controller write-cache failure,
filesystem corruption, snapshot rollback, or flash remapping.

## 3. Backup and restore boundary

Encrypted `KKR1` through `KKR8` files decode into versioned logical records.
Only current root-free `KKR8` resumes its stable public identity. Legacy
`KKR1`–`KKR7` is decode-only in production and is projected into a
fresh-identity local archive that omits
groups and live protocol state. The decrypted payload never
contains the source database id, keyed locators or indexes, SQLite pages, or
wrapped opaque-store row ciphertext.

Restore validates the complete logical payload, record counts, duplicates,
bounds, and references before creating the destination. Its free-space check
requires twice the decoded logical bytes, 2,048 bytes per restored record, and
a 64 MiB reserve. It writes a fresh private sibling with a fresh database id,
performs full store validation, checkpoints and syncs the file, directory-syncs,
atomically installs it only at an absent destination, directory-syncs again,
and reopens it.

Three restore interruption points cover the synced sibling, installed file
before directory sync, and directory-synced file before reopen. Restart tests
prove that a partial sibling is either rejected and honestly cleaned up or a
fully installed store opens normally. Restore never silently clobbers an
existing destination.

## 4. Bounded deletion maintenance

Logical deletion removes the live row and application references. The
maintenance API enables full SQLite `secure_delete`, requests at most 4,096
incremental-vacuum pages per call, and accepts a WAL checkpoint bound no larger
than 256 MiB. It truncates the WAL only when the observed file fits the caller's
bound and no reader prevents completion. The report includes freelist and WAL
measurements, whether truncation was deferred, and a value that is always false
for forensic-erasure guarantee.

SQLite cleanup can reduce remnants in the live Komms files. It cannot erase a
prior copy, filesystem snapshot, recipient copy, SSD-remapped block, carrier
ciphertext, or operating-system artifact. User copy therefore describes
logical removal from this Komms history, not physical or remote erasure.

## 5. Large-history budgets and results

`scripts/store-scale-gate.sh` creates the released `v0.3.0` schema, inserts
sealed legacy messages, migrates it, fully reopens and validates it, reads a
64-row conversation page, edits one middle message by exact id, deletes one
message by exact id, and measures SQLite main/WAL growth. It runs both required
sizes with the mobile Argon2id profile.

The budgets are:

| Rows | Migration | Unlock | Page | Exact edit | Exact delete | Peak RSS increase | Database + WAL |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 180 s | 30 s | 250 ms | 250 ms | 250 ms | 512 MiB | 64 MiB + 1,024 B/row |
| 1,000,000 | 1,800 s | 180 s | 500 ms | 500 ms | 500 ms | 768 MiB | 64 MiB + 1,024 B/row |

The 2026-07-26 Linux qualification measured commit `23c423c` on x86_64,
kernel 6.12.13, ext4, and Rust 1.88.0. Both sizes passed:

| Rows | Migration | Unlock | Page | Exact edit | Exact delete | Peak RSS increase | Database + WAL |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 10.824 s | 1.171 s | 378 µs | 3.021 ms | 1.232 ms | 70.62 MiB | 49.92 MiB |
| 1,000,000 | 143.641 s | 10.425 s | 388 µs | 2.575 ms | 1.120 ms | 70.50 MiB | 501.14 MiB |

Timing results describe this host and source revision, not every supported
device. The enforced budgets are regression ceilings rather than product
latency promises.

## 6. Platform qualification

| Platform/filesystem | Evidence in this change | Still open |
|---|---|---|
| Linux/ext4 | Owner-only database, WAL, SHM, lock, and media-directory mode tests; index/privacy tests; all migration and restore interruption points; real file and directory sync calls; atomic same-directory replacement; both scale sizes | Sudden-power-loss rig, controller/cache faults, snapshots, backup-exclusion integration, and forensic examination |
| macOS/APFS | Shared Unix permission, sync, and replacement implementation; scheduled macOS core test is configured | A result for this revision, power-loss behavior, app-container/backup exclusion, snapshots, and forensic examination |
| Windows Server 2025/NTFS (hosted) | [CI run 30225556928](https://github.com/AndriGitDev/Komms/actions/runs/30225556928) on commit `d8b328e` explicitly identified the checkout volume as NTFS, then passed the complete storage suite: released-schema migration, logical backup/restore, every replacement interruption point, opaque-index and privacy checks, exact history operations, and cross-process writer exclusion. The replacement path uses replace-existing and write-through semantics. | Owner-only ACL enforcement, directory durability under sudden power loss, physical storage behavior, backup integration, snapshots, and forensic examination |
| Android/iOS app filesystems | The Rust storage path is shared with the Unix implementation | Physical-device migration/restore, lifecycle interruption, app-private permissions, cloud-backup exclusion, free-space behavior, power-loss behavior, and forensic examination |

No unsupported cell is promoted by inference. The hosted Windows result
establishes code-path compatibility for that exact revision and identified
filesystem. It does not close physical filesystem, backup, power-loss,
permissions, snapshot, or forensic cells. A hosted macOS result remains open.

## 7. Repeatable commands

The focused storage checks are:

```sh
cargo test -p kult-store --lib -- --test-threads=1
cargo test -p kult-store --test backup -- --test-threads=1
scripts/store-scale-gate.sh
```

The complete publication candidate runs
`scripts/local-release-matrix.sh`, which includes the scale gate, workspace and
desktop Rust checks, backup/restore tests, parser fuzz targets, platform host
checks where their SDKs exist, dependency policy, and final repository review.

The remaining open evidence above is intentionally not represented as passed.
