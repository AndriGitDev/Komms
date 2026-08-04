# Stable-v1 external security-review scope

## 1. Review objective and target

The objective is to find design, cryptographic, state-machine, persistence,
parser, integration, and downgrade failures that could violate the stable-v1
security contract. The reviewer should challenge both the stated invariants and
whether those invariants are sufficient for the adversaries in
[`docs/02-threat-model.md`](../../docs/02-threat-model.md).

The authoritative target is the full Git tree named by the deterministic
package report. The report binds:

- a 40-hex commit and its tree;
- the package-policy version;
- source file/byte counts;
- a deterministic archive name, size, and SHA-256 digest; and
- the required review documents and source prefixes.

A finding against another branch, release, deployment, or locally modified
tree must identify that different target explicitly. The stable-v1 profile is a
candidate protocol freeze, not a stable product release or prior assurance
claim.

## 2. Assets

The minimum protected assets are:

| Asset | Required property |
|---|---|
| Message and attachment content | Confidential and integrity-protected between intended accepted endpoints, subject to the documented compromised-endpoint limit |
| Claimed pairwise author | Derived from an authenticated handshake/session rather than cleartext content or transport metadata |
| Claimed group author | Authenticated separately for each recipient device before sender-chain advance or content application |
| Account continuity | Stable only across one accepted device-authority/recovery lineage; forks and competing recoveries remain visible and fail closed |
| Offline account root | Absent from live stores, routine links, sync, and normal backups after genesis; opened only for explicit offline recovery |
| Device and session secrets | Sealed locally, independently generated where required, excluded from portable backup, and rotated or erased on the declared transitions |
| Ratchet and sender-chain state | Advanced at most once for an accepted event and atomically with the corresponding durable effects |
| Local history and social graph | Protected by row-bound opaque storage within the documented locked-copy limitations |
| Connect capability | Rotatable independently of stable identity, sealed locally, and never published under a stable identity-derived locator |
| First-contact resources | Protected from unbounded puzzle, KEM, prekey, row, byte, notification, and lifecycle work |
| Mailbox custody | Acknowledged only after durable exact-row commit; removed only after exact endpoint staging and lease acknowledgement |
| Delivery truth | `queued`, `sent`, and `delivered` retain their documented, distinct meanings |
| Availability state | Optional service failure cannot silently change identity, trust, content format, or delivery semantics |
| Recovery history | Preserved only under the exact identity/security label supported by the source artifact |

Metadata, traffic analysis, endpoint compromise, radio observability, and
operator visibility remain assets with bounded rather than absolute
protection. The threat model's residual-risk table is part of scope: a reviewer
should report any limitation that is incomplete, misleading, or contradicted by
code.

## 3. Security invariants to attack

### 3.1 Pairwise establishment and ratchets

1. A prekey bundle is accepted only when its complete canonical contents,
   expiry, authority proof, device certificate, and admission descriptor
   validate for the intended account/device context.
2. A first-contact proof is target/bundle bound and checked before ML-KEM work
   where the protocol permits.
3. The PQXDH transcript binds both identities, the selected bundle and prekeys,
   all DH/KEM contributions, protocol version, and the initial ciphertext.
4. A session exporter is derived only from an authenticated completed
   transcript; provider and direction separation prevents rendezvous cross-use.
5. Invalid, replayed, excessively skipped, wrong-session, or wrong-version
   ratchet messages do not advance state.
6. Decrypt/open and commit are staged so a crash cannot consume a key without
   its accepted durable event, or expose an event without the matching state.
7. Legacy state cannot be interpreted as authenticated PQXDH/exporter state
   without the explicit authenticated upgrade.

### 3.2 Envelopes, content, and delivery

1. Canonical widths, versions, lengths, retention hints, padding, fragmentation,
   and content bounds are enforced before allocation or state change.
2. The outer delivery token, carrier, route, timestamp, display name, and
   content-supplied author fields cannot confer sender authority.
3. A malformed or unauthenticated receipt cannot advance `delivered`; optional
   service acceptance and wake never advance any delivery state.
4. Duplicate, reordered, delayed, fragmented, or multi-carrier envelopes apply
   at most one logical transition.
5. Expiry and view-once behavior cannot revive removed plaintext through
   delayed delivery or restore, while retaining the documented no-remote-
   deletion limitation.

### 3.3 Recipient-authenticated groups

1. One shared sender-key ciphertext remains recipient-deniable, while every
   recipient device receives and verifies a distinct pairwise-delivered origin
   capability.
2. The origin tag binds group and generation, sender account/device,
   sender-chain id, recipient account/device, content id, retention, and shared
   ciphertext digest.
3. Tag verification is constant-time and occurs before sender-chain advance or
   decryption.
4. Stored authors derive from the verified device certificate and accepted
   device-authority lineage, never from group content.
5. Roster, device, session, ownership, moderation, and authority changes rotate
   or erase affected origin capability state.
6. Legacy membership-authenticated history is not rewritten or displayed as
   individually authenticated.

### 3.4 Device authority and recovery

1. Every `KDA2` transition is versioned, bounded, append-only, parent-hash and
   generation bound, and contains the complete next active/revoked set,
   immutable new certificates, transition kind/id, and required signatures.
2. Ordinary changes require a strict majority of the previous active set. A
   minority compromise cannot add, replace, rename, or revoke authority.
3. Ordering never selects between incompatible valid descendants. Forks,
   same-epoch recoveries, stale backups, and recovery conflicts are visible and
   fail closed.
4. Root recovery revokes every former active device, creates exactly one fresh
   recovery device, advances the epoch, and rotates discovery, rendezvous,
   wake, group, sync, and delivery state.
5. Descendants of older epochs never regain authority.
6. The account private root is absent from live stores, routine migration,
   routine backup, linked-device packages, and sync after genesis.
7. Copied-root Alpha artifacts cross an explicit new-identity/authority-reset
   boundary and do not silently preserve stronger identity claims.

### 3.5 Opaque storage, backup, and atomic state

1. Every sensitive equality lookup uses a database- and domain-separated keyed
   index; every sealed row binds database, schema, table, and final locator.
2. Copying a sealed value to a different row/domain/database fails
   authentication.
3. Migration is restartable and does not leave an accepted mixed plaintext/
   sealed state or a rollback path to weaker state.
4. The single-writer and path/lock rules cannot be bypassed through the
   supported filesystem aliases within their stated platform boundary.
5. Typed commit plans encompass all security-relevant effects of the
   transition; failpoints before and after commit preserve an explainable old
   or new state.
6. Root-free portable backup excludes ratchets, sender chains, live delivery
   queues, prekeys, provisional requests, replay tombstones, invitation
   capabilities, rendezvous exporters/state, wake state, and active device
   secrets.
7. Restore never resurrects expired/revoked authority or live service/session
   secrets, and legacy backup labels remain accurate.

### 3.6 First contact, discovery, and mailbox custody

1. Unknown senders enter only the fixed-count/fixed-byte sealed provisional
   domain until explicit acceptance.
2. Accept, Delete, Block, invitation, prekey consumption, replay tombstones,
   and request promotion are atomic and bounded.
3. Refusals are uniformly bounded and do not reveal request-inbox capacity.
4. Connect locators and record keys are capability/epoch derived with separate
   domains and the exact candidate, byte, record, clock, and window bounds.
5. Standard and Private discovery records contain no direct route. Sovereign
   direct-route publication requires its explicit warning.
6. Valid-record selection under invalid-candidate crowding is deterministic,
   bounded, and fails closed on authority conflict.
7. Mailbox deposit, registration, quota, lease, expiry, acknowledgement, and
   deletion state survives restart and disk-full/error failpoints.
8. Response loss, duplicate lease pages/acks, partial endpoint capacity,
   refusal, and hostile pagination cannot lose or delete unrelated rows.
9. The sender retains ciphertext until an authenticated end-to-end receipt or
   a declared terminal retry result.

### 3.7 Malformed input and integration

1. Every public decoder and network/RPC/FFI boundary applies a fixed byte,
   element, nesting, allocation, concurrency, and lifecycle bound before
   untrusted work.
2. Non-canonical encodings, unknown required versions, trailing bytes,
   truncation, overflow, duplicate identifiers/keys, and invalid Unicode fail
   according to the portable specification without panic or partial mutation.
3. Error/refusal shapes do not reveal secret material, plaintext, stable
   identity, social labels, mailbox tokens/locators, or hidden capacity.
4. Daemon and FFI synchronization/panic behavior cannot poison shared state or
   bypass the canonical node contract.
5. Desktop, Android, and iOS shells never recreate security decisions from
   render fields or stale local projections.

## 4. Review work packages

The proposed engagement is one integrated review with four work packages.
Proposers may change the effort allocation, but omitting an item requires an
explicit residual-scope note.

### WP1 — Protocol design and cryptographic composition

- the stable-v1 normative specification, threat model, cryptography
  specification, and accepted protocol ADRs;
- ML-KEM-768/X25519 hybrid composition and transcript binding;
- Double Ratchet/header encryption/skipped-key behavior;
- sealed envelopes, receipts, padding, fragmentation, and downgrade behavior;
- recipient-authenticated group origins and sender-key interaction;
- domain separation, associated data, randomness, erasure, and constant-time
  comparisons; and
- the conformance vectors and negative/state fixtures as test oracles, not as
  proof of security.

Primary source:

- `crates/kult-crypto/src/{handshake,prekeys,ratchet,group,util}.rs`
- `crates/kult-protocol/src/{envelope,content,fragmentation,receipt,group}.rs`
- `conformance/v1/`
- `docs/adr/0002-*.md`, `0003-*.md`, `0012-*.md`, `0029-*.md`, and
  `0035-*.md`

### WP2 — Identity, device authority, recovery, storage, and atomicity

- account/device certificate and `KDA2` lineage validation;
- strict-majority transitions, fork/conflict behavior, recovery epochs, and
  old-epoch rejection;
- link/approval ceremonies and root isolation;
- backup KKR8–KKR10, legacy reset/archive boundaries, secret exclusions, and
  restore rotations;
- opaque index/row binding, migration, writer exclusion, and deletion limits;
  and
- typed store/node commit plans, failpoints, notification recovery, and
  cross-domain crash invariants.

Primary source:

- `crates/kult-crypto/src/{device_authority,device_link_authority,recovery_authority,device}.rs`
- `crates/kult-store/src/{store_v2,migration,backup,commit,devices}.rs`
- `crates/kult-node/src/{authority,devices,atomic_tests}.rs`
- `docs/adr/0026-*.md`, `0027-*.md`, and `0028-*.md`
- `docs/34-atomic-transition-inventory.md`

### WP3 — Admission, discovery, mailbox, rendezvous, and wake

- pre-work first-contact validation and global/per-source resource budgets;
- sealed provisional consent and blocking transitions;
- Connect capabilities, epoch derivations, record selection, migration, and
  authenticated upgrades;
- mailbox-v2 durable acceptance, quota persistence, leases, exact
  acknowledgement, fairness, and crash/disk-full behavior;
- pairwise rendezvous exporter/slot/key derivation, fixed records, replay,
  generation, provider/direction separation, and client orchestration; and
- native-wake capability scope, key rotation/revocation, quotas, static
  payloads, and unchanged delivery semantics.

Primary source:

- `crates/kult-crypto/src/{admission,discovery,rendezvous}.rs`
- `crates/kult-protocol/src/{admission,discovery,rendezvous,wake}.rs`
- `crates/kult-transport/src/{internet,mailbox_v2,rendezvous,wake}.rs`
- `crates/kult-mailbox/`, `crates/kult-reference-service/`,
  `crates/kult-rendezvous/`, `crates/kult-wake/`, and `crates/kult-ohttp-relay/`
- `crates/kult-store/src/{admission,rendezvous,wake}.rs`
- `crates/kult-node/src/lib.rs`
- `docs/adr/0018-*.md`, `0019-*.md`, `0030-*.md`, `0031-*.md`, and
  `0032-*.md`

### WP4 — Boundary, parser, and adversarial integration review

- all codec entry points, fuzz targets, malformed fixtures, and allocation
  bounds;
- node/store/transport trust seams and source-scoped authority;
- daemon RPC framing, secret handling, filesystem/socket assumptions, and
  denial-of-service bounds;
- UniFFI type conversion, runtime ownership, error redaction, and shell
  projection;
- backup/import/courier file parsing; and
- optional-service least-authority boundaries where they intersect stable-v1
  endpoint security.

Primary source:

- `crates/kult-conformance/`, `crates/kultd/`, and `crates/kult-ffi/`
- `crates/kult-crypto/fuzz/` and `crates/kult-protocol/fuzz/`
- `apps/desktop/`, `apps/android/`, and `apps/ios/`
- `.github/workflows/` and `scripts/local-release-matrix.sh`

## 5. Architecture and trust boundaries

```text
Desktop / Android / iOS / CLI
              |
        RPC or typed UniFFI
              v
          kult-node
       /      |       \
 crypto   protocol   store-v2
   |          |          |
 secrets   bounded     sealed rows,
 and state  codecs      typed commits
       \      |       /
        transport scheduler
              |
 direct / DHT / mailbox / LAN / mesh / courier
              |
 optional rendezvous and wake services
```

The intended dependency/trust rules are:

- `kult-crypto` performs no I/O and owns secret-bearing protocol state.
- `kult-protocol` owns bounded encodings and must not make authority decisions
  from unauthenticated display fields.
- `kult-store` performs no network I/O and accepts only domain-bound sealed
  data plus typed atomic transitions.
- `kult-transport` never receives content plaintext or user identity private
  keys.
- `kult-node` is the only composition/orchestration authority.
- RPC/UniFFI/shell layers expose typed commands and render-safe projections;
  they do not reimplement trust or ordering.
- optional services may observe their documented network/service metadata,
  deny or interfere, but must not decrypt or authenticate a Komms message.

Reviewers should treat every seam as hostile and test whether a lower layer's
validated fact becomes an unvalidated higher-layer assumption.

## 6. Attack-surface map

| Surface | Inputs controlled by | Principal failure classes |
|---|---|---|
| Prekey/PQXDH | DHT node, inviter, initiator, stale endpoint | signature/transcript confusion, KEM-before-admission exhaustion, OPK replay, downgrade |
| Ratchet/envelope | peer, relay, carrier, reordered store | state advance on failure, replay, skip-window exhaustion, type/version confusion |
| Group origins | malicious member/device, removed member, stale recipient | author forgery, wrong recipient/device, shared-ciphertext substitution, capability reuse |
| Device authority | compromised minority/majority, stale backup, root thief | quorum bypass, fork selection, old-epoch revival, copied root |
| Store/migration | copied/tampered database, hostile path, crash/disk full | row transplant, plaintext index, partial migration, lock bypass, non-atomic effect |
| Backup/restore | stale/tampered/legacy file, stolen phrase/root | secret inclusion, identity overclaim, rollback, revoked state resurrection |
| Admission | Sybil sender, invitation thief, flood source | unbounded CPU/KEM/prekeys/disk/notifications, capacity oracle, consent bypass |
| Connect/DHT | censor, eclipse node, candidate flood, clock rollback | stable lookup correlation, invalid crowding, authority suppression/conflict, route leak |
| Mailbox v2 | malicious operator/client, response loss, restart | false durable acceptance, unrelated delete, lease confusion, quota reset, allocation loop |
| Rendezvous/wake | provider, capability thief, replay source | identity correlation, cross-provider/direction use, stale route, false delivery state |
| RPC/FFI/files | local untrusted client, malformed import, lifecycle race | panic/poison, secret error/log, unbounded frame, stale projection authorization |

## 7. Build and validation

The source archive includes lock files and exact scripts, not a dependency
cache or platform SDK. On a networked preparation host:

```sh
cargo fetch --locked
```

After dependencies are present, the core review baseline is:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --offline --workspace --all-features
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings
cargo build --locked --offline -p kult-crypto -p kult-protocol --no-default-features
python3 scripts/check-docs.py
python3 scripts/test_security_review_package.py
python3 scripts/security_review_package.py --revision HEAD --check
```

The portable contract baseline is:

```sh
cargo build --locked --offline -p kult-conformance
python3 scripts/update-conformance-vectors.py \
  --check --adapter target/debug/kult-conformance
python3 scripts/build-conformance-kit.py --check
python3 conformance/v1/run.py \
  --adapter target/debug/kult-conformance
cargo test --locked --offline -p kult-conformance
```

The complete platform, dependency, fuzz, scale, desktop, Android, and iOS
commands are in
[`scripts/local-release-matrix.sh`](../../scripts/local-release-matrix.sh) and
[`docs/24-local-release-gate.md`](../../docs/24-local-release-gate.md).
Platform deferrals and explicitly ignored physical/scale gates must be
reported rather than converted to passes.

Reviewers are encouraged to add independent models, proofs, differential
fixtures, fault injection, fuzz corpora, or test harnesses. A harness derived
from this implementation remains valuable finding evidence, but is not by
itself the separately produced interoperability execution tracked by P0-06.

## 8. Known limitations and open evidence

The following are disclosed starting conditions, not instructions to ignore
related vulnerabilities:

- no prior independent security review or independent interoperability run
  exists;
- the account root remains ultimate recovery authority; theft can take over
  the account and revoke every device;
- a compromised strict majority can authorize an ordinary device-authority
  branch;
- persistently compromised unlocked endpoints can observe everything their
  user can;
- service operators and network observers can observe their documented
  timing, volume, address, token/locator, and availability metadata;
- Private mode has no non-collusion claim without separately administered
  ingress;
- real APNs/FCM, deployed services, physical-device lifecycle, real NAT,
  sudden-power-loss, forensic, and two-radio evidence remain open;
- the portable backup fixture fixes the root-free outer/security semantics but
  does not claim every richer shell collection schema is a language-neutral
  interchange format;
- upstream primitive libraries and operating systems are dependencies rather
  than fully re-audited code, but their selection, version, configuration,
  calls, assumptions, and misuse remain in scope;
- side-channel claims are limited to intended constant-time operations and
  secret-independent structure; no comprehensive physical side-channel
  qualification exists; and
- all public product claims remain Beta until the evidence ledger closes the
  applicable gates.

Any reviewer conclusion that one of these limits is understated, internally
inconsistent, or broader in code is a finding.

## 9. Explicitly out of scope

Unless added by written scope change:

- live video, very large groups, advanced moderation, additional
  delay-tolerant carriers, federation, and post-v1 standards expansion;
- proof of security for the mathematical primitives themselves;
- a comprehensive audit of every upstream dependency, compiler, OS, firmware,
  app store, APNs, FCM, Tor, libp2p, or radio implementation;
- physical invasive side-channel or hardware fault attacks;
- a global-passive-adversary anonymity guarantee;
- resistance to a persistently compromised endpoint or coerced unlock;
- production infrastructure penetration testing, because no reference,
  mailbox, or wake production service is in this review target;
- legal, trademark, nonprofit, governance, or licensing advice; and
- product usability/accessibility/field qualification except where a shell
  boundary can bypass or misstate a security decision.

An out-of-scope dependency or environment remains relevant when its integration
invalidates an in-scope assumption. The final report should identify every
material area that could not be reviewed within time rather than imply
coverage.
