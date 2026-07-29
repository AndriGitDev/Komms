# Release evidence ledger

**Ledger date:** 2026-07-29

**Release scope:** stable-v1 candidate

**Current evidence baseline:** [`main@5a0addc`](https://github.com/AndriGitDev/Komms/tree/5a0addcff54a07d412f54187d691bf489bd08b56);
the stable protocol-transition expansion was merged by
[PR #82](https://github.com/AndriGitDev/Komms/pull/82)

**Baseline automated run:** [`a02b064`, CI run 197](https://github.com/AndriGitDev/Komms/actions/runs/30199264838);
this successful PR-head tree is the tree merged by PR #77

**Release-control run:** [`25daa69`, CI run 199](https://github.com/AndriGitDev/Komms/actions/runs/30202463092);
all nine jobs passed on draft PR #78

**Accountable release owner:** Andri (`@AndriGitDev`)

**Stable release decision:** not authorized; all P0 gates remain open

**Next ledger review:** 2026-08-09

This is the canonical release-scoped ledger required by P0-01. It records
evidence; it does not turn a design, test, or founder review into independent
assurance. Links to repository tests identify the current evidence source.
Closure requires retained run output tied to an exact revision and environment,
plus every named external artifact.

Andri temporarily owns founder and internal project categories. Every
independent role is explicitly **Unassigned** until a named external person
accepts it and the assignment is recorded in
[MAINTAINERS.md](../MAINTAINERS.md).

## 1. P0 gate ledger

| Gate | Accountable owner | Current control evidence | Status and open gaps | Revision / artifacts | Next review |
|---|---|---|---|---|---|
| **P0-01 Honest claims and evidence ledger** | Andri (FND; interim SEC/PROD) | Designed: vocabulary, frozen claim register, and this ledger exist; the repository documentation check passed in release-control CI. | **Open.** External website and repository-description corrections remain; no stable release evidence bundle exists. | [Stabilization vocabulary](29-stabilization-program.md#2-evidence-vocabulary); [stable-v1 profile](30-stable-v1-product-profile.md); [CI run 199](https://github.com/AndriGitDev/Komms/actions/runs/30202463092); this ledger; [public-copy follow-up](#4-public-copy-audit) | 2026-08-09 |
| **P0-02 Name-risk assessment and recorded decision** | Andri (FND and project risk owner); qualified trademark counsel: **Unassigned** | Designed: dated founder decision, observed overlap, migration cost, cadence, and escalation triggers recorded. | **Open.** This is not legal clearance. No qualified similarity/class/jurisdiction opinion or trademark/asset policy exists. | [Name-risk decision](32-name-risk-decision.md); [brand system](28-brand-system.md) | 2026-10-26, or trigger event |
| **P0-03 Stabilized core product profile** | Andri (FND; interim PROD/SEC) | Designed: product boundary, bounds, supported-system rule, services, and exclusions frozen. Nineteen typed plan kinds cover legacy migration plus root-free profile bootstrap, pairwise, group, attachment, scheduled activation, bounded maintenance, `KDA2` device control/link/sync, contact projection and restart presentation. ADR-0026 and ADR-0029 are accepted and implemented for Alpha: strict-majority device authority, recovery epochs, root-free `KKR8`, recipient-authenticated encrypt-once groups, visible legacy upgrade, deterministic crash tests, strict RPC/UniFFI, host shells, and Android/iOS simulator builds. Retained CI run 217 remains evidence for the earlier expanded matrix, Windows storage, MSRV, `no_std`, dependency policy and 22 earlier full-budget fuzz targets; the current source still needs revision-bound CI retention. | **Open.** ADR-0028 and ADR-0030 through ADR-0032 remain proposed. First-contact admission/legacy alias replacement, capability discovery and leased relay custody remain outside stable-v1 acceptance; revision-bound CI, field qualification, sudden-power-loss evidence, independent interoperability and independent security review are also open. | [Stable-v1 profile](30-stable-v1-product-profile.md); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0026](adr/0026-revocable-device-authority.md); [ADR-0029](adr/0029-recipient-authenticated-groups.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [root-free backup and legacy reset tests](../crates/kult-store/src/backup.rs); [baseline revision](https://github.com/AndriGitDev/Komms/commit/f17a60636a074b889105d7e123caf0fa475bebfc); [expanded revision](https://github.com/AndriGitDev/Komms/commit/6c73f71b18f120e5a3072fe77dfcd122cbf287dd); [CI run 217](https://github.com/AndriGitDev/Komms/actions/runs/30303253034); [P0 ADR index](adr/README.md) | 2026-08-09 |
| **P0-04 Clean-install and real-network golden path** | Andri (interim NET/PROD); independent field evaluator: **Unassigned** | Implemented with local/CI evidence for internet components and shells. | **Open.** No qualified default bootstrap/mailbox, clean-device distinct-NAT matrix, default-blackhole journey, replacement operator, or pure-core journey. | [Internet tests](../crates/kult-node/tests/internet_e2e.rs); [Alpha guide](27-alpha-testing.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md) | 2026-08-09 |
| **P0-05 Unsolicited-contact abuse admission** | Andri (interim SEC/NET/PROD); independent adversarial/usability evaluator: **Unassigned** | Designed, with automated evidence for interim byte/count bounds. | **Open.** No pre-KEM admission, durable request inbox, consent promotion, identity block implementation, or adversarial/field evidence. Current first contact can create normal contact state. | [ADR-0030](adr/0030-first-contact-admission.md); [transport bounds](05-transports.md); [protocol tests](../crates/kult-protocol/tests/protocol.rs) | 2026-08-09 |
| **P0-06 Independent crypto and protocol assurance** | Andri (interim SEC); independent cryptography reviewer: **Unassigned**; independent interoperability implementer: **Unassigned** | Automated evidence for local KATs, properties, sessions, and protocol decoding. | **Open.** No external vectors, separate implementation, review scope, findings report, disposition, or residual-risk statement. P0 protocol/security ADRs remain proposed. | [Baseline CI](https://github.com/AndriGitDev/Komms/actions/runs/30199264838); [Crypto KATs](../crates/kult-crypto/tests/kat.rs); [properties](../crates/kult-crypto/tests/properties.rs); [session tests](../crates/kult-crypto/tests/session.rs); [cryptography spec](04-cryptography.md) | 2026-08-09 |
| **P0-07 Signed and recoverable distribution** | Andri (interim REL/SEC); independent release evaluator: **Unassigned** | Implemented Alpha packaging with checksums; some workflow provenance/SBOM paths exist. | **Open.** Stable desktop/mobile signing, protected release-key recovery, authenticated updates, reproducibility measurements, clean install/upgrade/rollback, store/repository publication, and external verification are missing. | [Release runbook](25-release-runbook.md); [release workflow](../.github/workflows/release.yml); [0.3 Alpha artifacts](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0) | 2026-08-09 |
| **P0-08 Durable mailbox and operator qualification** | Andri (interim NET/SEC); independent operator evaluator: **Unassigned** | Implemented Alpha mailbox-v1 behavior with automated bounds and end-to-end receipt tests. | **Open.** Mailbox v1 can delete before endpoint custody. Persistent v2 deposits, leases, restart/disk-full/overload/expiry/multi-operator evidence, published operator policy, and maintained self-hosting cost model are missing. | [ADR-0032](adr/0032-leased-mailbox-delivery.md); [node mailbox tests](../crates/kult-node/tests/mailbox_e2e.rs); [transport mailbox tests](../crates/kult-transport/tests/mailbox.rs) | 2026-08-09 |
| **P0-09 Field qualification across supported claims** | Andri (interim PROD/NET/REL); independent accessibility/field evaluator: **Unassigned** | Implemented shells with host, simulator, packaging, and hosted Windows/NTFS core-storage evidence. | **Open.** No published named-device/OS/NAT/background/handoff/accessibility/recovery/two-radio matrix. macOS and Linux stable support cells are not frozen. | [Local release gate](24-local-release-gate.md); [opaque-store qualification](33-opaque-store-qualification.md); [HIL bench](10-hil-bench.md); [candidate platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems) | 2026-08-09 |
| **P0-10 Accountable founder authority, review, and incidents** | Andri (FND; interim COM/SEC); independent reviewers and backup steward: **Unassigned** | Implemented as public governance, ownership, security intake, recusal, release authority, and incident policy. | **Open.** No accepted backup steward, independent sensitive-surface reviewers, rehearsed incident record, or continuity handoff. Founder self-review is not independent. | [Governance](../GOVERNANCE.md); [maintainers](../MAINTAINERS.md); [security and incidents](../SECURITY.md); [CODEOWNERS](../.github/CODEOWNERS); [ADR-0033](adr/0033-nonprofit-founder-stewardship.md) | 2026-08-09 |

### Session 6 local development validation

On 2026-07-29, the ADR-0026 working tree based on `37330f7` was exercised on
arm64 macOS 26.5.2 with Rust 1.97.0 and Xcode 26.6. The source had not yet been
assigned a commit and the output was not retained by CI, so this record is
development validation only. It does not raise an evidence level or close a
P0 gate.

- The complete all-feature Rust workspace and desktop suites passed with
  warnings denied. Formatting, lint, dependency policy, `no_std`, strict
  RPC/UniFFI, linked-device adversarial, backup/recovery, and deterministic
  transaction/publication crash suites passed.
- A separate production-default workspace build passed with the superseded
  root-carrying link codec absent and legacy root-writing store constructors
  and commit variants confined to the explicit `legacy-test-fixtures`
  boundary.
- All 22 release-matrix fuzz targets completed their 60-second budgets: seven
  cryptographic decoders/openers and fifteen protocol/state decoders. No crash
  or sanitizer artifact was produced.
- The large-store gate passed at 100,000 rows (11.130 s migration, 1.881 s
  unlock, 617 µs page, 369 µs edit, 283 µs delete, 52,367,776 bytes) and
  1,000,000 rows (174.260 s migration, 19.434 s unlock, 2.316 ms page,
  3.224 ms edit, 805 µs delete, 525,545,888 bytes).
- The Android host-core suite, arm64/x86_64 debug APK assembly, and Android
  lint passed. The installed APK cold-launched on an Android 15
  `sdk_gphone64_arm64` emulator. Its expected unlock controls were present in
  the accessibility hierarchy; `FLAG_SECURE` correctly withheld app pixels
  from the screenshot.
- The 27-test Swift host suite, XCFramework build, generated iOS project, and
  unsigned iOS Simulator app build passed. A clean iOS 26.5 iPhone 17e
  simulator rendered the first-run branding, disclosure, unlock/restore,
  passphrase, and advanced-network controls without observed clipping.

The Android emulator and iOS Simulator observations are not physical-device,
lifecycle, accessibility, or field qualification. Revision-bound CI,
sudden-power-loss testing, named physical-device recovery/linking, independent
interoperability, and independent security review remain open.

### Session 7 local development validation

On 2026-07-29, the cumulative ADR-0026/ADR-0029 working tree based on
`37330f7` was exercised on arm64 macOS 26.5.2 with Rust 1.97.0 and Xcode 26.6.
The source had not yet been assigned a commit and the output was not retained
by CI, so this record is development validation only. It does not raise an
evidence level or close a P0 gate.

- The complete all-feature Rust workspace passed twice, including a
  warnings-denied run. Formatting, documentation/version checks, all-target
  lint, dependency policy, production-default and `no_std` builds, strict
  RPC/UniFFI, desktop, daemon, node, storage, crash, and integration suites
  passed.
- Group tests covered fixed-width recipient tags, constant-time comparison,
  malicious-member wrapper reuse, wrong recipient/device/context, replay and
  reorder, stale and conflicting origin announcements, sender-chain
  non-advancement on rejection, roster/device/session/authority rotation,
  restore/reset, linked-device filtering, shared-mesh delivery, and atomic
  crash points.
- The desktop shell passed 8 unit and 24 end-to-end tests. Its three-member
  journey established the full pairwise member mesh, completed recipient-origin
  exchange on every active device, preserved independent delivery state, and
  repeated origin exchange after roster, role, moderation, and ownership
  generation changes.
- All 24 fuzz targets completed their 60-second budgets: eight cryptographic
  decoders/openers and sixteen protocol/state decoders. No crash or sanitizer
  artifact was produced. The new group-origin envelope and group-control
  targets completed 23,549,652 and 5,299,002 iterations respectively.
- The large-store gate passed at 100,000 rows (12.140 s migration, 1.931 s
  unlock, 629 µs page, 436 µs edit, 294 µs delete, 52,351,392 bytes) and
  1,000,000 rows (214.324 s migration, 19.956 s unlock, 1.959 ms page,
  2.616 ms edit, 1.058 ms delete, 525,529,504 bytes).
- The Android host-core suite, arm64/x86_64 debug APK assembly, and Android
  lint passed. The installed APK cold-launched on an Android 15/API 35
  `sdk_gphone64_arm64` emulator. Its branding, privacy disclosure,
  encrypted-store controls, and advanced settings were present in the
  accessibility hierarchy; `FLAG_SECURE` withheld app pixels from the
  screenshot as designed.
- The 27-test Swift host suite, device/simulator XCFramework build, generated
  iOS project, and unsigned simulator build passed. An iOS 26.5 iPhone 17 Pro
  simulator rendered the first-run branding, disclosure, unlock/restore,
  passphrase, and advanced-network controls without observed clipping.
  Existing Swift 6 concurrency and audio deprecation warnings remain open for
  release-engineering cleanup.

The Android emulator and iOS Simulator observations are not physical-device,
background-lifecycle, accessibility, or field qualification. Existing Gradle
migration warnings also remain. Revision-bound CI and retained fuzz output,
named physical-device group upgrade/removal/restore journeys, independent
interoperability, and independent security review remain open.

## 2. Stable public claim register

These are the complete stable public claims authorized by the frozen profile.
The quoted wording is the strongest stable wording permitted after its evidence
closes. Until then, public copy must use the current evidence level and disclose
the listed gap. A new stable claim requires a new identifier here.

| Claim | Stable wording | Owner | Current evidence level | Revision / artifacts | Open gaps | Next review |
|---|---|---|---|---|---|---|
| **SV1-C01 Distribution** | Supported Komms clients install, update, and recover through authenticated release paths. | Andri (REL/SEC); external release evaluator: **Unassigned** | Implemented Alpha packaging only | [0.3 release](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0); [release runbook](25-release-runbook.md) | P0-07 signing, updates, rollback, reproducibility, and key recovery | 2026-08-09 |
| **SV1-C02 Local identity** | Komms identity can be created without a required phone number, email address, real name, or project account. | Andri (SEC/PROD); external reviewer: **Unassigned** | Automated evidence | [Identity design](06-identity-trust.md); [node e2e](../crates/kult-node/tests/node_e2e.rs); [FFI e2e](../crates/kult-ffi/tests/ffi_e2e.rs) | Independent protocol review and supported-platform clean-install evidence | 2026-08-09 |
| **SV1-C03 Pairwise confidentiality and authenticity** | Accepted contacts exchange authenticated end-to-end encrypted pairwise text; intermediaries receive sealed envelopes rather than message plaintext. | Andri (SEC); external cryptography reviewer: **Unassigned** | Test evidence | [`main@4fda544`](https://github.com/AndriGitDev/Komms/tree/4fda544739c0665b6a324256d858c16c1d73d992); [KATs](../crates/kult-crypto/tests/kat.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [pairwise crash matrix](../crates/kult-node/src/atomic_tests.rs) | P0-06 external vectors, review, and interoperability evidence | 2026-08-09 |
| **SV1-C04 Contact establishment** | Intentional Connect codes and bounded message requests establish contact without making a project service the identity authority. | Andri (SEC/NET/PROD); external evaluators: **Unassigned** | Designed | [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md) | Implement, accept, adversarially test, and field-qualify v2 contact flow | 2026-08-09 |
| **SV1-C05 Pairwise text bounds and atomicity** | One stable-v1 text event carries at most 65,507 UTF-8 bytes and changes visible/delivery state only through its complete atomic transition. | Andri (SEC/PROD); external reviewer: **Unassigned** | Test evidence | [Content codec](../crates/kult-protocol/src/content.rs); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [typed commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Independent protocol review and supported-platform sudden-power-loss qualification | 2026-08-09 |
| **SV1-C06 Bounded groups** | Stable-v1 groups support at most 64 active accounts and authenticate the claimed sender separately for every recipient. | Andri (SEC/PROD); external reviewer: **Unassigned** | **Implemented Alpha; external gates open.** One shared sender-key ciphertext is wrapped by a distinct fixed-width recipient tag whose key arrives over the authenticated pairwise device session. Verification precedes chain advance. Stored authors derive from the verified sender device and accepted authority chain. Live legacy groups visibly block until fresh exchange; old history retains its weaker label. Local tests cover known-answer and malformed codecs, wrong context/recipient/device, another member's valid-wrapper reuse, replay/reorder, monotonic announce races, membership/device/session/authority rotation, restore/reset, sync filtering, shared mesh, bounded fan-out, and transaction crash points across Rust, RPC, UniFFI and host shells. | [ADR-0029](adr/0029-recipient-authenticated-groups.md); [origin crypto](../crates/kult-crypto/src/group.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [attachment matrix](../crates/kult-node/tests/attachments_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [group crash matrix](../crates/kult-node/src/atomic_tests.rs); [RPC](../crates/kultd/tests/rpc_e2e.rs); [UniFFI](../crates/kult-ffi/tests/ffi_e2e.rs) | Retain revision-bound CI and fuzz artifacts; freeze stable wire/state and conformance vectors; obtain independent implementation/security review and named physical-device qualification | 2026-08-09 |
| **SV1-C07 Bounded attachments** | Consented attachments use authenticated resumable chunks, a 512 MiB primary limit, a 256 KiB preview limit, and no bulk airtime carrier. | Andri (SEC/PROD/NET); external reviewer and field evaluator: **Unassigned** | Test evidence for bounded metadata and file-first transitions | [Atomic inventory](34-atomic-transition-inventory.md); [ADR-0015](adr/0015-encrypted-attachment-pipeline.md); [protocol constants](../crates/kult-protocol/src/attachment.rs); [attachment e2e](../crates/kult-node/tests/attachments_e2e.rs); [media store tests](../crates/kult-store/tests/media.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | ADR-0015 acceptance or successor, protected-file device matrix and independent review | 2026-08-09 |
| **SV1-C08 Backup and recovery** | A versioned encrypted backup restores eligible user state on a clean supported device while live protocol secrets reset; offline account-root recovery replaces a lost device set. | Andri (SEC/PROD); external reviewer and field evaluator: **Unassigned** | **Implemented Alpha; external gates open.** Root-free `KKR8` and a separately held `.kra` authority use independent phrases. Restore creates a higher epoch and one fresh device. Legacy `KKR1`–`KKR7` are decode-only in production and can only create a fresh-identity former-account archive after a reviewed authority ceremony; no production API mints a new copied-root file, and crash-phase tests inspect staged and published stores to prove neither receives the former root. Plaintext exclusion tests cover account/device/prekey/ratchet/group/link/service/delivery secrets; stale backup, root theft, old epoch, fork/conflict, quorum loss, legacy-only-artifact reset, crash publication, strict RPC/UniFFI, desktop, host-mobile and simulator builds are exercised locally. | [Atomic inventory](34-atomic-transition-inventory.md); [storage contract](07-storage.md#4-backup--portability); [backup implementation/tests](../crates/kult-store/src/backup.rs); [backup e2e](../crates/kult-node/tests/backup_e2e.rs); [public FFI reset](../crates/kult-ffi/tests/ffi_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [ADR-0026](adr/0026-revocable-device-authority.md); [prior CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Retain revision-bound ADR-0026 CI artifacts, freeze stable wire/state format, run named clean physical-device and sudden-power-loss matrices, obtain independent interoperability and security review | 2026-08-09 |
| **SV1-C09 Blocking** | Blocking is an exact local identity rule that removes local relationship capabilities and state without claiming remote erasure or global identity revocation. | Andri (SEC/PROD); external abuse/usability evaluator: **Unassigned** | Designed | [ADR-0030](adr/0030-first-contact-admission.md#4-accept-reject-block-and-invite-are-explicit-state-transitions); [profile boundary](30-stable-v1-product-profile.md#7-blocking-and-deletion) | Implement block state/transitions across carriers, groups, capabilities, restore, and supported clients; adversarial/usability evidence | 2026-08-09 |
| **SV1-C10 Honest delivery** | Queued means durable local custody, sent means bounded next-hop custody, and delivered requires an authenticated end-to-end receipt; none means read. | Andri (SEC/NET/PROD); external evaluator: **Unassigned** | Automated evidence for current ladder; stable custody designed | [Architecture lifecycle](03-architecture.md#3-message-lifecycle); [transport semantics](05-transports.md); [node e2e](../crates/kult-node/tests/node_e2e.rs); [ADR-0032](adr/0032-leased-mailbox-delivery.md) | Durable direct admission, mailbox v2, crash matrix, operator and real-network qualification | 2026-08-09 |
| **SV1-C11 Supported platforms** | The stable release supports only the named device, OS, architecture, lifecycle, install, upgrade, and accessibility cells published as passed. | Andri (PROD/REL); independent field/accessibility evaluator: **Unassigned** | Implemented shells with automated build/simulator evidence | [Platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems); [release gate](24-local-release-gate.md) | P0-09 named physical matrix and exact macOS/Linux support cells | 2026-08-09 |
| **SV1-C12 Replaceable services** | Standard defaults are disclosed and replaceable; no project service is the user identity authority or receives message plaintext or user identity private keys. | Andri (NET/SEC/FND); external operator reviewer: **Unassigned** | Designed; pure-core components implemented | [Stabilization contract](29-stabilization-program.md#1-product-and-architecture-contract); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [self-hosting](26-self-hosting.md) | Dedicated reference services, public configuration/revision, default-blackhole and replacement evidence, independent operator review | 2026-08-09 |
| **SV1-C13 Resilient retry and fallback** | Komms retains queued work, retries within declared bounds, and can use more than one supported route; it does not guarantee availability or delivery time. | Andri (NET/PROD); external field evaluator: **Unassigned** | Automated evidence | [Transport design](05-transports.md); [node delivery tests](../crates/kult-node/tests/node_e2e.rs); [mesh policy tests](../crates/kult-node/tests/mesh_policies.rs); [sneakernet tests](../crates/kult-transport/tests/sneakernet.rs) | Real NAT, background, handoff, operator-failure, and two-radio field matrix | 2026-08-09 |
| **SV1-C14 Local deletion limits** | Delete removes live logical history and Komms-owned references from the current profile; it does not promise forensic or remote erasure. | Andri (SEC/PROD); external storage reviewer: **Unassigned** | Implemented with repeatable schema, migration, restore, remnant-control, Linux/ext4 scale, and hosted Windows Server 2025/NTFS storage-suite evidence | [Storage limits](07-storage.md); [ADR-0027](adr/0027-opaque-indexed-store.md); [qualification](33-opaque-store-qualification.md); [Windows/NTFS CI](https://github.com/AndriGitDev/Komms/actions/runs/30225556928); [opaque store](../crates/kult-store/src/store_v2.rs); [migration](../crates/kult-store/src/migration.rs); [backup tests](../crates/kult-store/tests/backup.rs); [ephemeral tests](../crates/kult-node/tests/ephemeral_e2e.rs) | Independent storage review; physical macOS, Windows, Android, and iOS qualification; sudden-power-loss, backup-exclusion, permissions, snapshot, and forensic evidence | 2026-08-09 |
| **SV1-C15 Nonprofit project mission** | Official Komms activity follows a nonprofit public-benefit mission; this is project policy, not registered-charity status and not a restriction on independent AGPL commercial use. | Andri (FND/COM; project policy owner); qualified legal reviewer: **Unassigned** | Implemented governance policy | [ADR-0033](adr/0033-nonprofit-founder-stewardship.md); [governance](../GOVERNANCE.md) | Legal entity, funding/trademark/asset policies, and qualified policy review remain P1 work | 2026-10-26 |

## 3. Evidence-level rules

1. A source file or ADR is **Designed**, not proof that runtime behavior occurs.
2. A merged implementation without a repeatable test is **Implemented**.
3. A test file becomes **Automated evidence** only when retained output names
   its exact revision, environment, command, and result.
4. Simulator, emulator, localhost, self-round-trip, or founder-only review does
   not satisfy field, independent interoperability, or independent review.
5. An independent role stays `Unassigned` until the named person has accepted
   the scope and conflict requirements in a public record.
6. A gate closes only through a ledger change that links all required artifacts
   and records founder release disposition. Closing one claim does not close
   another claim or its P0 gate.

## 4. Public-copy audit

### In-repository surfaces

The README, governance/security/contribution files, active product documents,
platform READMEs, and user-visible attachment copy are checked by
`python3 scripts/check-docs.py`. The check validates relative Markdown links,
the complete P0/claim identifiers, and terminology that previously overstated
deletion, source-metadata removal, evidence, or implementation provenance.

Negative statements such as “not independently audited” remain permitted and
necessary. The everyday promise “Private messaging that keeps working.” also
remains; the frozen profile supplies its availability limit.

### Public surfaces outside this repository

These corrections cannot be completed by this repository change and remain
P0-01 follow-up:

| Surface | Observed wording or risk | Required disposition |
|---|---|---|
| [`komms.org`](https://komms.org/) | The indexed page title still says 0.1 while the page presents 0.3. “works anywhere” and “truly deletable” exceed the stable claim register; the AGPL summary also compresses section-13 scope. | Align the version/title. Keep “Private messaging that keeps working.” Replace universal reachability and deletion wording with `SV1-C13` and `SV1-C14`; align the source-offer summary with ADR-0033. |
| [GitHub repository description](https://github.com/AndriGitDev/Komms) | “serverless” and “functional on & off the grid” can read as current universal/field-qualified claims. | Describe an Alpha with direct, local, radio, and file transport implementations and name the outstanding stable/field gates. |
| Release and package listings | Old screenshots, summaries, or package descriptions can outlive repository corrections. | Audit at every release; stable wording must cite a claim id and the release evidence bundle. |

The accountable owner for these external corrections is Andri. Completion must
be linked here before P0-01 closes.
