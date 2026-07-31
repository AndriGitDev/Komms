# Release evidence ledger

**Ledger date:** 2026-07-31

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
| **P0-03 Stabilized core product profile** | Andri (FND; interim PROD/SEC) | Designed: product boundary, bounds, supported-system rule, services, and exclusions frozen. Twenty-five typed plan kinds cover legacy migration plus root-free profile bootstrap, pairwise, group, attachment, scheduled activation, bounded maintenance, `KDA2` device control/link/sync, contact projection, ADR-0030 admission stage/accept/discard/sweep, complete-envelope `PendingStage`, and restart presentation. ADR-0017, ADR-0018, ADR-0019, ADR-0026, ADR-0029, ADR-0030, ADR-0031, ADR-0032, and ADR-0034 are accepted and implemented for Alpha: canonical Standard/Private/Sovereign policy, a signed replaceable provider directory with bounded last-valid/fork behavior, pinned direct-TLS and loopback-Tor rendezvous, transcript-bound rotating pairwise rendezvous with sealed non-backup state and visible forks, fixed-shape capability-gated native wake with durable identity-free revocation retries, bounded generic collection, direct APNs, Play-only FCM, and an inspected Google-free artifact, strict-majority device authority, recovery epochs, root-free KKR8–KKR10, recipient-authenticated encrypt-once groups, bounded provisional requests and explicit consent, capability-scoped fixed-size encrypted discovery, durable mailbox deposits and exact lease acknowledgement after endpoint commit, visible legacy upgrades, deterministic crash tests, strict RPC/UniFFI, host shells, simulator builds, and a locally validated two-role reference-service artifact. Retained CI run 217 remains evidence for the earlier expanded matrix, Windows storage, MSRV, `no_std`, dependency policy and 22 earlier full-budget fuzz targets; the current source still needs revision-bound CI retention. | **Open.** ADR-0028 remains proposed. The mode, rendezvous, and wake paths lack a reference deployment, qualified Tor/non-colluding-OHTTP ingress, retained multi-architecture image digest/SBOM/provenance/reproducibility evidence, hostile real-network evidence, independent interoperability/security review, and named physical-device qualification. No production directory, trusted root, qualified default operator, or wake gateway ships. Named physical APNs/FCM background/force-quit/Doze evidence remains open. Discovery has the same external/physical evidence gaps. The quarantined pre-C2 alias bridge remains outside stable-v1 acceptance; mailbox operator/upgrade/backup/cost qualification, field qualification, and sudden-power-loss evidence are also open. | [Stable-v1 profile](30-stable-v1-product-profile.md); [operating modes](36-operating-modes-and-provider-directory.md); [ADR-0017](adr/0017-optional-hybrid-modes.md); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0018](adr/0018-pairwise-rendezvous.md); [rendezvous matrix](../crates/kult-node/tests/rendezvous_e2e.rs); [ADR-0019](adr/0019-native-wake-gateway.md); [wake core](../crates/kult-node/src/lib.rs); [wake gateway](../crates/kult-wake/src/lib.rs); [wake runbook](37-native-wake-operations.md); [mobile wake matrix](38-native-wake-mobile-qualification.md); [reference service](../crates/kult-reference-service/src/lib.rs); [reference runbook](35-reference-service-operations.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [ADR-0026](adr/0026-revocable-device-authority.md); [ADR-0029](adr/0029-recipient-authenticated-groups.md); [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [ADR-0032](adr/0032-leased-mailbox-delivery.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [mailbox store](../crates/kult-transport/src/mailbox_v2.rs); [admission matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [root-free backup and legacy reset tests](../crates/kult-store/src/backup.rs); [baseline revision](https://github.com/AndriGitDev/Komms/commit/f17a60636a074b889105d7e123caf0fa475bebfc); [expanded revision](https://github.com/AndriGitDev/Komms/commit/6c73f71b18f120e5a3072fe77dfcd122cbf287dd); [CI run 217](https://github.com/AndriGitDev/Komms/actions/runs/30303253034); [P0 ADR index](adr/README.md) | 2026-08-09 |
| **P0-04 Clean-install and real-network golden path** | Andri (interim NET/PROD); independent field evaluator: **Unassigned** | **Implemented Alpha components; local journey evidence only.** One canonical mode contract, signed replaceable provider directory, bounded last-valid/fork behavior, manual opt-out, familiar shell status, and a repeatable host journey cover synthetic Standard defaults, configured-default blackhole, manual alternate bootstrap, authenticated replacement, pure-core/Sovereign operation, Connect-code contact, provisional consent, offline mailbox delivery, route repair, recovery, and restart invariants. | **Open.** No qualified default bootstrap/mailbox or production directory exists. The journey is hermetic/localhost, not two clean supported devices behind distinct ordinary NATs, a deployed default blackhole, an independently operated replacement, mobile handoff/background evidence, or a physical-device run. | [Operating modes](36-operating-modes-and-provider-directory.md); [local journey gate](../scripts/test-operating-mode-journeys.sh); [internet tests](../crates/kult-node/tests/internet_e2e.rs); [Alpha guide](27-alpha-testing.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md) | 2026-08-09 |
| **P0-05 Unsolicited-contact abuse admission** | Andri (interim SEC/NET/PROD); independent adversarial/usability evaluator: **Unassigned** | **Implemented Alpha; external gates open.** Signed expiring descriptors bind the exact bundle, puzzle/invitation policy, size and clock window. Fixed admission wrappers verify target-specific proofs before ML-KEM where possible. Global concurrency, puzzle/KEM, notification, per-tick, carrier, row and byte budgets constrain work. Valid strangers enter a sealed 32-row/512-KiB provisional domain through one atomic prekey/session/identity/safety-number/preview transition. Accept, Delete, Block and Sweep are typed atomic plans; group invites use explicit consent; KKR10 preserves bounded local blocks but excludes provisional, replay, invitation, prekey and live delivery state. Direct responses wait for exact durable staging/consumption and uniformly refuse invalid, duplicate or over-budget introductions. Capability-scoped Connect records carry the same descriptor without OPKs or direct Standard/Private routes. Rust, RPC, UniFFI, desktop, Android host and iOS simulator paths have local flood/Sybil/budget/prekey/replay/duplicate/disk-full/expiry/delayed-carrier evidence. | **Open.** Independent adversarial and usability review, named physical-device CPU/battery/background/accessibility evidence, mailbox-v2 operator admission, hostile-network discovery evidence, and retained revision-bound CI/fuzz evidence are missing. Optional reputation lists and evidence export are not implemented and are outside the current claim. | [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [admission crypto](../crates/kult-crypto/src/admission.rs); [admission codec](../crates/kult-protocol/src/admission.rs); [atomic provisional store](../crates/kult-store/src/admission.rs); [node admission matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [atomic crash/budget matrix](../crates/kult-node/src/atomic_tests.rs); [direct transport semantics](05-transports.md); [RPC evidence](../crates/kultd/tests/rpc_e2e.rs); [UniFFI evidence](../crates/kult-ffi/tests/ffi_e2e.rs) | 2026-08-09 |
| **P0-06 Independent crypto and protocol assurance** | Andri (interim SEC); independent cryptography reviewer: **Unassigned**; independent interoperability implementer: **Unassigned** | **Portable contract implemented; independent evidence open.** The versioned stand-alone specification covers canonical bounds and encodings, PQXDH, Double Ratchet, envelopes/content, recipient-authenticated groups, device authority/recovery, first contact, Connect discovery, mailbox v2, rendezvous, wake, atomicity, downgrade behavior, and malformed input. Fifty-one language-neutral exact cases, binary fixtures, state traces, a synthetic secret-free packet capture, a bounded adapter contract, manifest verification, and Komms fixture-consumption tests share one public source of truth. | **Open.** All current vectors and adapter results originate from the Komms implementation process. No separately produced implementation or fixture producer has run the kit, and no qualified external reviewer has published scope, findings, dispositions, retest results, or residual-risk statement. This row therefore records no independent interoperability or security claim. | [Protocol conformance](41-protocol-conformance.md); [ADR-0035](adr/0035-stable-v1-protocol-and-conformance-kit.md); [stand-alone specification](../conformance/v1/SPECIFICATION.md); [case manifest](../conformance/v1/manifest.json); [adapter](../crates/kult-conformance/src/lib.rs); [Crypto KATs](../crates/kult-crypto/tests/kat.rs); [properties](../crates/kult-crypto/tests/properties.rs); [session tests](../crates/kult-crypto/tests/session.rs) | 2026-08-09 |
| **P0-07 Signed and recoverable distribution** | Andri (interim REL/SEC); independent release evaluator: **Unassigned** | **Implemented validation controls; credential and external gates open.** The source-controlled policy separates the offline release manifest from Play upload, Google-free Android, iOS, macOS, and Windows roles, with explicit rotation and compromise response. Android app/core graphs are locked and artifact checksums are verified. Bounded validators enforce exact artifact-class signing coverage, canonical-matrix qualification, aggregate CycloneDX SBOM and dependency integrity tied to the checked-out locks/toolchain, exact/normalized/explained reproduction, independently administered report evidence, revision-authorized residual risk, deterministic safe archives, and complete evidence inventories. Workflow actions, the Swift test image, Rust bootstrap, XcodeGen, cargo tools, the BuildKit frontend, and container bases are immutable or checksum pinned. Builds default read-only; tag pushes retain only 90-day validation evidence and hosted attestations. Protected draft creation starts empty. Publication requires exact confirmation, an unchanged closed visual-approval record, an immutable completed asset set, an offline signature, bounded preflight, exact package/evidence digest agreement, and final metadata rechecks. | **Open.** No production role or offline release-manifest key/recovery copy is enrolled. The protected production-signing boundary therefore refuses to proceed. No production-signed Android, Apple, or Windows artifact, completed manifest signature, store account path, named-system install/upgrade/failure/rollback/compatibility result, externally administered reproduction, or independent release evaluation exists. The hosted second Linux build is measurement, not independence; the iOS artifact is Simulator-only. No release has exercised the new workflow, so revision-bound hosted artifacts and attestations are also pending. | [Release security and recovery](39-release-security-and-recovery.md); [release evidence bundles](40-release-evidence-bundles.md); [release policy](../release/policy-v1.json); [release workflow](../.github/workflows/release.yml); [release runbook](25-release-runbook.md); [local release gate](24-local-release-gate.md); [historical 0.3 Alpha artifacts](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0) | 2026-08-09 |
| **P0-08 Durable mailbox and operator qualification** | Andri (interim NET/SEC); independent operator evaluator: **Unassigned** | **Implemented Alpha; operator gate open.** `/komms/mailbox/2` commits opaque-indexed row-bound deposits before acceptance, persists registrations/deposits/leases/rate buckets/expiry across restart, retransmits bounded idempotent leases, and deletes only exact rows acknowledged after typed endpoint staging. Unregistered best-effort bridge transit explicitly refuses custody. Local tests cover response/ack loss, duplicate/partial/wrong-client acknowledgement, crash and disk-full failpoints, expiry/overload, key mismatch/row transplant, stable service identity, aggregate-only metrics/logging, bounded lifecycle work, and multi-operator deduplication. The self-hosting runbook records defaults, capacity/cost inputs, backup/restore, upgrade/rollback, v1 risk, and incident response. | **Open.** No revision-bound public deployment, observed resource/cost record, maintained backup/upgrade exercise, abuse/incident exercise, independent operator evaluation, real-network multi-operator matrix, or supported-platform sudden-power-loss evidence exists. Historical 0.3.0 artifacts predate v2 and do not count. | [ADR-0032](adr/0032-leased-mailbox-delivery.md); [mailbox store/failpoints](../crates/kult-transport/src/mailbox_v2.rs); [transport mailbox tests](../crates/kult-transport/tests/mailbox.rs); [node mailbox custody tests](../crates/kult-node/src/atomic_tests.rs); [node mailbox e2e](../crates/kult-node/tests/mailbox_e2e.rs); [operator runbook](26-self-hosting.md) | 2026-08-09 |
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

### Session 8 local development validation

On 2026-07-29, the cumulative ADR-0026/ADR-0029/ADR-0030 working tree based on
`37330f7` was exercised on arm64 macOS 26.5.2 with Rust 1.97.0 and Xcode 26.6.
The Session 8 source had not yet been assigned a commit and the output was not
retained by CI, so this record is development validation only. It does not
raise an evidence level or close a P0 gate.

- The complete all-feature Rust workspace passed with warnings denied.
  Formatting, documentation/version and message-request accessibility checks,
  all-target lint, dependency policy, production-default and `no_std` builds,
  strict RPC/UniFFI, desktop, daemon, node, storage, transport, deterministic
  crash, and integration suites passed.
- Admission tests covered signed bundle-bound descriptors, target-specific
  proof verification before KEM work, concurrency/work/notification/carrier
  budgets, the sealed 32-row/512-KiB provisional domain, atomic
  Accept/Delete/Block/Sweep transitions, group-invitation consent, exact
  direct-transport settlement, replay, duplicate, expiry, flood, delayed
  carriers, prekey exhaustion, and disk-full failpoints.
- The desktop shell passed 8 unit and 25 end-to-end tests, including message
  request decisions, invitation consent, authenticated capability exchange,
  attachments, and group-security upgrade prerequisites.
- All 25 fuzz targets completed their 60-second budgets. No crash or sanitizer
  artifact was produced. The admission-envelope target completed 14,860,587
  iterations; group-control, device-sync, and call-control completed 5,292,619,
  11,596,415, and 15,397,519 iterations respectively.
- The large-store gate passed at 100,000 rows (11.315 s migration, 1.869 s
  unlock, 1.673 ms page, 528 µs edit, 223 µs delete, 52,363,680 bytes) and
  1,000,000 rows (239.956 s migration, 20.542 s unlock, 1.583 ms page,
  2.478 ms edit, 1.213 ms delete, 525,595,040 bytes).
- The Android host-core suite, arm64/x86_64 debug APK assembly, and Android
  lint passed. In a separate targeted check, the installed APK cold-launched
  in 1.729 seconds on an Android 15/API 35 `sdk_gphone64_arm64` emulator. Its
  branding, disclosure, password semantics, unlock control, and advanced
  settings were present in the accessibility hierarchy; `FLAG_SECURE`
  withheld app pixels from the screenshot as designed.
- The 28-test Swift host suite, device/simulator XCFramework build, generated
  iOS project, and unsigned simulator build passed. A separate clean install
  on an iOS 26.5 iPhone 17e simulator rendered the first-run disclosure and
  encrypted-store controls without observed clipping.

The Android emulator and iOS Simulator observations are not physical-device,
battery/background-lifecycle, accessibility, usability, or field
qualification. Existing Gradle migration and Swift concurrency/audio warnings
remain. Revision-bound CI and retained artifacts, named physical-device
resource and lifecycle evidence, independent adversarial/usability review,
independent interoperability, and independent security review remain open.

### Session 9 local development validation

On 2026-07-30, the cumulative ADR-0026/ADR-0029/ADR-0030/ADR-0032 working tree
based on `37330f7` was exercised on arm64 macOS 26.5.2 with Rust 1.97.0 and
Xcode 26.6. The Session 9 source had not yet been assigned a commit and the
output was not retained by CI, so this record is development validation only.
It does not raise an evidence level or close a P0 gate.

- The complete all-feature Rust workspace passed with warnings denied.
  Formatting, documentation/version and accessibility checks, all-target lint,
  dependency policy, production-default and `no_std` builds, strict
  RPC/UniFFI, desktop, daemon, node, storage, transport, deterministic crash,
  and integration suites passed.
- Mailbox-specific tests covered durable commit before acceptance, random
  relay rows, opaque indexes, row-bound sealing, restart persistence,
  idempotent duplicate deposit and lease behavior, response and acknowledgement
  loss, exact partial acknowledgement, wrong-client refusal, expiry, rate and
  capacity limits, disk-full and crash failpoints, storage-key mismatch and row
  transplant, stable least-authority service identity, strict file permissions,
  symlink refusal, aggregate-only metrics/logging, bounded daemon and FFI
  collection, and multi-operator deduplication.
- Direct and mailbox custody tests required complete-envelope `PendingStage`
  commit before acknowledgement. Repeated relay pages resolved to the existing
  opaque content row. Unregistered bridge transit remained best effort and
  explicitly refused custody, while sender ciphertext remained queued through
  an authenticated end-to-end receipt.
- The desktop shell passed 8 unit and 25 end-to-end tests. The Android host-core
  suite, arm64/x86_64 debug APK assembly, and Android lint passed.
- All 25 fuzz targets completed their 60-second budgets. No crash or sanitizer
  artifact was produced. The mailbox-adjacent admission-envelope target
  completed 15,216,470 iterations; the stateful reassembler, group-control,
  device-sync, and call-control targets completed 3,955,002, 5,217,218,
  11,268,875, and 15,401,077 iterations respectively.
- The large-store gate passed at 100,000 rows (12.065 s migration, 2.079 s
  unlock, 651 µs page, 660 µs edit, 199 µs delete, 52,371,872 bytes) and
  1,000,000 rows (199.874 s migration, 21.307 s unlock, 1.802 ms page,
  3.062 ms edit, 1.161 ms delete, 525,758,880 bytes).
- In a separate targeted check, the installed APK cold-launched in 2.284
  seconds on an Android 15/API 35 `sdk_gphone64_arm64` emulator. Its branding,
  disclosure, password semantics, unlock control, restore action, and advanced
  settings were present in the accessibility hierarchy; `FLAG_SECURE` withheld
  app pixels from the screenshot as designed.
- The 28-test Swift host suite, device/simulator XCFramework build, generated
  iOS project, and unsigned simulator build passed. A separate clean install
  on an iOS 26.5 iPhone 17e simulator rendered the first-run disclosure and
  encrypted-store controls without observed clipping.

The Android emulator and iOS Simulator observations are not physical-device,
battery/background-lifecycle, accessibility, usability, sudden-power-loss, or
field qualification. Existing Gradle migration and Swift concurrency/audio
warnings remain. Revision-bound CI and retained artifacts, a deployed operator
with observed capacity/cost and backup/upgrade exercises, a real-network
multi-operator matrix, named physical-device evidence, independent operator
evaluation, independent interoperability, and independent security review
remain open.

### Session 10 local development validation

On 2026-07-29, the cumulative ADR-0026/ADR-0029/ADR-0030/ADR-0031/ADR-0032
working tree rooted at `37330f7` was exercised on arm64 macOS 26.5.2 with Rust
1.97.0 and Xcode 26.6. The Session 10 source had not yet been assigned a commit
and the output was not retained by CI, so this record is development validation
only. It does not raise an evidence level or close a P0 gate.

- Warnings-denied all-target/all-feature lint, formatting, production-default
  and `no_std` builds, documentation/version and accessibility checks, and the
  affected crypto, protocol, store, transport, node, daemon, RPC, UniFFI and
  desktop compile surfaces passed.
- Unit suites passed 41 crypto, 62 protocol, 61 store, 34 node and 37 transport
  tests; one deliberate store scale test remained ignored. Discovery-specific
  tests covered Connect-code checksum and account binding, independent locator
  and record-key derivation, fixed-size authenticated records, weekly publish
  and lookup windows, epoch rollback, invalid-candidate crowding, conflicting
  valid authority, capability rotation, legacy retirement, mode route policy,
  admission/prekey/authority republish, authenticated contact/device upgrades,
  backup/restore, restart and old-generation rejection.
- Broad non-socket integration matrices passed for attachments, backup,
  bridge, mock calls, carrier policy, contact rename, ephemeral content,
  first-contact admission, folders, groups, icons, incognito policy, labels,
  linked devices, mesh policy, edits, node retry/reorder, notes, pins,
  scheduled messages, screen security, single-writer enforcement and theme.
  A regression test preserves an established explicit route when a
  capability-only authenticated upgrade omits a complete route set.
- The new discovery-record fuzz target completed 7,770,776 iterations in its
  60-second budget and the discovery-control target completed 17,651,561
  iterations in its 60-second budget. Neither produced a crash or sanitizer
  artifact. Both are included in the local and CI release matrices.
- Desktop test targets compiled with warnings denied. The current Rust source
  produced the host, iOS-device and iOS-simulator native slices and assembled
  the XCFramework. The generated Swift bindings, KommsCore package and host
  test targets then compiled and linked against that library.

An unrestricted follow-up completed loopback Rust, RPC and UniFFI execution;
the 29-test Swift host suite; Android core/build, APK and lint gates under JDK
17; and clean launches of the current source on an Android API 35 emulator and
an iPhone 17 Pro simulator. The rendered first-run security gate was inspected
through the Android accessibility hierarchy because screen capture is
deliberately blocked there. Dependency-policy refresh and revision-bound CI
retention remain open. Emulator and Simulator observations are not
physical-device, battery/background, accessibility, usability, hostile
real-network, independent interoperability or independent security evidence.

### Session 11 local development validation

On 2026-07-30, the cumulative Sessions 6–11 working tree based on `685b43e`
was exercised on arm64 macOS 26.5.2 with Rust 1.97.0, the declared Rust 1.88
minimum, Xcode 26.6, and JDK 17.0.20. These local results are not retained by
hosted CI and do not raise an evidence level or close a P0 gate.

- A clean non-incremental all-target/all-feature workspace run passed the
  crypto, protocol, store, transport, node, rendezvous, daemon, RPC and UniFFI
  suites. The ordinary run omitted only the explicitly ignored large-store
  qualification and physical two-radio HIL cases. The large-store gate then
  passed separately at both 100,000 and 1,000,000 messages. The million-row
  result migrated in 249.475 seconds, unlocked in 20.602 seconds, kept exact
  page/edit/delete operations between 1.1 and 2.2 milliseconds, and used
  525,578,656 bytes, all within the published budgets.
- Formatting, warnings-denied all-target/all-feature lint, documentation,
  release-version and message-request accessibility controls, dependency
  policy, `no_std` crypto/protocol builds, whitespace checks, and the Rust 1.88
  all-target/all-feature compatibility build passed. Dependency policy retains
  the already documented non-fatal Meshtastic SPDX and duplicate-version
  warnings.
- ADR-0018 coverage passed the transcript-bound exporter vector, provider and
  direction separation, fixed 4,096-byte route record and fixed HTTP shapes,
  constant-bound parsing, generation/replay/clock rejection, legacy
  authenticated re-handshake, restore rotation, provider-conflict visibility,
  source-separated route hints, bounded trigger/coalescing/backoff/circuit
  behavior, capacity/overload, and blackhole delivery-state cases. The
  dedicated service crate remained persistence-free and identity-free in these
  tests; its deployable network/TLS wrapper is Session 12 work.
- Pairing and delivery regressions covered the `KDI2` simultaneous-first-flight
  convergence path, the `KPB2` authority-and-capability pairing wrapper needed
  for offline mailbox first contact, six-record discovery publication without
  single-owner RPC starvation, and negative attachment terminal states that
  cannot be overwritten by delayed remote control frames.
- The new rendezvous crypto target completed 64,588 iterations and the
  rendezvous protocol target completed 1,728,931 iterations in their
  60-second budgets. The changed device-prekey/pairing decoder completed
  19,457,753 iterations in 61 seconds. None produced a crash, hang, or
  sanitizer artifact.
- The desktop workspace passed warnings-denied lint, 8 unit tests and all 25
  end-to-end tests. The Android generated-binding/JVM suite passed; ARM64 and
  x86_64 APK assembly and lint passed under JDK 17; and the current APK
  cold-launched in 1.504 seconds on the running Android 15/API 35
  `sdk_gphone64_arm64` emulator. The live accessibility hierarchy exposed the
  expected first-run disclosure, encrypted-store passphrase, backup restore,
  and advanced-network controls.
- The 29-test Swift host suite passed. Host, iOS-device and both iOS-simulator
  native slices assembled into the XCFramework; the unsigned Simulator app
  built, installed and launched on an iOS 26.5 iPhone 17 Pro simulator. Visual
  inspection showed the expected branded first-run disclosure, unlock/restore,
  passphrase, and advanced-network surfaces. Existing Swift concurrency/audio
  and Gradle migration warnings remain.

The emulator and Simulator observations are not physical-device,
battery/background-lifecycle, accessibility, usability, sudden-power-loss, or
field qualification. The two-radio HIL row remains open. Revision-bound hosted
CI retention, deployment and independent operation of the reference service,
default-blackhole and replacement-provider journeys, qualified Private ingress,
hostile real-network evidence, independent interoperability, and independent
security review also remain open.

### Session 12 local development validation

On 2026-07-30, the cumulative Sessions 6–12 working tree based on `57e8a3f`
was exercised on arm64 macOS 26.5.2 with Rust 1.97.0 and a Docker 29.2.1
Linux/arm64 runtime. The source and local image were not yet assigned or tied
to a final commit and the output was not retained by hosted CI, so this is
development validation only.

- The dedicated reference-service suite passed 13 unit tests and 2 deployment
  profile tests. Coverage includes strict versioned configuration, non-symlink
  bounded key/config reads, distinct and matching service credentials, exact
  DHT namespaces/value widths/row and byte bounds, volatile rate buckets,
  a real Komms client's fixed-width Connect-record round trip, blackholed
  bootstrap and clean restart, canonical TLS 1.3 HTTP shapes, uniform
  fixed-size malformed responses, loopback-only aggregate health, and absence
  of configurable persistent or privileged roles.
- Formatting, warnings-denied targeted lint, shell lint, reusable-workflow
  lint, Compose parsing, and whitespace checks passed. The checked deployment
  profile requires an immutable image reference, numeric unprivileged user,
  read-only root, all-capability drop, `no-new-privileges`, equal memory and
  memory-plus-swap limits, zero core limit, bounded CPU/process/file
  descriptors, read-only config/key binds, bounded tmpfs, and the disabled
  container log driver.
- A locked release build completed inside the pinned Rust 1.88 Bookworm image.
  The resulting final uncommitted validation image was
  `sha256:f914f0c087bf2c14fdfa9ae3fc883094c9c034f02a9dbf705742a6d0de991e4e`,
  31,581,580 bytes, and reported `linux/arm64`, user `10002:10002`, a direct
  service-binary entrypoint, and the deliberately non-release revision label
  `validation-session12-final`. The hardened Compose smoke path generated
  separate temporary credentials, reached healthy, restarted, reached healthy
  again, and confirmed the disabled log driver.

No OCI index was published and no published digest, SBOM, provenance,
reproducibility comparison, named-host hardening, production key rotation,
public uptime/incident history, external operator, default-blackhole/replacement
journey, or Private-mode non-collusion evidence was earned. No reference
service was deployed. The one remaining deployment action for this session is
to show an exact host, administrative domain, immutable image and rollback
digests, and service-key fingerprints, obtain explicit authorization, apply
the validated profile, and complete the public operator record.

### Session 13 local development validation

On 2026-07-30, the cumulative Sessions 6–13 working tree based on `7288ec7`
was exercised on arm64 macOS 26.5.2 with Rust 1.97.0, Xcode 26.6, an Android
15/API 35 arm64 emulator, and an iOS 26.5 iPhone 17e simulator. The source was
not yet assigned or tied to a final commit and the output was not retained by
hosted CI, so this is development validation only.

- Provider-directory tests covered canonical signatures, bounded parsing,
  parent and generation binding, authenticated key rotation, rollback and
  fork conflicts, invalid-candidate last-valid retention, staleness, manual
  route preservation, and explicit opt-out without cache deletion.
- Pinned TLS 1.3 and loopback-Tor rendezvous tests covered mode separation,
  invalid proxy and direct-fallback refusal, provider reconciliation, and
  monotonic source handling. Daemon and UniFFI journeys preserved identity,
  safety numbers, verified contacts, local history, scheduled work, and honest
  delivery state across Standard, Private, and Sovereign restarts.
- The repeatable local journey gate exercised signed Standard configuration,
  alternate bootstrap, configured-default blackhole, authenticated operator
  replacement, directory opt-out, pure-core operation, Connect-code discovery,
  first-contact consent, offline durable mailbox delivery, authenticated route
  repair, rendezvous recovery, and backup restore/rekeying.
- Desktop, Android, and iOS tests consumed the same versioned settings fixture,
  rejected unknown modes, and checked each mode's disclosure and preserved
  user routes. A current Android debug APK was clean-installed and cold-launched
  on the API 35 emulator; its live accessibility hierarchy exposed the three
  mode controls, disclosure text, signed-directory fields, manual routes, and
  loopback-Tor configuration.
- A current arm64/x86_64 unsigned iOS Simulator app was clean-installed and
  launched on the iPhone 17e simulator. Visual inspection confirmed the
  Standard metadata disclosure, the Private Tor and non-collusion boundary,
  and the Sovereign route-preservation and direct-publication warning.

These journeys are hermetic host, localhost, emulator, and Simulator evidence.
They are not clean distinct-NAT, real-operator, qualified Tor/OHTTP,
background-lifecycle, battery, accessibility, physical-device, or field
qualification. No production provider directory, trusted root, default
operator, or service was configured or deployed.

### Session 14 local development validation

On 2026-07-30, the cumulative Sessions 6–14 working tree based on `9b13a75`
was exercised on arm64 macOS 26.5.2 with Rust 1.97.0, Xcode 26.6, OpenJDK
17.0.20, Gradle 9.6.1, and a Docker 29.2.1 Linux/arm64 runtime. The source and
local image had not yet been assigned or tied to a final commit and the output
was not retained by hosted CI, so this is development validation only.

- The required-platform local release matrix passed with Android and iOS app
  gates mandatory and every configured fuzz target given 60 seconds. It passed
  release/version, documentation, message-request accessibility, formatting,
  warnings-denied all-target/all-feature lint, all-feature workspace tests,
  documentation tests, crypto/protocol `no_std` builds, dependency policy, and
  whitespace checks. Dependency policy retained the already documented
  non-fatal Meshtastic SPDX, duplicate-version, unmatched allowance, and stale
  advisory-ignore warnings.
- Native-wake coverage passed fixed-shape codec vectors and malformed inputs,
  authenticated per-contact/per-device/per-direction capability exchange,
  exact generation conflict visibility, durable bounded gateway replay and
  revocation state, key rotation overlap, provider error reduction, quotas,
  coalescing, blackhole deadlines, aggregate-only health, sealed non-backup
  client state, durable revoke retry, next-hop-only triggering, and collection
  that cannot advance delivery state or activate mesh, sneakernet,
  attachments, or calls. A full 19-case daemon RPC rerun also passed after
  discovery maintenance was restricted to its heartbeat/lifecycle paths, so a
  read-only startup RPC no longer launches a blocking DHT publication before
  the next local request.
- The 100,000-row opaque-store gate migrated in 11.320 seconds, unlocked in
  1.929 seconds, completed page/edit/delete operations in 593/377/231
  microseconds, and used 52,363,680 bytes. The 1,000,000-row gate migrated in
  176.108 seconds, unlocked in 19.220 seconds, completed page/edit/delete in
  1.596/2.659/1.085 milliseconds, and used 525,726,112 bytes. Every measured
  value remained within the published time, memory, and database budgets.
- The desktop workspace passed 10 unit and 26 end-to-end tests. Android host
  core/build and tests passed, then arm64 and x86_64 native libraries, debug
  APK assembly, and lint passed. The generated Swift bindings and 30-test iOS
  host suite passed in 262.552 seconds; the iOS-device and both simulator
  native targets assembled into the XCFramework, and the unsigned arm64
  Simulator app built. Existing Gradle migration and Swift concurrency/audio
  warnings remain.
- All 10 crypto and 20 protocol fuzz targets completed their 60-second runs
  without a crash or sanitizer artifact. The new `wake_decode` target completed
  2,204,711 executions, expanded from 687 to 730 coverage edges, and minimized
  78 retained corpus cases. The physical two-radio HIL test remained
  deliberately ignored because no physical-radio run was requested or
  represented by this matrix.
- A locked local wake-gateway image was inspected as
  `sha256:d93e81e6229fe3683f7cff1b35e5ac142013a4ba67865cc2263af682532ece11`,
  30,901,465 bytes, `linux/arm64`, user `10003:10003`, direct `kult-wake`
  entrypoint, and deliberately non-release revision
  `validation-session14-working-tree`. The hardened Compose smoke path
  generated separate temporary credentials under the repository target
  directory, reached healthy, survived a restart, reached healthy again, and
  confirmed the disabled container log driver.

No wake image was published or deployed, no production APNs/FCM or operator
credentials were used, and no real provider delivery occurred. The image
digest is working-tree validation, not provenance or reproducibility evidence.
Simulator and host builds are not physical-device, background-lifecycle,
battery, notification-provider, accessibility, usability, or field
qualification. Named physical iOS/Android evidence, the two-radio HIL row,
revision-bound hosted CI retention, independent review, and deployed-operator
qualification remain open.

### Session 15 local development validation

On 2026-07-31, the cumulative Sessions 6–15 working tree based on `bcee6b1`
was exercised on arm64 macOS 26.5.2 with Rust 1.97.0, Xcode 26.6, OpenJDK
17.0.20, Gradle 9.6.1, an Android 15/API 35 arm64 emulator, and an iOS 26.5
iPhone 17 Pro Simulator. The source had not yet been assigned or tied to a
final commit and the output was not retained by hosted CI, so this is
development validation only.

- Eight focused node wake tests and all 22 UniFFI end-to-end tests passed.
  Coverage includes bounded complete relationship reconciliation, atomic
  capability rotation and revocation, provider-set replacement, mode
  transitions, immediate revocation when a saved provider configuration no
  longer matches the running node, legacy rows without wake state, strict wake
  configuration, and delivery state that cannot be advanced by a wake request.
  Discovery publication remains confined to the actor heartbeat and lifecycle
  paths rather than ordinary request handling.
- Every command in the required-platform local release matrix passed. The
  root-through-desktop stages ran under the matrix driver. After that shell
  did not inherit the Homebrew JDK path, the mandatory Android, iOS, and fuzz
  stages were resumed with the same commands and explicit installed
  toolchain paths rather than treating them as deferred. Workspace
  all-feature tests, `no_std` builds, dependency policy, and all 19 daemon RPC
  cases passed. Dependency policy retained only its already documented
  Meshtastic SPDX, duplicate-version, unmatched allowance, and stale
  advisory-ignore warnings.
- The 100,000-row opaque-store gate migrated in 12.924 seconds, unlocked in
  2.009 seconds, completed page/edit/delete in 613/751/574 microseconds, and
  used 52,392,352 bytes. The 1,000,000-row gate migrated in 331.905 seconds,
  unlocked in 24.477 seconds, completed page/edit/delete in
  1.573/5.689/2.284 milliseconds, and used 525,459,872 bytes. Every measured
  value remained within the published budget.
- The desktop workspace passed 10 unit and all 26 end-to-end tests under a
  real loopback environment. The settings surface maps the common wake
  contract and retains the pre-unlock incognito-input invariant for every
  editable field.
- The Android core build and all 36 tests passed. Play and Google-free app
  unit tests, debug assembly, and lint passed. The Google-free APK inspection
  found no Firebase, FCM, Google Play Services, registration service, or
  advertised wake capability. Both flavors installed and cold-launched on
  the API 35 emulator; the Play flavor remained usable without local Firebase
  application configuration.
- All 34 iOS core tests passed twice; the final post-review run completed in
  271.313 seconds. Device and both Simulator native slices assembled into the
  XCFramework, and the unsigned Simulator app built, installed, and launched.
  The implementation uses APNs directly, keeps the native token process-only,
  accepts only fixed generic payload profiles, bounds collection, handles
  token/permission/Background App Refresh state, and does not use PushKit.
- A revision-, artifact-, platform-, OS-, device-, network-, and carrier-bound
  field harness generated and validated the eleven required mobile lifecycle
  rows. It rejects secret or content-bearing fields and refuses to record a
  Simulator or emulator observation as a passing physical-device result.
- Release workflow and local-matrix definitions build both Android flavors,
  inspect the Google-free artifact, and retain distinct artifact names.
  Formatting, documentation, release-version, accessibility, JSON, YAML,
  shell, Python syntax, and whitespace checks passed.
- All 10 crypto and 20 protocol fuzz targets completed their 60-second
  budgets without a crash, hang, or sanitizer artifact. The wake decoder
  completed 2,147,657 executions and expanded from 730 to 766 coverage edges
  and from 797 to 849 features. Reassembly, attachment-manifest,
  group-control, and rendezvous targets also retained new local corpus
  coverage; generated corpora remain excluded by the repository's existing
  fuzz-corpus policy.

The emulator and Simulator launches prove only host integration and packaging.
No APNs or FCM provider credential was used, no provider delivery occurred,
and no background, force-quit, Background App Refresh, Doze/OEM,
deprioritization, battery, notification-permission, real-network, or
accessibility row was executed on a named physical device. Direct Standard
and loopback-Tor Private code paths are implemented, but qualified deployed
ingress, non-colluding OHTTP, production gateway operation, and independent
review remain open. Sovereign and provider-failure fallback retain the
ordinary direct, mailbox, and other configured delivery paths in local tests.

### Session 16 local development validation

On 2026-07-31, commit
`00be156710b262b03de592424e20619e903ca03e` was exercised on arm64 macOS
26.5.2 with Rust 1.97.0, Xcode 26.6, OpenJDK 17.0.20, Gradle 9.6.1, Android
API 35/NDK 27.2.12479018, and Docker client 29.5.2.

- The required-platform local release matrix completed without a deferred
  software gate. Release/version, documentation, message-request
  accessibility, formatting, warnings-denied lint, all-feature workspace
  tests, documentation tests, crypto/protocol `no_std`, root and desktop
  dependency policy, and whitespace checks passed. All 22 UniFFI and 19
  daemon RPC end-to-end cases passed with loopback networking available.
- The release-record suite passed 34 regression and end-to-end cases covering
  exact inventories, deterministic packing and safe extraction, malformed and
  oversized archives, semantic SBOM/dependency verification, artifact-class
  signing, canonical qualification matrices, independent-reproduction claims,
  residual-risk disposition, channel promotion, and publication preflight.
  Workflow, shell, and Python static validation also passed.
- A revision-bound Android inventory resolved 152 locked declarations with
  zero unknown licenses, zero policy-only declarations, 62 POM chains, and
  zero POM mismatches. The generated license, dependency, and 872-component
  CycloneDX records had SHA-256 digests
  `6f6fb802cc6b4694887180600a61178e57f37819456e9d85885e89da2f49a60e`,
  `9ec4cf44ad0849845d0185c3c48b47b0c197fbbc1dcdc29e237d956b992083e7`,
  and
  `782fdef853625a831620b8e770d3b8c38d874437b9e4f426d58aed41c92c5e49`.
  These are local generated records under ignored temporary storage, not
  signed retained release evidence.
- The 100,000-row opaque-store gate migrated in 13.796 seconds, unlocked in
  2.147 seconds, completed page/edit/delete in 604/1,672/473 microseconds,
  and used 52,363,680 bytes. The 1,000,000-row gate migrated in 241.176
  seconds, unlocked in 23.056 seconds, completed page/edit/delete in
  3.292/3.782/1.743 milliseconds, and used 525,595,040 bytes. Every value
  remained within the published budget.
- Desktop passed 10 unit and 26 end-to-end tests. Android core passed all 36
  tests; Play and Google-free app tests, debug assembly, lint, and the
  Google-free dependency/binary inspection passed. The iOS host suite passed
  all 34 tests in 293.791 seconds; all native slices assembled into the
  XCFramework and the unsigned arm64 Simulator app built.
- All 10 crypto and 20 protocol fuzz entry points completed a short
  exact-revision wiring run without a crash or sanitizer artifact. Each target
  had already completed a 60-second cumulative run before the Session 16
  release-only changes. The physical two-radio HIL case remained deliberately
  ignored.
- The pinned `docker/dockerfile:1.7` frontend resolved to a 22-platform OCI
  index. A local container build was unavailable because this host had no
  reachable Docker runtime or Buildx installation; the digest-pinned hosted
  image jobs remain the runnable validation path.

No production release key, recovery copy, platform signing credential, store
account, notarization path, or publication authorization was used. No
production package was signed or published. Hosted attestations, a second
controlled build at this exact revision, independently administered
reproduction, named install/upgrade/rollback systems, and physical-device
qualification remain open. Existing Swift concurrency/audio and Gradle
migration warnings also remain visible.

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
| **SV1-C04 Contact establishment** | Intentional Connect codes and bounded message requests establish contact without making a project service the identity authority. | Andri (SEC/NET/PROD); external evaluators: **Unassigned** | **Implemented Alpha; external gates open.** `kc2` binds the stable account digest to a random rotatable capability. Weekly fixed-size encrypted records carry complete bounded authority, at most two ingress bundles, three introduction routes and the admission descriptor. Lookup caps candidates/bytes, verifies before state mutation, and fails closed on authority conflicts. Standard/Private records are mailbox-only. Explicit legacy retirement and authenticated paired-contact/owned-device upgrades preserve identity and safety numbers. | [ADR-0030](adr/0030-first-contact-admission.md); [message-request matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [discovery crypto](../crates/kult-crypto/src/discovery.rs); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [DHT limits](../crates/kult-transport/src/internet.rs) | Retain revision-bound CI/fuzz evidence; run hostile multi-bootstrap/suppression and clean distinct-NAT journeys; independently adversarially review and physically qualify the combined v2 flow | 2026-08-09 |
| **SV1-C05 Pairwise text bounds and atomicity** | One stable-v1 text event carries at most 65,507 UTF-8 bytes and changes visible/delivery state only through its complete atomic transition. | Andri (SEC/PROD); external reviewer: **Unassigned** | Test evidence | [Content codec](../crates/kult-protocol/src/content.rs); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [typed commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Independent protocol review and supported-platform sudden-power-loss qualification | 2026-08-09 |
| **SV1-C06 Bounded groups** | Stable-v1 groups support at most 64 active accounts and authenticate the claimed sender separately for every recipient. | Andri (SEC/PROD); external reviewer: **Unassigned** | **Implemented Alpha; external gates open.** One shared sender-key ciphertext is wrapped by a distinct fixed-width recipient tag whose key arrives over the authenticated pairwise device session. Verification precedes chain advance. Stored authors derive from the verified sender device and accepted authority chain. Live legacy groups visibly block until fresh exchange; old history retains its weaker label. Local tests cover known-answer and malformed codecs, wrong context/recipient/device, another member's valid-wrapper reuse, replay/reorder, monotonic announce races, membership/device/session/authority rotation, restore/reset, sync filtering, shared mesh, bounded fan-out, and transaction crash points across Rust, RPC, UniFFI and host shells. | [ADR-0029](adr/0029-recipient-authenticated-groups.md); [origin crypto](../crates/kult-crypto/src/group.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [attachment matrix](../crates/kult-node/tests/attachments_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [group crash matrix](../crates/kult-node/src/atomic_tests.rs); [RPC](../crates/kultd/tests/rpc_e2e.rs); [UniFFI](../crates/kult-ffi/tests/ffi_e2e.rs) | Retain revision-bound CI and fuzz artifacts; freeze stable wire/state and conformance vectors; obtain independent implementation/security review and named physical-device qualification | 2026-08-09 |
| **SV1-C07 Bounded attachments** | Consented attachments use authenticated resumable chunks, a 512 MiB primary limit, a 256 KiB preview limit, and no bulk airtime carrier. | Andri (SEC/PROD/NET); external reviewer and field evaluator: **Unassigned** | Test evidence for bounded metadata and file-first transitions | [Atomic inventory](34-atomic-transition-inventory.md); [ADR-0015](adr/0015-encrypted-attachment-pipeline.md); [protocol constants](../crates/kult-protocol/src/attachment.rs); [attachment e2e](../crates/kult-node/tests/attachments_e2e.rs); [media store tests](../crates/kult-store/tests/media.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | ADR-0015 acceptance or successor, protected-file device matrix and independent review | 2026-08-09 |
| **SV1-C08 Backup and recovery** | A versioned encrypted backup restores eligible user state on a clean supported device while live protocol secrets reset; offline account-root recovery replaces a lost device set. | Andri (SEC/PROD); external reviewer and field evaluator: **Unassigned** | **Implemented Alpha; external gates open.** Root-free KKR8–KKR10 and a separately held `.kra` authority use independent phrases. Restore creates a higher epoch and one fresh device. KKR8 remains directly restorable and naturally supplies no later local block rows; KKR8/KKR9 receive a fresh discovery capability. Current KKR10 preserves bounded exact account/device blocks plus the Connect capability/generation while excluding provisional requests, replay tombstones and invitation capabilities. Legacy KKR1–KKR7 are decode-only in production and can only create a fresh-identity former-account archive after a reviewed authority ceremony; no production API mints a new copied-root file, and crash-phase tests inspect staged and published stores to prove neither receives the former root. Plaintext exclusion tests cover the discovery capability in the outer file and account/device/prekey/ratchet/group/link/service/delivery secrets in the payload; stale backup, root theft, old epoch, fork/conflict, quorum loss, legacy-only-artifact reset, crash publication, strict RPC/UniFFI, desktop, host-mobile and simulator builds are exercised locally. | [Atomic inventory](34-atomic-transition-inventory.md); [storage contract](07-storage.md#4-backup--portability); [backup implementation/tests](../crates/kult-store/src/backup.rs); [backup e2e](../crates/kult-node/tests/backup_e2e.rs); [public FFI reset](../crates/kult-ffi/tests/ffi_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [ADR-0026](adr/0026-revocable-device-authority.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [prior CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Retain revision-bound ADR-0026/ADR-0030/ADR-0031 CI artifacts, freeze stable wire/state format, run named clean physical-device and sudden-power-loss matrices, obtain independent interoperability and security review | 2026-08-09 |
| **SV1-C09 Blocking** | Blocking is an exact local identity rule that removes local relationship capabilities and state without claiming remote erasure or global identity revocation. | Andri (SEC/PROD); external abuse/usability evaluator: **Unassigned** | **Implemented Alpha at the first-contact boundary.** Exact provisional account/device blocks are sealed, bounded, persisted through KKR10, enforced before request promotion, and exposed through every shell. Block retires provisional state and local queues available at that boundary without claiming remote erasure. | [ADR-0030](adr/0030-first-contact-admission.md#4-accept-reject-block-and-invite-are-explicit-state-transitions); [provisional store](../crates/kult-store/src/admission.rs); [message-request matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [profile boundary](30-stable-v1-product-profile.md#7-blocking-and-deletion) | Extend capability cleanup across established relationships, group state, rendezvous and wake as those later protocols land; independently adversarially/usability test and physically qualify supported clients | 2026-08-09 |
| **SV1-C10 Honest delivery** | Queued means durable local custody, sent means bounded next-hop custody, and delivered requires an authenticated end-to-end receipt; none means read. | Andri (SEC/NET/PROD); external evaluator: **Unassigned** | **Implemented Alpha; external gates open.** Direct acceptance waits for exact durable staging/consumption. Mailbox acceptance waits for durable relay commit; collection leases bounded rows and deletes exact ids only after endpoint `PendingStage`. Duplicate delivery is absorbed and the sender retains ciphertext until the authenticated end-to-end receipt or terminal retry result. | [Architecture lifecycle](03-architecture.md#3-message-lifecycle); [transport semantics](05-transports.md); [direct/mailbox settlement tests](../crates/kult-node/src/atomic_tests.rs); [mailbox store/failpoints](../crates/kult-transport/src/mailbox_v2.rs); [mailbox e2e](../crates/kult-node/tests/mailbox_e2e.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [ADR-0032](adr/0032-leased-mailbox-delivery.md) | Retained revision-bound crash evidence, qualified operator/backup/upgrade/cost record, real-network and physical sudden-power-loss qualification, independent review | 2026-08-09 |
| **SV1-C11 Supported platforms** | The stable release supports only the named device, OS, architecture, lifecycle, install, upgrade, and accessibility cells published as passed. | Andri (PROD/REL); independent field/accessibility evaluator: **Unassigned** | Implemented shells with automated build/simulator evidence | [Platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems); [release gate](24-local-release-gate.md) | P0-09 named physical matrix and exact macOS/Linux support cells | 2026-08-09 |
| **SV1-C12 Replaceable services** | Standard defaults are disclosed and replaceable; no project service is the user identity authority or receives message plaintext or user identity private keys. | Andri (NET/SEC/FND); external operator reviewer: **Unassigned** | **Implemented Alpha locally; external gates open.** Standard/Private/Sovereign policy is common across core, daemon, UniFFI, desktop, Android, and iOS. A signed, versioned, parent-bound provider directory preserves manual routes, retains a bounded last-valid chain, exposes conflict/stale/unavailable state, supports authenticated key rotation and explicit opt-out, and has no mandatory entry. Direct pinned TLS and loopback-Tor rendezvous follow the selected mode. A dedicated two-role binary wraps a bounded Komms-only Kademlia cache and persistence-free fixed-shape rendezvous, terminates Noise/TLS in process, accepts no endpoint/mailbox/wake/directory authority, and ships with a hardened profile and runbook. A separate fixed-shape native-wake binary holds only dedicated TLS, capability-encryption, APNs/FCM credentials and bounded replay/revocation state; sealed client capabilities, durable identity-free revoke retries, pinned direct/Tor access, bounded generic collection, direct APNs, Play-only FCM, and an inspected Google-free artifact preserve ordinary delivery semantics. No production directory, trusted root, qualified default, native-provider credential, or network service is deployed. | [Operating modes](36-operating-modes-and-provider-directory.md); [ADR-0017](adr/0017-optional-hybrid-modes.md); [local journey gate](../scripts/test-operating-mode-journeys.sh); [ADR-0018](adr/0018-pairwise-rendezvous.md); [service component](../crates/kult-rendezvous/src/lib.rs); [network service](../crates/kult-reference-service/src/lib.rs); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [deployment profile](../deploy/reference-service/compose.yaml); [operator runbook](35-reference-service-operations.md); [operator record](reference-service-operator.md); [self-hosting boundary](26-self-hosting.md); [ADR-0019](adr/0019-native-wake-gateway.md); [wake deployment profile](../deploy/wake-gateway/compose.yaml); [wake runbook](37-native-wake-operations.md); [mobile wake matrix](38-native-wake-mobile-qualification.md); [wake operator record](wake-gateway-operator.md) | Retain revision-bound multi-architecture digest/SBOM/provenance and reproducibility evidence; deploy and qualify exact hardened reference and wake hosts; run named APNs/FCM physical lifecycle rows and clean distinct-NAT/default-blackhole/replacement journeys against real operators; qualify Tor or separated OHTTP Private ingress; obtain independent operator review and real plural operation before any plural claim | 2026-08-09 |
| **SV1-C13 Resilient retry and fallback** | Komms retains queued work, retries within declared bounds, and can use more than one supported route; it does not guarantee availability or delivery time. | Andri (NET/PROD); external field evaluator: **Unassigned** | **Automated local evidence.** Manual, authenticated discovery, LAN, and rendezvous hints remain source-separated. Rendezvous maintenance is trigger-bound, jittered, coalesced, single-flight, backoff/circuit limited, and blackhole failure leaves ordinary queued work and delivery semantics unchanged. | [Transport design](05-transports.md); [ADR-0018](adr/0018-pairwise-rendezvous.md); [rendezvous matrix](../crates/kult-node/tests/rendezvous_e2e.rs); [node delivery tests](../crates/kult-node/tests/node_e2e.rs); [mesh policy tests](../crates/kult-node/tests/mesh_policies.rs); [sneakernet tests](../crates/kult-transport/tests/sneakernet.rs) | Revision-bound retained evidence; real NAT, background, handoff, deployed operator failure/replacement, and two-radio field matrix | 2026-08-09 |
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
