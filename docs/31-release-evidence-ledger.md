# Release evidence ledger

**Ledger date:** 2026-08-03

**Release scope:** Komms 0.4 Beta candidate; stable-v1 assurance target

**Current source baseline:** [`main@5830d7c`](https://github.com/AndriGitDev/Komms/tree/5830d7c24adfffe491b229688adaf9bb592a3504);
the stabilization program was merged by
[PR #84](https://github.com/AndriGitDev/Komms/pull/84), followed by reviewed
dependency updates in PRs #85–#90. A release-preparation branch, local result,
or retained validation artifact is not a published Beta evidence bundle.

**Baseline automated run:** [`a02b064`, CI run 197](https://github.com/AndriGitDev/Komms/actions/runs/30199264838);
this successful PR-head tree is the tree merged by PR #77

**Release-control run:** [`25daa69`, CI run 199](https://github.com/AndriGitDev/Komms/actions/runs/30202463092);
all nine jobs passed on draft PR #78

**Accountable release owner:** Andri (`@AndriGitDev`)

**Stable release decision:** not authorized; all P0 gates remain open

**0.4 Beta publication decision:** not authorized; it requires the exact
completed signing, qualification, evidence, visual-review, and maintainer
publication boundaries

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
| **P0-02 Name-risk assessment and recorded decision** | Andri (FND and project risk owner); qualified trademark counsel: **Unassigned** | A dated founder decision records the observed overlap, migration cost, cadence, and escalation triggers. A project policy now separates AGPL scope, descriptive compatibility use, official naming, package identifiers, artwork, and third-party notices. | **Open.** This is not legal clearance. No qualified similarity/class/jurisdiction opinion, trademark review, or founder provenance attestation for the logo/icon/screenshot set exists. | [Name-risk decision](32-name-risk-decision.md); [brand system](28-brand-system.md); [license/trademark/assets policy](47-license-trademark-assets.md); [machine inventory](../operations/v1/assets.json) | 2026-10-26, or trigger event |
| **P0-03 Stabilized core product profile** | Andri (FND; interim PROD/SEC) | Designed: product boundary, bounds, supported-system rule, services, and exclusions frozen. Twenty-five typed plan kinds cover legacy migration plus root-free profile bootstrap, pairwise, group, attachment, scheduled activation, bounded maintenance, `KDA2` device control/link/sync, contact projection, ADR-0030 admission stage/accept/discard/sweep, complete-envelope `PendingStage`, and restart presentation. ADR-0017, ADR-0018, ADR-0019, ADR-0026, ADR-0029, ADR-0030, ADR-0031, ADR-0032, and ADR-0034 are accepted and implemented for Beta: canonical Standard/Private/Sovereign policy, a signed replaceable provider directory with bounded last-valid/fork behavior, pinned direct-TLS and loopback-Tor rendezvous, transcript-bound rotating pairwise rendezvous with sealed non-backup state and visible forks, fixed-shape capability-gated native wake with durable identity-free revocation retries, bounded generic collection, direct APNs, Play-only FCM, and an inspected Google-free artifact, strict-majority device authority, recovery epochs, root-free KKR8–KKR10, recipient-authenticated encrypt-once groups, bounded provisional requests and explicit consent, capability-scoped fixed-size encrypted discovery, durable mailbox deposits and exact lease acknowledgement after endpoint commit, visible legacy upgrades, deterministic crash tests, strict RPC/UniFFI, host shells, simulator builds, and a locally validated two-role reference-service artifact. Retained CI run 217 remains evidence for the earlier expanded matrix, Windows storage, MSRV, `no_std`, dependency policy and 22 earlier full-budget fuzz targets; the current source still needs revision-bound CI retention. | **Open.** ADR-0028 remains proposed. The mode, rendezvous, and wake paths lack a reference deployment, qualified Tor/non-colluding-OHTTP ingress, retained multi-architecture image digest/SBOM/provenance/reproducibility evidence, hostile real-network evidence, independent interoperability/security review, and named physical-device qualification. No production directory, trusted root, qualified default operator, or wake gateway ships. Named physical APNs/FCM background/force-quit/Doze evidence remains open. Discovery has the same external/physical evidence gaps. The quarantined pre-C2 alias bridge remains outside stable-v1 acceptance; mailbox operator/upgrade/backup/cost qualification, field qualification, and sudden-power-loss evidence are also open. | [Stable-v1 profile](30-stable-v1-product-profile.md); [operating modes](36-operating-modes-and-provider-directory.md); [ADR-0017](adr/0017-optional-hybrid-modes.md); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0018](adr/0018-pairwise-rendezvous.md); [rendezvous matrix](../crates/kult-node/tests/rendezvous_e2e.rs); [ADR-0019](adr/0019-native-wake-gateway.md); [wake core](../crates/kult-node/src/lib.rs); [wake gateway](../crates/kult-wake/src/lib.rs); [wake runbook](37-native-wake-operations.md); [mobile wake matrix](38-native-wake-mobile-qualification.md); [reference service](../crates/kult-reference-service/src/lib.rs); [reference runbook](35-reference-service-operations.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [ADR-0026](adr/0026-revocable-device-authority.md); [ADR-0029](adr/0029-recipient-authenticated-groups.md); [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [ADR-0032](adr/0032-leased-mailbox-delivery.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [mailbox store](../crates/kult-transport/src/mailbox_v2.rs); [admission matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [root-free backup and legacy reset tests](../crates/kult-store/src/backup.rs); [baseline revision](https://github.com/AndriGitDev/Komms/commit/f17a60636a074b889105d7e123caf0fa475bebfc); [expanded revision](https://github.com/AndriGitDev/Komms/commit/6c73f71b18f120e5a3072fe77dfcd122cbf287dd); [CI run 217](https://github.com/AndriGitDev/Komms/actions/runs/30303253034); [P0 ADR index](adr/README.md) | 2026-08-09 |
| **P0-04 Clean-install and real-network golden path** | Andri (interim NET/PROD); independent field evaluator: **Unassigned** | **Implemented Beta components; local journey and partial physical development evidence only.** One canonical mode contract, signed replaceable provider directory, bounded last-valid/fork behavior, manual opt-out, familiar shell status, and a repeatable host journey cover synthetic Standard defaults, configured-default blackhole, manual alternate bootstrap, authenticated replacement, pure-core/Sovereign operation, Connect-code contact, provisional consent, offline mailbox delivery, route repair, recovery, and restart invariants. Revision `69e22e48b24983fdc3a8dd3acece4e7704fcea2d` additionally retains corrected Mac first run, animated-QR pairing to a physical S23 Ultra, message-request acceptance, and bidirectional Delivered state on one local Wi-Fi network. | **Open.** No qualified default bootstrap/mailbox or production directory exists. The physical result used debug/ad-hoc development binaries, omitted exact scenario timings, and is not two clean production packages behind distinct ordinary NATs, a deployed default blackhole, an independently operated replacement, or mobile handoff/background evidence. | [Operating modes](36-operating-modes-and-provider-directory.md); [local journey gate](../scripts/test-operating-mode-journeys.sh); [internet tests](../crates/kult-node/tests/internet_e2e.rs); [physical development result](../field-qualification/v1/evidence/69e22e4/s23-ultra-macos-messaging.txt); [Beta guide](53-beta-testing.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md) | 2026-08-09 |
| **P0-05 Unsolicited-contact abuse admission** | Andri (interim SEC/NET/PROD); independent adversarial/usability evaluator: **Unassigned** | **Implemented Beta; external gates open.** Signed expiring descriptors bind the exact bundle, puzzle/invitation policy, size and clock window. Fixed admission wrappers verify target-specific proofs before ML-KEM where possible. Global concurrency, puzzle/KEM, notification, per-tick, carrier, row and byte budgets constrain work. Valid strangers enter a sealed 32-row/512-KiB provisional domain through one atomic prekey/session/identity/safety-number/preview transition. Accept, Delete, Block and Sweep are typed atomic plans; group invites use explicit consent; KKR10 preserves bounded local blocks but excludes provisional, replay, invitation, prekey and live delivery state. Direct responses wait for exact durable staging/consumption and uniformly refuse invalid, duplicate or over-budget introductions. Capability-scoped Connect records carry the same descriptor without OPKs or direct Standard/Private routes. Rust, RPC, UniFFI, desktop, Android host and iOS simulator paths have local flood/Sybil/budget/prekey/replay/duplicate/disk-full/expiry/delayed-carrier evidence. | **Open.** Independent adversarial and usability review, named physical-device CPU/battery/background/accessibility evidence, mailbox-v2 operator admission, hostile-network discovery evidence, and retained revision-bound CI/fuzz evidence are missing. Optional reputation lists and evidence export are not implemented and are outside the current claim. | [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [admission crypto](../crates/kult-crypto/src/admission.rs); [admission codec](../crates/kult-protocol/src/admission.rs); [atomic provisional store](../crates/kult-store/src/admission.rs); [node admission matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [atomic crash/budget matrix](../crates/kult-node/src/atomic_tests.rs); [direct transport semantics](05-transports.md); [RPC evidence](../crates/kultd/tests/rpc_e2e.rs); [UniFFI evidence](../crates/kult-ffi/tests/ffi_e2e.rs) | 2026-08-09 |
| **P0-06 Independent crypto and protocol assurance** | Andri (interim SEC); independent cryptography reviewer: **Unassigned**; independent interoperability implementer: **Unassigned** | **Portable contract and review package implemented; independent evidence open.** The versioned stand-alone specification covers canonical bounds and encodings, PQXDH, Double Ratchet, envelopes/content, recipient-authenticated groups, device authority/recovery, first contact, Connect discovery, mailbox v2, rendezvous, wake, atomicity, downgrade behavior, and malformed input. Fifty-one language-neutral exact cases, binary fixtures, state traces, a synthetic secret-free packet capture, a bounded adapter contract, manifest verification, and Komms fixture-consumption tests share one public source of truth. A four-work-package external scope now maps assets, invariants, architecture, attack surfaces, source, known limits, build/test instructions, severity/disposition/retest, disclosure terms, and a reproducible full-tree archive. An unranked four-candidate shortlist is research only. | **Open; waiting on external reviewer.** All current vectors, adapter results, review scope, and package validation originate from the Komms implementation process. No candidate has been contacted or assigned, no genuine external findings were supplied, no separately produced implementation or fixture producer has run the kit, and no qualified external reviewer has accepted scope or published findings, dispositions, retest results, or a residual-risk statement. This row therefore records no independent interoperability or security claim. | [Review readiness](42-independent-security-review.md); [review package](../security-review/stable-v1/README.md); [review scope](../security-review/stable-v1/SCOPE.md); [RFP](../security-review/stable-v1/RFP.md); [finding format](../security-review/stable-v1/FINDINGS.md); [Protocol conformance](41-protocol-conformance.md); [ADR-0035](adr/0035-stable-v1-protocol-and-conformance-kit.md); [stand-alone specification](../conformance/v1/SPECIFICATION.md); [case manifest](../conformance/v1/manifest.json); [adapter](../crates/kult-conformance/src/lib.rs); [Crypto KATs](../crates/kult-crypto/tests/kat.rs); [properties](../crates/kult-crypto/tests/properties.rs); [session tests](../crates/kult-crypto/tests/session.rs) | 2026-08-09 |
| **P0-07 Signed and recoverable distribution** | Andri (interim REL/SEC); independent release evaluator: **Unassigned** | **Implemented validation controls; credential and external gates open.** The source-controlled policy separates the offline release manifest from Play upload, Google-free Android, iOS, macOS, and Windows roles, with explicit rotation and compromise response. Android app/core graphs are locked and artifact checksums are verified. Bounded validators enforce exact artifact-class signing coverage, canonical-matrix qualification, aggregate CycloneDX SBOM and dependency integrity tied to the checked-out locks/toolchain, exact/normalized/explained reproduction, independently administered report evidence, revision-authorized residual risk, deterministic safe archives, and complete evidence inventories. Workflow actions, the Swift test image, Rust bootstrap, XcodeGen, cargo tools, the BuildKit frontend, and container bases are immutable or checksum pinned. Builds default read-only; tag pushes retain only 90-day validation evidence and hosted attestations. Protected draft creation starts empty. Publication requires exact confirmation, an unchanged closed visual-approval record, an immutable completed asset set, an offline signature, bounded preflight, exact package/evidence digest agreement, and final metadata rechecks. | **Open.** No production role or offline release-manifest key/recovery copy is enrolled. The protected production-signing boundary therefore refuses to proceed. No production-signed Android, Apple, or Windows artifact, completed manifest signature, store account path, named-system install/upgrade/failure/rollback/compatibility result, externally administered reproduction, or independent release evaluation exists. The hosted second Linux build is measurement, not independence; the iOS artifact is Simulator-only. No release has exercised the new workflow, so revision-bound hosted artifacts and attestations are also pending. | [Release security and recovery](39-release-security-and-recovery.md); [release evidence bundles](40-release-evidence-bundles.md); [release policy](../release/policy-v1.json); [release workflow](../.github/workflows/release.yml); [release runbook](25-release-runbook.md); [local release gate](24-local-release-gate.md); [historical 0.3 Alpha artifacts](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0) | 2026-08-09 |
| **P0-08 Durable mailbox and operator qualification** | Andri (interim NET/SEC); independent operator evaluator: **Unassigned** | **Implemented Beta; operator gate open.** `/komms/mailbox/2` commits opaque-indexed row-bound deposits before acceptance, persists registrations/deposits/leases/rate buckets/expiry across restart, retransmits bounded idempotent leases, and deletes only exact rows acknowledged after typed endpoint staging. Unregistered best-effort bridge transit explicitly refuses custody. A dedicated `kult-mailbox` artifact exposes only the v2 role, separates row protection, transport identity, and durable state, and reports aggregate content-free health. Local tests cover response/ack loss, duplicate/partial/wrong-client acknowledgement, crash and disk-full failpoints, expiry/overload, key mismatch/row transplant, stable service identity, aggregate-only metrics/logging, bounded lifecycle work, and multi-operator deduplication. The runbook records defaults, capacity/cost inputs, backup/restore, upgrade/rollback, v1 risk, and incident response. | **Open.** No revision-bound public deployment, observed resource/cost record, maintained backup/upgrade exercise, abuse/incident exercise, independent operator evaluation, real-network multi-operator matrix, or supported-platform sudden-power-loss evidence exists. Historical 0.3.0 artifacts predate v2 and do not count. | [ADR-0032](adr/0032-leased-mailbox-delivery.md); [mailbox store/failpoints](../crates/kult-transport/src/mailbox_v2.rs); [dedicated service](../crates/kult-mailbox); [transport mailbox tests](../crates/kult-transport/tests/mailbox.rs); [node mailbox custody tests](../crates/kult-node/src/atomic_tests.rs); [node mailbox e2e](../crates/kult-node/tests/mailbox_e2e.rs); [operator runbook](50-mailbox-service-operations.md) | 2026-08-09 |
| **P0-09 Field qualification across supported claims** | Andri (interim PROD/NET/REL); independent accessibility/field evaluator: **Unassigned** | **Partial exact-revision simulator and physical development evidence retained; field rows open.** A canonical matrix names Apple-silicon/Intel macOS, Windows, Linux, Android, iOS, distinct-NAT/CGNAT/IPv6, and stock-radio target cells. Thirty scenarios cover clean install, consent, offline delivery, recovery/device loss, attachments/calls, screen protection, accessibility, mobile lifecycle/handoff, NAT/relay/operator failure, pure-core operation, and Meshtastic RF/multi-hop/bridge behavior. The validator binds every canonical run to a full revision and artifact digest, requires exact per-step timings and redacted evidence, rejects missing rows or changed evidence, and prevents simulator results from becoming physical passes. Revision `440a410a5d5a9373935cef8eb3728efe5ed91e64` retains the simulator rows. Revision `996a3e4e961ae40589f303149855451430597874` retains a physical S23 Ultra clean-install pass and the superseded v0.4.1 Mac failure. Revision `69e22e48b24983fdc3a8dd3acece4e7704fcea2d` retains a non-canonical physical development note for corrected Mac first run, S23 pairing, request acceptance, and bidirectional Delivered state. The radio carrier emits content-free frame, byte, airtime, refusal, decode, and malformed-frame aggregates; ignored real-radio cases cover isolated E2EE and the physical-RF plus local-QUIC bridge path. | **Open.** No target is qualified. The corrected physical result used one local Wi-Fi network and debug/ad-hoc binaries, and lacks the exact timings required for a canonical row. No current complete physical Android, iOS, Intel macOS, Windows, Linux, distinct-NAT, CGNAT/IPv6, accessibility, cellular handoff, real-audio, multi-hop radio, or separately reachable Internet-bridge run exists. Simulator results cannot become physical passes. Independent accessibility evaluation, physical sudden-power-loss evidence, named operator/network conditions, production-artifact install/upgrade/rollback, and a final revision-wide rerun remain outstanding. | [Field matrix and runbook](43-field-qualification.md); [canonical matrix](../field-qualification/v1/matrix.json); [revision-bound simulator record](../field-qualification/v1/evidence/440a410/summary.json); [S23 and Mac development result](../field-qualification/v1/evidence/69e22e4/s23-ultra-macos-messaging.txt); [record validator](../scripts/field-qualification.py); [HIL bench](10-hil-bench.md); [native-wake field rows](38-native-wake-mobile-qualification.md); [local release gate](24-local-release-gate.md); [candidate platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems) | 2026-08-09 |
| **P0-10 Accountable founder authority, review, and incidents** | Andri (FND; interim COM/SEC); independent reviewers and backup steward: **Unassigned** | Public governance, ownership, security intake, recusal, release authority, lawful-request minimization, provider data flows, credential-specific containment, advisory fields, and four deterministic policy dry-runs are implemented. | **Open.** No accepted backup steward, independent sensitive-surface reviewer, qualified legal counsel, live human tabletop, real operator notification drill, or continuity handoff exists. The repository dry-runs are not live or independent evidence. | [Governance](../GOVERNANCE.md); [maintainers](../MAINTAINERS.md); [security and incidents](../SECURITY.md); [privacy/legal/incident readiness](49-privacy-legal-incident-readiness.md); [dry-run cases](../operations/v1/tabletops.json); [CODEOWNERS](../.github/CODEOWNERS); [ADR-0033](adr/0033-nonprofit-founder-stewardship.md) | 2026-08-09 |

### Session 22 stable-beta readiness audit

The repository now has a source-controlled, fail-closed shape for the final
consent pilot and release decision. This is implementation evidence, not gate
closure:

- `release/stable-beta-plan-v1.json` fixes the participant bounds, privacy
  contract, aggregate metrics and thresholds, eleven final-candidate reruns,
  exact P0 evidence kinds, support window, and rollback triggers.
- `scripts/stable-beta-readiness.py` prepares an honestly open record and
  recomputes every summary. It rejects omitted gates/rows, mislabeled
  independent or physical evidence, failed metric thresholds described as
  passing, participant-level extra fields, unresolved release blockers, or a
  candidate decision that claims merge, publication, or stable authority.
- Stable release promotion now requires `stable-beta.json` inside the signed
  release evidence archive and validates it with `--require-ready`.
- The participant-facing consent and runbook prohibit message content, contact
  graphs, stable user identifiers, per-user timelines, and retained raw event
  streams. Consent stays restricted and separate from the public aggregate.
- The candidate release-note template states the ordinary product promise and
  exact metadata, availability, deletion, support, and assurance limits without
  claiming those brackets have been earned.

No pilot, signed candidate, external review, independent conformance run,
operator qualification, physical field matrix, radio run, support commitment,
rollback approval, or founder go/no-go has occurred. All P0 gates therefore
remain open. The compact residual-risk template now records an owner, next
review date, and required action for distribution, independent, physical,
operator, pilot, legal/continuity, and final-decision gaps. See
[Stable-beta pilot and release decision](51-stable-beta-pilot-and-release-decision.md)
and [`release/residual-risks-v1.json`](../release/residual-risks-v1.json).

### Sessions 20–22 cumulative local development validation

On 2026-07-31, the cumulative working tree based on
`f55afcaad4c4aa94953b92708732942eb61363d9` was checked on arm64 macOS.
The source had not yet been assigned its final commits and the results were not
retained by hosted CI, so this is working-tree development validation only.

- Both Rust workspaces passed formatting and all-target/all-feature Clippy with
  warnings denied. The crypto/protocol no-default-feature build passed.
- The shared localization contract passed with 1,364 stable identifiers and
  complete English/Icelandic catalogs. Source coverage found 662 static
  strings, 1,132 registered source keys, and no justified technical literal.
  Fifteen localization regressions plus the cross-shell accessibility,
  message-request consent, focus, scalable-text, touch-target, announcement,
  reduced-motion, and AA-contrast checks passed.
- Seven contributor-profile regressions and twelve stewardship regressions
  passed. The operator role, external slot, provider-flow, funding, asset, and
  incident dry-run inventories were internally consistent.
- The dedicated fixed-mapping OHTTP relay passed eleven unit tests, one
  credential/configuration test, and two deployment-profile tests. These cover
  exact request/response shapes, reconstructed minimal upstream headers,
  smuggling rejection, bounded response parsing, one-exchange behavior,
  rotating source/global budgets, uniform error classes, separate TLS
  material, aggregate-only health, and the ephemeral hardened profile.
  Its Compose configuration, shell syntax, workflow syntax, formatting, and
  warnings-denied all-target Clippy checks passed.
- The release version/documentation checks, deterministic review-package
  check, Android license inventory tests, release evidence, qualification,
  field-record, signing, artifact-staging, release-policy, and stable-beta
  readiness suites passed. The stable-beta suite contains 13 regressions; the
  release-evidence suite contains 15.
- The stand-alone conformance adapter rebuilt successfully. All 51 committed
  answers matched, the binary fixtures/secret-free packet trace/manifest
  matched, and the public runner passed all 51 adapter cases.
- Earlier in the same working-tree cycle, the crypto, protocol, storage, node,
  transport, daemon, UniFFI, desktop, rendezvous, wake, reference-service, and
  dedicated-mailbox non-listener suites passed. The 100,000- and
  1,000,000-row opaque-store scale cases remained within their frozen budgets.

The current restricted host session did not authorize localhost listener tests,
the local container runtime socket, or writes to the shared Cargo, Gradle,
Swift, and Xcode caches. The complete
workspace/desktop listener suites, both dependency advisory checks, Android
host/application/lint builds, Swift host build, unsigned iOS Simulator build,
and all service-container build/restart/socket smokes therefore require a
post-commit rerun in an unrestricted local environment. They are not recorded
as passes or product failures here. The review-package digest also remains tied
to the committed base until the final source commits exist.

None of these checks is a consent pilot, independently produced result,
physical-device/accessibility/radio run, real operator deployment, production
signature, store submission, or release authorization. Every corresponding P0
and P1 evidence row remains open.

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

### Session 17 local development validation

On 2026-07-31, commit
`071e71334f1a9dea6f8ea0f71b37eb33f3bcf862` was exercised on arm64 macOS
26.5.2 with Rust 1.97.0 and Python 3.12.13.

- `CARGO_INCREMENTAL=0 cargo test --offline --workspace --all-features`
  completed successfully against the exact commit. Every executed workspace
  unit, integration, end-to-end, and documentation test passed. The large
  million-row qualification and physical two-radio HIL cases remained
  deliberately ignored under their existing explicit gates.
- Formatting and warnings-denied lint passed for the conformance, transport,
  and node targets with all targets and features. Documentation, kit-manifest,
  generated-artifact, and fixture-drift checks passed.
- The retained
  [Komms self-run](../conformance/v1/evidence/komms-self-run-071e713.json)
  passed all 51 stable-v1 cases. Its SHA-256 digest is
  `246252edacdc307eae712866b3757e5dd1129c93bed89e8b974125c43a5173ad`;
  it binds kit-manifest digest
  `2e8cd849b3cc3e831aa4a603baed01320569712e5cd6f2bff8630e584383bca2`
  and adapter digest
  `df5f418ab658fb0b4c40165ed71f0d64dd3aa775b8845cb0efba5f077b98a30c`.
- The report explicitly records `independent_execution_claimed: false`. All
  current fixtures and the adapter share the Komms implementation process, so
  this is revision-bound local compatibility evidence only.

No separately produced implementation or fixture producer ran this kit. No
qualified external security reviewer supplied findings, dispositions, or
retest evidence. Independent interoperability and P0-06 security assurance
therefore remain open.

### Session 18 review-readiness validation

On 2026-07-31, commit
`5a08e8e2e5cea4a2cad1ec511e97ab16cac53c85` was prepared and exercised on
arm64 macOS 26.5.2 with Python 3.12.13.

- The external-review scope maps the complete minimum P0-06 surface into four
  work packages: protocol/cryptographic composition; device authority,
  recovery, storage and atomicity; admission/discovery/custody/services; and
  malformed-input/RPC/FFI/shell integration.
- The prepared RFP fixes independence, conflict, named-team, data-handling,
  public finding/disposition, coordinated-disclosure, residual-risk and retest
  requirements. The finding format preserves original severity and both
  reviewer and maintainer positions.
- A four-candidate shortlist cites first-party service descriptions and public
  comparable work. No candidate was contacted, assigned, or authorized to
  spend project funds.
- Six package-builder regression tests passed. Documentation links and public
  evidence terminology passed. The builder rejected special tree entries and
  unsafe/missing inputs in its negative tests.
- Two separate invocations of the package builder produced byte-identical
  output for the exact commit. The 678-file, 15,509,820-byte tree became a
  6,712,258-byte archive with SHA-256
  `36f1cab72fcaa76efa29134dbe705775afbccd76cf30a7db2d3ffa2ae4ff831e`.
  A separate verification invocation accepted the archive/report pair.
- The retained
  [package report](../security-review/stable-v1/evidence/komms-security-review-5a08e8e2e5ce.json)
  has SHA-256
  `b15c7420b9a07abae7804eb49479af391a152b02d734ba0bba4aa62c6f5a254f`
  and explicitly records `reviewer: "unassigned"`,
  `findings_received: false`, and
  `independent_security_review_claimed: false`.

This is review-readiness and reproducible-handoff evidence only. P0-06 remains
open and waiting on a named conflict-checked external reviewer, a complete
public finding/disposition/retest/residual-risk record, and separately
produced interoperability evidence.

On 2026-08-03, the cumulative stabilization source scope was refreshed at
commit `78b504df6423f5ca204199b4dbfdecc5c694b031`, tree
`6f2555cbcee87966f210af76c7315a1d9be21936`. The required-prefix contract now
names the dedicated mailbox, reference, rendezvous, wake, and OHTTP relay
components. Two builds produced the same 9,654,286-byte archive from 787 files
and 20,310,981 source bytes. The archive SHA-256 is
`63984ad25f428b44334818f25ecef3e5951215de08fa9da1a30720fe06420ef9`;
the separately verified
[package report](../security-review/stable-v1/evidence/komms-security-review-78b504df6423.json)
has SHA-256
`b82b80ace160d9b83f8d3e84a7ea51bc20e28c55e56d72f0c2aa315447fa0f94`.
It still records an unassigned reviewer, no findings, and no independent-review
claim, so the gate remains open.

### Session 19 field-program validation

On 2026-07-31, commit
`440a410a5d5a9373935cef8eb3728efe5ed91e64` was exercised on the available
arm64 Android API-35 emulator and iOS 26.5 Simulators.

- Google-free and Play debug APKs were rebuilt from the exact revision. Their
  debug unit suites passed, and the Google-free artifact passed the dependency
  boundary check with no Firebase, FCM, or Google Play Services code or
  resources.
- A clean Google-free Android install completed mandatory encrypted-store and
  offline-authority onboarding, notification denial, ready-state presentation,
  explicit application lock, OS lock, task-switcher protection, screenshot
  protection, and a short recording check. Clean install and screen security
  are retained as `simulator-pass`.
- The native framework and unsigned iOS Simulator application were rebuilt
  from the exact revision. Clean installs on iPhone 17 Pro and iPhone 17e
  completed mandatory onboarding and reached the ready state in dark and light
  appearances without clipping. Both clean-install rows are retained as
  `simulator-pass`.
- The iPhone 17e app-switcher shield, device-lock boundary, explicit
  application lock, and documented still-screenshot limitation were observed.
  A short Simulator recording did not surface the UIKit live-capture
  notification, so screen security remains `observed`, not
  `simulator-pass`.
- Every run record passed matrix, artifact, timing, evidence-digest, redaction,
  and simulator-label validation. The canonical
  [revision summary](../field-qualification/v1/evidence/440a410/summary.json)
  records no qualified target.
- Throwaway application profiles and offline-authority packages were removed
  after the redacted records were retained. No recovery words or live profile
  data are present in the evidence.

These records are development evidence only. No physical Android or iOS
device, real notification provider, accessibility service, cellular handoff,
independent evaluator, real NAT pair, or stock-radio bench was exercised.
Those rows remain open.

### P1 sustainability ledger

| Gate | Current control evidence | Status and open gaps | Artifacts |
|---|---|---|---|
| **P1-01 Fast contributor path** | Seven bounded non-publishing profiles cover protocol, storage/node, desktop, Android core, iOS core, documentation, and localization work without release credentials. Profile validation rejects remote-login, publication, registry mutation, signing-variable inheritance, and history-changing commands. Issue forms, labels, review ownership, deterministic-fixture guidance, troubleshooting, and a pull-request handoff are source controlled. | **Implemented locally; adoption evidence open.** No sustained newcomer completion, issue-to-review timing, contributor usability study, or maintainer-capacity record exists. Publication remains maintainer-only. | [Contributor path](44-contributor-path.md); [profile contract](../contributor/profiles.json); [profile runner](../scripts/contributor-check.py); [issue form](../.github/ISSUE_TEMPLATE/good-first-change.yml); [review routing](../.github/CODEOWNERS) |
| **P1-02 Localization and accessibility system** | A shared English/Icelandic catalog generates desktop, Android, and iOS resources. Stable IDs, complete locale parity, placeholder/plural shape, NFC, bidi safety, fallback, malformed-resource, source-coverage, translation-expansion, and generated-output checks are mandatory. All shells expose System/English/Icelandic before unlock and in settings. Static accessibility controls cover onboarding, consent, conversation, groups, attachments, calls, recovery, modes, focus, keyboard navigation, scalable text, announcements, 44-point targets, reduced motion, and light/dark AA contrast. | **Implemented locally; external and physical gates open.** Platform builds and simulator journeys must be rerun on the final revision. No fluent Icelandic review, named physical-device largest-text/VoiceOver/TalkBack/switch-control run, disabled-user usability study, or independent accessibility assessment exists. This row makes no external-review or field-qualification claim. | [Localization and accessibility](45-localization-accessibility.md); [catalog contract](../locales/README.md); [catalog validator](../scripts/localization.py); [source guard](../scripts/check-localization-sources.py); [accessibility guard](../scripts/check-shell-accessibility.py); [field matrix](43-field-qualification.md) |

## 2. Stable public claim register

These are the complete stable public claims authorized by the frozen profile.
The quoted wording is the strongest stable wording permitted after its evidence
closes. Until then, public copy must use the current evidence level and disclose
the listed gap. A new stable claim requires a new identifier here.

| Claim | Stable wording | Owner | Current evidence level | Revision / artifacts | Open gaps | Next review |
|---|---|---|---|---|---|---|
| **SV1-C01 Distribution** | Supported Komms clients install, update, and recover through authenticated release paths. | Andri (REL/SEC); external release evaluator: **Unassigned** | Implemented Beta packaging and evidence controls only | [Beta guide](53-beta-testing.md); [historical 0.3 release](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0); [release runbook](25-release-runbook.md) | P0-07 signing, updates, rollback, reproducibility, and key recovery | 2026-08-09 |
| **SV1-C02 Local identity** | Komms identity can be created without a required phone number, email address, real name, or project account. | Andri (SEC/PROD); external reviewer: **Unassigned** | Automated evidence | [Identity design](06-identity-trust.md); [node e2e](../crates/kult-node/tests/node_e2e.rs); [FFI e2e](../crates/kult-ffi/tests/ffi_e2e.rs) | Independent protocol review and supported-platform clean-install evidence | 2026-08-09 |
| **SV1-C03 Pairwise confidentiality and authenticity** | Accepted contacts exchange authenticated end-to-end encrypted pairwise text; intermediaries receive sealed envelopes rather than message plaintext. | Andri (SEC); external cryptography reviewer: **Unassigned** | Test evidence | [`main@4fda544`](https://github.com/AndriGitDev/Komms/tree/4fda544739c0665b6a324256d858c16c1d73d992); [KATs](../crates/kult-crypto/tests/kat.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [pairwise crash matrix](../crates/kult-node/src/atomic_tests.rs) | P0-06 external vectors, review, and interoperability evidence | 2026-08-09 |
| **SV1-C04 Contact establishment** | Intentional Connect codes and bounded message requests establish contact without making a project service the identity authority. | Andri (SEC/NET/PROD); external evaluators: **Unassigned** | **Implemented Beta; external gates open.** `kc2` binds the stable account digest to a random rotatable capability. Weekly fixed-size encrypted records carry complete bounded authority, at most two ingress bundles, three introduction routes and the admission descriptor. Lookup caps candidates/bytes, verifies before state mutation, and fails closed on authority conflicts. Standard/Private records are mailbox-only. Explicit legacy retirement and authenticated paired-contact/owned-device upgrades preserve identity and safety numbers. | [ADR-0030](adr/0030-first-contact-admission.md); [message-request matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [discovery crypto](../crates/kult-crypto/src/discovery.rs); [discovery matrix](../crates/kult-node/tests/discovery_e2e.rs); [DHT limits](../crates/kult-transport/src/internet.rs) | Retain revision-bound CI/fuzz evidence; run hostile multi-bootstrap/suppression and clean distinct-NAT journeys; independently adversarially review and physically qualify the combined v2 flow | 2026-08-09 |
| **SV1-C05 Pairwise text bounds and atomicity** | One stable-v1 text event carries at most 65,507 UTF-8 bytes and changes visible/delivery state only through its complete atomic transition. | Andri (SEC/PROD); external reviewer: **Unassigned** | Test evidence | [Content codec](../crates/kult-protocol/src/content.rs); [atomic inventory](34-atomic-transition-inventory.md); [ADR-0028](adr/0028-atomic-protocol-commits.md); [typed commit plans](../crates/kult-store/src/commit.rs); [crash matrix](../crates/kult-node/src/atomic_tests.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Independent protocol review and supported-platform sudden-power-loss qualification | 2026-08-09 |
| **SV1-C06 Bounded groups** | Stable-v1 groups support at most 64 active accounts and authenticate the claimed sender separately for every recipient. | Andri (SEC/PROD); external reviewer: **Unassigned** | **Implemented Beta; external gates open.** One shared sender-key ciphertext is wrapped by a distinct fixed-width recipient tag whose key arrives over the authenticated pairwise device session. Verification precedes chain advance. Stored authors derive from the verified sender device and accepted authority chain. Live legacy groups visibly block until fresh exchange; old history retains its weaker label. Local tests cover known-answer and malformed codecs, wrong context/recipient/device, another member's valid-wrapper reuse, replay/reorder, monotonic announce races, membership/device/session/authority rotation, restore/reset, sync filtering, shared mesh, bounded fan-out, and transaction crash points across Rust, RPC, UniFFI and host shells. | [ADR-0029](adr/0029-recipient-authenticated-groups.md); [origin crypto](../crates/kult-crypto/src/group.rs); [group matrix](../crates/kult-node/tests/groups_e2e.rs); [attachment matrix](../crates/kult-node/tests/attachments_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [group crash matrix](../crates/kult-node/src/atomic_tests.rs); [RPC](../crates/kultd/tests/rpc_e2e.rs); [UniFFI](../crates/kult-ffi/tests/ffi_e2e.rs) | Retain revision-bound CI and fuzz artifacts; freeze stable wire/state and conformance vectors; obtain independent implementation/security review and named physical-device qualification | 2026-08-09 |
| **SV1-C07 Bounded attachments** | Consented attachments use authenticated resumable chunks, a 512 MiB primary limit, a 256 KiB preview limit, and no bulk airtime carrier. | Andri (SEC/PROD/NET); external reviewer and field evaluator: **Unassigned** | Test evidence for bounded metadata and file-first transitions | [Atomic inventory](34-atomic-transition-inventory.md); [ADR-0015](adr/0015-encrypted-attachment-pipeline.md); [protocol constants](../crates/kult-protocol/src/attachment.rs); [attachment e2e](../crates/kult-node/tests/attachments_e2e.rs); [media store tests](../crates/kult-store/tests/media.rs); [CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | ADR-0015 acceptance or successor, protected-file device matrix and independent review | 2026-08-09 |
| **SV1-C08 Backup and recovery** | A versioned encrypted backup restores eligible user state on a clean supported device while live protocol secrets reset; offline account-root recovery replaces a lost device set. | Andri (SEC/PROD); external reviewer and field evaluator: **Unassigned** | **Implemented Beta; external gates open.** Root-free KKR8–KKR10 and a separately held `.kra` authority use independent phrases. Restore creates a higher epoch and one fresh device. KKR8 remains directly restorable and naturally supplies no later local block rows; KKR8/KKR9 receive a fresh discovery capability. Current KKR10 preserves bounded exact account/device blocks plus the Connect capability/generation while excluding provisional requests, replay tombstones and invitation capabilities. Legacy KKR1–KKR7 are decode-only in production and can only create a fresh-identity former-account archive after a reviewed authority ceremony; no production API mints a new copied-root file, and crash-phase tests inspect staged and published stores to prove neither receives the former root. Plaintext exclusion tests cover the discovery capability in the outer file and account/device/prekey/ratchet/group/link/service/delivery secrets in the payload; stale backup, root theft, old epoch, fork/conflict, quorum loss, legacy-only-artifact reset, crash publication, strict RPC/UniFFI, desktop, host-mobile and simulator builds are exercised locally. Desktop genesis uses the native Save dialog; invalid or occupied destinations fail without consuming the one-time authority, and core, FFI, and desktop retry regressions keep the same runtime usable. The corrected ceremony also completed from a new physical Mac profile using the local development executable. | [Atomic inventory](34-atomic-transition-inventory.md); [storage contract](07-storage.md#4-backup--portability); [backup implementation/tests](../crates/kult-store/src/backup.rs); [backup e2e](../crates/kult-node/tests/backup_e2e.rs); [public FFI reset](../crates/kult-ffi/tests/ffi_e2e.rs); [linked-device matrix](../crates/kult-node/tests/linked_devices_e2e.rs); [desktop boundary](../apps/desktop/src-tauri/tests/desktop_e2e.rs); [physical development result](../field-qualification/v1/evidence/69e22e4/s23-ultra-macos-messaging.txt); [ADR-0026](adr/0026-revocable-device-authority.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md); [prior CI run 214](https://github.com/AndriGitDev/Komms/actions/runs/30281155361) | Retain revision-bound ADR-0026/ADR-0030/ADR-0031 CI artifacts, rerun desktop genesis from the final production-signed package, freeze stable wire/state format, run named clean physical-device and sudden-power-loss matrices, obtain independent interoperability and security review | 2026-08-09 |
| **SV1-C09 Blocking** | Blocking is an exact local identity rule that removes local relationship capabilities and state without claiming remote erasure or global identity revocation. | Andri (SEC/PROD); external abuse/usability evaluator: **Unassigned** | **Implemented Beta at the first-contact boundary.** Exact provisional account/device blocks are sealed, bounded, persisted through KKR10, enforced before request promotion, and exposed through every shell. Block retires provisional state and local queues available at that boundary without claiming remote erasure. | [ADR-0030](adr/0030-first-contact-admission.md#4-accept-reject-block-and-invite-are-explicit-state-transitions); [provisional store](../crates/kult-store/src/admission.rs); [message-request matrix](../crates/kult-node/tests/first_contact_admission_e2e.rs); [profile boundary](30-stable-v1-product-profile.md#7-blocking-and-deletion) | Extend capability cleanup across established relationships, group state, rendezvous and wake as those later protocols land; independently adversarially/usability test and physically qualify supported clients | 2026-08-09 |
| **SV1-C10 Honest delivery** | Queued means durable local custody, sent means bounded next-hop custody, and delivered requires an authenticated end-to-end receipt; none means read. | Andri (SEC/NET/PROD); external evaluator: **Unassigned** | **Implemented Beta; external gates open.** Direct acceptance waits for exact durable staging/consumption. Mailbox acceptance waits for durable relay commit; collection leases bounded rows and deletes exact ids only after endpoint `PendingStage`. Duplicate delivery is absorbed and the sender retains ciphertext until the authenticated end-to-end receipt or terminal retry result. | [Architecture lifecycle](03-architecture.md#3-message-lifecycle); [transport semantics](05-transports.md); [direct/mailbox settlement tests](../crates/kult-node/src/atomic_tests.rs); [mailbox store/failpoints](../crates/kult-transport/src/mailbox_v2.rs); [mailbox e2e](../crates/kult-node/tests/mailbox_e2e.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs); [ADR-0032](adr/0032-leased-mailbox-delivery.md) | Retained revision-bound crash evidence, qualified operator/backup/upgrade/cost record, real-network and physical sudden-power-loss qualification, independent review | 2026-08-09 |
| **SV1-C11 Supported platforms** | The stable release supports only the named device, OS, architecture, lifecycle, install, upgrade, and accessibility cells published as passed. | Andri (PROD/REL); independent field/accessibility evaluator: **Unassigned** | **Partial exact-revision development evidence retained; no supported stable cell yet.** Named candidate cells and complete procedures are published with a strict simulator/physical distinction. Revision `440a410a5d5a9373935cef8eb3728efe5ed91e64` retains three clean-install simulator passes, one Android screen-security simulator pass, and one non-qualifying iOS screen-security observation. Revision `996a3e4e961ae40589f303149855451430597874` retains one physical S23 Ultra clean-install/first-run pass on a debug-signed APK with 18 open rows, plus the superseded physical MacBook Air first-run failure. Revision `69e22e48b24983fdc3a8dd3acece4e7704fcea2d` retains corrected Mac first run, S23 pairing, request acceptance, and bidirectional Delivered state using exact debug/ad-hoc development binaries on one local Wi-Fi network; missing exact timings keep it outside the canonical pass set. Every target remains `qualified: false`. | [Platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems); [field matrix](43-field-qualification.md); [canonical target/scenario inventory](../field-qualification/v1/matrix.json); [revision-bound simulator record](../field-qualification/v1/evidence/440a410/summary.json); [S23 partial run](../field-qualification/v1/evidence/996a3e/galaxy-s23-ultra-android-16-run.json); [Mac failure note](../field-qualification/v1/evidence/996a3e/macbook-air-first-run-failure.txt); [corrected physical development result](../field-qualification/v1/evidence/69e22e4/s23-ultra-macos-messaging.txt); [release gate](24-local-release-gate.md) | Build production-signed final artifacts, repeat every applicable row with exact timing and evidence on the named Mac and S23, execute every other declared physical OS/device/lifecycle/accessibility cell, retain install/upgrade/rollback evidence, and obtain independent field/accessibility evaluation | 2026-08-09 |
| **SV1-C12 Replaceable services** | Standard defaults are disclosed and replaceable; no project service is the user identity authority or receives message plaintext or user identity private keys. | Andri (NET/SEC/FND); external operator reviewer: **Unassigned** | **Implemented Beta locally; external gates open.** Standard/Private/Sovereign policy is common across core, daemon, UniFFI, desktop, Android, and iOS. A signed, versioned, parent-bound provider directory preserves manual routes, retains a bounded last-valid chain, exposes conflict/stale/unavailable state, supports authenticated key rotation and explicit opt-out, and has no mandatory entry. Direct pinned TLS and loopback-Tor rendezvous follow the selected mode. A dedicated two-role binary wraps a bounded Komms-only Kademlia cache and persistence-free fixed-shape rendezvous, terminates Noise/TLS in process, accepts no endpoint/mailbox/wake/directory authority, and ships with a hardened profile and runbook. A separate fixed-shape native-wake binary holds only dedicated TLS, capability-encryption, APNs/FCM credentials and bounded replay/revocation state; sealed client capabilities, durable identity-free revoke retries, pinned direct/Tor access, bounded generic collection, direct APNs, Play-only FCM, and an inspected Google-free artifact preserve ordinary delivery semantics. A separate fixed-mapping OHTTP relay reconstructs minimal headers, enforces one HTTPS gateway plus exact outer sizes, retries nothing, keeps no durable state, and holds no gateway HPKE key; clients remain Tor-only and no gateway or non-collusion claim exists. No production directory, trusted root, qualified default, native-provider credential, or network service is deployed. | [Operating modes](36-operating-modes-and-provider-directory.md); [ADR-0017](adr/0017-optional-hybrid-modes.md); [local journey gate](../scripts/test-operating-mode-journeys.sh); [ADR-0018](adr/0018-pairwise-rendezvous.md); [service component](../crates/kult-rendezvous/src/lib.rs); [network service](../crates/kult-reference-service/src/lib.rs); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [deployment profile](../deploy/reference-service/compose.yaml); [operator runbook](35-reference-service-operations.md); [operator record](reference-service-operator.md); [self-hosting boundary](26-self-hosting.md); [ADR-0019](adr/0019-native-wake-gateway.md); [wake deployment profile](../deploy/wake-gateway/compose.yaml); [wake runbook](37-native-wake-operations.md); [mobile wake matrix](38-native-wake-mobile-qualification.md); [wake operator record](wake-gateway-operator.md); [OHTTP relay runbook](52-ohttp-relay-operations.md); [OHTTP relay operator record](ohttp-relay-operator.md) | Retain revision-bound multi-architecture digest/SBOM/provenance and reproducibility evidence; deploy and qualify exact hardened reference and wake hosts; run named APNs/FCM physical lifecycle rows and clean distinct-NAT/default-blackhole/replacement journeys against real operators; complete and qualify a separated OHTTP client/relay/gateway path or retain Tor-only Private wording; obtain independent operator review and real plural operation before any plural claim | 2026-08-09 |
| **SV1-C13 Resilient retry and fallback** | Komms retains queued work, retries within declared bounds, and can use more than one supported route; it does not guarantee availability or delivery time. | Andri (NET/PROD); external field evaluator: **Unassigned** | **Automated local evidence.** Manual, authenticated discovery, LAN, and rendezvous hints remain source-separated. Rendezvous maintenance is trigger-bound, jittered, coalesced, single-flight, backoff/circuit limited, and blackhole failure leaves ordinary queued work and delivery semantics unchanged. | [Transport design](05-transports.md); [ADR-0018](adr/0018-pairwise-rendezvous.md); [rendezvous matrix](../crates/kult-node/tests/rendezvous_e2e.rs); [node delivery tests](../crates/kult-node/tests/node_e2e.rs); [mesh policy tests](../crates/kult-node/tests/mesh_policies.rs); [sneakernet tests](../crates/kult-transport/tests/sneakernet.rs) | Revision-bound retained evidence; real NAT, background, handoff, deployed operator failure/replacement, and two-radio field matrix | 2026-08-09 |
| **SV1-C14 Local deletion limits** | Delete removes live logical history and Komms-owned references from the current profile; it does not promise forensic or remote erasure. | Andri (SEC/PROD); external storage reviewer: **Unassigned** | Implemented with repeatable schema, migration, restore, remnant-control, Linux/ext4 scale, and hosted Windows Server 2025/NTFS storage-suite evidence | [Storage limits](07-storage.md); [ADR-0027](adr/0027-opaque-indexed-store.md); [qualification](33-opaque-store-qualification.md); [Windows/NTFS CI](https://github.com/AndriGitDev/Komms/actions/runs/30225556928); [opaque store](../crates/kult-store/src/store_v2.rs); [migration](../crates/kult-store/src/migration.rs); [backup tests](../crates/kult-store/tests/backup.rs); [ephemeral tests](../crates/kult-node/tests/ephemeral_e2e.rs) | Independent storage review; physical macOS, Windows, Android, and iOS qualification; sudden-power-loss, backup-exclusion, permissions, snapshot, and forensic evidence | 2026-08-09 |
| **SV1-C15 Nonprofit project mission** | Official Komms activity follows a nonprofit public-benefit mission; this is project policy, not registered-charity status and not a restriction on independent AGPL commercial use. | Andri (FND/COM; project policy owner); qualified legal reviewer: **Unassigned** | **Implemented project controls; external and financial attestations open.** Governance, an explicit no-entity funding report, quarterly/material-change cadence, sponsor/conflict/surplus rules, accurate AGPL section-13 limits, commercial/government rights, trademark/asset/package policy, and provider lawful-request/incident dry-runs are source controlled. | [ADR-0033](adr/0033-nonprofit-founder-stewardship.md); [governance](../GOVERNANCE.md); [funding policy](48-funding-transparency.md); [initial report](../operations/v1/funding-report.json); [license/trademark/assets](47-license-trademark-assets.md); [privacy/legal/incident readiness](49-privacy-legal-incident-readiness.md) | No legal entity, dedicated project account, founder financial attestation, qualified legal/licensing review, independent transparency review, or live incident/legal exercise exists | 2026-10-26 |

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
| [GitHub repository description](https://github.com/AndriGitDev/Komms) | “serverless” and “functional on & off the grid” can read as current universal/field-qualified claims. | Describe a Beta with direct, local, radio, and file transport implementations and name the outstanding stable/field gates. |
| Release and package listings | Old screenshots, summaries, or package descriptions can outlive repository corrections. | Audit at every release; stable wording must cite a claim id and the release evidence bundle. |

The accountable owner for these external corrections is Andri. Completion must
be linked here before P0-01 closes.

## 5. P1 readiness ledger

P1 controls may be implemented while their external adoption evidence remains
open. No row below changes the rule that independent, physical, legal,
financial, or operator claims require the named evidence.

| Gate | Current control evidence | Status and open gaps | Artifacts |
|---|---|---|---|
| **P1-01 Fast contributor path** | Versioned bounded profiles cover protocol, storage/node, desktop, Android host core, iOS host core, localization, documentation, and stewardship. The runner strips credentials and rejects publishing, remote login, and history-changing commands. Issue forms, labels, sensitive ownership, deterministic fixtures, troubleshooting, and architecture orientation are present. | **Implemented locally; adoption evidence open.** No recorded independent newcomer has completed the path and submitted a reviewed change. | [Contributor path](44-contributor-path.md); [profiles](../contributor/profiles.json); [runner](../scripts/contributor-check.py); [runner tests](../scripts/test-contributor-check.py) |
| **P1-02 Localization and accessibility system** | One versioned catalog provides 1,364 stable identifiers across complete English and Icelandic locales and generated desktop, Android, and iOS resources. Checks cover source extraction, placeholders, plurals, NFC/bidi controls, fallback, malformed resources, expansion, cross-shell parity, semantics, focus, target size, contrast, and reduced motion. | **Implemented locally; human evidence open.** Fluent Icelandic review, named physical screen-reader/large-text/switch/magnification runs, disabled-user assessment, and independent accessibility review are unassigned. | [Localization/accessibility](45-localization-accessibility.md); [catalogs](../locales); [contract checks](../scripts/test-localization.py); [accessibility check](../scripts/check-shell-accessibility.py) |
| **P1-03 Stand-alone protocol and conformance kit** | A versioned implementation-independent specification, 51 language-neutral exact cases, binary fixtures, state traces, secret-free capture, adapter contract, archive builder, and Komms fixture consumers are implemented. | **Implemented locally; independent interoperability open.** No separately produced implementation or external fixture producer has run the kit. | [Protocol conformance](41-protocol-conformance.md); [specification](../conformance/v1/SPECIFICATION.md); [manifest](../conformance/v1/manifest.json); [runner](../conformance/v1/run.py) |
| **P1-04 Operator program and sustainable capacity** | A machine-readable role catalog, support/EOL policy, capacity/cost inputs, abuse/incident path, upgrade/rollback rules, and two strict external onboarding slots are implemented. The reference image can run bootstrap/DHT and rendezvous in separate processes with mutually exclusive credential mounts. A dedicated `kult-mailbox` artifact negotiates only `/komms/mailbox/2`, separates its row key, transport identity, and durable database, exposes aggregate-only health, and ships with a hardened non-publishing-by-default container path and complete custody runbook. A dedicated `kult-ohttp-relay` artifact implements one fixed RFC 9458 relay→gateway mapping, exact outer sizes, reconstructed minimal headers, no retries, no durable state, aggregate-only health, and no gateway HPKE key. | **Open.** No project service is deployed or qualified. The OHTTP client/gateway path, distinct administrative domains, and non-collusion evidence are absent; container/network smoke needs retained authorized execution; and two real distinct external operators have not supplied conformance, capacity, cost, backup, upgrade, incident, or independence evidence. | [Operator program](46-operator-program.md); [role catalog](../operations/v1/roles.json); [external slots](../operations/v1/operator-records.json); [reference runbook](35-reference-service-operations.md); [split reference profile](../deploy/reference-service/compose-split.yaml); [mailbox runbook](50-mailbox-service-operations.md); [mailbox artifact](../crates/kult-mailbox); [wake runbook](37-native-wake-operations.md); [OHTTP relay runbook](52-ohttp-relay-operations.md); [OHTTP relay artifact](../crates/kult-ohttp-relay) |
| **P1-05 License, trademark, and asset policy** | AGPL-3.0-only scope, bounded section-13 explanation, commercial/government rights, contribution terms, official/descriptive mark use, package identifiers, artwork groups, and third-party notices are recorded. The BIP-39 word-list attribution now retains its MIT notice instead of calling it public-domain data. | **Implemented project policy; qualified review open.** Trademark clearance, licensing advice, and founder provenance attestation for project artwork remain unassigned. | [Policy](47-license-trademark-assets.md); [asset inventory](../operations/v1/assets.json); [third-party notices](../THIRD_PARTY_NOTICES.md); [BIP-39 notice](../LICENSES/BIP-39-MIT.txt); [name decision](32-name-risk-decision.md) |
| **P1-06 Nonprofit funding and transparency** | Policy defines permitted income, mission use, compensation, surplus, sponsor independence, conflicts, personal/unreimbursed costs, quarterly/material-change reporting, and append-only corrections. An initial no-entity/no-account report refuses to infer zero amounts. | **Open.** Founder financial attestation, any real transactions/costs, dedicated account/entity, and independent accounting or transparency review are absent. | [Funding policy](48-funding-transparency.md); [initial report](../operations/v1/funding-report.json); [ADR-0033](adr/0033-nonprofit-founder-stewardship.md) |
| **P1-07 Privacy, legal, and incident runbooks** | Provider data-flow inventory covers direct, DHT, rendezvous, mailbox, wake, native providers, Tor, the implemented-but-unqualified OHTTP relay boundary, release stores, retention, correlation, lawful requests, credential-specific containment, advisories, and notifications. Four deterministic policy dry-runs reject unsafe shortcuts. | **Open.** Qualified counsel, backup security steward, live human tabletop, real operator/user notification drill, lawful-request disposition, and independent incident review are absent. | [Readiness runbook](49-privacy-legal-incident-readiness.md); [data flows](../operations/v1/data-flows.json); [dry-runs](../operations/v1/tabletops.json); [security policy](../SECURITY.md) |
