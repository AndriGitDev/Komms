# 24: Local Release Gate

Komms uses one complete local release matrix for publication candidates.
Ordinary contributions may open a focused pull request after the scoped checks
in [CONTRIBUTING.md](../CONTRIBUTING.md); CI is a verifier, not a substitute for
running the relevant local check. Publishing binaries, containers, or a stable
claim requires the full matrix, explicit maintainer authorization, and the
applicable P0 evidence in the
[stabilization program](29-stabilization-program.md).

This keeps the publication bar high without making every documentation or
bounded code contribution reproduce every platform. The commands are pinned in
[`scripts/local-release-matrix.sh`](../scripts/local-release-matrix.sh).

## 1. Toolchains and platform prerequisites

The core and desktop Cargo workspaces require Rust **1.88 or newer**. CI has a
dedicated build-compatibility job at exactly 1.88; normal local work should use a
current stable toolchain. The complete matrix also needs:

- nightly Rust with `cargo-fuzz`, plus `cargo-deny`;
- the desktop system libraries listed in
  [`apps/desktop/README.md`](../apps/desktop/README.md);
- JDK 17 or newer and Gradle 8.14.3 for the Android host/core gate;
- Android SDK 35, an NDK, `cargo-ndk`, and the configured Rust Android targets
  for APK/lint;
- Swift 5.9 or newer for the iOS host/core gate; and
- full Xcode, XcodeGen, and the configured Rust Apple targets for the unsigned
  iOS Simulator application gate.

The platform READMEs are authoritative for individual build commands. Missing
optional platform SDKs become explicit deferrals; missing tools for a gate that
the current release requires are failures.

## 2. Complete local matrix

The script runs:

1. workspace formatting, all-target/all-feature warnings-as-errors clippy, all
   tests, `no_std` crypto/protocol builds, `cargo-deny`, release-policy and
   dependency-integrity checks, deterministic security-review package
   validation, plus release-evidence/signing/release-qualification and
   field-qualification regression tests and bounded contributor-profile
   safety tests;
2. the ADR-0027 100,000- and 1,000,000-message migration, unlock, indexed page,
   exact edit/delete, memory, and database-growth budgets;
3. the desktop workspace's independent format, clippy, test, and deny gates;
4. the endpoint container image build plus dedicated reference, mailbox, wake,
   and OHTTP service image builds and restart/hardening smokes when a Docker
   daemon is available;
5. generated Kotlin UniFFI bindings plus the Android JVM/core two-node suite;
6. generated Swift UniFFI bindings plus the iOS/macOS host two-node suite;
7. Android APK/lint and the unsigned iOS Simulator application build when their
   complete SDKs are installed;
8. every crypto and protocol fuzz target for 60 seconds, including C2 device
   records and C7 call-control/call-media parsers; and
9. final Git whitespace and worktree review.

Run from the repository root:

```sh
scripts/local-release-matrix.sh
```

`KOMMS_FUZZ_SECONDS` may shorten a developer smoke pass, but the release record
uses the default 60 seconds. Set `KOMMS_REQUIRE_ANDROID_APP=1` or
`KOMMS_REQUIRE_IOS_APP=1` when that platform gate must fail rather than be
reported as deferred. Set `KOMMS_REQUIRE_SERVICE_CONTAINERS=1` to make an
unavailable container daemon fail instead of defer.

## 3. Deferred and external gates are explicit

A missing SDK is not a passing result. The script prints `DEFERRED` and keeps the
rest of the matrix running unless the matching `KOMMS_REQUIRE_*` flag is set.
The release handoff must list each deferred item with its reason. A host without
the Android SDK/NDK can still prove the generated bindings and JVM/core behavior;
a host without full Xcode can still run the Swift host/core suite. Per-push CI
also assembles a real Android debug APK, but that evidence neither changes a
local `DEFERRED` record nor substitutes for hands-on device qualification.

External evidence is outside this script and cannot be replaced by a green host
test:

- the physical two-radio Meshtastic bench;
- real distinct-NAT/DCUtR and live-call network/audio-route matrices;
- hands-on Android/iOS accessibility, lifecycle, and device qualification;
- hands-on qualification of the tag-built installer/APK artifacts;
- production-signed/store artifacts and a separately administered
  reproducibility execution; and
- an independent security audit.

The canonical target/scenario inventory and evidence-level validator are in
[field qualification](43-field-qualification.md). Their local regression test
is part of this script. That green regression result proves the record format
fails closed; it does not turn any open physical row green.

## 4. Hosted evidence

Hosted automation complements the local checkpoint:

- `.github/workflows/ci.yml` repeats core/desktop format, lint, tests,
  `no_std`, dependency policy, release-control tests, fuzz smoke, generated
  Android/iOS host suites, MSRV 1.88, Windows core-storage tests, and Android
  debug-APK assembly;
- the iOS Simulator job remains gated by the `IOS_APP_CI=1` repository variable;
  it is enabled for the current per-push release evidence;
- `.github/workflows/audit.yml` runs weekly and on demand: advisories for both
  Cargo workspaces, core tests on macOS, the opaque-store scale gate on Linux,
  and an informational coverage snapshot; and
- `.github/workflows/hil-nightly.yml` remains dormant until a trusted
  `meshtastic-hil` bench is online and `HIL_BENCH=armed`.

Every external workflow action is pinned to a full commit. Top-level workflow
permission defaults are read-only. Reviewed updates are proposed through the
GitHub Actions dependency updater.

The tag-triggered release workflow has read-only repository contents. Its
evidence job has only the additional identity and artifact-attestation
permissions needed to bind retained files. It builds native validation
packages, performs a second controlled Linux build, emits the revision-bound
evidence bundle and CycloneDX SBOM, creates hosted artifact attestations, and
retains the files for 90 days. It neither creates a GitHub release nor accesses
production-signing material. Empty-draft creation, completed-asset upload, and
publication are separate protected manual operations. Completed assets are
uploaded only after offline qualification, and publication verifies their
exact evidence-bound digests.

A green build is evidence for the exact commit and environment it ran on. It is
not evidence for unsigned code from another commit, a physical device path that
was not exercised, or one of the external gates above.

## 5. Version, packaging, and signing boundary

All current build surfaces report `0.4.1`: the Cargo workspace and desktop
crate, Tauri bundle, Android `versionName`, and iOS short version. Android
`versionCode` and iOS build number advance together at `5`. CI and the local
matrix enforce that alignment with `scripts/check-release-version.py`. The
release channel is separate from these numeric application versions. The
historical public
[v0.3.0 Alpha](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0)
predates the current evidence design. Its unsigned desktop and debug-signed
Android assets remain test artifacts, not 0.4 Beta evidence.

The current release controls define:

- validation, Alpha, Beta, and stable channels with Beta carrying the same
  prerelease signing and non-stable claim boundary as Alpha;
- separate release-manifest, Android Play, Android Google-free, iOS, macOS,
  Windows, and Linux roles with rotation and compromise response;
- dependency locks for Android core and both app flavors plus checked artifact
  SHA-256 metadata;
- bounded artifact staging, checksums, aggregate SBOM, public builder records,
  signing records, qualification records, residual risks, and safe archive
  extraction;
- exact versus normalized two-builder comparison without claiming external
  independence; and
- protected draft, offline signature, and publication boundaries.

No production role is enrolled. The `production_signing` workflow input
therefore stops at a protected enrollment boundary. The iOS gate remains an
unsigned Simulator build, desktop/Android release packages remain validation
artifacts, and Windows hardware-backed signing has no chosen provider. See
[release security and recovery](39-release-security-and-recovery.md),
[release evidence bundles](40-release-evidence-bundles.md), and the
[release runbook](25-release-runbook.md).

Signing keys and credentials never enter the repository. A store signature,
hosted artifact attestation, checksum, or project-controlled second build does
not substitute for production signing, supported-system qualification, or
independent reproduction.

## 6. Publication discipline

Before any remote action:

1. record the exact branch and commit;
2. preserve the local matrix results and deferred-gate list;
3. confirm the worktree contains only intentional changes;
4. obtain explicit authorization to push/open a pull request; and
5. separately obtain explicit authorization before merge.

Do not create repeated fixup pushes to use hosted CI as an interactive compiler.
If a final hosted run is authorized, push the already-green local checkpoint
once, cancel obsolete duplicate runs, and treat remote-only failures as new local
reproduction work before another publication attempt.
