# 24: Local Release Gate

Komms development uses one long-lived local branch and one complete local
release matrix. Feature work is not pushed merely to ask hosted CI whether it
compiles. Publication, a draft pull request, and any hosted repetition happen
only after the roadmap implementation is complete, local evidence is green, and
the maintainer explicitly authorizes the remote action.

This policy reduces private-repository runner cost without weakening the test
bar. The commands are pinned in
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
   tests, `no_std` crypto/protocol builds, and `cargo-deny`;
2. the desktop workspace's independent format, clippy, test, and deny gates;
3. generated Kotlin UniFFI bindings plus the Android JVM/core two-node suite;
4. generated Swift UniFFI bindings plus the iOS/macOS host two-node suite;
5. Android APK/lint and the unsigned iOS Simulator application build when their
   complete SDKs are installed;
6. every crypto and protocol fuzz target for 60 seconds, including C2 device
   records and C7 call-control/call-media parsers; and
7. final Git whitespace and worktree review.

Run from the repository root:

```sh
scripts/local-release-matrix.sh
```

`KOMMS_FUZZ_SECONDS` may shorten a developer smoke pass, but the release record
uses the default 60 seconds. Set `KOMMS_REQUIRE_ANDROID_APP=1` or
`KOMMS_REQUIRE_IOS_APP=1` when that platform gate must fail rather than be
reported as deferred.

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
- reproducible installer/store artifacts; and
- an independent security audit.

## 4. Hosted evidence

Hosted automation complements the local checkpoint:

- `.github/workflows/ci.yml` repeats core/desktop format, lint, tests,
  `no_std`, dependency policy, fuzz smoke, generated Android/iOS host suites,
  MSRV 1.88, and Android debug-APK assembly;
- the iOS Simulator job exists behind the `IOS_APP_CI=1` repository variable so
  a maintainer can authorize the higher-cost macOS repetition;
- `.github/workflows/audit.yml` runs weekly and on demand: advisories for both
  Cargo workspaces, core tests on macOS, and an informational coverage snapshot;
  and
- `.github/workflows/hil-nightly.yml` remains dormant until a trusted
  `meshtastic-hil` bench is online and `HIL_BENCH=armed`.

A green build is evidence for the exact commit and environment it ran on. It is
not evidence for unsigned code from another commit, a physical device path that
was not exercised, or one of the external gates above.

## 5. Version, packaging, and signing boundary

All current build surfaces report `0.1.0`: the Cargo workspace and desktop
crate, Tauri bundle, Android `versionName`, and iOS short version. This alignment
does not make 0.1.0 a supported binary release.

- Desktop bundle targets and platform icon files are configured for Linux,
  macOS, and Windows. No certificate, notarization credential, package-repository
  signature, or updater endpoint is configured.
- Android release signing is conditional. A maintainer may supply the
  git-ignored `apps/android/keystore.properties` file or the
  `KOMMS_ANDROID_KEYSTORE*` environment variables described in the Android
  README. Without them, release builds remain unsigned and debug/CI builds are
  unchanged.
- The iOS gate builds an unsigned Simulator application. App Store signing,
  provisioning, notarized distribution, and store metadata are not configured.

Signing keys and credentials never enter the repository. Reproducible signed
artifacts, store/package-manager publication, provenance, and update-channel
policy remain M6 work and must not be implied by the existing scaffolds.

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
