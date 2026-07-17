# 24: Local Release Gate

Komms development uses one long-lived local branch and one complete local
release matrix. Feature work is not pushed merely to ask hosted CI whether it
compiles. Publication, a draft pull request, and any hosted repetition happen
only after the roadmap implementation is complete, local evidence is green, and
the maintainer explicitly authorizes the remote action.

This policy reduces private-repository runner cost without weakening the test
bar. The commands are pinned in
[`scripts/local-release-matrix.sh`](../scripts/local-release-matrix.sh).

## 1. Complete local matrix

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

## 2. Deferred gates are explicit

A missing SDK is not a passing result. The script prints `DEFERRED` and keeps the
rest of the matrix running unless the matching `KOMMS_REQUIRE_*` flag is set.
The release handoff must list each deferred item with its reason. For the current
host, Android APK/lint/device work waits for the Android SDK/NDK; Android feature
implementation and the SDK-free JVM/core suite do not wait.

External evidence is outside this script and cannot be replaced by a green host
test:

- the physical two-radio Meshtastic bench;
- real distinct-NAT/DCUtR and live-call network/audio-route matrices;
- hands-on Android/iOS accessibility, lifecycle, and device qualification;
- reproducible installer/store artifacts; and
- an independent security audit.

## 3. Publication discipline

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
