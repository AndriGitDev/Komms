# Komms iOS (alpha)

Application **A2** ([03: Architecture](../../docs/03-architecture.md)): a
Swift shell over `kult-ffi`'s embedded node runtime, the same library
surface the desktop and Android apps consume (ADR-0010). The shell adds
**no protocol logic**: delivery states, errors, and security indicators
are the node's own, verbatim.

## What it does

- **Create / unlock / restore** an encrypted store at the gate; restoring
  takes a `.kkr` backup file plus its 24-word mnemonic.
- **Pair out-of-band**: show your prekey bundle as a QR, scan a friend's
  with the camera (or paste the hex, interoperable with the desktop and
  Android apps and `kult bundle` / `kult add`), or add a contact from
  their kult address alone via DHT lookup.
- **Message** with honest delivery states: `queued` → `sent` (handed to a
  link) → `delivered` (end-to-end encrypted receipt came back), plus the
  "held, will send when a faster link exists" verdict on airtime-budgeted
  mesh links.
- **Verify** contacts by safety number: identical digits and QR on both
  ends (all platforms), compared aloud or by scanning each other's code,
  with a visible verified badge. Key changes are surfaced, never hidden.
- **Transport indicators**: kult address, NAT verdict, LAN peers via mDNS,
  queued and bridged-in-transit counts, live listen addresses.
- **Backup** to a single encrypted file via the system share sheet; the
  sealing mnemonic is shown exactly once and stored nowhere. The data
  directory is excluded from iCloud/iTunes backup: portability is the
  user-held `.kkr` file, not Apple's servers.
- **Network settings** persist as secret-free `settings.json` in the data
  directory: the same file format as the desktop and Android apps and
  the same knobs as `kultd`'s flags.

QR rendering is CoreImage, scanning is AVFoundation metadata; no
third-party dependencies anywhere in the app: the only library it links
is the workspace's own Rust core.

## Layout

```
apps/ios/
├── KommsCore/     # Swift package: generated UniFFI bindings + the session layer
│   └── Tests/     # unit tests + a two-node e2e over the bindings surface
├── KommsApp/      # the SwiftUI shell: views, QR camera (UI only)
│   └── project.yml    # XcodeGen spec (the .xcodeproj is generated)
└── scripts/
    ├── generate-bindings.sh   # cargo build + uniffi-bindgen → KommsCore
    ├── test-core.sh           # bindings + swift test (Linux or macOS)
    └── build-xcframework.sh   # Rust static libs for device/simulator (macOS)
```

Every behavior lives in `KommsCore` and is pinned by its tests: the e2e
drives two full nodes (pair by scanned bundle hex, verified `delivered`
states via listener events, safety numbers, backup → mnemonic → restore →
automatic re-handshake) against the host-built `libkult_ffi`, no
simulator required. `KommsApp` is UI only.

Generated bindings are never committed; `scripts/generate-bindings.sh`
produces them fresh from the crate. The package is deliberately outside
the cargo workspace, mirroring the other shells' posture.

## Build & test

`KommsCore` (bindings + session layer + e2e) needs only a Swift ≥ 5.9
toolchain and Rust; Linux works, no Xcode:

```sh
apps/ios/scripts/test-core.sh
```

The app itself needs macOS with Xcode, plus
[XcodeGen](https://github.com/yonaskolb/XcodeGen) and the iOS Rust targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
apps/ios/scripts/build-xcframework.sh   # Rust static libs → KultFFI.xcframework
cd apps/ios/KommsApp
xcodegen generate
xcodebuild -project KommsApp.xcodeproj -scheme KommsApp \
  -destination 'generic/platform=iOS Simulator' build
```

Meshtastic radio support is feature-gated off, mirroring `kult-ffi`'s
default (an iPhone has no serial port; a radio's network API can be
attached from a `meshtastic`-featured build).

CI runs the `KommsCore` e2e on every push (Linux, official Swift
container). The simulator app build is a macOS job gated behind the
`IOS_APP_CI` repository variable; set it to `1` to arm (macOS runners
are billed 10× on private repos).

## Not yet

Push-style wake-ups and background delivery (the node runs while the app
is foregrounded, iOS offers no equivalent of Android's foreground
service), BLE radios, and store distribution (M6).
