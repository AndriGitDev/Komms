# Komms Android (alpha)

Application **A2** ([03 — Architecture](../../docs/03-architecture.md)): a
Kotlin shell over `kult-ffi`'s embedded node runtime — the same library
surface the desktop app dogfoods (ADR-0010). The shell adds **no protocol
logic**: delivery states, errors, and security indicators are the node's
own, verbatim.

## What it does

- **Create / unlock / restore** an encrypted store at the gate; restoring
  takes a `.kkr` backup file plus its 24-word mnemonic.
- **Pair out-of-band**: show your prekey bundle as a QR, scan a friend's
  with the camera (or paste the hex — interoperable with the desktop app
  and `kult bundle` / `kult add`), or add a contact from their kult
  address alone via DHT lookup.
- **Message** with honest delivery states — `queued` → `sent` (handed to a
  link) → `delivered` (end-to-end encrypted receipt came back), plus the
  "held — will send when a faster link exists" verdict on airtime-budgeted
  mesh links.
- **Verify** contacts by safety number: identical digits and QR on both
  ends (desktop included), compared aloud or by scanning each other's
  code, with a visible verified badge. Key changes are surfaced, never
  hidden.
- **Transport indicators**: kult address, NAT verdict, LAN peers via mDNS,
  queued and bridged-in-transit counts, refreshed live.
- **Backup** to a single encrypted file via the system file picker; the
  sealing mnemonic is shown exactly once and stored nowhere. OS cloud
  backup is disabled (`allowBackup=false`) — portability is the
  user-held `.kkr` file, not Google's servers.
- **Network settings** persist as secret-free `settings.json` in the data
  directory — the same file format as the desktop app and the same knobs
  as `kultd`'s flags.
- A **foreground service** keeps the node delivering while the app is
  backgrounded; **Lock** stops the node and returns to the gate.

## Layout

```
apps/android/
├── core/          # plain JVM: generated UniFFI bindings + the session layer
│   └── src/test/  # unit tests + a two-node e2e over the bindings surface
└── app/           # the Android shell: activities, layouts, camera QR scanner
```

Every behavior lives in `:core` and is pinned by its JVM tests — the e2e
drives two full nodes (pair by scanned bundle hex, verified `delivered`
states via listener events, safety numbers, backup → mnemonic → restore →
automatic re-handshake) against the host-built `libkult_ffi`, no emulator
required. `:app` is UI only.

This is deliberately its own Gradle build, outside the cargo workspace:
the Android dependency tree stays out of the core crates' lockfile and
cargo-deny surface. The runtime footprint is small and auditable — JNA
(the UniFFI transport), kotlinx-serialization (settings.json), androidx
basics, CameraX, and ZXing core (pure-Java QR encode/decode: no Google
Play Services, no ML Kit — F-Droid friendly). JVM dependencies are pinned
by `core/gradle.lockfile`.

## Build & test

`:core` (bindings + session layer + e2e) needs only a JDK ≥ 17, Gradle,
and the Rust toolchain — no Android SDK:

```sh
cd apps/android
gradle :core:build -Pkomms.androidApp=false   # builds kult-ffi, generates
                                              # bindings, runs the JVM e2e
```

The APK additionally needs the Android SDK, NDK, and cargo-ndk:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
cd apps/android
gradle :app:assembleDebug        # cross-compiles kult-ffi per ABI
```

ABIs default to `arm64-v8a,x86_64` (real phones + emulator); widen with
`-Pkomms.abis=arm64-v8a,armeabi-v7a,x86_64`. Meshtastic radio support is
feature-gated off, mirroring `kult-ffi`'s default (a radio's network API
can be attached from a `meshtastic`-featured build).

CI runs both: the `:core` JVM e2e on every push, and a debug-APK assembly
job that uploads the artifact.

## Not yet

Mobile push-style wake-ups (the node only runs while the foreground
service does), BLE radios, and store distribution (M6). The iOS shell
lives in [`apps/ios`](../ios/).
