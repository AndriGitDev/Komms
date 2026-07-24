# Komms Android (alpha)

Application **A2** ([03: Architecture](../../docs/03-architecture.md)): a
Kotlin shell over `kult-ffi`'s embedded node runtime, the same library
surface the desktop app dogfoods (ADR-0010). The shell adds **no protocol
logic**: delivery states, errors, and security indicators are the node's
own, verbatim.

## What it does

- **Protect every screen before unlock** with always-on `FLAG_SECURE` installed
  before each activity draws. Compliant screenshots, screen recordings, and
  recent-task previews are blocked. Settings show the shared B14 policy and its
  compromised-device, overlay/accessibility-abuse, and external-camera limits.
- **Request private keyboard behavior on every text editor.** Every audited XML
  and programmatic field uses `IncognitoEditText`, which sets Android's
  no-personalized-learning and no-suggestions metadata. Passphrases and recovery
  mnemonics are masked. Settings state honestly that third-party IMEs may ignore
  the request.
- **Create / unlock / restore** an encrypted store at the gate; restoring
  takes a `.kkr` backup file plus its 24-word mnemonic.
- **Pair out-of-band**: show your prekey bundle as a QR, scan a friend's
  with the camera (or paste the hex, interoperable with the desktop app
  and `kult bundle` / `kult add`), or add a contact from their kult
  address alone via DHT lookup.
- **Link and manage owned devices** without a cloud account. The dedicated
  TalkBack-accessible manager lists exact physical devices, offers signed rename
  and permanently confirmed revoke, and drives both sides of the time-bounded
  QR/paste ceremony with matching comparison codes and selective initial
  transfer. Explicit encrypted sync export/import carries only the C2 allowlist;
  device ids, pairwise sessions, group sender chains, and delivery rows remain
  independent.
- **Rename a contact's private local petname** with an explicit TalkBack-
  accessible row action. Android targets the exact peer key, uses an incognito
  field, previews shared NFC normalization and duplicate/confusable/bidi/
  invisible warnings, and confirms before accepting risk. Duplicate names remain
  separate; restart/`KKR7` preserves the rename with zero delivery work.
- **Message** with honest delivery states: `queued` → `sent` (handed to a
  link) → `delivered` (end-to-end encrypted receipt came back), plus the
  "held, will send when a faster link exists" verdict on airtime-budgeted
  mesh links.
- **Make alpha live-audio calls** to paired contacts only while the shared core
  observes a fresh direct QUIC route. Native `AudioRecord`, `AudioTrack`, and
  MediaCodec Opus use the voice-communication path at 48 kHz mono, 20 ms, and
  24 kbit/s. The TalkBack-labelled UI provides ring/answer/decline/cancel/
  hangup state and an explicit direct-QUIC/no-history explanation. Microphone
  permission is requested only for a call action; backgrounding tears down the
  call, and the delivery foreground service never claims continuous calling.
  TCP, relay-only, mailbox, sneakernet, and mesh routes cannot start or queue it.
- **Manage signed group authority** with visible owner/admin/member roles,
  capability-gated legacy upgrade, owner/admin rename and membership controls,
  owner-only role grants and ownership transfer, and signed poll moderation.
  The TalkBack-accessible member rows show generation and signed/legacy state,
  prevent owner leave, and consume only typed UniFFI records and events.
- **Send disappearing pairwise/group text and view-once attachments** with
  explicit native lifetime controls and honest device-local removal copy.
  Expired rows are filtered/refreshed from typed core events. View-once review
  disables ordinary preview, audio, open, and export; the first explicit reveal
  consumes into an app-private FileProvider path and remains terminal even when
  Android cannot hand the output to another app.
- **Edit authored canonical Text** in pairwise and group history through a
  native `IncognitoEditText` dialog. The action is available only on exact
  outbound text, uses shared capability/authorship checks, refreshes on typed
  target events, shows an edited revision marker, and presents the original plus
  every valid version for TalkBack inspection. Editing is not erasure.
- **Render safe source formatting** in pairwise, group, note-to-self, and
  scheduled rows through the shared bounded formatter. Android builds only
  selectable native text spans, composes semantic mention highlights, and
  copies the readable plain-text projection; it never linkifies, fetches, or
  interprets HTML, image syntax, or URL schemes from message source.
- **Schedule pairwise or group text** in local time: the sealed scheduled
  outbox is shown separately with edit/cancel controls until the core moves an
  entry into the ordinary delivery ladder at its absolute UTC instant.
- **Send and receive pairwise or group attachments** through Android's Storage
  Access Framework, with explicit consent, exact verified-byte progress,
  pause/resume/cancel/reject controls, and caller-selected export. Provider
  streams are copied with bounded memory through unique app-private staging
  files; no broad storage permission or URI-to-filesystem-path conversion is
  used. Generic files show and recheck F4 before explicit send/discard. JPEG/PNG
  selections use the shared Rust editor for orientation normalization,
  free/preset crop, 90-degree rotation, and user-positioned blur/pixelation, then
  review and send only the exact metadata-free PNG. Originals, intermediates,
  and protected receiver previews are deleted on send, discard, denial, failure,
  activity stop/lock, low storage, and restart orphan recovery.
- **Record pairwise or group audio messages** with runtime microphone consent,
  a foreground-only stop/review flow, no autoplay, locally derived
  duration/waveform, and explicit send/discard. Every native capture is rewritten
  to the shared metadata-free mono 16-bit PCM WAV / 16 kHz / 60-second profile
  and enters the existing F3 pipeline. Audio-focus loss, activity stop, lock,
  failure, discard, and restart remove plaintext cache files; completed clips are
  probed and exported only into short-lived app-private playback files. F4 is
  rechecked at send, and mesh-only audio waits with zero bulk airtime frames.
- **Create and use sender-key groups** from stored contacts: list and read
  group history, send messages, add/remove members as the creator, and leave
  as any member while local history remains stored. Inbound rows name the
  sender; outbound rows show every recipient's actual delivery state instead
  of a misleading group-level checkmark.
- **Create and vote in encrypted group polls** through dedicated TalkBack-
  labelled cards and a bounded exact-Unicode composer. The current roster is
  fixed at creation; votes and identities are visible to members, explicitly
  not anonymous; voters may change choices before creator-only closure.
- **Mention current group members** through an explicit accessible roster picker.
  The composer preserves semantic spans across IME input and recreation, removes
  a mention rather than silently retargeting it when edited across, restores
  app-private drafts after process restart, and distinguishes duplicate petnames
  without exposing peer ids. TalkBack, scalable text, Unicode/bidi content, and
  highlighted selectable history use the exact visible fallback text. Send
  rechecks roster and capabilities and offers an explicit ordinary-text fallback
  with no mention notification.
- **Manage private local conversation folders** for pairwise contacts, groups,
  and note-to-self. TalkBack/switch/keyboard actions cover All and Unfiled
  navigation, exact duplicate-capable Unicode names, durable non-drag reorder,
  explicit single-folder moves, deletion review, stale cleanup, and folder-first
  composition with label filters. The selected folder survives recreation only
  inside the same Android Keystore AES-GCM ciphertext as label filter state.
- **Manage private contact and conversation labels** for pairwise contacts,
  groups, and note-to-self using app-local data only. TalkBack/switch/keyboard
  actions expose exact targets, translated color names, non-color membership
  badges, duplicate-name order cues, deletion review, stale cleanup, and
  match-any/match-all filters. Filter ids and mode survive activity/process
  recreation only as Android Keystore AES-GCM ciphertext in private preferences;
  they never enter saved-instance state. Shared limits are 128 definitions,
  8,192 assignments, 32 labels per conversation, and 256 UTF-8 bytes per name;
  canonical colors are `neutral`, `red`, `orange`, `yellow`, `green`, `teal`,
  `blue`, `purple`, and `pink`.
- **Pin private local conversations** across pairwise contacts, groups, and
  note-to-self. The leading TalkBack-accessible block follows folder and label
  eligibility; chat actions pin/unpin exact typed targets, while the manager
  provides button reorder, unavailable-record cleanup, and durable restart
  behavior. The shared cap is 8,192 and pin work requests no permission or
  network/notification/transport activity.
- **Choose System, Light, or Dark appearance** from Settings, including before
  unlock. AppCompat DayNight is applied in `Application.onCreate` so the gate
  does not flash the wrong palette; after unlock the sealed F5 value wins and is
  restored by `KKR7`. Light/night resources use semantic roles and WCAG-tested
  reference contrast, Android high-contrast text and disabled-animation settings
  remain native, and delivery/security rows retain non-color cues.
- **Manage private custom icons** for contacts, groups, folders, and note-to-self.
  Native rows and pins render the sealed icon or generated initials; the manager
  offers all eight bundled glyphs, Android SAF JPEG/PNG selection, clear-to-
  fallback, and quota usage. Selected content is copied only into a short-lived
  app-private file before the shared core emits a metadata-free 256×256 RGBA PNG.
  The 512 KiB/1,024-record/64 MiB limits and corrupt fallback are shared with
  every shell; `KKR7` and authenticated own-device C2 sync are the only
  portability paths, and no icon creates network,
  permission beyond the picker, notification, capability, or transport work.
- **Verify** contacts by safety number: identical digits and QR on both
  ends (desktop included), compared aloud or by scanning each other's
  code, with a visible verified badge. Key changes are surfaced, never
  hidden.
- **Transport indicators**: kult address, NAT verdict, LAN peers via mDNS,
  scheduled, queued, and bridged-in-transit counts, refreshed live.
- **Backup** to a single encrypted file via the system file picker; the
  sealing mnemonic is shown exactly once and stored nowhere. OS cloud
  backup is disabled (`allowBackup=false`): portability is the
  user-held `.kkr` file, not Google's servers.
- **Network settings** persist as secret-free `settings.json` in the data
  directory: the same file format as the desktop app and the same knobs
  as `kultd`'s flags.
- A **foreground service** keeps the node delivering while the app is
  backgrounded; **Lock** stops the node and returns to the gate.

C4 deadline calculation, capability checks, deletion, terminal tombstones, and
KKR6 exclusion are shared-core behavior. The SDK-free `:core:test` suite pins
bindings and app source parity, and CI assembles a real debug APK; hands-on
device behavior remains a separate qualification gate. See
[C4 semantics and qualification](../../docs/19-ephemeral-messages.md).

## Layout

```
apps/android/
├── core/          # plain JVM: generated UniFFI bindings + the session layer
│   └── src/test/  # unit tests + a two-node e2e over the bindings surface
└── app/           # the Android shell: activities, layouts, camera QR scanner
```

Every node behavior lives in `:core` and is pinned by its JVM tests: the e2e
drives two full nodes (pair by scanned bundle hex, verified `delivered`
states via listener events, safety numbers, backup → mnemonic → restore →
automatic re-handshake) against the host-built `libkult_ffi`, no emulator
required. Its group acceptance scenario adds a real offline third identity
and pins creator authority, add/remove/leave convergence, history, and honest
partial delivery per recipient. Pairwise and group attachment acceptance covers
offer/consent/completion, exact bytes and metadata, lifecycle controls, exact
export, and overwrite refusal. Audio acceptance additionally strips an injected
native metadata chunk and pins identical canonical bytes and duration across
pairwise and sender-key group delivery. `:app` remains UI-only SAF, recorder, and
rendering glue.

Mention acceptance pins byte-for-byte Rust/UniFFI semantics, invalid Unicode
range rejection, exact peer targeting, and zero signal for plain text or similar
petnames. Android notifications use only a generic private preview and remain
subject to the existing user-controlled notification permission and platform
policy; they do not provide server push or an online-delivery guarantee.

Label acceptance drives the same deterministic fixture through Rust RPC,
UniFFI, Kotlin, and Swift, including exact Unicode, duplicate names, typed
peer/group/note targets, stable order, any/all results, restart, and errors.
Labels request no Contacts, clipboard, broad-storage, notification, nearby, or
network permission. Label data never appears in notification channels, lock
screen metadata, recent-task titles, logs, crash/analytics payloads, or
unprotected state. `KKR7` preserves exact definitions and memberships; C2 can
converge them only between authorized owned devices, while message labels remain
deferred.

Folder acceptance drives the shared B10 fixture through Rust RPC, UniFFI,
Kotlin, and Swift, including exact Unicode, duplicate names, stable manual order,
typed peer/group/note targets, single membership, label composition, restart,
deletion, and structured errors. Folder state requests no additional permission,
never leaves sealed owned-device storage. Portability is limited to `KKR7` and
authenticated own-device C2 sync.

Pin acceptance drives the shared B11 fixture through Rust RPC, UniFFI, Kotlin,
and Swift, covering exact typed peer/group/note targets, append and complete-set
reorder, folder/label composition, activity ordering, stale cleanup/reactivation,
restart, structured limits/errors, and zero delivery work. `KKR7` together with
authenticated own-device C2 sync are the only portability paths; message pins
remain deferred.

Theme acceptance drives the shared B12 fixture through Rust RPC, UniFFI, Kotlin,
and Swift: exact vocabulary/roles, first-run System, idempotency, restart,
`KKR7`, one local event, and zero queued or transport work. The ordinary private
preference cache carries no identity, message, contact, or network data.

Custom-icon acceptance drives the shared B13 fixture through Rust RPC, UniFFI,
Kotlin, and Swift: all four exact target types, canonical metadata-free output,
quota accounting, restart/`KKR7`, generated-initials fallback, local events, and
zero delivery work. The Android manager uses SAF access only for the explicit
selection and deletes its app-private transient after the blocking core call.

This is deliberately its own Gradle build, outside the cargo workspace:
the Android dependency tree stays out of the core crates' lockfile and
cargo-deny surface. The runtime footprint is small and auditable: JNA
(the UniFFI transport), kotlinx-serialization (settings.json), androidx
basics, CameraX, and ZXing core (pure-Java QR encode/decode: no Google
Play Services, no ML Kit, F-Droid friendly). JVM dependencies are pinned
by `core/gradle.lockfile`.

## Install the published Alpha

Download `Komms-0.1.0-android-debug.apk` and `SHA256SUMS` from the public
[Komms 0.1 Alpha release](https://github.com/AndriGitDev/Komms/releases/tag/v0.1.0).
It supports Android 8.0 (API 26) or newer on `arm64-v8a` phones and `x86_64`
emulators. This is a test-only APK signed with a development certificate, not a
store or production build. Verify its checksum, allow **Install unknown apps**
only for the browser or file manager used to open it, then turn that permission
off again. See the [Alpha testing guide](../../docs/27-alpha-testing.md) for the
complete install and smoke-test steps.

Android rejects an in-place upgrade from a build signed by a different key.
Export any data you need before uninstalling an older test build.

## Build & test

`:core` (bindings + session layer + e2e) needs only a JDK ≥ 17, Gradle 8.14.3,
and the Rust toolchain, no Android SDK:

```sh
cd apps/android
gradle :core:build -Pkomms.androidApp=false   # builds kult-ffi, generates
                                              # bindings, runs the JVM e2e
```

The APK additionally needs the Android SDK, NDK, and cargo-ndk:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --locked
cd apps/android
gradle :app:assembleDebug        # cross-compiles kult-ffi per ABI
```

ABIs default to `arm64-v8a,x86_64` (real phones + emulator); widen with
`-Pkomms.abis=arm64-v8a,armeabi-v7a,x86_64`. Meshtastic radio support is
feature-gated off, mirroring `kult-ffi`'s default (a radio's network API
can be attached from a `meshtastic`-featured build).

The local release matrix runs the `:core` JVM e2e and, on a host with the full
SDK/NDK, debug-APK assembly plus lint. Per-push CI also assembles the real debug
APK. Neither compilation path replaces the hands-on lifecycle, accessibility,
audio-route, background, and physical-device qualification matrix.

The published `v0.1.0` prerelease includes that installable debug APK alongside
the desktop packages and checksums. Future tagged candidates begin as drafts;
optional keystore secrets add a signed release APK and AAB. The exact secret
names, qualification steps, and explicit publication control are in the
[release runbook](../../docs/25-release-runbook.md).

## Version and release signing (scaffold)

The application id is `is.andri.komms`, the minimum Android version is API 26,
and the current `versionName` is `0.2.0`, aligned with the Rust, desktop, and iOS
surfaces. Release signing is optional and deliberately keyless by default.

To configure a future signed release, create the git-ignored
`apps/android/keystore.properties`:

```properties
storeFile=/absolute/path/to/komms-release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

The equivalent local/service inputs are `KOMMS_ANDROID_KEYSTORE`,
`KOMMS_ANDROID_KEYSTORE_PASSWORD`, `KOMMS_ANDROID_KEY_ALIAS`, and
`KOMMS_ANDROID_KEY_PASSWORD`. Keystores and `keystore.properties` are ignored by
Git and must never be committed. GitHub Actions receives a keystore only through
the `KOMMS_ANDROID_KEYSTORE_BASE64` secret described in the release runbook; it
is decoded into the runner's temporary directory. If no store is supplied, the
test APK is still produced and all ordinary debug/CI behavior is unchanged.
Store publication, provenance, and reproducible signed APK/AAB artifacts remain
M6 work.

## Not yet

Mobile push-style wake-ups after the foreground service itself is stopped,
BLE radios, and store distribution (M6). The iOS shell
lives in [`apps/ios`](../ios/).
