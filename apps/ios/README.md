# Komms iOS (alpha)

Application **A2** ([03: Architecture](../../docs/03-architecture.md)): a
Swift shell over `kult-ffi`'s embedded node runtime, the same library
surface the desktop and Android apps consume (ADR-0010). The shell adds
**no protocol logic**: delivery states, errors, and security indicators
are the node's own, verbatim.

## What it does

- **Obscure sensitive scenes before app-switcher snapshots and during live
  capture.** The always-on root privacy shield starts before unlock, covers on
  inactive/background transitions, and responds to UIKit capture notifications.
  Settings explicitly state that iOS cannot universally block still screenshots
  and that capture notification is not retroactive.
- **Reduce keyboard retention on every SwiftUI editor.** All 22 text editors
  disable autocorrection through one audited modifier; message/name fields keep
  only explicit capitalization semantics. Passphrases and recovery mnemonics use
  `SecureField`. Settings state that iOS has no per-field personalized-learning
  guarantee and non-secure third-party keyboards remain best effort.
- **Create / unlock / restore** an encrypted store at the gate; restoring
  takes a `.kkr` backup file plus its 24-word mnemonic.
- **Pair out-of-band**: show your prekey bundle as a QR, scan a friend's
  with the camera (or paste the hex, interoperable with the desktop and
  Android apps and `kult bundle` / `kult add`), or add a contact from
  their kult address alone via DHT lookup.
- **Rename a contact's private local petname** through swipe or context-menu
  actions. SwiftUI targets the exact peer key, uses the shared incognito field,
  previews NFC normalization and duplicate/confusable/bidi/invisible warnings,
  and requires explicit acceptance for risk. Duplicate names remain distinct;
  restart/`KKR5` preserves the local rename with zero delivery work.
- **Message** with honest delivery states: `queued` → `sent` (handed to a
  link) → `delivered` (end-to-end encrypted receipt came back), plus the
  "held, will send when a faster link exists" verdict on airtime-budgeted
  mesh links.
- **Send disappearing pairwise/group text and view-once attachments** with
  explicit SwiftUI lifetime controls and honest device-local removal copy.
  History shows relative expiry and refreshes on typed terminal events.
  View-once rows disable ordinary preview, playback, open, and export; Reveal
  once consumes into a unique protected app-private URL before Quick Look or a
  share target can receive it, and a failed handoff remains terminal.
- **Edit authored canonical Text** in pairwise and group history through an
  incognito SwiftUI editor. The action is available only on exact outbound text,
  uses shared capability/authorship checks, refreshes on typed target events,
  shows an edited revision marker, and presents the original plus every valid
  version for VoiceOver/Dynamic Type inspection. Editing is not erasure.
- **Render safe source formatting** in pairwise, group, note-to-self, and
  scheduled rows through the shared bounded formatter. SwiftUI builds only a
  selectable native `AttributedString`, composes semantic mention highlights,
  and copies the readable plain-text projection; it never linkifies, fetches,
  or interprets HTML, image syntax, or URL schemes from message source.
- **Schedule pairwise or group text** in local time: distinct scheduled rows
  stay editable/cancellable until the core activates them at the stored
  absolute UTC instant and they enter the ordinary delivery ladder.
- **Send and receive pairwise or group attachments** through iOS document
  pickers, with explicit consent, exact verified-byte progress,
  pause/resume/cancel/reject controls, and caller-selected export.
  Security-scoped provider files are copied with bounded memory through unique,
  backup-excluded, Data-Protection-complete staging paths; no photo-library
  permission is required. Generic files show and recheck F4 before explicit
  send/discard. JPEG/PNG selections use the shared Rust editor for orientation
  normalization, free/preset crop, 90-degree rotation, and user-positioned blur
  or pixelation, then review and send only the exact metadata-free PNG.
  Originals, intermediates, receiver previews, and protected export sources are
  cleaned on send, discard, denial, failure, background/lock, low storage, and
  restart. The UI states iOS's actual lifecycle contract: work continues only
  while the OS permits execution and resumes from durable verified progress.
- **Record pairwise or group audio messages** with explicit microphone consent
  and foreground-only capture, then stop into a no-autoplay review with locally
  derived duration/waveform and an F4 carrier explanation before explicit send
  or discard. AVFoundation's native recording is canonicalized to the shared
  metadata-free mono 16-bit PCM WAV / 16 kHz / 60-second profile before F3
  import. Interruption, route change, background, lock, view teardown, failure,
  discard, and restart clean the Data-Protection-complete transient; received
  clips are validated and materialized only for explicit protected playback.
- **Create and use sender-key groups** from stored contacts: list and read
  group history, send messages, add/remove members as the creator, and leave
  as any member while local history remains stored. Inbound rows name the
  sender; outbound rows show every recipient's actual delivery state instead
  of a misleading group-level checkmark.
- **Mention current group members** through an explicit accessible roster picker.
  The composer uses semantic ranges while preserving exact visible text, supports
  keyboard navigation where available, VoiceOver, Dynamic Type, Unicode/bidi,
  and duplicate-petname disambiguation, and stores drafts under complete Data
  Protection with backup exclusion. Editing across a mention removes its
  semantics rather than silently retargeting it. Send rechecks roster and
  capabilities and offers an explicit ordinary-text fallback with no mention
  notification.
- **Manage private local conversation folders** for pairwise contacts, groups,
  and note-to-self. SwiftUI exposes All and Unfiled navigation, exact
  duplicate-capable Unicode names, durable button reorder, explicit
  single-folder moves, deletion review, stale cleanup, and folder-first
  composition with label filters. The selected folder survives recreation only
  in the same non-synchronizing, this-device-only Keychain item as label filters.
- **Manage private contact and conversation labels** for pairwise contacts,
  groups, and note-to-self. The SwiftUI manager and assignment sheets support
  VoiceOver, Dynamic Type, Increased Contrast, Reduce Motion, hardware keyboard
  operation, exact Unicode/bidi text, duplicate-name color/order cues, non-color
  badges, destructive review, stale cleanup, and match-any/match-all filters.
  Selected ids and mode survive scene/background recreation only in a
  non-synchronizing, this-device-only Keychain item. Shared limits are 128
  definitions, 8,192 assignments, 32 labels per conversation, and 256 UTF-8
  bytes per name; canonical colors are `neutral`, `red`, `orange`, `yellow`,
  `green`, `teal`, `blue`, `purple`, and `pink`.
- **Pin private local conversations** across pairwise contacts, groups, and
  note-to-self. The leading VoiceOver/Dynamic-Type block follows folder and
  label eligibility; conversation actions pin/unpin exact typed targets and the
  manager provides button reorder plus unavailable-record cleanup. The shared
  8,192-pin limit, restart/`KKR5` behavior, and zero-network contract live in
  `KommsCore`, with no new permission or synchronized state.
- **Choose System, Light, or Dark appearance** in Settings, including at the
  gate. SwiftUI applies the cached choice immediately, then treats the sealed F5
  value as authoritative after unlock or `KKR5` restore. System follows iOS
  changes live; adaptive semantic colors preserve Increase Contrast,
  Differentiate Without Color, Dynamic Type, and Reduce Motion behavior, while
  delivery/security meaning always retains text, symbols, or accessible labels.
- **Manage private custom icons** for contacts, groups, folders, and note-to-self.
  SwiftUI rows and pins render the sealed icon or generated initials; the
  VoiceOver/Dynamic-Type manager offers all eight bundled glyphs, security-
  scoped Files JPEG/PNG selection, clear-to-fallback, and quota usage. The shared
  core produces only metadata-free 256×256 RGBA PNGs and enforces the 512 KiB,
  1,024-record, and 64 MiB caps with safe corrupt fallback. `KKR5` is the only
  portability path; icons never enter iCloud sync, URLs, peers, envelopes,
  capabilities, notifications, queues, or transports.
- **Verify** contacts by safety number: identical digits and QR on both
  ends (all platforms), compared aloud or by scanning each other's code,
  with a visible verified badge. Key changes are surfaced, never hidden.
- **Transport indicators**: kult address, NAT verdict, LAN peers via mDNS,
  scheduled, queued, and bridged-in-transit counts, live listen addresses.
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

C4 deadline calculation, capability checks, deletion, terminal tombstones, and
KKR5 exclusion are shared-core behavior. A full app type-check/simulator gate
requires Xcode; Swift parse plus the host UniFFI suite remain the local fallback.
See [C4 semantics and qualification](../../docs/19-ephemeral-messages.md).

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
simulator required. Its group acceptance scenario adds a real offline third
identity and pins creator authority, add/remove/leave convergence, history,
and honest partial delivery per recipient. Pairwise and group attachment
acceptance covers offer/consent/completion, exact bytes and metadata, lifecycle
controls, exact export, and overwrite refusal. Audio acceptance additionally
strips an injected native metadata chunk and pins identical canonical bytes and
duration across pairwise and sender-key group delivery. `KommsApp` remains
UI-only document-picker, recorder, and rendering glue.

Mention acceptance pins byte-for-byte Rust/UniFFI semantics, invalid Unicode
range rejection, exact peer targeting, restoration, and zero signal for plain
text or similar petnames. Rendering requests no contacts or notification
permission. Any notification remains on the existing user-controlled path, uses
a private generic preview, and offers no server-push or online-delivery guarantee.

Label acceptance uses the same deterministic fixture as Rust RPC, UniFFI, and
Kotlin, covering exact Unicode, stable ids/order, duplicate names, typed targets,
any/all results, restart, and errors. Labels request no Contacts, Photos,
notification, local-network, or other permission and never enter notification
categories, Spotlight, widgets, Siri/App Intents, pasteboard, previews, logs,
crash/analytics payloads, or ordinary scene restoration. `KKR5` preserves exact
definitions and memberships; message labels and linked-device synchronization
remain deferred.

Folder acceptance uses the same B10 fixture as Rust RPC, UniFFI, and Kotlin,
covering exact Unicode, duplicate names, stable manual order, typed
peer/group/note targets, single membership, label composition, restart,
deletion, and structured errors. Folder state requests no additional permission,
never leaves sealed local storage, and `KKR5` is its only portability path.

Pin acceptance uses the same B11 fixture as Rust RPC, UniFFI, and Kotlin,
covering exact typed peer/group/note targets, append and exact complete-set
reorder, folder/label composition, activity order, stale cleanup/reactivation,
restart, structured errors, and zero delivery work. `KKR5` is the only
portability path; message pins and linked-device pin sync remain deferred.

Theme acceptance uses the same B12 fixture as Rust RPC, UniFFI, and Kotlin,
covering the exact vocabulary/roles, first-run System, idempotency, restart,
`KKR5`, one local change event, and zero queued or transport work. The ordinary
non-synchronizing `UserDefaults` cache contains only the pre-unlock theme token;
it is not a portability or backup channel.

Custom-icon acceptance uses the same B13 fixture as Rust RPC, UniFFI, and
Kotlin, covering all exact target kinds, canonical metadata-free PNG output,
quota accounting, restart/`KKR5`, safe initials fallback, local events, and zero
delivery work. Security-scoped Files access lasts only for the explicit blocking
import call; no selected path or plaintext image becomes synchronized state.

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

Push-style wake-ups and continuous background delivery (iOS offers no
equivalent of Android's foreground service), BLE radios, and store
distribution (M6).
