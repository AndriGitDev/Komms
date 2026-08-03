# 12: Feature Delivery Plan

This document turns every item classified as **Build** or **Build with
constraints** in [11: Feature Scope](11-feature-scope.md) into sequenced work.
The scope document decides *whether* a feature belongs in Komms; this document
records *what remains*, its dependencies, and the acceptance bar.

It is a delivery plan, not a license to bypass the design process. Any change to
wire formats, cryptography, transport behavior, group authority, or replicated
state needs an ADR before implementation. Local-only application behavior does
not.

## 1. Status vocabulary

The canonical evidence levels are in
[29: Stabilization Program §2](29-stabilization-program.md#2-evidence-vocabulary).
The short labels below describe implementation inventory only:

| Status | Meaning |
|---|---|
| **Implemented** | The relevant production path exists. Automated, field, interoperability, independent-review, and stable evidence are stated separately. |
| **Partial** | A usable foundation exists, but some promised behavior or application surface is missing. |
| **Planned** | In scope but not implemented. |
| **Design-only** | A proposed ADR or design track exists, but product implementation is not authorized or implemented. |
| **Assurance** | An implemented security behavior with a permanent evidence and review track rather than a finite feature backlog item. |

## 2. Current baseline

Komms has a strong transport and security foundation plus shared versioned
content, attachment, carrier-capability, replicated-conversation, and linked-
device front doors. C7 direct-QUIC audio calls are implemented across the full
stack under accepted ADR-0013. ADR-0017 modes, ADR-0018 rendezvous, and the
ADR-0019 wake gateway/core and native Android/iOS clients are implemented for
Beta; external/deployment/physical-field gates remain open.

| Feature from scope | Current status | Main gap |
|---|---|---|
| Text messages | Implemented | Product polish and accessibility only. |
| Recorded audio messages | Implemented | Keep the canonical profile, lifecycle cleanup, F3/F4 behavior, and cross-platform acceptance gates stable. |
| End-to-end encryption | Assurance | Continuous review, KAT, fuzz, regression, external-vector, and independent-audit gates. |
| Post-quantum handshake | Assurance | Crypto-agility and downgrade-safe future upgrades. |
| Contact names / usernames | Partial | B5 local petname rename is implemented end to end; optional signed self-display suggestions remain deferred. |
| Message requests / first-contact consent | Implemented Beta | Preserve signed bounded admission, provisional isolation, explicit Accept/Delete/Block, group-invite consent, and direct durable settlement; independent adversarial/usability, physical-device battery/background/accessibility, capability discovery, and mailbox-v2 operator qualification remain. |
| Secure backups | Implemented | Future feature data must be added without leaking or silently omitting it. |
| Note to self | Implemented (text) | Attachments follow F3 shell integration. |
| Queued messages | Implemented | Already part of the honest delivery engine. |
| Scheduled messages | Implemented | Preserve the sealed absolute-UTC gate, edit/cancel-before-activation semantics, and distinct cross-shell lifecycle. |
| Text formatting | Implemented | Preserve exact source, bounded inert rendering, malicious-input parity, mention composition, and plain-text copy across every shell. |
| Folders | Implemented | Preserve single-folder membership, All/Unfiled views, deterministic order, stale cleanup, label composition, and zero-network behavior. |
| Pins | Implemented (conversation) | Preserve exact typed targets, complete durable reorder, stale reactivation/cleanup, folder → label → pin composition, and zero-network behavior; message pins remain separate. |
| Dark mode | Implemented | Sealed system/light/dark preference, shared semantic roles, and native live switching in every shell. |
| Custom icons | Implemented | Preserve exact typed targets, strict local image canonicalization, sealed quotas, initials fallback, `KKR10`/C2 own-device portability, and zero-network behavior. |
| Screen security | Implemented | Always-on shared policy, native shell protections, rapid desktop lock, and explicit platform limitations. |
| Incognito keyboard | Implemented | Always-on field inventory, Android no-learning request, secure secret fields, and honest iOS/desktop limits. |
| Local still-image editing | Implemented | Keep shared deterministic semantics, cleanup, exact-review, and metadata-removal gates stable; video remains out of scope. |
| Mentions | Implemented | ADR-0016 canonical peer targets, current-roster composers, conservative group capability gating, and local navigation/notification. |
| Labels | Implemented (contact/conversation) | Private pairwise, group, and note-to-self labels with fixed limits, stale cleanup, and accessible any/all filtering; message labels remain deferred. |
| File sharing | Implemented | Bounded F3/F4 delivery plus shared fail-closed file rows, explicit warned open/export, mismatch handling, lifecycle cleanup, and cross-language parity. |
| Linked devices | Implemented Beta with ADR-0026 authority | Preserve confirmed linking, independent per-device cryptography, strict-majority `KDA2`, visible forks/conflicts, recovery epochs, deterministic ordinary-data sync, honest legacy reset, and root-free `KKR10`; physical, independent-review, and interoperability gates remain. |
| Message editing | Implemented | ADR-0020 immutable revisions, pairwise and recipient-authenticated group authorship, deterministic offline reconciliation, retained versions, legacy-history labels, and every front door/shell. |
| Disappearing/view-once messages | Implemented | ADR-0021 exact local deadlines, envelope-v2 coarse relay deletion, tombstones, KKR6 exclusion, terminal reveal, and honest local-only promises. |
| Group polls | Implemented Beta | ADR-0022 fixed-electorate visible votes, deterministic heads/tallies, recipient-authenticated voter/creator origins, creator snapshot closure, and every front door/shell. Independent and physical qualification remain open. |
| Admin/role controls | Implemented | ADR-0023 owner-serialized signed roles, transfer, re-keying, and poll moderation through every shell. |
| Live voice/video calls | Implemented (Beta audio) | Preserve direct-QUIC-only gating, transient ratcheted control, authenticated Opus media, and zero history/backup/mesh work; real-network/device qualification precedes stable enablement and video. |
| Optional hybrid reachability/wake | Implemented Beta; external gates open | ADR-0017 modes, signed replaceable providers, ADR-0018 rendezvous, and ADR-0019 gateway/core/mobile clients are implemented with fixed codecs, sealed non-backup state, durable identity-free revoke retries, pinned HTTPS/Tor clients, bounded orchestration/collection, direct APNs, Play-only FCM, an inspected Google-free flavor, dedicated least-authority service artifacts, and strict front doors. Qualified deployment/Private ingress, external review, and named physical field evidence remain open. |

## 3. Shared foundations

These are prerequisites, not new user-facing scope.

### F1. Finish the group front door

The sender-key group core and its shared `kultd` RPC, CLI, and `kult-ffi` front
doors are implemented. Desktop, Android, and iOS group UX are implemented, completing
the shared group front door before polls, mentions, or roles.

Deliver:

- group records, messages, per-member delivery state, and group events through
  RPC and UniFFI;
- create, send, add, remove, leave, list, and history in CLI/desktop/Android/iOS;
- cross-surface tests proving that all shells interpret the same group state;
- truthful partial-delivery UI per member.

### F2. Versioned content model

**State:** implemented. [ADR-0014](adr/0014-versioned-message-content.md) is accepted
and implemented: the compatibility frame, permanent legacy-text path,
encrypted capability negotiation, scoped stable content ids, bounded
unknown-content behavior, sealed capability state, and render-safe RPC/UniFFI
outcomes are shared across pairwise and sender-key group messages.

The implemented codec keeps legacy raw text readable and carries the accepted,
bounded `Text`, `Attachment`, `Mention`, `Edit`, `Ephemeral`, `Poll`,
`GroupAuthority`, and `CallControl` kinds. C7 call control is ordinary encrypted
pairwise content—there is deliberately no relay-visible `CallSignal` envelope.
Formatting remains exact Text plus local rendering metadata and does not need a
distinct wire type.

The ADR must define:

- version negotiation and unknown-content behavior;
- strict size/depth/count limits for every decoder;
- compatibility with existing pairwise and group history;
- content IDs and references without exposing content type to intermediaries;
- padding behavior so a type does not defeat existing size-hiding promises;
- fuzz targets and migration behavior.

### F3. Attachment and media pipeline

**State:** implemented through core, shared RPC/CLI/UniFFI front doors, and the
desktop, Android, and iOS shells.
[ADR-0015](adr/0015-encrypted-attachment-pipeline.md) now has bounded
manifest/bulk codecs, deterministic chunk cryptography, sealed quota-bound
storage, explicit consent/cancel/reject/resume state, pairwise and encrypt-once
group transfer, streamed export, and a scheduler-enforced no-airtime class.
Activation consumes F4's fresh, time-bounded verdict on every offer or
missing-range request. Applications receive the same snapshot and change events
for user-facing feature gating, plus bounded path-based send/export, render-safe
transfer records and events, and every lifecycle control. Shells must not infer
capacity from an available route alone. Desktop uses native caller-selected
paths; Android uses Storage Access Framework streams and iOS uses
security-scoped document-provider URLs, with both mobile shells staging bounded
copies in app-private storage. All three provide pairwise/group send, protected
caller-selected export, exact per-object verified-byte progress, and lifecycle
controls without exposing protocol or storage internals. JPEG/PNG thumbnails
are generated locally with bounded decoders, stripped of source
metadata, capped at 256 KiB, sealed as the manifest's preview object, and
materialized only through protected transient paths for rendering. Each shell
states its real lifecycle behavior: desktop continues while open or minimized
and resumes after restart, Android keeps the node alive with its data-sync
foreground service, and iOS resumes durable verified progress on foreground
because the OS provides no equivalent continuous background service.

The existing envelope path is suitable for small payloads, not an unbounded file
transfer. Define attachments as encrypted, content-addressed chunks with a sealed
manifest, resumable receipt state, and bounded local storage.

Required properties:

- each chunk is independently authenticated and encrypted with a random
  attachment key carried only inside the ratcheted content;
- chunk order, total size, media type, filename, and content hash are in the
  sealed manifest, not routing metadata;
- cancellation, retry, deduplication, quota, and partial-file cleanup are
  explicit;
- previews are generated locally and stored sealed;
- a receiving user chooses whether to download large content;
- old clients retain an honest "unsupported attachment" record rather than
  corrupting or dropping the conversation.

### F4. Per-peer carrier capabilities

**State:** implemented through node, RPC/CLI, and UniFFI. The node probes stored
delivery hints on each heartbeat, publishes a 60-second snapshot and verdict
change event, and safely downgrades expired positive observations to
`offline_or_unknown`. Attachment activation consumes this same snapshot, so
applications and the scheduler no longer infer capacity independently.

The node scheduler knows link profiles, but applications do not receive a stable
per-peer verdict suitable for feature gating. Expose a capability snapshot and
change events such as:

- `realtime`: a currently usable high-bandwidth internet/LAN media path;
- `bulk`: non-airtime path available now or store-and-forward;
- `mesh_only`: only an airtime-budgeted path is currently known;
- `offline_or_unknown`.

This verdict gates calls, large files, media autoplay/download, and user-facing
explanations. It must remain advisory and time-bounded because reachability can
change immediately. ADR-0013's measured decision is conservative: only an
observed fresh direct QUIC path qualifies as `realtime`; TCP and circuit-relayed
paths do not, even when they can carry ordinary messages.

### F5. Local metadata store

**State:** sealed store foundation implemented. `kult-store` provides versioned,
bounded records and stable replacement keys for conversation types, folders,
single-folder membership, pins, labels and multi-label membership, drafts, UI
preferences, and custom icons. The table exposes only row count and approximate
sealed sizes in a copied database; `KKR10` backs up every non-ephemeral
user-authored record and note-to-self history. Legacy backup reset retains only
the eligible local-archive subset under a fresh identity.
Feature behavior and shell UX remain separate B7/B13 slices. B10 folders,
B11 conversation pins, B12 appearance, and B18 labels use the implemented record
shapes and the ordinary-history `KKR10` contract unchanged.

Add sealed endpoint-private records for conversation type, folders, pins, labels,
drafts, UI preferences, and custom icons. Keep local organization out of peer,
service, and transport payloads; C2 sync may carry only its explicit own-device
allowlist. Define which records belong in encrypted backups and version the backup
format when the first new record ships. Scheduled delivery is separate core queue
state covered by B8, not a UI-metadata timer.

Hybrid mode/provider preferences may use the F5 preference record, but
rendezvous exporters, source-scoped leases, generations, wake capabilities,
revocations, and pending collection work are sealed core service state. They
must not be represented as folders/drafts/preferences or B8 scheduled messages.

## 4. Build features

### B1. Text messages

**State:** implemented. Treat as the compatibility baseline for every content-model
change.

Remaining work:

- keep the permanent legacy-text path and mixed-version coverage green;
- add copy, reply-context navigation, selectable text, accessibility labels, and
  robust Unicode/bidirectional-text rendering in every shell;
- keep the existing queued/sent/delivered meanings unchanged.

Acceptance:

- old and new nodes exchange text in both directions;
- pairwise, group, internet, LAN, mesh, and sneakernet paths render identical
  Unicode content and honest delivery state.

### B2. Recorded audio messages

**State:** implemented across desktop, Android, and iOS.

**Depends on:** F2, F3, F4.

Every shell implements the accessible foreground-only sequence record → stop →
review → explicitly send or discard. Review and received-message playback never
autoplay; duration and the 64-bin waveform are derived locally from the actual
bytes and are not attachment metadata. Pairwise and sender-key group delivery
reuse the ordinary F3 attachment pipeline without new wire, cryptographic, or
transport behavior.

The single interoperable profile is a canonical 44-byte RIFF/WAVE header followed
by mono signed 16-bit little-endian PCM at 16 kHz, MIME `audio/wav`, filename
`audio-message.wav`, at most 60 seconds and 1,920,044 encoded bytes. The shared
canonicalizer validates the native recording, streams only the PCM data into a
new protected destination, and strips every extra container chunk. PCM WAV is
the common native floor across the supported webview, Android, and iOS versions;
introducing a compressed codec or a different wire/media profile requires a
separate compatibility decision rather than per-platform formats.

Policy:

- fresh internet/LAN or other F4 realtime/bulk route: ordinary attachment quotas;
- mailbox/sneakernet: ordinary configured attachment quotas and durable resume;
- mesh-only: hold for a faster link and emit zero manifest, chunk, missing-range,
  or other bulk airtime frames, with that reason shown before explicit send;
- offline/unknown: remain queued locally until a fresh faster route exists.

Permission denial leaves the ordinary composer usable. Microphone capture stops
and plaintext is discarded on interruption, background/lock, view teardown, or
shutdown; recording never continues in the background. Review and playback use
app-private/protected transients, clean failure paths, and startup orphan cleanup.
Desktop continues F3 transfers while open/minimized, Android uses the implemented
data-sync foreground service, and iOS resumes durable verified progress when the
OS returns the app to the foreground.

Acceptance injects a metadata-bearing native WAV and proves identical canonical
bytes, duration, pairwise delivery, sender-key group delivery, and protected
playback through Rust FFI plus every platform wrapper. Malformed, spoofed,
truncated, noncanonical, oversized, and overwrite cases fail closed. A dedicated
ADR-0015 regression proves audio on a mesh-only route emits zero airtime frames.

### B3. End-to-end encryption

**State:** implemented; permanent assurance track.

Every new content variant must travel inside the existing pairwise ratchet or
sender-key group body. New control data must not create a weaker side channel.
Maintain KATs, property tests, parser fuzzing, secret zeroization, no-panic rules,
dependency review, and the external audit gate. No shell may expose an
"unencrypted" fallback.

Acceptance is unchanged security behavior under every new feature's end-to-end
tests, plus negative tests proving intermediaries see only permitted metadata.

### B4. Post-quantum upgrades

**State:** hybrid X25519 + ML-KEM-768 handshake implemented; permanent assurance
track.

Create a crypto-agility ADR before introducing another primitive or parameter
set. It must specify signed capability advertisement, downgrade resistance,
transcript binding, mixed-version sessions, deprecation windows, and backup/key
migration. Never negotiate by accepting an unauthenticated "lowest common
denominator."

Acceptance:

- current clients remain interoperable during a staged upgrade;
- an active attacker cannot force classical-only or an older PQ suite;
- test vectors pin every supported suite and cross-version transcript.

### B5. Contact names and usernames

**State:** local petname rename implemented end to end; optional remote suggestion
deferred.

The implemented B5 slice reaches `kult-node`, strict RPC/CLI, UniFFI, desktop,
Android, and iOS. Rename always targets the exact peer key, NFC-normalizes and
bounds the proposed name, permits duplicates, and assesses duplicate,
mixed-script/confusable, bidirectional-control, and invisible-character risks.
A warned rename requires explicit acceptance. The mutation rewrites only the
sealed contact record, emits one endpoint-local event, survives restart and
`KKR10`, and creates zero lookup, capability, message, notification, queue,
envelope, or transport work. The shared B5 fixture and cross-surface tests pin
normalization, warnings, duplicate acceptance, persistence, and privacy.

If an optional self-selected display name is desired later, add it as a signed,
non-unique suggestion in the prekey bundle/DHT record. A recipient may choose
to accept it initially, but it can never silently override their local petname.
That is not a global username registry and must not imply uniqueness. The
bundle-format change still requires its own ADR, compatibility path, and tests
for remote-suggestion changes. It is not part of implemented B5.

### B6. Secure backups

**State:** current KKR10 and directly restorable root-free KKR8 compatibility
implemented; permanent decode-only KKR1–KKR7 reset compatibility track.
Production APIs cannot create copied-root legacy files.

For every feature in this plan, decide explicitly whether its state is identity
critical, conversation history, local preference, secret ephemeral state, or
re-creatable cache. Back up the first two; normally back up local organization;
never back up live ratchet/sender chains or temporary decrypted media.

Acceptance:

- backup and restore preserve all promised feature state;
- older KKR1 through KKR7 files remain readable only through an explicit
  new-identity archive reset;
- root-free KKR8 remains directly restorable and naturally contains no KKR9
  block rows;
- a restored node rotates/re-handshakes where required;
- omitted caches are rebuilt without data loss or false delivery state.

### B7. Note to self

**Depends on:** F5.

**State:** text note-to-self implemented through `kult-store`, `kult-node`, RPC/CLI,
UniFFI, desktop, Android, and iOS. Every surface uses the reserved
`note_to_self` identity. `KKR10` includes the sealed history; the bounded
new-identity legacy archive also retains eligible notes. Attachments follow F3
shell integration.

Implement a first-class local conversation, not a fake contact or a message sent
through the node's own ratchet. Store entries sealed in `kult-store`; never queue,
publish, generate receipts, or touch a transport. Support text first and
attachments after F3.

Acceptance proves zero envelopes are emitted, entries survive restart and
backup/restore, and all shells use the same reserved conversation identity.

### B8. Scheduled and queued messages

**State:** implemented end to end. `kult-store` seals pairwise/group scheduled text
separately from the encrypted delivery queue, and `kult-node` activates it only
when the absolute UTC instant is reached. RPC/CLI and UniFFI expose
create/list/edit/cancel, with the same scheduled lifecycle events. Desktop,
Android, and iOS expose local-time composer controls, editable/cancellable
scheduled rows, scheduled counts, and the ordinary queued/sent/delivered
history after activation.

This is a core queue/storage change, not part of the F5 local UI metadata store.

The implementation persists an optional UTC `not_before` timestamp in core
storage and enforces it in the node scheduler so delivery survives app exit,
background suspension, and restart. The UI handles local time zones and
daylight-saving display, but it
must not be the only gate. Define behavior for clock rollback/advance and permit
edit/cancel until encryption/queue activation.

Acceptance:

- nothing reaches any transport before `not_before`;
- restart and time-zone changes do not alter the intended instant;
- when the instant arrives offline, the message becomes ordinarily queued;
- UI clearly distinguishes scheduled, queued, sent, and delivered.

The core acceptance items are covered by restart, clock rollback/advance,
offline activation, pairwise/group, RPC, and UniFFI tests. All three shell
builds cover the shared scheduled records/events, and their conversation views
render the four states distinctly.

### B9. Text formatting

**State:** implemented end to end across `kult-node`, strict RPC/CLI, UniFFI,
desktop, Android, and iOS without a store, backup, content-kind, capability,
envelope, or transport-format change.

Use a deliberately small CommonMark-style subset: emphasis, strong, inline code,
code blocks, quotes, and lists. Store/transmit source text and render locally.
Disable raw HTML, remote images, automatic network fetches, scriptable links, and
unsafe URL schemes. A recipient that lacks formatting support sees readable
plain source.

Acceptance uses a shared conformance corpus across desktop, Android, and iOS,
including malicious input, huge nesting, bidirectional text, and copy-as-plain-
text behavior.

The implemented shared formatter accepts at most 64 KiB source, 1,024 blocks, 4,096
runs, inline/list depth 4, and 64 canonical UTF-8 semantic ranges. Complexity
falls back to the whole exact source. RPC and UniFFI expose only text, block
roles, and inert style tokens; desktop, Android, and iOS map them to native text
primitives for pairwise, group, note-to-self, and scheduled rows. B17 mention
ranges compose as highlights. The shared B9 fixture pins exact source and copy
text, malicious HTML/link/image syntax, bidi, list depth, and highlight styles.
See [16: Safe Text Formatting](16-safe-text-formatting.md).

### B10. Folders

**Depends on:** F5.

**State:** implemented end to end across `kult-store`, `kult-node`, RPC/CLI,
UniFFI, desktop, Android, and iOS.

Folders are local views over conversation IDs. Support create, rename, reorder,
move, delete-without-deleting-conversations, and an unfiled/default view. Do not
sync folders to contacts or leak them onto the wire.

Acceptance covers restart, backup/restore, deleted contacts/groups, and the same
conversation appearing in at most one folder unless multi-folder behavior is
explicitly chosen before implementation.

The implemented contract chooses single-folder membership. Exact names retain their
UTF-8 bytes and may duplicate; cryptorandom 16-byte IDs and persisted manual
order disambiguate them. All and Unfiled are virtual views. Complete-set reorder,
move/unfile, delete cascade, and stale cleanup are atomic, and folder selection
composes before the independent B18 any/all label filter. Shared limits are 128
folders, 8,192 assignments, and 256 UTF-8 bytes per name. `KKR10` preserves exact
IDs, names, order, membership, and stale behavior. Every mutation creates zero
envelope, queue, receipt, capability, or transport work.

### B11. Pins

**Depends on:** F5.

**State:** conversation pins implemented end to end across `kult-store`, `kult-node`,
RPC/CLI, UniFFI, desktop, Android, and iOS. Message pins remain deferred.

Pins use exact typed pairwise peer, group, or note-to-self `ConversationId`
values, never visible names. One pin per conversation and a fixed 8,192-pin
limit are enforced. Pin/unpin are idempotent; append order is durable and
compacts transactionally at `u32::MAX`. Reorder atomically requires the exact
complete durable set, including stale pins, so unavailable targets are never
silently lost.

The shared query composes folder selection, label any/all filtering, and then a
leading pinned block. Pinned rows use manual order, recent activity for tied
legacy order, and stable typed bytes; unpinned rows use recent activity and the
same typed tie-breaker. Unavailable pins remain diagnosable, can be removed only
by exact cleanup while stale, and reactivate only when the same typed identity
becomes available. `KKR10` preserves exact target, order, and stale behavior.
Every surface proves that pin work creates no envelope, queue, receipt,
notification, capability, crypto, or transport work.

### B12. Dark mode

**State:** implemented end to end. The canonical `system`, `light`, and `dark`
choice is stored in the existing independently sealed F5 UI-preference record at
`appearance.theme`. Missing or unknown legacy values safely render as System;
idempotent writes emit only the endpoint-local `ThemeChanged` event and create
no envelope, queue, capability, notification, cryptographic, or transport work.
`kult-node`, strict RPC operations `theme` / `theme_set`, CLI commands `theme` /
`theme-set`, UniFFI, and every platform wrapper expose the same contract.

Every shell applies a non-sensitive device-local cache before unlock to prevent
a theme flash, then reconciles after unlock: a canonical sealed value wins
(including after `KKR10` restore), while a missing value is initialized from the
cached/default System choice. Desktop resolves shared semantic CSS roles and
live `prefers-color-scheme` / `prefers-contrast` / `prefers-reduced-motion`;
Android applies AppCompat DayNight before the first Activity and uses matching
light/night semantic resources; iOS applies SwiftUI's preferred color scheme and
adaptive platform colors. The shared B12 fixture pins the exact vocabulary,
semantic roles, WCAG 2 contrast thresholds, and reference-palette ratios.

Acceptance covers first-run System, strict input, idempotency, restart, `KKR10`
restore, local-only events, zero delivery work, live native switching, high
contrast, reduced motion, and light/dark major-surface rendering. Security and
delivery states retain text, icons, or accessible labels and never rely on color.

### B13. Custom icons

**Depends on:** F5.

**Implemented.** Contacts, sender-key groups, private folders, and note-to-self each
have one exact typed private icon identity. No record renders deterministic
generated initials. Users can instead choose one of eight bundled glyphs
(`person`, `group`, `folder`, `note`, `star`, `heart`, `shield`, `compass`) or a
content-verified local JPEG/PNG. The shared node normalizes EXIF orientation,
rejects animated PNG and oversized/decompression-heavy inputs, applies a
centered-square or explicit oriented-pixel square crop, resizes to 256×256, and
emits a non-interlaced RGBA8 PNG containing only IHDR/IDAT/IEND, with no source
metadata copied.

The existing F5 record is now enforced as one icon per exact target, at most
512 KiB each, 1,024 records, and 64 MiB aggregate encoded bytes. Reads verify the
canonical profile again; a missing, corrupt, or non-canonical sealed image falls
back without rewriting or exposing it. Folder deletion removes its icon; other
unavailable exact identities remain inaccessible and can safely reactivate only
if that same technical identity returns. `KKR10` preserves icons as ordinary
sealed user-authored local metadata.

Node, strict RPC/CLI, UniFFI, desktop, Android, and iOS expose the same target,
set-image, set-glyph, read, clear, usage, and local-change contract. Desktop,
Android SAF, and iOS Files provide native selection and accessible management;
all conversation/folder lists render the sealed icon or initials. No avatar URL,
envelope, capability, notification, DHT record, peer synchronization, queue item,
or transport work exists. The shared B13 fixture and layer acceptance tests prove
metadata removal, input/output bounds, quota enforcement including the low-level
store boundary, all four target types, restart, `KKR10`, idempotency, corrupt and
missing fallback, and zero delivery work.

### B14. Screen security

**Implemented.** Platform controls have honest, always-on guarantees:

- Android: always-on secure-window protection for screenshots/screen recording
  and task previews, with the exact policy visible in settings;
- iOS: obscure sensitive content in the app switcher and respond to capture
  notifications; do not claim iOS can universally block screenshots;
- desktop: obscure recent/task previews where supported and provide a rapid lock
  shortcut; document compositor/OS limits.

The policy exists before unlock and is not a preference or F5 record. A shared
typed contract crosses `kult-node`, strict RPC/CLI, and UniFFI so every shell
renders the same `platform_enforced` / `best_effort` / `unavailable` claims and
limitations. Android installs `FLAG_SECURE` before every declared activity draws.
iOS starts covered, covers before inactive/background snapshots, and covers while
UIKit reports live capture while explicitly stating that still screenshots cannot
be universally blocked. Desktop requests Tauri native content protection, covers
on focus loss, and maps `Ctrl/Cmd+Shift+L` to the existing complete lock path.

The shared B14 fixture and layer tests prove capability parity, strict wire/CLI
parsing, pre-unlock availability, and zero stored/network behavior. Platform CI
builds the native implementations. Device/compositor qualification for actual
capture and app-switcher behavior follows [13: Screen Security](13-screen-security.md)
and remains a release-evidence task rather than an inflated cross-platform claim.

### B15. Incognito keyboard

**State:** implemented across `kult-node`, strict RPC/CLI, UniFFI, desktop, Android,
and iOS as an immutable always-on policy plus exhaustive native field controls.

The shared contract distinguishes `platform_enforced`, `platform_requested`,
`best_effort`, and `unavailable` rather than implying that a keyboard hint is a
guarantee. It is available before unlock, has no disable preference or stored
record, and creates no envelope, capability, notification, queue, or transport
work. Required semantic classes are message, future search, passphrase,
mnemonic, and name.

Android routes every XML and programmatic text editor through one class that
sets `IME_FLAG_NO_PERSONALIZED_LEARNING` and no-suggestions metadata on the final
input connection. iOS applies one shared, inventory-tested no-correction modifier to every
SwiftUI editor. Desktop classifies every editable textual HTML control and
applies autocomplete, autocorrect, autocapitalization, and spellcheck hints at
startup and after modal cloning. Passphrases and recovery mnemonics use masked
secret entry on every shell.

Automated acceptance inventories 21 Android construction paths, 20 iOS SwiftUI
editors, and 24 desktop editable textual controls, and checks shared fixture,
FFI, strict RPC/CLI, pre-unlock, and zero-delivery parity. No implemented search box
exists yet; its required class prevents a future search surface from bypassing
the policy. Android explicitly states that its documented flag is a request;
iOS and desktop expose no per-field personalized-learning guarantee. Manual
keyboard qualification follows [14: Incognito Keyboard](14-incognito-keyboard.md).

### B16. Local media editing

**State:** implemented for still JPEG/PNG across desktop, Android, and iOS.

**Depends on:** F3.

One path-based Rust/UniFFI helper performs content-verified bounded decoding
(32 MiB encoded, 4096 per edge, 12 megapixels), EXIF-orientation normalization,
exact integer crop then quarter-turn rotation, ordered user-positioned blur or
pixelation, and deterministic RGBA PNG encoding that omits source metadata. Output is
create-new and re-probed before F3 import; malformed, spoofed, truncated,
animated, unsupported, over-dimension, decompression-bomb-like, and overwrite
cases fail closed.

Desktop provides a keyboard/screen-reader-operable editor, Android stages SAF
streams without broad storage permission, and iOS stages security-scoped files
under complete Data Protection without photo-library permission. All show the
exact final asset and require explicit send or discard for pairwise or
sender-key groups. Only that final PNG enters F3. Protected originals, decoded
review state, and intermediates are removed on send, discard, denial, failure,
low storage, background/lock, shutdown, and restart orphan recovery.

Video editing, cloud processing, automatic face recognition, filters/effects,
generative editing, and editable projects are not part of this delivery. Any
new content kind, manifest field, wire metadata, crypto, or transport behavior
still requires an ADR.

Acceptance covers deterministic Rust/FFI/wrapper semantics, EXIF/GPS/XMP/comment
and thumbnail removal, orientation/crop/rotation/blur/pixelation, cancellation
and low-storage cleanup, exact pairwise/group delivery, protected receiver
preview/export, F4 reconfirmation, and zero mesh airtime.

### B17. Mentions

**State:** implemented across protocol, node, storage/backup, RPC/CLI, UniFFI,
desktop, Android, and iOS. **Governed by:**
[ADR-0016](adr/0016-group-mention-content.md). **Depends on:** F1, F2.

Compose mentions in group message text using an explicit member picker rather
than ambiguous free-form names. Encode a stable peer reference alongside fallback
display text so every client can highlight the intended member despite different
local petnames. Mention notifications remain local and opportunistic: there is no
server push guarantee.

The implemented kind `0x0003` uses exact authenticated fallback UTF-8 and canonical
sorted, non-overlapping UTF-8 byte ranges into a bounded target table. It never
normalizes Unicode or exposes kind, target, or range fields outside the existing
encrypted padded content. Historic resolution remains scoped to the exact group
peer and cannot retarget after a petname collision, rename, or departure.

Semantic send consumes a review token bound to the current roster, identity
mapping, and fresh authenticated per-peer capability snapshots. Every current
co-member must support Mention before the ordinary sender-key encrypt-once fanout;
unknown, stale, removed, changed, or incompatible members force a new review.
The explicit fallback sends the exact visible text as ordinary text and emits no
mention signal. RPC/CLI and UniFFI accept exact peer targets and byte ranges and
return render-safe records without raw authenticated payload bytes.

Acceptance covers duplicate petnames, roster changes, removed members, Unicode,
plain-text fallback, backup/restart, unknown and malformed durable retention,
mixed-version capability changes, accessibility, exact encrypt-once fanout, and
no notification for a peer merely sharing a similar display name. Endpoint-local
notifications use private generic previews and remain subject to mute/platform
policy; they provide no server-push or online-delivery guarantee.

### B18. Labels

**Depends on:** F5.

**State:** implemented through `kult-store`, `kult-node`, RPC/CLI, UniFFI, desktop,
Android, and iOS. PR #43/B17 was only the administrative branch base; labels have
no semantic dependency on Mention content. B18 stays inside the accepted F5
`LabelRecord` and `LabelAssignment` shapes and `KKR10`, so it requires no new
payload ADR.

Labels target stable pairwise, group, and note-to-self `ConversationId` values.
Definitions use independently minted random 16-byte IDs, exact UTF-8 names, and
the canonical `neutral`, `red`, `orange`, `yellow`, `green`, `teal`, `blue`,
`purple`, and `pink` tokens. Duplicate visible names remain distinct and are
presented with color plus deterministic insertion order. Empty or fixed
Pattern_White_Space-only names are rejected without otherwise normalizing or
rewriting text. Shared limits are 128 live definitions, 8,192 assignments, 32
labels per conversation, and 256 UTF-8 bytes per name.

Create, get, update, delete, assign, unassign, membership, labels-for-target,
stale inspection/cleanup, and deterministic match-any/match-all filtering are
bounded node operations shared by every wrapper. Deletion cascades atomically;
assign/unassign are idempotent. Unavailable definitions and conversation targets
stay durably diagnosable but are excluded from active filters. Filters affect
presentation only, never receipt, notification, delivery, search, unread truth,
queue work, ordering, or history. `KKR10` preserves exact IDs, names, colors,
ordering, membership, and stale behavior. The legacy archive reset retains only
eligible organization and never resumes the former identity.

All shells provide accessible managers, non-color badges, assignment actions,
duplicate disambiguation, deletion review, stale states, and any/all filters.
Android and iOS retain selected filters only in protected device-local state.
Label data never enters logs, crash reports, OS metadata, envelopes, DHT, group
state, capability advertisements, sender keys, ratchets, transport hints,
analytics, or remote notifications; label operations create zero network work.
There is no server, contact, or shared-taxonomy synchronization. C2 may converge
labels only inside authenticated encrypted bundles between authorized devices
of the same account.

Acceptance covers exact Unicode and whitespace boundaries, collision retry,
unknown colors, duplicate names, limit exhaustion, atomic failure/restart,
arbitrary operation sequences, stale references, delete/recreate isolation,
legacy KKR1–KKR7 archive compatibility, copied-database scans, wrapper fixture parity,
cross-shell accessibility and protected restoration, and zero-network-work
matrices. Message labels remain deferred pending demonstrated UI value. Folders,
pins, sorting, roles, shared tags, and generic organization frameworks remain
outside B18.

## 5. Build-with-constraints features

### C1. File sharing

**State:** implemented. Bounded attachments and the generic pre-send F4 explanation,
fresh verdict recheck, changed-verdict reconfirmation, and explicit send/discard
flow are implemented across desktop, Android, and iOS. Generic non-image rows use one
shared fail-closed filename/media-type policy with explicit warned open/export,
protected temporary lifecycle, and no auto-open or scanning claim.

**Depends on:** F2, F3, F4. **Governed by:** ADR-0015.

The implemented tiers are:

1. small files over internet/LAN with explicit user download;
2. resumable transfer over mailbox/sneakernet within local quotas;
3. a hard mesh block: every bulk attachment waits for a faster link and emits
   zero airtime-class frames under ADR-0015.

The sender UI must show the active policy before sending. The scheduler must
hold all bulk content for a faster link instead of fragmenting it across LoRa.
Reject dangerous filenames/paths, never auto-open executables, scan only locally
if an engine is present, and do not promise malware detection.

Acceptance includes loss/reorder/resume, duplicate chunks, hash mismatch, quota
exhaustion, sender cancellation, receiver rejection, malicious manifests, and
proof that an oversized transfer emits zero mesh frames.

### C2. Linked devices

**State:** implemented Beta with accepted offline-root authority. **Decisions:**
[ADR-0024](adr/0024-account-authorized-linked-devices.md) for per-device
delivery/sync and [ADR-0026](adr/0026-revocable-device-authority.md) for
authority/recovery.

Use one account identity with separately authenticated device keys rather than
copying live ratchet databases. Linking is proximate through a QR handshake or a
local-network session confirmed on both devices. Define:

- device certificate issuance and a visible device list;
- device addition, rename, last-seen, revocation, and lost-device recovery;
- per-device pairwise sessions and group sender keys;
- fan-out/dedup semantics and delivery state across devices;
- encrypted history transfer with progress and selective import;
- deterministic sync for contacts, verification, local organization, edits,
  polls, and expiry tombstones;
- what remains device-local (drafts, downloaded media, screen settings);
- backup interaction and how a restored identity avoids resurrecting revoked
  devices.

Acceptance covers three-device partition/rejoin, concurrent pairwise and group
sends, edits/polls/tombstones, revoked-device exclusion, group re-key after
revocation, replay/rollback rejection, KKR10 recovery plus KKR1–KKR7
new-identity archive reset, no cloud
service, strict RPC/CLI, UniFFI, and the confirmed QR/paste ceremony in every
shell. Local acceptance additionally covers offline-root migration,
new-identity copied-root reset, strict-majority transitions, stolen-minority
replacement attempts, quorum loss, root theft, forks, stale backups, old
epochs, recovery conflicts, root-free backup exclusions, deterministic crash
points, desktop, Android host/APK/simulator, and Swift host/iOS Simulator
builds. Hands-on devices, sudden power loss, revision-bound CI retention,
independent security review, and independently produced interoperability remain
separate P0 gates.

### C3. Message editing

**State:** implemented. **Depends on:** F2. **Decision:**
[ADR-0020](adr/0020-authenticated-message-edits.md).

Model an edit as a new protected event referencing the original message ID;
never mutate history invisibly. Use a monotonic per-author revision plus a
deterministic tie-breaker for rare concurrent same-author device edits. Preserve
an "edited" marker; decide before implementation whether prior versions remain
locally inspectable. The supported UI lets a user edit only content attributed
to them; pairwise cryptography enforces that origin, while current group
cryptography does not yet resist a malicious member.

Offline peers apply edits when they arrive, including edit-before-original
ordering. Group edits retain ordinary encrypt-once sender-key fan-out, but each
recipient verifies a distinct account/device/chain/content-bound origin tag
before advancing or applying the event. Implemented C2 sync carries
immutable edit rows and their deterministic winners between authorized owned
devices.

Acceptance covers reorder, duplication, partitions, malicious cross-author
edits, edits after group removal, old-client fallback, and eventual convergence.
The implementation additionally covers strict raw-send bypass refusal,
restart/`KKR10` restore, shared parity fixtures, dedicated fuzzing, exact RPC/CLI
and UniFFI events/models, and accessible retained-version UI on all three shells.
See [18: Authenticated Message Editing](18-message-editing.md).

### C4. Disappearing messages and view-once media

**State:** implemented. **Decision:** accepted
[ADR-0021](adr/0021-ephemeral-retention.md).

Define separate promises:

- **local expiry:** delete local plaintext/history after a configured deadline;
- **network retention expiry:** let mailboxes/bridges discard undelivered sealed
  envelopes after a coarse absolute deadline;
- **view once:** remove the local decryptable copy after first open.

The current scope text cannot be implemented by putting expiry only in the
encrypted payload: an intermediary cannot read it. The ADR must choose a coarse
relay-visible expiry hint or an unlinkable expiry token, bind the value into the
end-to-end authenticated content, give relays a maximum TTL, quantify the
metadata leak, define clock-skew behavior, and update envelope versioning and
fuzzing. A relay cannot authenticate the sender itself, so it treats the value
only as a bounded deletion hint. Relays may delete early or retain copied
ciphertext; recipients can capture plaintext. The UI must never promise
guaranteed erasure or screenshot prevention.

Acceptance covers offline delivery near expiry, clock skew, relay restart,
expiry-before-original ordering, backup exclusion/tombstones, linked devices,
quoted/replied content, and honest limitation copy.

The implementation uses content-v1 kind 5 plus envelope v2. The exact
deadline and canonical hour-ceiling hint are authenticated together; relays
apply the hint only to deletion, while endpoints enforce the exact deadline.
Sealed lifecycle rows and terminal tombstones prevent restart, duplicate, and
reorder resurrection. KKR6 excludes active ephemeral plaintext/manifests/media
and includes terminal tombstones. Legacy archive reset carries no active
ephemeral content. View-once
consumption commits the tombstone before output and ordinary preview/export/
playback paths refuse the transfer. Pair/group capability gates, anonymous-first-
flight refusal, raw-send bypass tests, strict RPC/CLI, UniFFI, all three shells,
parity fixtures, and dedicated fuzzing are included. C2 sync propagates only
terminal expiry/consumption tombstones; active ephemeral content remains
installation-local and the UI still makes no remote-erasure promise.
See [19: Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md).

### C5. Group polls

**Implemented. Depends on:** F1, F2. **Decision:**
[ADR-0022](adr/0022-convergent-group-polls.md).

Content-v1 kind 6 carries immutable creation, vote, and creator-close events
with stable IDs. The creation-time roster is fixed; votes and identities are
visible to members and explicitly not anonymous. Maximum
`(revision, event id)` selects each open vote head, while closure freezes the
creator-claimed sorted snapshot; tallies are derived locally. Complete current-
roster capability gating, origin exchange, and raw-send refusal protect old
clients. Every recipient authenticates the voter and creator device separately;
legacy membership-authenticated history is not relabelled.

Acceptance covers canonical/arbitrary decoding, partitions, changed,
duplicate, and reordered votes, outsiders, additions/removals, conflicting
closure, convergence, KKR10 restore, C2 owned-device sync, RPC/CLI, UniFFI,
desktop, Android host core,
and iOS host/app contracts. Android debug-APK assembly is automated; hands-on
Android/iOS device evidence remains in the common M5 platform release gate
rather than weakening the implemented protocol contract.

### C6. Admin and role controls

**State:** Implemented. **Depends on:** F1. **Decision:**
[ADR-0023](adr/0023-group-roles-and-owner-authority.md).

Extend the current single creator-managed roster with signed, generation-bound
capabilities such as invite, remove, rename, role grant, and poll moderation.
Specify who may grant/revoke each capability, how creator transfer works, how
conflicting offline authority changes resolve, and how every change triggers the
necessary group-secret/sender-chain rotation.

Start with a minimal `owner` / `admin` / `member` model. Avoid a generic policy
language. Removed or demoted devices must not retain future authority even when
their stale commands arrive later.

Acceptance includes forged/stale capability rejection, concurrent admin actions,
owner transfer, last-owner safeguards, offline members, removed-device exclusion,
and deterministic convergence.

The implemented design keeps exactly one owner as sequencer. Admin invite, ordinary
member removal, rename, and poll moderation are signed generation-bound requests;
role grants, admin removal, and ownership transfer remain owner-only. Canonical
content-v1 kind 7 full states and ordered transfer certificates make authority
auditable after forwarding, restart, and backup. Same-generation forks use the
smallest authenticated state event id and a higher generation cannot advance a
replica through a losing transfer-chain prefix. Every accepted operation rotates
the group secret and sender chains; excluded members never receive the new
secret. Poll moderation is a separately signed owner snapshot under its own
domain and is never mislabeled as creator closure.

`KKR6` added sealed authority records and consumed request ids; current `KKR10`
restores them, while legacy new-identity reset omits groups. Acceptance is
pinned in crypto/protocol, node concurrency/transfer/removal flows, KKR10
restore, RPC/CLI, UniFFI,
desktop, Android host core/APK assembly, and iOS host/app coverage. Hands-on
Android and iOS device execution remains deferred without weakening
implementation parity.

### C7. Live voice and video calls

**Depends on:** F4 and accepted ADR-0013.

**State:** Beta audio implemented. ADR-0013 is accepted. The pinned
localhost/loss spike selected one reliable ordered `/komms/call/1` substream on
a fresh direct QUIC connection; the implemented libp2p QUIC transport disables
datagrams. Relay-only and TCP paths do not qualify as realtime. Distinct-NAT,
DCUtR, mobile network, CPU, battery, native audio-route, background, and lock
measurements remain release gates rather than unmeasured design claims.

The implementation delivers ratchet-carried offer/answer/decline/busy/cancel/
hangup signaling, linked-device first-answer arbitration, call-specific media
keys derived inside the core, replay protection, key rotation, bounded Opus
audio, jitter buffering, native voice processing, and interruption teardown.
Controls and media are transient and absent from history, search, backup, and C2
sync. Ratchet secrets never reach the UI layer. Video begins only after the
physical audio qualification matrix passes.

The call button is enabled only for a fresh F4 `realtime` capability backed by
an observed direct QUIC route. Mailbox, sneakernet, LoRa, TCP fallback, and
relay-only paths show a precise unavailable reason. No project-operated
STUN/TURN, SFU, or signaling service is introduced.

Automated acceptance now covers authenticated caller identity, declined/busy/
racing calls, direct LAN/localhost QUIC, bounded media, tamper/replay failure,
key erasure transitions, exact hangup, linked-device arbitration, every front
door/shell host layer, and proof that call attempts emit no mesh frames. Real
distinct-NAT/DCUtR, sustained loss/jitter, network handoff, CPU/battery,
Bluetooth/headset, and physical background/lock evidence remain release gates.
See [23: Live Audio Calls](23-live-audio-calls.md).

### C8. Optional hybrid reachability and native wake

**Depends on:** F4, capability-scoped DHT discovery, durable mailbox delivery,
and ADR-0017 through ADR-0019. ADR-0018 is accepted and implemented for Beta;
the complete convenience plane remains major M6 adoption work.

Deliver this as a feature-gated module over the unchanged core:

1. derive and separately seal the post-handshake hybrid service exporter;
2. retain manual, DHT, LAN, and rendezvous hints by source and expiry instead of
   overwriting one source with another;
3. add fixed-size direct HTTPS plus Tor or OHTTP rendezvous clients and a bounded,
   persistence-disabled rendezvous service;
4. expose explicit Sovereign, Private, and Standard mode selection and precise
   metadata disclosure through RPC, UniFFI, desktop, Android, and iOS;
5. issue, rotate, revoke, and distribute per-contact opaque wake capabilities;
6. add APNs directly on iOS and FCM only to a Google Play Android flavor while
   preserving a Google-free artifact;
7. trigger only after direct or mailbox next-hop acceptance, coalesce per native
   destination, and run one bounded generic collection cycle on receipt; and
8. publish service hardening, deployment, key-rotation, no-log, incident, and
   independent-operation runbooks before a production default is offered.

Items 1–8 are implemented for the local Beta profile. The
rendezvous and wake clients support pinned TLS 1.3 directly or through an
explicit loopback Tor SOCKS5 endpoint. The dedicated reference and native-wake
service binaries, images, hardened deployment profiles, signed/versioned
provider directory, last-valid/fork handling, canonical mode policy, familiar
status language, bounded generic collection, next-hop-only wake scheduling,
durable revocation retry, strict RPC/UniFFI front doors, direct APNs lifecycle,
Play-only FCM callbacks, and a separately inspected Google-free Android
artifact are present. The selected Private client path is loopback Tor. A
separate fixed-mapping RFC 9458 relay artifact now provides bounded,
header-stripping relay-side deployment, but no client/gateway integration or
non-collusion evidence. No
production directory, default operator, deployed service, production APNs/FCM
credential, qualified Tor/OHTTP ingress, or non-collusion evidence is included.
See [Operating modes and provider configuration](36-operating-modes-and-provider-directory.md)
the [native-wake runbook](37-native-wake-operations.md), and the
[mobile qualification matrix](38-native-wake-mobile-qualification.md).

Rendezvous is post-pairing only and never replaces kult-address/QR first contact.
Native push carries no sender, recipient Komms identity, conversation, message,
media, or unread-count data. Neither service response changes queued/sent/
delivered state. F4 probes fresh returned hints through ordinary transports and
never trusts the service to label a route realtime or bulk.

Acceptance includes:

- cross-platform mode changes that neither rotate identity nor lose queued work;
- epoch, provider, direction, nonce, generation, clock-skew, replay, rollback,
  malformed-record, dummy-response, and multi-provider rendezvous tests;
- proof that two providers receive different slots for the same pair/epoch and
  that delivery/mailbox tokens are never reused;
- APNs low-priority/throttling, Background App Refresh off, force-quit, token
  rotation, gateway restart, and provider-outage device tests;
- FCM Doze, visible high-priority notification, deprioritization, notification
  denial, WorkManager, token rotation, and Google-free-build tests;
- replay/flood/coalescing/revocation/shared-NAT/Tor abuse tests with hard memory,
  body, concurrency, bandwidth, and per-capability bounds;
- inspection proving native tokens, slots, capabilities, and full addresses do
  not enter proxy/CDN/WAF/application logs, traces, analytics, or crash output;
- service seizure tests showing stored rendezvous bytes disclose no route and
  wake state discloses no Komms identity or message key; and
- a full blackhole matrix in which every optional endpoint fails while direct,
  signed DHT, mailbox, LAN, mesh, and sneakernet delivery remains functional.

An external review of the three ADRs and implementation is a release gate before
Standard mode can be recommended to non-test users.

## 6. Delivery sequence

The order below maximizes usable increments while keeping protocol dependencies
honest. Parallel work is safe only where rows do not share a foundation. These
rows describe repository implementation, not stable release evidence. The
[stabilization program](29-stabilization-program.md) takes priority and defines
the gates that must close before broader feature expansion.

| Wave | Progress | Outcome and features |
|---|---|---|
| **0: Shared foundations** | Implemented + automated evidence | F1–F5 have implementation paths; ADR-0015 remains formally Proposed despite the implemented attachment pipeline. |
| **Parallel: mobile reachability** | Partial Beta | ADR-0017 modes, ADR-0018 rendezvous, and ADR-0019 gateway/core are implemented behind reversible policy; native Android/iOS integration, deployment, external review, and physical qualification remain. |
| **1: Local-first product polish** | Implemented + automated evidence | B5, B7–B15, and B18 have Beta paths; optional signed self-display suggestions remain a separate format-gated extension to B5. Localization and external accessibility evidence remain open. |
| **2: Typed content and asynchronous media** | Implemented + automated evidence | F2/F3, B2, B16, B17, and C1 have core and shell paths; hands-on device evidence remains an M5 release gate. |
| **3: Replicated conversation features** | Implemented + automated evidence | C3, C4, C5, and C6 have paths through the documented surfaces; field and independent evidence remain separate. |
| **4: Multi-device** | Implemented + automated evidence | ADR-0024 and C2 have implementation paths, including cross-device hardening of Wave 3; physical-device qualification remains open. |
| **5: Real-time media** | Implemented Beta path | ADR-0013 and C7 audio are implemented through the documented surfaces, restricted to observed direct QUIC; real-network/device qualification gates stable enablement and video. |

Scheduled messages (B8) completed as the intended isolated core-plus-shell
delivery. Its durable gate remains in the shared queue/storage schema rather
than F5 or UI-only state and is not coupled to the content codec.

## 7. ADR and format queue

Do not combine these into one oversized design decision.

| Order | Decision | Unlocks |
|---|---|---|
| 1 (accepted) | ADR-0014: versioned typed message content and compatibility | Audio, files, edits, polls, structured mentions. |
| 2 (proposed; implemented) | ADR-0015: encrypted attachment/chunk transfer and carrier policy | Audio, files, media editing; formal ADR acceptance remains. |
| 3 (accepted) | ADR-0016: canonical group-mention content | B17 stable encrypted targets, range semantics, compatibility, and local notification. |
| 4 (accepted; implemented Beta) | ADR-0017: optional hybrid modes and threat boundary | C8 mode guarantees, signed replaceable provider configuration, and honest product claims; deployment and field qualification remain. |
| 5 (accepted; implemented Beta) | ADR-0018: rotating pairwise rendezvous | C8 private post-pairing route refresh; qualified network deployment and Private-ingress evidence remain. |
| 6 (proposed) | ADR-0019: capability-gated native wake | C8 APNs/FCM acceleration and bounded collection. |
| 7 (accepted) | ADR-0021: expiry/retention metadata and deletion semantics | C4 disappearing and view-once content. |
| 8 (accepted) | ADR-0020: immutable edit events, authorization, ordering, and retained versions | Message editing and multi-device convergence. |
| 9 (accepted) | ADR-0022: fixed-electorate visible-vote polls and creator snapshot closure | Convergent encrypted group polls. |
| 10 (accepted) | ADR-0023: group roles/capabilities and authority transfer | Admin controls and moderated polls. |
| 11 (partially superseded) | ADR-0024: multi-device identity, independent delivery/ratchets/sender chains and sync | Linked-device data plane; its copied-root authority survives only as an explicit legacy migration input. |
| 12 (accepted) | ADR-0026: offline root, strict-majority device authority, recovery epochs, visible conflicts and root-free backup | Revocable linked-device authority and honest Alpha migration/reset. |
| 13 (accepted) | ADR-0013: measured direct-QUIC call signaling/media contract | C7 Beta audio; physical qualification gates video and stable enablement. |
| 14 (accepted) | ADR-0029: recipient-authenticated group origins | Individual sender/device authorship without abandoning one shared group ciphertext or recipient deniability. |
| 15 (accepted) | ADR-0030: bounded first-contact admission and consent | Signed pre-KEM admission policy, fixed provisional requests, explicit Accept/Delete/Block and group-invite consent. |
| As needed | Signed optional self-display name in bundle records | Non-global username suggestion. |
| Before next PQ suite | Downgrade-safe crypto agility | Future post-quantum upgrades. |

Each wire/storage change must include versioning, old-client behavior, migration,
fuzz corpus updates, bounded decoding, backup impact, and copied-database leakage
review.

## 8. Cross-feature release gates

No feature is **Stable** until all applicable gates pass. “Implemented” or
“automated evidence” may be used earlier according to
[29: Stabilization Program §2](29-stabilization-program.md#2-evidence-vocabulary):

1. **Security:** plaintext and secrets never leave their intended boundary;
   intermediaries learn no unapproved metadata; parsers are bounded and fuzzed.
2. **Carrier honesty:** UI and scheduler agree about mesh, mailbox, sneakernet,
   LAN, and internet behavior; unsupported traffic is held or refused before it
   consumes scarce airtime.
3. **Offline behavior:** restart, partition, reorder, duplication, and delayed
   delivery have explicit tests.
4. **Compatibility:** old stored history, old backups, and at least the previous
   wire/content version have a documented path.
5. **Backups:** inclusion/exclusion is intentional and restore tests cover it.
6. **All surfaces:** RPC/CLI where applicable, UniFFI, desktop, Android, and iOS
   either support the feature or show an honest unsupported state.
7. **Accessibility and localization:** semantic labels, keyboard navigation,
   scalable text, contrast, reduced motion, bidirectional text, and localizable
   strings have repository evidence; field qualification and a cross-shell
   localization system are reported separately rather than inferred.
8. **Resource bounds:** storage, memory, CPU, battery, bandwidth, and attachment
   quotas fail safely and visibly.
9. **Documentation:** user promise, limitations, threat-model effect, and manual
   test instructions are current.
10. **Release controls:** format, clippy with denied warnings, tests, `no_std`,
    fuzz smoke, generated bindings, shell tests/builds, `cargo-deny`,
    dependency-integrity metadata, and evidence-tool regression tests are green
    before publication. The exact tag has an SBOM, provenance, checksums,
    signing and qualification records, and measured reproduction. Platform
    behavior has named device/simulator evidence at its honest level. Hosted CI
    is a later authorized repetition, not the development loop; production
    signing, empty-draft creation, completed-asset upload, and publication
    remain separate protected actions.

## 9. Implemented foundation inventory

This is historical implementation inventory, not the current priority order.
Current work follows the [stabilization program](29-stabilization-program.md).
Keep each numbered item, and each shell named within an item, in a separate
reviewable PR when maintenance changes it:

1. completed: expose group operations through RPC, CLI, and UniFFI, with an
   end-to-end bindings test;
2. completed: add group list/history/create/send UI to desktop, Android, and iOS;
3. completed: build the per-peer carrier capability API and pin mesh-only
   decisions in node, scheduler, and FFI tests;
4. completed through B5 private contact rename, B10 folders, B11 conversation pins, B12 appearance,
   B13 custom icons, B14 screen security, B15 incognito keyboard, and B18 labels: add the
   sealed local metadata foundation, note-to-self, private single-membership
   conversation folders, exact typed conversation pins, and private
   contact/conversation labels plus a sealed local theme choice; message pins and
   message labels remain deferred; B14 adds the separate always-on pre-unlock
   screen-security contract; B15 adds the separate always-on pre-unlock input
   privacy contract and exhaustive native field controls; scheduled delivery
   completed separately in the core queue/storage path;
5. completed: ship typed content, attachments, audio, image editing, mentions,
   and bounded safe text formatting through every front door and shell;
   ADR-0015's formal status remains Proposed.

The C1 non-image file presentation slice is implemented over the unchanged F3/F4
pipeline: safe generic rows, explicit open/export affordances, stronger
filename/media-type mismatch handling, accessibility/lifecycle behavior, and
malicious-file/large-file/resume qualification add no auto-open, remote scanning,
preview, or mesh behavior. C3 immutable message editing is now implemented
across protocol, node, storage, RPC/CLI, UniFFI, desktop, Android, and iOS with
pairwise and recipient-authenticated group authorship, retained versions, and
deterministic offline convergence. C4
disappearing text and view-once attachments are likewise implemented end to end
with exact local deadlines, coarse authenticated relay deletion, sealed
tombstones, and KKR6 exclusion. C5 encrypted group polls are now implemented with
visible votes, fixed electorates, deterministic convergence, recipient-
authenticated voter/creator origins, and creator snapshot closure.
C6 signed owner/admin/member roles, ownership transfer,
mandatory re-keying, and poll moderation are now implemented through every shell.
C7 live audio calls are now implemented through direct QUIC, transient ratcheted
signaling, authenticated media, RPC/CLI, UniFFI, and all three shells. Real-NAT,
mobile handoff, battery, route, background/lock, and physical-device evidence
remain release qualification; video remains gated on that audio evidence.
Optional signed self-display suggestions remain deferred behind their separate
bundle-format ADR and compatibility work.
Optional hybrid services remain a separate design program with their stated ADR
gates.
