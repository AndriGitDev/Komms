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

| Status | Meaning |
|---|---|
| **Shipped** | Present through the relevant core and application surfaces, with tests. |
| **Partial** | A usable foundation exists, but some promised behavior or application surface is missing. |
| **Planned** | In scope but not implemented. |
| **Design-only** | A proposed ADR or design track exists, but product implementation is not authorized or shipped. |
| **Assurance** | Shipped security behavior that remains a permanent release gate rather than a feature backlog item. |

## 2. Current baseline

Komms has a strong transport and security foundation plus shared versioned
content, attachment, and carrier-capability front doors. New replicated content
types such as edits, polls, expiry, and call signaling still require their own
accepted designs before individual shells implement UI.

| Feature from scope | Current status | Main gap |
|---|---|---|
| Text messages | Shipped | Product polish and accessibility only. |
| Recorded audio messages | Shipped | Keep the canonical profile, lifecycle cleanup, F3/F4 behavior, and cross-platform acceptance gates stable. |
| End-to-end encryption | Assurance | Continuous audit, KAT, fuzz, and regression gates. |
| Post-quantum handshake | Assurance | Crypto-agility and downgrade-safe future upgrades. |
| Contact names / usernames | Partial | Local petnames exist; rename UX and optional signed self-display name do not. |
| Secure backups | Shipped | Future feature data must be added without leaking or silently omitting it. |
| Note to self | Shipped (text) | Attachments follow F3 shell integration. |
| Queued messages | Shipped | Already part of the honest delivery engine. |
| Scheduled messages | Shipped | Preserve the sealed absolute-UTC gate, edit/cancel-before-activation semantics, and distinct cross-shell lifecycle. |
| Text formatting | Planned | Safe common subset and consistent rendering. |
| Folders | Shipped | Preserve single-folder membership, All/Unfiled views, deterministic order, stale cleanup, label composition, and zero-network behavior. |
| Pins | Shipped (conversation) | Preserve exact typed targets, complete durable reorder, stale reactivation/cleanup, folder → label → pin composition, and zero-network behavior; message pins remain separate. |
| Dark mode | Shipped | Sealed system/light/dark preference, shared semantic roles, and native live switching in every shell. |
| Custom icons | Shipped | Preserve exact typed targets, strict local image canonicalization, sealed quotas, initials fallback, `KKR4` portability, and zero-network behavior. |
| Screen security | Shipped | Always-on shared policy, native shell protections, rapid desktop lock, and explicit platform limitations. |
| Incognito keyboard | Planned | Android control; best available behavior and honest limits elsewhere. |
| Local still-image editing | Shipped | Keep shared deterministic semantics, cleanup, exact-review, and metadata-removal gates stable; video remains out of scope. |
| Mentions | Shipped | ADR-0016 canonical peer targets, current-roster composers, conservative group capability gating, and local navigation/notification. |
| Labels | Shipped (contact/conversation) | Private pairwise, group, and note-to-self labels with fixed limits, stale cleanup, and accessible any/all filtering; message labels remain deferred. |
| File sharing | Partial | Bounded cross-shell F3 delivery and generic pre-send F4 confirmation are shipped; richer non-image media presentation remains. |
| Linked devices | Planned | Proximate linking, device keys, sync, revocation, and recovery. |
| Message editing | Planned | Authenticated revisions and deterministic offline reconciliation. |
| Disappearing/view-once messages | Planned | Expiry semantics, relay metadata design, deletion limits. |
| Group polls | Planned | Typed group content and convergent vote updates. |
| Admin/role controls | Planned | Cryptographic group capabilities and authority transitions. |
| Live voice/video calls | Design-only | ADR-0013 remains Proposed; measured media transport and carrier gating precede implementation. |
| Optional hybrid reachability/wake | Design-only | ADR-0017 through ADR-0019 remain Proposed; acceptance precedes mode boundaries, rotating rendezvous, and best-effort native wake. |

## 3. Shared foundations

These are prerequisites, not new user-facing scope.

### F1. Finish the group front door

The sender-key group core and its shared `kultd` RPC, CLI, and `kult-ffi` front
doors are shipped. Desktop, Android, and iOS group UX are shipped, completing
the shared group front door before polls, mentions, or roles.

Deliver:

- group records, messages, per-member delivery state, and group events through
  RPC and UniFFI;
- create, send, add, remove, leave, list, and history in CLI/desktop/Android/iOS;
- cross-surface tests proving that all shells interpret the same group state;
- truthful partial-delivery UI per member.

### F2. Versioned content model

**State:** shipped. [ADR-0014](adr/0014-versioned-message-content.md) is accepted
and implemented: the compatibility frame, permanent legacy-text path,
encrypted capability negotiation, scoped stable content ids, bounded
unknown-content behavior, sealed capability state, and render-safe RPC/UniFFI
outcomes are shared across pairwise and sender-key group messages.

The shipped codec keeps legacy raw text readable and carries bounded typed
`Text`, `Attachment`, and `Mention` content under their accepted feature
contracts. Future candidates include `Edit`, `Poll`, and `PollVote`; each exact
shape still requires its own accepted design. Call signaling remains
the separate `CallSignal` envelope proposed by ADR-0013. Formatting remains text
plus local rendering metadata and does not need a distinct wire type.

The ADR must define:

- version negotiation and unknown-content behavior;
- strict size/depth/count limits for every decoder;
- compatibility with existing pairwise and group history;
- content IDs and references without exposing content type to intermediaries;
- padding behavior so a type does not defeat existing size-hiding promises;
- fuzz targets and migration behavior.

### F3. Attachment and media pipeline

**State:** shipped through core, shared RPC/CLI/UniFFI front doors, and the
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

**State:** shipped through node, RPC/CLI, and UniFFI. The node probes stored
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
change immediately. The ADR-0013 spike decides whether any circuit-relayed path
meets the latency and capacity requirements for `realtime`; the capability API
must not assume that before measurements exist.

### F5. Local metadata store

**State:** sealed store foundation shipped. `kult-store` provides versioned,
bounded records and stable replacement keys for conversation types, folders,
single-folder membership, pins, labels and multi-label membership, drafts, UI
preferences, and custom icons. The table exposes only row count and approximate
sealed sizes in a copied database; `KKR4` backs up every user-authored record
and note-to-self history while `KKR1`, `KKR2`, and `KKR3` remain restorable.
Feature behavior and shell UX remain separate B7/B13 slices. B10 folders,
B11 conversation pins, B12 appearance, and B18 labels use the shipped record
shapes and `KKR4` contract unchanged.

Add sealed local-only records for conversation type, folders, pins, labels,
drafts, UI preferences, and custom icons. Keep local organization out of network
payloads. Define which records belong in encrypted backups and version the backup
format when the first new record ships. Scheduled delivery is separate core queue
state covered by B8, not a UI-metadata timer.

Hybrid mode/provider preferences may use the F5 preference record, but
rendezvous exporters, source-scoped leases, generations, wake capabilities,
revocations, and pending collection work are sealed core service state. They
must not be represented as folders/drafts/preferences or B8 scheduled messages.

## 4. Build features

### B1. Text messages

**State:** shipped. Treat as the compatibility baseline for every content-model
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

**State:** shipped across desktop, Android, and iOS.

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
Desktop continues F3 transfers while open/minimized, Android uses the shipped
data-sync foreground service, and iOS resumes durable verified progress when the
OS returns the app to the foreground.

Acceptance injects a metadata-bearing native WAV and proves identical canonical
bytes, duration, pairwise delivery, sender-key group delivery, and protected
playback through Rust FFI plus every platform wrapper. Malformed, spoofed,
truncated, noncanonical, oversized, and overwrite cases fail closed. A dedicated
ADR-0015 regression proves audio on a mesh-only route emits zero airtime frames.

### B3. End-to-end encryption

**State:** shipped; permanent assurance track.

Every new content variant must travel inside the existing pairwise ratchet or
sender-key group body. New control data must not create a weaker side channel.
Maintain KATs, property tests, parser fuzzing, secret zeroization, no-panic rules,
dependency review, and the external audit gate. No shell may expose an
"unencrypted" fallback.

Acceptance is unchanged security behavior under every new feature's end-to-end
tests, plus negative tests proving intermediaries see only permitted metadata.

### B4. Post-quantum upgrades

**State:** hybrid X25519 + ML-KEM-768 handshake shipped; permanent assurance
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

**State:** local petnames shipped; broader UX partial.

Deliver contact rename in all shells first. Petnames remain authoritative and
never leave the device. If an optional self-selected display name is desired,
add it as a signed, non-unique suggestion in the prekey bundle/DHT record; a
recipient may accept it initially but their local petname always overrides it.
This is not a global username registry and must not imply uniqueness.

A bundle-format change requires an ADR and compatibility path. Acceptance covers
Unicode normalization, spoofing/confusable warnings, duplicate names, and the
fact that changing a remote suggestion never silently renames a local petname.

### B6. Secure backups

**State:** KKR4 shipped; permanent compatibility track.

For every feature in this plan, decide explicitly whether its state is identity
critical, conversation history, local preference, secret ephemeral state, or
re-creatable cache. Back up the first two; normally back up local organization;
never back up live ratchet/sender chains or temporary decrypted media.

Acceptance:

- backup and restore preserve all promised feature state;
- older KKR1/KKR2/KKR3 files remain restorable;
- a restored node rotates/re-handshakes where required;
- omitted caches are rebuilt without data loss or false delivery state.

### B7. Note to self

**Depends on:** F5.

**State:** text note-to-self shipped through `kult-store`, `kult-node`, RPC/CLI,
UniFFI, desktop, Android, and iOS. Every surface uses the reserved
`note_to_self` identity. `KKR4` includes the sealed history; exact KKR1–KKR3
restore compatibility remains. Attachments follow F3 shell integration.

Implement a first-class local conversation, not a fake contact or a message sent
through the node's own ratchet. Store entries sealed in `kult-store`; never queue,
publish, generate receipts, or touch a transport. Support text first and
attachments after F3.

Acceptance proves zero envelopes are emitted, entries survive restart and
backup/restore, and all shells use the same reserved conversation identity.

### B8. Scheduled and queued messages

**State:** shipped end to end. `kult-store` seals pairwise/group scheduled text
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

Use a deliberately small CommonMark-style subset: emphasis, strong, inline code,
code blocks, quotes, and lists. Store/transmit source text and render locally.
Disable raw HTML, remote images, automatic network fetches, scriptable links, and
unsafe URL schemes. A recipient that lacks formatting support sees readable
plain source.

Acceptance uses a shared conformance corpus across desktop, Android, and iOS,
including malicious input, huge nesting, bidirectional text, and copy-as-plain-
text behavior.

### B10. Folders

**Depends on:** F5.

**State:** shipped end to end across `kult-store`, `kult-node`, RPC/CLI,
UniFFI, desktop, Android, and iOS.

Folders are local views over conversation IDs. Support create, rename, reorder,
move, delete-without-deleting-conversations, and an unfiled/default view. Do not
sync folders to contacts or leak them onto the wire.

Acceptance covers restart, backup/restore, deleted contacts/groups, and the same
conversation appearing in at most one folder unless multi-folder behavior is
explicitly chosen before implementation.

The shipped contract chooses single-folder membership. Exact names retain their
UTF-8 bytes and may duplicate; cryptorandom 16-byte IDs and persisted manual
order disambiguate them. All and Unfiled are virtual views. Complete-set reorder,
move/unfile, delete cascade, and stale cleanup are atomic, and folder selection
composes before the independent B18 any/all label filter. Shared limits are 128
folders, 8,192 assignments, and 256 UTF-8 bytes per name. `KKR4` preserves exact
IDs, names, order, membership, and stale behavior. Every mutation creates zero
envelope, queue, receipt, capability, or transport work.

### B11. Pins

**Depends on:** F5.

**State:** conversation pins shipped end to end across `kult-store`, `kult-node`,
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
becomes available. `KKR4` preserves exact target, order, and stale behavior.
Every surface proves that pin work creates no envelope, queue, receipt,
notification, capability, crypto, or transport work.

### B12. Dark mode

**State:** shipped end to end. The canonical `system`, `light`, and `dark`
choice is stored in the existing independently sealed F5 UI-preference record at
`appearance.theme`. Missing or unknown legacy values safely render as System;
idempotent writes emit only the endpoint-local `ThemeChanged` event and create
no envelope, queue, capability, notification, cryptographic, or transport work.
`kult-node`, strict RPC operations `theme` / `theme_set`, CLI commands `theme` /
`theme-set`, UniFFI, and every platform wrapper expose the same contract.

Every shell applies a non-sensitive device-local cache before unlock to prevent
a theme flash, then reconciles after unlock: a canonical sealed value wins
(including after `KKR4` restore), while a missing value is initialized from the
cached/default System choice. Desktop resolves shared semantic CSS roles and
live `prefers-color-scheme` / `prefers-contrast` / `prefers-reduced-motion`;
Android applies AppCompat DayNight before the first Activity and uses matching
light/night semantic resources; iOS applies SwiftUI's preferred color scheme and
adaptive platform colors. The shared B12 fixture pins the exact vocabulary,
semantic roles, WCAG 2 contrast thresholds, and reference-palette ratios.

Acceptance covers first-run System, strict input, idempotency, restart, `KKR4`
restore, local-only events, zero delivery work, live native switching, high
contrast, reduced motion, and light/dark major-surface rendering. Security and
delivery states retain text, icons, or accessible labels and never rely on color.

### B13. Custom icons

**Depends on:** F5.

**Shipped.** Contacts, sender-key groups, private folders, and note-to-self each
have one exact typed private icon identity. No record renders deterministic
generated initials. Users can instead choose one of eight bundled glyphs
(`person`, `group`, `folder`, `note`, `star`, `heart`, `shield`, `compass`) or a
content-verified local JPEG/PNG. The shared node normalizes EXIF orientation,
rejects animated PNG and oversized/decompression-heavy inputs, applies a
centered-square or explicit oriented-pixel square crop, resizes to 256×256, and
emits a metadata-free non-interlaced RGBA8 PNG containing only IHDR/IDAT/IEND.

The existing F5 record is now enforced as one icon per exact target, at most
512 KiB each, 1,024 records, and 64 MiB aggregate encoded bytes. Reads verify the
canonical profile again; a missing, corrupt, or non-canonical sealed image falls
back without rewriting or exposing it. Folder deletion removes its icon; other
unavailable exact identities remain inaccessible and can safely reactivate only
if that same technical identity returns. `KKR4` preserves icons as ordinary
sealed user-authored local metadata.

Node, strict RPC/CLI, UniFFI, desktop, Android, and iOS expose the same target,
set-image, set-glyph, read, clear, usage, and local-change contract. Desktop,
Android SAF, and iOS Files provide native selection and accessible management;
all conversation/folder lists render the sealed icon or initials. No avatar URL,
envelope, capability, notification, DHT record, peer synchronization, queue item,
or transport work exists. The shared B13 fixture and layer acceptance tests prove
metadata removal, input/output bounds, quota enforcement including the low-level
store boundary, all four target types, restart, `KKR4`, idempotency, corrupt and
missing fallback, and zero delivery work.

### B14. Screen security

**Shipped.** Platform controls have honest, always-on guarantees:

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

On Android, request the no-personalized-learning/incognito input flags on every
sensitive field. On iOS and desktop, disable autocorrection/prediction where APIs
permit, but document that third-party keyboards or the OS may ignore hints. Never
put secrets such as mnemonics in normal predictive fields.

Acceptance checks all message, search, passphrase, mnemonic, and naming fields;
automated UI assertions cover the flags where platforms expose them.

### B16. Local media editing

**State:** shipped for still JPEG/PNG across desktop, Android, and iOS.

**Depends on:** F3.

One path-based Rust/UniFFI helper performs content-verified bounded decoding
(32 MiB encoded, 4096 per edge, 12 megapixels), EXIF-orientation normalization,
exact integer crop then quarter-turn rotation, ordered user-positioned blur or
pixelation, and deterministic metadata-free RGBA PNG encoding. Output is
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

**State:** shipped across protocol, node, storage/backup, RPC/CLI, UniFFI,
desktop, Android, and iOS. **Governed by:**
[ADR-0016](adr/0016-group-mention-content.md). **Depends on:** F1, F2.

Compose mentions in group message text using an explicit member picker rather
than ambiguous free-form names. Encode a stable peer reference alongside fallback
display text so every client can highlight the intended member despite different
local petnames. Mention notifications remain local and opportunistic: there is no
server push guarantee.

The shipped kind `0x0003` uses exact authenticated fallback UTF-8 and canonical
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

**State:** shipped through `kult-store`, `kult-node`, RPC/CLI, UniFFI, desktop,
Android, and iOS. PR #43/B17 was only the administrative branch base; labels have
no semantic dependency on Mention content. B18 stays inside the accepted F5
`LabelRecord` and `LabelAssignment` shapes and `KKR4`, so it requires no new
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
queue work, ordering, or history. `KKR4` preserves exact IDs, names, colors,
ordering, membership, and stale behavior while KKR1–KKR3 restore unchanged.

All shells provide accessible managers, non-color badges, assignment actions,
duplicate disambiguation, deletion review, stale states, and any/all filters.
Android and iOS retain selected filters only in protected device-local state.
Label data never enters logs, crash reports, OS metadata, envelopes, DHT, group
state, capability advertisements, sender keys, ratchets, transport hints,
analytics, or remote notifications; label operations create zero network work.
There is no server, remote, shared, or linked-device label synchronization.

Acceptance covers exact Unicode and whitespace boundaries, collision retry,
unknown colors, duplicate names, limit exhaustion, atomic failure/restart,
arbitrary operation sequences, stale references, delete/recreate isolation,
KKR1–KKR4 interoperability, copied-database scans, wrapper fixture parity,
cross-shell accessibility and protected restoration, and zero-network-work
matrices. Message labels remain deferred pending demonstrated UI value. Folders,
pins, sorting, roles, shared tags, and generic organization frameworks remain
outside B18.

## 5. Build-with-constraints features

### C1. File sharing

**State:** partial. Bounded attachments and the generic pre-send F4 explanation,
fresh verdict recheck, changed-verdict reconfirmation, and explicit send/discard
flow are shipped across desktop, Android, and iOS. Richer non-image media polish
remains.

**Depends on:** F2, F3, F4. **Governed by:** ADR-0015.

The shipped tiers are:

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

**ADR required; major M6 work.**

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

Acceptance requires three-device partition/rejoin tests, concurrent sends and
edits, revoked-device exclusion, group re-key after revocation, no cloud service,
and a full QR/LAN linking ceremony on each platform.

### C3. Message editing

**Depends on:** F2. **ADR required.**

Model an edit as a new authenticated event referencing the original message ID;
never mutate history invisibly. Use a monotonic per-author revision plus a
deterministic tie-breaker for rare concurrent same-author device edits. Preserve
an "edited" marker; decide before implementation whether prior versions remain
locally inspectable. A user may edit only content they authored.

Offline peers apply edits when they arrive, including edit-before-original
ordering. Group edits use ordinary sender-key fan-out and the same authorship
checks. Linked-device convergence must be designed together with C2.

Acceptance covers reorder, duplication, partitions, malicious cross-author
edits, edits after group removal, old-client fallback, and eventual convergence.

### C4. Disappearing messages and view-once media

**ADR required.**

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

### C5. Group polls

**Depends on:** F1, F2. **ADR required if poll events become a new replicated
wire type.**

Define a poll creation event with stable poll/option IDs and close policy, plus
idempotent vote events authenticated as the voting member. Use last valid vote
per member with a deterministic event-order rule; tally locally. Decide whether
votes are visible to all members or only the creator before implementation;
do not claim anonymous voting without a separate cryptographic design.

Acceptance covers partitions, changed votes, duplicate/reordered votes, roster
changes, removed members, poll closure, old clients, and convergent tallies.

### C6. Admin and role controls

**Depends on:** F1. **ADR required.**

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

### C7. Live voice and video calls

**Depends on:** F4 and accepted ADR-0013.

Run the ADR-0013 spike before product implementation:

1. prototype `/komms/call/1` audio over a dedicated libp2p path;
2. measure NAT success, relay-to-direct upgrade, latency, loss, jitter, CPU,
   battery, and dependency cost on desktop plus both mobile platforms;
3. compare the raw-QUIC/libp2p approach with the constrained WebRTC fallback;
4. accept ADR-0013 with the measured media-transport choice.

Then deliver ratchet-carried call offer/answer/cancel/busy/hangup signaling,
call-specific media keys derived inside the core, replay protection, key
rotation, Opus audio, echo cancellation, jitter buffering, and interruption
handling. Add video only after audio acceptance passes. Never export ratchet
secrets to the UI layer.

The call button is enabled only for a fresh F4 `realtime` capability. Mailbox,
sneakernet, and LoRa paths show a precise unavailable reason. The spike decides
whether a circuit-relayed libp2p path can satisfy that capability; until ADR-0013
is accepted, product code and copy must not assume that relay-only reachability
qualifies. No project-operated STUN/TURN, SFU, or signaling service is introduced.

Acceptance includes authenticated caller identity, declined/busy/racing calls,
NAT and LAN matrices, path loss during a call, Bluetooth/headset transitions,
background/lock behavior, network handoff, call-key erasure, and proof that call
attempts emit no mesh frames.

### C8. Optional hybrid reachability and native wake

**Depends on:** F4, existing signed DHT discovery, existing mailbox delivery,
and accepted ADR-0017, ADR-0018, and ADR-0019. **Major M6 adoption work.**

Deliver this as a feature-gated module over the unchanged core:

1. derive and separately seal the post-handshake hybrid service exporter;
2. retain manual, DHT, LAN, and rendezvous hints by source and expiry instead of
   overwriting one source with another;
3. add fixed-size direct HTTPS plus Tor/OHTTP rendezvous clients and a bounded,
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
honest. Parallel work is safe only where rows do not share a foundation.

| Wave | Progress | Outcome and features |
|---|---|---|
| **0: Shared foundations** | Complete | F1–F5 are implemented; ADR-0015 remains formally Proposed despite the shipped attachment pipeline. |
| **Parallel: mobile reachability** | Design-only | Accept ADR-0017–0019, then implement C8 behind reversible feature gates. |
| **1: Local-first product polish** | In progress | B7, B8, B10–B14, and B18 are shipped; B5, B9, and B15 remain. |
| **2: Typed content and asynchronous media** | Substantially complete | F2/F3, B2, B16, and B17 are shipped; C1 is usable across all shells with richer media polish remaining. |
| **3: Replicated conversation features** | Planned | C3, C4, C5, and C6. |
| **4: Multi-device** | Planned | C2, followed by cross-device hardening of Wave 3. |
| **5: Real-time media** | Design-only | ADR-0013 spike and C7, restricted to qualified internet/LAN paths. |

Scheduled messages (B8) completed as the intended isolated core-plus-shell
delivery. Its durable gate remains in the shared queue/storage schema rather
than F5 or UI-only state and is not coupled to the content codec.

## 7. ADR and format queue

Do not combine these into one oversized design decision.

| Order | Decision | Unlocks |
|---|---|---|
| 1 (done) | ADR-0014: versioned typed message content and compatibility | Audio, files, edits, polls, structured mentions. |
| 2 (proposed; implemented) | ADR-0015: encrypted attachment/chunk transfer and carrier policy | Audio, files, media editing; formal ADR acceptance remains. |
| 3 (done) | ADR-0016: canonical group-mention content | B17 stable encrypted targets, range semantics, compatibility, and local notification. |
| 4 (proposed) | ADR-0017: optional hybrid modes and threat boundary | C8 mode guarantees and honest product claims. |
| 5 (proposed) | ADR-0018: rotating pairwise rendezvous | C8 private post-pairing route refresh. |
| 6 (proposed) | ADR-0019: capability-gated native wake | C8 APNs/FCM acceleration and bounded collection. |
| 7 | Expiry/retention metadata and deletion semantics | Disappearing and view-once content. |
| 8 | Edit event ordering and tombstones | Message editing and multi-device convergence. |
| 9 | Group roles/capabilities and authority transfer | Admin controls and moderated polls. |
| 10 | Multi-device identity, device certificates, sync, revocation | Linked devices. |
| 11 | Accept ADR-0013 after measured media spike | Voice/video calls. |
| As needed | Signed optional self-display name in bundle records | Non-global username suggestion. |
| Before next PQ suite | Downgrade-safe crypto agility | Future post-quantum upgrades. |

Each wire/storage change must include versioning, old-client behavior, migration,
fuzz corpus updates, bounded decoding, backup impact, and copied-database leakage
review.

## 8. Cross-feature release gates

No feature is done until all applicable gates pass:

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
   strings are covered.
8. **Resource bounds:** storage, memory, CPU, battery, bandwidth, and attachment
   quotas fail safely and visibly.
9. **Documentation:** user promise, limitations, threat-model effect, and manual
   test instructions are current.
10. **CI:** format, clippy with denied warnings, tests, fuzz smoke, and
    `cargo-deny` are green; platform-specific behavior has device/simulator
    evidence where CI cannot prove it.

## 9. Completed foundation program and next priorities

Keep each numbered item, and each shell named within an item, in a separate
reviewable PR:

1. completed: expose group operations through RPC, CLI, and UniFFI, with an
   end-to-end bindings test;
2. completed: add group list/history/create/send UI to desktop, Android, and iOS;
3. completed: build the per-peer carrier capability API and pin mesh-only
   decisions in node, scheduler, and FFI tests;
4. completed through B10 folders, B11 conversation pins, B12 appearance,
   B13 custom icons, B14 screen security, and B18 labels: add the
   sealed local metadata foundation, note-to-self, private single-membership
   conversation folders, exact typed conversation pins, and private
   contact/conversation labels plus a sealed local theme choice; message pins and
   message labels remain deferred; B14 adds the separate always-on pre-unlock
   screen-security contract, and scheduled delivery completed separately in the
   core queue/storage path;
5. completed: ship typed content, attachments, audio, image editing, and mentions
   through every front door and shell; ADR-0015's formal status remains Proposed.

The next high-value local-first slice is B15 incognito keyboard behavior, with
Android's native no-personalized-learning flag and honest best-effort limits on
iOS, desktop, and third-party keyboards.
Replicated edits/expiry/polls/roles, linked-device identity, real-time media, and
optional hybrid services remain separate programs with their stated ADR gates.
