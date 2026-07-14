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
| **Assurance** | Shipped security behavior that remains a permanent release gate rather than a feature backlog item. |

## 2. Current baseline

Komms already has a strong transport and security foundation, but its public
message model is still effectively `Vec<u8>` in the node and UTF-8 text at the
FFI boundary. Attachments, edits, polls, expiry, and calls therefore need shared
content and capability foundations before individual shells implement UI.

| Feature from scope | Current status | Main gap |
|---|---|---|
| Text messages | Shipped | Product polish and accessibility only. |
| Recorded audio messages | Planned | Attachment/media model, recording UI, carrier policy. |
| End-to-end encryption | Assurance | Continuous audit, KAT, fuzz, and regression gates. |
| Post-quantum handshake | Assurance | Crypto-agility and downgrade-safe future upgrades. |
| Contact names / usernames | Partial | Local petnames exist; rename UX and optional signed self-display name do not. |
| Secure backups | Shipped | Future feature data must be added without leaking or silently omitting it. |
| Note to self | Planned | Local conversation type and UI. |
| Queued messages | Shipped | Already part of the honest delivery engine. |
| Scheduled messages | Planned | Durable `not_before` gate and UI. |
| Text formatting | Planned | Safe common subset and consistent rendering. |
| Folders | Planned | Local organization metadata and UI. |
| Pins | Planned | Local conversation/message pin metadata and UI. |
| Dark mode | Planned | Shared theme semantics and shell implementations. |
| Custom icons | Planned | Local-only contact/group/conversation artwork. |
| Screen security | Planned | Platform protections and documented limitations. |
| Incognito keyboard | Planned | Android control; best available behavior and honest limits elsewhere. |
| Local media editing | Planned | Pre-encryption transforms and temporary-file hygiene. |
| Mentions | Planned | Typed peer reference, group-aware composer, and navigation. |
| Labels | Planned | Local contact/conversation/message metadata and filtering. |
| File sharing | Planned | Resumable encrypted attachments and carrier-aware limits. |
| Linked devices | Planned | Proximate linking, device keys, sync, revocation, and recovery. |
| Message editing | Planned | Authenticated revisions and deterministic offline reconciliation. |
| Disappearing/view-once messages | Planned | Expiry semantics, relay metadata design, deletion limits. |
| Group polls | Planned | Typed group content and convergent vote updates. |
| Admin/role controls | Planned | Cryptographic group capabilities and authority transitions. |
| Live voice/video calls | Planned | ADR-0013 spike, call signaling/media, and carrier gating. |

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

Add a versioned, length-bounded message-content codec while keeping legacy raw
text readable. Start with `Text`; add typed variants only as their feature lands.
Candidate variants are `Attachment`, `Edit`, `Poll`, `PollVote`, and `Mention`;
their exact shapes remain decisions for the content ADR. Call signaling remains
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

**State:** core implemented behind node APIs; product-surface integration is
planned. [ADR-0015](adr/0015-encrypted-attachment-pipeline.md) now has bounded
manifest/bulk codecs, deterministic chunk cryptography, sealed quota-bound
storage, explicit consent/cancel/reject/resume state, pairwise and encrypt-once
group transfer, streamed export, and a scheduler-enforced no-airtime class.
Activation consumes F4's fresh, time-bounded verdict on every offer or
missing-range request. Applications receive the same snapshot and change events
for user-facing feature gating; shells must not infer capacity from an available
route alone.

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

Add sealed local-only records for conversation type, folders, pins, labels,
drafts, UI preferences, and custom icons. Keep local organization out of network
payloads. Define which records belong in encrypted backups and version the backup
format when the first new record ships. Scheduled delivery is separate core queue
state covered by B8, not a UI-metadata timer.

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

**Depends on:** F2, F3, F4.

Deliver a press/hold or tap-to-record composer, local playback, waveform/duration
metadata, and explicit send confirmation. Prefer an interoperable low-bitrate
codec such as Opus where platform support and licensing pass review. Strip
container metadata that could leak device/location information.

Policy:

- internet/LAN: normal attachment limits;
- mailbox/sneakernet: allowed within configured quotas;
- LoRa: tiny clips may be queued only under an explicit conservative cap;
  otherwise show "will send when a faster link exists" before committing airtime.

Acceptance includes interrupted recording cleanup, background upload resumption,
locked-device behavior, and a cross-platform encode/decode test.

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

**State:** KKR2 shipped; permanent compatibility track.

For every feature in this plan, decide explicitly whether its state is identity
critical, conversation history, local preference, secret ephemeral state, or
re-creatable cache. Back up the first two; normally back up local organization;
never back up live ratchet/sender chains or temporary decrypted media.

Acceptance:

- backup and restore preserve all promised feature state;
- older KKR1/KKR2 files remain restorable;
- a restored node rotates/re-handshakes where required;
- omitted caches are rebuilt without data loss or false delivery state.

### B7. Note to self

**Depends on:** F5.

Implement a first-class local conversation, not a fake contact or a message sent
through the node's own ratchet. Store entries sealed in `kult-store`; never queue,
publish, generate receipts, or touch a transport. Support text first and
attachments after F3.

Acceptance proves zero envelopes are emitted, entries survive restart and
backup/restore, and all shells use the same reserved conversation identity.

### B8. Scheduled and queued messages

**State:** ordinary queued delivery shipped; scheduling planned.

This is a core queue/storage change, not part of the F5 local UI metadata store.

Persist an optional UTC `not_before` timestamp in core storage and enforce it in
the node scheduler so delivery survives app exit, background suspension, and
restart. The UI handles local time zones and daylight-saving display, but it
must not be the only gate. Define behavior for clock rollback/advance and permit
edit/cancel until encryption/queue activation.

Acceptance:

- nothing reaches any transport before `not_before`;
- restart and time-zone changes do not alter the intended instant;
- when the instant arrives offline, the message becomes ordinarily queued;
- UI clearly distinguishes scheduled, queued, sent, and delivered.

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

Folders are local views over conversation IDs. Support create, rename, reorder,
move, delete-without-deleting-conversations, and an unfiled/default view. Do not
sync folders to contacts or leak them onto the wire.

Acceptance covers restart, backup/restore, deleted contacts/groups, and the same
conversation appearing in at most one folder unless multi-folder behavior is
explicitly chosen before implementation.

### B11. Pins

**Depends on:** F5.

Support pinned conversations first, then optionally pinned messages inside a
conversation. Pins are local metadata keyed by stable IDs and never affect group
state. Define deterministic ordering (manual order, then recent activity).

Acceptance covers deletion/tombstones, restore, and missing referenced content.

### B12. Dark mode

Define system/light/dark choices and a shared semantic color token set with WCAG
contrast targets. Each shell uses native/system theme signals; no security or
delivery state may be conveyed by color alone.

Acceptance includes first-run system mode, live switching, high contrast,
reduced motion, and screenshots of the major surfaces in both themes.

### B13. Custom icons

**Depends on:** F5.

Allow local contact, group, folder, and note-to-self icons from generated initials,
bundled glyphs, or a user-selected local image. Crop and re-encode locally, strip
metadata, cap dimensions/bytes, and store the result sealed. Never fetch avatar
URLs or send custom icons to peers in the first version.

Acceptance proves metadata removal, quota enforcement, backup behavior, and safe
fallback after a missing/corrupt image.

### B14. Screen security

Implement platform controls with honest guarantees:

- Android: secure-window protection for screenshots/screen recording and task
  previews, with a user-visible policy if toggling is allowed;
- iOS: obscure sensitive content in the app switcher and respond to capture
  notifications; do not claim iOS can universally block screenshots;
- desktop: obscure recent/task previews where supported and provide a rapid lock
  shortcut; document compositor/OS limits.

Acceptance includes lock/background transitions and verifies that sensitive
views do not remain in app-switcher snapshots on supported platforms.

### B15. Incognito keyboard

On Android, request the no-personalized-learning/incognito input flags on every
sensitive field. On iOS and desktop, disable autocorrection/prediction where APIs
permit, but document that third-party keyboards or the OS may ignore hints. Never
put secrets such as mnemonics in normal predictive fields.

Acceptance checks all message, search, passphrase, mnemonic, and naming fields;
automated UI assertions cover the flags where platforms expose them.

### B16. Local media editing

**Depends on:** F3.

Start with image crop/rotate, metadata stripping, and face/pixel blur before
adding video trimming/redaction. Transform before attachment encryption; retain
neither the original nor intermediate plaintext unless the user explicitly asks.
Use platform-native codecs where possible and never send media to a cloud API.

Acceptance includes EXIF/GPS removal, cancellation cleanup, low-storage failure,
orientation/color preservation, and byte-level proof that only the edited asset
enters the attachment pipeline.

### B17. Mentions

**Depends on:** F1, F2.

Compose mentions in group message text using an explicit member picker rather
than ambiguous free-form names. Encode a stable peer reference alongside fallback
display text so every client can highlight the intended member despite different
local petnames. Mention notifications remain local and opportunistic: there is no
server push guarantee.

Acceptance covers duplicate petnames, roster changes, removed members, Unicode,
plain-text fallback, and no notification for a peer merely sharing a similar
display name.

### B18. Labels

**Depends on:** F5.

Implement private local labels for contacts and conversations first; add message
labels only if the UI demonstrates value. Support color/name, filtering, and
multi-label membership. Labels never enter DHT, group state, or message content.

Acceptance covers rename/delete, backup/restore, stale references, and accessible
filter controls.

## 5. Build-with-constraints features

### C1. File sharing

**Depends on:** F2, F3, F4. **ADR required.**

Ship in tiers:

1. small files over internet/LAN with explicit user download;
2. resumable transfer over mailbox/sneakernet within local quotas;
3. an intentionally tiny mesh allowance, or a hard mesh block, chosen from
   measured airtime rather than intuition.

The sender UI must show the active policy before sending. The scheduler must
hold oversized content for a faster link instead of fragmenting it across LoRa.
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

## 6. Delivery sequence

The order below maximizes usable increments while keeping protocol dependencies
honest. Parallel work is safe only where rows do not share a foundation.

| Wave | Outcome | Features |
|---|---|---|
| **0: Finish current foundations** | Existing group core is usable; product can make carrier-aware decisions. | F1, F4; design F2/F3/F5. |
| **1: Local-first product polish** | High-value features with no new network semantics. | B5 rename UX, B7, B9–B15, B18; preserve B1/B3/B4/B6 gates. |
| **2: Typed content and asynchronous media** | Shared content/attachment path across all shells. | F2, F3, B2, B16, C1; B17 after F2. |
| **3: Replicated conversation features** | Offline-convergent edits, expiry, polls, and group authority. | C3, C4, C5, C6. |
| **4: Multi-device** | Proximate device linking and convergent state. | C2, followed by cross-device hardening of Wave 3. |
| **5: Real-time media** | Direct internet/LAN audio, then video. | ADR-0013 spike and C7. |

Scheduled messages (B8) may land in Wave 1 as a small isolated core PR. Persist
the durable gate in the shared queue/storage schema rather than F5 or the UI, and
do not couple it to the content codec.

## 7. ADR and format queue

Do not combine these into one oversized design decision.

| Order | Decision | Unlocks |
|---|---|---|
| 1 (done) | ADR-0014: versioned typed message content and compatibility | Audio, files, edits, polls, structured mentions. |
| 2 (proposed) | ADR-0015: encrypted attachment/chunk transfer and carrier policy | Audio, files, media editing. |
| 3 | Expiry/retention metadata and deletion semantics | Disappearing and view-once content. |
| 4 | Edit event ordering and tombstones | Message editing and multi-device convergence. |
| 5 | Group roles/capabilities and authority transfer | Admin controls and moderated polls. |
| 6 | Multi-device identity, device certificates, sync, revocation | Linked devices. |
| 7 | Accept ADR-0013 after measured media spike | Voice/video calls. |
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

## 9. Recommended first execution program

Keep each numbered item, and each shell named within an item, in a separate
reviewable PR:

1. expose the already-shipped group operations through RPC, CLI, and UniFFI, with
   an end-to-end bindings test;
2. add group list/history/create/send UI to desktop, then Android, then iOS as
   separate follow-ups over the proven interface;
3. build the per-peer carrier capability API and pin mesh-only decisions in node,
   scheduler, and FFI tests;
4. add the sealed local metadata foundation, then note-to-self; implement
   scheduled delivery in its own core queue/storage PR;
5. write the typed-content and attachment ADRs as separate design PRs, with no
   implementation hidden in either decision.

This program unlocks the largest number of approved features without combining
unrelated review surfaces or starting with the two riskiest programs,
linked-device identity and real-time media.
