# 19: Disappearing Messages and View-Once Attachments

C4 adds two authenticated, endpoint-local retention modes without claiming
remote erasure:

- **disappearing text** is removed from each Komms installation when that
  installation reaches the exact authenticated deadline; and
- **view-once attachments** keep an unopened decryptable copy until the first
  explicit reveal or the deadline, whichever comes first. The first reveal is
  terminal on that installation.

Recipients, linked devices, compromised endpoints, operating systems, cameras,
and copied ciphertext remain outside that promise. Product copy therefore says
“removed from this device” and “view once on this device.” It never promises
recall, screenshot prevention, or deletion from somebody else's hardware.

The normative wire/storage decision is
[ADR-0021](adr/0021-ephemeral-retention.md).

## 1. User behavior

Pairwise and group text composers offer permanent text plus 1 minute, 1 hour,
1 day, 1 week, and 30 day lifetimes. Attachment review offers view once with a
1 hour, 1 day, 1 week, or 30 day unopened-copy fallback. The selection is an
explicit per-send choice, not a hidden conversation default.

History shows the local removal deadline. Expiry removes the row and refreshes
the active conversation through a typed terminal event. A view-once attachment
never enters the ordinary preview, autoplay, playback, open, or export path.
After download and consent, **Reveal once** writes through the core's terminal
consume operation into a protected application path. The sealed tombstone is
committed before any plaintext output; success and output failure both delete
the locally decryptable chunks. A second reveal is refused.

Formatting, semantic mentions, edits, replies, quotes, and scheduling do not
silently inherit ephemeral semantics. C4 disappearing text is its own content
kind; group mentions fall back only through an explicit ordinary-text choice.
Ephemeral content cannot be edited, and raw/generic send entry points reject an
already encoded ephemeral frame. An anonymous first handshake flight is always
ordinary content, so ephemeral send requires an established authenticated
session and advertised support.

## 2. Wire and relay contract

Content format v1 kind `0x0005` contains a random content id, mode, exact UTC
`expires_at`, canonical coarse `retention_until`, and either UTF-8 text or an
attachment manifest. `retention_until` is the one-hour ceiling of `expires_at`.
Both values are inside the Double Ratchet or sender-key authenticated plaintext.

Envelope v2 adds the same hour-aligned `retention_until` in cleartext. Mailboxes,
bridges, queues, and fragments treat it only as a bounded deletion hint: they
discard at or after it and may discard earlier. The recipient accepts the
message only when the decrypted content binds the exact same canonical bucket.
Ordinary content in envelope v2 and ephemeral content without a v2 hint fail
closed. Relays cannot extend the application deadline and do not learn the
exact deadline, but they do learn one coarse retention bucket for ephemeral
traffic.

Local removal uses the exact authenticated deadline, not the coarse relay hint.
A clock jump forward removes due content before receive, queue activation,
attachment work, or transport flush. A rollback can delay local removal, so the
UI describes a device-clock deadline rather than a synchronized global event.

## 3. Storage, restart, and backup

Every authored or accepted ephemeral id has a separately sealed lifecycle row
keyed by exact conversation, author, and content id. Active rows point to any
associated media transfers. Expiry or consumption deletes the history row,
queue reference, transfer metadata, and sealed media chunks, then retains a
terminal `expired` or `consumed` tombstone. Duplicate, delayed, reordered, and
expiry-before-original delivery therefore cannot resurrect plaintext after a
restart.

`KKR7` is the current backup format. It preserves KKR5's exclusion of active ephemeral history,
attachment manifests, and media, while including terminal tombstones. Restore
cannot move a live disappearing/view-once copy to another device and cannot
revive a copy already removed on the source. `KKR1` through `KKR6` remain
restorable. Ordinary history, edits, note-to-self, and private local metadata
keep their previous backup behavior.

C2 linked-device sync carries terminal expiry/consumption tombstones but never
active ephemeral plaintext, manifests, or media. Every installation enforces
its own local deadline and first reveal; no device may promise that another
device or recipient deleted a copy.

## 4. Surfaces

The strict RPC/CLI and UniFFI surfaces expose separate pair/group disappearing
send operations, separate pair/group view-once attachment imports, expiry fields
on history/events/attachment models, one terminal consume operation, and typed
expiry/consumption events. Ordinary attachment export returns a specific error
for view-once transfers.

Desktop, Android, and iOS use those same core calls. Their selectors, history
labels, terminal refresh, protected reveal path, and preview/export/playback
blocks are shell responsibilities; deadline calculation, capability checks,
deletion, tombstones, and backup exclusion remain core responsibilities.

## 5. Security and privacy limits

- A recipient can photograph, copy, transcribe, or capture plaintext before it
  disappears. A compromised or privileged endpoint can do the same.
- A relay may retain copied ciphertext past the hint despite Komms requesting
  deletion. Without the endpoint keys that ciphertext remains sealed, but C4 is
  not a cryptographic proof of physical erasure.
- Secure deletion on flash storage is best effort below the encrypted-record and
  key-deletion boundary because wear levelling and snapshots are controlled by
  the OS/device.
- The coarse hour bucket is observable to envelope carriers. Exact expiry, mode,
  content, conversation, sender, and recipient identity remain encrypted or
  hidden by the ordinary delivery-token design.
- View once restricts Komms's local presentation paths; it is not DRM and does
  not disable operating-system accessibility or external cameras.

## 6. Qualification matrix

Automated acceptance covers bounded/malformed decoding and fuzzing; envelope
hint mismatch; capability and anonymous-first-flight refusal; pairwise/group
delivery; expiry before original; duplicate/reordered delivery; restart;
tombstone non-resurrection; first-output and output-failure consumption;
ordinary export refusal; KKR1–KKR7 restore; active-content exclusion and
tombstones; C2 tombstone convergence; relay,
bridge, fragment, and queue deletion; strict RPC/CLI; UniFFI; shared parity
fixtures; and desktop/Android/iOS source behavior.

Before a packaged mobile release, qualify on physical devices as well:

1. send every lifetime near a minute/hour boundary with sender and recipient
   clocks ahead and behind;
2. background, terminate, reboot, and reopen before and after the deadline;
3. download view-once image, audio, and generic-file samples, verify that no
   preview/autoplay/export action appears, reveal once, then verify a second
   reveal fails;
4. force protected-output failure and low-storage interruption, then verify the
   item remains terminal and no transient survives startup cleanup;
5. exercise screen readers, large text, keyboard navigation, bidi text, and
   localized relative-deadline copy; and
6. inspect app backups, logs, notifications, recent-task/app-switcher state, and
   protected transient directories for content leakage.

Android APK/device validation is deferred on hosts without an Android SDK. iOS
app type-check/simulator validation requires a full Xcode installation; Swift
parse and the host UniFFI behavior suite remain the local fallback gates.
