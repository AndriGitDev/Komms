# Start Here: Komms in Plain Words

*No cryptography knowledge needed. Five minutes.*

## What is this?

Komms is a messenger being built so that **nobody between you and the person
you're writing to can read, scan, or block your messages**: not a company, not a
government scanner, not the network itself. Not because a policy promises it, but
because the messages protect themselves and no mandatory provider can open them.

Three things make it different from the messengers you know:

1. **There is no mandatory company in the middle.** WhatsApp, Telegram, even
   Signal depend on servers operated by one organization. Komms messages travel
   directly between devices, through volunteers, or over radio. Optional
   convenience services can help wake a sleeping phone or find a paired friend,
   but they cannot read messages and communication still works without them.
2. **It works when the internet doesn't.** Messages can travel over small,
   ~€30 [Meshtastic](https://meshtastic.org) radios (kilometres of range, no SIM card,
   no infrastructure), between phones nearby, or even on a USB stick carried in a
   pocket. If someone switches the internet off, communication continues.
3. **You are not a phone number.** No number, no email, no account, no sign-up. Your
   identity is a cryptographic key created on your own device. Nobody can ban your
   account, because there is no account.

## What do the crypto words mean?

You'll see five terms around the project. This is all you need:

| Term | Plain meaning |
|---|---|
| **End-to-end encryption** | Your message is locked on your device and only your contact's device can unlock it. Everyone in between sees scrambled bytes. |
| **Post-quantum** | The locks are designed to survive even the codebreaking computers expected in the future. Messages recorded today stay private tomorrow. |
| **kult address** (`kk1…`) | Your ID, like a phone number you invented yourself and nobody can take away. Share it as a QR code, sticker, or text. |
| **Safety number** | A 60-digit number you and a friend compare (in person or over a call) to be *certain* no one is impersonating either of you. |
| **Courier file / bundle** | Your encrypted messages packed into a `.kkb` file that can travel on a USB stick or another file channel: messaging with no network at all. Animated message-bundle QR is planned; current QR flows are for pairing and verification. |

## What does it protect me from, honestly?

**It protects**: the content of your messages; who you talk to (as far as
technically possible); your message history on a lost or stolen (locked) device; your
ability to communicate during internet shutdowns.

**It cannot protect**: a phone that is already hacked or taken from you unlocked;
the fact that a radio transmission physically happened (radio can be detected); you,
if the person you message shares your messages; or all timing/network metadata
when you enable an optional convenience service. No honest tool claims otherwise.
Our full, frank list is in the [threat model](02-threat-model.md).

## Can I use it today?

Yes, for Alpha testing. [Komms 0.1 Alpha](https://github.com/AndriGitDev/Komms/releases/tag/v0.1.0)
has downloadable packages for Windows, macOS, Linux, and Android. Follow the
[Alpha testing guide](27-alpha-testing.md) to choose a package, verify its
checksum, install it, and report what you find. The desktop packages are not
production-signed or notarized, the Android APK is debug-signed, and iOS remains
source/Simulator-only. Hands-on device qualification, signed and store
distribution, the physical radio bench, and an external audit remain before a
stable release.

Messages may use a small safe formatting subset for emphasis, strong text,
quotes, lists, and code. The exact readable source stays encrypted in history
and on the wire; each app renders it locally without HTML, clickable links,
remote images, or background fetches. See
[Safe Text Formatting](16-safe-text-formatting.md) for the exact promise.

Received files never open automatically. Their displayed name and type are
sender-provided hints, not a malware verdict. Unknown, mismatched, or active
types remain export-only; a reviewed matching type still requires an explicit
warning and user action before operating-system handoff. See
[Safe File Presentation](17-safe-file-presentation.md).

You can edit canonical text you authored in a pairwise or group conversation.
Komms sends that change as a new encrypted event, keeps an **edited** marker and
inspectable version history, and derives the same winner even when offline
carriers deliver edits out of order. Editing does not erase what another device
already received or copied. See
[Authenticated Message Editing](18-message-editing.md).

You can also choose disappearing text or a view-once attachment. Komms removes
its local decryptable copy at the selected deadline, or after the first explicit
view-once reveal, and prevents delayed delivery or backup restore from reviving
that item. This does not delete a recipient's capture, control another device,
or guarantee screenshot prevention. Relays see one coarse deletion bucket but
not the exact deadline or content. See
[Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md).

Groups can also create encrypted single-choice polls. Votes and voter identities
are visible to members—Komms does not call them anonymous—and the creator closes
the exact vote snapshot they have received. Offline, duplicate, and reordered
events still converge locally. See [Group Polls](20-group-polls.md).

Groups can upgrade to signed owner, admin, and member roles. There is always one
owner. Admins can request common work while the owner is offline, but the owner
still commits one ordered change and refreshes the group's encryption keys.
Ownership can be transferred; the owner must transfer before leaving. A signed
owner moderation close is visibly different from the poll creator's ordinary
close. There is no server account or hidden moderator behind these roles. See
[Group Roles, Ownership, and Moderation](21-group-roles.md).

One Komms identity can authorize up to eight independently keyed devices through
a mutually confirmed QR or paste ceremony. Sync is explicit and encrypted
between those devices; there is no cloud account, and revoking one exact device
does not revoke or silently clone another. Recovery creates fresh device
credentials rather than reviving credentials from a backup. See
[Linked Devices](22-linked-devices.md).

Already paired contacts can also make alpha live-audio calls when both devices
have a fresh direct QUIC connection. Call setup stays inside the ordinary
end-to-end encrypted ratchet and the audio uses fresh call-specific keys; there
is no Komms call server. Calls do not work through volunteer relays, TCP
fallback, mailboxes, radio, or sneakernet and never become delayed work. Real
phone/network/audio-route qualification remains before a stable release. See
[Live Audio Calls](23-live-audio-calls.md).

The published packages are the quickest start. If you are developing Komms or
want to inspect it from source, run the desktop shell with:

```sh
git clone https://github.com/AndriGitDev/Komms && cd Komms
cd apps/desktop/src-tauri && cargo run     # the desktop app (Linux deps: see apps/desktop/README.md)
```

Or watch two devices exchange encrypted messages through a file, no GUI at all:

```sh
cargo run --example sneakernet_demo
```

Platform build instructions:

- [Desktop](../apps/desktop/README.md)
- [Android](../apps/android/README.md)
- [iOS](../apps/ios/README.md)

## Where should I read next?

| If you want to know… | Read… |
|---|---|
| how to install and test the 0.1 Alpha | [Alpha Testing](27-alpha-testing.md) |
| what Komms promises and why | [Why Komms](01-why.md) |
| what it protects—and what it cannot | [Threat Model](02-threat-model.md) |
| how the system is layered | [Architecture](03-architecture.md) |
| what is implemented versus remaining | [Roadmap](08-roadmap.md) |
| which product features fit the model | [Feature Scope](11-feature-scope.md) |
| the exact delivery status of each feature | [Feature Delivery Plan](12-feature-delivery-plan.md) |
| how authored message edits work and what they cannot erase | [Authenticated Message Editing](18-message-editing.md) |
| what disappearing/view-once means—and what it cannot erase | [Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md) |
| how encrypted group polls converge and why votes are visible | [Group Polls](20-group-polls.md) |
| how signed group roles, ownership transfer, and moderation work | [Group Roles, Ownership, and Moderation](21-group-roles.md) |
| how one account safely authorizes, syncs, and revokes physical devices | [Linked Devices](22-linked-devices.md) |
| when live audio calls work—and when they deliberately do not | [Live Audio Calls](23-live-audio-calls.md) |
| how a release is validated locally before any hosted run | [Local Release Gate](24-local-release-gate.md) |
| why a technical decision was made | [ADR Index](adr/README.md) |

## How can I help?

- **Not technical?** Read this document and tell us what confused you: that's a
  real contribution—file it as an issue. Hands-on testing of the published
  Alpha packages and their setup instructions matters too.
- **Organizer / activist?** Read the [threat model](02-threat-model.md) and tell us
  where it doesn't match your reality on the ground.
- **Developer?** Start with [CONTRIBUTING](../CONTRIBUTING.md) and the
  [implementation guide](09-implementation-guide.md).
- **Cryptographer?** Attack the [crypto spec](04-cryptography.md). Please.

## Why does this exist?

Because private conversation is a human right, and rights need infrastructure, not
just arguments. The longer version (including our answer to the EU's ChatControl
law) is in [Why Komms](01-why.md).
