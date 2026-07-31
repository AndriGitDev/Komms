# Start Here: Komms in Plain Words

*No cryptography knowledge needed. Five minutes.*

## What is this?

Komms is a messenger being built so that **people carrying your messages are
not given the keys to read or scan their contents**. It also offers more than
one route, so no mandatory exclusive provider is the only way to communicate.
Encryption cannot promise delivery against every network block, device seizure,
radio jammer, or compromised endpoint; the goal is to preserve useful
alternatives when at least one supported path remains.

Three things make it different from the messengers you know:

1. **There is no mandatory exclusive provider.** Komms messages may travel
   directly, through chosen volunteer mailbox operators holding sealed
   ciphertext, or over local and radio links. Standard mode can consume
   disclosed, signed, replaceable defaults, although no qualified default
   operator currently ships. Optional post-pairing
   rendezvous and phone wake services cannot read message content or hold
   identity private keys; removing them leaves the pure-core routes available.
2. **It is designed for more than one kind of network.** Messages can use
   [Meshtastic](https://meshtastic.org) radios, local links, or a `.kkb` courier
   file carried on removable media. The software paths have automated tests;
   the physical two-radio and real-world mobile matrices remain Alpha
   qualification work. During a shutdown, communication still needs a
   supported route, working devices, power, configuration, and sometimes radio
   hardware.
3. **You are not a phone number.** No number, no email, no account, no sign-up. Your
   identity is a cryptographic key created on your own device. There is no
   centrally administered Komms account for one operator to deactivate.
   Contacts can block an identity, and networks, app stores, service operators,
   and device owners can deny access to their own resources.

## What do the crypto words mean?

You'll see five terms around the project. This is all you need:

| Term | Plain meaning |
|---|---|
| **End-to-end encryption** | Your message is locked on your device and only your contact's device can unlock it. Everyone in between sees scrambled bytes. |
| **Post-quantum** | The handshake combines classical and standardized post-quantum key agreement to reduce “record now, decrypt later” risk. It is not a guarantee against endpoint compromise, implementation bugs, or future cryptanalysis. |
| **kult address** (`kk1…`) | Your cryptographic ID, created on your device rather than assigned by a central registry. Share it as a QR code, sticker, or text. |
| **Safety number** | A 30-digit number you and a friend compare (in person or over a trusted call) to check that the identity keys match; scanning compares the full 256-bit value. It cannot make a compromised endpoint trustworthy. |
| **Courier file / bundle** | Your encrypted messages packed into a `.kkb` file that can travel on a USB stick or another file channel: messaging with no network at all. Animated message-bundle QR is planned; current QR flows are for pairing and verification. |

## What does it protect me from, honestly?

**It is designed to protect**: the content of your messages; who you talk to (as
far as the selected routes and threat model allow); your message history on a
lost or stolen locked device; and communication options during internet
shutdowns when a supported alternate path remains.

**It cannot protect**: a phone that is already hacked or taken from you unlocked;
the fact that a radio transmission physically happened (radio can be detected); you,
if the person you message shares your messages; or all timing/network metadata
when you enable an optional convenience service. No honest privacy claim says
otherwise.
Our full, frank list is in the [threat model](02-threat-model.md).

## Can I use it today?

Yes, for Alpha testing. [Komms 0.3 Alpha](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0)
has downloadable packages for Windows, macOS, Linux, and Android. Follow the
[Alpha testing guide](27-alpha-testing.md) to choose a package, verify its
checksum, install it, and report what you find. The desktop packages are not
production-signed or notarized, the Android APK is debug-signed, and iOS remains
source/Simulator-only. Hands-on device qualification, signed and store
distribution, the physical radio bench, and an external audit remain before a
stable release. Fresh internet installs also need deliberate bootstrap/mailbox
configuration today. Deterministic local Standard-blackhole, replacement, and
pure-core journeys now exist, but clean supported devices behind distinct real
NATs and qualified operators remain P0 work, not a current plug-and-play claim.

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
carriers deliver edits out of order. Current pairwise and upgraded group
authorship is authenticated separately for each recipient device; legacy group
history retains its visible weaker label. Editing does not erase what another
device already received or copied. See
[Authenticated Message Editing](18-message-editing.md).

You can also choose disappearing text or a view-once attachment. Komms removes
its local decryptable copy at the selected deadline, or after the first explicit
view-once reveal, and prevents delayed delivery or backup restore from reviving
that item. This does not delete a recipient's capture, control another device,
or guarantee screenshot prevention. Relays see one coarse deletion bucket but
not the exact deadline or content. See
[Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md).

Groups can also create encrypted single-choice polls. Votes and voter identities
are visible to members—Komms does not call them anonymous—and the apparent
creator closes the exact vote snapshot they have received. Offline, duplicate,
and reordered events still converge locally. Current Alpha groups authenticate
each claimed voter and creator separately to every recipient device while
retaining one shared sender-key ciphertext and recipient deniability. Legacy
group history remains labelled as membership-authenticated. See
[Group Polls](20-group-polls.md) and
[ADR-0029](adr/0029-recipient-authenticated-groups.md).

Groups can upgrade to signed owner, admin, and member roles. There is always one
owner. Admins can request common work while the owner is offline, but the owner
still commits one ordered change and refreshes the group's encryption keys.
Ownership can be transferred; the owner must transfer before leaving. A signed
owner moderation close is visibly different from an apparent creator's ordinary
close. There is no server account or hidden moderator behind these roles. See
[Group Roles, Ownership, and Moderation](21-group-roles.md).

One Komms identity can authorize up to eight independently keyed devices through
a mutually confirmed QR or paste ceremony. Sync is explicit and encrypted
between those devices; there is no cloud account. The stable account root is a
separately held offline recovery authority and never enters ordinary device
linking. Routine changes require a strict majority of the previous active set;
forks remain visible and fail closed. Recovery revokes the former set and
creates fresh device credentials rather than reviving credentials from a
backup. See
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
| how to install and test the 0.3 Alpha | [Alpha Testing](27-alpha-testing.md) |
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
| how one account authorizes, syncs, revokes, and recovers devices | [Linked Devices](22-linked-devices.md) |
| when live audio calls work—and when they deliberately do not | [Live Audio Calls](23-live-audio-calls.md) |
| how a release is validated locally before any hosted run | [Local Release Gate](24-local-release-gate.md) |
| how a tagged candidate becomes a protected draft or public release | [Release Runbook](25-release-runbook.md) |
| how release keys are separated, recovered, rotated, and revoked | [Release Security and Recovery](39-release-security-and-recovery.md) |
| what a revision-bound release evidence bundle contains | [Release Evidence Bundles](40-release-evidence-bundles.md) |
| how to read or run the stand-alone stable-v1 protocol kit | [Stable-v1 Protocol Conformance](41-protocol-conformance.md) |
| how the optional content-free phone-wake gateway is bounded and operated | [Native-Wake Operations](37-native-wake-operations.md) |
| what evidence is required before stable or wire v1 | [Stabilization Program](29-stabilization-program.md) |
| which persisted protocol transitions are atomic and which remain open | [Atomic Transition Inventory](34-atomic-transition-inventory.md) |
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

Because private conversation is a human right, and rights need infrastructure,
not just arguments. The longer version—including Komms's position on European
policy proposals and temporary rules commonly discussed as
“Chat Control”—is in [Why Komms](01-why.md).
