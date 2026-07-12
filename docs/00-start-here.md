# Start Here — Komms in Plain Words

*No cryptography knowledge needed. Five minutes.*

## What is this?

Komms is a messenger being built so that **nobody between you and the person
you're writing to can read, scan, or block your messages** — not a company, not a
government scanner, not the network itself. Not because a policy promises it, but
because the system is built without any middleman who *could*.

Three things make it different from the messengers you know:

1. **There is no company in the middle.** WhatsApp, Telegram, even Signal run servers
   your messages pass through, operated by an organization that can be pressured,
   banned, or ordered to install scanning. Komms has no servers. Messages travel
   directly between devices, through volunteers, or over radio.
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
| **kult address** (`kk1…`) | Your ID — like a phone number you invented yourself and nobody can take away. Share it as a QR code, sticker, or text. |
| **Safety number** | A 60-digit number you and a friend compare (in person or over a call) to be *certain* no one is impersonating either of you. |
| **Courier file / bundle** | Your encrypted messages packed into a file that can travel on a USB stick or as QR codes — messaging with no network at all. |

## What does it protect me from — honestly?

**It protects**: the content of your messages; who you talk to (as far as
technically possible); your message history on a lost or stolen (locked) device; your
ability to communicate during internet shutdowns.

**It cannot protect**: a phone that is already hacked or taken from you unlocked;
the fact that a radio transmission physically happened (radio can be detected); you,
if the person you message shares your messages. No honest tool claims otherwise —
our full, frank list is in the [threat model](02-threat-model.md).

## Can I use it today?

Almost — there are no installers to download yet, but the first desktop app
exists and runs from source (phone apps are next; see the
[roadmap](08-roadmap.md)). If you're comfortable with a terminal:

```sh
git clone https://github.com/AndriGitDev/Komms && cd Komms
cd apps/desktop/src-tauri && cargo run     # the desktop app (Linux deps: see apps/desktop/README.md)
```

Or watch two devices exchange encrypted messages through a file, no GUI at all:

```sh
cargo run --example sneakernet_demo
```

## How can I help?

- **Not technical?** Read this document and tell us what confused you — that's a
  real contribution, file it as an issue. When apps arrive, testing them will matter
  more than code.
- **Organizer / activist?** Read the [threat model](02-threat-model.md) and tell us
  where it doesn't match your reality on the ground.
- **Developer?** Start with [CONTRIBUTING](../CONTRIBUTING.md) and the
  [implementation guide](09-implementation-guide.md).
- **Cryptographer?** Attack the [crypto spec](04-cryptography.md). Please.

## Why does this exist?

Because private conversation is a human right, and rights need infrastructure, not
just arguments. The longer version — including our answer to the EU's ChatControl
law — is in [Why Komms](01-why.md).
