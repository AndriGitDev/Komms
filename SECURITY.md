# Security Policy

## Reporting a vulnerability

Email **andri@andri.is**. If you need encryption for the report itself, request
a key in a first message without vulnerability details.

Please include: affected component/doc section, impact as you understand it, and
reproduction steps or a proof-of-concept where applicable.

## What to expect

- Acknowledgment within **72 hours**.
- Assessment and a remediation plan within **14 days** for confirmed issues.
- Credit in release notes (or anonymity, your choice). No bounty program yet; this is
  an unfunded open project, and recognition is what we have.

## Ground rules

- Coordinated disclosure: please give us the 14-day assessment window before publishing.
- The shipped alpha implementation and its specifications are both in scope.
  Threat-model gaps, broken constructions, unstated assumptions, local data
  leakage, transport-policy bypasses, and platform lifecycle failures are
  especially valuable reports. Start with the
  [threat model](docs/02-threat-model.md) and
  [cryptography specification](docs/04-cryptography.md) for the intended
  guarantees and accepted limits.

For C3 message editing, cross-author application, cross-conversation target
confusion, raw-content authorization bypasses, arrival-order divergence,
capability downgrade, hidden prior-version loss, and plaintext edit metadata are
in scope. The intended immutable-event and retained-version contract is
[18: Authenticated Message Editing](docs/18-message-editing.md) and
[ADR-0020](docs/adr/0020-authenticated-message-edits.md).

Runtime and release-surface reports are also in scope: plaintext or identity
leakage through logs/errors, secret-file permission or time-of-check/time-of-use
bypasses, passphrase/mnemonic retention, panic cascades across daemon or FFI
synchronization boundaries, linked-device authorization/revocation failures,
and direct-QUIC call-policy or media-authentication bypasses. The intended
contracts are [09: Implementation Guide §4b–4c](docs/09-implementation-guide.md),
[22: Linked Devices](docs/22-linked-devices.md), and
[23: Live Audio Calls](docs/23-live-audio-calls.md). Official 0.1 Alpha packages
are published from tag `v0.1.0`, but desktop production signing/notarization,
Android release signing, and an update channel remain scaffold-only. Verify
`SHA256SUMS` from the [official prerelease](https://github.com/AndriGitDev/Komms/releases/tag/v0.1.0);
a third-party binary must not be represented as an official Komms release.

## Scope notes

Accepted limitations documented in
[02: Threat Model §4](docs/02-threat-model.md) (e.g. persistently compromised
endpoints, LoRa radio observability, global passive adversaries) are known trade-offs,
not vulnerabilities, but arguments that a documented limitation is *understated* are
very much in scope.
