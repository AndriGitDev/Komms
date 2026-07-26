# Security Policy

## Reporting a vulnerability

Email **andri@andri.is**. If you need encryption for the report itself, request
a key in a first message without vulnerability details.

This is currently a single-maintainer intake, as disclosed in
[MAINTAINERS.md](MAINTAINERS.md); it is not staffed around the clock. Do not
send a vulnerability through a public issue.

Please include: affected component/doc section, impact as you understand it, and
reproduction steps or a proof-of-concept where applicable.

## Response targets

- Acknowledgment target: **72 hours**.
- Initial assessment target for a confirmed issue: **14 days**.
- Regular updates while an accepted report remains unresolved.
- Credit in release notes, or anonymity, at the reporter's choice.

These are targets rather than a 24/7 support guarantee. If you receive no
acknowledgment, resend with `[Komms security]` in the subject. There is currently
no bounty program; do not incur expense in expectation of payment.

## Ground rules

- Coordinated disclosure: please allow the initial assessment window and agree
  on a disclosure date based on impact and fix complexity. Imminent user harm
  may require faster action by both parties.
- The Alpha implementation and its specifications are both in scope; neither is
  represented as independently audited.
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
[23: Live Audio Calls](docs/23-live-audio-calls.md). Official 0.3 Alpha packages
are published from tag `v0.3.0`, but desktop production signing/notarization,
Android release signing, and an update channel remain scaffold-only. Verify
`SHA256SUMS` from the [official prerelease](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0);
a third-party binary must not be represented as an official Komms release.

Optional-service and operator reports are in scope: discovery-capability or
rendezvous-slot leakage, DHT poisoning/eclipsing/suppression, signed-directory
downgrade, service-key compromise, access-log/metric/trace/crash/snapshot
leakage, cross-role correlation, a RAM-only service retaining state, a mailbox
falsely acknowledging durable custody, or failure to fall back when project
defaults are blackholed. Deployment reports should identify the source
revision, image digest, configuration, hosting/provider boundary, and relevant
key-rotation or incident procedure. The intended boundaries are
[ADR-0017](docs/adr/0017-optional-hybrid-modes.md),
[ADR-0031](docs/adr/0031-capability-scoped-dht-discovery.md), and
[ADR-0034](docs/adr/0034-operator-minimized-reference-discovery.md).

## Scope notes

Accepted limitations documented in
[02: Threat Model §4](docs/02-threat-model.md) (e.g. persistently compromised
endpoints, LoRa radio observability, global passive adversaries) are known trade-offs,
not vulnerabilities, but arguments that a documented limitation is *understated* are
very much in scope.
