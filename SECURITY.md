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

## Scope notes

Accepted limitations documented in
[02: Threat Model §4](docs/02-threat-model.md) (e.g. persistently compromised
endpoints, LoRa radio observability, global passive adversaries) are known trade-offs,
not vulnerabilities, but arguments that a documented limitation is *understated* are
very much in scope.
