# Security Policy

## Reporting a vulnerability

Email **andri@andri.is**. If you need encryption for the report itself, say so in a
first plaintext mail and a key will be provided (a published PGP key will be added here
before any code ships).

Please include: affected component/doc section, impact as you understand it, and
reproduction steps or a proof-of-concept where applicable.

## What to expect

- Acknowledgment within **72 hours**.
- Assessment and a remediation plan within **14 days** for confirmed issues.
- Credit in release notes (or anonymity, your choice). No bounty program yet — this is
  an unfunded open project; recognition is what we have.

## Ground rules

- Coordinated disclosure: please give us the 14-day assessment window before publishing.
- During the current **design phase (M0)**, flaws in the *specifications* — threat-model
  gaps, broken constructions, unstated assumptions in
  [docs/04-cryptography.md](docs/04-cryptography.md) — are in scope and especially
  valuable. Finding them now is cheap; finding them after M1 is not.

## Scope notes

Accepted limitations documented in
[02 — Threat Model §4](docs/02-threat-model.md) (e.g. persistently compromised
endpoints, LoRa radio observability, global passive adversaries) are known trade-offs,
not vulnerabilities — but arguments that a documented limitation is *understated* are
very much in scope.
