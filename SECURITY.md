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

## Incident handling

The founder is the current security coordinator and incident decision owner.
There is no 24/7 team or accepted backup security steward. That continuity gap
is tracked in [MAINTAINERS.md](MAINTAINERS.md) and the
[release evidence ledger](docs/31-release-evidence-ledger.md).

For a confirmed vulnerability or operational incident, the coordinator:

1. opens a private, access-limited incident record with discovery time, affected
   revisions/services, reporter preference, known impact, and evidence custody;
2. classifies urgency and decides containment without exposing report details
   through public issues, logs, or ordinary diagnostics;
3. identifies affected releases, protocol versions, operators, credentials, and
   user actions, including whether signing, service, domain, or notification
   channels remain trustworthy;
4. prepares and validates the smallest safe correction, key/service rotation,
   rollback, or disabling action, recording every deferred platform or external
   dependency;
5. coordinates disclosure with the reporter and publishes an advisory with
   affected versions, impact, fixes, workarounds, credits, and residual risk;
6. notifies known official operators and users through authenticated project
   release/advisory channels when action is required; and
7. publishes a post-incident process summary when doing so will not expose
   reporters, users, credentials, or still-exploitable detail.

The incident owner may make an emergency release or disable an official
project-operated service within the authority in
[GOVERNANCE.md](GOVERNANCE.md). Emergency action does not waive release
evidence: missing checks and independent review remain explicit, and the
evidence ledger records follow-up and closure. If the founder has a conflict,
the project seeks an unconflicted external reviewer; none is currently assigned
in advance.

The role-specific provider data flows, lawful-request sequence, credential
containment matrix, advisory fields, user-notification boundary, and internal
policy dry-runs are in
[Privacy, Legal, and Incident Readiness](docs/49-privacy-legal-incident-readiness.md).
Those dry-runs are not a live incident, legal opinion, external tabletop, or
24/7 response claim.

## Ground rules

- Coordinated disclosure: please allow the initial assessment window and agree
  on a disclosure date based on impact and fix complexity. Imminent user harm
  may require faster action by both parties.
- The Beta implementation and its specifications are both in scope; neither is
  represented as independently audited.
  Threat-model gaps, broken constructions, unstated assumptions, local data
  leakage, transport-policy bypasses, and platform lifecycle failures are
  especially valuable reports. Start with the
  [threat model](docs/02-threat-model.md) and
  [cryptography specification](docs/04-cryptography.md) for the intended
  guarantees and accepted limits.

The prepared commissioned-review scope, reproducible source package, finding
format, disclosure proposal, and current unassigned status are in
[Independent Security-Review Readiness](docs/42-independent-security-review.md).
That package does not replace this ordinary vulnerability intake and does not
claim that a review has occurred. No reviewer is currently authorized to
access private systems, contact users or operators, or incur project expense.

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
[23: Live Audio Calls](docs/23-live-audio-calls.md). The historical official
0.3 Alpha packages were published from tag `v0.3.0` and predate the current
release-evidence design. Komms 0.4 Beta is official only if the exact package is
published under `v0.4.0` with its completed evidence archive; a branch build or
retained validation artifact is not a release. Production signing,
notarization, store distribution, and an update channel remain open until their
recorded gates close. A third-party binary must not be represented as an
official Komms release.

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
