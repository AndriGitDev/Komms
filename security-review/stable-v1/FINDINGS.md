# Security finding, disposition, and retest format

## 1. Current finding status

No genuine external findings have been supplied for this review target. This
file defines the intake and publication shape; it is not a finding list and
must not be cited as evidence of review.

## 2. Stable finding record

Every finding receives an immutable identifier such as `KSR-2026-001`.
Corrections, severity discussion, disposition, and retest append to that
record; they do not replace the original description.

Required fields:

| Field | Meaning |
|---|---|
| Identifier | Stable reviewer/project finding id |
| Title | Short, factual failure description |
| Reviewer severity | Reviewer's original severity and rubric |
| Status | Current lifecycle value from §4 |
| Target | Exact source revision, archive digest, component, path/symbol, and protocol/state version |
| Assets/invariants | Exact `SCOPE.md` asset and invariant violated or weakened |
| Adversary and preconditions | Required capability, access, timing, state, user action, and configuration |
| Description | Root cause and violated assumption |
| Impact | Confidentiality, integrity, authenticity, availability, privacy, recovery, or assurance consequence |
| Exploit path | Bounded steps, trace, proof, or counterexample sufficient to reproduce |
| Reach and persistence | Affected peers/devices/messages/epochs and whether effects survive restart, restore, rotation, or correction |
| Detection and recovery | Observable signals, containment, user/operator action, and irreversible effects |
| Evidence | Non-secret fixture, test, packet/state trace, proof-of-concept, or analytical argument |
| Recommendation | Security property the correction must establish; optional implementation guidance separately labelled |
| Maintainer disposition | `fix`, `mitigate`, `accepted-risk`, `disputed`, or `duplicate`, with rationale and owner |
| Correction | Exact commits, tests, migrations, compatibility impact, and release/user action |
| Reviewer retest | Exact revision/artifact, steps, result, remaining exposure, and reviewer/date |
| Publication | Initial/final report version, embargo/redaction reason if any, and public link |

Secrets, private user data, exploit credentials, and reporter identity belong
in a separately controlled attachment, not the public record.

## 3. Severity rubric

Severity is based on plausible impact and exploitability in the stated threat
model, not fix size, scheduling pressure, or whether a regression test is easy.

| Level | Guideline |
|---|---|
| **Critical** | Practical compromise of message/account/release authority or broad plaintext/secret exposure with little user-specific access; unrecoverable or ecosystem-wide impact; or a stable security claim fundamentally false |
| **High** | Serious confidentiality, authenticity, authority, recovery, durable-custody, or cross-user isolation failure under realistic attacker capabilities, including persistent targeted compromise or remotely reachable resource exhaustion with major service/product impact |
| **Medium** | Material bounded security/privacy failure requiring stronger preconditions, narrower scope, meaningful user action, or limited persistence; defense-in-depth failure that composes into a realistic higher-impact path |
| **Low** | Limited impact, unlikely preconditions, small information leak, local hardening gap, or contract inconsistency that does not presently create a practical major compromise |
| **Informational** | Useful hardening, clarity, test, or assurance observation with no demonstrated security impact |

The report should separately state exploitability, affected population/scope,
detectability, persistence, recovery cost, and confidence. CVSS or another
rubric may supplement this table but must not erase protocol-specific
reasoning.

Severity disagreement is recorded as two positions. The maintainer cannot
silently lower the reviewer's rating, and the reviewer cannot silently replace
the project's disposition.

## 4. Finding lifecycle

Allowed states:

```text
reported
  -> acknowledged
  -> fix-in-progress
  -> fixed-awaiting-retest
  -> retest-passed | retest-failed | partially-fixed

reported
  -> disputed | accepted-risk | duplicate
```

- `reported`: delivered by the reviewer; no maintainer conclusion yet.
- `acknowledged`: reproduced or analytically accepted.
- `fix-in-progress`: a correction is being prepared; not evidence of safety.
- `fixed-awaiting-retest`: maintainer tests pass at an exact commit, but the
  reviewer has not validated it.
- `retest-passed`: reviewer repeated the relevant method against the exact
  correction and found the stated issue resolved.
- `retest-failed`: the original issue remains or the correction is bypassable.
- `partially-fixed`: impact or reach is reduced but residual exposure remains.
- `disputed`: parties disagree; both complete arguments remain public.
- `accepted-risk`: the maintainer knowingly leaves the issue, with rationale,
  user impact, owner, expiry/review date, and compensating control.
- `duplicate`: mapped to another immutable finding without losing evidence.

Only the reviewer sets a retest result. Local regression success remains
maintainer evidence and is labelled accordingly.

## 5. Correction and regression requirements

For each accepted issue:

1. reproduce it against the original exact revision;
2. add the smallest safe negative/regression test or formal counterexample
   check;
3. identify wire/state/storage/backup/compatibility and user-action impact;
4. implement focused corrections without rewriting unrelated history;
5. run the relevant scoped and release gates;
6. record exact commit and test output;
7. supply the reviewer a deterministic correction package; and
8. publish the original finding, disposition, retest, and residual risk.

Security-sensitive migrations must cover crash/restart, rollback, stale input,
and mixed-version behavior. A format change requires the compatibility process;
it cannot be hidden as an implementation-only fix.

## 6. Public disposition index

The public machine-readable index should contain, at minimum:

```json
{
  "schema": "komms-security-review-findings/v1",
  "review_target": {
    "revision": "<40-hex>",
    "archive_sha256": "<64-hex>"
  },
  "report": {
    "reviewer": "<named external reviewer>",
    "initial_version": "<version/date>",
    "final_version": "<version/date-or-null>"
  },
  "findings": [
    {
      "id": "KSR-2026-001",
      "reviewer_severity": "high",
      "status": "fixed-awaiting-retest",
      "affected_revision": "<40-hex>",
      "correction_revisions": ["<40-hex>"],
      "retest_revision": null,
      "retest_result": null,
      "residual_risk": "<concise statement>"
    }
  ]
}
```

An empty list is valid only when a named reviewer completed the accepted scope
and explicitly reported no findings. The current project state has no such
record.

## 7. Embargo and redaction record

Every delayed or redacted item records:

- finding id and severity;
- initial report date;
- agreed public date;
- exact reason and affected users/services;
- parties approving the change;
- next review date; and
- the public fields that remain visible.

Scheduling, reputation, or an inconvenient correction is not a sufficient
reason to hide a finding. Redaction protects people, credentials, user data,
or a still-live exploit path; it does not manufacture a clean report.
