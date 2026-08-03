# 51: Stable-beta pilot and release decision

Komms does not become stable because the implementation backlog is empty or
local tests are green. The final candidate is a revision- and digest-bound
decision package that combines a consent-based pilot, every P0 gate, the
complete final-candidate rerun, support/update commitments, rollback, release
notes, residual risks, and accountable founder approval.

The machine-readable contract is
[`release/stable-beta-plan-v1.json`](../release/stable-beta-plan-v1.json).
[`scripts/stable-beta-readiness.py`](../scripts/stable-beta-readiness.py)
prepares and validates `stable-beta.json`. A stable release-evidence bundle
must contain that record and pass `--require-ready`. Alpha, Beta, and validation
evidence may remain honestly open.

## 1. Present status

The stable-beta decision is **blocked and not authorized**. No consent-based
pilot has run against production-like signed artifacts. All ten P0 gates in the
[release evidence ledger](31-release-evidence-ledger.md) remain open.
Production signing roles are not enrolled, no independent security or
interoperability result exists, no target platform is field-qualified, no
physical radio row has passed, and no plural operator deployment is qualified.

The repository now provides the runnable evidence shape; it does not fill
those rows with invented results. Simulator and localhost results remain local
automated evidence.

## 2. Pilot boundary

The pilot accepts 8–24 consenting participants for no more than 21 days and
requires at least six completed journeys. Entry requires merged P0
implementation changes, green CI, one immutable production-like signed Beta
artifact set, exact install/update/recovery instructions, a restricted consent
store, and explicit authorization to begin.

The participant-facing terms and operational sequence are
[`pilot/v1/CONSENT.md`](../pilot/v1/CONSENT.md) and
[`pilot/v1/RUNBOOK.md`](../pilot/v1/RUNBOOK.md). The public aggregate records:

- install completion;
- contact-establishment success;
- first-message completion within 15 minutes;
- offline-delivery and fallback success;
- controlled crash/recovery success;
- mode comprehension and expected notification behavior;
- critical accessibility blockers; and
- combined support minutes.

The record rejects extra participant fields. It fixes the privacy contract to
no message content, contact graph, stable user identifier, per-user timeline,
or retained raw event stream. Consent records stay restricted and separate.

## 3. Thresholds and defects

The source plan freezes minimum sample counts and thresholds before the pilot.
A completed record recomputes pass/fail from aggregate integers; changing the
word `result` cannot turn a failed metric into a pass. Privacy incidents and
critical accessibility blockers have a threshold of zero.

Critical or high defects stop the pilot. A correction receives a focused
change, regression evidence, new artifacts, and reruns for every affected
matrix row. The candidate cannot be ready while a release-blocking defect is
anything other than `fixed-verified`.

## 4. Final-candidate matrix

The final revision must supply exact evidence for all eleven rows:

| Row | Required evidence |
|---|---|
| Clean install | Named physical field run |
| Distinct ordinary NAT | Named physical endpoint/network run |
| Optional-service blackhole | Named physical endpoint/network run |
| Self-hosted replacement | Operator run plus physical endpoint run |
| Mailbox restart/overload | Durable operator run |
| Backup/recovery | Named physical field run |
| Signed upgrade/rollback | Completed release bundle plus physical field run |
| Supported devices | Named physical field runs |
| Physical radio | Stock-radio on-air run |
| Accessibility | Independent physical accessibility review |
| Conformance | Separately produced independent execution |

Every evidence row includes kind, URI, SHA-256, candidate revision, timestamp,
producer, administrative domain, environment, and explicit
independent/physical flags. Independent kinds require a separately identified
producer and administrative domain. Physical kinds reject simulator, emulator,
or synthetic environments. The validator also rejects a passed row missing any
kind required by the plan.

## 5. P0 audit

`stable-beta.json` contains P0-01 through P0-10 in canonical order. A closed
gate has no open finding, has a closure timestamp, and includes every evidence
kind fixed in the source plan. Removing a gate, replacing an external result
with a project-local one, or closing a row using prose fails validation.

The detailed evidence and open gaps remain in the
[ledger](31-release-evidence-ledger.md). The compact candidate record binds
the final decision to the exact release artifacts rather than replacing that
ledger.

## 6. Support, update, and rollback

A ready candidate names at least a 90-day support window, at least 30 days of
end-of-life notice, active general/security contacts, and the update path for
every artifact class in `release/policy-v1.json`. The update paths remain
authenticated stores where enrolled and bounded manual verification elsewhere;
there is no unqualified automatic updater.

Rollback is selected and tested before the go decision. It either restores
exact prior compatible artifacts or withdraws the candidate and uses a tested
clean restore when no compatible prior release exists. The trigger list
includes signing-key compromise, critical security regression, migration
corruption, widespread install/upgrade failure, custody/receipt regression,
and loss of Sovereign fallback after a provider change.

## 7. Decision and authority

The founder record can say `go` only after the pilot passes, the candidate
matrix passes, every P0 gate closes, release-blocking defects are verified,
and support and rollback are approved. Its scope is deliberately limited to
preparing a stable-beta candidate.

Even a passing record must set merge, publication, and stable-claim authority
to false. The completed release bundle still needs its offline signature and
the existing protected publication checks. Merge, tag, store submission,
deployment, publication, and a stable claim each require a separate explicit
decision.

## 8. Preparing the record

After the artifact inventory and release notes exist:

```sh
python3 scripts/stable-beta-readiness.py prepare \
  --revision <full-revision> \
  --version <version> \
  --artifact-manifest target/artifacts.json \
  --release-notes reviewed/release-notes.md \
  --output reviewed/stable-beta.json
```

The prepared record is valid and intentionally reports `ready=false`. Fill it
only from retained evidence, then run:

```sh
python3 scripts/stable-beta-readiness.py validate \
  --record reviewed/stable-beta.json \
  --artifact-manifest target/artifacts.json \
  --release-notes reviewed/release-notes.md \
  --expected-revision <full-revision> \
  --expected-version <version> \
  --require-ready
```

Stable promotion requires this passing record. Validation, Alpha, and Beta workflows
remain able to describe open work without weakening the stable boundary.
