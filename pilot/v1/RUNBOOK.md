# Stable-v1 consent-based Alpha pilot runbook

This runbook prepares the pilot required before a stable-beta candidate. It
does not authorize recruitment, publication, release, spending, deployment,
or use of production credentials.

## 1. Entry conditions

Do not enroll participants until all of these are true:

1. the intended P0 implementation changes are merged and current CI is green;
2. a validation bundle exists for one immutable revision and artifact set;
3. the production-like Alpha artifacts have the required release-manifest and
   platform signatures without exposing signing material to the pilot host;
4. clean-install, update, rollback, backup/recovery, and support instructions
   match those exact artifact digests;
5. the consent text has been reviewed and assigned its immutable version;
6. the coordinator has a restricted location for consent records that is
   separate from product diagnostics and aggregate pilot data; and
7. the founder has explicitly authorized starting this bounded pilot.

If any artifact changes, stop enrollment, assign a new pilot artifact record,
and repeat the relevant entry checks. Never replace bytes under an existing
filename or digest.

## 2. Enrollment

- Enroll 8–24 people, aiming for at least six completed journeys.
- Show every disclosure in `CONSENT.md` before installation.
- Assign a random one-time pilot code. Do not reuse a Komms fingerprint,
  contact, email, phone number, device id, support id, or prior-pilot code.
- Keep the consent record restricted. Give the participant the code and the
  withdrawal contact.
- Record only aggregate counters in the working worksheet. Do not copy the
  one-time code into that worksheet.

No participant is required to share personal contacts or real conversation
content. Use agreed non-sensitive test messages.

## 3. Journey

Record the artifact digest and environment once for the run, then aggregate:

1. install started/completed;
2. contact establishment attempted/completed;
3. first authenticated message completed within 15 minutes;
4. offline mailbox delivery attempted/completed;
5. disclosed fallback attempted/completed;
6. controlled crash or recovery attempted/completed;
7. mode explanation checked/correct;
8. expected notification behavior attempted/observed;
9. critical accessibility blockers found; and
10. combined support minutes.

Record issue severity and category without a participant id or per-user
timeline. Security-sensitive diagnostics follow `SECURITY.md` and remain
outside the public pilot record.

## 4. Aggregation and privacy check

Before producing `stable-beta.json`:

- sum each numerator, denominator, count, and support-minute total;
- remove the raw worksheet if it contains row-level participant data;
- confirm that no message content, contact graph, stable identifier, IP
  address, provider token, or event timeline remains;
- retain only redacted, revision-bound aggregate evidence;
- record withdrawals only as a count; and
- have a second human compare the aggregate totals with the restricted
  worksheet without copying its rows.

Run:

```sh
python3 scripts/stable-beta-readiness.py validate \
  --record reviewed/stable-beta.json \
  --artifact-manifest reviewed/artifacts.json \
  --release-notes reviewed/release-notes.md \
  --expected-revision <40-or-64-hex-revision> \
  --expected-version <version>
```

The ordinary validation accepts an honestly open record. `--require-ready`
must fail until the pilot passes, every final-candidate matrix row passes,
P0-01 through P0-10 close with the required evidence kinds, release-blocking
defects are fixed and verified, support and rollback are approved, and Andri
records a candidate-only go decision.

## 5. Defects and reruns

A critical or high security, privacy, custody, recovery, corruption, install,
upgrade, or widespread availability defect stops the pilot. Preserve the
finding without personal data, correct it in a focused change with a regression
test, produce new artifacts and evidence, and repeat every matrix row affected
by the changed revision.

The final candidate matrix always reruns clean install, distinct NAT,
optional-service blackhole, self-hosted replacement, mailbox restart/overload,
backup/recovery, signed upgrade/rollback, supported devices, physical radio,
accessibility, and independent conformance. A prior simulator, project-local
review, or pilot run against different bytes cannot be relabeled as that
evidence.

## 6. Closeout

At the pilot end:

- record the aggregate outcome and unresolved findings;
- notify participants of the closeout and any safety-relevant limitation;
- honor withdrawals and the restricted-record retention decision;
- publish no row-level data;
- complete the P0 audit, support/update plan, rollback decision, and
  candidate-only founder go/no-go record; and
- prepare—but do not publish—the completed signed evidence bundle.

Merge, tag, release publication, store submission, deployment, and a stable
claim each remain separate actions requiring explicit authorization.
