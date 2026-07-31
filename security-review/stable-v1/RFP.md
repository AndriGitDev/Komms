# Request for proposal: Komms stable-v1 security review

## 1. Status

This is a prepared engagement brief, not an issued request. No candidate has
been contacted, no commercial terms have been accepted, no funds have been
committed, and no reviewer has been assigned.

The project seeks a qualified external team to review the exact revision and
scope in this package before stable security claims. The engagement should
combine applied cryptographic protocol analysis with Rust systems,
persistence/state-machine, parser, and integration review.

## 2. Requested response

A proposal should state:

1. the legal contracting entity and every practitioner expected to perform
   material review work;
2. each practitioner's relevant secure-messaging, applied-cryptography, Rust,
   distributed-state, storage, parser/fuzzing, and mobile/FFI experience;
3. present or recent relationships with Komms, its maintainer, material
   dependencies, shortlisted operators, or competing products that could
   create an actual or perceived conflict;
4. proposed work-package coverage, reviewer-days by discipline, review
   method, assumptions, and explicitly excluded areas;
5. preparation needs, target start, active-review duration, reporting window,
   and reserved retest window;
6. fixed or capped price, currency, taxes/expenses, payment milestones, and
   expiry of the proposal;
7. subcontractors, data locations, source-retention policy, access controls,
   and deletion date;
8. willingness to produce the public artifacts in §5 and accept the
   disclosure terms in §6; and
9. references to comparable public reports.

Availability, team composition, scope fit, conflicts, publication terms, and
price are selection gates. A recognizable organization name alone is not
sufficient.

## 3. Independence requirements

The selected reviewers must:

- be organizationally outside the implementation and release decision;
- not have authored the reviewed Komms design or implementation;
- disclose financial, employment, close personal, operator, dependency, and
  competitive relationships relevant to impartiality;
- retain freedom to report unfavorable findings, incomplete coverage,
  disputed dispositions, and residual risk;
- identify the people who actually performed the work and the review period;
  and
- distinguish their own analysis from maintainer-provided claims and tests.

The founder remains accountable for remediation and the release decision.
Reviewer independence supplies assurance evidence; it does not transfer product
authority or permit a reviewer's name to be used beyond the final report's
actual conclusion.

## 4. Required technical coverage

The minimum engagement is all four work packages in
[`SCOPE.md`](SCOPE.md):

- WP1 protocol design and cryptographic composition;
- WP2 identity, device authority, recovery, opaque storage, migration, backup,
  and atomicity;
- WP3 first contact, capability-scoped discovery, mailbox custody,
  rendezvous, and wake; and
- WP4 malformed input, denial-of-service bounds, daemon/RPC/FFI, shell
  integration, and trust seams.

At least one named practitioner should have demonstrated applied cryptography
experience and at least one should have demonstrated Rust systems/security
review experience. One person may satisfy both, but the proposal should explain
how independent internal checking occurs for high-impact conclusions.

The review must cover, at minimum: PQXDH, Double Ratchet transitions, downgrade
behavior, sealed envelopes, device authority/recovery, opaque storage and
migrations, atomic transitions, recipient-authenticated group origins, first
contact, Connect discovery, mailbox custody, backup/restore, and malformed
input behavior.

## 5. Expected deliverables

### Before active review

- signed or otherwise authenticated acceptance of the exact source revision,
  archive digest, scope, named team, conflicts, schedule, and publication
  terms;
- confirmation that the package builds or a bounded setup-gap list; and
- a short test plan mapping intended methods to the four work packages.

### During review

- promptly communicated critical/high candidates through the private security
  channel;
- reproducible evidence or a precise argument for every proposed finding;
- a running list of coverage blockers and requested clarifications; and
- no unapproved access to production users, services, accounts, credentials,
  or third-party systems.

### Initial report

- exact revision/archive digest, dates, practitioners, person-days, methods,
  scope, exclusions, setup, and limitations;
- architecture/threat-model assessment;
- one record per finding using
  [`FINDINGS.md`](FINDINGS.md) or a format carrying all equivalent fields;
- positive observations clearly separated from assurance claims;
- unreviewed areas and residual risks; and
- a machine-readable finding index.

### Remediation and retest

- one bounded clarification round;
- a reserved retest of exact correction commits;
- status, evidence, remaining exposure, and new-regression observations for
  every finding; and
- explicit treatment of disputed, accepted-risk, partially fixed, and
  non-reproducible items.

### Final public package

- a public report containing the accepted scope, methods, all findings and
  severities, dispositions, retest results, limitations, and residual risk;
- the machine-readable finding/disposition index;
- non-secret proof-of-concept, vector, trace, or harness artifacts that are
  necessary to reproduce conclusions and safe to publish; and
- a statement that the review is time- and scope-bounded and does not
  guarantee security.

The project will publish maintainer dispositions beside the reviewer's final
status. A correction is not described as reviewer-verified until the reviewer
has actually retested its exact revision.

## 6. Disclosure and embargo proposal

The default outcome is a public final report. Proposed terms are:

1. findings remain private during active review and coordinated remediation;
2. critical/high issues are disclosed to the security coordinator as soon as
   reasonably validated;
3. the parties agree an initial public date based on exploitability and safe
   correction, targeting no later than 90 days after delivery of the initial
   report;
4. an extension requires a written public-date update and reason; it must not
   erase the finding, lower severity for scheduling convenience, or imply a
   passed review;
5. imminent user harm may require accelerated coordinated disclosure;
6. narrowly tailored redaction may protect reporter identity, user data,
   credentials, or still-exploitable operational detail, but the finding's
   existence, severity, affected scope, disposition, and residual risk remain
   visible; and
7. reviewers may state disagreement with a maintainer disposition in the final
   report.

The final contract may refine timing, but a permanently private report or a
right to suppress unfavorable conclusions does not satisfy P0-06.

## 7. Severity and disposition

The project proposes the five-level rubric and lifecycle in
[`FINDINGS.md`](FINDINGS.md). A reviewer may use its established rubric if the
report explains the mapping and preserves impact, exploitability,
preconditions, affected assets, scope, and recovery.

The maintainer owns remediation disposition; the reviewer owns the accuracy of
its finding and retest conclusion. Neither side silently rewrites the other's
position. Every original identifier remains stable through correction and
retest.

## 8. Access and data handling

The ordinary review target is public source plus the deterministic package.
No production secrets or user data are required. If a private coordination
system is agreed later, access must be least-privilege, named, time-bounded,
revocable, and excluded from ordinary logs/recordings where practical.

The proposal must state:

- where source copies, communications, findings, and proof-of-concept data are
  stored;
- who can access them;
- backup and subcontractor boundaries;
- incident notification terms; and
- deletion/return timing after the final report.

Test accounts, provider credentials, store credentials, signing material,
production infrastructure access, and physical devices are not granted by this
brief.

## 9. Acceptance and closure

Commercial selection and spending require explicit founder authorization.
Technical acceptance requires a complete proposal, conflict review, agreed
revision/scope, and a publication/retest commitment.

Completing an engagement does not automatically close P0-06. The ledger closes
only after durable public scope, findings, dispositions, retest, residual-risk,
and separate independent-interoperability evidence are linked to exact
revisions.
