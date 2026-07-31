# Independent security-review readiness

Komms has a revision-bound external-review package and reproducible source
archive process. It does **not** yet have an assigned reviewer, completed
review, external findings, retest, residual-risk statement, or independent
security assurance.

This document records readiness and the remaining external action. The
canonical P0-06 status remains the
[release evidence ledger](31-release-evidence-ledger.md).

## 1. Review package

The package entry point is
[`security-review/stable-v1/README.md`](../security-review/stable-v1/README.md).
It contains:

- the exact assets, security invariants, architecture/trust boundaries, attack
  surfaces, work packages, source map, build commands, known limitations, and
  exclusions;
- a prepared RFP with independence, team, scope, disclosure, data-handling,
  deliverable, and retest requirements;
- a researched four-candidate shortlist with first-party evidence and
  unresolved diligence;
- a stable finding/severity/disposition/retest/publication format; and
- a bounded deterministic archive policy.

Minimum scope includes PQXDH, Double Ratchet state, downgrade behavior, sealed
envelopes, recipient-authenticated group origins, device authority and
recovery, opaque storage/migration, atomic transitions, first-contact
admission, Connect discovery, mailbox custody, root-free backup/restore, and
malformed input. Rendezvous, wake, RPC, UniFFI, and shell seams remain in scope
where they can violate the stable endpoint contract.

No genuine external findings were supplied while this package was prepared.
The project's documented limitations and audit-finding crosswalk are
maintainer-authored inputs, not external findings.

## 2. Deterministic review target

The review target is an exact committed Git tree. Build its handoff archive
with:

```sh
python3 scripts/security_review_package.py \
  --revision <40-hex-review-revision> \
  --output-dir security-review-artifacts
```

Validate reproducibility without retaining another copy:

```sh
python3 scripts/security_review_package.py \
  --revision <40-hex-review-revision> \
  --check
```

Verify a handed-off archive and its report:

```sh
python3 scripts/security_review_package.py \
  --verify-report <package-report.json> \
  --archive <package.tar.gz>
```

The builder rejects:

- a source tree beyond 4,096 files or 64 MiB;
- symlinks, submodules, special entries, unsafe paths, and duplicate archive
  members;
- omission of any required review document or implementation prefix;
- a tar beyond 96 MiB or compressed archive beyond 64 MiB; and
- an existing output with different bytes.

Tar entry time comes from the fixed commit and gzip time is zero. The report
binds commit, tree, file/byte counts, archive name/size/SHA-256, package
version, required inputs, and the explicit unassigned/no-findings/no-assurance
state. The duplicated source archive is locally generated; its compact digest
report is retained with project evidence.

The prepared target is commit
`5a08e8e2e5cea4a2cad1ec511e97ab16cac53c85`, tree
`626d47e8c79252f592fd13782347b9dc686a55d1`. Its 678 tracked files total
15,509,820 bytes. The deterministic archive is 6,712,258 bytes with SHA-256
`36f1cab72fcaa76efa29134dbe705775afbccd76cf30a7db2d3ffa2ae4ff831e`.
The retained
[package report](../security-review/stable-v1/evidence/komms-security-review-5a08e8e2e5ce.json)
has SHA-256
`b15c7420b9a07abae7804eb49479af391a152b02d734ba0bba4aa62c6f5a254f`.

## 3. Candidate research

The unranked research shortlist is:

- NCC Group Cryptography Services;
- Trail of Bits;
- Least Authority; and
- Cure53.

The selection rationale and first-party sources are in
[`REVIEWERS.md`](../security-review/stable-v1/REVIEWERS.md). Research establishes
only plausible fit. It does not establish current availability, lack of
conflict, the practitioners who would perform the work, sufficient allocation,
publication/retest terms, or an acceptable price.

No candidate has been contacted. Issuing the RFP, discussing commercial terms,
or spending funds requires explicit founder authorization.

## 4. Expected evidence

P0-06 requires one durable chain:

```text
exact source/archive
  -> named conflict-checked external team and accepted scope
  -> initial report and complete finding index
  -> exact correction commits and maintainer dispositions
  -> reviewer retest of every finding
  -> final public report and residual-risk statement
```

Disputed and accepted-risk findings remain visible. A maintainer test is not a
reviewer retest. A private clean-report claim without public scope, findings,
limitations, dispositions, and residual risk does not satisfy the gate.

Independent interoperability is a separate P0-06 requirement. The current
Komms adapter and all 51 cases originate from the Komms implementation process.
A separately produced implementation or fixture producer must run the public
kit with its provenance and independence recorded.

## 5. Remaining action

The one review-readiness action outside the repository is:

> With explicit authorization and an approved budget, issue the prepared RFP,
> select a named conflict-checked team, bind the accepted scope to the retained
> archive digest, and commission the public review plus retest.

Until that occurs, public wording remains “prepared for external review” or
“not independently reviewed,” never “audited,” “approved,” or “certified.”
