# Komms stable-v1 security-review package

**Status:** prepared; external reviewer unassigned; no external findings
received; no independent security assurance claimed.

This directory is the handoff entry point for a qualified review of the
stable-v1 candidate. The review target is an exact Git commit named by the
package report, not a moving branch or an uncommitted working tree.

## Package map

| File | Purpose |
|---|---|
| [`SCOPE.md`](SCOPE.md) | assets, invariants, work packages, architecture, attack surfaces, source map, build instructions, and exclusions |
| [`RFP.md`](RFP.md) | proposed engagement brief, independence conditions, deliverables, disclosure terms, and retest expectations |
| [`REVIEWERS.md`](REVIEWERS.md) | researched candidate shortlist and unresolved diligence |
| [`FINDINGS.md`](FINDINGS.md) | finding, severity, disposition, publication, and retest format |
| [`package.json`](package.json) | bounded source-archive policy and required review inputs |
| [`evidence/komms-security-review-5a08e8e2e5ce.json`](evidence/komms-security-review-5a08e8e2e5ce.json) | retained report for the prepared exact-revision source archive |
| [`../../docs/42-independent-security-review.md`](../../docs/42-independent-security-review.md) | project-facing status and reproduction guide |

The portable protocol contract is
[`conformance/v1/SPECIFICATION.md`](../../conformance/v1/SPECIFICATION.md).
The implementation must not be inferred from that document alone: scope
includes the production state machines, persistence boundaries, network
adapters, RPC/FFI surfaces, and shell integration listed in `SCOPE.md`.

## Reproduce the exact source archive

From a clean checkout of the revision named by the retained package report:

```sh
python3 scripts/security_review_package.py \
  --revision <40-hex-review-revision> \
  --output-dir security-review-artifacts

python3 scripts/security_review_package.py \
  --verify-report security-review-artifacts/komms-security-review-<12-hex>.json \
  --archive security-review-artifacts/komms-security-review-<12-hex>.tar.gz
```

The builder reads only the committed Git tree. It rejects symlinks, submodules,
special entries, missing required inputs, unsafe paths, and source/archive
limits. It uses the commit timestamp for tar members and a zero gzip timestamp.
Two builds of the same commit must be byte-identical:

```sh
python3 scripts/security_review_package.py \
  --revision <40-hex-review-revision> \
  --check
```

The generated JSON report records the complete source revision and tree,
archive name, size, SHA-256 digest, source bounds, required paths, and the
explicitly unassigned review status. The compressed source copy is a handoff
artifact and is not committed back into the source tree.

## Review evidence required for P0-06

Preparing or receiving this package does not close P0-06. Closure requires:

1. a named, conflict-checked reviewer accepting a revision-bound scope;
2. a public scope and methodology record;
3. a complete initial finding set using an equivalent or more precise format;
4. public dispositions for every finding, including disputed and accepted-risk
   items;
5. reviewer retest results against exact correction revisions;
6. a final public report and residual-risk statement; and
7. a separately produced implementation or fixture execution for the distinct
   independent-interoperability portion of P0-06.

Maintainer review, the public conformance adapter, a second build, or a second
in-tree implementation path does not become independent evidence merely by
being packaged here.
