# ADR-0035: Stable-v1 protocol and conformance kit

- **Status**: Accepted; conformance kit implemented; independent execution gate open
- **Date**: 2026-07-31
- **Depends on**: all accepted stable-v1 protocol and state ADRs

## Context

Komms has protocol descriptions, accepted ADRs, codec tests, and
implementation tests, but those sources serve different purposes. An
implementation-specific test suite is not a sufficient contract for a
separately produced implementation. The stable-v1 candidate needs one
language-neutral description, exact fixtures, negative behavior, transition
traces, and explicit compatibility rules.

Calling an in-tree encode/decode round trip independent interoperability would
also overstate the evidence. Compatibility artifacts and independent execution
are separate deliverables.

## Decision

### 1. The versioned kit is the portable protocol contract

`conformance/v1/` contains:

- the stand-alone normative stable-v1 specification;
- the bounded version-1 adapter contract;
- ordered language-neutral known-answer and state-transition cases;
- valid, malformed, and compatibility fixtures;
- a synthetic secret-free packet capture; and
- a complete digest manifest for normative and generated kit files.

The specification does not require knowledge of Rust types or source prose.
Optional services are identified separately from endpoint requirements and
have no authority to change message identity, cryptographic trust, or delivery
semantics.

### 2. Conflicts fail visibly

Normative precedence is:

1. the stand-alone specification;
2. exact cases and binary fixtures; then
3. the adapter contract.

Any disagreement is a profile defect. Implementations fail the affected case
until an explicit compatibility change corrects the contract; they do not
choose the most permissive interpretation.

### 3. Stable-v1 changes are versioned

The `komms-stable-v1` profile and kit `1.x` preserve already published wire
bytes, state meanings, accept/reject outcomes, and downgrade behavior.

- Clarifications that do not change observable behavior may update prose.
- Compatible additions require a reviewed minor kit version and cannot change
  an existing case answer.
- A change to existing canonical bytes, field meaning, transition semantics,
  or accept/reject behavior requires a new profile or major kit version.
- Deprecated formats retain their declared decode/migration behavior for the
  compatibility period; they are not silently rewritten as stronger history.

Every change to a normative artifact regenerates the manifest and passes the
in-tree implementation plus fixture-consumption gates.

### 4. Komms consumes the public fixtures

Primitive known-answer tests read the committed public case files. The
`kult-conformance` adapter exercises the same production codecs and protocol
state machines exposed by the rest of Komms, with a deterministic byte stream
confined to public fixture construction.

The adapter never reads a production profile, keystore, network state, or
credential. It has fixed request, response, case, allocation, and execution
bounds.

### 5. Evidence labels remain honest

An in-tree execution establishes only that this revision agrees with its
published kit. It is not:

- independent interoperability;
- independent cryptographic or security review;
- a side-channel or production-hardening assessment;
- physical-device or service qualification; or
- proof that every optional deployment is available.

Independent interoperability remains open until a separately produced
implementation or fixture producer runs the published kit and its provenance
and development independence are recorded. P0-06 also remains open until a
qualified external security reviewer publishes scope, findings, dispositions,
and residual risk.

## Alternatives considered

### Treat Rust tests as the specification

Rejected. That makes the implementation its own only source of truth and
requires another implementer to infer semantics from private types and control
flow.

### Publish vectors without negative and state behavior

Rejected. Matching a few primitive outputs would not constrain replay,
rollback, fork, malformed-input, recovery, lease, or downgrade handling.

### Label a second in-tree path independent

Rejected. A second path produced under the same implementation process can be
useful differential evidence, but it does not establish independent
interoperability.

## Consequences

- Stable-v1 wire and state changes now have an explicit compatibility boundary.
- Reviewers and other implementers have one portable entry point.
- The repository must keep implementation tests and public fixtures in sync.
- P1-03 has implemented artifacts but remains open until a genuinely
  independent execution is retained.
- P0-06 remains open for external security review and independent
  interoperability evidence.

## Implementation status

The version-1 specification, adapter, 51-case suite, binary fixtures, synthetic
packet capture, manifest checks, and Komms fixture-consumption tests are
implemented in the repository. Revision-bound local and hosted results are
recorded separately in the evidence ledger; independent execution and external
review remain unassigned.
