# Stable-v1 protocol conformance

The portable `komms-stable-v1` contract lives under
[`conformance/v1/`](../conformance/v1/README.md). It is the entry point for a
separately produced implementation and for compatibility review of Komms
itself.

“Stable-v1” identifies a frozen candidate wire/state target. It does not mean
that a Komms product release is stable, independently reviewed, independently
interoperable, or qualified on physical devices.

## 1. Artifact map

| Artifact | Purpose |
|---|---|
| [`SPECIFICATION.md`](../conformance/v1/SPECIFICATION.md) | stand-alone normative endpoint, wire, state, bounds, error, and compatibility contract |
| [`ADAPTER.md`](../conformance/v1/ADAPTER.md) | bounded JSON-lines interface used to exercise another implementation |
| [`cases/`](../conformance/v1/cases) | language-neutral known answers, negative results, and transition traces |
| [`fixtures/`](../conformance/v1/fixtures) | exact valid, malformed, and compatibility bytes |
| [`packets/`](../conformance/v1/packets) | synthetic packet capture and secret-free index |
| [`manifest.json`](../conformance/v1/manifest.json) | size and SHA-256 inventory for normative/generated kit files |
| [`run.py`](../conformance/v1/run.py) | dependency-free manifest, schema, fixture, and adapter verifier |

The normative order and conflict behavior are fixed by
[ADR-0035](adr/0035-stable-v1-protocol-and-conformance-kit.md). A discrepancy
is corrected through compatibility review; an implementation does not select
whichever artifact is easiest to satisfy.

## 2. Verify the published kit

From the repository root:

```sh
python3 conformance/v1/run.py
cargo build --locked -p kult-conformance
python3 scripts/update-conformance-vectors.py \
  --check --adapter target/debug/kult-conformance
python3 scripts/build-conformance-kit.py --check
python3 conformance/v1/run.py \
  --adapter target/debug/kult-conformance
cargo test --locked -p kult-conformance
```

These commands verify the file manifest and case schemas, ensure committed
answers and generated binary artifacts have not drifted, run the cases against
Komms, and prove that Komms consumes the public fixtures.

## 3. Run another implementation

Implement the bounded process contract in
[`ADAPTER.md`](../conformance/v1/ADAPTER.md), then run:

```sh
python3 conformance/v1/run.py \
  --adapter /absolute/path/to/implementation-adapter \
  --implementation "name and immutable revision" \
  --report /absolute/path/to/conformance-result.json
```

The result includes the kit manifest digest, adapter digest, complete case
result list, and execution time. It deliberately records
`independent_execution_claimed: false`; independence, provenance, build
inputs, platform, limitations, and the responsible party must be established
outside the self-reported result.

An external evidence package must contain:

- the exact Komms kit version and manifest digest;
- the other implementation's immutable source revision and adapter digest;
- build instructions and relevant dependency locks;
- operating system, architecture, and compiler/runtime versions;
- the unmodified result file and command;
- any unsupported optional operations or deviations; and
- a statement explaining organizational and implementation independence.

## 4. Change control

Maintainer regeneration is:

```sh
cargo build --locked -p kult-conformance
python3 scripts/update-conformance-vectors.py \
  --write --adapter target/debug/kult-conformance
python3 scripts/build-conformance-kit.py --write
```

Regeneration is not a routine formatting step. Changing an existing answer,
fixture, field meaning, state result, or acceptance outcome requires explicit
compatibility review. Breaking behavior receives a new profile or major kit
version. A compatible addition receives a reviewed minor version and leaves
all prior answers unchanged.

## 5. Evidence boundary

Passing the kit demonstrates agreement with the cases it contains. It does not
establish protocol security, correct constant-time behavior, production
hardening, independent interoperability, external review, physical-device
qualification, or optional-service availability.

The remaining P1-03 action is one retained execution by a separately produced
implementation or fixture producer. P0-06 additionally requires a qualified
external security review with published findings, dispositions, retest
results, and residual risks. Until those events occur, both gates remain
visibly open in the
[release evidence ledger](31-release-evidence-ledger.md).
