# Komms stable-v1 conformance kit

This directory is the portable protocol truth for the frozen
`komms-stable-v1` candidate profile. It is independent of a programming
language and contains:

- the stand-alone normative [specification](SPECIFICATION.md);
- the version-1 [adapter contract](ADAPTER.md);
- ordered JSON known-answer and state-transition cases;
- valid, malformed, and compatibility binary fixtures;
- a secret-free synthetic reference packet capture;
- a dependency-free runner; and
- a SHA-256 manifest for every normative or generated kit file.

“Stable-v1” identifies a compatibility target. It does not claim that a Komms
product release is stable, independently reviewed, interoperable with an
independently produced implementation, or qualified on physical devices.

## Verify this copy

From the repository root:

```sh
python3 conformance/v1/run.py
```

The runner rejects missing, extra-manifested, changed, oversized, non-regular,
or symlinked normative/generated kit files; validates the case schemas and
references; and checks every SHA-256 digest in `manifest.json`. Result files
under `evidence/` are deliberately excluded so a run cannot make its own input
manifest stale. A signed release evidence bundle must authenticate the
manifest itself. A digest list inside the same untrusted archive is an
integrity check, not publisher authentication.

## Run an implementation

An implementation exposes the bounded JSON-lines interface in
[ADAPTER.md](ADAPTER.md). Run it with:

```sh
python3 conformance/v1/run.py \
  --adapter /absolute/path/to/conformance-adapter
```

The in-tree implementation is exercised with:

```sh
cargo build -p kult-conformance
python3 conformance/v1/run.py \
  --adapter target/debug/kult-conformance
```

To retain a machine-readable result:

```sh
python3 conformance/v1/run.py \
  --adapter /absolute/path/to/conformance-adapter \
  --implementation "implementation name and revision" \
  --report /absolute/path/to/result.json
```

The runner deliberately writes `independent_execution_claimed: false`. A
reviewer or implementer must establish independence, provenance, environment,
and revision outside this mechanical result. Passing the kit is necessary
compatibility evidence; it is not a security audit.

## Case and artifact layout

`kit.json` fixes case-file order. A case has a stable id, purpose, adapter
operation, arguments, and exact expected success or error. Later cases may
refer only to a prior committed answer. Compact expressions are resolved
before an adapter sees a request:

| Expression | Meaning |
|---|---|
| `{"$utf8_hex":"text"}` | UTF-8 bytes encoded as lowercase hex |
| `{"$repeat_hex":{"byte_hex":"aa","bytes":32}}` | one byte repeated a bounded number of times |
| `{"$concat_hex":[...]}` | concatenated resolved hex strings |
| `{"$pad_hex":{"prefix_hex":...,"length":4096,"byte_hex":"00"}}` | exact-width byte padding |
| `{"$xor_hex":{"value":...,"offset":7,"byte_hex":"01"}}` | one bounded byte mutation |
| `{"$case":{"id":"prior-id","pointer":"/result/value"}}` | RFC 6901 pointer into a prior answer |

`artifacts.json` maps selected case fields to binary files. The build script
also creates `packets/reference-v1.pcapng` with link type USER0 (147). Every
packet uses published synthetic vector material; no production credential,
address, token, relationship, or message appears in it.

## Maintainer regeneration

Regeneration is an intentional compatibility action:

```sh
cargo build -p kult-conformance
python3 scripts/update-conformance-vectors.py \
  --write --adapter target/debug/kult-conformance
python3 scripts/build-conformance-kit.py --write
```

Ordinary gates use non-mutating checks:

```sh
python3 scripts/update-conformance-vectors.py \
  --check --adapter target/debug/kult-conformance
python3 scripts/build-conformance-kit.py --check
```

Changing an expected answer, binary fixture, state trace, field meaning, or
accept/reject result requires compatibility review. A breaking change requires
a new profile or major kit version; it must not silently rewrite this kit.
