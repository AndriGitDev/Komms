# 40: Release evidence bundles

Komms release evidence is a bounded, revision-scoped archive. It records what
was built and tested; it does not convert a simulator, project-controlled
second build, or internal review into physical or independent evidence.

The implementation is
[`scripts/release-evidence.py`](../scripts/release-evidence.py), with separate
validators for
[qualification](../scripts/release-qualification.py) and
[signing](../scripts/release-signing.py). Their regression tests are part of
the local and hosted release gates.

## 1. Bundle inventory

An evidence bundle contains:

| Record | Purpose |
|---|---|
| `source.json` | Exact source revision, tag, version, source-date epoch, collector, and build environments |
| `builders.json` | Bounded public records for every native builder; no stable host identifier or credential |
| `artifacts.json` | Exact path, size, mode, SHA-256, and supported normalized digest for every package |
| `release-evidence.json` | Channel, artifact totals, record digests, build environments, and narrowly stated claims |
| `SHA256SUMS` | Exact inventory of every bundle file except the detached signature |
| `komms.cdx.json` | Deterministic CycloneDX 1.5 aggregate SBOM for both Cargo workspaces and Android locked dependencies |
| `android-licenses.json` | Every locked Android coordinate, revision-controlled declared expression, optional verified POM cross-check, and unresolved count |
| `dependency-policy.json` | Cargo policy results, lockfile digests, Android dependency-lock and verification-metadata results, plus the complete release-toolchain policy and digest |
| `provenance.json` | Local provenance statement; hosted attestations remain separate |
| `reproducibility.json` | Exact, normalized, explicitly explained, different, and missing results between two build records |
| `qualification.json` | Canonical-matrix digest plus named environment and install/upgrade/rollback case rows |
| `signing.json` | Public fingerprint, exact artifact digests, verifier, and status for every signing role |
| `residual-risks.json` | Open risks or the accountable release decision |
| `release-notes.md` | User-visible scope and limitations |
| `SHA256SUMS.sig` | Detached offline release-manifest signature, added only after promotion |

Artifact input is limited to 512 regular files and 16 GiB. Symlinks, path
traversal, unsupported filesystem entries, duplicate checksum rows,
secret-bearing JSON fields, oversized records, and unrecorded files fail
closed. Safe archive extraction applies the same path and size rules. The
publication path separately limits the complete draft to 513 assets and 16 GiB
before downloading anything.

## 2. Local validation bundle

Use an exact clean revision and a staging directory containing only intended
packages:

```sh
revision="$(git rev-parse HEAD)"
epoch="$(git show -s --format=%ct HEAD)"

python3 scripts/release-evidence.py builder-record \
  --revision "$revision" \
  --builder-id local-controlled-1 \
  --os macOS \
  --architecture arm64 \
  --environment "clean controlled release host" \
  --runner-image "named host image and version" \
  --isolated \
  --tool "rustc=$(rustc --version)" \
  --output target/builder.json

python3 scripts/release-evidence.py inventory \
  --artifact-dir target/release-artifacts \
  --revision "$revision" \
  --output target/artifacts.json

python3 scripts/release-qualification.py prepare \
  --revision "$revision" \
  --version 0.3.0 \
  --artifact-manifest target/artifacts.json \
  --output target/qualification.json

python3 scripts/release-signing.py prepare \
  --revision "$revision" \
  --artifact-manifest target/artifacts.json \
  --output target/signing.json

python3 scripts/android-license-evidence.py inventory \
  --repository . \
  --policy release/android-license-policy-v1.json \
  --revision "$revision" \
  --output target/android-licenses.json

python3 scripts/android-license-evidence.py validate \
  --repository . \
  --policy release/android-license-policy-v1.json \
  --record target/android-licenses.json \
  --expected-revision "$revision" \
  --require-complete
```

The source-controlled policy makes a clean host deterministic. Passing
`--gradle-cache /path/to/modules-2/files-2.1` additionally records and compares
available POM declarations. A mismatch fails the complete gate. The inventory
records upstream declarations; it is neither legal advice nor a license
compatibility approval.

Run both Cargo policy gates and the Android dependency build before recording
them as passed. Generate the SBOM and dependency record:

```sh
python3 scripts/release-evidence.py sbom \
  --repository . \
  --revision "$revision" \
  --version 0.3.0 \
  --android-license-report target/android-licenses.json \
  --output target/komms.cdx.json

python3 scripts/release-evidence.py dependency-record \
  --repository . \
  --revision "$revision" \
  --root-cargo-deny passed \
  --desktop-cargo-deny passed \
  --android-dependency-locking passed \
  --android-dependency-verification passed \
  --android-license-report target/android-licenses.json \
  --output target/dependency-policy.json
```

Assemble with `--channel validation`, then verify:

```sh
python3 scripts/release-evidence.py bundle \
  --artifact-dir target/release-artifacts \
  --output-dir target/release-evidence \
  --revision "$revision" \
  --version 0.3.0 \
  --tag v0.3.0 \
  --source-date-epoch "$epoch" \
  --builder target/builder.json \
  --channel validation \
  --sbom target/komms.cdx.json \
  --android-licenses target/android-licenses.json \
  --dependency-policy target/dependency-policy.json \
  --qualification target/qualification.json \
  --signing target/signing.json \
  --residual-risks release/residual-risks-v1.json

python3 scripts/release-evidence.py verify \
  --bundle-dir target/release-evidence \
  --expected-revision "$revision"
```

Generated evidence belongs under ignored `target/` storage until a release
candidate is intentionally retained.

## 3. Reproducibility measurement

Each build gets its own builder record. Run the same revision from a second
clean controlled environment and compare the two evidence manifests:

```sh
python3 scripts/release-evidence.py compare \
  --first first/release-evidence.json \
  --second second/release-evidence.json \
  --output target/reproducibility.json \
  --require none
```

`exact` means byte-for-byte equality. `normalized` means only the explicitly
implemented ZIP-entry or tar-entry normalization agreed; it is not a claim
that arbitrary differences are harmless. `explained` requires both final file
digests, a non-empty explanation, and durable supporting evidence. `different`
and `missing` remain unexplained and block stable promotion. APK, AAB, IPA, and
signed desktop containers commonly include platform-signing or packaging
metadata, so the record reports exact and unsigned-payload measurements
separately where supported.

A project-controlled second build is a reproducibility measurement, not
independence. `independently_verified` remains false until a separately
administered environment supplies a reviewed record. Platform artifacts are
described as measured reproducibility unless the evidence actually establishes
bit-for-bit reproduction.

An independent record must name the separate administrator, environment,
execution time, HTTPS report location and digest, and two distinct builder
identities. Stable validation also requires the report to cover every release
artifact exactly once with no unexplained or missing row:

```sh
python3 scripts/release-evidence.py validate-reproducibility \
  --record reviewed/reproducibility.json \
  --artifact-manifest target/release-artifacts.json \
  --expected-revision "$revision" \
  --require-independent
```

## 4. Qualification records

The source matrix is
[`release/qualification-matrix-v1.json`](../release/qualification-matrix-v1.json).
Every case begins `open`.

The qualification record binds the exact matrix name, version, and SHA-256.
Validation requires every matrix row and case in canonical order; deleting a
platform, environment contract, or required transition fails even when the
remaining summary would otherwise appear complete.

- `observed` records useful simulator, emulator, generic-host, or unsupported
  behavior without creating a supported claim.
- `passed` requires a named supported environment, exact artifact digest,
  start/end time, steps, and result.
- `failed` retains the actual failed run.
- `blocked` identifies an unavailable credential, device, account, network, or
  other external precondition.
- `open` means no run occurred.

The validator rejects a simulator or generic host marked `passed`. Stable
validation adds `--require-complete`, which rejects every open, observed,
blocked, or failed case.

## 5. Promotion and offline signature

A validation bundle is promoted only after the public signing record,
qualification record, reproducibility disposition, residual-risk decision,
and release notes are complete:

```sh
python3 scripts/release-evidence.py promote \
  --bundle-dir target/release-evidence \
  --output-dir target/promoted-evidence \
  --channel alpha \
  --signing reviewed/signing.json \
  --qualification reviewed/qualification.json \
  --reproducibility reviewed/reproducibility.json \
  --residual-risks reviewed/residual-risks.json \
  --release-notes reviewed/release-notes.md
```

Alpha promotion requires a verified release-manifest role plus the native
signing role for every platform artifact actually included. Stable promotion
also requires every policy signing role and artifact class, a completely
passed qualification matrix, no unexplained reproduction difference, genuine
independent reproduction evidence, and an authorized residual-risk decision.
The command copies rather than mutates the validation bundle and recomputes
every record digest.

Stable residual-risk authorization names the exact revision, decision owner,
decision time, durable go/no-go evidence, and a closed or explicitly accepted
disposition for every listed risk. Any `open` risk blocks promotion:

```sh
python3 scripts/release-evidence.py validate-residual-risks \
  --record reviewed/residual-risks.json \
  --expected-revision "$revision" \
  --require-authorized
```

Promotion never substitutes artifact bytes. When platform signing,
notarization, or store packaging changes a package, first assemble a fresh
validation bundle from the final package directory and records bound to those
new digests. Promoting an unsigned bundle and uploading different signed files
is rejected at publication.

Move only `SHA256SUMS` to the offline signing device, compare the bundle and
key fingerprints, sign it as described in
[release security and recovery](39-release-security-and-recovery.md), and
return `SHA256SUMS.sig`. Verify the complete bundle locally before packaging
it. Packaging an Alpha or Stable bundle fails when the detached signature is
absent. The publication workflow separately performs the cryptographic
signature check against the enrolled public key.

Package the completed directory with the exact top-level layout and name:

```sh
python3 scripts/release-evidence.py pack \
  --bundle-dir target/promoted-evidence \
  --output target/Komms-0.3.0-release-evidence.tar.gz
```

The release draft must contain exactly the final top-level package files plus
that one archive. Before publication, the workflow safely extracts and verifies
the bundle, then checks every downloadable package name, byte count, and
SHA-256 against `artifacts.json`:

```sh
python3 scripts/release-evidence.py verify-published-artifacts \
  --artifact-dir target/final-release-assets \
  --manifest target/promoted-evidence/artifacts.json \
  --expected-revision "$revision"
```

The retained hosted archive is named
`Komms-MAJOR.MINOR.PATCH-validation-evidence.tar.gz`; it is deliberately
ineligible for publication. Completed assets are uploaded only after the empty
draft, exact tag, archive digest, and maintainer authorization have been
rechecked. A same-tag asset is never replaced.

No release may be promoted merely by editing the claim booleans. The signing,
qualification, reproduction, and residual-risk records remain independently
validated inputs.

## 6. Hosted evidence and retention

The release workflow:

- uses native Windows, macOS, Linux, Android, and iOS Simulator build paths;
- pins every action to a full commit;
- fixes the release Rust, Gradle, Java, cargo-ndk, and checksum-verified
  XcodeGen versions where applicable, plus the Dockerfile frontend and image
  bases by registry digest;
- records declared licenses for every locked Android coordinate, distinguishes
  Gradle-verified POMs from POM digests bound by the evidence record, and fails
  when a declaration is unknown;
- records each build environment without credentials or stable runner
  identifiers;
- performs two controlled Linux builds and retains their comparison;
- generates the aggregate SBOM and dependency-policy record;
- produces GitHub artifact attestations for retained validation files; and
- retains candidate, build, comparison, and evidence artifacts for 90 days.

Hosted attestations bind GitHub's run identity to candidate files. They are not
the offline release signature, a store signature, physical-device evidence, or
an external reproducibility result.

A validation run may be durable evidence for its exact revision once its run
URL and artifact digest are recorded in the ledger. Expired workflow artifacts
cannot close a durable gate; an authorized release evidence archive must be
retained with the release and in the project's recovery archive.
