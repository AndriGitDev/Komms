# 25: Release runbook

Komms uses one immutable source tag to create retained validation artifacts,
then separate protected operations to create an empty private draft, upload an
externally completed asset set, and publish it. A tag push never creates or
edits a release.

The historical public `v0.3.0` Alpha predates this release-evidence design. Its
unsigned desktop and debug-signed Android packages remain test artifacts, not
evidence that the production-signing or stable gates are closed.

## 1. Prepare source and versions

Update every version surface:

1. root Cargo workspace;
2. desktop crate and Tauri bundle;
3. Android `versionName` and monotonically increasing `versionCode`; and
4. iOS short version and monotonically increasing build number.

Validate the intended tag:

```sh
python3 scripts/check-release-version.py v0.4.2
```

Run the complete local matrix. Require every platform SDK promised by this
candidate:

```sh
KOMMS_REQUIRE_ANDROID_APP=1 \
KOMMS_REQUIRE_IOS_APP=1 \
scripts/local-release-matrix.sh
```

Record the clean commit, toolchain versions, complete output, and every
external or deferred row. A local green run cannot close a credential,
supported-system, physical-device, real-network, radio, independent-review, or
external-reproduction gate.

After explicit authorization, create an annotated semantic-version tag on the
reviewed commit and push that tag. The tag-triggered workflow has read-only
repository permission. It:

- checks the exact tag and source-date epoch;
- builds unsigned validation packages on native runners;
- builds the Linux artifacts in a second controlled environment;
- tests and inspects both Android flavors;
- builds an unsigned iOS Simulator application;
- inventories every package and build environment;
- emits dependency policy, CycloneDX SBOM, qualification, signing, residual
  risk, reproducibility, stable-beta readiness, provenance, and checksum
  records;
- verifies the complete bounded bundle;
- creates hosted artifact attestations; and
- retains workflow artifacts for 90 days.

It does not create a GitHub release, publish a container, use a production
credential, or make a stable claim.

## 2. Review validation evidence

Download `release-evidence-bundle` and `validation-candidate-assets` from the
exact workflow run. Verify:

```sh
python3 scripts/release-evidence.py verify \
  --bundle-dir release-evidence \
  --expected-revision <full-tag-revision>
```

Review:

- source, version, tag, and source-date epoch;
- every artifact digest and build record;
- Cargo policy and Android lock/verification records;
- exact, normalized, explained, different, and missing reproducibility rows;
- open or observed qualification rows;
- every open signing role; and
- residual risks, the honestly open stable-beta record, and release notes.

The first hosted comparison is not independent reproduction. The iOS
Simulator archive and unsigned packages are validation evidence only.

## 3. Optionally create an empty private draft

Draft creation is a distinct manual workflow run. Select the same tag, enable
`create_draft`, leave `publish` and `production_signing` disabled, and enter:

```text
DRAFT vMAJOR.MINOR.PATCH
```

The protected `release-draft` environment requires a maintainer reviewer. The
job accepts only an absent release or an empty draft for the exact existing
tag. It leaves the release private, marked prerelease, and empty. Validation
packages remain the workflow artifact `validation-candidate-assets`; they are
not downloadable release packages and cannot collide with completed signed
assets.

If a draft already contains an asset, investigate instead of deleting or
overwriting it. A new candidate gets a new version/tag or an explicitly
recorded aborted-draft disposition.

## 4. Complete production signing and qualification

Follow [release security and recovery](39-release-security-and-recovery.md).
Private keys and credentials cross only their explicit human or protected
environment boundaries. Never place them in source, evidence JSON, logs,
issues, release notes, or ordinary workflow inputs.

For each production artifact:

1. verify the source revision before signing;
2. sign through the enrolled role;
3. run the platform verifier and record the public fingerprint and exact
   artifact digest;
4. perform clean install, authenticated upgrade, failed-upgrade recovery,
   rollback, old-version compatibility, and the declared update path on a
   named supported environment;
5. retain failed and blocked rows honestly; and
6. obtain the separately administered reproduction or review evidence required
   by the intended channel.

Complete the public `signing.json`, `qualification.json`,
`reproducibility.json`, `residual-risks.json`, `stable-beta.json`, and release
notes. The stable-beta record follows the consent, final matrix, gate audit,
support, rollback, and founder-decision procedure in
[stable-beta pilot and release decision](51-stable-beta-pilot-and-release-decision.md).
Promote the final-artifact validation bundle with the command in
[release evidence bundles](40-release-evidence-bundles.md). Stable promotion
fails unless every required role and qualification row is closed, reproduction
has no unexplained difference, genuine independent reproduction is recorded,
the release owner authorizes the residual-risk decision, and the stable-beta
readiness record passes.

If platform signing or notarization changes any package byte, stage those final
packages, regenerate `artifacts.json`, signing and qualification records, and a
fresh validation bundle before promotion. Do not promote the hosted unsigned
bundle while substituting signed files afterward. Promotion copies the exact
artifact bytes it was given.

The offline release-manifest device signs the promoted `SHA256SUMS`. Return
only `SHA256SUMS.sig`. Verify the public signature, safely package the promoted
directory as exactly
`Komms-MAJOR.MINOR.PATCH-release-evidence.tar.gz` with a top-level
`release-evidence/` directory, and retain its digest.

Before upload, require the release draft to still have no assets. Upload all
final packages and the one completed evidence archive together. Never upload
the retained validation packages, a `*-validation-evidence.tar.gz` archive, or
an unpromoted bundle to the release. Never replace or delete a same-tag asset;
an aborted candidate gets a recorded disposition and a new version where
needed.

From a clean maintainer host, verify the staged set and then use one bounded
upload invocation:

```sh
python3 scripts/release-evidence.py verify-published-artifacts \
  --artifact-dir target/final-release-assets \
  --manifest target/promoted-evidence/artifacts.json \
  --expected-revision <full-tag-revision>

python3 scripts/release-evidence.py pack \
  --bundle-dir target/promoted-evidence \
  --output target/Komms-MAJOR.MINOR.PATCH-release-evidence.tar.gz

gh release upload vMAJOR.MINOR.PATCH \
  target/final-release-assets/* \
  target/Komms-MAJOR.MINOR.PATCH-release-evidence.tar.gz \
  --repo AndriGitDev/Komms
```

GitHub asset upload is not transactional. If only part of the invocation
succeeds, stop and record the draft as aborted; do not delete, replace, or
`--clobber` the partial set into a release.

## 5. Required human visual gate

Preview the exact candidate artifacts on:

1. an Android environment appropriate to the claimed row;
2. an iOS environment appropriate to the claimed row;
3. each claimed macOS hardware/OS cell;
4. each claimed Windows cell; and
5. each claimed Linux distribution/desktop cell.

Create a
[Release visual approval](../.github/ISSUE_TEMPLATE/release-visual-approval.md)
issue with revision, artifact digest, environment, screenshots or recording,
findings, retest results, and final maintainer decision. Screen-capture
protection may require a live review; do not weaken it to manufacture a
screenshot. Simulator preview evidence remains `observed`, not physical-device
qualification.

## 6. Publish deliberately

Publication is a new manual run against the same tag. Select `alpha`, `beta`,
or `stable`, enable `publish`, leave build/draft/signing inputs disabled, provide
the completed visual-review issue, and enter:

```text
PUBLISH vMAJOR.MINOR.PATCH
```

The protected `release-publication` environment requires a maintainer
reviewer. It resolves the supplied visual-approval issue, requires the project
label, closed state, exact release tag, and no unchecked requirement, and
retains the normalized issue metadata for a final recheck. Before downloading,
the job also requires an existing draft, an exact completed-evidence filename,
at most 513 assets, and at most 16 GiB across the asset set. It then downloads
every asset and:

- safely extracts it with bounded path and size checks;
- verifies every bundle checksum and the exact tag revision;
- verifies the offline OpenSSH signature against the enrolled public key and
  namespace;
- validates the signing roles required by the selected channel;
- validates the qualification matrix, requiring complete passes for stable;
- requires the downloadable package names, sizes, and SHA-256 values to match
  `artifacts.json` exactly, with no missing or extra asset;
- requires the evidence channel to equal the selected channel; and
- for stable, requires production-signing, independent-reproduction, and
  stable-qualification claims backed by their records.

It rechecks the visual issue, draft state, and immutable asset metadata after
verification. Only then does it change the unchanged package set to a public
prerelease or stable release and replace the draft notes with the signed
evidence notes. It does not rebuild or re-sign assets. Container publication
and store submission remain separately authorized operations.

## 7. Current stopping point

Validation artifacts and evidence can be produced locally and in hosted CI.
Production signing, store submission, and stable publication are blocked on the
credential enrollment, supported-system qualification, independent evidence,
and physical field rows listed in the
[release evidence ledger](31-release-evidence-ledger.md). Do not bypass those
blocks by publishing unsigned packages under stable wording.
