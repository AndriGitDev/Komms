# 39: Release security and recovery

**Status:** implemented validation controls; production credential enrollment
and supported-platform qualification are open

**Accountable owner:** Andri

**Stable release authority:** not authorized

Komms separates source validation, native builds, platform signing, draft
creation, completed-asset upload, and public publication. A successful build does not confer release
authority, and a tag push has no repository write permission. The canonical
machine-readable policy is
[`release/policy-v1.json`](../release/policy-v1.json).

No production signing private key, store credential, provisioning profile, or
publication token is stored in the repository. None was generated while
preparing this policy.

## 1. Release authority is split by operation

The hosted release path has four boundaries:

1. A tag push checks out the exact tag without persisted credentials, builds
   validation packages on native runners, performs a second controlled Linux
   build, creates an SBOM and evidence bundle, and retains the workflow
   artifacts for 90 days. Every build job is read-only.
2. A manually dispatched `release-draft` job requires the exact phrase
   `DRAFT vMAJOR.MINOR.PATCH` and a protected-environment reviewer. It creates
   or confirms an empty private draft. Validation packages remain expiring
   workflow artifacts and are never mistaken for release attachments.
3. Production platform signing and offline manifest signing occur only after
   explicit enrollment. The completed public signing record names public
   fingerprints and exact artifact digests. A maintainer uploads the completed
   packages and one completed evidence archive together to the empty draft,
   without replacing names. Signing material never enters an ordinary
   validation job.
4. A separate `release-publication` job requires the exact phrase
   `PUBLISH vMAJOR.MINOR.PATCH`, a completed visual-review issue, and a
   protected-environment reviewer. It rebuilds nothing. It verifies the
   promoted evidence bundle, offline signature, draft state, bounded asset
   inventory, and every downloadable package digest before changing the
   existing draft to public. It rechecks the asset inventory immediately before
   publication.

The only workflow jobs with `contents: write` are draft creation and
publication. Action dependencies are pinned to full commits and are monitored
for reviewed updates. Publication remains maintainer-only.

## 2. Signing roles

Each role has a separate trust and recovery scope:

| Role | Authority | Required custody |
|---|---|---|
| Release manifest | Evidence manifest, checksums, and release notes | Offline hardware-backed Ed25519 key; two encrypted recovery copies; no unattended workflow access |
| Android Play | Upload to the configured Play application | Dedicated upload key; store-held app-signing key; least-privilege store account |
| Android Google-free | Direct-distribution APK upgrades | Dedicated offline or HSM-backed Android key, separate from the Play upload key |
| Apple iOS | iOS distribution and store submission | Role-scoped Apple distribution identity, provisioning assets, and least-privilege store account |
| Apple macOS | Developer ID signing and notarization | Dedicated Developer ID identity and protected notarization credential |
| Windows | MSI and NSIS Authenticode signatures | Hardware-backed code-signing provider with a narrowly scoped signing identity |
| Linux | AppImage, DEB, and RPM digests | Release-manifest signature; no reuse of repository, service, directory, or operator keys |

Directory, provider-directory, service, wake, mailbox, container, user
identity, and release keys are never interchangeable.

## 3. Human enrollment procedure

Enrollment stops at the credential or store boundary until a maintainer
explicitly confirms the target account, application identifier, role, public
fingerprint, recovery plan, and rollback.

For every role:

1. Record the exact package identifier, account or provider, permitted
   operation, and named custodians.
2. Generate the private key on the intended offline device, hardware token, or
   managed hardware-backed provider—not on a general CI runner.
3. Create two encrypted recovery copies on separately controlled media. Test a
   recovery copy by signing a non-release fixture, then return the copy to
   offline custody.
4. Export only the public certificate or fingerprint. Compare it through a
   second channel before adding public verification material.
5. Configure a protected environment with required maintainers and only the
   minimum credential needed for that role. Do not make credentials available
   to pull-request or validation jobs.
6. Sign a disposable candidate, verify it using the platform verifier, exercise
   upgrade and rollback, and record the result before enabling the role for a
   release.

### Offline release-manifest identity

After the enrollment decision, generate an Ed25519 key on the offline signing
device:

```sh
ssh-keygen -t ed25519 -a 100 -f /offline/komms-release-manifest-v1
```

The private path above is illustrative and must not be copied into a workflow
or repository. Add only the public key to
`release/keys/allowed_signers` in OpenSSH allowed-signers form:

```text
komms-release-v1 ssh-ed25519 <public-key> komms release manifest v1
```

The `release-manifest` row in `signing.json` records the enrolled public
fingerprint, tested recovery/verifier procedure, and the complete intended
artifact digest set. It does not claim that the completed bundle signature
already exists. The actual release authorization is the separate detached
signature checked during publication.

The offline device signs the completed evidence checksum inventory:

```sh
ssh-keygen -Y sign \
  -f /offline/komms-release-manifest-v1 \
  -n komms-release \
  SHA256SUMS
```

The public `SHA256SUMS.sig` accompanies the evidence bundle. Publication uses
the enrolled principal, namespace, and public key to verify it. A signature is
not valid evidence if the private key was exposed to the build host or if the
checksum inventory does not match the bundle.

### Platform enrollment boundaries

- Android enrollment records the Play app-signing and upload certificate
  fingerprints separately. The Google-free key has its own fingerprint and
  recovery exercise. `apksigner verify --print-certs` and the store console
  must agree before an upgrade test can pass.
- Apple enrollment records the team, bundle identifier `is.andri.komms`,
  distribution certificate fingerprints, profile identifiers, and account
  roles. iOS and macOS credentials are not silently shared. A test submission,
  notarization check, and installed upgrade precede release use.
- Windows enrollment requires a chosen hardware-backed Authenticode provider,
  certificate chain, timestamp service, revocation procedure, and a provider
  operation that signs only reviewed digests. A raw long-lived PFX in a general
  repository secret is not the target design.
- Linux users verify the release-manifest signature and package digest. A
  future apt or RPM repository needs a separately scoped repository-signing
  role and its own rotation plan.

## 4. Rotation and compromise

Routine rotation creates and verifies the replacement before retiring the old
identity. Where the platform supports it, the old identity authorizes the new
public key and both remain accepted for one tested overlap release. Android
signing lineage and store-specific upgrade rules take precedence over a
generic key swap.

Suspected compromise freezes draft mutation, publication, store submission,
and updater metadata. The incident owner records:

- the affected role, public fingerprint, first and last possibly affected
  artifact digests, and discovery time;
- revocation or store-reset actions and their limitations;
- whether installed clients will accept a replacement;
- rebuilt artifact and source revisions;
- user notification, unsupported upgrade paths, and residual risk; and
- the recovery-key or replacement-provider exercise.

An affected artifact is never silently replaced under the same tag or
filename. A corrected release receives new immutable evidence and version
identity.

## 5. Update and rollback contract

Komms has no unqualified in-app updater. Android Play and iOS use their
authenticated store paths after enrollment. Direct Android and desktop
artifacts use a bounded manual procedure: fetch the new evidence bundle from an
authorized project channel, verify the offline manifest signature and artifact
digest, preserve a verified backup, close the application, install, and verify
the displayed version before deleting the prior installer.

Failed upgrades must preserve or restore the prior compatible application and
store. Automatic database downgrade is not assumed. The qualification matrix
records clean install, authenticated upgrade, interrupted or failed upgrade,
rollback, old-version compatibility, update path, and signing-key compromise
response on each named supported environment.

## 6. Current blockers

The source-controlled validation path is ready, but production signing is
intentionally blocked:

- no release-manifest public key or tested recovery copies are enrolled;
- Android Play and Google-free production keys and store roles are not
  enrolled or exercised;
- Apple distribution, provisioning, notarization, and store roles are not
  enrolled or exercised;
- no hardware-backed Windows Authenticode provider is selected or configured;
- no signed platform artifact has completed clean install, upgrade, failure,
  rollback, and compatibility qualification;
- Android dependency declarations are inventoried, but the broader
  third-party-asset/legal policy review remains a separate open gate;
- no externally administered reproducibility run or independent release
  evaluation exists; and
- physical-device and supported-desktop rows remain open.

The exact next external action is a maintainer enrollment decision for the
first signing role. Until that happens, selecting `production_signing` fails at
the protected enrollment boundary and no stable distribution claim is
available.
