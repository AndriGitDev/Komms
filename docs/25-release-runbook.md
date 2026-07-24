# 25: Release Runbook

Komms release candidates are assembled by
[`release.yml`](../.github/workflows/release.yml) on native GitHub runners. One
tag produces Windows MSI/NSIS installers, a universal macOS app/DMG, Linux
AppImage/DEB/RPM packages, an installable Android test APK, and a validated
Linux `kultd` container candidate. The workflow keeps the GitHub release in
draft state until a maintainer explicitly publishes it as a prerelease. That
same explicit action publishes the multi-architecture self-hosting image to
GHCR; a tag push alone never exposes an unqualified container.

The current candidate is **Komms 0.2 Alpha**. Its technical semantic version is
`0.2.0` across Cargo, Tauri, Android, and iOS, and its release tag is `v0.2.0`.

Komms 0.1 Alpha remains public as a
[GitHub prerelease](https://github.com/AndriGitDev/Komms/releases/tag/v0.1.0),
with Windows MSI/NSIS, universal macOS DMG/app archive, Linux
AppImage/DEB/RPM, a debug-signed Android APK, and `SHA256SUMS`. Its public
[`komms-kultd` package](https://github.com/AndriGitDev/Komms/pkgs/container/komms-kultd)
provides Linux amd64/arm64 images under `0.1.0`, `0.1-alpha`, and `alpha`.

This makes artifacts available consistently; it does not turn the current alpha
into an audited stable release. Platform signing, hands-on device testing, radio
hardware, real-NAT/live-call qualification, and an independent security audit
remain separate gates.

## 1. Prepare the source

Choose a semantic version and update every version surface:

1. `workspace.package.version` in the root `Cargo.toml`;
2. the desktop crate and Tauri bundle versions;
3. Android `versionName` and its monotonically increasing `versionCode`; and
4. iOS `CFBundleShortVersionString` and its monotonically increasing build
   number.

For the current version, verify the alignment with:

```sh
python3 scripts/check-release-version.py v0.2.0
```

Run the complete local gate. Android is mandatory for a candidate that promises
an APK:

```sh
KOMMS_REQUIRE_ANDROID_APP=1 scripts/local-release-matrix.sh
```

Record the commit, the complete output, every external/deferred gate, and the
hands-on smoke-test devices. A green compiler run is not a substitute for those
records.

## 2. Configure optional signing

No signing material belongs in Git. Without secrets, the workflow still emits
unsigned desktop packages and an automatically debug-signed APK suitable for
direct testing.

For a stable Android signing identity, configure these GitHub Actions secrets:

- `KOMMS_ANDROID_KEYSTORE_BASE64`: the release JKS/keystore encoded as one
  base64 value;
- `KOMMS_ANDROID_KEYSTORE_PASSWORD`;
- `KOMMS_ANDROID_KEY_ALIAS`; and
- `KOMMS_ANDROID_KEY_PASSWORD`.

Then set the repository variable `KOMMS_ANDROID_SIGNING_ENABLED=1`. When the
gate and all secrets are present, the workflow adds a signed release APK and
AAB. The debug APK is still included as an obvious test artifact. Preserve the
keystore and its passwords offline: losing them prevents compatible upgrades,
while disclosing them lets another party impersonate a release.

The macOS runner accepts Tauri's standard `APPLE_CERTIFICATE`,
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD`, and `APPLE_TEAM_ID` secrets. Set the repository variable
`KOMMS_APPLE_SIGNING_ENABLED=1` only after the certificate inputs have been
validated. Without that explicit gate, stale or partial secrets are ignored and
the Alpha macOS package remains unsigned. Windows Authenticode signing is not
configured yet; add a reviewed certificate provider or Tauri `signCommand`
before describing Windows packages as signed.

## 3. Build a draft candidate

After explicit authorization for the remote operation, create and push an
annotated `vMAJOR.MINOR.PATCH` tag. A tag push runs the release workflow and
creates a draft prerelease. The same existing tag can be rebuilt manually from
**Actions → release candidates → Run workflow** with `publish` disabled.

The workflow refuses malformed tags, mismatched application versions, and
replacement of assets on an already-public release. It uploads each native
package and generates `SHA256SUMS` only after every platform build succeeds.

## 4. Qualify the artifacts

Before publication:

1. compare the draft's source tag and commit with the recorded local gate;
2. verify every download against `SHA256SUMS`;
3. install the MSI/NSIS, DMG, AppImage or native Linux package, and APK on real
   supported systems;
4. exercise create/unlock, pair, send/receive, backup/restore, lock, restart,
   and upgrade behavior; and
5. record OS versions, architectures, signing status, failures, and all external
   gates in the release notes.

The debug APK is installable on Android 8.0 (API 26) or newer, but it uses a
development certificate and is not store-ready. Android will reject an upgrade
when the installed build was signed by a different key; uninstall the old test
build only after exporting any data that must be retained.

## 5. Publish deliberately

Once the draft assets themselves pass qualification, manually run the workflow
for the same tag with `publish` enabled. That explicit run verifies that the
draft contains checksums, an APK, and every promised desktop package family,
then builds and publishes `ghcr.io/andrigitdev/komms-kultd` for Linux amd64 and
arm64 before publishing the existing qualified assets as a public GitHub
prerelease. The version tag is accompanied by `0.2-alpha` and `alpha`
for this release, never `latest`. It does not rebuild or silently replace the
desktop/mobile artifacts that were tested.

The current `komms-kultd` package is public. A new package namespace may still
default to private: if the anonymous manifest check fails after its first push,
open that package's settings, change its visibility to **Public**, and rerun the
publication job. The job keeps the GitHub release in draft state until an
anonymous pull succeeds.

Do not mark an alpha prerelease as stable, claim that unsigned packages are
signed, or promise an audited security level until the corresponding external
gate has actually been completed.
