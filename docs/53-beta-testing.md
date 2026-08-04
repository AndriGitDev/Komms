# 53: Install and Test Komms 0.4 Beta

Komms 0.4 Beta is a prerelease candidate for careful hands-on testing. It is
not a stable release, an independently audited build, or suitable for emergency
or safety-critical communication. Back up disposable test data before an
upgrade and retain every recovery file and phrase separately.

The source and application version is `0.4.1`; `beta` is the release channel.
The only eligible source tag is `v0.4.1`. A branch name, workflow artifact, or
container alias is not a release identity.

## 1. Obtain an eligible package

The release page is authoritative only after a maintainer publishes a completed
Beta whose evidence archive binds the exact package set. Before that happens,
use source builds or explicitly labelled validation artifacts; do not represent
them as the public Beta.

When the release exists, obtain it from the
[`v0.4.1` release page](https://github.com/AndriGitDev/Komms/releases/tag/v0.4.1).
Choose an asset beginning with the matching class:

| Platform | Expected staged asset class | Current boundary |
|---|---|---|
| Windows 10/11 x64 | `Komms-0.4.1-windows-x86_64-…` | MSI or NSIS package; publication requires verified Authenticode evidence. |
| macOS Intel or Apple silicon | `Komms-0.4.1-macos-universal-…` | Universal DMG; publication requires Developer ID and notarization evidence. |
| Linux x86-64 | `Komms-0.4.1-linux-x86_64-…` | AppImage, DEB, or RPM bound by the release-manifest role. |
| Android 8.0+ | `Komms-0.4.1-android-play-arm64-…` or `Komms-0.4.1-android-google-free-arm64-…` | Play and Google-free are separate signing roles; the Google-free build contains no FCM SDK. |
| iOS 16+ | No public package unless a qualified `ios-arm64` IPA is present | The routine validation workflow builds an unsigned Simulator archive, not an installable IPA. |

If the completed release lacks a platform asset, that platform is not supplied
by this Beta. Do not substitute a retained validation package or third-party
binary.

## 2. Verify the exact release

Download the completed `Komms-0.4.1-release-evidence.tar.gz` archive and the
package from the same release. The archive must unpack to one
`release-evidence/` directory and its `artifacts.json` must list the package's
exact filename, byte size, and SHA-256 digest. Follow
[Release Evidence Bundles](40-release-evidence-bundles.md) to safely unpack and
verify it.

On Linux or macOS, calculate the package digest with:

```sh
shasum -a 256 Komms-0.4.1-PLATFORM-ASSET
```

On Windows PowerShell:

```powershell
Get-FileHash .\Komms-0.4.1-PLATFORM-ASSET -Algorithm SHA256
```

The value must equal the `sha256` entry for that exact path. Also inspect
`signing.json`, `qualification.json`, `residual-risks.json`, and
`release-notes.md`; a successful hash does not close an open signing or
physical-qualification row. Stop if the package, evidence archive, tag, source
revision, version, or digest disagrees.

## 3. Upgrade carefully from 0.3 Alpha

The 0.4 trust model intentionally does not continue copied account-root
authority as normal live state.

- A profile that never copied its account root may offer an explicit safe
  in-place authority migration.
- Any evidence that the root was copied requires the visible new-identity
  reset. Komms may retain only accurately labelled eligible local history,
  notes, organization, and petnames; every contact must verify the new safety
  number.
- Legacy `KKR1`–`KKR7` backups are decode-only migration inputs and never resume
  their former identity. Root-free `KKR8`–`KKR10` restore requires the separate
  offline recovery authority where applicable and creates one fresh recovery
  device.
- Android and desktop operating systems may reject an in-place package update
  when the signing identity differs. Preserve an encrypted export before
  uninstalling a disposable test build.

Never weaken the reset prompt or copy a root/recovery secret into ordinary app
storage to make an upgrade appear seamless.

## 4. Run the Beta acceptance walk-through

Use two fresh test identities on separate candidate devices when possible:

1. Create, lock, restart, and unlock both profiles. Store the offline recovery
   authority, backup, and their different phrases separately.
2. Exchange `kc2` Connect codes. Confirm the first sender appears only as a
   Message Request, then exercise Accept, Delete, and Block with disposable
   identities.
3. Compare the 30-digit safety number through a separate trusted channel, or
   scan the full-value verification QR.
4. Send text and an attachment in both directions. Confirm that `queued` means
   local custody, `sent` means bounded next-hop custody, and only an
   authenticated end-to-end receipt produces `delivered`.
5. Create a group, wait for its recipient-authentication upgrade, then exercise
   text, an edit, a poll vote, a role change, and member/device removal. Old
   legacy history must keep its weaker security label.
6. Link another owned device through scan/compare/confirm, revoke it, and check
   that the remaining authority set converges. Treat a visible fork or recovery
   conflict as a hard stop.
7. Test offline mailbox delivery only against an operator whose exact source,
   role, retention, and limits you understand. A mailbox acceptance is not an
   end-to-end receipt.
8. Switch among Standard, Private, and Sovereign and confirm that identity and
   message history stay unchanged. Optional-service failure must leave ordinary
   direct, mailbox, local, mesh, and file fallbacks intact where configured.
9. Create a current backup, restore it on a clean disposable profile with the
   required separate authority, and re-verify the resulting device and contact
   state.

Audio calls require a fresh direct QUIC route and never fall back through TCP,
relay, mailbox, radio, or sneakernet. Native wake is a content-free hint only;
it never marks a message sent or delivered and is subject to platform
background limits.

## 5. Report evidence without secrets

For a product defect, open a
[GitHub issue](https://github.com/AndriGitDev/Komms/issues) with the exact asset
name and digest, source revision, device/OS, network conditions, concise steps,
timings, expected result, and observed result. Remove identities, Connect
codes, safety numbers, capabilities, message content, social labels, file
paths, push tokens, and private network addresses from logs.

Report vulnerabilities privately through [SECURITY.md](../SECURITY.md).
Simulator or host results must remain labelled as such; they are not
physical-device, real-network, operator, accessibility, radio, independent
interoperability, or independent security-review evidence.

## 6. Optional self-hosting

The prepared immutable node image is
`ghcr.io/andrigitdev/komms-kultd:0.4.1`; `0.4-beta` and `beta` are moving Beta
aliases only when the separately authorized container publication has occurred.
There is no `latest` alias. Dedicated reference, mailbox, wake, and OHTTP roles
have separate images and runbooks and must not be collapsed into one
identity-bearing service.

Read [Self-hosting](26-self-hosting.md) and the relevant operator runbook before
exposing a port. No current project default is qualified merely because an
image builds or is available in a registry.

## 7. Build from source

The [desktop](../apps/desktop/README.md),
[Android](../apps/android/README.md), and [iOS](../apps/ios/README.md) guides
cover each shell. The complete non-publishing candidate gate is:

```sh
KOMMS_REQUIRE_ANDROID_APP=1 \
KOMMS_REQUIRE_IOS_APP=1 \
scripts/local-release-matrix.sh
```

Record every deferral. Passing local tests authorizes neither a tag nor a
public release.
