# 53: Install and Test Komms 0.4 Beta

Komms 0.4.2 Beta is a public prerelease for careful hands-on testing. It is an
explicitly unsigned, pre-production test release—not a stable release, an
independently audited build, or software for emergency, safety-critical, or
production communication. Back up disposable test data before an upgrade and
retain every recovery file and phrase separately.

The source and application version is `0.4.2`; `beta` is the release channel.
The release source is tag `v0.4.2` at commit
`5a09190cfef9cfef92703672517bc008b6e8cc1f`. A branch name, workflow artifact,
or container alias is not that public release identity.

## 1. Obtain an eligible package

Obtain the public test release only from the
[`v0.4.2` release page](https://github.com/AndriGitDev/Komms/releases/tag/v0.4.2).
Choose the exact asset for the test environment:

| Platform | Public 0.4.2 test asset | Current boundary |
|---|---|---|
| Windows 10/11 x64 | `Komms-0.4.2-windows-x86_64-Komms_0.4.2_x64_en-US.msi` or `Komms-0.4.2-windows-x86_64-Komms_0.4.2_x64-setup.exe` | Both are unsigned; expect SmartScreen warnings. |
| macOS Intel or Apple silicon | `Komms-0.4.2-macos-universal-Komms_0.4.2_universal.dmg` | The universal DMG is unsigned and not notarized; expect Gatekeeper warnings. |
| Linux x86-64 | the AppImage, DEB, or RPM whose name begins `Komms-0.4.2-linux-x86_64-` | All three are unsigned. |
| Android 8.0+ arm64 | `Komms-0.4.2-android-google-free-test-signed.apk` | Installable Google-free APK signed with a test/debug certificate, not a production release key. |
| iOS Simulator | `Komms-0.4.2-ios-simulator-validation.zip` | Unsigned Simulator application only; it cannot be installed on a physical iPhone. |

The Android files containing `release-unsigned` and the Play AAB are retained
validation artifacts, not ordinary install packages. There is no public
physical-device iOS IPA. Do not substitute a third-party binary.

## 2. Verify the exact release

Download `UNSIGNED-TEST-SHA256SUMS` and the package from the same release. On
Linux or macOS, verify the files present in the directory with:

```sh
shasum -a 256 -c UNSIGNED-TEST-SHA256SUMS
```

On Windows PowerShell, calculate the selected package digest and compare it to
the matching line in `UNSIGNED-TEST-SHA256SUMS`:

```powershell
Get-FileHash .\Komms-0.4.2-PLATFORM-ASSET -Algorithm SHA256
```

The public checksum manifest itself has SHA-256
`48ba6a499bdfcb03d10fb79e7ef1000996658b916a722ff4775cfbaf3705c1f4`.
Stop if the filename, version, source revision, or digest disagrees.

The attached `Komms-0.4.2-validation-evidence.tar.gz` has SHA-256
`b639a1ad81210a17f4dc8bc5d47d981ab0011aa45357b99638350e4d9d99e58f`.
It and `VALIDATION-SHA256SUMS` preserve the original hosted validation set. The
archive is validation evidence, not a completed production evidence bundle or
offline release signature. Its records correctly say:

- `production_signed: false`;
- `qualified_for_stable: false`; and
- `independently_reproduced: false`.

For Android, the test certificate SHA-256 is
`ec07a2d6a873d4b921c03c63a4c38888db582ee8b9e00517c124b4e395083cb7`.
The test-signed Google-free APK has the same normalized unsigned payload as the
hosted Google-free validation APK; only its test signature differs. Uninstall
it before a future production-signed build because an authenticated in-place
upgrade from this certificate is not promised.

The [0.4.2 release record](54-v0.4.2-unsigned-test-release.md) binds the hosted
workflow, artifact checksums, one-version exception, and open gates. Follow
[Release Evidence Bundles](40-release-evidence-bundles.md) when inspecting the
attached archive, but do not reinterpret its validation channel as a signed
release channel.

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

Use two fresh test identities on separate test devices when possible:

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
`ghcr.io/andrigitdev/komms-kultd:0.4.2`; `0.4-beta` and `beta` are moving Beta
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
