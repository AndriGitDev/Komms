# Install and Test Komms 0.1 Alpha

Komms 0.1 Alpha is a public prerelease for hands-on testing. Download it from
the [v0.1.0 GitHub release](https://github.com/AndriGitDev/Komms/releases/tag/v0.1.0).
It is not an audited stable release: back up important Komms data, expect rough
edges, and do not rely on it for emergency communication.

## 1. Choose a package

| Platform | Release asset | Notes |
|---|---|---|
| Windows 10/11 x64 | `Komms-0.1.0-windows-x64.msi` or `Komms-0.1.0-windows-x64-setup.exe` | Pick one installer format; both install the same Alpha. |
| macOS Intel or Apple silicon | `Komms-0.1.0-darwin-universal.dmg` | Universal application. The `.app.tar.gz` is also available for manual deployment. |
| Linux x86-64 | `Komms-0.1.0-linux-amd64.AppImage`, `.deb`, or `.rpm` | Use the format native to your distribution. |
| Android 8.0+ | `Komms-0.1.0-android-debug.apk` | Test-only, debug-signed APK for `arm64-v8a` phones and `x86_64` emulators. |
| iOS | No downloadable Alpha package | Build the unsigned Simulator app from source using the [iOS guide](../apps/ios/README.md). |

The desktop packages are not production-signed or notarized, and the Android
APK uses a development certificate. An operating-system warning is therefore
expected. Only continue after downloading from the release above and verifying
the checksum.

## 2. Verify the download

Download `SHA256SUMS` from the same release. On Linux, verify every downloaded
release asset in the current directory with:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

On macOS, calculate a package hash and compare it with that file:

```sh
shasum -a 256 Komms-0.1.0-darwin-universal.dmg
grep 'Komms-0.1.0-darwin-universal.dmg' SHA256SUMS
```

On Windows PowerShell:

```powershell
Get-FileHash .\Komms-0.1.0-windows-x64.msi -Algorithm SHA256
Select-String -Path .\SHA256SUMS -Pattern 'Komms-0.1.0-windows-x64.msi'
```

The two hexadecimal values must match exactly. Stop if they do not.

## 3. Install

### Windows

Open either the MSI or setup EXE. Windows SmartScreen may identify it as an
unrecognized unsigned app. Check the hash first, then use the warning's
additional-information path only if the publisher URL and filename are the
ones above.

### macOS

Open the DMG and drag Komms to Applications. Because the Alpha is not signed
with an Apple Developer ID or notarized, Gatekeeper may block the first launch.
After verifying the hash, try opening it once, then use **System Settings →
Privacy & Security → Open Anyway**. Do not disable Gatekeeper globally.

### Linux

For the AppImage:

```sh
chmod +x Komms-0.1.0-linux-amd64.AppImage
./Komms-0.1.0-linux-amd64.AppImage
```

On Debian or Ubuntu:

```sh
sudo apt install ./Komms-0.1.0-linux-amd64.deb
```

On Fedora or another RPM-based distribution:

```sh
sudo dnf install ./Komms-0.1.0-linux-x86_64.rpm
```

The Linux packages are not signed in this Alpha.

### Android

Download the APK on the device, allow **Install unknown apps** for that browser
or file manager, and open the APK. Turn that permission off again afterward.
Android refuses an in-place update when an older test build was signed with a
different key. Export any data you need before uninstalling such a build.

## 4. Run a ten-minute smoke test

Use two supported devices if possible:

1. Create and unlock a fresh identity on each device with a strong, unique
   passphrase. Record any recovery material offline and never share it in an
   issue report.
2. Exchange the pairing bundle or QR code over a channel you trust.
3. Compare the complete safety number through a separate trusted channel before
   treating the contact as verified.
4. Send ordinary and safely formatted text in both directions. Confirm the
   honest `queued → sent → delivered` progression rather than assuming that
   `sent` means the other device received it.
5. Try an attachment, then lock and restart one app. Unlock it again and confirm
   that expected local state remains available.
6. Create an encrypted backup and confirm that you can safely retain its
   passphrase or recovery mnemonic. Do not delete the working profile merely to
   test restore unless its data is disposable.

Calls require a fresh direct QUIC path and deliberately do not fall back through
relays, mailboxes, TCP, radio, or sneakernet. Radio paths and real-world mobile
lifecycle behavior still need broader hardware testing.

## 5. Report what you find

Open a [GitHub issue](https://github.com/AndriGitDev/Komms/issues) with:

- the exact release filename, operating-system version, and CPU architecture;
- concise reproduction steps and what you expected versus what happened; and
- relevant logs after removing identities, addresses, safety numbers, message
  content, filesystem paths, and other private data.

Report vulnerabilities privately using [SECURITY.md](../SECURITY.md), not a
public issue. There is no automatic updater yet; check the GitHub releases page
and repeat the checksum and backup steps before installing a future Alpha.

## 6. Optional self-hosted node

The public `kultd` image supports Linux amd64 and arm64:

```sh
docker pull ghcr.io/andrigitdev/komms-kultd:0.1.0
```

Read the [self-hosting guide](26-self-hosting.md) before exposing ports or
volunteering mailbox or bridge capacity. `0.1.0` is the immutable release tag;
`0.1-alpha` and `alpha` are moving Alpha aliases. There is intentionally no
`latest` tag.

## 7. Build or explore from source

Developers can still build each platform using the
[desktop](../apps/desktop/README.md), [Android](../apps/android/README.md), and
[iOS](../apps/ios/README.md) guides. The original no-GUI file-carrier demo is a
useful protocol exercise after cloning the source:

```sh
cargo run --example sneakernet_demo
```
