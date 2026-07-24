**Komms 0.2 Alpha** is an early test release. Back up important data before upgrading and do not rely on it for emergency communication.

This release makes Komms meaningfully calmer and more dependable:

- the Android background node recovers more reliably after the app has been idle;
- attachment transfer avoids the pathological delay seen with larger images;
- desktop, Android, and iOS share a new Komms brand system and conversation-first layout;
- backup, linked-device, network, and diagnostic controls move into Settings;
- unlock screens explain that decrypting the store and starting the node can take up to 30 seconds; and
- expanded cross-platform tests cover startup, backup/RPC behavior, transfer progress, and shell consistency.

Artifacts are built from the tagged source by GitHub Actions:

- Windows: MSI and NSIS installers
- macOS: universal Apple silicon/Intel application and DMG
- Linux: AppImage, Debian package, and RPM
- Android: an installable, debug-signed APK; a release APK and AAB are also included when maintainer signing secrets are configured
- Self-hosting: `ghcr.io/andrigitdev/komms-kultd:0.2.0` for Linux amd64/arm64, with `0.2-alpha` and `alpha` aliases, published with the qualified prerelease

Desktop packages may be unsigned, and the always-present Android test APK uses a development certificate. Expect an operating-system warning and verify the file against `SHA256SUMS`. A debug-signed APK is for testing only, cannot be submitted to an app store, and may need to be uninstalled before installing a build signed by a different key.

Known alpha gaps include hands-on device qualification, the physical two-radio bench, real-NAT/live-call matrices, and an independent security audit. See the repository's Alpha testing guide, release runbook, and security documentation before testing.
