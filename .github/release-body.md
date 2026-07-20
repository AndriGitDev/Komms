**Komms 0.1 Alpha** is an early test release. Back up important data before upgrading and do not rely on it for emergency communication.

Artifacts are built from the tagged source by GitHub Actions:

- Windows: MSI and NSIS installers
- macOS: universal Apple silicon/Intel application and DMG
- Linux: AppImage, Debian package, and RPM
- Android: an installable, debug-signed APK; a release APK and AAB are also included when maintainer signing secrets are configured

Desktop packages may be unsigned, and the always-present Android test APK uses a development certificate. Expect an operating-system warning and verify the file against `SHA256SUMS`. A debug-signed APK is for testing only, cannot be submitted to an app store, and may need to be uninstalled before installing a build signed by a different key.

Known alpha gaps include hands-on device qualification, the physical two-radio bench, real-NAT/live-call matrices, and an independent security audit. See the repository release runbook and security documentation before testing.
