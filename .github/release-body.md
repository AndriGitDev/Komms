**Komms 0.3 Alpha** is an early test release. Back up important data before upgrading and do not rely on it for emergency communication.

This release makes pairing, delivery, and cross-platform use meaningfully more dependable:

- Android now carries the same branded, conversation-first visual system as iOS and desktop;
- post-quantum pairing bundles use compact Base45 codes and bounded animated QR frames that real phone cameras can parse;
- fresh user actions take priority while unreachable messages retry passively, then report `delivery failed after 30 days` if no encrypted receipt returns;
- human-readable safety numbers are shortened to 30 digits while QR verification still compares the full 256-bit value;
- desktop sharing, discovery status, contact rename, conversation rendering, lock layout, icons, and shutdown behavior are hardened; and
- release qualification now requires human visual approval on Android, iOS, macOS, and Linux in addition to automated platform builds and tests.

Artifacts are built from the tagged source by GitHub Actions:

- Windows: MSI and NSIS installers
- macOS: universal Apple silicon/Intel application and DMG
- Linux: AppImage, Debian package, and RPM
- Android: an installable, debug-signed APK; a release APK and AAB are also included when maintainer signing secrets are configured
- Self-hosting: `ghcr.io/andrigitdev/komms-kultd:0.3.0` for Linux amd64/arm64, with `0.3-alpha` and `alpha` aliases, published with the qualified prerelease

Desktop packages may be unsigned, and the always-present Android test APK uses a development certificate. Expect an operating-system warning and verify the file against `SHA256SUMS`. A debug-signed APK is for testing only, cannot be submitted to an app store, and may need to be uninstalled before installing a build signed by a different key.

Known alpha gaps include hands-on device qualification, the physical two-radio bench, real-NAT/live-call matrices, and an independent security audit. See the repository's Alpha testing guide, release runbook, and security documentation before testing.
