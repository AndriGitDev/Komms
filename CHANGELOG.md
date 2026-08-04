# Changelog

Release notes describe product and compatibility changes. Security assurance,
platform support, and operator availability are earned only by the exact
revision-bound records linked from a completed release.

## 0.4.2 Beta — unsigned test release

Published 2026-08-04 as a public prerelease from tag `v0.4.2`, commit
`5a09190cfef9cfef92703672517bc008b6e8cc1f`.

### Distribution status

- Published the exact green hosted validation set as an explicitly unsigned,
  pre-production test exception for version 0.4.2 only. This did not enroll or
  exercise any production signing role and does not weaken the release policy
  for later versions.
- Added unsigned Windows, macOS, and Linux packages; an unsigned iOS Simulator
  archive; unsigned Android validation packages; and a Google-free Android APK
  signed with the existing test/debug certificate for physical-device testing.
- Attached `UNSIGNED-TEST-SHA256SUMS`, the original
  `VALIDATION-SHA256SUMS`, and the revision-bound validation evidence archive.
  The evidence continues to report `production_signed: false`,
  `qualified_for_stable: false`, and `independently_reproduced: false`.
- Recorded the exact exception, checksums, test certificate, hosted validation
  run, and remaining gates in
  [the 0.4.2 release record](docs/54-v0.4.2-unsigned-test-release.md).

### Security and trust

- Replaced copied live account-root authority with bounded `KDA2`
  strict-majority device manifests, visible fork/conflict failure, offline
  recovery authority, and recovery epochs that revoke the former active set.
- Made legacy copied-root migration honest: eligible single-device profiles can
  migrate in place; any evidence of a copied root requires a visible new
  identity and contact re-verification.
- Added recipient-authenticated group origins for text, attachments, edits,
  polls, expiry, roles, moderation, ownership, and owned-device imports without
  abandoning encrypt-once sender-key ciphertext.
- Added bounded admission descriptors, target-specific puzzle or invitation
  proofs, sealed Message Requests, explicit Accept/Delete/Block, and the same
  consent boundary for group invitations.

### Discovery and delayed delivery

- Added rotatable `kc2` Connect codes and fixed-size capability-scoped encrypted
  DHT records; stable identity-indexed discovery remains only as a visible
  time-bounded legacy migration path.
- Replaced mailbox-v1 delete-on-check-in behavior with durable mailbox v2
  deposits, idempotent leases, exact acknowledgement after endpoint staging,
  restart-safe quotas, and bounded aggregate-only service health.
- Added transcript-bound rotating pairwise rendezvous with fixed-shape records,
  provider/direction separation, replay/generation checks, and a dedicated
  least-authority reference service.

### Modes, services, and mobile lifecycle

- Unified Standard, Private, and Sovereign across core, daemon, FFI, desktop,
  Android, and iOS using a signed replaceable provider directory and retained
  last-valid behavior.
- Added the fixed-shape native wake gateway and bounded collection contract.
  Wake never advances queued, sent, or delivered state.
- Added direct APNs support, Play-only FCM support, and a Google-free Android
  flavor with no FCM SDK or advertised wake capability.
- Added separate hardened images and runbooks for reference, mailbox, wake, and
  fixed-mapping OHTTP relay roles. No qualified default operator is implied.

### Release, protocol, and stewardship

- Added a stand-alone stable-v1 specification, language-neutral fixtures,
  malformed cases, packet captures without secrets, and a conformance runner.
- Added a deterministic external security-review package, field qualification
  matrix, real-device/radio-ready forms, and explicit independence boundaries.
- Added revision-bound release evidence, SBOM, provenance, signing-role,
  qualification, reproducibility, rollback, and protected publication controls.
- Added bounded contributor profiles, English/Icelandic localization parity,
  accessibility checks, operator policies, licensing/trademark inventory,
  funding transparency, and privacy/legal/incident runbooks.
- Replaced the desktop first-run authority path field with the native Save
  dialog and made invalid, cancelled, occupied, and failed destinations
  retryable without consuming the one-time authority or stopping the runtime.

### Compatibility and migration

- All internal crates and application surfaces report `0.4.2`; Android and iOS
  use build number `6`.
- Current backups are root-free `KKR10`. Root-free `KKR8` and `KKR9` remain
  compatible inputs. `KKR1`–`KKR7` remain decode-only former-identity migration
  inputs and never resume the old account.
- Live legacy groups visibly require the origin-authentication upgrade. Old
  history keeps its membership-authenticated label and is not rewritten.
- Mailbox-v1 custody and identity-indexed discovery are not promoted into the
  v2 claims. Operators and contacts must upgrade through their explicit
  compatibility paths.

### Open assurance gates

- Production signing roles and store credentials are not enrolled.
- Independent security review, independent interoperability/reproduction,
  qualified public operators, real-network and named physical-device matrices,
  accessibility assessment, and the physical two-radio bench remain open.
- The public 0.4.2 Beta is not a stable release and is not suitable for
  emergency or safety-critical communication.

## 0.4.1 Beta — failed physical-validation candidate

The immutable `v0.4.1` tag completed its hosted validation workflow but was not
published. A physical macOS clean-install run exposed a first-run offline
authority export failure: an invalid initial destination could unwind the
runtime worker, making every later retry in that process fail. The candidate
therefore received no macOS pass and no public package set. The corrected
candidate is `v0.4.2`.

## 0.4.0 Beta — failed validation candidate

The immutable `v0.4.0` tag was not published. Its Android package job could not
resolve the installed SDK manager, and both Linux builds rejected an unrelated
AppImage bundle symlink before evidence assembly. No release draft or public
package set was created. Its successor was `v0.4.1`.

## 0.3.0 Alpha — historical

The published [0.3 Alpha](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0)
introduced the cross-platform interface preview, compact pairing QR flow, and
the original packaged desktop/Android test artifacts. It predates the 0.4
device-authority, origin-authentication, admission, discovery, mailbox-v2, and
release-evidence contracts. Its unsigned/debug-signed artifacts remain test
artifacts only.
