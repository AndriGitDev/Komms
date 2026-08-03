# iOS 26.5 simulator observation

Revision: `440a410a5d5a9373935cef8eb3728efe5ed91e64`

Date: 2026-07-31

Environments:

- iPhone 17 Pro Simulator, iOS 26.5, arm64
- iPhone 17e Simulator, iOS 26.5, arm64
- Xcode 26.6
- local maintainer run

Artifact:

- unsigned Debug simulator application archive:
  `378bdcd3cebdac3bdd6d17ef647dd493f37dd505cc693479e98f6a874cb009af`
  (14,253,440 bytes)

The native core framework and application were rebuilt from the revision above.
The application build completed successfully. Existing Swift isolation and
deprecated audio-session warnings remained visible and are not treated as
field qualification.

## Clean install and first run

Komms was removed and freshly installed on both simulator profiles. Cold launch
completed in 1.03 seconds on the iPhone 17 Pro and 0.60 seconds on the iPhone
17e. The first screen disclosed local encrypted identity storage, no central
account requirement, restoration, and advanced network settings.

Each throwaway profile then completed all mandatory first-run steps:

1. create the encrypted store with a synthetic passphrase;
2. present the one-time offline account-authority warning and words;
3. save the encrypted `.kra` package through the system document exporter;
4. acknowledge separate storage of the package and its words; and
5. reach the ordinary ready state.

Both form factors reached Standard / Connected with Pair a contact and Note to
self. The smaller iPhone 17e view retained all critical first-run and ready
actions without clipping in light appearance; the iPhone 17 Pro run covered
dark appearance. No recovery words or authority packages were retained.
Both throwaway authority files and both simulator application profiles were
removed after redacted evidence capture.

Result: `clean-install-and-first-run` is `simulator-pass` for both cells.

## Screen-security observation

On the iPhone 17e profile:

- the app switcher showed only “Komms is protected” and the inactive-scene
  privacy explanation;
- device lock exposed no Komms content;
- the in-application Lock action cleared the live session and returned to an
  empty encrypted-store gate; and
- ordinary still screenshots remained possible, matching the documented iOS
  limitation.

A short simulator recording did not cause iOS Simulator to report live capture
to the application, so the active ready screen remained visible. This method
therefore does not prove or disprove the UIKit live-capture notification path.
The row is recorded as `observed`, not `simulator-pass`, and physical-device
recording/mirroring qualification remains open.

The retained images use an empty throwaway profile and contain no message,
contact, address, safety-number, passphrase, recovery phrase, or authority
package.

## Limits

This is simulator evidence only. It does not qualify APNs, Background App
Refresh, force quit, device-lock timing, physical screen recording or
mirroring, notification permissions, token rotation, cellular handoff,
accessibility service navigation, real first contact, or durable end-to-end
delivery. Every other iOS field row remains open.
