# Android API 35 simulator observation

Revision: `440a410a5d5a9373935cef8eb3728efe5ed91e64`

Date: 2026-07-31

Environment:

- `sdk_gphone64_arm64 / komms-api35`
- Android 15 / API 35
- arm64 emulator
- local maintainer run

Artifacts:

- Google-free debug APK:
  `3eed92eeb041bc99bfa44a9963021321120db4aa5b29c972a945ee27397861a7`
  (44,576,569 bytes)
- Play debug APK:
  `096e32258b0476d2f132397dd119fe0fe388585456ad837e751171311e8b726a`
  (45,330,451 bytes)

Both flavors were rebuilt from the revision above. Their debug unit suites
passed with tasks rerun, and the Google-free artifact contained no Firebase,
FCM, Google Play Services bytecode, or matching resources.

## Clean install and first run

The exact Google-free artifact was installed after removal of the prior Komms
application profile. A cold launch completed in 1,535 ms. The first screen
exposed password-classified Store passphrase and Confirm passphrase fields,
Create Komms, restore, and advanced-network controls.

A throwaway profile then completed all mandatory first-run steps:

1. create the encrypted store with matching synthetic passphrases;
2. display the mandatory offline account-authority warning;
3. save the encrypted `.kra` package in the emulator's document storage;
4. acknowledge separate storage of the package and its words;
5. deny optional notification permission; and
6. reach the ordinary ready state.

The ready hierarchy exposed Komms, Standard / Fallback ready, Pair a contact,
and Note to self. No route edit or release credential was required. The
throwaway authority package, UI dumps, and application profile were removed
after the redacted evidence was retained.

Result: `clean-install-and-first-run` is `simulator-pass`.

## Screen-security lifecycle

The ready window and encrypted-store gate both inherited the platform secure
window flag:

- a direct screenshot retained only system chrome and an opaque application
  surface;
- Android overview retained the Komms task identity while replacing
  application content with the protected theme surface;
- the device-lock capture contained no Komms content;
- a three-second platform recording produced an opaque frame with system
  chrome only; and
- the in-application Lock action stopped the session and returned to an empty
  password-classified encrypted-store gate.

The retained images use a throwaway empty profile and contain no message,
contact, address, safety-number, passphrase, recovery phrase, or authority
package.

Result: `screen-security-lifecycle` is `simulator-pass`.

## Limits

This is emulator evidence only. It does not qualify a physical Android device,
Doze or OEM behavior, FCM delivery, radio conditions, battery/CPU budgets,
cellular handoff, biometric or hardware-backed storage, accessibility service
navigation, real first contact, or durable end-to-end delivery. Every other
Android field row remains open.
