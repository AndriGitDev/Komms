# 14. Incognito Keyboard

B15 reduces accidental retention and suggestion of sensitive Komms input by
keyboards, writing tools, spelling services, and webview autofill. It is an
always-on shell policy available before unlock, not a setting, sealed record,
protocol capability, or remote promise.

## 1. Exact user promise

Komms marks every shipped text-entry surface for the strongest relevant input
privacy the platform exposes. Passphrases and recovery mnemonics use masked
secret fields. Message composers, scheduled text, names, filenames, addresses,
and other technical text disable personalized learning, correction, prediction,
spellcheck, autofill, or capitalization where a supported API exists.

This is exposure reduction, not a guarantee that typed text cannot be observed.
The active input method and operating system necessarily process keystrokes.
Malicious or non-compliant keyboards, compromised endpoints, accessibility and
overlay abuse, privileged writing tools, physical keyboards with storage, and
external observation remain outside the guarantee.

## 2. Shared capability matrix

| Capability | Android | iOS | Desktop |
|---|---|---|---|
| Personalized-learning control | `platform_requested` | `unavailable` | `unavailable` |
| Correction/prediction control | `platform_requested` | `best_effort` | `best_effort` |
| Spellcheck control | `platform_requested` | `best_effort` | `best_effort` |
| Secret-text visual masking | `platform_enforced` | `platform_enforced` | `best_effort` |
| Applies before unlock | Yes | Yes | Yes |
| User-disableable | No | No | No |

`platform_requested` means a documented native control is set but the input
method may ignore it. `best_effort` means Komms supplies the strongest available
trait or web attribute without an enforcement API. `unavailable` means no honest
per-field control exists. These levels must not be upgraded in shell copy.

The shared contract covers semantic field classes `message`, `search`,
`passphrase`, `mnemonic`, and `name`. There is no search box in the shipped
shells today; the class is included so a future search field cannot silently
bypass the policy.

## 3. Platform behavior

### Android

Every XML and programmatic editor is `IncognitoEditText`. It sets
`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING` on the view and again on the
final input connection, and adds `TYPE_TEXT_FLAG_NO_SUGGESTIONS` to text editor
metadata. Passphrases and the 24-word recovery mnemonic use password input.

Android explicitly documents the learning flag as a request rather than a
guarantee. An IME may ignore it. The settings surface renders that limitation
from the shared B15 policy.

### iOS

Every `TextField`, `TextEditor`, and `SecureField` uses one audited SwiftUI
modifier that disables autocorrection and selects explicit capitalization
semantics. Passphrases and recovery mnemonics use `SecureField`; iOS substitutes
the system keyboard for secure text entry. Non-secure fields remain best effort:
iOS exposes no public per-field guarantee that personalized learning is off, and
third-party keyboards may not honor every trait.

### Desktop

Every editable textual HTML control carries a semantic
`data-incognito-input` classification. Startup and modal cloning apply
`autocomplete="off"`, `autocorrect="off"`, `autocapitalize="off"`, and
`spellcheck="false"`. Passphrases and recovery mnemonics are password inputs.

Webview attributes are hints. The browser engine, OS input method, writing
tools, or privileged software may ignore them. Read-only copy surfaces are not
keyboard entry and are excluded from the editable-field inventory.

## 4. Field inventory and automated gates

| Surface | Automated inventory |
|---|---|
| Android | 16 XML editors plus 5 programmatic editors; raw editor construction is rejected |
| iOS | 20 SwiftUI text editors; modifier count must equal editor count |
| Desktop | 24 editable textual controls; privacy classification count must match |

The inventories include current message and scheduled-message composers,
passphrase and mnemonic restore fields, contact/group/folder/label names,
attachment filenames, pairing data, delivery hints, and network configuration.
Numeric crop controls, date/time pickers, selectors, and read-only copy surfaces
do not invoke a predictive text keyboard and are excluded.

The shared fixture `fixtures/b15-incognito-keyboard-parity.json` pins capability
tokens, required field classes, pre-unlock behavior, and zero storage/network
effects across `kult-node`, strict RPC/CLI, UniFFI, and all three shell tests.

## 5. Manual qualification

Release evidence should be recorded on representative first-party and
third-party keyboards:

1. inspect the platform editor metadata for message, naming, passphrase, and
   mnemonic fields;
2. verify passphrase and mnemonic characters are masked and iOS secure entry
   switches away from third-party keyboards;
3. type unique canary words, leave Komms, and check that compliant keyboards do
   not suggest them elsewhere;
4. repeat with a keyboard known to ignore privacy hints and record the limitation
   rather than treating it as an app failure;
5. confirm unlock, restore, message composition, names, accessibility, hardware
   keyboards, and international input remain usable.

Manual absence of a later suggestion is useful release evidence, not proof that
no keyboard or OS component retained the input.

## 6. Non-goals

B15 does not ship a custom keyboard, disable all third-party keyboards, inspect
keyboard storage, block accessibility services, sanitize clipboard history,
hide already-rendered content, change message encryption, or create a remotely
negotiated capability. B14 screen security, clipboard hardening, endpoint
integrity, and operating-system trust remain separate boundaries.
