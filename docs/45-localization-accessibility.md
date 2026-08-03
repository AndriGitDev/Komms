# 45: Localization and Accessibility

Komms uses one versioned localization contract across desktop, Android, and
iOS. English (`en-US`) is the required fallback and Icelandic (`is`) is the
first complete non-English locale. Language choice is private presentation
state: it cannot change identity, protocol bytes, cryptographic trust,
delivery semantics, contacts, or history.

This document records implemented controls and their limits. It is not an
external accessibility assessment and does not qualify a physical device.

## 1. Canonical localization contract

The shared catalog and shell-specific paired messages live in
[`locales/`](../locales/). Generated Android resources, the desktop bundle, iOS
JSON catalogs, `Localizable.strings`, and `InfoPlist.strings` are derived from
that source.

The contract enforces:

- stable lowercase identifiers and identical identifier sets;
- identical text/plural shape and positional placeholder types;
- English and Icelandic `one`/`other` plural selection;
- NFC text with catalog bidi controls rejected;
- first-strong isolation around inserted strings;
- explicit rationale for intentionally untranslated technical values;
- fail-closed unknown identifiers and malformed resources;
- bounded translation expansion and complete generated-resource parity; and
- strict source coverage for desktop HTML/JavaScript, Android source adapters,
  and SwiftUI/static iOS copy.

System, English, and Icelandic selection is available before unlock and in
settings on all three shells. Unsupported system languages fall back to
English. The override is stored only as local appearance state.

Run the bounded localization profile:

```sh
python3 scripts/contributor-check.py localization
```

Or run its individual controls:

```sh
python3 scripts/localization.py check
python3 scripts/check-localization-sources.py
python3 scripts/test-localization.py
python3 scripts/check-shell-accessibility.py
```

## 2. Accessibility surface contract

| Surface | Implemented shell contract |
|---|---|
| Onboarding and modes | semantic headings and labels, described mode controls, scalable text, pre-unlock language choice, and visible security disclosures |
| Message requests and invitations | separate list semantics, labelled safety/name controls, 44-point actions, explicit Accept/Delete/Block/Join behavior, focus recovery, and polite status announcements |
| Conversations and groups | conversation-log semantics, labelled composer/actions, keyboard-operable mention and organization controls, authenticated-origin status, poll state and vote labels, and non-color delivery cues |
| Attachments and audio | labelled progress, explicit consent and terminal view-once language, protected preview descriptions, non-autoplay audio, and accessible playback controls |
| Calls | labelled availability/action state and status announcements without changing delivery semantics |
| Backup, recovery, and devices | secure-field classification, alert semantics, labelled comparison codes and QR frames, conflict announcements, and explicit irreversible-action copy |
| Settings and organization | natural focus order, keyboard navigation on desktop, labelled folders/labels/icons, scalable platform controls, and immediate language/theme feedback |

Desktop controls have a 44 CSS-pixel minimum target, visible focus rings,
dialog focus containment and restoration, arrow-key navigation for composite
controls, a higher-contrast media profile, and a reduced-motion profile.
Android uses scalable `sp`, theme-level 48/52 dp targets, live regions,
headings, label relationships, and explicit announcements. iOS uses Dynamic
Type styles, native focus order, 44-point custom controls, combined semantic
groups, update traits, and no nonessential custom animation.

The automated contrast gate evaluates normal-text role pairs at WCAG AA
4.5:1 or greater in both light and dark palettes. Color remains supplemental:
delivery, warning, selection, and security state also have text, symbols,
traits, or borders.

## 3. Evidence boundary

Automated source and simulator checks can prove that required labels, focus
logic, target sizes, localization resources, plural rules, and palette
relationships are present. They cannot prove VoiceOver/TalkBack usability,
switch-control behavior, motor accessibility, real-device font clipping,
platform magnification, cognitive clarity, or the experience of disabled
users.

The following remain open:

- named physical-device runs at the largest supported text sizes;
- complete VoiceOver, TalkBack, keyboard, switch-control, contrast, reduced
  motion, and screen-magnification journeys;
- localization review by a fluent Icelandic reviewer; and
- an independent accessibility assessment with retained findings and retest
  dispositions.

Simulator observations stay labelled as simulator evidence in the
[field-qualification matrix](43-field-qualification.md). No accessibility row
becomes externally reviewed or field-qualified without the named execution.
