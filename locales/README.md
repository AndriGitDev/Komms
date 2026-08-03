# Komms localization catalogs

`en-US.json` and `is.json` hold the shared canonical catalog.
`shell-messages.json` adds explicitly paired shell copy while
`intentionally_unchanged` records bounded technical exceptions. Together they
are the source of user-facing strings for the desktop, Android, and iOS
shells. Stable identifiers are lowercase snake-case and survive copy edits.
Platform resources are generated from these catalogs; changing a generated
copy directly is rejected.

## Contract

- Every locale contains exactly the same identifiers and the same text/plural
  shape.
- Stable-v1 uses `one` and `other` plural forms. Icelandic selects `one` for
  values ending in 1 except those ending in 11.
- `%1$s` and `%1$d` are positional string and integer placeholders. A
  translation may reorder positions but may not change, add, or remove their
  types.
- Renderers wrap substituted strings in Unicode first-strong isolation.
  Catalogs themselves must be NFC and contain no bidi marks, embeddings,
  overrides, or isolates.
- A missing requested locale falls back to `en-US`. A missing identifier,
  malformed catalog, placeholder mismatch, or missing default catalog fails
  closed.
- Icelandic text may equal English only when `intentionally_unchanged` records a
  bounded reason for that exact identifier, such as a product name or canonical
  filename.
- Catalog values are plain text. They never contain HTML, Markdown, links, log
  fields, secrets, or executable formatting.

## Update

Edit the relevant canonical entries and their paired Icelandic values, then
run:

```sh
python3 scripts/localization.py generate
python3 scripts/check-localization-sources.py
python3 scripts/test-localization.py
```

The generator writes Android `values`/`values-is`, the desktop catalog bundle,
and the two iOS JSON resources. The release and contributor checks use
`python3 scripts/localization.py check`, which regenerates in memory and rejects
any drift.

Each shell exposes System, English, and Icelandic selection. The preference is
private local presentation state; it does not alter identity, message formats,
trust, delivery semantics, or protocol state. System selection follows the
platform language, and an unsupported locale falls back to English.

Security, recovery, safety-number, authority, consent, blocking,
delivery-state, provider, and error copy requires the sensitive-surface review
recorded in `CODEOWNERS`. Translators should preserve the exact distinction
between queued, sent, delivered, read, local deletion, remote deletion,
identity, device authority, and optional-service availability.
