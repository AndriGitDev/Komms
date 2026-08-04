> [!WARNING]
> **Komms 0.4.2 Beta is an unsigned, pre-production test release.** It bypasses
> the production-signing and protected-publication gates for version 0.4.2
> only. Do not use it for emergency, safety-critical, or production
> communication.

The public assets are bound to tag `v0.4.2` and commit
`5a09190cfef9cfef92703672517bc008b6e8cc1f`. Back up disposable test data and
keep the separately protected recovery authority available.

This release replaces the 0.3 Alpha trust and delivery foundations rather than
merely polishing them:

- linked devices now use revocable, strict-majority device authority with
  visible fork/conflict handling and root-authorized recovery epochs; the
  stable account private key is no longer copied into routine live state or
  backups;
- sender-key groups retain encrypt-once ciphertext while authenticating each
  claimed origin separately for every recipient and security-sensitive event;
- unknown senders and group invitations enter a bounded Message Request domain
  with explicit Accept, Delete, and Block decisions;
- Connect codes replace identity-indexed discovery with a rotatable random
  capability, fixed-size encrypted records, bounded lookup, and explicit legacy
  retirement;
- durable mailbox v2 uses committed deposits, idempotent leases, exact
  acknowledgement after endpoint staging, restart-safe quotas, and bounded
  content-free operator health;
- rotating pairwise rendezvous and content-free native wake are separated into
  least-authority services, with Standard, Private, and Sovereign sharing one
  replaceable-provider contract;
- Android and iOS implement the common wake lifecycle while preserving a
  Google-free Android flavor and ordinary delivery when optional providers
  fail;
- the stable-v1 protocol specification, language-neutral fixtures,
  conformance runner, release evidence controls, operator runbooks,
  localization, and accessibility checks are now part of the source tree;
- every application and internal crate reports version `0.4.2`, with Android
  and iOS build number `6`; and
- desktop first run uses the native Save dialog for the offline authority and
  keeps failed or cancelled destinations safely retryable.

The complete hosted validation pipeline passed. This public test set contains
unsigned native desktop packages, unsigned Android validation packages, a
Google-free Android APK signed with a test/debug certificate, and an unsigned
iOS Simulator archive. Container publication, store submission, and service
deployment remain separate maintainer-authorized operations; the prepared
moving aliases are `0.4-beta` and `beta`, never `latest`.

This Beta does **not** claim an independent security audit, independent
interoperability, production operator qualification, physical mobile/radio
qualification, universal background delivery, anonymity, remote erasure, or
stable support. No qualified default operator currently ships. `queued`,
`sent`, and `delivered` retain their exact custody meanings, and optional wake
or rendezvous acknowledgement never advances them.

Before installing, verify the package against `UNSIGNED-TEST-SHA256SUMS` and
follow the Beta testing guide. The attached validation archive correctly
reports `production_signed: false`, `qualified_for_stable: false`, and
`independently_reproduced: false`; it is not an offline release signature.
Production signing, authenticated updates, qualification, store distribution,
and stable publication remain open. The 0.4.2 exception does not authorize a
later release to bypass those gates.
