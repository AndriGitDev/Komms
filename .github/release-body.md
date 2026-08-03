**Komms 0.4 Beta** is a prerelease for careful testing. Back up important data,
keep the separately protected recovery authority available, and do not rely on
this build for emergency or safety-critical communication.

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
  localization, and accessibility checks are now part of the source tree; and
- every application and internal crate reports version `0.4.0`, with Android
  and iOS build number `4`.

The candidate pipeline builds native desktop packages, both Android flavors,
an unsigned iOS Simulator archive, the headless node, and dedicated reference,
mailbox, wake, and OHTTP service images. A completed public release may contain
only the exact packages bound into its revision-specific evidence archive.
Container publication, store submission, and service deployment remain
separate maintainer-authorized operations; the prepared moving aliases are
`0.4-beta` and `beta`, never `latest`.

This Beta does **not** claim an independent security audit, independent
interoperability, production operator qualification, physical mobile/radio
qualification, universal background delivery, anonymity, remote erasure, or
stable support. No qualified default operator currently ships. `queued`,
`sent`, and `delivered` retain their exact custody meanings, and optional wake
or rendezvous acknowledgement never advances them.

Before installing, verify the package digest and completed evidence archive,
then follow the Beta testing guide, release runbook, and security documentation.
Production signing and publication require their explicit evidence and
authorization boundaries; validation artifacts are not substitutes for them.
