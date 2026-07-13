# ADR-0003: In-house Double Ratchet with hybrid PQXDH handshake

- **Status**: Accepted
- **Date**: 2026-07-11

## Context

The E2EE session layer needs forward secrecy, post-compromise security, deniability,
tolerance of long offline gaps and heavy reordering (mesh reality), small wire overhead
(LoRa reality), and resistance to harvest-now-decrypt-later.

## Decision

Implement the Signal-published designs ourselves on RustCrypto primitives: PQXDH-style
hybrid initial key agreement (X25519 + ML-KEM-768) and the Double Ratchet with header
encryption, with delay-tolerance parameters fixed in
[04: Cryptography](../04-cryptography.md). Designs are adopted verbatim from the
published specifications; only encoding and parameters are ours.

## Alternatives considered

- **Wrap libsignal**: most audited code, but AGPL-on-AGPL is fine while the *architecture*
  isn't: libsignal assumes Signal's server model, its session/prekey plumbing resists
  our DHT/mesh distribution, and mesh-motivated changes (skip windows, compact encoding)
  would mean maintaining a fork of a moving target anyway.
- **MLS (RFC 9420) for everything**: the group-messaging state of the art, but handshake
  and commit messages are large and chatty (hostile to 200-byte frames) and 1:1
  messaging gains nothing over the Double Ratchet. Adopted instead as the *large-group*
  path in M6.
- **Noise-based session (e.g. WireGuard-style)**: excellent for live links, but no
  asynchronous first message to offline recipients and no per-message ratchet.

## Consequences

Full control over encoding, parameters, and mesh adaptations; the implementation must
earn trust through the test obligations of 04 §11 and the M6 external audit. Implementing
published designs (not inventing primitives or protocols) keeps this on the defensible
side of "don't roll your own crypto."
