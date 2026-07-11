# ADR-0002 — XChaCha20-Poly1305 as the universal AEAD

- **Status**: Accepted
- **Date**: 2026-07-11

## Context

One AEAD is used for messages, storage, sealed state, and bundles. The system targets
phones and cheap mesh-gateway hardware, and encrypts under high concurrency where nonce
management mistakes are the classic failure mode.

## Decision

XChaCha20-Poly1305 everywhere, with randomly generated 24-byte nonces carried alongside
the ciphertext.

## Alternatives considered

- **AES-256-GCM**: fastest with AES-NI, but slow *and* side-channel-prone in software on
  hardware without it (older phones, RISC-V/ESP32-class gateways), and its 96-bit nonce
  makes random nonces a birthday-bound liability at our message volumes.
- **ChaCha20-Poly1305 (96-bit nonce)**: same software profile, same nonce liability —
  would force stateful nonce counters through every ratchet and storage path.
- **AES-GCM-SIV / AEGIS**: misuse resistance or speed, but far less ubiquitous across the
  library and platform matrix we need, and AEGIS again favors AES hardware.

## Consequences

Random nonces are safe by margin (2⁻³² collision at ~2⁸⁰ messages), eliminating an entire
bug class; uniform performance across all target hardware; 24-byte nonce overhead per
envelope — accepted, and the padding buckets account for it.
