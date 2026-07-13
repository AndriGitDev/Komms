# ADR-0001: Rust core with UniFFI bindings

- **Status**: Accepted
- **Date**: 2026-07-11

## Context

One protocol implementation must serve desktop, iOS, Android, headless relays, and
eventually microcontroller-class mesh gateways. Duplicate implementations of security
code across platforms multiply audit surface and guarantee divergence.

## Decision

All crypto, protocol, transport, and storage logic lives in one Rust workspace
(`kult-*` crates). Clients consume it through UniFFI-generated bindings (Kotlin, Swift)
and Tauri (desktop). `kult-crypto` stays `no_std`+alloc compatible.

## Alternatives considered

- **Go**: mature go-libp2p, but gomobile FFI is clumsy, GC pauses and binary size hurt on
  mobile, and there is no credible embedded story.
- **TypeScript/Node**: fastest UI iteration, unacceptable for constant-time crypto and
  off-grid/embedded targets.
- **C/C++ core**: maximum portability, memory-unsafety in exactly the code that must not
  have it.

## Consequences

Single audited implementation; memory safety in the TCB; strongest ecosystem fit
(RustCrypto, rust-libp2p, zeroize/subtle). Cost: UniFFI binding maintenance and slower UI
iteration than a pure-JS stack, accepted.
