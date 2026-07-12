# ADR-0010 — kult-ffi embeds the node runtime in-process

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

M5 needs `kult-ffi`: the UniFFI layer through which the Tauri desktop app and the
Kotlin/Swift mobile shells drive a node. The implementation guide pins the surface —
"exactly `Node`'s command/event API, nothing more" — but three shape questions remain
open, and each constrains the apps for years:

- **Where does the running node live?** `kult-node` is a passive library: something
  must own it, tick the delivery engine, and run the connectivity lifecycle (DHT
  bootstrap and bundle publication, NAT probing with relay reservation, mailbox
  check-ins). On desktop that something could be the existing `kultd` daemon behind
  its Unix socket; on iOS and Android there is no daemon to run — the node must live
  inside the app process.
- **Sync or async calls?** UniFFI can export blocking methods or async ones (foreign
  futures). The node itself is an actor ticking on its own thread either way.
- **How do binary identifiers cross the boundary?** Peer ids, message ids, and prekey
  bundles are raw bytes in Rust; apps use them as map keys, list identities, and QR
  payloads.

## Decision

`kult-ffi` embeds the full runtime in-process: one constructor opens the store,
attaches the configured carriers, and starts the same actor/tick/lifecycle
composition `kultd` runs — no external daemon, no socket. Methods are **blocking**;
events reach the application through a registered callback listener on a dedicated
thread. Peer and message ids cross as lowercase hex strings; prekey bundles as bytes;
delivery states and events as typed enums mirroring `kult-node`'s.

## Alternatives considered

- **FFI as a client of `kultd`'s socket RPC**: reuses the daemon's runtime and keeps
  one composition root. Rejected: there is no way to run a separate daemon on iOS
  (and only fragile ones on Android), so mobile needs the embedded path regardless —
  a socket-client FFI would mean maintaining *two* FFI transports or abandoning
  mobile. Desktops that want a long-lived shared node can still run `kultd` and speak
  the documented JSON RPC directly; the two front doors deliberately mirror each
  other, and a change to one almost always belongs in the other.
- **Extracting the shared runtime into `kult-node` (or a new crate)** so `kultd` and
  `kult-ffi` compose it once. Deferred, not rejected: the duplicated surface is ~200
  lines of composition with no protocol logic, and moving it into `kult-node` would
  drag tokio and concrete transport types into the layer the architecture keeps them
  out of. If the two copies drift or a third front door appears, extraction is the
  natural refactor and would supersede this point.
- **Async (foreign-future) methods**: strictly more machinery on both sides of the
  boundary — every exported call becomes a future bridged into each language's
  executor — for operations that are either sub-millisecond channel round-trips or
  rare (`add_contact_by_address`). Rejected for the first slice: blocking calls
  dispatched off the UI thread are one idiomatic line in Kotlin and Swift. Revisit if
  app work shows real need (e.g. structured cancellation of DHT lookups).
- **Raw byte ids at the boundary**: no encoding cost, but every language then needs a
  byte-array-keyed map and equality discipline; hex strings are copyable, loggable,
  and already the convention in `kultd`'s wire format and CLI. Bundles stay bytes
  because they are payloads (QR codes, files), not identifiers.

## Consequences

- A mobile or desktop shell gets a working node — internet carrier, LAN mDNS,
  mailboxes, NAT traversal, optional radio and spool — from one constructor call, and
  the M5 acceptance criteria can be exercised end-to-end through this one surface
  (the crate's e2e test drives two nodes to verified delivery exactly as a shell
  would).
- We commit to keeping `kult-ffi`'s runtime and `kultd`'s daemon in lockstep by
  review (both files say so); the extraction alternative above is the trigger-ready
  remedy if that discipline fails.
- Mobile platform realities (background execution limits, push-less wakeups) are
  squarely the app layer's problem and untouched by this ADR; the embedded runtime
  simply stops when the OS stops the process, and the store's queue persistence
  (M2) makes that safe.
- Blocking calls mean a careless shell can jank its UI thread; the crate docs state
  the dispatch expectation. The event thread never blocks the node: the listener
  runs downstream of an unbounded channel.
