# 11: Feature Scope

The [roadmap](08-roadmap.md) orders the *engineering* milestones (M0 to M6) that
build the protocol, transports, and app shells. This document is the other axis:
which *product* features (the surface a messenger-app user recognizes) belong in
Komms, and under what constraints. It exists so feature requests get triaged
against the architecture instead of against a competitor's feature list.

The organizing question is never "does app X have this?" It is: does the feature
survive a **decentralized, metadata-blind, delay-tolerant, offline-first** system
whose lowest-bandwidth carrier is a LoRa mesh? A feature that assumes a central
coordinator, always-on connectivity, or generous bandwidth either gets redesigned
to fit those constraints or is declined.

Each item notes where it lands: which crate or milestone already covers it, or
what it would take. Nothing here loosens a security or scope commitment in
[01: Why](01-why.md) or the [roadmap](08-roadmap.md); where a feature touches the
protocol, transports, or crypto, it lands only behind an ADR that shows it
surviving the threat model and the mesh bandwidth floor (real-time calls, now in
scope, are the current example: internet/LAN only, ADR-0013 (Proposed)).

## Build (fits the architecture as-is)

These are either already carried by the core crates, are purely client-side, or
map directly onto a shipped mechanism. Most are M5 app-shell UX over an existing
`kult-ffi` surface, not new protocol.

- **Text and audio messages.** The core feature of the protocol and transport
  layers, routed by the scheduler across whatever carrier is up (mDNS, mesh,
  internet). Audio is a recorded clip sent as a message payload, not a live call:
  it rides the same fragmentation path, and on a mesh link it is subject to the
  same airtime budget and "held, will send when a faster link exists" verdict as
  any large payload (M4, §4.2 of the transport spec).
- **End-to-end encryption.** Native to `kult-crypto`; not optional and not a
  toggle. Every message is sealed; there is no unencrypted mode to add.
- **Post-quantum upgrades.** Already the design: the handshake is hybrid PQXDH
  (see [04: Cryptography](04-cryptography.md)). No user-facing feature, listed
  because users ask for it by name.
- **Usernames / contact names.** Identity is a keypair; the human label is a
  local petname or a DHT-resolvable nickname over the kult-address digest, never
  a phone number or a central registry (see [06: Identity & Trust](06-identity-trust.md)).
- **Secure backups.** Shipped: the `KKR2` mnemonic-sealed backup (Argon2id under a
  24-word BIP-39 phrase, ADR-0011/ADR-0012). Stored locally or moved by
  sneakernet; no cloud.
- **Note to self.** A local conversation with no peer, persisted in `kult-store`.
  Purely local.
- **Scheduled / queued messages.** Already implicit in the delivery engine: an
  outbound message sits in the local queue until a carrier is available. A "send
  at time T" hint is a client-side gate on top of the same queue.
- **Text formatting, folders, pins, dark mode, custom icons.** Purely client-side
  UI. No protocol involvement.
- **Screen-security / incognito keyboard.** Platform APIs in the mobile UI layer
  (Android/iOS). No protocol involvement.
- **Local media editing (e.g. face blurring).** Client-side image processing
  applied *before* encryption, so the edited bytes are what gets sealed. No
  protocol involvement, and it keeps the plaintext original off the wire.
- **Mentions and labels.** Client-side string parsing (`@name`) inside the chat
  view. No protocol involvement.

## Build with constraints (needs transport-awareness or local-first sync)

Realistic, but only if they respect carrier bandwidth or tolerate offline/delayed
peers. The recurring rule: the app must know which carrier a peer is reachable on
and degrade honestly, exactly as the delivery ladder already does.

- **File sharing.** Fine over mDNS or internet libp2p; on a radio mesh it must be
  blocked or hard-capped, since a large transfer would monopolize airtime. Reuses
  the fragmentation path but needs a per-carrier size policy in the app.
- **Linked devices.** Multi-device by syncing identity across devices over the
  local network or a direct QR key swap, never a cloud sync. This is the
  Sesame-style multi-device work already parked in M6; the constraint is that
  linking happens proximately, not through a server.
- **Message editing.** Requires decentralized state reconciliation (a simplified
  CRDT or last-writer-wins with vector clocks) across carriers where some peers
  are offline or delayed. Feasible but is real protocol work, not a UI toggle.
- **Disappearing messages / view-once media.** Client-side expiry is easy; the
  hard part is enforcing deletion across mailbox stores and mesh relays that hold
  sealed copies. Needs an absolute expiration token carried in the payload so
  every intermediate store can drop it without reading it.
- **Group polls.** Feasible as structured payload broadcast over the shipped
  sender-key groups (ADR-0012); a poll is just a typed message body plus tallying
  in the UI.
- **Admin / role controls.** Plausible via cryptographic role tokens embedded in
  the group's signed state (creator-managed membership already exists, ADR-0012),
  rather than a server dictating who is an admin.
- **Live voice and video calls.** In scope and on the near horizon, strictly
  confined to high-bandwidth carriers: internet libp2p tunnels and LAN (mDNS),
  never a radio mesh. The core can already negotiate a direct connection (QUIC,
  with DCUtR hole-punching to upgrade relayed paths), so a call sets up a media
  stream over that connection with the identity keys authenticating the peer; no
  central coordinator mints or routes anything. The app must gate the feature on
  carrier: if a peer is reachable only over Meshtastic (or any airtime-budgeted
  link), calling is disabled with an honest reason, the same way the delivery
  ladder already reports "held, will send when a faster link exists." Recorded
  audio/video *clips* (asynchronous payloads) remain in scope on every carrier;
  this entry adds the synchronous case. This touches transports, so it is pinned
  by ADR-0013 (Proposed): media transport choice (SRTP-style over the libp2p
  stream vs. a WebRTC data path), call-setup signaling that stays metadata-blind
  over the pairwise ratchet, and the exact carrier-gating rule.

## Deferred or declined (fights the model)

Structurally incompatible with offline-first, metadata-blind, low-bandwidth-floor
operation, or would collapse a mesh. Any of these would need a compelling ADR to
move.

- **Call links.** Depend on a central cloud coordinator to mint and route ad-hoc
  links to a reachable endpoint. Routing a generic web link to an offline P2P node
  has no meaning here. Declined.
- **Very large groups (1,000+).** Over mesh/radio, fanning one message out to
  hundreds of members causes packet collisions and network collapse. Group caps
  stay low for mesh-reachable groups; large-group work (OpenMLS, M6) targets
  internet-carried groups with explicit caps, never unbounded mesh broadcast.
- **Stories / ephemeral broadcast media.** Global broadcast of ephemeral media is
  heavy vertical overhead that conflicts with a delay-tolerant, data-conserving
  mesh model. Declined.

## How to change this document

Adding a "Build" feature is an app-shell task tracked under M5/M6. Moving anything
out of "Deferred or declined," or adding a feature that touches the protocol,
transports, or crypto, requires an ADR in [docs/adr/](adr/) that shows the feature
surviving the threat model and the mesh bandwidth floor. This keeps the feature
surface honest about the same constraints the rest of the design is held to.
