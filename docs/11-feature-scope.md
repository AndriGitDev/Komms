# 11: Feature Scope

The [roadmap](08-roadmap.md) orders the *engineering* milestones (M0 to M6) that
build the protocol, transports, and app shells. This document is the other axis:
which *product* features (the surface a messenger-app user recognizes) belong in
Komms, and under what constraints. It exists so feature requests get triaged
against the architecture instead of against a competitor's feature list.

The sequenced implementation work for every approved item is in
[12: Feature Delivery Plan](12-feature-delivery-plan.md).

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

These are either already carried by the core crates, stay local to a device, or
fit the architecture without changing its security model. Their shipped/planned
status and prerequisites are tracked in the delivery plan.

- **Text and audio messages.** Both are shipped. Recorded audio is an
  asynchronous encrypted F3 attachment, never a live call: every shell records
  the same bounded metadata-free mono PCM WAV profile, requires local review and
  explicit send/discard, and derives duration/waveform only on the endpoint.
  F4 explains the current carrier at confirmation. Under ADR-0015's hard rule,
  a mesh-only route holds every audio clip for a faster link and emits zero bulk
  airtime frames.
- **End-to-end encryption.** Native to `kult-crypto`; not optional and not a
  toggle. Every message is sealed; there is no unencrypted mode to add.
- **Post-quantum upgrades.** Already the design: the handshake is hybrid PQXDH
  (see [04: Cryptography](04-cryptography.md)). No user-facing feature, listed
  because users ask for it by name.
- **Usernames / contact names.** Identity is a keypair and the authoritative
  human label is a local petname, never a phone number or central-registry name
  (see [06: Identity & Trust](06-identity-trust.md)). An optional signed
  self-display name may later be advertised as a non-unique suggestion, but it
  never silently overrides the recipient's petname.
- **Secure backups.** Shipped: the `KKR4` mnemonic-sealed backup (Argon2id under a
  24-word BIP-39 phrase, ADR-0011/ADR-0012), including sealed local metadata and
  note-to-self history; `KKR1`/`KKR2`/`KKR3` remain restorable. Stored locally or
  moved by sneakernet; no cloud.
- **Note to self.** Shipped as a sealed local conversation in `kult-store`, with
  the reserved `note_to_self` identity across every shell and no peer, envelopes,
  receipts, queue entries, or transport activity. Text is supported; attachments
  follow the attachment shell work.
- **Scheduled / queued messages.** Already implicit in the delivery engine: an
  outbound message sits in the local queue until a carrier is available.
  Scheduling now has a durable absolute-UTC gate in core storage and the node
  scheduler, plus shared RPC/CLI/UniFFI operations for create/list/edit/cancel,
  so app exit or suspension cannot send early. Desktop, Android, and iOS now
  provide local-time composer controls plus distinct editable/cancellable
  scheduled rows before the ordinary queued, sent, and delivered states.
- **Text formatting, folders, pins, dark mode, custom icons.** These stay off the
  wire. Persistent organization and artwork use sealed local storage; formatting
  and themes are rendered by each shell.
- **Screen-security / incognito keyboard.** Platform APIs in the mobile UI layer
  (Android/iOS). No protocol involvement.
- **Local still-image editing.** Shipped across desktop, Android, and iOS through
  one bounded Rust helper: JPEG/PNG orientation normalization, free/preset crop,
  90-degree rotation, and manual blur/pixelation are applied *before* encryption.
  The exact metadata-free PNG is reviewed and is the only asset sealed; protected
  originals and intermediates are cleaned locally. No protocol involvement.
- **Mentions and labels.** Labels are sealed local metadata. Group mentions are
  shipped through explicit current-roster pickers and canonical typed content,
  with exact readable fallback text and stable encrypted peer references rather
  than ambiguous free-form `@name` parsing. Semantic send fails closed unless
  every current co-member has fresh authenticated support; an explicit plain-text
  fallback never notifies. Mention notifications are endpoint-local and
  opportunistic, with no server-push guarantee.

## Build with constraints (needs transport-awareness or local-first sync)

Realistic, but only if they respect carrier bandwidth or tolerate offline/delayed
peers. The recurring rule: the app must know which carrier a peer is reachable on
and degrade honestly, exactly as the delivery ladder already does.

- **File sharing.** Fine over mDNS or internet libp2p; on a radio mesh it must be
  blocked or hard-capped, since a large transfer would monopolize airtime. It
  needs encrypted resumable chunks and sealed manifests rather than treating the
  existing envelope fragmentation path as unbounded file transport.
- **Linked devices.** One account identity uses separately authenticated device
  keys, per-device sessions, revocation, and deterministic sync. Linking happens
  proximately through a confirmed QR or LAN ceremony, never by copying live
  ratchet databases or depending on cloud sync.
- **Message editing.** Requires authenticated revision events and deterministic
  reconciliation across carriers where peers may be offline or delayed. The ADR
  chooses ordering, tombstones, and old-client behavior before implementation.
- **Disappearing messages / view-once media.** Client-side expiry is easy; the
  hard part is enforcing deletion across mailbox stores and mesh relays that hold
  sealed copies. Network retention needs a bounded relay-visible deletion hint,
  cryptographically bound to the encrypted content, because an intermediary
  cannot act on an expiry value visible only after decryption.
- **Group polls.** Feasible as structured payload broadcast over the shipped
  sender-key groups (ADR-0012), with authenticated idempotent vote events and a
  deterministic tally that converges after delayed or reordered delivery.
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
  audio/video *clips* remain asynchronous payloads; audio can be composed on
  every platform but waits for a non-airtime link when F4 reports mesh-only.
  This entry adds the synchronous case. This touches transports, so it is pinned
  by ADR-0013 (Proposed): media transport choice (SRTP-style framing over a
  libp2p path vs. a constrained WebRTC media path), call-setup signaling that
  stays metadata-blind over the pairwise ratchet, and measured qualification of
  any relayed path for the carrier-gating rule.

## Deferred or declined (fights the model)

Structurally incompatible with offline-first, metadata-blind, low-bandwidth-floor
operation, or would collapse a mesh. Any of these would need a compelling ADR to
move.

- **Call links.** A reusable link needs a rendezvous and routing design for a
  caller who has no established pairwise session with a reachable endpoint. No
  metadata-preserving, serverless design has been accepted. Declined.
- **Very large groups (1,000+).** Over mesh/radio, fanning one message out to
  hundreds of members causes packet collisions and network collapse. Group caps
  stay low for mesh-reachable groups; large-group work (OpenMLS, M6) targets
  internet-carried groups with explicit caps, never unbounded mesh broadcast.
- **Stories / ephemeral broadcast media.** Global broadcast of ephemeral media is
  heavy vertical overhead that conflicts with a delay-tolerant, data-conserving
  mesh model. Declined.

## How to change this document

Adding a "Build" feature must also update the delivery plan with its status and
prerequisites. Moving anything out of "Deferred or declined," or adding a feature
that touches the protocol, transports, crypto, or replicated state requires an
ADR in [docs/adr/](adr/) that shows the feature surviving the threat model and
the mesh bandwidth floor. This keeps the feature surface honest about the same
constraints the rest of the design is held to.
