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
- **Scheduled / queued messages.** Shipped. Ordinary queued delivery waits
  honestly for a carrier; scheduled delivery adds a durable absolute-UTC gate
  in core storage and the node
  scheduler, plus shared RPC/CLI/UniFFI operations for create/list/edit/cancel,
  so app exit or suspension cannot send early. Desktop, Android, and iOS now
  provide local-time composer controls plus distinct editable/cancellable
  scheduled rows before the ordinary queued, sent, and delivered states.
- **Text formatting.** Planned as a small safe source-text subset rendered by
  each shell, with no raw HTML, remote fetches, or scriptable links.
- **Conversation pins.** Planned over the shipped F5 `PinRecord`; pin identity
  and manual order stay sealed and local. Message pins remain a separate design
  because they require stable message-reference semantics.
- **Dark mode.** Planned as shared semantic color roles rendered natively by
  each shell; color can never be the only security or delivery signal.
- **Custom icons.** Planned over the shipped F5 icon record with bounded local
  crop/re-encode and no remote avatar lookup or synchronization.
- **Screen-security / incognito keyboard.** Platform APIs in the mobile UI layer
  (Android/iOS). No protocol involvement.
- **Local still-image editing.** Shipped across desktop, Android, and iOS through
  one bounded Rust helper: JPEG/PNG orientation normalization, free/preset crop,
  90-degree rotation, and manual blur/pixelation are applied *before* encryption.
  The exact metadata-free PNG is reviewed and is the only asset sealed; protected
  originals and intermediates are cleaned locally. No protocol involvement.
- **Mentions.** Group mentions are shipped through explicit current-roster
  pickers and canonical typed content,
  with exact readable fallback text and stable encrypted peer references rather
  than ambiguous free-form `@name` parsing. Semantic send fails closed unless
  every current co-member has fresh authenticated support; an explicit plain-text
  fallback never notifies. Mention notifications are endpoint-local and
  opportunistic, with no server-push guarantee.
- **Private labels.** Shipped for pairwise contacts, groups, and note-to-self
  through the sealed F5 metadata store and every wrapper and shell. Stable random
  IDs remain separate from exact names and canonical colors; duplicates use color
  plus deterministic order rather than raw IDs in human-facing UI. Accessible
  managers, non-color badges, assignment actions, stale-record cleanup, and
  deterministic match-any/match-all filters are local presentation only. Limits
  are 128 live labels, 8,192 assignments, 32 labels per conversation, and 256
  UTF-8 bytes per name. `KKR4` preserves exact identity, ordering, membership,
  and stale behavior. Labels do not affect messages, delivery, search, unread
  truth, notifications, or transports and do not sync remotely. Message labels,
  pins, shared tags, and linked-device label sync remain separate work.
- **Private conversation folders.** Shipped for pairwise contacts, groups, and
  note-to-self through F5 and every wrapper and shell. One stable typed
  conversation belongs to at most one folder; All and Unfiled are virtual views.
  Exact duplicate-capable names use stable random IDs plus durable manual order,
  never display-name inference. Create, rename, complete-set reorder, move,
  unfile, deletion review/cascade, and stale cleanup are atomic local operations.
  Folder selection runs before the independent B18 any/all label filter. Limits
  are 128 folders, 8,192 assignments, and 256 UTF-8 bytes per name. `KKR4`
  preserves exact identity, order, membership, and stale behavior. Folders do
  not affect messages, delivery, search, unread truth, notifications, transports,
  or remote state and are not synchronized between devices.

## Build with constraints (needs transport-awareness or local-first sync)

Realistic, but only if they respect carrier bandwidth or tolerate offline/delayed
peers. The recurring rule: the app must know which carrier a peer is reachable on
and degrade honestly, exactly as the delivery ladder already does.

- **File sharing.** The bounded F3 pipeline is shipped across desktop, Android,
  and iOS: independently sealed resumable chunks, explicit consent and lifecycle
  controls, protected export, exact progress, and pairwise/encrypt-once group
  transfer. A hard no-airtime class holds every bulk object for a faster link;
  richer non-image media presentation remains product polish rather than a new
  transport design.
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
- **Optional hybrid reachability and native wake.** In scope only as a
  reversible convenience plane over the unchanged server-independent core.
  Established peers may use rotating provider-specific rendezvous slots for
  encrypted route hints, and a sender may emit a content-free APNs/FCM wake only
  after a direct peer or recipient-selected mailbox accepted the sealed
  envelope. DHT/QR remains first-contact discovery, mailboxes remain durable
  delivery, encrypted receipts remain delivery truth, and complete service
  failure falls back to Sovereign mode. Standard mode discloses service-use
  metadata; Private mode reduces source/target linkage through Tor or a
  non-colluding OHTTP relay without promising global anonymity. The feature is
  governed by proposed ADR-0017, ADR-0018, and ADR-0019 and does not ship until
  all three are accepted.

## Deferred or declined (fights the model)

Structurally incompatible with offline-first, metadata-blind, low-bandwidth-floor
operation, or would collapse a mesh. Any of these would need a compelling ADR to
move.

- **Call links.** A reusable link needs a rendezvous and routing design for a
  caller who has no established pairwise session with a reachable endpoint.
  ADR-0018 deliberately creates slots only after pairing and does not solve this
  first-contact problem. No acceptable design has been accepted. Declined.
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
ADR listed in the [ADR index](adr/README.md) that shows the feature surviving
the threat model and the mesh bandwidth floor. This keeps the feature surface
honest about the same constraints the rest of the design is held to.
