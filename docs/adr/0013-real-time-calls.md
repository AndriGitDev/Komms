# ADR-0013: Real-time voice/video calls over high-bandwidth carriers only

- **Status**: Proposed
- **Date**: 2026-07-13

## Context

The roadmap now puts live voice and video calls on the near horizon
([08: Roadmap](../08-roadmap.md), [11: Feature Scope](../11-feature-scope.md)).
This is the first **synchronous, real-time media** path in a system otherwise
built entirely around asynchronous, delay-tolerant, sealed messages, and it
forces decisions the store-and-forward design never had to make. The design
constraints that bound the choice are the same ones the rest of Komms is held to:

- **No project-operated infrastructure.** No STUN/TURN servers, no SFU, no
  signaling server. Whatever a call needs, it establishes peer to peer, the same
  way messages do. This is also why "call links" stays declined in feature scope.
- **Metadata-blind.** Call setup must not reveal who is calling whom to any
  intermediary, so it cannot introduce a coordinator or a side channel weaker
  than sealed sender (04 §7).
- **Carrier reality.** A real-time bidirectional media stream is fundamentally
  incompatible with the LoRa mesh (233-byte frames, region duty-cycle budget) and
  with store-and-forward mailboxes or sneakernet. Calls only make sense on the
  high-bandwidth carriers the transport core already builds: internet libp2p
  (QUIC primary, TCP fallback) and LAN/mDNS, with Circuit Relay v2 + DCUtR
  upgrading relayed paths to direct ones.
- **One trust root.** A call must be end-to-end encrypted and peer-authenticated
  under the existing identity keys, introducing no new key hierarchy.

## Decision

Calls are **confined to internet libp2p and LAN/mDNS connections** and are
**disabled over any airtime-budgeted mesh link or store-and-forward carrier**. The
app gates the feature on the peer's reachable carrier and, when only a mesh or
mailbox path exists, offers no call and says why, mirroring the delivery ladder's
honest "held, will send when a faster link exists" verdict. Asynchronous
audio/video **clips** are unaffected and remain ordinary payloads on every carrier.

**Signaling** (offer/answer and ICE-like candidate exchange) travels as ordinary
sealed envelopes over the existing pairwise Double Ratchet session, as a new
`EnvelopeKind::CallSignal`, so call setup is exactly as metadata-blind as
messaging: no signaling server, no coordinator, sealed sender preserved. NAT
traversal reuses the in-network trio already shipped (AutoNAT, Circuit Relay v2,
DCUtR); candidates are restricted to host/peer-reflexive plus our own relay
addresses, never a third-party STUN/TURN server.

**Media encryption** is keyed from the session secret via HKDF (a dedicated
call-media key), so the media stream is E2EE under the same identity keys that
authenticate the peer. No new trust root.

**Media transport** is the one open sub-decision, to be settled by a spike:

- *Option A (default):* media over a dedicated libp2p substream
  (`/komms/call/1`, QUIC datagrams for the media path), with SRTP-style framing
  keyed from the ratchet. Keeps the whole call inside the existing libp2p
  connection and dependency surface.
- *Option B (fallback):* a WebRTC media path (libwebrtc) for its mature
  congestion control, jitter buffering, and codecs, DTLS-SRTP keyed out of band
  via the ratchet-carried signaling, ICE restricted as above. Chosen only if
  raw-QUIC media quality proves too costly to build well.

Option A is preferred to keep the dependency and metadata surface minimal; the
codec (Opus for audio; a low-complexity video codec for video) is common to both.

## Alternatives considered

- **Central SFU or cloud call coordinator (Signal call-links model).** Rejected:
  requires project-operated infrastructure and breaks metadata-blindness. It is
  the same reason "call links" is declined in [11: Feature Scope](../11-feature-scope.md).
- **Calls over the LoRa mesh.** Rejected: 233-byte frames and duty-cycle limits
  make real-time bidirectional media impossible, and attempting it would collapse
  the mesh for everyone on it. Calls are explicitly an on-grid feature.
- **Third-party STUN/TURN for NAT traversal.** Rejected: leaks connection
  metadata to external servers. We already have AutoNAT + Relay v2 + DCUtR in
  network (ADR-0004 and the M3 NAT work).
- **A separate real-time signaling channel.** Rejected: any channel outside the
  sealed pairwise ratchet would weaken the metadata posture; the ratchet already
  carries typed control messages (group control, receipts) and can carry call
  signaling the same way.

## Consequences

- **Easier:** reuses the transport core's connection establishment, NAT
  traversal, and the ratchet's key material and authentication; adds no servers
  and no new trust root; signaling rides machinery that already exists.
- **Harder:** introduces real-time media handling (codecs, jitter buffering,
  congestion control, echo cancellation), a category the codebase currently has
  none of, and a non-trivial dependency (Opus, possibly libwebrtc) that must
  clear `cargo-deny` and the app workspaces' strict posture. The feature is
  internet/LAN only and must be presented that way everywhere: the UI and the
  marketing copy must never imply calls work off-grid, or they would contradict
  the project's central promise.
- **Committing to maintain:** a carrier-gating rule in every shell (no call
  offered when only mesh/mailbox reachability exists), and the CallSignal
  envelope shape.
- **Revisit if:** raw-QUIC media quality proves inadequate (switch to Option B),
  or a bounded low-bitrate voice mode over a fast *local* mesh (not LoRa) becomes
  worth its own ADR.
