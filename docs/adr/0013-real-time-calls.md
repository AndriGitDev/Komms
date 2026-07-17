# ADR-0013: Real-time voice/video calls over high-bandwidth carriers only

- **Status**: Accepted for audio implementation; platform qualification remains a release gate
- **Date**: 2026-07-13
- **Accepted**: 2026-07-16

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

**Signaling** is a bounded content-v1 `CallControl` event encrypted as an
ordinary pairwise ratchet message. It does not add a cleartext
`EnvelopeKind::CallSignal`: envelope kind is relay-visible in the shipped wire
format, so a dedicated kind would unnecessarily identify call attempts. The
fixed operations are offer, answer, decline, busy, cancel, and hangup. They bind
one random call id, the exact physical sender device, an expiry, and the
operation-specific fields. They are transient control state, not chat history,
search input, notification-preview text, or backup content. A call offer fans
out to every currently authorized recipient device; the first valid answer wins
deterministically and later answers become terminal no-ops.

The offer carries a fresh random 32-byte **call master secret** inside the
Double Ratchet ciphertext. Directional media and media-header keys are derived
with HKDF from that secret, the call id, both stable account ids, and the exact
answering device id. The Double Ratchet root or chain keys are never exported to
the media layer. The first media-stream record proves possession of the derived
key and binds the stream to the answered device before any audio is accepted.
Per-frame sequence, timestamp, key phase, and payload are authenticated; replay,
wrong-call, wrong-direction, and post-hangup frames fail closed. Call secrets and
decoded audio are erased on every terminal transition and are never backed up or
included in C2 sync.

**Media transport** for the audio alpha is one reliable ordered libp2p
substream negotiated as `/komms/call/1` over an already direct QUIC connection.
The pinned `libp2p-quic 0.13.1` transport explicitly disables QUIC datagrams, so
the proposal's earlier “QUIC datagrams inside a libp2p substream” option does
not exist. A bounded writer drops audio frames that have not entered the stream
once they are older than the playout deadline; an endpoint jitter buffer skips
late sequence numbers rather than growing latency without bound. Once bytes
enter the reliable stream, packet loss can still cause head-of-line delay, which
is an explicit alpha limitation and a measured release criterion.

The first implementation therefore requires a fresh direct `/quic-v1` route.
TCP/Yamux, Circuit Relay, mailbox, sneakernet, and every airtime carrier do not
qualify as `realtime`. AutoNAT, relay reservation, and DCUtR may establish and
upgrade connectivity, but the call button remains unavailable until the
ordinary transport layer observes the resulting direct QUIC path. This is more
conservative than treating relay connectivity as media-ready and never emits a
call offer merely because a store-and-forward route exists.

Opus is the only audio wire codec. Capture, acoustic echo cancellation, route
selection, and interruption integration use the native platform audio stack;
the core owns canonical frame bounds, encryption, replay state, jitter policy,
and transport. Video remains out of scope until the audio release matrix passes.
WebRTC is not the automatic fallback: without third-party STUN/TURN it cannot
reuse the shipped libp2p relay path, and adding it would create a second NAT and
dependency surface without solving Komms' constrained-connectivity requirement.

## Transport spike evidence

The executable spike is
`crates/kult-transport/tests/call_transport_spike.rs`. On 2026-07-16 it exercised
the exact locked `libp2p 0.56.0`, `libp2p-quic 0.13.1`, and
`libp2p-stream 0.4.0-alpha` stack with 100 160-byte frames at a 20 ms cadence:

- direct Apple-silicon localhost QUIC: 0.258 ms p95 before an induced receiver
  stall;
- a UDP proxy adding 3 ms per datagram and deterministically dropping 5 % after
  handshake: eight datagrams dropped, every frame recovered in order, 5.30 ms
  p50, 33.7 ms p95, and 35.0 ms maximum; and
- an induced 120 ms receiver stall delayed the ordered stream by 100.8 ms at
  the measured frame, demonstrating that reliable delivery does not remove
  head-of-line latency.

Those measurements select an implementation path; they do not establish mobile
release quality. Real distinct-NAT/DCUtR, Wi-Fi and cellular handoff, sustained
loss/jitter, CPU, battery, Bluetooth, speaker/earpiece, background/lock, and
Android/iOS device results remain mandatory qualification evidence. Failure of
those gates keeps calls alpha-disabled or reopens this ADR; it never silently
widens `realtime` to relay, TCP, or mesh.

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
  traversal, and the ratchet's authenticated confidential channel; adds no
  servers and no new trust root; signaling rides machinery that already exists.
- **Harder:** introduces real-time media handling (codecs, jitter buffering,
  congestion control, echo cancellation), a category the codebase currently has
  none of, and a non-trivial codec dependency that must clear `cargo-deny` and
  the app workspaces' strict posture. Reliable ordered delivery also leaves
  head-of-line latency to bound and qualify. The feature is
  internet/LAN only and must be presented that way everywhere: the UI and the
  marketing copy must never imply calls work off-grid, or they would contradict
  the project's central promise.
- **Committing to maintain:** a carrier-gating rule in every shell (no call
  offered without a direct QUIC route), the bounded `CallControl` content shape,
  transient linked-device arbitration, fresh per-call keys, and the
  `/komms/call/1` stream contract.
- **Revisit if:** the reliable substream cannot meet the platform qualification
  gates, or a bounded low-bitrate voice mode over a fast *local* mesh (not LoRa)
  becomes worth its own ADR. Any unreliable-media or WebRTC alternative needs a
  new measured ADR rather than an implicit fallback.
