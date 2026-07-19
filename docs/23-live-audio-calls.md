# 23: Live Audio Calls

Komms ships an alpha live-audio path for already paired contacts. Calls are
peer-to-peer, authenticated by the same identities as messages, and available
only when both endpoints have a fresh direct QUIC route. There is no Komms call
server, signaling service, SFU, STUN/TURN service, or reusable call link.

This document describes the implemented C7 audio contract. Video is not part of
the shipped path. [ADR-0013](adr/0013-real-time-calls.md) is normative for the
transport and cryptographic decisions.

## 1. Availability and honest limits

The call action is enabled only when the shared carrier assessment reports a
fresh direct `/quic-v1` path and every authorized recipient device supports the
exact call-control format. A relayed connection may be upgraded with DCUtR, but
it does not qualify until the direct QUIC path is actually observed.

Komms refuses to start a call over:

- TCP/Yamux fallback;
- Circuit Relay without a completed direct upgrade;
- volunteer mailboxes;
- Meshtastic or any other airtime-budgeted carrier;
- sneakernet bundles; or
- an offline, unknown, incompatible, or sessionless route.

The UI reports the exact unavailable reason. It never converts a call attempt
into queued or store-and-forward work. Recorded audio messages remain the
asynchronous alternative and retain their separate F3/F4 delivery rules.

## 2. Signaling

Offer, answer, decline, busy, cancel, and hangup are bounded content-v1
`CallControl` values carried inside ordinary pairwise Double Ratchet messages.
No relay-visible call envelope kind was added. A control binds:

- a cryptorandom 16-byte call id;
- the exact initiating and responding physical-device ids;
- a short expiry (ordinary offers last 60 seconds; remote claims beyond the
  90-second bound fail closed); and
- the operation-specific authenticated fields.

An offer fans out to the currently authorized devices on the recipient's
account. The first valid answer wins; other devices end honestly. Call controls
are transient: they do not appear in chat history, search, backups, C2 sync, or
notification-preview text. Recent terminal state may remain renderable for five
minutes, without retaining call secrets.

## 3. Media security and transport

The offer carries a fresh 32-byte call master secret inside the ratchet. The
core derives directional media and header keys from that secret, the call id,
both stable account identities, and the exact answering device. Ratchet root and
chain keys never cross into the media layer.

Audio uses one `/komms/call/1` reliable ordered substream on the already direct
QUIC connection. Both directions must first authenticate a media hello. Every
subsequent record binds its direction, sequence, timestamp, key phase, and
payload under XChaCha20-Poly1305. The core rejects tampering, replay,
wrong-call/wrong-device/wrong-direction frames, invalid key phases, and media
after a terminal transition. Keys rotate every 4,096 records; the replay window
is 128 records.

Opus is the only audio packet format. Shells capture and play 48 kHz mono audio
in 20 ms frames at 24 kbit/s through native audio APIs. An Opus packet is at
most 1,275 bytes. The core bounds the unsent queue to eight frames, discards a
not-yet-written packet after 200 ms, starts playout after three authenticated
frames, and caps jitter storage at six frames. Reliable QUIC can still suffer
head-of-line delay; the alpha does not hide that limitation.

## 4. Platform behavior

- **Desktop:** the Tauri shell uses native browser audio capture/playback and a
  bounded WebCodecs Opus path. Hiding or locking the app ends live capture and
  the call.
- **Android:** `AudioRecord`, `AudioTrack`, and the platform Opus codec provide
  the native voice-communication path. Microphone permission is requested only
  when the user starts or answers. Backgrounding tears the call down; the
  ordinary delivery foreground service does not claim continuous calling.
- **iOS:** AVFoundation voice processing and the native Opus codec provide the
  audio path. Backgrounding, protected-data loss, interruption, or media-service
  reset tears down or fails the call honestly.

Every shell provides ring/answer/decline, outgoing cancel, active hangup, an
explicit direct-QUIC/no-history explanation, accessible state text, and a
single-live-call limit. Starting a call first discards or stops any unsent
recorded-audio capture so two microphone pipelines cannot overlap.

## 5. Privacy boundary

Call state, master secrets, derived keys, decoded PCM, and Opus queues are
memory-only. They are not stored, backed up, synchronized, indexed, logged, or
placed in crash/analytics payloads. Terminal transitions erase core secrets and
shells zero temporary media buffers where their platform APIs permit.

Network observers still see that the two IP endpoints exchange QUIC traffic,
plus timing and volume. Direct peer-to-peer calling does not provide network
anonymity, hide a peer's network address from the other peer, or survive a
compromised endpoint. Screen security does not prevent a recipient from using
another device to record a call.

## 6. Acceptance and remaining release evidence

Automated acceptance covers canonical and malformed control decoding,
call-specific key derivation, replay/tamper/wrong-context failure, key rotation,
bounded queues and jitter, direct-QUIC-only gating, TCP/relay/mesh refusal,
linked-device first-answer arbitration, expiry, bidirectional authenticated
Opus packets, exact hangup, no chat history, RPC/CLI, UniFFI, and desktop,
Android-host, and iOS-host two-node lifecycles. The real iOS Simulator app also
builds unsigned from the generated XCFramework on a full Xcode host.

These remain release qualification rather than implementation claims:

- two real networks behind distinct NATs, including DCUtR upgrade;
- sustained loss/jitter, Wi-Fi/cellular handoff, CPU, memory, and battery;
- speaker, earpiece, wired, Bluetooth, and interruption matrices on real phones;
- foreground/background/lock behavior on supported Android and iOS releases;
- acoustic echo and intelligibility measurements; and
- hands-on Android/iOS device, lifecycle, and audio-route validation (Android
  debug-APK assembly and unsigned iOS Simulator builds are already automated
  compilation evidence).

Failure of a qualification gate keeps calls alpha or disabled for that platform;
it never widens the carrier rule or invents a fallback through relay, TCP, radio,
or a central service.
