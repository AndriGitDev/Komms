# 02 — Threat Model

This document defines who KommsKult defends against, what it protects, and — just as
importantly — what it does *not* claim to protect. Every design decision in
[03 — Architecture](03-architecture.md) and [04 — Cryptography](04-cryptography.md) traces
back to a row in this document.

## 1. Assets

| Asset | Description |
|---|---|
| **Message content** | Text, media, and files exchanged between users. |
| **Message metadata** | Who talks to whom, when, how often, from where, and message sizes. |
| **Identity keys** | Long-term Ed25519/X25519 key material that *is* a user's identity. |
| **Session state** | Ratchet state whose compromise could expose past or future messages. |
| **Local message history** | The plaintext database on a user's own device. |
| **Social graph** | Contact lists and group memberships. |
| **Availability** | The ability to communicate at all, including when infrastructure is down or hostile. |

## 2. Adversaries

Listed roughly in ascending order of capability.

### A1 — Mass content scanning (the ChatControl model)
An actor with legal or technical leverage over *service providers*, compelling them to scan,
filter, or report message content (client-side or server-side).

**Defense**: there is no service provider to compel. No KommsKult component ever has access
to plaintext other than the endpoints. There is no server operator who can be ordered to
insert scanning, because there are no servers — see [03 — Architecture](03-architecture.md).

### A2 — Passive network observer
An ISP, IXP tap, or national passive-collection program recording traffic.

**Defense**: all traffic is end-to-end encrypted (content) and transport-encrypted
(links). Padding to size buckets and encrypted ratchet headers reduce what
traffic analysis yields. Full traffic-analysis resistance is **partial** — see §5.

### A3 — Active network attacker / censor
An actor who can block, throttle, inject, or MITM traffic: national firewalls, hostile
Wi-Fi, BGP hijackers.

**Defense**: transport authentication (Noise/TLS with pinned peer keys) defeats MITM.
Censorship is countered by transport diversity: if the internet path is blocked, the same
envelopes flow over LAN, BLE, LoRa mesh, or sneakernet
([05 — Transports](05-transports.md)). Obfuscated internet transports are on the
roadmap ([08 — Roadmap](08-roadmap.md), M6).

### A4 — Infrastructure seizure / shutdown
Confiscation of relays, takedown of bootstrap nodes, or a regional internet blackout.

**Defense**: no single point of failure by construction. Any node can relay; discovery is
DHT-based with multiple bootstrap paths; the Meshtastic/LoRa fallback functions with zero
internet infrastructure. Loss of any relay loses nothing but its queued ciphertexts, which
are sealed and padded.

### A5 — Malicious peer or relay
A participant in the network — a relay holding mailboxes, a DHT node, a mesh repeater —
that logs, drops, replays, or forges traffic.

**Defense**: relays only ever see sealed envelopes (no sender identity, padded sizes,
opaque recipient tokens). AEAD + ratchet ordering defeats forgery and replay. Dropping is
mitigated by redundant delivery across transports and delivery receipts; a relay that
drops everything degrades into adversary A4, already handled.

### A6 — Retrospective decryption ("harvest now, decrypt later")
An actor recording ciphertext today, hoping to decrypt it with a future
cryptanalytic advance or quantum computer.

**Defense**: hybrid post-quantum key agreement (X25519 **and** ML-KEM-768; both must fall)
plus forward secrecy from the Double Ratchet. See [04 — Cryptography](04-cryptography.md).

### A7 — Endpoint compromise (targeted)
Malware, forensic seizure of an unlocked device, or a coerced unlock — against a *specific*
target.

**Defense (bounded)**: at-rest encryption under an Argon2id-derived key protects a
powered-off/locked device. Forward secrecy means a captured device does not reveal
messages deleted before capture; post-compromise security means a *transient* compromise is
healed by the next DH ratchet step. A persistently compromised endpoint sees everything its
user sees — no messenger can prevent that (§5).

## 3. Security goals

| Goal | Meaning | Mechanism |
|---|---|---|
| **Confidentiality** | Only intended recipients read content. | XChaCha20-Poly1305 AEAD under Double Ratchet keys. |
| **Integrity & authenticity** | Messages cannot be altered or forged. | AEAD tags; identity-key-signed handshakes. |
| **Forward secrecy** | Key compromise doesn't expose past messages. | Symmetric + DH ratchets; keys zeroized after use. |
| **Post-compromise security** | Security self-heals after transient compromise. | DH ratchet steps on every round trip. |
| **Post-quantum confidentiality** | A6 resistance for content. | Hybrid PQXDH-style handshake (ML-KEM-768). |
| **Metadata minimization** | Network learns as little as possible about who/when/how much. | Sealed sender, encrypted headers, size-bucket padding, no central rendezvous. |
| **Deniability** | Transcripts are not cryptographic proof of authorship to third parties. | No signatures over message content; authentication via shared MAC keys (Signal-style). |
| **No mandatory identifiers** | No phone number, email, or real name — ever. | Keypair-as-identity ([06 — Identity & Trust](06-identity-trust.md)). |
| **Availability off-grid** | Communication survives infrastructure loss. | Transport abstraction with LoRa mesh + sneakernet fallbacks. |
| **Sovereignty** | Users hold their own keys and data; anyone can run every component. | Local-first storage, AGPLv3, no privileged nodes. |

## 4. Non-goals and accepted limitations

Honesty here is a security feature. KommsKult does **not** claim to provide:

1. **Anonymity against a global passive adversary.** Correlating traffic across the whole
   internet can link endpoints. Mitigations (Tor/arti integration, cover traffic) are
   roadmap items, not launch guarantees.
2. **Protection on a persistently compromised endpoint** (A7, persistent). If the OS is
   hostile, the screen and keyboard are hostile.
3. **LoRa radio-layer anonymity.** Transmitting on LoRa is physically observable and
   direction-findable. The mesh hides *content* and (with sealed envelopes) *who inside
   the mesh is talking to whom*, but not *that a radio transmitted*.
4. **Spam/abuse-free open discovery.** Decentralization trades away central moderation.
   Abuse controls are local (blocklists, contact gating, proof-of-work on introductions).
5. **Guaranteed delivery latency.** Store-and-forward over intermittent transports is
   eventually-consistent by design; the UI must communicate delivery state truthfully.

## 5. Residual-risk summary

| Adversary | Residual risk |
|---|---|
| A1 | None by architecture (no scannable intermediary exists). |
| A2 | Coarse traffic patterns on the internet transport until cover-traffic/Tor milestones land. |
| A3 | Determined national censor can degrade internet transport; off-grid transports remain. |
| A4 | Regional mesh partitions until a bridge node appears; sneakernet covers the gap. |
| A5 | Targeted denial by a well-placed relay; mitigated by multipath redundancy. |
| A6 | Broken only if *both* X25519 and ML-KEM-768 fail. |
| A7 | Persistent endpoint compromise is out of scope; transient compromise is healed. |
