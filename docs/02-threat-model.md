# 02: Threat Model

This document defines who Komms defends against, what it protects, and, just as
importantly, what it does *not* claim to protect. Every design decision in
[03: Architecture](03-architecture.md) and [04: Cryptography](04-cryptography.md) traces
back to a row in this document.

## 1. Assets

| Asset | Description |
|---|---|
| **Message content** | Text, media, and files exchanged between users. |
| **Message metadata** | Who talks to whom, when, how often, from where, and message sizes. |
| **Identity keys** | Long-term Ed25519/X25519 key material that *is* a user's identity. |
| **Session state** | Ratchet state whose compromise could expose past or future messages. |
| **Local message history** | Decrypted content visible to an unlocked endpoint and its independently sealed at-rest representation. |
| **Social graph** | Contact lists and group memberships. |
| **Private organization** | Local folder/label definitions, stable IDs, order, memberships, selected views/filters, and stale-reference diagnostics. |
| **Availability** | The ability to communicate at all, including when infrastructure is down or hostile. |

## 2. Adversaries

Listed roughly in ascending order of capability.

### A1: Mass content scanning (the ChatControl model)
An actor with legal or technical leverage over *service providers*, compelling them to scan,
filter, or report message content (client-side or server-side).

**Defense**: no service provider is required to communicate, and no relay or
optional convenience service receives message plaintext or message keys. A
provider can be compelled to log service-use metadata, deny service, or alter
its own software, but it cannot add server-side content scanning to ciphertext
it cannot open. Persistently compromised endpoint software remains A7; optional
service boundaries are pinned by [ADR-0017](adr/0017-optional-hybrid-modes.md).

### A2: Passive network observer
An ISP, IXP tap, or national passive-collection program recording traffic.

**Defense**: all traffic is end-to-end encrypted (content) and transport-encrypted
(links). Padding to size buckets and encrypted ratchet headers reduce what
traffic analysis yields. Full traffic-analysis resistance is **partial**; see §5.

### A3: Active network attacker / censor
An actor who can block, throttle, inject, or MITM traffic: national firewalls, hostile
Wi-Fi, BGP hijackers.

**Defense**: transport authentication (Noise/TLS with pinned peer keys) defeats MITM.
Censorship is countered by transport diversity: if the internet path is blocked, the same
envelopes flow over LAN, BLE, LoRa mesh, or sneakernet
([05: Transports](05-transports.md)). Obfuscated internet transports are on the
roadmap ([08: Roadmap](08-roadmap.md), M6).

### A4: Infrastructure seizure / shutdown
Confiscation of relays, takedown of bootstrap nodes, or a regional internet blackout.

**Defense**: no single point of failure exists in the core. Any node can relay;
discovery is DHT-based with multiple bootstrap paths; the Meshtastic/LoRa
fallback functions with zero internet infrastructure. Loss of any relay loses
nothing but its queued ciphertexts, which are sealed and padded. Loss of every
optional rendezvous or native-wake service removes convenience only and must
fall back to the same direct, DHT, mailbox, LAN, mesh, and sneakernet paths.

### A5: Malicious peer, relay, or optional service
A participant in the network (a relay holding mailboxes, a DHT node, a mesh
repeater, rendezvous provider, or native-wake gateway) that logs, drops,
replays, correlates, or forges traffic.

**Defense**: relays only ever see sealed envelopes (no sender identity, padded
sizes, opaque recipient tokens). Rendezvous stores fixed-size encrypted route
records, and native push carries only a static wake shape. AEAD, ratchet
ordering, rendezvous generation/expiry checks, and bounded wake capabilities
defeat accepted-content forgery and stale-state rollback. Services can still
observe their network metadata and deny work. Redundant core delivery and
encrypted receipts make total dropping degrade into adversary A4.

### A6: Retrospective decryption ("harvest now, decrypt later")
An actor recording ciphertext today, hoping to decrypt it with a future
cryptanalytic advance or quantum computer.

**Defense**: hybrid post-quantum key agreement (X25519 **and** ML-KEM-768; both must fall)
plus forward secrecy from the Double Ratchet. See [04: Cryptography](04-cryptography.md).

### A7: Endpoint compromise (targeted)
Malware, forensic seizure of an unlocked device, or a coerced unlock, against a *specific*
target.

**Defense (bounded)**: at-rest encryption under an Argon2id-derived key protects a
powered-off/locked device. Forward secrecy means a captured device does not reveal
messages deleted before capture; post-compromise security means a *transient* compromise is
healed by the next DH ratchet step. A persistently compromised endpoint sees everything its
user sees; no messenger can prevent that (§5).

## 3. Security goals

| Goal | Meaning | Mechanism |
|---|---|---|
| **Confidentiality** | Only intended recipients read content. | XChaCha20-Poly1305 AEAD under Double Ratchet keys. |
| **Integrity & authenticity** | Messages cannot be altered or forged. | AEAD tags; identity-key-signed handshakes. |
| **Forward secrecy** | Key compromise doesn't expose past messages. | Symmetric + DH ratchets; keys zeroized after use. |
| **Post-compromise security** | Security self-heals after transient compromise. | DH ratchet steps on every round trip. |
| **Post-quantum confidentiality** | A6 resistance for content. | Hybrid PQXDH-style handshake (ML-KEM-768). |
| **Metadata minimization** | Network learns as little as possible about who/when/how much. | Sealed sender, encrypted headers, size-bucket padding, no mandatory identity-indexed rendezvous; optional pairwise capabilities. |
| **Deniability** | Transcripts are not cryptographic proof of authorship to third parties. | No signatures over message content; authentication via shared MAC keys (Signal-style). |
| **No mandatory identifiers** | No phone number, email, or real name, ever. | Keypair-as-identity ([06: Identity & Trust](06-identity-trust.md)). |
| **Availability off-grid** | Communication survives infrastructure loss. | Transport abstraction with LoRa mesh + sneakernet fallbacks. |
| **Sovereignty** | Users hold their own keys and data; anyone can run every component. | Local-first storage, AGPLv3, no privileged nodes. |

Optional Hybrid Infrastructure Layer modes do not change the confidentiality,
authenticity, deniability, identity, or off-grid goals above. They add a bounded
metadata surface documented in
[ADR-0017](adr/0017-optional-hybrid-modes.md): direct Standard-mode requests may
expose a client address, opaque target, timing, and volume; a native wake gateway
must learn the provider token it wakes; APNs/FCM observe app-instance delivery.
Private mode separates client address from target request through Tor or a
non-colluding OHTTP relay, but it does not promise anonymity against collusion
or a global passive observer. Service compromise can suppress convenience work
but cannot decrypt or forge an accepted Komms message.

Private folders and labels are endpoint organization, never communications
metadata. Their definitions, single-folder assignments, and many-to-many label
memberships remain inside the independently sealed `local_metadata` domain;
protected folder/label view preferences remain device-local. An organization
operation creates no envelope, mailbox, mesh, sneakernet,
LAN, internet, DHT, capability, sender-key, ratchet, delivery-token, analytics,
or remote-notification work. A copied SQLite database reveals only the already
accepted row count and approximate sealed blob sizes. `KKR4` is the only folder
or label portability mechanism: neither has server or linked-device
synchronization. Once rendered on an unlocked endpoint, folder and label text
has the same bounded A7 exposure as the rest of the user's visible local data.

Some platform workflows require bounded plaintext transients after unlock—for
example, an OS picker import, recorder review, image edit, playback, or explicit
export. These live only in protected app-private locations, are excluded from
backup, are never the core database source of truth, and are cleaned on the
documented success, discard, failure, lock/background, shutdown, and restart
paths. Their exposure on a persistently compromised unlocked endpoint remains A7.

## 4. Non-goals and accepted limitations

Honesty here is a security feature. Komms does **not** claim to provide:

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
6. **Metadata invisibility from an enabled convenience service.** Pairwise
   capabilities prevent public enumeration, not observation of connections,
   timing, volume, or a native provider destination at the component that must
   process it.
7. **Guaranteed mobile background execution.** APNs/FCM and the operating system
   may throttle, delay, coalesce, or discard a wake; force-quit, permissions,
   battery policy, and provider outage remain honest failure cases.

## 5. Residual-risk summary

| Adversary | Residual risk |
|---|---|
| A1 | No server-side content-scanning point exists; malicious or compelled endpoint software remains A7. |
| A2 | Coarse traffic patterns on internet transport and enabled convenience services until cover-traffic/Tor mitigations apply. |
| A3 | Determined national censor can degrade internet transport; off-grid transports remain. |
| A4 | Regional mesh partitions until a bridge node appears; optional-service outage loses convenience, not core communication. |
| A5 | Targeted denial and service-use correlation by a well-placed component; denial is mitigated by multipath core fallback. |
| A6 | Broken only if *both* X25519 and ML-KEM-768 fail. |
| A7 | Persistent endpoint compromise is out of scope; transient compromise is healed. |
