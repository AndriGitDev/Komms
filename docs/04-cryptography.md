# 04 — Cryptography Specification

This is the normative specification of KommsKult's cryptographic core (`kult-crypto`).
Design rationale lives in the ADRs; this document says *what* is built.
Threat mapping: [02 — Threat Model](02-threat-model.md).

> **Status**: design-frozen for M1 implementation. Any deviation during implementation
> requires a new ADR.

## 1. Primitives

| Purpose | Primitive | Crate (RustCrypto unless noted) | Rationale |
|---|---|---|---|
| AEAD (messages, storage, sealed envelopes) | **XChaCha20-Poly1305** | `chacha20poly1305` | 192-bit nonce → random nonces are safe (collision prob. negligible); constant-time in pure software — no AES-NI needed on phones and cheap mesh gateways; large security margin. |
| ECDH | **X25519** | `x25519-dalek` | Ubiquitous, misuse-resistant, small keys (32 B — matters on LoRa). |
| Signatures | **Ed25519** | `ed25519-dalek` | Identity keys and prekey signing only — never over message content (deniability). |
| Post-quantum KEM | **ML-KEM-768** (FIPS 203) | `ml-kem` | NIST-standardized; hybrid with X25519 so both must break. |
| KDF | **HKDF-SHA-256** | `hkdf`, `sha2` | The Double Ratchet's specified KDF; interoperable with published test vectors. |
| Hashing / fingerprints | **SHA-256**; **BLAKE3** for bulk/file hashing | `sha2`, `blake3` | SHA-256 where protocol-conservatism matters; BLAKE3 where speed does. |
| Password KDF (at-rest key) | **Argon2id** | `argon2` | Memory-hard; parameters in §8. |
| Secret hygiene | `zeroize` on every secret type | `zeroize` | Keys never outlive their use. |

All random generation uses the OS CSPRNG (`OsRng`) — no userspace PRNG state.

## 2. Key inventory

| Key | Type | Lifetime | Purpose |
|---|---|---|---|
| Identity key `IK` | Ed25519 (+ X25519 via separate keypair, cross-signed) | Long-term | The user's identity; signs prekey bundles. |
| Signed prekey `SPK` | X25519 | Rotated ~weekly | Medium-term DH input; signed by `IK`. |
| PQ signed prekey `PQSPK` | ML-KEM-768 | Rotated ~weekly | KEM input for hybrid handshake; signed by `IK`. |
| One-time prekeys `OPK_i` | X25519 | Single use | Strengthens first-message forward secrecy. |
| Ephemeral key `EK` | X25519 | Single handshake | Sender-side handshake freshness. |
| Ratchet keys | X25519 | Per DH ratchet step | Double Ratchet public ratchet. |
| Chain/message keys | 32-B symmetric | Single message | Derived; zeroized after use. |
| Storage master key `SK` | 32-B symmetric | Long-term (rotatable) | At-rest encryption root, §8. |

We deliberately use **separate** Ed25519 and X25519 identity keypairs (cross-signed at
creation) instead of birational conversion — simpler to audit, no edge-case pitfalls.

## 3. Handshake: hybrid PQXDH

Establishes the initial shared secret between Alice (initiator) and Bob (recipient, who
may be offline), following Signal's PQXDH construction adapted to our encoding.

Bob publishes a **prekey bundle** (via DHT or exchanged directly/QR — see
[06 — Identity & Trust](06-identity-trust.md)):

```
Bundle_B = { IK_B, SPK_B, Sig(IK_B, SPK_B), PQSPK_B, Sig(IK_B, PQSPK_B), OPK_B? , relay hints,
             expiry, Sig(IK_B, canonical-bundle) }
```

The final signature covers a canonical serialization of **every** field — including the
expiry, the OPK (or its absence), and the relay hints — so whoever serves the bundle (a
DHT node, a courier) can withhold it but cannot extend its lifetime, strip its OPK, or
redirect its relay hints ([06 — Identity & Trust §2](06-identity-trust.md)).

Alice verifies all three signatures, then computes:

```
DH1 = DH(IK_A_x25519, SPK_B)
DH2 = DH(EK_A,        IK_B_x25519)
DH3 = DH(EK_A,        SPK_B)
DH4 = DH(EK_A,        OPK_B)          # if an OPK was available
(KEM_ct, KEM_ss) = ML-KEM-768.Encaps(PQSPK_B)

SK_root = HKDF-SHA-256(
    ikm  = 0xFF*32 || DH1 || DH2 || DH3 || DH4 || KEM_ss,
    salt = 0*32,
    info = "KommsKult-PQXDH-v1"
)
```

The first envelope to Bob carries `IK_A`, `EK_A`, the `OPK` id used, and `KEM_ct`, plus an
initial Double-Ratchet message encrypted under `SK_root` with the handshake transcript
hash as associated data (binds the ciphertext to the exact bundle used; a MITM who swaps
any handshake element causes AEAD failure).

Security properties: mutual (deniable) authentication from DH1/DH2; forward secrecy from
EK/OPK; **post-quantum confidentiality** because `SK_root` is not computable without
breaking *both* X25519 and ML-KEM-768.

## 4. Sessions: Double Ratchet

Standard Double Ratchet (Signal specification) with these fixed parameters:

| Parameter | Value |
|---|---|
| Root/chain KDF | HKDF-SHA-256, domain-separated info strings (`"KK-root"`, `"KK-chain"`, `"KK-msg"`) |
| Message AEAD | XChaCha20-Poly1305; nonce = 24 random bytes carried in the envelope |
| Header encryption | **Enabled** (Double Ratchet HE variant) — ratchet public keys and counters are not visible on the wire |
| Max skipped message keys per chain (`MAX_SKIP`) | 1 000 |
| Max stored skipped keys per session | 2 000, LRU-evicted, each with 30-day TTL |
| AEAD associated data | session id ‖ protocol version |

**Delay-tolerance rationale**: off-grid links reorder and delay heavily; generous
`MAX_SKIP` with bounded, TTL'd storage keeps weeks-stale fragments decryptable without
enabling a memory-exhaustion attack. These bounds are normative — implementers must not
raise them without an ADR.

**Deniability**: no content signatures anywhere. Authenticity comes from AEAD under keys
that both parties (and only they) could derive — either could have forged the transcript,
so it proves nothing to third parties.

## 5. Envelope format

Compact binary, little-endian, fixed field order (no self-describing serialization in the
hot path — every byte counts on LoRa). One envelope per message or fragment:

```
byte    0      : version (0x01)
byte    1      : type (0x01 msg | 0x02 handshake | 0x03 receipt | 0x04 fragment)
bytes   2..34  : delivery token (32 B, §7)
bytes  34..N   : body (type-specific, always ciphertext)
```

Bodies by type — `msg`/`receipt`: an encoded ratchet message
(`version ‖ encrypted header(80) ‖ nonce(24) ‖ ciphertext+tag`); `handshake`: an
anonymous-boxed first flight (`ephemeral X25519 pub(32) ‖ nonce(24) ‖ ciphertext+tag`),
so the initiator's identity travels only inside AEAD; `fragment`: an 8-byte fragment
header (message id hash 4 B = truncated BLAKE3 of the whole payload, index 2 B LE,
count 2 B LE) followed by the payload slice — reassembly precedes decryption and
re-verifies the id hash over the assembled bytes. Fragmentation policy and MTU tables:
[05 — Transports §4](05-transports.md).

**Padding**: plaintext is padded (ISO/IEC 7816-4) to size buckets
{192 B, 512 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB} before encryption; larger payloads (media)
are chunked at 64 KiB. The 192 B bucket exists so a short text message plus overhead still
fits typical LoRa payloads after fragmentation into ≤2 frames.

## 6. Group messaging (v1: sender keys)

Per group, each member generates a **sender key**: a chain key + Ed25519-free MAC scheme
(chain key ratchets forward per message; message key = HKDF(chain key)). Sender keys are
distributed to each member over the existing pairwise Double Ratchet sessions. A group
message = one XChaCha20-Poly1305 ciphertext under the sender's current message key,
delivered to all members (single ciphertext — critical for mesh bandwidth).

- Member removal ⇒ all remaining members rotate sender keys.
- Forward secrecy per sender via chain ratcheting; PCS via periodic rotation.
- Group size guidance: ≤ 64 members in v1. Beyond that, MLS (M6+).

## 7. Sealed sender & delivery tokens

Goal: intermediaries learn neither sender nor recipient identity
([02 — Threat Model §5](02-threat-model.md), adversary A5).

- **Delivery token**: `token_i = HMAC-SHA-256(K_mailbox, epoch_i)` truncated to 32 B, where
  `K_mailbox` is a per-contact-pair secret derived from the session root and `epoch_i`
  rotates daily. Only sender and recipient can compute or recognize the sequence; a relay
  sees uncorrelatable 32-byte values. The recipient hands current tokens to its chosen
  relays as "accept mail for these" filters.
- **Sender anonymity**: the envelope contains no sender field at all; sender identity is
  established *inside* the AEAD (encrypted header / handshake data). Transport-level
  anonymity is bounded per the threat model's residual-risk table.

## 8. Encryption at rest

```
passphrase/biometric-unlocked keystore
        │ Argon2id (m=256 MiB, t=3, p=4; mobile profile m=64 MiB)
        ▼
   KEK (32 B)
        │ unwraps (XChaCha20-Poly1305)
        ▼
   SK — storage master key
        │ HKDF-SHA-256, per-domain info strings
        ▼
   per-table keys: messages / sessions / contacts / queue
```

- Database: SQLite; every stored blob individually AEAD-sealed (random 24-B nonce) — no
  reliance on whole-file encryption alone, and blobs stay sealed in backups.
- Ratchet session state is the most sensitive record class; serialized state is
  additionally wrapped and zeroized in memory after each persist.
- Key rotation: re-wrap `SK` under a new KEK (passphrase change is O(1)); full `SK`
  rotation re-encrypts lazily.

## 9. Fingerprints & verification

Safety number = SHA-256 iterated 5 200× over (version ‖ IK_min ‖ IK_max), identity keys
sorted bytewise so both parties compute the identical value. The 60 decimal digits
(12 groups of 5) are taken from HKDF-SHA-256(digest, info = `"KK-fingerprint"`) expanded
to 48 bytes, read as 12 big-endian u32 words each reduced mod 100 000; the raw 32-byte
digest is the QR comparison value. Rationale and UX:
[06 — Identity & Trust](06-identity-trust.md).

## 10. Explicit exclusions

- No custom primitives, ever. Constructions may be composed here; primitives come from
  audited crates pinned by exact version and checksum.
- No compression before encryption (compression-oracle class attacks).
- No protocol-level plaintext timestamps; time lives inside the AEAD.
- `kult-crypto` is `no_std`-compatible (alloc-only) to keep the door open for
  microcontroller-class ports.

## 11. Test obligations (normative for M1)

1. Known-answer tests against published X25519, Ed25519, ML-KEM-768, XChaCha20-Poly1305,
   HKDF, and Argon2id vectors.
2. Double Ratchet interop vectors generated against a reference implementation, committed
   to the repo.
3. Property tests: ratchet under arbitrary message loss/reorder within `MAX_SKIP` always
   decrypts; beyond bounds always fails closed.
4. Fuzzing (cargo-fuzz) on envelope parsing and handshake message parsing.
5. `cargo-deny` + pinned lockfile; no git dependencies in `kult-crypto`.
