# 09: Implementation Guide

The implementation handoff and maintenance contract. M1–M5 now have substantial
shipped implementations, so this guide applies both to new features and to changes
that must preserve existing boundaries. The design documents say *what*; this says
*how to build it without drifting*. When this guide and a design doc conflict, the
design doc wins and the conflict is a bug—file it.

## 1. Ground rules

1. **No design changes in implementation PRs.** A change to anything specified in docs
   02–07 requires an ADR first (template: `docs/adr/template.md`).
2. **Crate boundaries are law.** The "must never" column in
   [03: Architecture §2](03-architecture.md) is enforced by review and by dependency
   direction, e.g. `kult-crypto`'s `Cargo.toml` has no I/O crates, period.
3. **Crypto code standards** (in `kult-crypto`, `kult-protocol`):
   - `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`.
   - Every secret in a `zeroize::Zeroizing`/`ZeroizeOnDrop` type; no `Debug`/`Display`
     on secret types; no secret ever in a log or error message.
   - Constant-time comparison (`subtle`) for every tag/token/key equality.
   - No panics on untrusted input: parsers return `Result`, fuzzers prove it.
   - Dependencies pinned via lockfile; `cargo-deny` gate (licenses, advisories, dupes);
     no git dependencies.
4. **Errors are honest**: failure states surface to the delivery engine and UI truthfully
   (`queued/sent/delivered/failed`), never faked.
5. **Every milestone lands with its tests** as defined in the acceptance criteria of
   [08: Roadmap](08-roadmap.md); CI = fmt + clippy (deny warnings) + tests + fuzz smoke
   (60 s per target) + cargo-deny.

## 2. Build order

The original dependency order remains the rule for new lower-layer capability:
`kult-crypto` → `kult-protocol` + `kult-store` (parallel-safe) → `kult-node`
→ transports → `kult-ffi`/RPC → apps. Existing features may touch several layers
in one reviewable slice, but behavior still flows through those contracts;
shells never become an alternate core. Each lower layer compiles and tests without
depending on the layers above it.

## 3. Architectural API sketches

These sketches preserve dependency direction and ownership. The checked-in Rust
APIs are authoritative for exact signatures; do not copy an old sketch over a
newer bounded or typed interface.

### 3.1 `kult-crypto`

```rust
pub struct Identity { /* IK_ed25519 + IK_x25519, cross-signed */ }
impl Identity {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self;
    pub fn public(&self) -> IdentityPublic;                 // → kult address
    pub fn sign_prekeys(&self, spk: &X25519Public, pqspk: &MlKemPublic) -> PrekeySignatures;
}

pub struct PrekeyBundle { /* per 04 §3, self-authenticating */ }
impl PrekeyBundle { pub fn verify(&self) -> Result<VerifiedBundle, BundleError>; }

// Handshake (04 §3)
pub fn initiate(me: &Identity, bundle: &VerifiedBundle, rng: ...)
    -> (Session, InitialMessage);
pub fn respond(me: &Identity, prekeys: &PrekeyStore, msg: &InitialMessage)
    -> Result<Session, HandshakeError>;

// Double Ratchet (04 §4), opaque, serializable-encrypted, zeroizing
impl Session {
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> RatchetMessage;
    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8])
        -> Result<Vec<u8>, RatchetError>;   // enforces MAX_SKIP=1000, store cap 2000/TTL 30d
    pub fn seal_state(&self, sk: &StorageKey) -> SealedState;
    pub fn unseal_state(sealed: &SealedState, sk: &StorageKey) -> Result<Self, _>;
}

pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> SafetyNumber; // 04 §9
```

### 3.2 `kult-protocol`

```rust
pub struct Envelope { /* 04 §5 wire format */ }
impl Envelope {
    pub fn encode(&self) -> Bytes;                          // fixed layout, LE
    pub fn decode(b: &[u8]) -> Result<Self, CodecError>;    // fuzz target #1
}
pub fn pad(plaintext: &[u8]) -> Padded;                     // buckets per 04 §5
pub fn fragment(env: &Envelope, mtu: usize) -> Vec<Envelope>;      // type 0x04
pub struct Reassembler { /* 24h window, per-peer caps, NACK generation (05 §4.2) */ }
pub fn delivery_token(k_mailbox: &MailboxKey, epoch: Epoch) -> Token; // 04 §7
```

### 3.3 `kult-transport`

The trait from [05: Transports §1](05-transports.md), plus:

```rust
pub struct SneakernetTransport;   // .kkb bundles, implement FIRST (M2): no networking,
                                  // exercises the full envelope path end-to-end
pub struct Libp2pTransport;       // M3: QUIC/TCP, Kademlia records, relay-v2 mailboxes
pub struct MeshtasticTransport;   // M4: serial/TCP protobuf client, private PortNum,
                                  // runtime MTU from radio config, duty-cycle accounting
```

For Meshtastic: use the published protobuf definitions via a generated client; do not
hand-roll the serial framing. Airtime budget module is its own reviewed unit.

### 3.4 `kult-store`

```rust
pub struct Store { /* SQLite; every blob AEAD-sealed per 07 §2 */ }
// open(path, kek) → unwraps SK; domain key per table via HKDF
// messages / sessions / contacts / queue / media / schedules / local metadata;
// no network I/O or transport scheduling
```

### 3.5 `kult-node`

```rust
pub struct Node { /* composes store + transports + sessions */ }
// event-driven: Command (send, add_contact, accept_request, export_bundle…)
//             → Event (message, receipt, key_changed, transport_status…)
// delivery engine: per-message state machine queued→sent→delivered, multipath,
// dedup by message id, retry with per-transport backoff
// local appearance: theme_preference / set_theme_preference
//             → ThemeChanged (local only; no delivery-engine work)
```

`kult-ffi` exposes exactly `Node`'s command/event API via UniFFI, nothing more.
The daemon mirrors B12 as strict `theme` and `theme_set` RPC operations; the CLI
spells them `kult theme` and `kult theme-set system|light|dark`. Shells resolve
System from native platform signals rather than introducing a core display mode.

## 4. Testing strategy (beyond per-milestone acceptance)

- **KATs**: primitive test vectors vendored under `crates/kult-crypto/tests/vectors/`.
- **Property tests** (`proptest`): ratchet loss/reorder/dup within bounds ⇒ decrypts;
  outside bounds ⇒ typed failure. Padding round-trips. Fragment/reassemble = identity.
- **Fuzz targets** (`cargo-fuzz`): crypto envelope, handshake, bundle, mnemonic,
  and attachment-chunk decoding; protocol envelope, bundle import, reassembly,
  content, capability, attachment manifest/bulk/ranges, and mention decoding.
- **Simulation harness** (M3+): in-process multi-node network with scripted link
  conditions (latency, loss, partitions, MTU), deterministic seed, replayable failures.
  This harness is how store-and-forward, NACK, and bridging logic get tested without
  radios on the desk.
- **Hardware-in-loop** (M4): two USB Meshtastic radios in CI-adjacent nightly job;
  bench runbook in [10: HIL Bench](10-hil-bench.md).

## 5. Review gates

Every PR: CI green + one review. Additionally:

| Touched | Extra gate |
|---|---|
| `kult-crypto` | Second reviewer; diff against spec section cited in PR description |
| Wire formats (envelope, bundle, tokens) | Version-bump check + fuzz corpus updated |
| Dependencies | `cargo-deny` diff reviewed; new crypto deps need an ADR |
| Storage schema | Migration + "copied-file leakage" checklist from 07 §2 |
| Sealed local metadata | Limit, stale-reference, transaction/failure, KKR compatibility, and zero-network-work matrices |
| Desktop/mobile shell | Relevant accessibility, lifecycle, protected-transient cleanup, and real build evidence |

## 6. Definition of done (any milestone)

Acceptance criteria in [08: Roadmap](08-roadmap.md) demonstrably met, CI green, docs
updated where behavior is user-visible, no `TODO` without a tracking issue, and the demo
described in the milestone runs from a fresh clone with documented commands.
