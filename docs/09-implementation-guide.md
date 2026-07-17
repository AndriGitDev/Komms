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
   [08: Roadmap](08-roadmap.md); the local release matrix = fmt + clippy (deny
   warnings) + tests + no_std + bindings/shell builds + fuzz smoke (60 s per
   target) + cargo-deny. Hosted CI repeats an already-green checkpoint only
   after explicit publication authorization.

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
// C7 derives directional media/header keys from a fresh call master secret,
// call id, both accounts, and exact answering device. Ratchet keys never cross.
pub struct CallMediaSender;  // seal hello/audio; bounded key-phase rotation
pub struct CallMediaReceiver; // authenticate context/direction; reject replay
```

### 3.2 `kult-protocol`

```rust
pub struct Envelope { /* 04 §5 wire format */ }
impl Envelope {
    pub fn encode(&self) -> Bytes;                          // fixed layout, LE
    pub fn decode(b: &[u8]) -> Result<Self, CodecError>;    // fuzz target #1
}
// C4 retained envelopes use v2 with a canonical hour-aligned deletion hint;
// content-v1 kind 5 binds the exact deadline and same hint under endpoint AEAD.
pub fn encode_disappearing_text_payload(expires_at: u64, text: &str) -> Result<Vec<u8>>;
pub fn encode_view_once_attachment_payload(expires_at: u64, manifest: &AttachmentManifest)
    -> Result<Vec<u8>>;
pub fn pad(plaintext: &[u8]) -> Padded;                     // buckets per 04 §5
pub fn fragment(env: &Envelope, mtu: usize) -> Vec<Envelope>;      // type 0x04
pub struct Reassembler { /* 24h window, per-peer caps, NACK generation (05 §4.2) */ }
pub fn delivery_token(k_mailbox: &MailboxKey, epoch: Epoch) -> Token; // 04 §7
// C7 content-v1 CallControl: offer/answer/decline/busy/cancel/hangup, strict and bounded.
pub fn encode_call_control_payload(control: &CallControl) -> Result<Vec<u8>>;
pub fn decode_call_control_payload(bytes: &[u8]) -> DecodedCallControl;
```

### 3.3 `kult-transport`

The trait from [05: Transports §1](05-transports.md), plus:

```rust
pub struct SneakernetTransport;   // .kkb bundles, implement FIRST (M2): no networking,
                                  // exercises the full envelope path end-to-end
pub struct Libp2pTransport;       // M3: QUIC/TCP, Kademlia records, relay-v2 mailboxes
pub struct MeshtasticTransport;   // M4: serial/TCP protobuf client, private PortNum,
                                  // runtime MTU from radio config, duty-cycle accounting
pub struct CallStream;            // C7: /komms/call/1, direct QUIC only; never TCP/relay
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
// local icons: custom_icon / set_custom_icon_from_path / set_bundled_custom_icon
//              / clear_custom_icon / custom_icon_usage
//             → CustomIconsChanged (local only; no delivery-engine work)
// screen security: screen_security_policy(platform)
//             → immutable pre-unlock capability/limitation contract; no store
// input privacy: incognito_keyboard_policy(platform)
//             → immutable pre-unlock field/control/limitation contract; no store
// private petnames: assess_contact_name(peer, proposed)
//              / rename_contact(peer, proposed, accept_warnings)
//             → ContactRenamed (local only; exact peer target; no delivery work)
// ephemeral: send_disappearing_message / send_group_disappearing_message
//          / send[_group]_view_once_attachment / consume_view_once_attachment
//          → expiry-bearing history/events + EphemeralRemoved
// Exact deadline sweep, tombstone-before-output, raw-send refusal, and KKR6
// exclusion live below the shell; ordinary attachment export rejects view once.
// calls: call_availability / calls / start|answer|decline|cancel|hangup_call
//      / send_call_audio / take_call_audio
//      → CallUpdated; transient direct-QUIC state, no history/backup/delayed work
```

`kult-ffi` exposes exactly `Node`'s command/event API via UniFFI, nothing more.
The daemon mirrors B12 as strict `theme` and `theme_set` RPC operations; the CLI
spells them `kult theme` and `kult theme-set system|light|dark`. Shells resolve
System from native platform signals rather than introducing a core display mode.
The daemon mirrors B13 with strict `custom_icon`, `custom_icon_set_path`,
`custom_icon_set_bundled`, `custom_icon_clear`, and `custom_icon_usage` operations.
The CLI spells these `icon`, `icon-set-image`, `icon-set-glyph`, `icon-clear`, and
`icon-usage` with exact `contact:HEX`, `group:HEX`, `folder:HEX`, or
`note-to-self` targets. Binary PNG bytes use the RPC's existing lowercase-hex
rule; shells receive bounded bytes through UniFFI and never infer targets from
display names.

B14 is an immutable free policy function rather than a `Node` mutation because
screen protection must apply before the store opens. UniFFI exports
`screen_security_policy(platform)` directly. Strict RPC names the operation
`screen_security_policy`; the CLI spells it
`kult screen-security android|ios|desktop`. Capability levels are
`platform_enforced`, `best_effort`, and `unavailable`. Shells must enforce native
behavior and render the returned mechanism and limitations; they must not add a
disable toggle, persist the policy, or upgrade best-effort/unsupported claims.
The native implementation and qualification contract is
[13: Screen Security](13-screen-security.md).

B15 follows the same free-function shape because input protection must cover
passphrase and restore fields before a store exists. UniFFI exports
`incognito_keyboard_policy(platform)`; strict RPC uses
`incognito_keyboard_policy`, and the CLI spells it
`kult incognito-keyboard android|ios|desktop`. Capability levels add
`platform_requested` to distinguish a documented but non-binding native request
from generic `best_effort`. Shells must render the limitations, keep the policy
always on, mask passphrases and mnemonics, and maintain an automated inventory
of every textual field. New search or naming inputs are incomplete until they
join that inventory. The native contract is
[14: Incognito Keyboard](14-incognito-keyboard.md).

B5 contact rename is a local contact-record mutation, not a protocol identity
operation. The daemon mirrors it as strict `contact_name_assessment` and
`rename_contact` RPC operations; the CLI spells them `kult contact-name-check`
and `kult contact-rename [--accept-warnings]`. Every front door must call the
shared assessment, display all returned warning codes, and pass explicit
acceptance before a warned mutation. Shells must target an exact peer key and
must never resolve, mention, or retarget by petname. New name inputs also remain
inside the B15 incognito-field inventories. The complete contract and manual
qualification matrix are in
[15: Private Contact Names](15-contact-petnames.md).

B9 safe formatting is a pure local read model. Rust uses
`kult_node::format_text(source, highlights)`; strict RPC uses `format_text`, the
CLI uses `kult format-text`, and UniFFI exposes the same bounded records. Never
add formatting bytes to stored content, negotiate it as a capability, or let a
shell parse HTML/URLs independently. Shell renderers may map only the returned
block and style enums to native inert text APIs, must preserve the returned
plain-text projection for copy, and must include pairwise, group, note-to-self,
and scheduled paths. The full contract is
[16: Safe Text Formatting](16-safe-text-formatting.md).

C1 file presentation is another pure local decision over authenticated but
untrusted display hints. Rust uses `classify_attachment_file(media_type,
filename)`; strict RPC uses `attachment_file_presentation`, the CLI uses
`kult file-presentation`, and UniFFI exposes the same typed record. Shells must
consume the returned policy, bidi-isolate filenames, never auto-open, never
claim scanning, and recheck completed inbound state before protected temporary
materialization. Do not add sniffing, preview, scanner, or transport behavior to
this API. The complete contract is
[17: Safe File Presentation](17-safe-file-presentation.md).

C3 editing is a replicated immutable content feature. Encode only canonical
content-v1 kind `0x0004`; never expose a generic raw-content route that can
smuggle an Edit around `kult-node` authorization. Pairwise and group send APIs
must accept exact target-author and target-content-id bytes, require authenticated
Edit capability (and complete current-roster support for groups), and reject
non-Text targets. History consumers use the node resolver, not raw rows; the
resolver hides edit events, retains ordered versions, and selects maximum
`(revision, edit_id)` independent of arrival time. RPC operations are
`edit_message` and `group_edit_message`; CLI commands are `edit` and
`group-edit`; UniFFI mirrors them and the typed refresh events. The complete
wire, storage, shell, and qualification contract is
[18: Authenticated Message Editing](18-message-editing.md).

C4 is a replicated lifecycle feature, not a timer implemented by each shell.
Only the dedicated pair/group disappearing and view-once APIs may create
content-v1 kind `0x0005`; generic send and scheduling reject encoded ephemeral
content, and an anonymous first flight is forbidden. RPC operations are
`send_disappearing`, `group_send_disappearing`,
`attachment_send_view_once`, `group_attachment_send_view_once`, and
`attachment_consume_view_once`; the matching CLI commands use hyphens. UniFFI
exposes the same typed methods, expiry fields, attachment flags, and terminal
event. Sweep before all tick work, bind envelope-v2's coarse bucket to the exact
authenticated deadline, commit a tombstone before reveal output, refuse normal
export/preview, and keep active ephemeral content out of KKR6. The complete
contract is [19: Disappearing Messages and View-Once Attachments](19-ephemeral-messages.md).

C5 polls are replicated immutable group content, never a shell-owned counter.
Only the dedicated create/vote/close APIs may emit content-v1 kind `0x0006`;
generic pairwise and group send reject it. Resolve each open voter head by
maximum `(revision, event id)`, then replace the open view with the winning
creator-attested close snapshot. The electorate is the fixed sorted creation
list and votes are visible, not anonymous. RPC uses `group_poll_create`,
`group_polls`, `group_poll_vote`, and `group_poll_close`; the CLI uses matching
hyphenated commands; UniFFI exposes `GroupPoll` and `PollUpdated`. Shells render
the node snapshot and never resolve raw events. The complete contract is
[20: Group Polls](20-group-polls.md) and
[ADR-0022](adr/0022-convergent-group-polls.md).

C6 authority is a signed control plane over the existing sender-key group, not
mutable role flags in a shell. Use only content-v1 kind `0x0007` for canonical
full public state and only the bounded pairwise `GroupControl` variants for
announces, requests, results, and removals. Verify identity signatures, exact
member identities, transfer-chain continuity, current-owner ancestry, secret
hash, generation, request id, and role table before mutation. Same-generation
states choose the smallest authenticated event id; a greater generation must
extend the accepted transfer prefix. The owner commits one transition, rotates
secret and chains, stores the winning sealed authority record, and emits typed
refresh events. RPC/CLI and UniFFI expose only exact ids and render-safe roles;
shells must not parse payloads or infer authority from display names. Moderated
poll closure has its own owner-signature domain and renders a moderator identity.
The complete contract is
[21: Group Roles, Ownership, and Moderation](21-group-roles.md) and
[ADR-0023](adr/0023-group-roles-and-owner-authority.md).

C7 calls are a transient authenticated media path, not another durable message
type. Only `kult-node` may emit/consume content-v1 `CallControl`, select the
first valid linked-device answer, derive the exact media context, and open a
stream after the shared F4 verdict confirms direct QUIC. RPC/CLI and UniFFI
mirror typed call snapshots, availability reasons, lifecycle actions, and
bounded Opus packet ingress/egress; shells never receive a call master secret or
ratchet key. Every terminal or background/lock path must erase secrets and
buffers. The complete contract is [23: Live Audio Calls](23-live-audio-calls.md).

## 4. Testing strategy (beyond per-milestone acceptance)

- **KATs**: primitive test vectors vendored under `crates/kult-crypto/tests/vectors/`.
- **Property tests** (`proptest`): ratchet loss/reorder/dup within bounds ⇒ decrypts;
  outside bounds ⇒ typed failure. Padding round-trips. Fragment/reassemble = identity.
- **Fuzz targets** (`cargo-fuzz`): crypto envelope, handshake, bundle, mnemonic,
  and attachment-chunk decoding; protocol envelope, bundle import, reassembly,
  content, capability, attachment manifest/bulk/ranges, mention, edit, ephemeral,
  and poll
  decoding.
- **Simulation harness** (M3+): in-process multi-node network with scripted link
  conditions (latency, loss, partitions, MTU), deterministic seed, replayable failures.
  This harness is how store-and-forward, NACK, and bridging logic get tested without
  radios on the desk.
- **Hardware-in-loop** (M4): two USB Meshtastic radios in CI-adjacent nightly job;
  bench runbook in [10: HIL Bench](10-hil-bench.md).

## 5. Review gates

Every publication candidate has a green local release matrix and an explicit
deferred-gate list. Every PR also needs one review; a hosted repetition runs
only when explicitly authorized. Additionally:

| Touched | Extra gate |
|---|---|
| `kult-crypto` | Second reviewer; diff against spec section cited in PR description |
| Wire formats (envelope, bundle, tokens) | Version-bump check + fuzz corpus updated |
| Dependencies | `cargo-deny` diff reviewed; new crypto deps need an ADR |
| Storage schema | Migration + "copied-file leakage" checklist from 07 §2 |
| Sealed local metadata | Limit, stale-reference, transaction/failure, KKR compatibility, and zero-network-work matrices |
| Contact petname mutation | Exact peer targeting, normalization, warning review, duplicate-name disambiguation, restart/KKR compatibility, and zero-network-work evidence |
| Safe text formatting | Shared malicious/bidi/limits corpus, exact source compatibility, inert renderer inventory, mention composition, plain-text copy, and zero-network-work evidence |
| Desktop/mobile shell | Relevant accessibility, lifecycle, protected-transient cleanup, and real build evidence |

## 6. Definition of done (any milestone)

Acceptance criteria in [08: Roadmap](08-roadmap.md) demonstrably met, the local
release matrix green, docs updated where behavior is user-visible, no `TODO`
without a tracking issue, and the demo described in the milestone runs from a
fresh clone with documented commands. The exact local/publication workflow is
[24: Local Release Gate](24-local-release-gate.md).
