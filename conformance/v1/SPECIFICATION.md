# Komms stable-v1 protocol specification

**Profile:** `komms-stable-v1`
**Specification version:** 1.0.0
**Conformance-kit version:** 1.0.0

## 1. Status and interpretation

This document is the stand-alone normative wire and state specification for
the `komms-stable-v1` candidate profile. It is written for implementers who do
not use the Komms source tree. Rationale, product behavior, deployment advice,
and operator guidance are deliberately outside the normative core.

“Stable-v1” names a compatibility target. It does not claim that a product
release is stable, independently reviewed, independently interoperable, or
qualified on physical devices.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be
interpreted as described by BCP 14 when, and only when, they appear in all
capitals.

The normative material is, in descending order:

1. this specification;
2. the exact cases and binary fixtures in this kit;
3. the adapter contract.

If two normative artifacts disagree, an implementation MUST fail the affected
case and the profile MUST be corrected through an explicit compatibility
change. An implementation MUST NOT silently select whichever interpretation is
most permissive.

Unless a field says otherwise:

- an octet is eight bits;
- byte strings are shown as `a || b`;
- byte ranges are half-open;
- integers are unsigned;
- `u16_le`, `u32_le`, and `u64_le` are fixed-width little-endian;
- `u16_be`, `u32_be`, and `u64_be` are fixed-width big-endian;
- lengths count octets, not characters;
- UTF-8 is accepted byte-exactly and is not normalized;
- arrays and lists are in transmission order;
- reserved bits and octets MUST be zero;
- exact-width all-zero identifiers are invalid unless explicitly allowed;
- a decoder MUST reject trailing input for a complete value; and
- length, count, and work bounds MUST be checked before allocation or
  expensive cryptography.

## 2. Cryptographic conventions

### 2.1 Algorithms

The profile uses:

| Purpose | Algorithm |
|---|---|
| authenticated encryption | XChaCha20-Poly1305 |
| classical Diffie-Hellman | X25519 |
| signatures | Ed25519 |
| post-quantum KEM | ML-KEM-768 |
| key derivation | HKDF-SHA-256 |
| keyed authentication | HMAC-SHA-256 |
| conservative digest | SHA-256 |
| bulk/content digest | BLAKE3 |
| password derivation | Argon2id v1.3 |

Production randomness MUST come from a cryptographically secure operating
system source. The deterministic stream in the adapter contract exists only
for public fixtures and MUST NOT be used in a product.

### 2.2 Domain-separated signatures

`Sign_D(sk, D, M)` is Ed25519 signing of `D || M`. `Verify_D` verifies the same
byte string. Domain strings in this specification are exact UTF-8 without a
terminating NUL.

An account or device public identity is:

```text
IdentityPublic =
    ed25519_public[32] ||
    x25519_public[32] ||
    cross_signature[64]
```

The cross signature is:

```text
cross_signature =
    Ed25519.Sign(ed25519_secret,
        UTF8("Komms-cross-sign-v1") || x25519_public)
```

Every consumer MUST verify the cross signature before accepting the X25519
key. The stable account id is the 32-byte Ed25519 public key. A physical device
has a separate independently generated `IdentityPublic`.

The stable address digest is
`SHA-256(ed25519_public || x25519_public)`. The symmetric safety number for
accounts `A` and `B` sorts their Ed25519 public keys as `lo, hi`, then computes:

```text
d0 = SHA-256(01 || lo[32] || hi[32])
d(i) = SHA-256(d(i-1)) for i=1..5199
qr_comparison = d5199
display_bytes = HKDF-SHA-256-Expand(
    HKDF-SHA-256-Extract(absent_salt, d5199),
    "KK-fingerprint", 48)
```

The human form reads the first 24 display bytes as six big-endian `u32`
values, reduces each modulo 100,000, and renders six zero-padded five-digit
groups. QR comparison uses the complete 32-byte `qr_comparison`; the decimal
rendering is not substituted for it.

### 2.3 HKDF and AEAD

`HKDF32(salt, ikm, info)` is HKDF-SHA-256 with a 32-byte output. An absent salt
means the RFC 5869 all-zero hash-length salt. HKDF output MUST NOT exceed 8,160
bytes.

`Seal(key, aad, plaintext)` is:

```text
random_nonce[24] ||
XChaCha20-Poly1305.Encrypt(key, random_nonce, aad, plaintext)
```

The AEAD output contains ciphertext followed by its 16-byte tag, so a seal is
40 octets longer than its plaintext. Authentication failure, truncation, and a
wrong key MUST have the same externally observable protocol result.

### 2.4 CP1 structured encoding

Several bounded control structures use the Canonical Postcard Profile,
abbreviated `CP1`. CP1 is the following language-neutral subset of Postcard
1.1:

- a fixed `[u8; N]` is exactly `N` octets with no prefix;
- `u8` is one octet;
- `u16`, `u32`, `u64`, and `usize` use shortest-form unsigned LEB128;
- `bool` is `00` for false and `01` for true;
- a byte string is `uleb128(length) || bytes`;
- UTF-8 text is `uleb128(length) || bytes`;
- a sequence is `uleb128(count) || element...`;
- a struct is the concatenation of fields in the stated order;
- `Option<T>` is `00` for absent or `01 || T` for present;
- an enum is `uleb128(zero_based_variant_index) || variant_fields`;
- no map, float, signed integer, indefinite value, or ignored trailing field is
  used by this profile.

All integer and count encodings MUST be shortest form. Decoders MUST reject
overflow, invalid Boolean or option tags, non-existent enum variants, invalid
UTF-8, trailing bytes, and profile-specific over-limit values.

`IdentityPublic` under CP1 is the `ed[32]` field, then `x[32]`, then a
length-prefixed 64-byte `cross_signature`.

### 2.5 Constant-time comparison and secret lifetime

Authentication tags, MACs, and secret commitments MUST be compared in constant
time. A receiving implementation MUST authenticate a candidate transition or
message before committing any counter, chain, replay window, lease, queue, or
history mutation. Message keys, one-time prekeys, opened account roots, and
temporary plaintext key material MUST be erased as soon as their required
operation completes.

## 3. Public prekeys and hybrid session establishment

### 3.1 Prekey bundle

ML-KEM-768 public keys, ciphertexts, and secret keys have lengths 1,184, 1,088,
and 2,400 octets respectively.

`PrekeyBundle` is CP1 with fields in this order:

```text
identity: IdentityPublic
spk_id: u32
spk: [u8; 32]
spk_sig: bytes[64]
pqspk_id: u32
pqspk: bytes[1184]
pqspk_sig: bytes[64]
opk: Option<(u32, [u8; 32])>
expires_at: u64
relay_hints: sequence<bytes>
bundle_sig: bytes[64]
```

The complete encoding is limited to 32 KiB. There may be at most 20 relay-hint
entries, each at most 4 KiB and at most 16 KiB in aggregate.

Signatures are:

```text
spk_sig = Sign_D(identity,
    "Komms-spk-v1",
    u32_le(spk_id) || spk)

pqspk_sig = Sign_D(identity,
    "Komms-pqspk-v1",
    u32_le(pqspk_id) || pqspk)
```

The bundle signature message is:

```text
identity.ed || identity.x ||
u32_le(spk_id) || spk ||
u32_le(pqspk_id) || pqspk ||
(00 | 01 || u32_le(opk_id) || opk_public) ||
u64_le(expires_at) ||
u32_le(non_admission_hint_count) ||
for each non-admission hint:
    u32_le(hint_length) || hint
```

and is signed with domain `Komms-bundle-v1`. The optional bearer invitation
extension beginning `KAI1` is excluded from that message so the public bundle
remains verifiable after the bearer secret is removed. The signed admission
descriptor beginning `KAD1` and every ordinary relay hint are included. The
separate admission bundle digest excludes both admission extensions and the
bundle signature to avoid circularity. The enclosing bundle is re-signed after
the descriptor and optional invitation are attached.

A bundle MUST be rejected if expired, if any signature or cross signature is
invalid, or if any structural bound is exceeded. A one-time prekey MUST be
consumed in the same durable endpoint transaction that accepts its initial
session.

### 3.2 PQXDH

Alice initiates to a verified Bob bundle:

```text
DH1 = X25519(IK_A.x_secret, SPK_B)
DH2 = X25519(EK_A_secret, IK_B.x_public)
DH3 = X25519(EK_A_secret, SPK_B)
DH4 = X25519(EK_A_secret, OPK_B)       # omitted when no OPK
(KEM_ct, KEM_ss) = ML-KEM-768.Encaps(PQSPK_B)

IKM = ff*32 || DH1 || DH2 || DH3 || [DH4] || KEM_ss
SK_root = HKDF32(00*32, IKM, "Komms-PQXDH-v1")
HKA     = HKDF32(absent, SK_root, "KK-hka")
NHKB    = HKDF32(absent, SK_root, "KK-nhkb")
K_mailbox = HKDF32(absent, SK_root, "KK-mailbox")
```

The transcript and stable session id are:

```text
session_id = SHA-256(
    "Komms-PQXDH-v1" ||
    IK_A.ed || IK_A.x ||
    IK_B.ed || IK_B.x ||
    SPK_B ||
    PQSPK_B ||
    EK_A ||
    KEM_ct ||
    (01 || OPK_B | 00)
)
```

The optional-service exporter is:

```text
hybrid_service_exporter =
    HKDF32(session_id, SK_root,
           "Komms-Hybrid-Service-Exporter-v1")
```

It exists only after both sides verify the complete PQXDH transcript. It MUST
be stored as separately sealed, non-backup service state. A legacy or one-sided
session has no exporter and MUST perform an authenticated re-handshake; an
implementation MUST NOT synthesize an exporter from ratchet, mailbox, or other
local state.

`InitialMessage` is CP1:

```text
initiator: IdentityPublic
ek: [u8; 32]
spk_id: u32
pqspk_id: u32
opk_id: Option<u32>
kem_ct: bytes[1088]
first: bytes
```

The responder MUST verify the initiator identity, all referenced key ids,
the exact optional-prekey presence, and the KEM ciphertext length before
accepting the first ratchet message.

### 3.3 Double Ratchet with encrypted headers

The root KDF is:

```text
RK' || CK || NHK =
    HKDF-SHA-256(salt=RK, ikm=DH_output,
                info="KK-root", output_length=96)
```

The symmetric chain KDF is:

```text
CK' = HKDF32(absent, CK, "KK-chain")
MK  = HKDF32(absent, CK, "KK-msg")
```

A plaintext header is:

```text
ratchet_public[32] || u32_le(previous_chain_length) ||
u32_le(message_number)
```

The 40-byte header is sealed with a 24-byte nonce and 16-byte tag, producing
an 80-byte encrypted header. Ratchet message wire format is:

```text
01 || encrypted_header[80] || payload_nonce[24] ||
payload_ciphertext || payload_tag[16]
```

Associated data is:

```text
base_ad    = session_id[32] || 01
header_ad  = base_ad || "KK-hdr"
payload_ad = base_ad || encrypted_header || caller_authenticated_data
```

At most 1,000 missing message keys may be advanced for one received message.
At most 2,000 skipped keys are retained per session, LRU-evicted, with a
30-day TTL. A message outside those bounds fails closed. Replay, malformed
header, wrong header key, wrong associated data, and payload failure MUST NOT
advance state. A successful receive and its durable side effects MUST commit
atomically.

## 4. Envelope, content, and delivery

### 4.1 Sealed envelope

Envelope v1 is:

```text
version=01 ||
kind[1] ||
delivery_token[32] ||
body
```

Envelope v2 is:

```text
version=02 ||
kind[1] ||
delivery_token[32] ||
u64_le(retention_until) ||
body
```

Kinds are:

| Value | Meaning |
|---:|---|
| `01` | pairwise ratchet message |
| `02` | anonymous-boxed handshake |
| `03` | encrypted end-to-end receipt |
| `04` | fragment |
| `05` | pairwise-encrypted group control |
| `06` | sender-key group message |

The maximum encoded envelope is 128 KiB. A v2 retention value MUST be non-zero
and an exact multiple of 3,600 seconds. An endpoint accepts it only if the
authenticated ephemeral content carries the same hour ceiling.

The ordinary dedup id is the first 16 bytes of BLAKE3 over the complete
encoded envelope. A `KFA1` handshake uses the independently verified admission
content id from section 8.

An encrypted receipt's ratchet plaintext is CP1:

```text
acks: sequence<[u8;16]>
nacks: sequence<(message_digest_prefix[4], sequence<u16>)>
```

An acknowledgement names the complete encoded envelope's dedup id. A NACK
names only missing fragment indices for one bounded partial. A receipt is
delivery evidence only after its pairwise ratchet authentication; it never
means read. The complete padded receipt must fit the ordinary 128-KiB envelope
limit.

### 4.2 Delivery tokens

For daily epoch `e` and recipient Ed25519 identity:

```text
delivery_token =
    HMAC-SHA-256(K_mailbox,
        "KK-token-v1" || u64_le(e) || recipient_ed25519[32])
```

The complete 32-byte HMAC is used. Recipient binding makes the two directions
of a relationship distinct.

### 4.3 Content framing

Authenticated unpadded content beginning with `ff 4b 4d 43` is typed. The v1
header is exactly:

```text
ff 4b 4d 43 ||
format_version=01 ||
u16_le(kind) ||
flags=00 ||
content_id[16] ||
u32_le(payload_length) ||
payload
```

The header is 28 octets; the complete frame is at most 65,535 octets. The
declared payload length MUST equal the remaining input. A future format version
or non-zero flags is retained as unsupported, not interpreted. An unknown v1
kind is retained as unsupported. A malformed typed frame MUST NOT fall back to
text. Authenticated bytes without the magic are legacy text only when they are
valid UTF-8; otherwise they are unsupported opaque content.

Kinds are:

| Kind | Payload |
|---:|---|
| 1 | exact UTF-8 text |
| 2 | attachment manifest |
| 3 | group mention |
| 4 | immutable edit event |
| 5 | ephemeral text or view-once attachment |
| 6 | group poll event |
| 7 | signed group authority state |
| 8 | transient pairwise call control |

#### Attachment manifest

The maximum manifest payload is 1,024 octets:

```text
version=01 || flags=00 || attachment_key[32] || object_count[1] ||
object...
```

`object_count` is one or two. Each object is:

```text
role[1] || object_id[16] || u64_le(total_length) ||
u32_le(chunk_data_length) || u32_le(chunk_count) ||
BLAKE3_digest[32] || media_type_length[1] || media_type ||
u16_le(filename_length) || filename
```

Role 0 is the required primary; role 1 is an optional preview with a distinct
id and no filename. Chunk data length is exactly 49,152. Chunk count is the
ceiling of `total_length / 49,152`, or zero for an empty object. Primary size is
at most 512 MiB and 10,923 chunks. Preview size is at most 256 KiB and six
chunks, and its media type is `image/jpeg` or `image/png`. Media type is
lowercase ASCII, 1–127 octets. It contains exactly one non-terminal `/`; every
other octet is `a-z`, `0-9`, `!`, `#`, `$`, `&`, `^`, `_`, `.`, `+`, or `-`.
Filename is optional UTF-8, 1–255 octets when present, is neither `.` nor
`..`, contains neither `/` nor `\`, and contains no Unicode scalar in
U+0000–U+001F or U+007F–U+009F.

#### Mention

```text
version=01 || flags=00 || target_count[1] || span_count[1] ||
u32_le(text_length) || sorted_unique_targets[target_count][32] ||
UTF8_text || spans[span_count]
```

Each span is `u32_le(start) || u32_le(end) || target_index[1]`. There are 1–64
targets and 1–64 sorted, non-overlapping spans. Text is 1–16,384 octets.
Offsets are UTF-8 byte boundaries and every target-table entry MUST be used.

#### Edit

```text
target_author_ed25519[32] || target_content_id[16] ||
u64_le(revision) || u32_le(text_length) || UTF8_text
```

Revision is positive; replacement text is 1–16,384 octets. An application
accepts an edit only from the authenticated original author and converges by
the maximum `(revision, edit_event_content_id)`.

#### Ephemeral

```text
version=01 || mode[1] || reserved[2]=0 ||
u64_le(expires_at) || u64_le(retention_until) ||
u32_le(body_length) || body
```

Mode 1 body is non-empty UTF-8. Mode 2 body is a canonical attachment
manifest. `retention_until` is the least multiple of 3,600 greater than or
equal to `expires_at`. Accepted lifetimes are 60 seconds through 30 days.
Expiry and view-once consumption leave a durable bounded tombstone; a replay
MUST NOT restore plaintext.

#### Poll

Every poll payload begins `version=01 || operation || policy || reserved=00`.
Operations are create=1, vote=2, close=3, moderated-close=4.

A create is:

```text
01 01 01 00 || u64_le(group_generation) ||
u16_le(question_length) || option_count[1] || voter_count[1] ||
UTF8_question ||
for each option: option_id[16] || u16_le(text_length) || UTF8_text ||
sorted_unique_voters[voter_count][32]
```

Generation is positive; question is 1–1,024 octets; there are 2–12 distinct
options with 1–256 octets each and 1–64 voters.

A vote is:

```text
01 02 00 00 || poll_author[32] || poll_id[16] ||
option_id[16] || u64_le(positive_revision)
```

A manual close is `01 03 00 00 || poll_author[32] || poll_id[16] ||
head_count[1] || 00*3 || heads`. A moderated close is `01 04 00 00 ||
group_id[32] || poll_author[32] || poll_id[16] ||
u64_le(authority_generation) || head_count[1] || 00*3 || heads ||
owner_signature[64]`. Each sorted unique head is:

```text
voter[32] || vote_event_id[16] || option_id[16] ||
u64_le(positive_revision)
```

There are at most 64 heads. Moderation signatures use domain
`Komms-group-poll-moderation-v1`.

#### Group authority and call controls

Group authority v2 binds every account-level signature to an active physical
device and a complete `KDA2` proof. State is generation-counted, contains at
most 64 sorted members, exactly one owner, a bounded ordered owner-transfer
chain, and the group-secret digest. The canonical state signing bytes are:

```text
02 || 01 || 00 00 ||
group[32] ||
u64_le(generation) ||
u64_le(owner_epoch) ||
original_owner[32] ||
owner[32] ||
signer_account[32] ||
signer_device[32] ||
u32_le(signer_authority_length) || KDA2_signer_authority ||
prior_state_id[16] ||
u16_le(name_length) ||
member_count[1] ||
transfer_count[1] ||
secret_hash[32] ||
UTF8_name ||
member... ||
owner_transfer...
```

Each sorted member is:

```text
peer_ed25519[32] || role[1] ||
u16_le(identity_length) || CP1_IdentityPublic
```

Roles are owner=1, admin=2, and member=3. Each ordered owner transfer is:

```text
u64_le(epoch) ||
u64_le(generation) ||
prior_state_id[16] ||
from_owner[32] ||
to_owner[32] ||
from_device[32] ||
u32_le(from_authority_length) || KDA2_from_authority ||
device_signature[64]
```

The complete encoded state is the signing bytes followed by the authorizing
device signature `[64]`. Every embedded authority proof MUST accept the named
physical device for the corresponding account and generation. The state
signature and transfer signatures use:

```text
Komms-group-authority-state-v1
Komms-group-owner-transfer-v1
Komms-group-admin-request-v1
Komms-group-poll-moderation-v1
```

The complete authority payload is at most 4 MiB; a member identity at most 512
octets; a group name at most 256 UTF-8 octets; and each embedded device
authority proof at most 1 MiB. The exact valid v2 encoding is fixture
`group-authority-device-bound-v2`. Legacy group-authority v1 is accepted only
for explicit migration and already-stored history. A state transported as
content kind 7 must also fit the 65,507-octet content-payload ceiling.

Call-control payloads are transient and never durable chat history:

```text
version=01 || operation[1] || call_id[16] ||
initiator_device[32] || u64_le(expires_at) || operation_fields
```

Operations are offer=1, answer=2, decline=3, busy=4, cancel=5, hangup=6.
Offer appends a fresh 32-byte master secret. Answer, decline, and busy append
the responder device. Cancel appends nothing. Hangup appends responder device
and a one-byte reason. Identifiers, expiry, and required 32-byte fields are
non-zero. Call controls require pairwise origin authentication and do not
expand a relay's authority.

### 4.4 Padding and fragmentation

Before content encryption, ISO/IEC 7816-4 padding uses a single `80` octet
followed by zero octets to the smallest bucket in:

```text
192, 512, 1024, 4096, 16384, 65536
```

Larger media is chunked. Transport fragmentation does not alter end-to-end
content. A fragment body is:

```text
message_digest_prefix[4] || u16_le(index) || u16_le(count) || slice
```

The prefix is the first four bytes of BLAKE3 over the reassembled exact
payload. Reassembly MUST bound count, bytes, and lifetime, reject inconsistent
duplicates, and verify the digest before decryption. One payload has at most
1,024 fragments and 128 KiB. An endpoint retains at most 256 partial payloads
for at most 24 hours. A duplicate identical fragment is idempotent; a
conflicting count, out-of-range index, aggregate overflow, or final digest
mismatch fails closed.

## 5. Recipient-authenticated group origins

Each sender physical device has a sender-key chain per group:

```text
key_id[16], chain_key[32], iteration[u32]
CK' = HKDF32(absent, CK, "KK-group-chain")
MK  = HKDF32(absent, CK, "KK-group-msg")
header_key = HKDF32(absent, group_secret, "KK-group-hdr")
```

Group message v1 has membership-level authenticity:

```text
01 || sealed_header[60] || payload_nonce[24] ||
payload_ciphertext || tag[16]
```

Its header plaintext is `key_id[16] || u32_le(iteration)`. Group message v2
has a 76-byte sealed header whose plaintext appends `content_id[16]`:

```text
02 || sealed_header[76] || payload_nonce[24] ||
payload_ciphertext || tag[16]
```

Header AD is `Komms-group-hdr-v1 || version`. Payload AD is
`Komms-group-msg-v1 || version || group_id[32] || sealed_header`.

V2 retains one shared ciphertext. For every recipient account/device, the
sender distributes a separate random 32-byte `origin_key` over an authenticated
pairwise device session. The recipient-scoped tag is:

```text
HMAC-SHA-256(origin_key,
    "Komms-Group-Origin-v1" ||
    group_id[32] ||
    sender_account[32] ||
    sender_device[32] ||
    recipient_account[32] ||
    recipient_device[32] ||
    sender_chain_key_id[16] ||
    envelope_content_id[16] ||
    u64_le(authenticated_retention_or_zero) ||
    SHA-256(shared_group_ciphertext))
```

The wrapper is:

```text
ff 4b 47 01 || u32_le(shared_length) ||
shared_group_ciphertext || origin_tag[32]
```

Sender-chain and origin-capability distribution travels inside a pairwise
ratchet as CP1 `GroupControlPayload`. Its enum indices are:

```text
0 Announce(GroupAnnounce)                 # legacy
1 Leave(group[32])
2 Remove(group[32])                       # legacy creator removal
3 AuthorityAnnounce(GroupAuthorityAnnounce)
4 AdminRequest(GroupAdminRequest)
5 AdminResult(GroupAdminResult)
6 AuthorityRemove(group[32], state_id[16], state_payload: bytes)
7 OriginAnnounce(GroupOriginAnnounce)
8 OriginAuthorityAnnounce(GroupOriginAuthorityAnnounce)
```

The component structs, in field order, are:

```text
GroupMemberInfo =
    peer[32], identity: bytes

GroupAnnounce =
    group[32], name: UTF8, creator[32],
    members: sequence<GroupMemberInfo>,
    secret[32], generation: u64,
    key_id[16], chain_key[32], iteration: u32

GroupAuthorityAnnounce =
    group[32], state_id[16], state_payload: bytes,
    secret[32], key_id[16], chain_key[32], iteration: u32

GroupOriginAnnounce =
    announce: GroupAnnounce,
    origin_generation: u64,
    recipient_account[32], recipient_device[32], origin_key[32]

GroupOriginAuthorityAnnounce =
    announce: GroupAuthorityAnnounce,
    origin_generation: u64,
    recipient_account[32], recipient_device[32], origin_key[32]
```

`GroupAdminRequest` is `request_id[16], group[32], base_generation: u64,
action, signature: bytes[64]`. Its CP1 action indices are invite=0 carrying a
`GroupMemberInfo`, remove=1 carrying `peer[32]`, rename=2 carrying UTF-8 text,
and moderate-poll=3 carrying `poll_author[32], poll_id[16]`.
`GroupAdminResult` is `group[32], request_id[16], accepted: bool, generation:
u64, state_id: Option<[u8;16]>, reason: u8`; reason is accepted=0, stale=1,
unauthorized=2, or invalid=3, and `accepted` is true exactly for reason 0.

Every v2 origin generation, group generation, recipient identity/device, chain
id/key, group secret, and origin key is non-zero. Rosters contain at most 64
unique members, names at most 256 UTF-8 octets, encoded identities at most 512
octets, and authority payloads at most 65,507 octets. The complete control must
fit the 128-KiB envelope after pairwise framing and section 4.4 padding.

The receiver MUST derive the author only from the pairwise-authenticated
device certificate and accepted device-authority chain. It MUST verify the tag
in constant time before advancing or decrypting the sender chain. Text,
attachments, mentions, edits, polls, expiry events, roles, moderation,
ownership, and device-sync imports all require the same origin rule.

Origin keys and sender chains rotate and old capabilities are erased on roster,
device, session, group generation, or device-authority changes. Legacy v1
history remains visibly membership-authenticated; it MUST NOT be relabeled as
individually authenticated.

Group receiving chains use the same 1,000-key skip, 2,000-key retained, and
30-day TTL bounds as pairwise sessions.

## 6. Revocable device authority and recovery

### 6.1 Device certificates

The account private root signs only genesis and explicit recovery. It MUST NOT
exist in a live store, routine link package, routine migration, or ordinary
backup after genesis.

A v2 device certificate is CP1:

```text
account: IdentityPublic
device: IdentityPublic
serial: [u8; 16]
issued_at: u64
device_signature: bytes[64]
```

The device signature covers:

```text
u16_le(2) || account.IdentityPublic_raw ||
device.IdentityPublic_raw || serial[16] || u64_le(issued_at)
```

with domain `Komms-device-authority-certificate-v2`.
`IdentityPublic_raw` is the fixed 128-byte form from section 2.2. Serial is
random and non-zero.

### 6.2 KDA2 manifest

A manifest is `KDA2 || CP1(transitions)`, with 1–64 transitions and at most
1 MiB after the magic. Each transition contains:

```text
version=2
account
parent_hash[32]
parent_generation
generation
recovery_epoch
transition_id[16]
optional recovery_id[16]
kind
complete sorted device-entry set
sorted newly introduced certificates
authorization
```

Kinds are genesis=1, add=2, rename=3, observe=4, revoke=5, replace=6, and
recovery=7. There are at most eight active devices, 64 lifetime
certificate/tombstone entries, and 64 UTF-8 octets in a device name.

In the CP1 transport form, the fields have the order above. The transition
kind is its zero-based CP1 enum index (`0..6` corresponding to the semantic
values `1..7`). A device entry is:

```text
certificate: DeviceAuthorityCertificate
name: UTF8
last_seen: u64
revoked_at: Option<u64>
revoked_after_counter: Option<u64>
```

The authorization is CP1 enum index 0 followed by a sequence of
`signer[32], signature: bytes[64]`, or index 1 followed by
`signature: bytes[64]` for root authorization. The manifest wrapper is the CP1
sequence of transitions with no further field.

The canonical proposal bytes, independent of the growing signature list, are:

```text
u16_le(version) ||
account_raw[128] ||
parent_hash[32] ||
u64_le(parent_generation) ||
u64_le(generation) ||
u64_le(recovery_epoch) ||
transition_id[16] ||
(00 | 01 || recovery_id[16]) ||
kind[1] ||
u32_le(device_entry_count) || canonical_entry... ||
u32_le(new_certificate_count) ||
    (u32_le(certificate_message_length) ||
     certificate_message || device_signature[64])...
```

Each canonical entry is:

```text
u32_le(certificate_message_length) ||
certificate_message || device_signature[64] ||
u32_le(name_length) || UTF8_name ||
u64_le(last_seen) ||
(00 | 01 || u64_le(revoked_at)) ||
(00 | 01 || u64_le(revoked_after_counter))
```

Here `certificate_message` is the fixed 282-byte certificate signing message
from section 6.1, without its trailing device signature. Device entries and
new certificates are strictly sorted by physical-device Ed25519 key and
contain no duplicates.

An ordinary approval is:

```text
signer_device_ed25519[32] ||
Sign_D(signer_device,
       "Komms-device-authority-transition-v2",
       canonical_proposal)
```

Signers are unique, sorted, and active in the complete previous state.
Quorum is `floor(previous_active_count / 2) + 1`. A committed ordinary
transition MUST meet quorum; collection of partial approvals does not itself
change authority.

Genesis has generation 1, recovery epoch 0, zero parent, one fresh active
device, and a root authorization over the canonical proposal using domain
`Komms-device-authority-root-transition-v2`.

Recovery increments the parent generation and recovery epoch, includes a fresh
non-zero recovery id, revokes every formerly active device, and introduces
exactly one fresh active recovery device. It has root authorization under the
same root-transition domain. Descendants of lower recovery epochs are invalid.

The complete transition hash is SHA-256 of:

```text
canonical_proposal ||
(01 || u32_le(signature_count) ||
     (signer[32] || signature[64])...
 | 02 || root_signature[64])
```

Every child binds the exact parent transition hash and generation.

Two verified ordinary children of one parent are a visible fork. Two different
root transitions at the same recovery epoch are a visible recovery conflict.
Neither may be selected by timestamp, generation ordering, lexicographic hash,
or arrival order. The endpoint MUST fail closed and require explicit recovery
or resolution.

Recovery also rotates or invalidates device sync, pairwise sessions,
rendezvous, wake, group chains/origin capabilities, delivery work, and
introduction state. Stable account identity is retained only where the
accepted higher recovery epoch makes that safe.

### 6.3 Offline recovery authority

An account root may exist only in an explicitly opened offline `KRA1` package:

```text
KRA1 || CP1(
    version=1,
    account: IdentityPublic,
    sealed_root: bytes
)
```

The 32-byte entropy represented by the 24-word recovery mnemonic derives:

```text
key = HKDF32(
    salt=identity_digest,
    ikm=mnemonic_entropy,
    info="Komms-account-recovery-authority-key-v1")

aad = "Komms-account-recovery-authority-package-v1" ||
      u16_le(1) || account_raw[128]
```

The opened CP1 payload is `root_secret: bytes[64], account:
IdentityPublic`. The package is at most 4 KiB. Opening requires an explicit
recovery flow and local attempt throttling; the root is erased immediately
after signing one recovery transition.

## 7. Root-free backup and restoration

Current backup outer format, called KKR10, is:

```text
magic "KKRA"[4] ||
u32_le(argon2_memory_kib) ||
u32_le(argon2_iterations) ||
u32_le(argon2_parallelism) ||
salt[16] ||
Seal(backup_key,
     "Komms-root-free-backup-v10",
     CP1(AuthorityBackupPayload))
```

The mnemonic supplies 32 bytes of entropy. Argon2id v1.3 derives the 32-byte
backup key using the exact header parameters and salt. The maximum file size
is 16 GiB and the logical record ceiling is 50,000,000.

The v10 logical payload contains, in order: creation time, public account,
accepted `KDA2` proof, sealed Connect-capability state, contacts, eligible
message history, session-reset peer ids, group metadata without chains, group
history without pending fanout, group authority, local organization,
note-to-self history, ephemeral tombstones, contact-device public records, and
local block rules.

The outer file, key schedule, exclusion rules, recovery transition, and minimal
portable payload fixed by `root-free-backup-kkr10` are part of this profile.
The richer application-record collections retain their KKR10 CP1 schemas for
Komms backup compatibility, but this kit does not claim a language-neutral
cross-product interchange schema for every UI metadata record. A separately
produced implementation MAY reject non-empty optional application collections
as unsupported while still importing the minimal fixture; it MUST NOT skip,
reinterpret, or partially restore them. A future portable collection schema
requires a new backup format or an explicit compatible extension.

It MUST NOT contain:

- the account private root or `KRA1` mnemonic;
- any reusable physical-device private credential;
- own prekey secrets;
- pairwise ratchet or skipped-message keys;
- device-sync channel roots;
- group sender or receiver chains;
- group-origin keys;
- rendezvous exporters, slots, or route records;
- wake capabilities or native provider tokens;
- delivery queues, leased rows, or sender retry ciphertext;
- provisional first-contact sessions, previews, invitation capabilities, or
  replay tombstones.

Restore requires the separately opened matching account root, verifies the
complete payload before replacing a profile, creates a higher recovery epoch
with one fresh device, and re-handshakes contacts. KKR8 and KKR9 are direct
root-free predecessor formats. KKR1–KKR7 copied the account root and therefore
are archive inputs only: they require a visible new identity/authority reset
and contact re-verification, not silent continuation.

## 8. Bounded first-contact admission and consent

### 8.1 Admission descriptor

The public prekey bundle carries one `KAD1 || CP1(AdmissionDescriptor)` relay
hint and, only in an out-of-band invite artifact, an optional
`KAI1 || invitation_secret[32]`.

The descriptor fields are:

```text
version=1
bundle_digest[32]
validity_epoch[u64]
expires_at[u64]
max_clock_skew_secs[u32]
puzzle_profile=1
difficulty[u8]
max_first_ciphertext[u32]
optional invitation_commitment[32]
sorted token_issuer_ids[][32]
signature[64]
```

The descriptor is at most 512 octets. Epochs are one hour. Difficulty is
8–20 leading zero bits. First ciphertext is 1–16 KiB. Clock skew is at most
six hours. There are at most four sorted unique issuer ids.

`bundle_digest` is:

```text
SHA-256("Komms-admission-bundle-v1" ||
       canonical_bundle_signing_message_without_admission_extensions)
```

The descriptor's signature message is the preceding fields in fixed order,
using little-endian integers, `00`/`01` optional commitment, one-byte issuer
count, and the issuer ids. Its signature domain is
`Komms-admission-descriptor-v1`.

An invitation commitment is:

```text
SHA-256("Komms-admission-invitation-v1" ||
       recipient_device_ed25519[32] ||
       bundle_digest[32] ||
       u64_le(validity_epoch) ||
       u64_le(expires_at) ||
       invitation_secret[32])
```

The bearer invitation secret is never published in a DHT record.

### 8.2 KFA1 wrapper and proofs

The exact 168-byte header is:

```text
offset  size  field
0       4     "KFA1"
4       1     version=1
5       1     proof kind: puzzle=1, invitation=2
6       2     reserved=0
8       32    target account Ed25519
40      32    target physical-device Ed25519
72      32    signed bundle digest
104     8     validity epoch, little-endian
112     16    admission content id
128     32    proof
160     4     target-bundle length, little-endian
164     4     sealed-flight length, little-endian
```

It is followed by the exact target prekey bundle and anonymous-boxed initial
flight. Bundle length is 1–32 KiB; sealed flight is 1–16 KiB.

```text
content_id = first16(SHA-256(
    "Komms-admission-content-v1" || 01 ||
    target_account || target_device || bundle_digest ||
    u64_le(validity_epoch) || SHA-256(sealed_flight)))
```

The puzzle is valid when:

```text
SHA-256("Komms-admission-puzzle-v1" ||
       target_account || target_device || bundle_digest ||
       u64_le(validity_epoch) || content_id || nonce[32])
```

has the advertised number of leading zero bits. A client search is limited to
`2^22` attempts. The invitation proof is:

```text
HMAC-SHA-256(invitation_secret,
    "Komms-admission-invitation-proof-v1" ||
    target_account || target_device || bundle_digest ||
    u64_le(validity_epoch) || content_id)
```

The target MUST verify shape, exact bundle, descriptor, expiry, and either the
puzzle or invitation proof before ML-KEM decapsulation where possible.

### 8.3 Consent state

An unknown sender enters a sealed provisional request domain, never normal
contacts or history. Admission, one-time-prekey consumption, provisional
session state, verified identity/device authority, safety number, bounded
preview, and request row commit atomically.

Accept atomically promotes the request and session. Delete removes provisional
material and leaves only a bounded replay tombstone. Block additionally removes
local capabilities and queued work; it does not claim remote deletion. Group
invitations cross the same consent boundary.

Implementations MUST enforce global concurrency, puzzle/KEM work, provisional
row and byte, preview, notification, per-tick, carrier, mailbox, and bridge
budgets. Refusals have a bounded uniform shape and MUST NOT reveal request-inbox
capacity. The stable provisional domain admits at most 32 rows and 512 KiB
total. One row carries at most 64 KiB of sealed session state, 4 KiB of first
content, and 2 KiB of UTF-8 preview, and expires within seven days.

## 9. Capability-scoped discovery

### 9.1 Connect code

A Connect code is:

```text
"kc2" || base32_lower_no_padding(
    identity_digest[32] ||
    discovery_capability[32] ||
    checksum[4])
```

`identity_digest` is the stable account address digest:

```text
identity_digest = SHA-256(
    account_ed25519_public[32] || account_x25519_public[32])
```

`discovery_capability` is random and non-zero.

```text
checksum = first4(SHA-256(
    "Komms-Connect-Code-v2" ||
    identity_digest || discovery_capability))
```

Only canonical lowercase RFC 4648 base32 without padding is accepted.
Capability rotation does not change the account fingerprint or safety number.
The capability is sealed at rest and included only in encrypted root-free
backup and authenticated contact/device updates.

### 9.2 Epoch keys and introduction tokens

A discovery epoch is 604,800 seconds:

```text
locator_e = HMAC-SHA-256(
    discovery_capability,
    "Komms-DHT-Locator-v2" || u64_be(e))

record_key_e = HKDF32(
    salt=locator_e,
    ikm=discovery_capability,
    info="Komms-DHT-Record-Key-v2")

record_aad =
    "Komms-DHT-Record-v2" || locator_e || u64_be(e)
```

A record is endpoint-valid from `e*604800 - 86400` through
`(e+1)*604800 + 86400`, saturating only at the lower boundary and rejecting
integer overflow. Maintenance publishes epochs `current-1` through
`current+4`; lookup queries only `current-1`, `current`, and `current+1`.

The separate daily introduction token for one ingress device is:

```text
introduction_key =
    HKDF32(recipient_device_ed25519,
           discovery_capability,
           "Komms-Introduction-Mailbox-Key-v2")

introduction_token =
    HMAC-SHA-256(introduction_key,
        "Komms-Introduction-Mailbox-Token-v2" ||
        u64_be(day_epoch))
```

### 9.3 Fixed DHT record

The sealed value is exactly 1,179,648 octets:

```text
nonce[24] ||
XChaCha20-Poly1305(
    record_key_e, nonce, record_aad,
    plaintext[1,179,608])
```

The plaintext's final 64 octets are a signature. The preceding 1,179,544
octets contain:

```text
"KDR2" ||
u16_be(2) ||
locator[32] ||
u64_be(epoch) ||
u64_be(generation) ||
u64_be(issued_at) ||
u64_be(expires_at) ||
account_raw[128] ||
u32_be(authority_length) || KDA2_authority ||
ingress_count[1] ||
for each ingress, sorted by device id:
    u16_be(certificate_length) || CP1(device_certificate) ||
    u32_be(prekey_length) || CP1(prekey_bundle) ||
route_count[1] ||
for each route, sorted by (kind, bytes):
    kind[1] || u16_be(route_length) || route_bytes ||
signer_device_ed25519[32] ||
zero padding to octet 1,179,544
```

Generation is positive. There are one or two ingress devices. A certificate
is at most 4 KiB; prekeys are at most 32 KiB. Published ingress bundles contain
no OPK and no ordinary transport hint, but do contain a valid signed admission
descriptor. There are at most three routes, each 1–1,024 octets. Route kind 1
is an introduction mailbox; kind 2 is an explicitly warned Sovereign direct
route. Standard and Private modes MUST publish only kind 1.

The signature is by an active device in the included `KDA2` proof:

```text
Sign_D(device,
    "Komms-DHT-Record-Signature-v2",
    SHA-256(plaintext[0..1,179,544]))
```

All padding MUST be zero and is covered by the signature. At most eight
candidate values and their fixed aggregate byte count may be retained per
locator. Invalid candidates are discarded within fixed work limits. Among
valid records at the expected epoch and account digest, selection is highest
generation followed by the lexicographically smallest SHA-256 of the complete
plaintext. This ordering resolves redundant publications, never an authority
fork: a fork or recovery conflict inside `KDA2` remains a visible failure.

The legacy identity-indexed DHT record is migration-only and MUST NOT publish
the new capability under the old stable identity-derived key.

## 10. Durable leased mailbox v2

The libp2p protocol id is `/komms/mailbox/2`. Requests are at most 320 KiB and
responses at most 3 MiB. The exact codec is deterministic CBOR:

- definite-length maps, arrays, text, integers, and Booleans only;
- externally tagged enum map with exactly one variant;
- field names and their serializer order are fixed by the following shapes;
- every field below described as `bytes`, `bytes16`, or `bytes32` is encoded
  as a definite-length CBOR array of unsigned integer octets; a CBOR byte
  string is noncanonical for this profile;
- a decoder MUST re-encode and byte-compare, rejecting alternative encodings,
  key order, trailing input, or over-limit values.

Semantic request shapes are:

```text
{"Deposit":{"envelope": bytes}}
{"Lease":{"tokens": [bytes32, ...]}}
{"AckLease":{"lease_id": bytes16, "row_ids": [bytes16, ...]}}
```

Responses are:

```text
{"Deposit":{"accepted": bool}}
{"Lease":{
    "serving": bool,
    "lease_id": bytes16,
    "expires_at": uint,
    "rows": [{"row_id":bytes16,"envelope":bytes}, ...]
}}
{"AckLease":{"accepted": bool}}
```

The exact canonical encodings are fixed by
`mailbox-v2-canonical-cbor` in `cases/services.json`.

A deposit is accepted only after its opaque row commits durably. The relay
persists a keyed token index, random non-zero row id, exact ciphertext, expiry,
and content-id dedup under row-bound authenticated storage. It enforces
per-token, per-client, global item/byte, retention, and rate limits.

A lease page has at most 128 rows and 1 MiB of raw ciphertext. It remains
durable at the relay until the endpoint transactionally stages the exact
accepted envelopes and sends `AckLease` naming the exact lease and row ids.
Acknowledgements contain at most 128 distinct ids and delete no unrelated row.
Duplicate deposits, leases, pages, acks, response loss, restart, partial
capacity, and crash at every transaction boundary MUST be idempotent and MUST
NOT lose accepted ciphertext.

A miss or refusal is:

```text
serving=false, lease_id=00*16, expires_at=0, rows=[]
```

and has the same bounded externally visible shape. A collector uses bounded
pages, jittered backoff, fairness, and a per-lifecycle work ceiling; it MUST NOT
loop until an adversarial relay returns empty. Sender ciphertext remains queued
until an end-to-end receipt, not merely relay acceptance.

Mailbox v1 delete-on-check-in is disabled by default and does not satisfy this
profile's custody guarantee.

## 11. Rotating pairwise rendezvous

The service is an optional least-authority post-pairing route cache. It is not
an identity directory, mailbox, endpoint, or delivery authority.

Provider id and hourly directional keys are:

```text
provider_id = SHA-256(canonical_https_origin || provider_static_key[32])
recipient = recipient.ed[32] || recipient.x[32]

locator_key = HKDF32(
    provider_id, hybrid_service_exporter,
    "Komms-Rendezvous-Locator-v1" || recipient)

payload_root = HKDF32(
    provider_id, hybrid_service_exporter,
    "Komms-Rendezvous-Payload-v1" || recipient)

slot_e = HMAC-SHA-256(
    locator_key,
    "Komms-Rendezvous-Slot-v1" || u64_be(e))

payload_key_e = HKDF32(
    u64_be(e), payload_root,
    "Komms-Rendezvous-Epoch-Key-v1")

record_aad =
    "Komms-Rendezvous-Record-v1" ||
    provider_id || slot_e || u64_be(e)
```

An epoch is 3,600 seconds. Choosing the local recipient identity derives the
publication direction; choosing the peer recipient derives the lookup
direction.

The plaintext is exactly 4,096 octets:

```text
version=01 || reserved=00 ||
u64_be(epoch) || u64_be(generation) ||
u64_be(issued_at) || u64_be(expires_at) ||
route_count[1] ||
for each route:
    kind[1] || u16_be(UTF8_length) || canonical_UTF8_route ||
zero padding
```

There are at most eight routes, each at most 512 octets. Padding is zero.
Route kind 1 is a canonical libp2p multiaddress; kind 2 is a canonical mailbox
relay multiaddress. Routes are strictly sorted by `(kind, UTF8_route)` with no
duplicates. Generation is non-zero and monotonic. `issued_at <= expires_at`
and the lifetime is at most 7,200 seconds. The sealed record is exactly 4,136
octets.

An endpoint accepts an opened record only when:

```text
record.epoch == queried_epoch
record.generation >= greatest_accepted_generation
effective_now = max(wall_clock_now, retained_clock_floor)
record.expires_at > effective_now
record.issued_at <= effective_now + 300
```

The retained clock floor prevents clock rollback from reviving an expired
record. The authority value of an accepted generation is its complete ordered
route set and expiry. Replaying that authority value at the greatest generation
is idempotent even when the publication epoch or issue time differs. A
different route set or expiry at the same generation is a durable conflict:
the provider source is cleared and remains fail-closed until a strictly newer
valid generation arrives. A lower generation, wrong epoch, expired record,
excessive future issue time, invalid lifetime, noncanonical order, duplicate
route, or non-zero padding is rejected.

The recipient advertises its complete provider set through an authenticated
pairwise device session:

```text
KRV1 || version=01 ||
account[32] || device[32] ||
u64_be(authority_generation) || u64_be(generation) ||
provider_count[1] ||
for each provider, strictly sorted:
    u16_be(origin_length) || canonical_https_origin ||
    provider_static_key[32]
```

The two generations and every provider static key are non-zero. There are at
most eight providers and every origin is 1–512 UTF-8 octets. An empty provider
set explicitly disables rendezvous for that sending device.

HTTP uses binary bodies and media type
`application/komms-rendezvous-v1`:

| Operation | Path | Request bytes | Response bytes |
|---|---|---:|---:|
| register | `/v1/rendezvous/register` | 4,180 | 64 |
| lookup | `/v1/rendezvous/lookup` | 64 | 4,136 |

A register request is `slot[32] || u64_be(epoch) || u32_be(ttl) ||
sealed_record[4136]`. A lookup request is `slot[32] || u64_be(epoch) ||
zero_padding[24]`. A syntactically valid register receives 64 fresh random
octets whether admitted or refused. A lookup hit returns the stored 4,136
octets; a miss or admission refusal returns 4,136 fresh random octets. Any
wrong path, media type, length, padding, or other malformed request receives a
uniform 64-random-octet error body. No capability appears in a URL.

Endpoints query only for queued work without a fresh route, active
conversation/call setup, wake collection, or near-expiry while active. They
use single-flight, coalescing, jitter, backoff, and a circuit breaker. Service
acknowledgement means neither registered, reachable, sent, nor delivered.

## 12. Native wake

Native wake is optional availability assistance. It has no authority over
message identity or delivery state. A wake may be requested only after direct
transport acceptance without receipt or, preferably, durable mailbox
acceptance. It MUST NOT advance queued, sent, or delivered state.

A gateway-encrypted capability plaintext is exactly 704 octets:

```text
version=01 ||
platform[1] || environment[1] || profile[1] ||
u64_be(expires_at) ||
capability_id[16] ||
u16_be(provider_token_length) ||
provider_token padded to 512 octets ||
app_topic_length[1] ||
app_topic padded to 128 octets ||
zero padding
```

Platform is APNs=1 or FCM=2. Environment is development=1 or production=2.
Profile is background-only=1 or generic-visible=2. Provider token is 1–512
octets; topic is 1–128 octets; expiry and capability id are non-zero.

The public capability is exactly 748 octets:

```text
u32_be(gateway_key_id) || nonce[24] ||
XChaCha20-Poly1305 ciphertext[704] || tag[16]
```

Associated data is `Komms-Wake-Capability-v1`. Capability lifetime is at most
30 days. Key ids, nonces, and sealed payloads are non-zero. Gateway keys are
durable, versioned, rotated with bounded overlap, and separate from user,
directory, rendezvous, and release keys.

A canonical gateway origin and its leaf-certificate pin are separated by:

```text
provider_id = SHA-256(
    "Komms-Wake-Provider-v1" ||
    u16_be(canonical_https_origin_length) ||
    canonical_https_origin ||
    provider_static_key[32])
```

The HTTPS media type is `application/komms-wake-v1`; paths are
`/v1/wake/register`, `/v1/wake/trigger`, and `/v1/wake/revoke`. Register
request/response lengths are 768/1,024. Trigger and revoke requests are 1,024;
their generic responses are 256. Exact bodies are:

```text
register request =
    version=01 || platform[1] || environment[1] || profile[1] ||
    u16_be(provider_token_length) ||
    provider_token padded to 512 ||
    app_topic_length[1] || app_topic padded to 128 ||
    request_nonce[16] || zero padding to 768

register response =
    version=01 || accepted[1] || u64_be(expires_at) ||
    u16_be(capability_length) || capability padded to 748 ||
    zero padding to 1,024

trigger or revoke request =
    version=01 || u16_be(748) || capability[748] ||
    request_nonce[16] || zero padding to 1,024

trigger or revoke response =
    version=01 || zero padding[255]
```

Every request nonce is random and non-zero. A refused registration has
`accepted=00`, zero expiry, zero capability length, and zero capability bytes;
an issued registration has `accepted=01`, non-zero expiry, and capability
length 748. All fixed padding is zero. Trigger/revoke requests carry only the
opaque capability and replay nonce.

An authenticated pairwise complete capability set is:

```text
KWC1 || version=01 ||
sender_account[32] || sender_device[32] ||
recipient_account[32] || recipient_device[32] ||
u64_be(authority_generation) || u64_be(generation) ||
capability_count[1] ||
for each descriptor, strictly sorted by (origin, static_key):
    u16_be(origin_length) || canonical_https_origin ||
    provider_static_key[32] || u64_be(expires_at) ||
    capability[748]
```

All four identity/device values, both generations, every provider static key,
every descriptor expiry, and every public capability's key id, nonce, and
sealed body are non-zero. There are at most four descriptors and every origin
is 1–512 UTF-8 octets. An empty complete set revokes its predecessor. Blocking,
token change, device removal, recovery, authority change, mode change, and
provider change rotate or revoke the set.

The gateway accepts no sender, account, conversation, message, text, media,
unread, or timestamp field. It enforces bounded replay state through
capability expiry, per-capability/per-destination/global quotas, and
coalescing. APNs and FCM payloads are static and content-free.

A wake collection performs one bounded configured-mailbox pass, relevant
rendezvous refresh, ordinary dedup/ratchet/persistence/receipt work, a platform
deadline, and durable remainder. It never triggers mesh flood, sneakernet
export, attachment autoplay, or call setup.

## 13. Atomic state and error behavior

A stable-v1 endpoint treats each authenticated transition as an all-or-nothing
commit. At minimum this applies to:

- one-time-prekey consumption and initial session installation;
- ratchet receive state, message persistence, dedup, and receipt scheduling;
- group-origin verification, sender-chain advance, content application, and
  pending fanout;
- device-authority acceptance and all state invalidated by recovery;
- provisional first-contact admission and consent actions;
- attachment staging and content commit;
- mailbox endpoint staging and exact-row acknowledgement; and
- backup restore into a new profile.

An implementation MUST distinguish internally:

- malformed/canonicality failure;
- unsupported but bounded version or kind;
- authentication or integrity failure;
- replay/stale/old-epoch failure;
- authority fork or recovery conflict;
- resource/capacity refusal; and
- durable I/O failure.

Network services MAY intentionally collapse those to a uniform bounded
response. Endpoints MUST preserve unsupported authenticated content opaquely
where this specification says so. No failure may partially advance
cryptographic state, consume unrelated work, delete unrelated custody rows, or
be converted into success by sorting candidate authority.

Parsers MUST be total for arbitrary input, enforce fixed maximum allocation
before decoding nested values, and reject non-canonical duplicate, reordered,
overflowing, or trailing representations. Expensive operations are subject to
per-request and global work limits.

## 14. Compatibility and downgrade rules

| Area | Current | Compatibility rule |
|---|---|---|
| content | typed v1 | valid UTF-8 without magic remains legacy text; typed input never falls back |
| envelope | v2 when retained, otherwise v1 | unknown versions fail; v1 remains byte-exact |
| PQXDH/ratchet | v1 | no classical-only downgrade; missing exporter requires authenticated re-handshake |
| groups | origin-authenticated v2 | v1 history remains visibly membership-authenticated |
| group authority | v2 | v1 only for explicit Alpha migration/stored history |
| device authority | KDA2 | copied-root manifests cannot silently become KDA2 |
| backup | KKR10 (`KKRA`) | KKR8/9 direct predecessors; KKR1–7 reset/new identity only |
| first contact | KAD1/KFA1 | unknown senders cannot enter normal history |
| discovery | KDR2/`kc2` | identity-indexed DHT is migration-only and cannot reveal the capability |
| mailbox | `/komms/mailbox/2` | v1 is disabled by default and offers no leased-custody guarantee |
| rendezvous | v1 | optional; absence leaves direct/mailbox/fallback behavior |
| wake | v1 | optional; absence or failure leaves delivery semantics unchanged |

A sender MUST use an authenticated capability exchange before enabling a newer
format for a relationship. A receiver MUST NOT accept a weaker alternate after
the stronger format was committed unless this table explicitly defines a
visible migration. Unknown security-critical versions are rejected; unknown
authenticated application content is retained as unsupported.

## 15. Operating modes and optional services

Cryptographic trust, message formats, identity, delivery state, and fallback
semantics are invariant across Standard, Private, and Sovereign modes.

- Standard MAY use disclosed, replaceable defaults.
- Private uses Tor or separately administered OHTTP ingress and MUST NOT claim
  non-collusion without distinct administrative domains.
- Sovereign disables optional rendezvous and wake by default while retaining
  DHT, user-selected mailboxes, QR/file exchange, direct, LAN, mesh, and
  sneakernet.

Provider directories, bootstrap caches, rendezvous, mailbox, OHTTP, and wake
are optional operational components. None is a user identity authority,
plaintext bridge, receipt authority, or source of message authorship. Failure
of every optional component leaves bounded retry and user-selected fallback;
it does not permit a format or trust downgrade.

## 16. Conformance requirements

A conforming implementation:

1. implements the required primitive, codec, state, and negative behavior in
   this document;
2. passes every applicable exact case in `cases/`;
3. accepts every applicable valid/compatibility fixture and rejects every
   applicable malformed fixture;
4. emits canonical bytes equal to the published values;
5. follows the published state traces, including replay, reorder, ratchet,
   quorum, recovery, and lease behavior, and satisfies the separately tested
   atomic crash-boundary requirements in section 13;
6. reports unsupported optional operations explicitly rather than silently
   passing them; and
7. records its source revision, build inputs, platform, adapter digest, case
   results, and limitations in its evidence result.

The packet capture is synthetic reference material, not live traffic. The
root-free backup vector uses an explicitly reduced fixture KDF cost and MUST
NOT set a production password-hardening policy.

Passing this kit demonstrates agreement with the tested profile. It does not
establish security, side-channel resistance, production hardening,
independence, field qualification, or service availability. Independent
interoperability requires a separately produced implementation or fixture
producer, run by a party able to attest its provenance and development
independence.

## Appendix A. Fixed global bounds

| Value | Bound |
|---|---:|
| prekey bundle | 32 KiB |
| envelope | 128 KiB |
| unpadded content frame | 65,535 bytes |
| attachment manifest | 1,024 bytes |
| primary attachment | 512 MiB |
| preview attachment | 256 KiB |
| device authority proof | 1 MiB / 64 transitions |
| active devices | 8 |
| device authority lifetime entries | 64 |
| account recovery package | 4 KiB |
| first-contact sealed flight | 16 KiB |
| admission puzzle | 8–20 bits / at most `2^22` attempts |
| provisional request domain | 32 rows / 512 KiB |
| provisional session / first content / preview | 64 KiB / 4 KiB / 2 KiB |
| provisional lifetime | 7 days |
| DHT record | exactly 1,179,648 bytes |
| DHT candidates per locator | 8 |
| mailbox request / response | 320 KiB / 3 MiB |
| mailbox lease page | 128 rows / 1 MiB ciphertext |
| rendezvous plaintext / seal | exactly 4,096 / 4,136 bytes |
| wake plaintext / capability | exactly 704 / 748 bytes |
| pairwise/group skipped advance | 1,000 |
| pairwise/group retained skipped keys | 2,000 for 30 days |

## Appendix B. Exact domain strings

```text
Komms-cross-sign-v1
KK-fingerprint
Komms-spk-v1
Komms-pqspk-v1
Komms-bundle-v1
Komms-PQXDH-v1
KK-hka
KK-nhkb
KK-mailbox
Komms-Hybrid-Service-Exporter-v1
KK-root
KK-chain
KK-msg
KK-hdr
KK-group-chain
KK-group-msg
KK-group-hdr
KK-group-hdr-v1
KK-group-msg-v1
Komms-Group-Origin-v1
Komms-device-authority-certificate-v2
Komms-device-authority-transition-v2
Komms-device-authority-root-transition-v2
Komms-account-recovery-authority-key-v1
Komms-account-recovery-authority-package-v1
Komms-root-free-backup-v10
Komms-admission-bundle-v1
Komms-admission-descriptor-v1
Komms-admission-invitation-v1
Komms-admission-content-v1
Komms-admission-puzzle-v1
Komms-admission-invitation-proof-v1
KK-token-v1
Komms-Connect-Code-v2
Komms-DHT-Locator-v2
Komms-DHT-Record-Key-v2
Komms-DHT-Record-v2
Komms-DHT-Record-Signature-v2
Komms-Introduction-Mailbox-Key-v2
Komms-Introduction-Mailbox-Token-v2
Komms-Rendezvous-Locator-v1
Komms-Rendezvous-Payload-v1
Komms-Rendezvous-Slot-v1
Komms-Rendezvous-Epoch-Key-v1
Komms-Rendezvous-Record-v1
Komms-Wake-Capability-v1
Komms-Wake-Provider-v1
Komms-group-authority-state-v1
Komms-group-owner-transfer-v1
Komms-group-admin-request-v1
Komms-group-poll-moderation-v1
```
