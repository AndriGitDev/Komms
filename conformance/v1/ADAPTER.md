# Stable-v1 conformance adapter contract

**Contract version:** 1
**Profile:** `komms-stable-v1`

The adapter is a test boundary, not a network service or production random
source. It lets one language-neutral runner drive equivalent operations in
separately produced implementations.

## Process contract

The runner starts the executable without shell interpolation. Standard input
and output are UTF-8 JSON Lines:

```json
{"id":"case-id","operation":"primitive.x25519","arguments":{}}
{"id":"case-id","ok":true,"result":{}}
```

The adapter MUST:

- accept at most one request per non-empty input line;
- emit exactly one response line for every request, in request order;
- copy the JSON `id` value without interpreting it;
- accept a request line no larger than 4 MiB;
- bound all decoded fields before allocating or doing expensive work;
- emit finite JSON numbers and lowercase even-length hex;
- never read production profiles, keystores, network state, or credentials;
- use only the supplied deterministic seeds in trace operations; and
- return an error without partial protocol-state mutation.

A success response is exactly:

```json
{"id":<copied>,"ok":true,"result":<operation object>}
```

An error response is exactly:

```json
{
  "id":<copied-or-null>,
  "ok":false,
  "error":{"code":"stable_code","message":"bounded diagnostic"}
}
```

Malformed top-level JSON uses `id: null`. The runner compares the complete
response except `id`; therefore error codes, messages, nulls, array order, and
field types are part of kit version 1. Object-key order and insignificant JSON
whitespace are not.

Input hexadecimal in the published cases is lowercase. An adapter MUST accept
that form and MUST emit lowercase. It MAY reject uppercase or other
non-canonical spellings. Unsigned integers are mathematical integers in the
range required by the named field; implementations must not round through an
IEEE-754 representation.

## Deterministic vector stream

Operations needing random bytes use the 32-byte `rng_seed_hex` (or a
field-specific seed) as:

```text
block(i) = SHA-256(
    UTF8("Komms-Conformance-RNG-v1") ||
    seed32 ||
    u64_be(i)
)
stream = block(0) || block(1) || ...
```

Each operation starts each named stream at counter zero and consumes bytes
from left to right, independent of caller read chunking. This construction is
only for reproducible public fixtures. It MUST NOT be exposed as or substituted
for a production CSPRNG.

## Operations

### Adapter inventory

`adapter.capabilities`

Arguments are `{}`. The result identifies profile `komms-stable-v1`, adapter
version `1`, and the complete supported operation-name array.

### Primitive known answers

`primitive.x25519`

- arguments: `alice_secret_hex[32]`, `bob_secret_hex[32]`;
- result: both public keys and their shared secret.

`primitive.ed25519`

- arguments: `secret_hex[32]`, arbitrary `message_hex`;
- result: `public_hex[32]`, `signature_hex[64]`.

`primitive.hkdf_sha256`

- arguments: arbitrary `ikm_hex`, `salt_hex`, `info_hex`, and
  `output_len` in `1..=8160`;
- result: `okm_hex`.

`primitive.xchacha20poly1305`

- arguments: `key_hex[32]`, `nonce_hex[24]`, arbitrary `aad_hex` and
  `plaintext_hex`;
- result: `sealed_hex`, with the 16-byte tag appended.

`primitive.argon2id`

- arguments: password, salt, optional secret and associated-data hex,
  `memory_kib`, `iterations`, `parallelism`, and `output_len`;
- result: `output_hex`;
- algorithm/version: Argon2id v1.3 (`0x13`).

### Content and envelope codecs

`content.encode_text`

- arguments: `content_id_hex[16]`, UTF-8 `text`;
- result: canonical content-v1 `encoded_hex`.

`content.suite`

- arguments define synthetic attachment, mention, edit, ephemeral, poll, and
  call-control values;
- result contains the exact canonical content-v1 frame for each value and a
  decode round-trip Boolean.

`content.decode`

- arguments: `encoded_hex`;
- result: one total classification: legacy text, a known typed value,
  unsupported version/kind, or malformed.

`envelope.decode`

- arguments: `encoded_hex`;
- result: kind, token, optional retention, body, and 16-byte dedup content id.

`token.delivery`

- arguments: `mailbox_key_hex[32]`, `recipient_ed25519_hex[32]`, `epoch`;
- result: `token_hex[32]`.

### Group and admission

`group.origin_tag`

- arguments are the 32-byte origin key, all fixed-width
  `GroupOriginContext` fields, nullable retention, and the exact shared
  ciphertext;
- result: `tag_hex[32]`.

`group.message_trace`

- generates one sender chain and one origin-authenticated v2 shared group
  ciphertext from the supplied group/origin keys and deterministic seed;
- returns the shared ciphertext, recipient wrapper, tag, opened plaintext,
  header fields, and replay/wrong-recipient/tamper rejection results.

`group.authority_trace`

- creates a root/account and separate physical device from supplied secrets;
- creates KDA2 genesis, embeds it in one owner authority state, signs the state
  with the active physical device, and frames it as content-v1 kind 7;
- returns the canonical authority bytes, signing bytes, KDA2 proof, and
  verification results.

`admission.puzzle`

- arguments are the target account/device, bundle digest, validity epoch,
  content id, difficulty, bounded maximum attempts, and vector seed;
- result is the first stream nonce satisfying the puzzle and a verification
  Boolean;
- exhaustion is an error, never an unbounded search.

`admission.trace`

- builds one device-signed prekey bundle and descriptor committed to an
  out-of-band invitation;
- removes the bearer invitation from the public bundle, then builds exact
  KFA1 invitation and puzzle wrappers around the supplied synthetic first
  flight;
- returns descriptor bindings, proofs, wrappers, and strict round-trip
  results.

### Discovery

`discovery.connect_code`

- arguments: synthetic identity secret `[64]` and non-zero capability `[32]`;
- result: canonical `kc2` text, identity digest, and capability.

`discovery.locator`

- arguments: capability `[32]`, weekly epoch;
- result: locator `[32]`.

`discovery.introduction_token`

- arguments: capability `[32]`, device id `[32]`, daily epoch;
- result: token `[32]`.

`discovery.record_trace`

- constructs one complete authority-bound ingress bundle, signed admission
  descriptor, introduction-only route, padded DHT plaintext, signature, and
  exact-size sealed v2 record from synthetic inputs;
- opens and verifies the result;
- returns the record bytes/digests and semantic summary.

### Mailbox v2

`mailbox.v2.trace`

- arguments: one canonical envelope, two tokens, one lease id, one row id,
  and expiry;
- result: canonical CBOR for durable deposit, deposit responses, lease request,
  serving page, uniform miss/refusal, exact-row acknowledgement, and response.

`mailbox.v2.canonicalize`

- arguments: `message` equal to `request` or `response`, plus `encoded_hex`;
- result: the identical canonical bytes;
- alternate encodings, trailing input, truncation, and oversize values fail.

### Rendezvous

`rendezvous.derive`

- arguments: canonical provider origin, provider static key, transcript-bound
  exporter, recipient identity secret, and hourly epoch;
- result: provider id, recipient public keys, slot, and epoch.

`rendezvous.seal`

- same derivation arguments plus exactly 4,096 plaintext bytes and a vector
  seed;
- result: exact 4,136-byte seal, SHA-256 digest, and nonce.

### Native wake

`wake.trace`

- encodes one exact 704-byte target payload, seals it into a 748-byte
  capability using the supplied synthetic gateway key and nonce, and opens it
  again;
- returns the exact registration request, issued/refused response, trigger,
  generic response, and authenticated pairwise capability-control bytes;
- covers APNs or FCM, development or production, and background-only or
  generic-visible profiles selected by the arguments.

### Recovery and device authority

`recovery_authority.trace`

- seals one synthetic account root into KRA1, opens it with the generated
  phrase, and returns the package/public binding/round-trip result.

`backup.root_free_trace`

- creates a minimal root-free authority profile, exports KKR10, restores it
  with the separate root, and reports the higher recovery epoch;
- returns a synthetic backup and phrase for compatibility testing;
- the fixture uses an explicitly reduced test KDF cost and is not an accepted
  production password-hardening profile;
- reports whether the root bytes, old device bytes, or live-prekey marker
  occur in the file; all must be false.

`device_authority.trace`

- creates KDA2 genesis, majority-authorized second-device transition, and a
  root-authorized recovery epoch;
- returns each manifest and branch/epoch relations.

`device_authority.verify`

- strictly decodes and verifies one KDA2 proof;
- returns public state only.

### Hybrid handshake and ratchet

`pqxdh.trace`

- builds and verifies a signed X25519/ML-KEM-768 prekey bundle;
- performs both sides of PQXDH;
- emits multiple initiator messages, receives them in the declared permutation,
  checks replay rejection, then advances each direction through a DH ratchet;
- returns exact public bundle/message bytes, opened payloads, shared mailbox
  key, session id, and transcript-bound service exporter.

The returned mailbox key/exporter are synthetic known-answer material. A real
implementation MUST keep the exporter in sealed non-backup service state and
MUST NOT log either secret.
