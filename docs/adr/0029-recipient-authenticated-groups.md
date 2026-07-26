# ADR-0029: Recipient-authenticated sender-key groups

- **Status**: Proposed
- **Date**: 2026-07-26
- **Supersedes on acceptance**: the membership-level-authenticity tradeoff in
  [ADR-0012](0012-sender-key-groups.md). Sender-key encryption, one shared
  ciphertext, recipient-scoped delivery, and bounded groups remain.

## Context

The current group construction gives every member each sender's symmetric
chain key and deliberately omits a signature. Any member can therefore create
a valid ciphertext under another member's chain. The delivery token usually
identifies the actual pairwise sender, but it is a routing capability rather
than cryptographic origin authentication and can be observed and copied on
shared carriers.

Membership-level authenticity is insufficient for author-sensitive state such
as edits, votes, role requests, moderation, and disappearing-message
authorship. At the same time, Komms should retain one group ciphertext per
message, recipient-deniable transcripts, and the existing per-recipient
envelopes needed by mailbox collection and receipts.

## Decision

### 1. Each sender chain has a distinct origin key per recipient device

When a device distributes or rotates its group sender chain, every recipient
device receives an additional random 32-byte `origin_key` over that device's
authenticated pairwise session. Origin keys are unique to:

- group id;
- sender account and physical device;
- sender-chain key id; and
- recipient account and physical device.

The shared sender chain and group ciphertext remain unchanged. Origin keys are
never shared with another recipient, included in a group broadcast, exported
in backups, or reused after membership/device/session reset.

The recipient knows its own origin key and can fabricate a transcript addressed
only to itself. It cannot forge the same sender to another recipient. This
preserves the ordinary deniability property that a receiver cannot
cryptographically prove its own transcript while preventing one malicious
member from changing honest members' group state as somebody else.

### 2. Every per-recipient envelope authenticates the shared ciphertext

For each existing recipient-scoped envelope, the sender computes:

```text
origin_tag = HMAC-SHA-256(
    origin_key,
    "Komms-Group-Origin-v1" ||
    group_id ||
    sender_account ||
    sender_device ||
    recipient_account ||
    recipient_device ||
    sender_chain_key_id ||
    envelope_content_id ||
    authenticated_retention ||
    SHA-256(shared_group_ciphertext)
)
```

The exact fixed-width encoding is versioned and contains no ambiguous
concatenation. The wire body is a bounded wrapper containing the shared group
ciphertext and 32-byte tag. The group id and identities remain inside
authenticated calculations; they are not added as plaintext routing metadata.

The receiver first maps the delivery token to one pairwise sender device, opens
the group header without advancing a chain, selects the exact receiving chain
and origin key, verifies the tag in constant time, and only then advances and
decrypts the sender chain. Unknown keys are retryable while an authenticated
announce may still be in flight. A bad tag, wrong recipient/device, replay, or
identity mismatch is a terminal invalid envelope and never mutates group state.

### 3. Author-sensitive content requires origin authentication

Text and attachments use the same authenticated wrapper for one uniform group
path. Edits, polls/votes, expiry events, role/admin requests, moderation,
ownership operations, and device-sync imports additionally refuse legacy
membership-authenticated group messages.

The stored author is taken only from the verified pairwise device certificate,
never from a plaintext content field, sender-chain key id, delivery token
alone, petname, or group roster position.

### 4. Rotation and removal erase origin capability

Sender-chain rotation creates fresh per-recipient origin keys. Removing an
account or device deletes its outgoing key at senders and its incoming keys at
the removed device's honest local state. Surviving members rotate their sender
chains and origin keys under the same generation transition.

A removed or compromised member may retain old group and origin keys it already
saw. Generation, chain-id, roster, recipient-device, and replay binding prevent
those keys from authenticating new-generation traffic.

### 5. Existing alpha groups upgrade visibly

The sender-key announce and group-message wrapper receive explicit new
versions. Existing groups enter a bounded “security upgrade required” state:
all active members redistribute fresh chains and origin keys before new
author-sensitive content is accepted.

Legacy messages remain readable as historical membership-authenticated content
and are labelled accurately. They are never rewritten to appear
individually origin-authenticated after the fact.

## Alternatives considered

### Keep delivery-token matching as the author check

Rejected. A delivery token is observable routing data and was not designed to
prove that the member holding a shared sender chain created a ciphertext.

### Add an Ed25519 signature to every group message

Rejected for this profile. It is compact and publicly verifiable, but creates a
transferable sender proof for every ordinary message. Recipient-specific MACs
fit the existing per-recipient envelope fan-out and retain receiver
deniability.

### Encrypt the complete message separately for every recipient

Rejected. It discards the sender-key bandwidth benefit and multiplies group
encryption and radio payload cost. This decision adds only one bounded tag to
each envelope while retaining one shared ciphertext.

### Keep membership-level authenticity but disable polls and edits

Rejected. It removes useful everyday features without repairing misleading
ordinary message authorship.

### Move all current groups directly to MLS

Deferred. MLS is the preferred standards path for larger and more dynamic
groups, but a constrained multipath/radio profile and migration require
separate interoperability work. Current small groups still need honest author
authentication.

## Consequences

- A group ciphertext is still produced once, then wrapped with one 32-byte tag
  per recipient envelope.
- Group announce state grows by one 32-byte secret per sender-chain/recipient
  device pair and must stay within existing group/device bounds.
- Recipients can forge their own local transcripts, but cannot forge another
  member's vote/edit/message to honest third-party recipients.
- Device identity becomes part of group author verification and must follow the
  revocable authority model in ADR-0026.
- Codec, fuzz, reorder, malicious-member, shared-mesh, device-removal, and
  legacy-upgrade tests are release requirements.
