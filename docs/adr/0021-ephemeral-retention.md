# ADR-0021: Authenticated ephemeral retention and local deletion

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

“Disappearing” combines three different promises that cannot honestly be
implemented by one UI timer: removal of local plaintext, shortened retention of
undelivered sealed envelopes, and first-open consumption of local media. A
relay cannot read an encrypted deadline or authenticate a sender. A recipient,
relay operator, linked device, backup holder, or screen-capture tool can retain
copies outside Komms. The protocol must still converge across offline delivery,
clock skew, reordering, restart, backup, and sender-key fan-out without reviving
content after its local promise has become terminal.

## Decision

Komms exposes two content modes under content-v1 kind `0x0005`:

- **Disappearing text** is removed from this installation’s sealed history at
  an exact authenticated Unix-seconds deadline.
- **View-once attachment** is made permanently unavailable on this installation
  before the first plaintext byte is emitted to a protected presentation
  handle, or at its exact fallback deadline if never opened.

These are local lifecycle controls, not remote erasure, screenshot prevention,
or proof that an intermediary deleted every copy.

### Canonical payload

All integers are little-endian. The common content header carries the random
author-minted content id. The kind-`0x0005` payload is:

```text
version(1)              # 1
mode(1)                 # 1 disappearing text; 2 view-once attachment
reserved(2)             # zero
expires_at(8)           # exact local deadline
retention_until(8)      # ceil(expires_at / 3600) * 3600
body_len(4)
body(body_len)          # exact UTF-8 or canonical ADR-0015 manifest
```

The payload consumes the frame. Empty disappearing text, invalid UTF-8,
non-zero reserved bytes, unknown mode/version, noncanonical lengths, trailing
bytes, overflow, malformed manifests, and a retention value not equal to the
canonical hour ceiling fail closed. Local sends accept lifetimes from 60 seconds
through 30 days. The recipient’s own clock applies the exact deadline; content
received at or after it creates only a tombstone. Clock skew can therefore make
one device expire earlier or later in wall-clock terms, which is preferable to
trusting an unauthenticated sender clock correction.

### Envelope v2 and relay behavior

Envelope v1 remains byte-for-byte decodable. Envelope v2 is:

```text
version=2(1) || kind(1) || delivery_token(32)
  || retention_until(8) || ciphertext_body
```

The hint must be non-zero and hour-aligned. A recipient accepts ephemeral
content only when the clear v2 hint exactly equals the value authenticated
inside decrypted content; v1 ephemeral content, v2 ordinary content, and a
mismatch are discarded. Fragments inherit the same v2 hint, including selective
retransmissions. A mailbox or bridge retains a v2 envelope only until the
minimum of its own maximum TTL and the hint. Already-expired deposits are
accepted-and-discarded so retries cannot extend retention. Restart, capacity
eviction, relay policy, or operator action may delete earlier.

The hour bucket reveals that the envelope requests shortened retention and an
upper-bound deletion hour. Tokens, ciphertext, padding, and routing otherwise
remain unchanged. Relays cannot authenticate the sender, so the hint is only a
deletion instruction: it grants no authority, cannot extend relay policy, and
does not prove deletion. A malicious relay can retain a copy indefinitely.

### Local storage, tombstones, and ordering

Every accepted or locally authored ephemeral id receives a sealed marker keyed
inside ciphertext by exact conversation, author, and content id. The marker
holds the exact deadline, mode, state (`Active`, `Consumed`, or `Expired`), and
active local media-transfer ids. SQLite columns expose only a random row order
and sealed blobs.

Expiry processing runs before scheduling, receive activation, attachment work,
or queue flush. It durably changes the marker to a terminal tombstone first,
then deletes the pairwise/group plaintext row, associated outbound envelopes,
media metadata, and unreferenced sealed chunk files. First-open consumption
also writes the terminal tombstone before streaming and removes sources even if
the destination write fails. A crash between tombstoning and physical cleanup
cannot reopen content; cleanup resumes on the next tick.

An original arriving after an `Expired`/`Consumed` marker is acknowledged but
never stored. Duplicates cannot rehydrate it. Edits cannot target ephemeral
content. Quotes and replies are not yet a shipped structured content type; a
future design must render a non-plaintext expired placeholder rather than copy
ephemeral text into permanent content.

### Backup and linked-device behavior

`KKR5` added sealed ephemeral tombstones and current `KKR7` preserves that
contract. Backups exclude all ephemeral
plaintext and media, including content still live at export time, and convert
exported active markers to terminal tombstones with transfer ids removed.
`KKR1` through `KKR6` remain restorable. A restore therefore never resurrects
an erasure promise.

Each linked installation applies the authenticated deadline and first-open rule
to its own local copy. First open is per installation, not a synchronized claim
that every device or recipient deleted. Shipped C2 linked-device sync carries
tombstones but not active ephemeral content; an active copy may disappear earlier after receiving one, never
later or by resurrecting plaintext.

### Capability and compatibility

Pairwise send requires a live session and authenticated `(content v1,
0x0005)` support. Group send requires every current co-member to advertise the
kind. Anonymous first flights never carry ephemeral content. Existing clients
continue decoding envelope v1 and never receive kind `0x0005` through the
supported send path; unexpected typed content remains unsupported, never
guessed as text. Raw send/schedule APIs reject pre-encoded ephemeral frames.

## Alternatives considered

- **Encrypted deadline only.** Rejected because a relay cannot act before the
  recipient decrypts.
- **Exact clear deadline.** Rejected because minute/second precision leaks more
  timing metadata without improving the local promise.
- **Unlinkable expiry tokens and a later revocation list.** Rejected for this
  slice because offline relays need another authenticated distribution plane,
  retain state longer, and still cannot prove deletion.
- **UI-only timer or deleting only a message row.** Rejected because queues,
  backups, restarts, fragments, and sealed media would revive content.
- **Remote delete command.** Rejected as erasure theater; recipients control
  their devices and can capture plaintext.
- **Consume after successful rendering.** Rejected because a crash after
  plaintext exposure but before state commit would permit a second open.

## Consequences

Envelope v2 and the new content kind require golden, property, arbitrary-input,
fragment, mailbox, bridge, restart, backup, and cross-surface parity tests.
Relays learn one coarse retention bucket for ephemeral traffic. Backups trade
live ephemeral history for a strict no-resurrection rule. Product copy must say
“removed from this device” and “view once on this device,” and must explicitly
say recipients, linked devices, operating systems, cameras, and relays may keep
copies.
