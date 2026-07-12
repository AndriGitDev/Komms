# ADR-0007 — Recipient-scoped delivery tokens

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

[04 — Cryptography §7](../04-cryptography.md) originally defined one delivery-token
sequence per contact pair: `token_i = HMAC-SHA-256(K_mailbox, epoch_i)`. Both directions
of a conversation shared it — A→B and B→A envelopes carry the same token in any given
epoch.

M3's mailbox relays make that a correctness bug. A relay mailbox is collect-and-delete:
the recipient checks in, the relay hands over everything queued under the recipient's
tokens and deletes it (a volunteer node cannot retain unbounded mail, so "keep until
TTL and redeliver forever" is not an option). If both parties of a pair pick the same
relay — likely, since relays are a small set of community nodes — a shared token
sequence means A's check-in drains envelopes deposited *for B*. A cannot tell an echo of
her own mail from mail addressed to her until decryption fails, and by then the relay
has already deleted the only copy. Silent message loss, violating the delivery engine's
"never lost, never faked" contract.

## Decision

Bind the addressee into the token:
`token_i = HMAC-SHA-256(K_mailbox, "KK-token-v1" ‖ epoch_i ‖ IK_recipient^Ed25519)`.
Each pair now has two disjoint token sequences, one per direction; a node's check-in
filter set (built only from tokens where *it* is the recipient) can never match mail
addressed to its peer. Introduction tokens were already recipient-scoped.

## Alternatives considered

- **Non-destructive collect (TTL-only deletion).** Fixes the loss but forces the relay
  to store every envelope for the full TTL (~30 days) and redeliver it on every
  check-in; any cap-based eviction under that load reintroduces exactly the loss this
  ADR removes. Volunteer relays need deposits to leave when collected.
- **Recipient acks driving relay deletion.** Only the true addressee can distinguish
  its mail, so envelopes collected by the wrong party must be re-served until the right
  one acks — which is non-destructive collect again, plus ack plumbing through the
  transport contract.
- **Direction byte from the session role (initiator/responder).** Equivalent outcome,
  but requires exposing the ratchet role from `kult-crypto`; the recipient identity key
  is already at every call site and matches how introduction tokens are scoped.

## Consequences

- Shared relays are safe: a check-in drains only mail addressed to the checker.
- Unlinkability is unchanged: HMAC is keyed by the secret `K_mailbox`, so outputs are
  pseudorandom to anyone else regardless of the public input added.
- A sender no longer recognizes multipath echoes of its own envelopes (the token now
  matches only at the recipient); echoes stash as pending and expire instead of being
  consumed by a failed decrypt. Harmless either way.
- No migration: nothing is deployed. Spec §7 and `kult-protocol::delivery_token` change
  together in the PR that lands this ADR.
