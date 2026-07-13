# ADR-0012: Sender-key groups v1: encrypted headers, creator-managed membership, announce-until-acked

- **Status**: Accepted
- **Date**: 2026-07-13

## Context

The crypto spec (04 §6) and architecture (03 §6) fix the v1 group model:
per-member **sender keys** (a forward-ratcheting chain per sender per group),
distributed over the existing pairwise Double Ratchet sessions, with each
group message encrypted **once** and fanned out: one ciphertext, not N, which
is what makes groups affordable over LoRa. The spec deliberately leaves the
concrete wire format, membership semantics, and distribution reliability
undefined. Implementing them forces five shape decisions:

- **What do intermediaries see?** A naive sender-key header (key id +
  iteration in the clear) lets every relay and mesh bystander link all of one
  sender's group traffic across token rotations: exactly what sealed sender
  (04 §7) exists to prevent.
- **Who manages membership?** Signal-style anarchic groups (anyone updates
  membership, clients converge) need conflict resolution machinery far beyond
  v1's "≤ 64 members" ambition.
- **How does a sender key reliably reach every member** over carriers that
  lose whole envelopes (mesh, couriers)? A member missing one distribution
  message is deaf to that sender forever.
- **What happens on restore from backup?** Chains are session-class state:
  exporting them has the same replay/fork hazards ADR-0011 rejected for
  ratchets.
- **How is a group message authenticated?** The spec pins an "Ed25519-free
  MAC scheme": no signatures.

## Decision

**Chains** (`kult-crypto::group`): per group each member holds a sending
chain `(key_id: 16 random bytes, chain_key: 32, iteration: u32)`;
`ck' = HKDF(ck, "KK-group-chain")`, `mk = HKDF(ck, "KK-group-msg")`: the
same shape as the pairwise symmetric ratchet, with the same delay-tolerance
bounds (`MAX_SKIP` 1000, stored-skipped cap 2000 LRU, TTL 30 days) per
receiving chain. There is no DH step: forward secrecy per sender comes from
the chain, post-compromise security from rotation (below).

**Wire format** (`EnvelopeKind::GroupMessage`, body):
`version(1) ‖ enc_header(60) ‖ nonce(24) ‖ ct`. The header,
`key_id(16) ‖ iteration(4 LE)`, is AEAD-sealed under a **group header key**
`K_hdr = HKDF(group_secret, "KK-group-hdr")` known only to members, so
intermediaries see uniformly random bytes; the payload is
XChaCha20-Poly1305 under the message key with the group id, protocol
version, and sealed header bound as associated data. Plaintexts ride the
standard padding buckets. Delivery reuses the pairwise machinery unchanged:
the one ciphertext is fanned out in per-member envelopes addressed by each
pair's rotating delivery token, so relays, mailboxes, receipts, NACKs, and
bridging all work on group traffic without knowing it is group traffic.

**Membership** is creator-managed: the member who created the group is the
only one who may add, remove, or re-key it, and membership updates carry a
monotonic generation counter so stale updates can never regress the roster.
Every control message travels end-to-end encrypted over the pairwise
ratchets (`EnvelopeKind::GroupControl`) in one self-contained shape: an
**announce** carrying the group state (name, creator, roster with member
identities, group secret, generation) plus the sender's current chain
snapshot. Receivers honor the roster/secret/generation part only from the
recorded creator; the sender-key part from any current member. One shape
means invites, adds, removals, rotations, and redistributions are all the
same message, and receiving any one of them is sufficient context to start
decrypting its sender.

**Reliability**: each pending announce is tracked per (group, member) with
the chain snapshot **frozen at entitlement time** (join, add, rotation):
never the live chain, so a member served late can still read every message
sent since they became entitled. Announces re-send on a slow end-to-end
timer until the ordinary encrypted receipt acknowledges the envelope; group
messages fanned out to a member whose session does not exist yet keep their
per-member `Queued` state (with the ciphertext retained) and go out when the
session appears. Group envelopes whose sender chain is not yet known stash
in the existing pending store: "announce still in flight" and "handshake
still in flight" are the same situation and get the same cure.

**Rotation** (fresh chain, new key_id, announces to the full roster):
triggered by member removal or leave (spec: remaining members rotate), by a
message-count threshold (PCS), by restore from backup, and (as a
redistribution of the *current* chain, not a rotation) whenever a pairwise
session with a co-member is re-established (their device may have restored
and lost every receiving chain). On removal the creator also mints a fresh
group secret; the previous one is kept for header-decrypting in-flight
traffic, one generation deep.

**Backup** (format `KKR2`; `KKR1` files still restore): carries each group's
identity (id, name, creator, roster, secret, generation) and the group
message history, but never chains, mirroring ADR-0011: a restored node mints
a fresh sending chain and announces it, and co-members redistribute theirs
over the re-handshaken sessions.

## Alternatives considered

- **Cleartext key id + iteration in the group header** (Signal's
  SenderKeyMessage shape): rejected: Signal wraps its group messages in
  per-recipient sealed sender, so its header is never intermediary-visible;
  ours would be. One static id would undo the daily token rotation for group
  traffic.
- **Per-member re-encryption of group messages** (no shared ciphertext):
  rejected by the spec: N ciphertexts is exactly what sender keys exist to
  avoid on airtime-budgeted links.
- **A shared group delivery token** so one mesh broadcast serves all
  members: rejected for v1: collect-and-delete mailboxes break (the first
  collector drains everyone's copy; recipient-scoped tokens are ADR-0007's
  whole point). Worth revisiting as a mesh-only optimization once the HIL
  bench can measure it.
- **Signed sender keys** (Ed25519 per chain, Signal-style): rejected: the
  spec pins the Ed25519-free construction; within a ≤ 64-member group,
  members are trusted not to forge each other, and the omission preserves
  deniability. The consequence is stated plainly below.
- **Anarchic membership with convergence** (any member updates the roster):
  rejected for v1: concurrent adds/removes need causal ordering or CRDT
  semantics; a single writer plus a generation counter is verifiably
  monotone. MLS (RFC 9420) is the documented successor for large groups.
- **Exporting chains in backups**: rejected for the same reasons ADR-0011
  refused to export ratchets: restored chain state forks the moment either
  copy advances.

## Consequences

- Any group member can forge messages *as any other member of that group*
  (they hold the same chain keys). This is the documented trade of the
  signature-free design: group authenticity is membership-level, not
  member-level. Pairwise conversations are unaffected.
- Sender keys require **pairwise reachability**: two members who share a
  group but no prekey path (no bundle, no DHT, no common carrier) cannot
  read each other until one appears. The creator always has bundles for
  everyone (adding requires a stored contact), so the roster's identities
  travel in the announce and the DHT resolves the rest where internet
  exists; on pure sneakernet the members swap bundles the same way they met
  the creator. No relaying re-encryption is possible or attempted.
- A fan-out burst is linkable *as a burst* by an observer who sees several
  envelopes with identical bodies; sender and recipients stay sealed. The
  per-member-re-encryption alternative that would hide this was rejected
  above; the residual risk joins the transport-metadata table (02 §6).
- The removed-member window is honest: whoever held the group secret can
  header-decrypt (but never read) traffic sealed under it until the creator's
  re-key propagates; payload keys rotate immediately with the chains.
- The store's outbound queue gains group routing context, and `KKR1` backups
  restore without groups: both pre-release formats, both versioned.
