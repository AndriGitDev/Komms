# ADR-0023: Owner-serialized group roles and generation-bound administration

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

ADR-0012 deliberately gave one creator exclusive authority over group name,
roster, and secrets. C6 must delegate useful administration without turning the
roster into an arrival-order CRDT, letting an offline former admin act after
revocation, or weakening the mandatory re-key on membership and authority
changes. Group traffic may be delayed, duplicated, reordered, or partitioned;
there is no server that can serialize competing mutations.

Komms also has two distinct authenticity properties. Sender-key message
authentication is membership-level and deliberately deniable, while pairwise
ratchet controls identify the exact peer at an endpoint. Durable authority must
remain verifiable after forwarding, restart, and backup, so role state and
administrative requests require identity signatures in addition to transport
authentication.

## Decision

### Roles and capabilities

Each group has exactly one `owner` and zero or more `admin` and `member`
entries. This is a fixed role model, not a policy language.

| Operation | Owner | Admin | Member |
|---|---:|---:|---:|
| invite a stored/identified peer | yes | signed request to owner | no |
| remove an ordinary member | yes | signed request to owner | no |
| rename the group | yes | signed request to owner | no |
| close any group poll as moderator | yes | signed request to owner | no |
| grant or revoke admin | yes | no | no |
| transfer ownership | yes | no | no |
| remove an admin | yes | no | no |

An admin request is useful while the owner is temporarily offline: it queues
over the existing pairwise ratchet and is applied when the owner receives it.
The owner remains the sole state sequencer. This intentionally chooses a
smaller, auditable delegation model over multi-writer membership.

The owner cannot leave, remove itself, or be demoted. Ownership must first be
transferred to an existing member. Transfer makes the previous owner an admin,
so the group always has exactly one owner and never crosses a last-owner state.

### Signed authority state

The first C6 operation upgrades a legacy creator-managed group only when every
current co-member advertises content-v1 kind `0x0007`. The original creator
becomes owner; everyone else begins as member. Legacy groups remain valid and
creator-managed until that explicit capability-gated upgrade.

Every committed authority state contains:

```text
group_id || generation || owner_epoch || original_owner || current_owner
signer || prior_state_id || name || sorted roster(identity, role)
SHA-256(group_secret) || ordered owner-transfer certificates
```

The current owner signs the canonical bounded encoding under the
`Komms-group-authority-state-v1` domain, except that the prior owner signs the
state which enacts an ownership transfer. Subsequent states are signed by the
new current owner. Content-v1 kind `0x0007` carries the signed public state as
an immutable group event; it is retained for audit and backup but rendered as
a role/update card rather than a chat bubble. A v2 pairwise authority announce
carries the same state, signature, current secret, and sender-chain snapshot to
each entitled member. The secret hash binds the public event and private
announce without revealing the secret in group history.

Ownership transfer adds a certificate:

```text
group_id || next_owner_epoch || transfer_generation || prior_state_id
from_owner || to_owner
```

signed by `from_owner` under
`Komms-group-owner-transfer-v1`. The ordered transfer chain starts at the
original creator and must advance one epoch at a time. A self-contained
authority announce includes that chain, so a member or new invitee can verify
the current owner even after missing earlier group history. Binding the exact
generation and winning prior-state id limits the prior owner's state signature
to the one transition that enacts the transfer; every later state must be signed
by the new owner. If authenticated states contain conflicting transfer chains
at the same owner epoch and
generation, the smallest authority-state event id wins. A chain rooted in the
losing state cannot advance an already accepted replica.

For one owner epoch, a state is accepted only at a greater generation. If an
owner equivocates at the same generation, the smallest authenticated state
event id wins. Honest implementations issue one state per generation and bind
the next state to the winning prior state id. This deterministic rule is a
convergence backstop, not a fairness claim about a malicious owner.

### Admin requests and stale authority

An admin request contains a random request id, group id, exact base generation,
one bounded operation, and the requesting identity's domain-separated
signature. It travels only as pairwise `GroupControl` to the current owner and
never carries a secret. The owner accepts it only when:

- the signature verifies against the authenticated sender;
- the sender is an admin in the current signed state;
- the base generation exactly equals the current generation;
- the requested target and operation satisfy the fixed role table; and
- the request id has not already been consumed.

The owner then emits the same signed full-state transition used by a direct
owner action. Concurrent requests for one generation are serialized by the one
owner; after the first accepted transition advances the generation, remaining
requests at the old generation are stale terminal no-ops. A pairwise
ratchet-authenticated result is returned to the requester for honest UI status;
the signed public authority state remains the durable source of truth. Removed
or demoted devices therefore cannot retain future authority, even if their old
request arrives later.

### Rotation and removal

Every accepted rename, role change, ownership transfer, addition, removal, or
moderated poll closure advances the authority generation. Membership, role, and
ownership changes mint a fresh group secret and rotate every remaining
sender-chain; rename also rotates so a stale authority snapshot can never be
mistaken for current entitlement. The previous header secret remains only one
generation deep for in-flight traffic, as in ADR-0012.

An excluded member receives a self-contained signed removal notice with the
owner transfer chain and new public state but never the new secret. Reordered
transfer/removal delivery is therefore verifiable. Stale announces, requests,
and removal notices cannot regress a newer generation or owner epoch.

### Poll moderation

Ordinary poll closure remains creator-authored under ADR-0022. An admin may
request moderation; the owner emits a separately typed owner-signed moderation
closure containing the exact group id, poll author/id target, authority
generation, and final visible vote-head snapshot, signed under
`Komms-group-poll-moderation-v1`. Poll resolution accepts it only
when the signature matches the owner in the referenced valid authority
generation. The UI identifies it as owner moderation, never as the poll
creator's action.

### Bounds, compatibility, and recovery

Groups remain capped at 64 members. Names, identities, transfer chains,
requests, roles, and signatures have explicit decoder bounds; canonical role
state is sorted by peer id with one entry per roster member. Unknown authority
versions remain unsupported and malformed/trailing/noncanonical encodings fail
closed. Generic raw group or pairwise send APIs reject canonical kind `0x0007`.

`KKR6` adds the sealed authority record, owner-transfer chain, consumed request
ids, and authority events. `KKR1`–`KKR5` remain restorable as legacy
creator-managed groups. Sender chains are still never backed up. The authority
table is sealed under the existing group-storage key and adds no public index,
transport header, DHT record, delivery token, or relay-visible field.

## Alternatives considered

- **Admins directly mutate replicated state.** Rejected for C6 because
  concurrent offline changes require a retained event DAG, rollback/replay,
  and selective-secret-distribution semantics approaching MLS.
- **Arrival order chooses concurrent admin changes.** Rejected because
  replicas would diverge after partitions.
- **Unsigned role fields in ordinary announces.** Rejected because any member
  can redistribute sender chains and authority must survive forwarding and
  backup independently of one pairwise session.
- **Multiple owners.** Rejected for the minimal model because last-owner and
  conflicting-transfer rules become materially harder without adding a needed
  product capability.
- **A generic capability expression language.** Rejected as unnecessary attack
  surface; the three fixed roles and table are inspectable in every shell.

## Consequences

Administration remains sovereign and delay-tolerant but not owner-independent:
an admin's request waits until the owner is reachable. A compromised owner can
still remove members, appoint admins, transfer ownership, rename, or moderate a
poll; signatures provide attribution and deterministic state, not protection
from the legitimate authority key. A removed endpoint retains old plaintext
and ciphertext it already held but cannot decrypt or authorize future state.

Release acceptance covers signature and bound failures, stale/deduplicated
requests, concurrent admin requests, owner transfer and conflicting transfer
certificates, last-owner safeguards, offline delivery, removal/exclusion,
mandatory rotation, poll moderation, deterministic reorder convergence,
`KKR1`–`KKR6`, RPC/CLI, UniFFI, and accessible desktop/Android/iOS role controls.
