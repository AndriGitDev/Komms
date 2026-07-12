# ADR-0009 — Internet↔mesh bridging as token-blind transit forwarding

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

[05 — Transports §4.2 rule 5](../05-transports.md) specifies that any Komms node
attached to both the LoRa mesh and the internet acts as a store-and-forward bridge in
both directions — the "village with one Starlink terminal" property, and the escape
hatch for mesh partitions in the threat model (A4). The rule says *that* bridging
happens; it does not say *how* a bridge recognizes third-party traffic or where it
forwards traffic to, and both questions collide with deliberate design constraints:

- **Sealed sender**: an envelope reveals nothing but a rotating 32-byte delivery token.
  A bridge cannot learn who a foreign envelope is for, so it can never look up the
  recipient's published hints or route toward them.
- **The mailbox contract** ([ADR-0007](0007-recipient-scoped-delivery-tokens.md)):
  a relay accepts a deposit only for a *registered* token. A mesh-only recipient can
  never register over libp2p, so internet-side senders' deposits for it would be
  refused at every relay — including at the bridge itself.
- **Airtime scarcity**: anything a bridge floods onto the mesh spends the scarcest
  budget in the system, and bridging must not let internet-side strangers spend it
  without bound.

## Decision

Bridging is **token-blind transit forwarding**, an opt-in policy of the delivery
engine plus one relaxation of the mailbox accept rule, both bounded:

1. **Foreignness is decided by token alone.** An envelope whose delivery token matches
   none of the bridge's own session tokens and none of its own introduction tokens
   (over the same epoch windows the receive path uses) is transit. The bridge learns
   nothing else and needs nothing else.
2. **Mesh → internet**: foreign envelopes heard on an airtime-class carrier enter a
   bounded in-memory transit queue and are offered as ordinary mailbox **deposits** to
   the bridge's configured relay set (its own mailbox service included, deposited
   locally without a self-dial). A relay accepts exactly when the recipient registered
   that token there — the registration *is* the routing table, and refusals are cheap
   and honest. Deposits retry with backoff a bounded number of times, then drop; the
   sender's end-to-end retry and receipt machinery remains the source of reliability.
3. **Internet → mesh**: a bridge's mailbox service accepts deposits for *unregistered*
   tokens into a separate bounded buffer instead of refusing them, and the delivery
   engine floods each buffered envelope on its broadcast (mesh) carriers — after its
   own queue, under the normal duty-cycle budget, re-flooding a fixed small number of
   times spaced exponentially (there is no feedback channel: receipts are end-to-end
   and opaque to the bridge). Recipients pick their traffic out of the flood by token,
   exactly as with any mesh traffic.
4. **Loop safety**: transit is deduplicated by envelope content id, never re-forwarded
   onto the carrier class it arrived from (split horizon), and every queue/buffer is
   capped in items, bytes, per-envelope size (the 4 KiB airtime ceiling), and TTL.

The relaxation in (3) applies only to a node that explicitly enables bridging; the
plain mailbox contract is unchanged everywhere else. Everything the bridge handles is
a sealed envelope plus a rotating token — the same view any relay already has.

## Alternatives considered

- **Route by recipient**: have mesh envelopes carry the recipient's relay hints so the
  bridge can deposit precisely. Rejected: it puts routing metadata (a stable relay
  choice) on the air next to every message, exactly the linkability the token design
  exists to prevent, and it changes the envelope wire format.
- **Mesh-side mailbox registration**: let mesh recipients register token filters at
  the bridge over LoRa, keeping the strict accept rule. Rejected for now: it needs a
  new authenticated wire exchange (registrations must be unforgeable or they become a
  denial-of-service vector), costs airtime of its own, and still requires the
  unregistered-deposit path for the *internet→mesh* direction bootstrap (a recipient
  that never met the bridge). The bounded-flood design needs neither.
- **Bridge as decrypting proxy**: obviously never — the bridge is untrusted by
  construction and must stay so.
- **Selective retransmission across the bridge**: the bridge fragments oversized
  internet-origin envelopes for the mesh, but NACKs are end-to-end encrypted and name
  the *original sender*, who never fragmented anything. Serving NACKs at the bridge
  would require it to read receipts. Bounded blind re-flooding was chosen instead;
  revisit if real meshes show it wasting airtime or dropping too much.

## Consequences

- A village mesh gains asynchronous global reach through any single volunteer with
  both carriers, with zero configuration on the mesh side and ordinary mailbox
  check-ins on the internet side.
- Internal mesh chatter that no internet relay recognizes costs the bridge a bounded
  number of refused deposits per envelope — accepted as the price of token blindness.
- Anyone who can reach a bridge's mailbox port can make it spend mesh airtime, bounded
  by the transit caps, the flood-count limit, and the duty-cycle budget (the bridge's
  own traffic always flushes first). Operators opt in (`kultd` enables bridging only
  when a radio is attached; `--no-bridge` opts out).
- Delivery through a bridge is best-effort per envelope; reliability continues to rest
  on end-to-end receipts and sender retries. If field use shows blind re-flooding is
  not enough, mesh-side registration (alternative 2) is the natural upgrade and would
  supersede parts of this ADR.
