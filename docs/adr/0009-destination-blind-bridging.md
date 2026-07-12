# ADR-0009 — Destination-blind internet↔mesh bridging

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

The transport spec (05 §4.2 rule 5) promises: *any KommsKult node attached to
both the mesh and the internet acts as a store-and-forward bridge in both
directions* — one Starlink terminal gives a whole valley's mesh asynchronous
global reach. The spec names the behavior but not the mechanism, and sealed
sender constrains it hard: a bridge sees only sealed envelopes and rotating
delivery tokens. It can never learn who a message is for, so it can never
*route* — it can only forward blindly and let token recognition happen at
the edges.

## Decision

Bridging is an **opt-in node mode** with an explicit list of **forward
hints** (`DeliveryHint`s), configured by the operator:

1. An inbound envelope that provably isn't ours — a ratchet or fragment
   envelope whose delivery token matches no local session, or a handshake
   flight whose anonymous box we cannot open — is queued for forwarding
   (in addition to the normal early-arrival stash, which still covers our
   own out-of-order traffic).
2. Each queued envelope is sent once to every configured forward hint via
   the ordinary transport scheduler: **mesh broadcast** hints flood the
   radio side (recipients recognize their tokens), **mailbox relay** hints
   deposit on the internet side (the mailbox's accept-filter — tokens the
   recipient registered — decides acceptance). Fragmentation, airtime
   budgets, and the 4 KiB airtime ceiling apply exactly as for our own
   traffic; over-ceiling third-party envelopes are dropped for airtime
   hints rather than held.
3. Each envelope is forwarded **at most once** (content-id set), the queue
   is bounded (drop-oldest), held only in memory, and forwarded traffic
   flushes after the node's own queue. Failed hints retry with the same
   exponential backoff as the delivery engine.

## Alternatives considered

- **Recipient-aware routing** (bridge maps tokens → peers): impossible by
  design — sealed sender exists precisely so relays can't build this map.
- **Re-flooding everything everywhere** (no configuration): simple, but a
  mesh↔mesh pair of bridges would echo traffic and the internet side has
  no broadcast primitive to flood into; explicit hints keep the operator
  in control of where third-party bytes go.
- **Durable bridge spool** (persist forwarded queue): rejected for now —
  end-to-end reliability already comes from sender retry-with-backoff and
  encrypted receipts; bridge durability adds a disk-residency cost for
  other people's traffic with no end-to-end gain.

## Consequences

A village bridge is one daemon flag away. The bridge learns nothing beyond
what any mesh listener already sees (sealed envelopes, token pseudonyms,
sizes, timing). Third-party fragments transit the bridge's reassembler
bookkeeping (bounded, fail-closed) and third-party queue slots are capped,
so a hostile mesh can waste a bridge's airtime allowance but cannot grow
its memory unboundedly or starve its own traffic (own queue flushes
first). Restarting a bridge drops queued third-party envelopes; senders'
retries make this a latency cost, not a loss.
