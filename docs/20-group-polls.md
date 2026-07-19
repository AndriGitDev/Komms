# 20: Group Polls

Komms groups support private, encrypted, single-choice polls. “Private” means
the poll travels only inside the sender-key group conversation; it does **not**
mean an anonymous ballot. Every member who has the poll can see who voted and
which choice their current vote selects.

## Product promise

- Any current member can create a poll when every current co-member supports
  polls.
- Creation fixes the exact current roster as the electorate. Later additions
  do not join that poll or receive its historical creation event.
- Each eligible member has one current choice and may change it until closure.
- The poll creator normally closes it. Closure freezes the visible vote
  snapshot the creator has received and cannot be undone. In a C6 signed-role
  group, the current owner may instead commit a separately signed moderation
  snapshot; an admin may request that owner action.
- Duplicate, delayed, and reordered events converge without trusting clocks.
- Poll events are encrypted and padded through the ordinary group path. Relays
  and transports do not learn the question, choices, voters, or tally.
- Polls survive restart and encrypted `KKR7` backup/restore as ordinary sealed
  group history. They do not appear as chat-message bubbles.

This is not a secret ballot, proof of universal participation, or proof that a
creator observed every offline vote before closing. Members can retain or share
anything their device displayed. Removed members keep poll history they already
received, but they receive no future group traffic.

## Deterministic behavior

Poll and option IDs are stable random identifiers. A vote carries a positive
voter-local revision; the greatest `(revision, event id)` is that voter’s head.
The creator’s close event carries the sorted heads it accepted. A moderated
close carries the same exact target and heads plus the authority generation and
current owner's `Komms-group-poll-moderation-v1` signature, binding the group id,
poll author/id, generation, and heads. It is accepted only
against a valid signed authority state. If conflicting valid closures arrive,
the smallest close event ID wins. The tally is always derived locally from
these authenticated immutable events, never from a server or mutable counter.

Limits are deliberately fixed: 1,024 UTF-8 bytes for the question, 2–12
choices, 256 UTF-8 bytes per choice, 64 voters, and 64 locally authored vote
revisions per identity and poll. Exact Unicode is preserved; apps validate byte
limits without trimming or rewriting submitted text.

## Interfaces

The RPC operations are `group_poll_create`, `group_polls`,
`group_poll_vote`, `group_poll_close`, and `group_poll_moderate_close`. The CLI mirrors them as
`group-poll-create`, `group-polls`, `group-poll-vote`, and
`group-poll-close`, plus `group-poll-moderate-close`. Poll, option, author, voter, group, and event identifiers
are explicit; RPC rejects unknown and ambiguous fields.

UniFFI exposes the same create/list/vote/close/moderate calls, `GroupPoll`, `PollOption`,
`PollVote`, and `Event.PollUpdated`. Desktop, Android, and iOS render dedicated
cards with visible tallies and voter names, confirm the non-anonymous vote, and
show creator closure or the exact owner moderator identity. Shells refresh from the node snapshot on events;
they do not resolve votes themselves.

## Compatibility and verification

An authenticated capability intersection blocks typed poll actions if any
current co-member is unknown or old. Generic raw send cannot bypass the gate.
Unknown content remains old-client-safe under the common content framework.

The local acceptance matrix covers canonical and arbitrary-input decoding,
malformed lengths and bounds, duplicate/reordered/changed votes, outsiders,
fixed electorates, removal/addition, conflicting closure, partitions,
cross-node convergence, raw-send refusal, RPC/CLI/UniFFI parity, desktop and
host-mobile bindings, signed owner moderation, exact KKR1–KKR7 restore, and C2
owned-device convergence. Android debug-APK assembly is automated; real-device
poll interaction remains part of the platform release gate.

The normative replicated-state and wire decision is
[ADR-0022](adr/0022-convergent-group-polls.md).
Signed moderation and owner/admin authority are specified separately in
[ADR-0023](adr/0023-group-roles-and-owner-authority.md).
