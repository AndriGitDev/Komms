# ADR-0022: Visible-vote convergent group polls

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

A poll is replicated conversation state, not a mutable server object. Komms has
no authoritative service that can serialize votes, decide who belonged to a
poll, or close it while devices are partitioned. Group history can arrive late,
duplicated, or reordered, and membership may change between creation, voting,
and closure. A design based on timestamps, arrival order, or a mutable tally
would diverge. Calling ordinary authenticated votes anonymous would also be a
false privacy claim.

## Decision

Komms uses content-v1 kind `0x0006` for three immutable sender-key group
events: creation, vote, and manual closure. All integers are little-endian.
Every payload starts with `version(1) || operation(1) || policy/reserved(2)`.

Creation (`operation = 1`) carries:

```text
version=1 || operation=1 || close_policy=1 || reserved=0
group_generation(8) || question_len(2) || option_count(1) || voter_count(1)
question(question_len)
repeated option_id(16) || option_text_len(2) || option_text
repeated sorted voter_peer_id(32)
```

The common content id is the stable poll id. Option ids are random and unique
within the poll; presentation order is the encoded order. The supported local
API snapshots the exact sorted current roster and its generation. The payload
is creator-attested because a receiver cannot reconstruct an old roster after
arbitrary offline membership changes. The authenticated creator must appear in
the electorate.

Vote (`operation = 2`) carries:

```text
version=1 || operation=2 || reserved(2)=0
poll_author(32) || poll_id(16) || option_id(16) || revision(8)
```

The enclosing sender-key event authenticates the voter. A vote is valid only
for a listed electorate member and a stable option id. For each voter, the
current head is the maximum `(revision, vote content id)`. Revisions are
positive; supported local authors increment their own maximum and are capped at
64 vote events per poll. Duplicate and reordered records therefore converge
without clocks. Votes and voter identities are visible to every member that
holds the poll. Polls are single-choice and explicitly **not anonymous**.

Closure (`operation = 3`) carries:

```text
version=1 || operation=3 || reserved(2)=0
poll_author(32) || poll_id(16) || head_count(1) || reserved(3)=0
repeated sorted voter(32) || vote_event_id(16) || option_id(16) || revision(8)
```

Only the authenticated poll creator can close. Closure is an irreversible,
creator-attested snapshot of the visible vote heads the creator accepted at
that moment. This makes the final tally converge even when another replica
never received an underlying vote before a member was removed or a partition
ended. If multiple structurally valid creator closures exist, the smallest
closure content id wins. Closure is not proof that the creator observed every
vote, and no server fairness claim is made.

Question text is exact non-empty UTF-8 up to 1,024 bytes. A poll has 2–12
non-empty exact UTF-8 choices of at most 256 bytes each and 1–64 sorted unique
voters. Reserved bytes, unknown operations or policies, duplicate option ids,
unsorted/duplicate voters, zero revisions, noncanonical lengths, invalid
UTF-8, and trailing bytes fail closed. A future poll payload version is retained
as unsupported rather than treated as malformed. Decoding is allocation-free
and total over arbitrary input.

### Membership, compatibility, and storage

The electorate never changes. A later addition does not gain a vote or receive
historical poll backfill under the existing group-history rule. Removal does
not rewrite a previously accepted or final vote. A removed device retains the
history it already received, just as it retains ordinary group messages.

Typed create/vote/close requires every current co-member to advertise
`(content v1, kind 0x0006)` in authenticated session capabilities. Missing or
old clients block the action before persistence or send. Anonymous first
flights and generic pairwise/group raw-send APIs cannot carry canonical poll
content. Unexpected future or unknown content remains unsupported rather than
being guessed as text.

Poll events remain individually sealed ordinary group-history rows. The node
derives cards, visible vote heads, and tallies on read; it persists no mutable
tally. Current `KKR6` carries those rows unchanged, so restart and restore recompute the
same result without a backup version or database migration.

## Alternatives considered

- **Mutable poll/tally record.** Rejected because arrival order would decide
  state after partitions and restore.
- **Wall-clock last vote wins.** Rejected because clocks are neither trusted
  nor consistently ordered.
- **Current roster defines eligibility.** Rejected because removal would
  rewrite history and additions could vote without receiving creation.
- **Closure marker without vote heads.** Rejected because replicas missing a
  pre-close vote could permanently disagree on the final tally.
- **Anonymous label on authenticated votes.** Rejected as privacy theater. A
  separate cryptographic anonymous-voting protocol would be required.
- **Creator-only private votes.** Rejected for v1 because sender-key fan-out
  delivers the same group event to all current members and the product needs
  an honest, inspectable rule.

## Consequences

Poll creators determine when to close and attest the final observed snapshot;
Komms guarantees deterministic convergence, not election fairness or secret
ballots. The fixed electorate and visible identities must be shown before
creation and voting. Parser fuzzing, changed/duplicate/reordered vote tests,
membership and old-client gates, closure conflicts, KKR6 restore, strict
RPC/CLI, UniFFI, and all shell contracts are release requirements.
