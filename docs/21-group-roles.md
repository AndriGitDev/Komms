# Group Roles, Ownership, and Moderation

C6 adds private, cryptographically attributable group administration without a
server. It is shipped through `kult-node`, RPC/CLI, UniFFI, desktop, Android,
and iOS. [ADR-0023](adr/0023-group-roles-and-owner-authority.md) is the normative
decision; this document is the product and operator contract.

## Role model

Every upgraded group has exactly one owner and any number of admins and members.
The owner can invite or remove any non-owner, rename the group, grant or revoke
admin, transfer ownership, and moderate a poll. An admin can request an invite,
ordinary-member removal, rename, or poll moderation. A member has no
administrative capability.

Admins do not become independent state writers. Their signed request is bound to
the exact current authority generation and travels over the pairwise ratchet to
the owner. The owner remains the sole sequencer, so concurrent requests converge:
the first valid request advances the generation and the rest become stale
terminal results. The UI reports acceptance or rejection without treating that
pairwise result as durable group state.

The owner cannot leave, remove itself, or be demoted. Ownership must first be
transferred to an existing member. The previous owner becomes an admin, keeping
the group at exactly one owner.

## Signed authority state

Legacy groups remain creator-managed until the creator explicitly upgrades them.
Upgrade is refused unless every current co-member has authenticated support for
content-v1 kind 7. The initial signed state makes the creator owner and every
other participant a member.

Each immutable authority event contains the group, generation, owner epoch,
original and current owners, authorizing signer, prior state id, exact name,
sorted full roster and roles, the current secret hash, and the ordered ownership
transfer certificates. The authorizing identity signs the canonical bounded
encoding under `Komms-group-authority-state-v1`. The prior owner signs the state
that transfers ownership; the new owner signs subsequent states.

Each transfer certificate advances one epoch, links the previous owner to an
existing new owner, binds the exact transfer generation and winning prior-state
id, and is signed under `Komms-group-owner-transfer-v1`. The prior owner's
special state signature is valid only for that exact transfer transition; every
later state requires the new owner's signature. A self-contained announce
carries the full certificate chain. A same-generation
equivocation resolves to the smallest authenticated authority event id; a later
state rooted in the losing transfer chain cannot advance an accepted replica.

Public group history contains only signed authority state and a hash of the
current secret. The current secret and sender-chain snapshot travel separately
inside authenticated pairwise controls to entitled members. Generic raw send
APIs cannot inject kind 7.

## Rotation and exclusion

Upgrade, rename, role change, transfer, membership change, and moderated poll
closure all advance the authority generation and rotate the group secret and
sender chains. Only one previous header secret is retained for in-flight traffic.
A removed member gets a signed removal state but never the new secret.

Delayed, duplicated, or reordered requests and announcements cannot regress a
newer generation. Demoted or removed admins cannot exercise an old request after
the generation changes. A restored node receives fresh sender chains rather than
portable live chain state.

## Poll moderation

Ordinary closure remains the poll creator's visible vote-head snapshot. Owner
moderation is a distinct operation. An admin may request it, but the owner
sequences the authority generation and emits the closure. The exact group id,
poll author/id target, authority generation, and final visible vote heads are
signed under `Komms-group-poll-moderation-v1`.

Resolution accepts moderation only when the signature matches the owner in the
referenced valid authority generation. Every shell labels the result as owner
moderation, includes the moderator identity, and never attributes it to the poll
creator.

## Storage and backup

The winning authority payload, event id, and bounded consumed-request ids live in
a separately sealed `group_authority` record. This preserves legacy group-record
encoding and adds no public database index or transport metadata.

`KKR6` introduced signed authority records and consumed request ids; current
`KKR7` carries them forward with linked-device recovery state, while continuing KKR5's terminal ephemeral
tombstones and exclusion of live ephemeral plaintext/media. `KKR1` through
`KKR5` remain restorable as legacy creator-managed groups. Sender and receiver
chains are never portable.

## Interface behavior

RPC/CLI and UniFFI expose typed authority reads, upgrade, rename, role change,
ownership transfer, and moderation operations. Authority-update and admin-result
events tell shells which exact group to refresh; no signature, identity blob,
secret, or chain crosses into ordinary UI models.

Desktop, Android, and iOS member views show the current owner, each role,
generation, and legacy/signed state. Owner-only controls grant/revoke admin and
transfer ownership. Owner and admin controls use the same core paths for rename,
membership, and moderation; an owner cannot leave until transfer succeeds.

## Honest limits

Signatures attribute authority state; they do not constrain a legitimately
compromised or malicious owner. The owner can remove members, appoint admins,
rename, transfer ownership, or close a poll. Admin work waits for the owner to be
reachable. Removed endpoints retain plaintext and ciphertext already received.
There is no server appeal, quorum, generic policy language, hidden moderation,
or claim that owner action is fair.

## Qualification

Local acceptance covers canonical and arbitrary decoding, signature/domain
failure, stale and duplicate requests, concurrent admins, transfer-chain forks,
last-owner refusal, offline delivery, removal and re-keying, signed moderation,
reorder and C2 owned-device convergence, KKR1-KKR7 restore, RPC/CLI, UniFFI, desktop, Android host
core, and iOS host/app builds. Android APK/device execution remains part of the
common deferred SDK/device gate; it does not weaken the implemented Android
surface or shared protocol contract.
