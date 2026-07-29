# Atomic protocol-transition inventory

**Inventory date:** 2026-07-29

**Scope:** the implemented Alpha paths that overlap the frozen stable-v1
profile, plus every adjacent persisted path found in the `kult-node` →
`kult-store` call graph

**Disposition:** implementation and local test evidence; ADR-0028 remains
Proposed

This inventory is the acceptance checklist for
[ADR-0028](adr/0028-atomic-protocol-commits.md). It distinguishes a complete
typed transition from an adjacent Alpha path that is not yet eligible for
stable-v1. A row marked excluded or open is not evidence of universal protocol
atomicity.

## 1. Transaction contract

The store exposes twenty-three bounded protocol plan kinds. Some retain
explicit legacy profile/migration support; current stable-profile authority
paths use the `Authority*` variants:

| Plan | One logical transition | Principal bound |
|---|---|---|
| `ProfileBootstrap` | Publish one legacy copied-root profile inside an unpublished sibling store | Three exact singleton rows; migration compatibility only |
| `AuthorityProfileBootstrap` | Publish one public account trust anchor, independent `KDA2` device state, and prekey vault inside an unpublished sibling store | Three exact singleton rows; no account root |
| `AuthorityMigration` | Replace one eligible single-device legacy root/profile with its public trust anchor and generation-one `KDA2` state | Exact root/public-authority singleton transition |
| `PrekeyPublish` | Issue one fresh out-of-band one-time-prekey bundle and replace the exact vault that owns it | One exact vault replacement |
| `PairwiseSend` | Advance up to eight device sessions and retain every resulting ciphertext with its history, delivery, schedule, attachment, or control consequence | 8 sessions, 128 queue rows, 512 mutations |
| `PairwiseReceive` | Accept one pairwise plaintext/control and advance its receiving and optional receipt-sending state | 128 queue rows, 512 mutations |
| `HandshakeReceive` | Consume an optional one-time prekey and establish the exact session and accepted first-flight consequence | 8 device records, 128 queue rows, 512 mutations |
| `AdmissionStage` | Consume an optional one-time prekey and seal one verified stranger/session/first-content candidate in the provisional request domain | 32 rows / 512 KiB domain; 4 KiB first content; 2 KiB preview |
| `AdmissionAccept` | Promote one exact provisional request into a contact, session, normal history, delivery and receipt consequence | One request and exact candidate state |
| `AdmissionDiscard` | Delete or block one exact provisional request, retire its provisional keys, and retain only bounded replay/block state | 4,096 replay tombstones; 4,096 block rules |
| `AdmissionSweep` | Expire a bounded page of provisional requests and replay tombstones | 16 expiries per lifecycle tick |
| `ReceiptReceive` | Accept one authenticated receipt/control, advance its session, and apply its exact delivery or deferred-work consequence | 128 queue rows, 512 mutations |
| `GroupSend` | Advance one sender chain or perform one late fan-out and retain all recipient-scoped copies and delivery rows | 64 accounts, 8 devices per account, 512 queue rows, 2,048 mutations |
| `GroupReceive` | Advance one receiver chain and retain the accepted plaintext consequence plus its encrypted receipt | One group chain and one receipt session |
| `GroupState` | Apply one roster, authority, announcement, receiver-chain, removal, or deferred group-control transition | 256 exact mutations |
| `DeviceControl` | Apply the legacy copied-root device-control layout | 8,192 exact mutations; migration compatibility only |
| `AuthorityDeviceControl` | Replace current `KDA2` authority/counters, rotate affected group senders, append/compact convergence events, or transition one root-free link-package recovery handle | 8,192 exact mutations; 4,094 groups per profile |
| `DeviceLink` | Import one legacy copied-root link package onto a pristine target | 8,192 imported records; migration compatibility only |
| `AuthorityDeviceLink` | Atomically switch one confirmed pristine target to a root-free linked account and import its selected snapshot | 8,192 imported records; 4,094 groups |
| `DeviceProjection` | Apply one already-durable convergence winner and retire any exact session/capability/queue consequences | 512 exact mutations |
| `AttachmentStage` | Create the bounded metadata graph for one outbound attachment manifest | 256 mutations |
| `AttachmentState` | Apply one bounded transfer/object/missing-range/deferred-control transition | 256 mutations |
| `Maintenance` | Apply one bounded retry, expiry, tombstone, terminal-input, repair, queue, or presentation acknowledgement transition | 256 exact mutations |

Every plan validates its complete before-state before `BEGIN IMMEDIATE`.
`CommitPlan` is the only protocol-state write surface used by stable-profile
node modules. The source guard in `atomic_tests.rs` rejects direct session,
group, history, delivery, queue, replay, ephemeral, media and device-state
setters in those modules. It audits `devices.rs` rather than excluding the
file; only the explicitly delimited pre-C2 contact-manifest bridge described in
section 4 is removed from that check. The former multi-autocommit link-snapshot
import and convergence-log retention entry points have been removed; current
production replacements are `AuthorityDeviceLink` and
`AuthorityDeviceControl`.

The ownership rules are structural:

- an advanced pairwise sending session owns at least one durable ciphertext,
  and each retained message ciphertext has exactly one per-device delivery
  owner;
- an advanced group sender chain owns one immutable group event and every
  eligible account has exactly one logical delivery, with no more than eight
  physical copies;
- an advanced receiver chain owns the accepted plaintext/control consequence,
  replay marker, source-row acknowledgement, and any receipt ciphertext;
- a consumed one-time prekey owns the newly established exact-device session;
  issued one-time prekeys become visible to the caller only after the
  replacement vault commits;
- a stranger's consumed one-time prekey and candidate session own exactly one
  sealed provisional request until Accept, Delete, Block, or expiry retires it;
- a confirmed link secret remains live until the new channel and manifest
  commit; a sealed recovery handle owns a package return value lost after
  commit and is cleared only by authenticated target activity;
- detached candidates replace live memory only after the commit receipt;
- a presentation marker commits with every visible change, so a restart after
  commit but before event delivery requires a complete snapshot resync.

Transport sends, discovery publication, native wake, call presentation, and UI
events occur after the database commit. File transfer uses a separate
file-first rule: a temporary authenticated chunk may reach the filesystem
before its metadata transition, but it is unreachable as accepted media until
that transition commits and restart reconciliation removes abandoned files.

## 2. Stable-profile path inventory

| Path | Advanced or destroyed material | Atomic owner | Restart and side-effect disposition |
|---|---|---|---|
| Fresh prekey-bundle export | One-time-prekey vault | `PrekeyPublish` | Bundle return follows commit; failure leaves the live and durable vault unchanged |
| Outbound first flight | New sending session, ciphertext, history and delivery | `PairwiseSend` | Session never exists without its queued ciphertext |
| Inbound first flight from an accepted contact or compatibility path | Optional consumed one-time prekey, new session, accepted first content, receipt | `HandshakeReceive` | OPK removal and session establishment are one transaction |
| Unknown first flight | Verified admission wrapper, optional consumed one-time prekey, isolated candidate session/identity/safety number, bounded preview and request row | `AdmissionStage` | Proof, exact target, expiry, size, carrier/work budgets and replay are checked before the atomic stage; no contact or normal history exists |
| Message-request Accept | Provisional session/identity/first content, contact, history, receipt and presentation | `AdmissionAccept` | Promotion is all-or-nothing; only committed acceptance exposes normal send/history state |
| Message-request Delete or Block | Provisional state, replay tombstone and optional exact account/device block | `AdmissionDiscard` | Candidate keys and request row disappear together; Block claims no remote deletion |
| Message-request expiry | Provisional state and bounded replay state | `AdmissionSweep` | At most 16 expiry mutations per tick; restart sees either the complete request or complete retirement |
| Pairwise text, edits and ordinary versioned content | Sending or receiving ratchet, immutable history, replay, receipts | `PairwiseSend` / `PairwiseReceive` | Presentation follows commit; duplicate input is absorbed |
| Pairwise capabilities and protocol controls, including role/admin requests | Pairwise ratchet and typed control consequence | Send/receive/receipt plans | Authenticated deferred work is durable before follow-up and deleted with that follow-up |
| Group create, invite acceptance, roster change and leave/removal | Group record, sender generation, receiver chains and contact stubs | `GroupState` | One bounded roster transition; events follow commit |
| Group chain/origin announcement and acknowledgement | Pairwise session, per-recipient origin capability, monotonic origin generation, pending announcement and receiver chain commitment | `PairwiseSend`, `ReceiptReceive`, `GroupState` | Announcement ciphertext owns pending state; a newer generation or exact idempotent duplicate is accepted, while stale/divergent controls cannot replace the chain or earn an acknowledgement |
| Group authority, roles, transfer and owner moderation | Signed authority record, generation and immutable announcement | `GroupSend`, `PairwiseSend`, `GroupState` | Authority state and its authenticated announcement/control consequence commit together |
| Group text, attachments, edits, polls, authority and ephemeral events | Sender chain, one immutable shared ciphertext, recipient origin tags, recipient/device deliveries and queue | `GroupSend` | At most 63 remote accounts × 8 devices = 504 fixed-width recipient wrappers around one ciphertext in stable-v1 |
| Group receive | Verified pairwise sender device, recipient origin tag, receiver chain, accepted plaintext, replay state and receipt session/ciphertext | `GroupReceive` | Origin verification completes before candidate chain advance; bad recipient/device/context, duplicate, replay and reordered input cannot advance the chain incorrectly |
| Late group fan-out and partial carrier handoff | Retained ciphertext, new device deliveries and queue rows | `GroupSend` | Does not re-encrypt or advance the sender chain; restart retains unsent copies |
| Outbound attachment offer | Manifest history, transfer/object graph and optional view-once marker | `AttachmentStage`, then send plan | Manifest encryption waits for complete staged objects |
| Inbound attachment offer | Accepted manifest history, transfer/object graph, replay and receipt | Receive plan | No transfer becomes visible before the accepting receive commits |
| Attachment request, chunk, completion and refusal | Transfer/object progress, missing ranges and accepted deferred control | `AttachmentState` or response-owning `PairwiseSend` | The encrypted response and consumed request commit together when a response advances a session |
| Attachment expiry/view-once | Tombstone, plaintext history removal and media references | `Maintenance` | The tombstone and removals are one bounded transition; later input cannot revive plaintext |
| Scheduled-message activation | Schedule row, ratchet or sender chain, history, delivery and ciphertext | `PairwiseSend` / `GroupSend` | No transport or activation event occurs before commit; failed activation retains the schedule |
| Schedule create/edit/cancel | One sealed local outbox row | Single-row store operation | No cryptographic state, queue row or transport work exists before activation |
| Call-control send/receive | Pairwise ratchet and encrypted transient control | Pairwise send/receive plans | Signalling commits before in-memory call state or call events; live call/media state is intentionally process-local |
| Direct next-hop settlement | Complete sealed carrier envelope or verified introduction | Typed consuming plan, `AdmissionStage`, or bounded idempotent `pending_push` | The fixed response is held until exact durable staging/consumption; invalid, duplicate and over-budget introductions are refused without generic pending state |
| Deferred inbox acceptance | Complete sealed carrier envelope plus ingress class | Bounded idempotent `pending_push` admission | Admission advances no cryptographic state; the consuming plan deletes the exact named row and applies the preserved carrier budget after restart |
| Retry, expiry, terminal rejection and stale-session reset | Queue schedule/removal, delivery state, replay, session/capability reset | `Maintenance` | Work is paged at 256 mutations; retryable input remains durable |
| Event-delivery recovery | Sealed presentation marker | Visible plan plus `Maintenance` acknowledgement | Reopen emits `StateResyncRequired`; acknowledgement follows delivery |
| Media restart reconciliation | Missing-file object state and abandoned filesystem rows | Paged `AttachmentState` | Metadata repair commits before orphan cleanup; each page is bounded |
| Fresh profile creation | Public account trust anchor, independent physical-device authority and fresh prekey vault | `AuthorityProfileBootstrap` inside sibling publication | Destination is absent or a complete openable root-free profile; the generated root exists only in the separately exported recovery authority |
| Eligible single-device Alpha migration | Legacy account root/device state to public trust anchor and `KDA2` state | `AuthorityMigration` | The confirmed offline authority must match; commit either retains the legacy profile or publishes the complete root-free profile |
| Device rename, approval, revocation, recovery and channel counters | Signed manifest, exact channel state, affected group sender chains, capability/session retirement and convergence events | `AuthorityDeviceControl` | Detached memory follows commit; the 4,094-group profile ceiling leaves room for a full 4,096-event bundle, authority and recovery retirement while revocation rotates every group chain in the same transaction |
| Confirmed device-link completion | Public account identity, target device/channel state, regenerated local group senders and selected records | `AuthorityDeviceLink` | The source first seeds convergence winners for the snapshot, then exports only the selected namespaces; one bounded pristine-target transaction consumes the target ceremony secret only after success |
| Link-package return recovery | Source manifest/channel and transcript-derived recovery key | `AuthorityDeviceControl` | Approval commits a small sealed recovery handle; retry after restart reseals from committed state, and authenticated target sync deletes it |
| Device-sync import and duplicate import | Manifest/counter, convergence events, revocation rotations and exact winner projections | `AuthorityDeviceControl`, then idempotent `DeviceProjection` / `GroupState` | Accepted control state commits before projections; established `KDA2` contact endpoints, session/capability retirement and stale-orphan removal publish in one projection transaction; restart reapplies winners and sequence replay is rejected without writes |
| Backup export | A read-only root-free `KKR9` snapshot with fresh mnemonic | No live-state transition | Export includes bounded local block rules but excludes provisional requests/replay tombstones, invitation capabilities, account root, device/link/session/service secrets, ratchets, prekeys, chains, queues, wire ids, resumable delivery, live ephemeral plaintext/media and call state |
| Backup restore | New sibling database, higher recovery epoch, reset markers, one fresh device and fresh prekeys | `AuthorityProfileBootstrap` during sibling initialization plus atomic filesystem replacement | Compatible KKR8 or current KKR9 restore requires the separate offline authority; KKR8 restores no block rows; destination is absent or a complete openable store and old-epoch credentials remain revoked |
| Legacy-backup archive reset | Decode-only in-memory `KKR1`–`KKR7` input to a fresh account, one KDA2 device, cleared petnames/public contact identities, eligible local organization, notes and non-ephemeral pairwise history; production cannot mint a copied-root file | `AuthorityProfileBootstrap` inside a restore sibling plus atomic filesystem publication | The former root is never written to the sibling; crash-phase tests inspect staged and published stores; groups, sessions, routes, verification, devices, queues, service capabilities and resumable delivery are omitted, and the destination is absent or a complete root-free former-identity archive |

Edits, polls, roles and ephemeral content do not receive a special durability
exception: they are immutable authenticated content carried by the same
pairwise or group plans. Their convergent read projections run only after the
accepted event is durable.

## 3. Store-call audit

The production node call graph was searched for every raw `put`, `set`,
`update`, `delete`, queue, replay, seen, session, group, media and history
write. The remaining direct calls fall into these categories:

| Remaining direct write | Classification |
|---|---|
| Labels, folders, pins, icons, theme, petnames and note-to-self | Local sealed presentation/organization state; no ratchet, sender chain, replay, delivery or carrier consequence |
| Schedule create/edit/cancel | One local row; activation is typed |
| Complete-envelope `pending_push` | Bounded idempotent ingress staging before parsing or cryptographic work |
| Media garbage collection after semantic commit | Physical cleanup after the durable tombstone/progress transition |
| Explicit outgoing contact import, hint/verification changes | User-selected local destination/presentation state; inbound unknown identities can enter only through `AdmissionStage` and explicit `AdmissionAccept` |
| Pre-C2 contact-device alias/manifest migration | Explicitly delimited ADR-0030 compatibility quarantine; its route/session retarget sequence is not stable-v1 evidence |
| Restore population writes inside an unpublished sibling | Bounded reconstruction work is never visible at the destination; fresh device/prekey initialization is typed before atomic publication |

No stable-profile sender/receiver chain, one-time prekey consumption, current
device authority/counter, link import, convergence winner, group state,
protocol history, delivery, outbound queue, replay/seen, attachment state, or
ephemeral tombstone is written through those local-state calls. Adding such a
call outside the named compatibility bridge fails the source guard.

## 4. Open and excluded paths

These boundaries keep ADR-0028 Proposed:

1. **A pre-C2 alias migration remains quarantined compatibility code.** It is
   the only raw contact/session route-retarget setter sequence excluded from
   the node source guard. New unknown first contact does not use it.
2. **Live call state is process-local by design.** Ratchet-protected signalling
   is covered; ringing, active-call and media state are not restored after a
   process stop and are not stable persisted state.
3. **Mailbox-v1 relay custody remains outside this node/store transaction.**
   Endpoint inbox acceptance is covered, but leased relay deletion only after
   endpoint acknowledgement remains proposed in ADR-0032.
4. **Independent and physical evidence remains open.** The deterministic
   matrix is not independent protocol review or supported-platform sudden
   power-loss qualification.

The intentionally excluded P2 paths are live video, groups above 64 accounts,
advanced moderation, high-bandwidth media, Freenet-style or other additional
delay-tolerant carriers, cross-protocol federation, richer optional
discovery/wake services, and later governance expansion. None is evidence for
or against stable-v1 atomicity.

## 5. Failure and restart matrix

`crates/kult-node/src/atomic_tests.rs` applies every transaction failpoint to
every current stable-profile plan plus the legacy bootstrap and explicit
authority-migration boundaries, using twenty-five fixtures where maintenance
and admission have separate terminal, reset, stage, accept, discard, and
expiry cases:

- before and after `BEGIN IMMEDIATE`;
- before and after every numbered logical statement;
- before and after commit;
- before and after candidate cryptography and memory replacement;
- before and after event delivery; and
- disk-full, constraint and duplicate-index failure classes.

The same suite covers duplicate and reordered deferred input, duplicate device
sync import, retry after restart, presentation-outbox recovery, link-package
return recovery, scheduled activation, a maximum stable-v1 group fan-out of
504 physical deliveries, and rejection/restart at the profile group ceiling.
Admission fixtures cover invalid proof, duplicate/replay refusal, one-time
prekey consumption, provisional count/byte exhaustion, disk-full rollback,
per-carrier/work ceilings, exact Accept/Delete/Block effects, direct response
settlement, and expiry/restart.
The linked-device suite also proves selective initial transfer, root-free
return-value recovery, strict-majority authority, contact projection
all-or-nothing behavior, exact convergence-event compaction, group
deletion/authority tombstones, stale-backup recovery and restart replay. The
group end-to-end suite covers partial carrier handoff followed by sender
restart. Pending-inbox, media and custom-icon tests fill their item/byte quotas;
media tests also cover duplicate chunks, interrupted temporary files and exact
missing ranges. Legacy and root-free profile publication, live-store migration,
copied-root reset and backup tests inject every atomic-replacement phase and
initializer failure; the legacy-only-artifact path additionally proves direct
root-free projection through public UniFFI.
Disk-full, constraint and duplicate-index classes run against every fixture.

For each injected point, reopen observes either the complete transition or its
complete absence. The input remains retryable in the absent case; the durable
case absorbs replay and requests presentation resynchronization when needed.
No test accepts an intermediate chain/session state.

This repository evidence is not physical sudden-power-loss qualification,
external review, or independently produced interoperability evidence. Those
remain P0 gates in the [release evidence ledger](31-release-evidence-ledger.md).
