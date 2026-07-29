# 22: Linked Devices

Komms supports several independently keyed installations under one stable
account identity. This is direct, encrypted device-to-device state transfer—not
a cloud account or a promise that every device is continuously online.

The authority and recovery contract is
[ADR-0026](adr/0026-revocable-device-authority.md). The independent ratchet,
delivery, sender-chain, and convergent-sync mechanics retained from
[ADR-0024](adr/0024-account-authorized-linked-devices.md) remain part of the
design.

## What users can rely on

- The stable account private key is an offline recovery authority. It is absent
  from live stores, ordinary link packages, sync events, and root-free routine
  backups after profile creation or migration.
- Every physical device has its own immutable certified identity, PQXDH/Double
  Ratchet sessions, capability state, group sender chains, and delivery rows.
- Ordinary device changes append one versioned `KDA2` transition bound to the
  exact parent hash and generation and complete next device set.
- A strict majority of the previous active devices must authorize add, rename,
  observe, revoke, or replace operations. One active device can add a second;
  two active devices require both; three active devices require two.
- Concurrent valid children of one parent are visible authority forks. Komms
  retains the accepted branch and conflict evidence, clears verification, and
  fails closed instead of selecting authority by generation or byte ordering.
- Root recovery creates a higher epoch, revokes every former active device,
  introduces exactly one fresh recovery device, and rotates live sync,
  relationship-capability, group-chain, session, queue, and delivery state.
  Descendants of older epochs are rejected.
- Pairwise delivery exposes exact per-device queued/sent/delivered state. The
  account-level state remains an aggregate and never implies every device is
  online.
- Contacts, folders, labels, pins, icons, appearance, ordinary history, edits,
  polls, group authority, and terminal expiry tombstones can converge through
  authenticated encrypted sync bundles.

The Alpha proof profile permits at most eight active devices, 64 lifetime
certificate/tombstone entries, 64 carried transitions, and 1 MiB of encoded
authority. Reaching a bound refuses the authority operation; it never truncates
evidence or chooses a branch. A compact checkpoint would require a future
version and compatibility decision.

## Offline recovery authority

A fresh profile generates the stable account root, uses it to sign genesis,
then seals it into a caller-selected `.kra` file. The opening phrase is shown
once and is not stored. The live profile retains only the public account trust
anchor, one independent device secret, and the accepted manifest.

The `.kra` file and its separate 24-word phrase are not an ordinary backup.
Anyone holding both can take over the stable identity and revoke every current
device. They should be kept offline and separately from an unlocked device.
Opening attempts are locally throttled, but the phrase entropy and protected
offline file—not that restartable throttle—are the security boundary.

Routine `KKR8` backup has its own file and one-time phrase. Restore requires
both the `KKR8` pair and the `.kra` pair so the account root is opened only for
one explicit recovery epoch.

## Link flow

1. On an existing device, open **Linked devices → Link another device** and
   show or copy the ten-minute offer.
2. On a pristine installation, choose **Link this new device**, scan or paste
   the offer, and name the candidate. The target creates an independent device
   identity; it receives no account root.
3. Return the target response to the source. Compare the same six digits on
   both screens over the proximate or otherwise trusted context.
4. Select the initial contacts, local organization, and non-ephemeral history
   categories and explicitly confirm.
5. If the current active set requires more signatures, transfer the exact
   approval request to the additional device or devices and return their
   detached approvals. Recovery words are not used while an ordinary strict
   majority remains available.
6. Transfer the sealed package to the target and explicitly complete. The
   target activates only after the complete chain and quorum proof verify.
7. Both screens show the same account and authority state but different exact
   physical-device ids.

Opaque offer, response, approval, and package bytes may be transferred by
camera, paste, or file. They must go only between the intended installations.
The comparison code and explicit confirmations are the authentication step;
proximity alone is not.

## What remains local

Drafts, scheduled outbox work, active ephemeral content, live queues and
ratchets, downloaded media, most shell preferences, and protected temporary
files do not synchronize. Initial transfer excludes them too. Disappearing and
view-once promises remain installation-local; terminal tombstones synchronize
to prevent resurrection, but another device or recipient may already have kept
a copy.

## Sync and conflicts

Current shells expose explicit encrypted sync export/import. Each bundle is for
one exact active destination, is direction-bound and monotonically numbered,
and rejects replay, rollback, the wrong recipient, revoked senders, or an
unaccepted authority branch. Ordinary data conflicts converge by signed Lamport
order and stable event ids.

Authority does not use that ordering rule. A fork or same-epoch root recovery
conflict is retained as bounded visible safety evidence and requires recovery
and contact safety-number comparison. “Imported” means only that one owned
device transactionally accepted and applied an authenticated bundle; it is not
a transport receipt or proof that any third device is online.

## Loss, compromise, and recovery

With an available strict majority, revoke the lost device. The transition
removes its future delivery and sync authority, retires its local queues,
sessions, and capabilities, and rotates surviving group sender chains. A stolen
minority cannot approve its own replacement or re-enter under a new certificate.
The device may still retain plaintext it already decrypted.

When the quorum is lost, open the offline recovery authority explicitly.
Recovery names the last accepted manifest, advances the recovery epoch, revokes
the former active set, and creates one fresh device. Stale backups and
old-epoch descendants cannot resurrect old credentials. Two different
root-signed transitions at the same epoch are a visible recovery conflict, not
an ordering contest.

The root remains the ultimate takeover secret. Root theft permits account
takeover; Komms can detect a conflicting recovery observed by an existing
installation, but it cannot make a stolen root harmless.

## Backup and Alpha migration

`KKR8` preserves the public account, accepted authority proof, accurately
eligible local history and organization, certified contact endpoints, and
terminal tombstones. It excludes the account root, physical-device private
keys, prekeys, pairwise ratchets, group sender/receiver chains, link-channel
roots, live rendezvous or wake capabilities, wire ids, queues, and resumable
delivery state. Queued or sent local history restores as failed history and
contacts re-handshake.

Legacy `KKR1` through `KKR7` inputs remain an explicit compatibility boundary.
A legacy single-device profile with no durable evidence that the account root
was copied may migrate in place after exporting and confirming its `.kra`.
Durable multi-device or link-channel evidence requires a visible
new-identity authority reset. A person who exported a legacy `KKR7` file or
otherwise copied the root can conservatively choose reset even when the live
store shows one device.

Reset preserves only accurately labelled local petnames, eligible local
organization, note-to-self, and non-ephemeral pairwise history. It does not
preserve the old safety number, verification, routes, groups, sessions,
delivery promises, or revocation authority. Every contact is guided through
re-verification under the new identity.

When the legacy backup is the only surviving artifact, every shell offers the
same visible reset before import. The user first creates and separately saves a
fresh `.kra`, reviews the new address and phrase, and confirms that all safety
numbers change. The legacy file is then decrypted only in memory; one
root-free sibling is built directly from the allowed archive projection and
published atomically. The copied root is never written to an intermediate or
final store.

## Qualification

Local acceptance covers strict codec/signature bounds, quorum approval,
three-device partition/rejoin, stolen-minority revocation, quorum loss, root
theft, stale backup, replay, fork and recovery conflicts, old-epoch rejection,
selective transfer, independent ratchets and chains, restart/crash failpoints,
root-free backup exclusions, a legacy-only-artifact reset through public
UniFFI, strict RPC/CLI, desktop, Android host, and Swift host paths. Current
Android APK and iOS Simulator builds exercise the same public contract.

Simulator and self-round-trip results are not physical-device qualification,
sudden-power-loss evidence, independent security review, or independently
produced interoperability. Those gates remain open. Message pins remain
deferred until stable message-reference semantics are designed separately.
