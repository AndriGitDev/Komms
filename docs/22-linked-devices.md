# 22: Linked Devices

Komms supports several independently keyed installations under one stable
account identity. This is direct, encrypted device-to-device state transfer—not
a cloud account or a promise that every device is continuously online.

The normative design is [ADR-0024](adr/0024-account-authorized-linked-devices.md).

## What users can rely on

- Every physical device has its own certified identity, PQXDH/Double Ratchet
  sessions, capability state, group sender chains, and delivery rows.
- Linking requires a pristine target, a ten-minute source offer, matching
  six-digit codes on both screens, and explicit confirmation on each side.
- The source chooses whether the initial encrypted package includes contacts,
  private organization, and non-ephemeral history.
- Up to eight devices can be active. Names are account-signed; last-seen is a
  coarse observation, not presence.
- Revocation targets one exact device, is permanent, requires a destructive
  confirmation, excludes future delivery/sync, and rotates surviving group
  sender chains.
- Pairwise delivery exposes honest per-device queued/sent/delivered state. The
  account-level state remains an aggregate and never implies every device is
  online.
- Contacts, verification, folders, labels, pins, icons, appearance, ordinary
  history, edits, polls, group authority, and terminal expiry tombstones can
  converge through authenticated encrypted sync bundles.

## What remains local

Drafts, scheduled outbox work, active ephemeral content, live queues and
ratchets, downloaded media, most shell preferences, and protected temporary
files do not synchronize. Initial transfer excludes them too. Disappearing and
view-once promises remain installation-local; terminal tombstones synchronize
to prevent resurrection, but another device or recipient may already have kept
a copy.

## Link flow

1. On an existing device, open **Linked devices → Link another device** and
   show or copy the offer.
2. On a pristine installation, choose **Link this new device**, scan/paste the
   offer, and name the device.
3. Return the target response to the source. Compare the same six digits on
   both screens over the proximate/trusted context.
4. On the source, select the initial categories and explicitly approve.
5. Transfer the encrypted package to the target and explicitly complete.
6. Both screens show the same account and signed device list, but different
   exact physical-device ids.

Opaque offer/response/package hex may be copied when a camera is unavailable.
It must be transferred only between the two intended installations. The
comparison code is the authentication step; proximity alone is not.

## Sync and conflicts

Current shells expose explicit encrypted sync export/import. Each bundle is for
one exact active destination, has a monotonic direction counter, and rejects
replay or wrong-device import. Concurrent changes converge by signed Lamport
order and stable event ids. Concurrent device-manifest forks select one signed
state id; losing authority changes must be retried from the winner.

Sync is not a transport receipt. “Imported” means the destination accepted and
applied an authenticated bundle. It says nothing about a third device or
recipient.

## Loss and recovery

If one linked device is lost, revoke it from another active device as soon as
possible. The lost device can retain content already decrypted; revocation
prevents new delivery and accepted sync.

`KKR7` recovery intentionally does not resurrect any backed-up device
credential. Restore keeps the stable account and ordinary data, revokes every
device that was active in that backup, and mints a fresh sole active device.
Older KKR files remain restorable through migration.

## Qualification

Local acceptance covers three-device partitions and rejoin, concurrent sends,
independent pairwise and group chains, selective transfer, edit/poll/tombstone
convergence, malformed/replay/rollback rejection, revocation, restart, KKR7
recovery, strict RPC/CLI, UniFFI, desktop, Android host-core source parity, and
iOS host-core source parity. Per-push CI assembles the Android debug APK; full
SwiftUI app type-check/simulator testing requires full Xcode. Real-device
ceremony, revocation, and recovery behaviors remain hands-on qualification.
