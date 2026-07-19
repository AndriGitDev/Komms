# ADR-0024: Account-authorized linked devices and convergent local sync

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

Komms previously equated the stable account identity with one physical
installation. Encrypted backup was safe migration, but copying a live ratchet
database would reuse identity, prekey, pairwise-ratchet, and group-sender state
on multiple machines. That creates nonce/counter races, ambiguous revocation,
and no honest answer to which endpoint received a message.

C2 needs multiple devices without a cloud account, server log, or mandatory
coordinator. Devices can be partitioned, exchange state in either order, send
concurrently, and be permanently lost. Existing contacts must retain one stable
conversation identity while encrypting independently to every authorized
physical endpoint.

## Decision

### Stable account, independent device identities

The existing Ed25519/X25519 identity remains the stable account and
conversation identity. Every installation additionally generates a fresh
Ed25519/X25519 device identity. The account signs an immutable device
certificate containing the complete account/device public keys, a random
16-byte serial, and issuance time.

The account also signs a complete, monotonically generated device manifest.
Each row contains the immutable certificate, a bounded signed display name, a
coarse last-seen hint, and optional permanent revocation plus its last accepted
sync counter. Rows sort by device id. At most eight devices may be active and at
most 64 lifetime certificate/tombstone rows are retained. A revoked certificate
can never be rewritten, deleted, or made active again.

Valid same-generation forks converge by the lexicographic manifest state id;
lower generations, fork losers, certificate rewrites, missing known rows, and
un-revocation fail closed. Last-seen is an audit/presentation hint, never an
online-presence claim.

### Proximate, mutually confirmed linking

Only a pristine installation can become a link target. An active source creates
a ten-minute, account-signed offer containing a random ceremony id, the current
manifest, source device id, and one-use X25519 public key. The target generates
its permanent device identity plus a one-use X25519 key and signs a response
binding the offer, proposed device name, and both ephemeral keys.

Both endpoints derive the same transcript-bound HKDF key and six-digit
comparison code. Neither side completes unless the user explicitly confirms
that the digits match. The source then issues the target certificate, advances
the manifest, and encrypts an initial transfer under XChaCha20-Poly1305. The
user independently selects contacts/verification, local organization, and
non-ephemeral history. Active ephemeral content, drafts, live queues, ratchets,
downloaded media, and protected shell transients never enter the package.

Offer, response, and package are opaque versioned bytes exposed as QR/pasteable
hex by RPC, UniFFI, and every shell. Komms requires no cloud service for the
ceremony. Local-network transport may carry the same authenticated bytes later;
it must not weaken the comparison step.

### Per-device delivery cryptography

The `KDP1` contact bundle binds one device-signed PQXDH prekey bundle to its
account certificate and complete manifest. A contact stores the stable account
record plus sealed physical endpoint rows. Every active physical device has an
independent pairwise ratchet and capability snapshot. Legacy one-device bundles
migrate deterministically to the unique earliest issued certified endpoint
when its first manifest arrives.

Pairwise sends fan out one independently encrypted copy per active device.
Per-device delivery rows report queued, sent, and delivered honestly; the
existing account-level state remains the aggregate presentation. Safety-
sensitive typed content (edits, disappearing content, view-once media, polls,
mentions, and authority operations) fails closed unless every active endpoint
or group recipient has a live authenticated capability.

Each local device owns a distinct group sender chain. Receivers retain multiple
chains under the stable account member, keyed by exact physical device and
sender-key id. Device revocation removes its sessions, capabilities, queued
copies, and sync channel, and rotates surviving local group sender chains.

### Encrypted deterministic convergence

Linking establishes a separate symmetric channel root between the source and
target devices. Sync bundles are direction-bound, sequence-numbered,
XChaCha20-Poly1305 sealed, limited to 4,096 events and 16 MiB, and addressed to
exact physical ids. Replays, wrong direction, unknown/revoked senders, manifest
rollback, oversized values, malformed keys, and post-revocation counters fail
closed.

Events are signed by the emitting device and authorized by its certificate and
manifest generation. A Lamport clock plus deterministic event-id ordering
selects one winner per namespace/key. The convergent namespaces are:

- contacts and separately mergeable verification;
- certified contact-device endpoints;
- folders, labels, pins, icons, and the sealed appearance preference;
- non-ephemeral pairwise/group/note history;
- immutable edit and group-poll events;
- group definitions and signed authority state; and
- terminal expiry/consumption tombstones.

Drafts, scheduled outbox rows, live queues/ratchets, active ephemeral content,
downloaded media, non-theme UI preferences, and protected platform transients
remain device-local. A target never inherits another device's queue or wire-id
promise. Sync keeps only converged winners plus required tombstones, bounding
the replay log while preserving convergence for a new device.

### Recovery and revocation

`KKR7` stores the account, current manifest, local device id, convergence
winners, certified contact endpoints, ordinary state, and terminal tombstones;
it never stores live ratchets or the local device private key as a reusable
credential. Restoring mints a fresh device certificate and atomically revokes
every device active in the backup at the backup creation time. The recovered
installation is the sole active row until another device is explicitly linked.
`KKR1` through `KKR7` remain readable and migrate to the same model.

Revocation is permanent, exact-id targeted, explicitly confirmed in every
shell, and cannot revoke the current or last active device. A lost device may
retain plaintext it already saw; revocation protects future delivery and sync,
not retrospective erasure.

## Consequences

- One account remains one contact/conversation while every physical endpoint
  has independent PQXDH, ratchet, capability, delivery, and group-sender state.
- Komms gains linked-device availability without project-operated storage or an
  online account service.
- Initial history transfer and later sync are bounded explicit operations; the
  current UI does not claim continuous background cloud sync.
- Account private-key availability on each linked device is a deliberate
  authority tradeoff: it permits offline manifest progress and stable message
  authorship. Independent device credentials still make delivery separation,
  revocation, and ratchet safety enforceable.
- Same-generation manifest forks converge deterministically, not fairly. A
  malicious account-authorized device can race authority changes until revoked.
- Last-seen, sync completion, and per-device delivery indicators must retain
  their narrow meanings and must not become presence or remote-erasure claims.

## Acceptance evidence

The implementation includes strict codec and fuzz targets, no-std crypto and
protocol checks, KKR1–KKR7 migration tests, three-device partition/rejoin,
concurrent pairwise/group sends, independent ratchets and sender chains,
edit/poll/tombstone convergence, rollback and replay rejection, restart and
revocation exclusion, and backup recovery that never resurrects old
credentials. The ceremony is driven end to end through node, strict JSON RPC,
CLI parsing, UniFFI, desktop Session, Android Session, and iOS Session surfaces.
Android debug-APK assembly is automated, while real Android/iOS device
qualification remains a release gate; it does not weaken the shared-core
acceptance.
