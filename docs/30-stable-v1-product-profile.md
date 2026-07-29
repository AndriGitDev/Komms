# Stable-v1 product profile

**Status:** frozen release target; not a statement that Komms is stable

**Decision date:** 2026-07-26

**Accountable owner:** Andri, founder and lead maintainer

**Change control:** a material expansion or weakening requires an ADR, an
updated claim entry in the [release evidence ledger](31-release-evidence-ledger.md),
and founder approval

Komms stable-v1 is an everyday private messenger with a deliberately bounded
public contract. The product promise remains:

> **Private messaging that keeps working.**

That sentence expresses the product direction: Komms keeps queued work and can
try more than one supported route. It is not a promise of universal
availability, guaranteed delivery time, censorship resistance against every
adversary, or operation after every usable device, route, or power source is
lost.

This profile freezes what may be represented as stable. A feature can exist in
the repository or an Alpha package without joining this profile. Every stable
public statement must use one of the claim identifiers below and must satisfy
the corresponding entry in the
[release evidence ledger](31-release-evidence-ledger.md).

## 1. Installation and supported systems

**Claims:** `SV1-C01`, `SV1-C11`

A stable release is installed from a project-authorized artifact with a
published checksum, production signature where the platform supports one,
provenance, an SBOM, and an authenticated update path or an explicitly bounded
manual-update procedure. Install, upgrade, rollback, recovery from an interrupted
upgrade, and release-key recovery must be exercised from clean systems before
the stable label is used.

The stable-v1 candidate matrix is:

| Client family | Candidate architecture and floor | Stable declaration rule |
|---|---|---|
| Android | Android 8.0 / API 26 or newer; `arm64-v8a` | Only named physical device and OS cells recorded as passed are supported. Emulator assembly is build evidence only. |
| iOS | iOS 16 or newer; `arm64` | Only named physical iPhone and iOS cells recorded as passed are supported. Simulator assembly is build evidence only. |
| Windows | Windows 10/11; x86-64 | Only named supported Windows releases with signed installer, install, upgrade, rollback, and lifecycle evidence are supported. |
| macOS | Intel and Apple silicon | The minimum macOS release and every supported hardware/OS cell must be named in the release matrix before stable. |
| Linux desktop | x86-64 | Support is distribution- and version-specific. AppImage, DEB, or RPM availability alone does not imply support for every Linux system. |

Every combination not present as passed in the published stable release matrix
is unsupported, even if it builds or happens to run. The headless operator
image is a separate Linux amd64/arm64 support profile and does not turn a client
platform into a supported server platform.

The current unsigned or debug-signed 0.3 packages remain Alpha artifacts and do
not satisfy this section.

## 2. Identity and contact establishment

**Claims:** `SV1-C02`, `SV1-C04`

- A user creates a local cryptographic identity without a required phone
  number, email address, real name, or project account.
- The ordinary intentional-contact path is a versioned Connect code exchanged
  by QR, link, paste, or file. It contains a random rotatable discovery
  capability distinct from the stable account fingerprint.
- A nearby pairing flow works without a project service. A Standard internet
  flow may use disclosed, replaceable bootstrap and introduction-mailbox
  defaults.
- Public discovery exposes bounded, capability-scoped introduction data and
  mailbox routes, not a stable identity-to-current-IP directory.
- A valid cryptographic introduction is a provisional message request, not
  consent, a trusted contact, group membership, or permission to spend
  unbounded endpoint resources.
- An invitation can provide the fast consent path. Unsolicited contact is
  subject to the signed admission policy, hard count/byte/work quotas, and an
  explicit Accept, Delete, or Block decision.
- Safety-number comparison remains the out-of-band verification path. Contact
  names are local petnames and are not identity.

The stable implementation must accept the authority, admission, and discovery
decisions in [ADR-0026](adr/0026-revocable-device-authority.md),
[ADR-0030](adr/0030-first-contact-admission.md), and
[ADR-0031](adr/0031-capability-scoped-dht-discovery.md), or superseding ADRs
that close the same threats. ADR-0026 authority and ADR-0030 provisional
message requests are implemented for Alpha. Capability-scoped discovery,
independent adversarial evidence, and field qualification remain open, so the
combined reachability/consent claim is not yet stable-v1.

## 3. Pairwise text

**Claims:** `SV1-C03`, `SV1-C05`

- Stable-v1 supports authenticated end-to-end encrypted UTF-8 text between two
  accepted contacts.
- One canonical v1 text content frame is at most 65,535 bytes, including its
  28-byte header. The exact text payload limit is therefore **65,507 UTF-8
  bytes**. User interfaces must measure bytes, not characters, and reject a
  larger value before changing delivery state.
- A send succeeds locally only after the immutable history event, ratchet
  transition, per-device delivery state, and durable outbound ciphertext commit
  atomically.
- A receive becomes visible only after the receiving ratchet, history,
  replay/seen state, receipt state, and source-row acknowledgement commit
  atomically.
- Text formatting, when presented, is a bounded inert local projection. The
  authenticated source remains text and cannot create links, HTML, scripts,
  remote fetches, or executable content.

Legacy Alpha text may remain readable, but stable-v1 send and receive behavior
uses the declared versioned content and atomic transition contract.

## 4. Bounded groups

**Claims:** `SV1-C06`

- A stable-v1 group contains at most **64 active accounts**. One account may
  have at most **8 active linked devices** under the device-authority profile.
  Lower operational limits may be selected, but no interface or operator may
  raise these protocol ceilings.
- Group text and attachment manifests use one sender-key ciphertext with
  recipient-scoped delivery. Delivery remains visible per recipient rather
  than collapsing partial delivery into a false group-wide success.
- Every recipient must authenticate the claimed sender account and device for
  ordinary messages and author-sensitive events. Membership knowledge alone
  is not sufficient authorship evidence.
- Membership changes rotate the applicable sender and recipient-origin
  material. Removed members may retain content and keys they already received;
  removal is not remote erasure.
- Joining a group is an explicit consent action. Receipt of an invitation does
  not expose membership, download media, or create mesh airtime.

[ADR-0029](adr/0029-recipient-authenticated-groups.md) is the accepted Alpha
implementation of this contract. Stable-v1 still requires revision-bound CI,
independent protocol/security and interoperability evidence, and named
physical-platform qualification. Groups larger than 64 accounts and any future
MLS profile are excluded.

## 5. Bounded attachments

**Claims:** `SV1-C07`

Stable-v1 supports one encrypted primary object and at most one optional image
preview per attachment offer:

| Property | Stable-v1 limit |
|---|---|
| Primary object | 512 MiB / 536,870,912 bytes |
| Preview object | 256 KiB / 262,144 bytes |
| Plain data per chunk | 49,152 bytes |
| Primary chunks | 10,923 maximum |
| Preview chunks | 6 maximum |
| Manifest | 1,024 bytes maximum |
| Filename hint | 255 UTF-8 bytes maximum |
| Media-type hint | 127 lowercase ASCII bytes maximum |
| Active media objects | 8 inbound and 8 outbound per peer; 32 globally |
| Default media-store quota | 2 GiB |
| Default incomplete-media quota | 1 GiB |

Attachment acceptance is explicit. Chunks authenticate independently, resume
after interruption, and remain excluded from airtime-budgeted mesh carriers.
The filename and media type are untrusted hints. A received file is not
described as safe, is never opened automatically, and is exported or opened
only after an explicit user action and a platform-qualified protected-file
transition.

Image and audio preparation may create a canonical output that omits source
metadata, but Komms does not call a file “metadata-free”: dimensions, duration,
format fields, filesystem data, traffic observations, and recipient-created
copies can still exist. Malware detection, cloud scanning, and remote deletion
are not stable-v1 claims.

## 6. Backup, recovery, and linked authority

**Claims:** `SV1-C08`

- A user can export one root-free encrypted, versioned backup and its newly
  generated 24-word backup mnemonic. First-run setup separately exports the
  offline account-recovery authority and its own 24-word opening phrase.
  Restore requires both pairs and refuses to overwrite an existing profile.
- The stable backup carries the account identity, contacts, ordinary retained
  history, eligible local organization, group authority, and the accepted
  device-authority chain.
- Ratchet state, group sender/receiver chains, one-time prekeys, reusable device
  private credentials, live ephemeral plaintext/media, calls, and queued
  outbound runtime work do not become portable backup state. Restored contacts
  re-handshake.
- The account root is an offline recovery authority and is absent from routine
  live-device stores and link packages. Ordinary device changes use a strict
  majority of the previous active device set; loss of that majority requires
  explicit root recovery.
- Root recovery revokes the previous active set, creates one fresh recovery
  device, rotates relationship capabilities, and makes conflicts visible.
- A stable release includes clean-device backup/restore, lost-device,
  old-backup, stolen-device, manifest-fork, recovery-conflict, and failed-restore
  evidence on supported platforms.

Current root-free `KKR9` round trips, secret-exclusion checks, recovery epochs,
fork/conflict cases, crash failpoints, cross-shell host tests, and Android/iOS
simulator builds are Alpha implementation evidence for accepted
[ADR-0026](adr/0026-revocable-device-authority.md). They do not freeze stable
wire/state v1 or close physical-device, sudden-power-loss, independent-review,
or independent-interoperability gates.

## 7. Blocking and deletion

**Claims:** `SV1-C09`, `SV1-C14`

Block is an explicit sealed local rule bound to the exact account/device
identity. It removes local provisional state, pending invitations, queued local
copies, and that relationship's rendezvous/wake capabilities, and prevents new
ordinary contact or group-invite state from that identity. It does not:

- erase content already received by another person or device;
- revoke an identity globally;
- make a remote operator delete ciphertext;
- prove that screenshots, exports, backups, notifications, filesystem
  snapshots, or flash remnants are gone; or
- stop a blocked person from creating a different identity.

Deleting history removes the live logical record and Komms-owned references
from the current profile. Local storage applies best-effort remnant reduction,
but the user-facing statement is “removed from this Komms history,” never
forensic or remote erasure.

Mute, Delete, Reject, and Block remain distinct actions. Optional reputation
lists must be signed, scoped, expiring, inspectable, and user-overridable; they
are not a hidden global ban service.

## 8. Delivery semantics

**Claims:** `SV1-C10`, `SV1-C13`

| User-visible state | Exact meaning |
|---|---|
| **Scheduled** | Retained locally for a future activation time; no ratchet or transport work has occurred. |
| **Queued** | The local atomic transition retained the history event and durable outbound ciphertext; no next hop has accepted it. |
| **Sent** | A direct endpoint or store-and-forward next hop accepted bounded custody under its declared contract. This does not prove recipient receipt or reading. |
| **Delivered** | An authenticated end-to-end receipt from the intended recipient device was accepted. It does not mean read. |
| **Delivery failed after 30 days** | No end-to-end receipt arrived before the bounded retry window ended. History remains; automatic queue retention ended. |

Stable direct acceptance occurs only after bounded durable endpoint admission,
not a volatile RAM queue. Stable mailbox acceptance occurs only after a durable
v2 deposit; collection leases rows and deletes only exact rows acknowledged
after endpoint commit. Duplicate delivery is absorbed without duplicate
history, and the sender retains its original ciphertext until the encrypted
end-to-end receipt or terminal retry result.

No delivery state promises latency. A user can remain unreachable when all
configured operators, routes, radios, carried files, devices, or power sources
are unavailable or blocked.

## 9. Optional services and pure-core operation

**Claims:** `SV1-C12`, `SV1-C15`

The stable profile distinguishes:

- **Core roles:** capability-scoped DHT discovery and durable mailboxes. Users
  may choose or self-host their bootstrap peers and mailbox operators.
- **Optional convenience:** post-pairing rendezvous and content-free native
  wake. Removing them may reduce speed or mobile convenience but does not change
  message format, identity, or the end-to-end trust root.
- **Standard mode:** may ship disclosed, replaceable project defaults for easy
  first use.
- **Sovereign mode:** disables project-operated optional services and retains
  manual, community, local, radio, file, and self-hosted routes.

No service receives message/media plaintext or user Komms identity private
keys. That is not a claim that an operator sees nothing: addresses, timing,
volume, opaque locators/tokens, live memory, service keys, availability, and
provider telemetry can remain visible. A malicious operator can suppress,
replay, delay, correlate, or refuse work within those limits.

The **Private** mode label remains outside stable-v1 until its non-collusion,
OHTTP placement, operator independence, lifecycle, and field evidence are
published. A RAM-backed discovery service is not a durable mailbox. One
founder-operated deployment is not plural infrastructure.

Official project operation follows the nonprofit public-benefit mission in
[ADR-0033](adr/0033-nonprofit-founder-stewardship.md). This is project policy,
not registered-charity status and not a restriction on independent AGPL
commercial use.

## 10. Exclusions

The following may remain implemented, experimental, or planned, but are not
part of the stable-v1 public contract unless this profile is formally revised:

- live audio or video calls;
- groups above 64 active accounts, MLS, public communities, and broadcast
  channels;
- anonymous messaging, metadata invisibility, traffic-analysis resistance, or
  protection from a global passive adversary;
- remote or forensic erasure, screenshot prevention, or permanent suppression
  of a person who creates another identity;
- guaranteed delivery, guaranteed background execution, or operation through
  every block, outage, device loss, or jammer;
- disappearing/view-once content, edits, polls, roles, moderation, semantic
  mentions, linked-device convenience, and advanced local organization as
  required golden-path features;
- Freenet-style carriers, cross-protocol federation, cryptocurrency-dependent
  operation, or mandatory project infrastructure;
- independent-audit, independent-interoperability, production-readiness, or
  high-risk-user claims until the exact evidence gate closes.

Excluded features must be visibly labelled Alpha or experimental, remain
isolated from the stable golden path, and fail without weakening this profile.
