# 06: Identity & Trust

Komms has no accounts, no registration, and no mandatory identifiers. **The keypair is
the identity.** Everything in this document follows from that.

## 1. Identity

A user's identity is the Ed25519 identity public key `IK` (with its cross-signed X25519
counterpart, [04: Cryptography §2](04-cryptography.md)), generated on-device at first
launch. No network interaction, no phone number, no email, no name. Creating an identity
is free and instant; users may hold several (work/personal/disposable) and the protocol
neither knows nor cares.

Displayed identity fingerprint = **kult address**: `kk1` +
base32(multihash(IK)), self-checking and stable. It remains the safety-number
input, but it is not the normal reachability artifact.

Displayed first-contact artifact = **Connect code**: `kc2` plus a canonical
base32 payload containing the stable account digest, a random 32-byte discovery
capability, and checksum. The capability is a rotatable bearer reachability
secret. Rotating it leaves `IK`, the kult address, and every safety number
unchanged. Publishing a Connect code makes the account reachable to its
holders; it does not promise anonymity.

## 2. Prekey bundles

To be reachable while offline, a user publishes a signed prekey bundle
([04: Cryptography §3](04-cryptography.md)):

```
DiscoveryRecord = {
  capability-derived locator, epoch, generation, issue/expiry,
  account IK, complete device-authority proof,
  up to two certified-device SPK/PQSPK bundles,
  admission policy, up to three introduction mailboxes,
  zero padding, complete active-device signature
}
```

Distribution channels are equivalent in authentication once the complete
account/device proof verifies; the channel still affects *availability* and
metadata:

1. **DHT record** under a weekly locator derived from the Connect capability.
2. **Direct exchange**: Connect QR/link/file, pairing QR, BLE tap, or pasted text.
3. **Mesh broadcast**: compact bundle announcement on the Meshtastic port (rate-limited).

The version-two direct pairing artifact binds the complete certified-device
prekey bundle, current discovery capability, and capability generation under
an active physical-device signature. This lets an offline recipient's selected
mailbox recognize the first capability-derived introduction token without
re-enabling the stable identity-derived legacy token. A raw `KDP2` bundle
remains accepted for compatibility but carries no new-profile offline
introduction authority.

A tampered, wrong-recipient, wrong-locator, stale, revoked, forked, or
non-canonical record fails closed; a *withheld* record (DHT censorship) is
worked around via alternate DHT paths, introduction mailboxes, or channels
2–3. What no channel can prevent is a fabricated identity claiming to be
"Alice". That's what verification is for.

The v2 DHT value has one exact encrypted size, carries no OPK or direct route in
Standard/Private modes, and accepts at most eight candidates per locator. A
Sovereign user may publish a direct route only after an explicit warning that
every Connect-code holder can poll it. After pairing, contacts use
authenticated route controls, selected mailboxes, and optional pairwise
rendezvous rather than returning to identity-indexed public lookup.

Optional rendezvous is deliberately absent from this first-contact list. Under
[ADR-0018](adr/0018-pairwise-rendezvous.md), an authenticated session derives
provider- and direction-specific rotating slots only after pairing. Native-wake
capabilities under [ADR-0019](adr/0019-native-wake-gateway.md) are likewise sent
inside that session. Neither capability is a username, public identity record,
or substitute for safety-number verification.

## 3. Verification

Trust is established human-to-human, not by an authority:

| Method | Mechanics | Assurance |
|---|---|---|
| **QR scan** (primary) | In person, scan each other's safety QR ([04 §9](04-cryptography.md)). | Strong: binds key to person in front of you. |
| **Safety number compare** | Read the 30-digit (~100-bit) number over a channel you already trust (a call, in person). | Strong if the channel is. |
| **Sticker/print** | kult address printed on a poster/card/leaflet, pull-based: you contact the address you physically obtained. | Good against remote MITM; matches activist distribution reality. |
| **TOFU** (default) | First contact pins the key; any later key change triggers a blocking warning. | Baseline: same model as SSH; honest about being unverified in the UI. |

Verification state (`unverified` / `verified` / `key-changed!`) is stored sealed,
displayed persistently, and never sent to the contact or a service. C2 can carry
it only inside an authenticated encrypted sync bundle to another authorized
device owned by the same account.

## 4. Petnames

Global usernames require a global authority, excluded by design. Instead, **petnames**:
every contact's display name is a private, local label chosen by *you*. B5 lets the
user rename an exact peer in every implemented interface. Names are NFC-normalized and
bounded; duplicates are valid because the peer key, never display text, is the
identity. Duplicate, mixed-script/confusable, bidirectional-control, and invisible-
character risks are shown for explicit review before a warned rename. The label is
stored only in the sealed contact record, survives restart and `KKR10`, and creates no
message, capability, lookup, notification, queue, or transport work.

What the network sees remains keys and tokens, never the local petname. An optional
signed self-display suggestion is not implemented. It would be non-unique, could
never silently replace a local petname, and requires a separate bundle-format ADR and
compatibility path. See [15: Private Contact Names](15-contact-petnames.md).

## 5. Key lifecycle

- **Rotation**: `SPK`/`PQSPK` rotate weekly (automatic); `OPK`s replenish as consumed.
  Identity key rotation = new identity, announced through existing encrypted sessions
  (old key signs a transition statement to the new key; contacts migrate with a
  confirmation prompt).
- **Backup**: identity + storage keys export as an encrypted recovery file guarded by a
  BIP-39-style mnemonic. Losing both device and recovery file means the identity is gone,
  stated plainly in the UI. Sovereignty means no one else can recover it *for* you,
  including us. There is no "us" at runtime.
- **Revocation**: a signed revocation statement propagates through sessions and DHT;
  contacts mark the identity dead and refuse new sessions to it.

## 6. Linked devices (C2, revocable-device Beta)

Each physical device holds its own certified device keypair. The stable account
root signs only genesis and an explicit offline recovery epoch. Routine
authority changes are bounded append-only `KDA2` transitions authorized by a
strict majority of the previous active set. Every transition binds its parent,
generation, complete next active/revoked set, new immutable certificates, kind,
id, and signatures. Forks and same-epoch recovery conflicts are visible and
fail closed.

PQXDH/Double Ratchet sessions, device secrets, delivery rows, and group sender
chains remain per physical device. Linking a pristine installation requires a
time-bounded offer, scan/compare/confirm on both sides, and an additional-device
approval only when the previous active-set quorum requires it. Neither the
package nor any live store receives the account root.

The account root lives only in separately exported encrypted offline recovery
material. Recovery opens it transiently to revoke the entire former active set,
advance the recovery epoch, create one fresh device, and rotate live service,
session, delivery, rendezvous, wake, and group-chain state. Descendants of the
old epoch are rejected. Routine `KKR10` backup is root-free and separately
requires that offline authority for stable-identity restore.

Authenticated explicit device-to-device bundles converge contacts and
verification, private organization, ordinary history, edits, polls, group
authority, and terminal expiry tombstones. Drafts, scheduled outbox rows, live
queues/ratchets, active ephemeral content, downloaded media, and most shell
preferences remain installation-local. See [22: Linked Devices](22-linked-devices.md)
and the offline-root authority contract in
[ADR-0026](adr/0026-revocable-device-authority.md).

## 7. First-contact abuse controls

[ADR-0030](adr/0030-first-contact-admission.md) is accepted and implemented for
Beta:

- a signed, expiring recipient policy advertises a bounded client puzzle for
  unsolicited public-address contact;
- authenticated QR/link/file invitations may bypass visible puzzle work;
- carrier and node byte, item, concurrency, KEM, disk, notification, and
  per-tick budgets reject excess work before it becomes an unbounded queue;
- a valid stranger enters a sealed, fixed-size provisional request inbox and
  becomes a normal contact only after explicit acceptance;
- reject, block, group-invite consent, and optional signed reputation lists are
  local, inspectable state transitions rather than central moderation; and
- ordinary UI presents this as a familiar message request while technical
  admission details remain in diagnostics.

The implemented path binds the descriptor, exact target bundle, invitation or
puzzle proof, expiry, and content id before ML-KEM work where possible. Direct
next-hop acceptance waits for the atomic provisional stage or another complete
durable transition. Accept promotes the request atomically; Delete retains
only a bounded replay tombstone; Block also persists the exact account/device
rule and removes the provisional row without claiming remote deletion. Group
invitations use the same explicit consent boundary. The current evidence
includes Rust, RPC, UniFFI, desktop, Android host, and iOS simulator tests;
physical-device battery/background/accessibility qualification and independent
adversarial review remain open.

Puzzle work only raises unsolicited-sender cost and does not defeat a
distributed adversary; fixed count, byte, work, time, carrier, and concurrency
quotas remain the controlling safety boundary. Optional signed reputation
inputs remain unimplemented and are not required for the consent boundary.
