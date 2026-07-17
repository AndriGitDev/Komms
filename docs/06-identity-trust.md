# 06: Identity & Trust

Komms has no accounts, no registration, and no mandatory identifiers. **The keypair is
the identity.** Everything in this document follows from that.

## 1. Identity

A user's identity is the Ed25519 identity public key `IK` (with its cross-signed X25519
counterpart, [04: Cryptography §2](04-cryptography.md)), generated on-device at first
launch. No network interaction, no phone number, no email, no name. Creating an identity
is free and instant; users may hold several (work/personal/disposable) and the protocol
neither knows nor cares.

Displayed identity = **kult address**: `kk1` + base32(multihash(IK)), self-checking,
QR-friendly, and safe to print on a sticker.

## 2. Prekey bundles

To be reachable while offline, a user publishes a signed prekey bundle
([04: Cryptography §3](04-cryptography.md)):

```
Bundle = { IK, SPK+sig, PQSPK+sig, [OPK...], relay hints, expiry }
```

Distribution channels, all equivalent in trust (the bundle is self-authenticating,
everything is signed by `IK`, so the channel only affects *availability*):

1. **DHT record** under `H(IK)` on the internet transport.
2. **Direct exchange**: QR code, BLE tap, file, or pasted text.
3. **Mesh broadcast**: compact bundle announcement on the Meshtastic port (rate-limited).

A tampered bundle fails signature verification; a *withheld* bundle (DHT censorship) is
worked around via channels 2–3. What no channel can prevent is a fabricated identity
claiming to be "Alice". That's what verification is for.

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
| **Safety number compare** | Read the 60-digit number over a channel you already trust (a call, in person). | Strong if the channel is. |
| **Sticker/print** | kult address printed on a poster/card/leaflet, pull-based: you contact the address you physically obtained. | Good against remote MITM; matches activist distribution reality. |
| **TOFU** (default) | First contact pins the key; any later key change triggers a blocking warning. | Baseline: same model as SSH; honest about being unverified in the UI. |

Verification state (`unverified` / `verified` / `key-changed!`) is stored locally,
displayed persistently, and never synced anywhere.

## 4. Petnames

Global usernames require a global authority, excluded by design. Instead, **petnames**:
every contact's display name is a private, local label chosen by *you*. B5 lets the
user rename an exact peer in every shipped interface. Names are NFC-normalized and
bounded; duplicates are valid because the peer key, never display text, is the
identity. Duplicate, mixed-script/confusable, bidirectional-control, and invisible-
character risks are shown for explicit review before a warned rename. The label is
stored only in the sealed contact record, survives restart and `KKR6`, and creates no
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

## 6. Multi-device (roadmap, M6)

Design direction for C2: each physical device holds its own device keypair; the
identity key signs a device manifest; sessions are per-device (Sesame-style
fan-out). The shipped contract remains one identity = one active device, with
the encrypted-backup path for migration. No current shell silently synchronizes
folders, labels, drafts, or other local organization.

## 7. First-contact abuse controls

Open reachability invites spam (threat model non-goal #4). Local, user-controlled
mitigations (no central moderator exists):

- **Contact gating** (default): unknown-sender messages land in a request queue showing
  only a size-bounded intro; the ratchet session completes only on accept.
- **Introduction cost**: senders attach a small proof-of-work over (their `IK` ‖ recipient
  token ‖ day) to first-contact envelopes; free for humans, expensive at spam scale.
  Contacts-of-contacts can include a signed introduction voucher instead.
- **Local blocklists**, exportable/shareable as signed lists users may *choose* to
  subscribe to: community moderation without central authority.
