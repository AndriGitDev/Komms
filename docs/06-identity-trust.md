# 06 — Identity & Trust

KommsKult has no accounts, no registration, and no mandatory identifiers. **The keypair is
the identity.** Everything in this document follows from that.

## 1. Identity

A user's identity is the Ed25519 identity public key `IK` (with its cross-signed X25519
counterpart — [04 — Cryptography §2](04-cryptography.md)), generated on-device at first
launch. No network interaction, no phone number, no email, no name. Creating an identity
is free and instant; users may hold several (work/personal/disposable) and the protocol
neither knows nor cares.

Displayed identity = **kult address**: `kk1` + base32(multihash(IK)) — self-checking,
QR-friendly, and safe to print on a sticker.

## 2. Prekey bundles

To be reachable while offline, a user publishes a signed prekey bundle
([04 — Cryptography §3](04-cryptography.md)):

```
Bundle = { IK, SPK+sig, PQSPK+sig, [OPK...], relay hints, expiry }
```

Distribution channels, all equivalent in trust (the bundle is self-authenticating —
everything is signed by `IK`, so the channel only affects *availability*):

1. **DHT record** under `H(IK)` on the internet transport.
2. **Direct exchange**: QR code, BLE tap, file, or pasted text.
3. **Mesh broadcast**: compact bundle announcement on the Meshtastic port (rate-limited).

A tampered bundle fails signature verification; a *withheld* bundle (DHT censorship) is
worked around via channels 2–3. What no channel can prevent is a fabricated identity
claiming to be "Alice" — that's what verification is for.

## 3. Verification

Trust is established human-to-human, not by an authority:

| Method | Mechanics | Assurance |
|---|---|---|
| **QR scan** (primary) | In person, scan each other's safety QR ([04 §9](04-cryptography.md)). | Strong — binds key to person in front of you. |
| **Safety number compare** | Read the 60-digit number over a channel you already trust (a call, in person). | Strong if the channel is. |
| **Sticker/print** | kult address printed on a poster/card/leaflet — pull-based: you contact the address you physically obtained. | Good against remote MITM; matches activist distribution reality. |
| **TOFU** (default) | First contact pins the key; any later key change triggers a blocking warning. | Baseline — same model as SSH; honest about being unverified in the UI. |

Verification state (`unverified` / `verified` / `key-changed!`) is stored locally,
displayed persistently, and never synced anywhere.

## 4. Petnames

Global usernames require a global authority — excluded by design. Instead, **petnames**:
every contact's display name is a private, local label chosen by *you*. What the network
sees is only keys and tokens. A contact may *suggest* a display name inside the encrypted
channel (transmitted end-to-end, shown as "suggested: …" until accepted). No name
squatting, no impersonation surface, no takedown target.

## 5. Key lifecycle

- **Rotation**: `SPK`/`PQSPK` rotate weekly (automatic); `OPK`s replenish as consumed.
  Identity key rotation = new identity, announced through existing encrypted sessions
  (old key signs a transition statement to the new key; contacts migrate with a
  confirmation prompt).
- **Backup**: identity + storage keys export as an encrypted recovery file guarded by a
  BIP-39-style mnemonic. Losing both device and recovery file means the identity is gone
  — stated plainly in the UI. Sovereignty means no one else can recover it *for* you,
  including us. There is no "us" at runtime.
- **Revocation**: a signed revocation statement propagates through sessions and DHT;
  contacts mark the identity dead and refuse new sessions to it.

## 6. Multi-device (roadmap, M6)

Design direction (recorded now so M1–M5 don't paint us into a corner): each physical
device holds its own device keypair; the identity key signs a device manifest; sessions
are per-device (Sesame-style fan-out). Until then: one identity = one device, with the
encrypted-backup path for migration.

## 7. First-contact abuse controls

Open reachability invites spam (threat model non-goal #4). Local, user-controlled
mitigations — no central moderator exists:

- **Contact gating** (default): unknown-sender messages land in a request queue showing
  only a size-bounded intro; the ratchet session completes only on accept.
- **Introduction cost**: senders attach a small proof-of-work over (their `IK` ‖ recipient
  token ‖ day) to first-contact envelopes; free for humans, expensive at spam scale.
  Contacts-of-contacts can include a signed introduction voucher instead.
- **Local blocklists**, exportable/shareable as signed lists users may *choose* to
  subscribe to — community moderation without central authority.
