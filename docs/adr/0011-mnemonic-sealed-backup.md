# ADR-0011: Mnemonic-sealed root-free backup files; sessions reset, never exported

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

The storage spec (07 §4) and identity model (06 §5) promise an encrypted
single-file backup: identity + contacts + history + session-reset markers,
guarded by a BIP-39-style mnemonic, restoring on a new device with sessions
re-handshaking. Implementing it forces four shape decisions:

- **What seals the file, exactly?** "BIP-39-style mnemonic" names a UX, not a
  key schedule.
- **Where does the wordlist come from?** Every existing Rust mnemonic crate is
  a new supply-chain edge for what is, at bottom, 2048 frozen public-domain
  words and a checksum rule.
- **What happens to live ratchet sessions?** The spec says they are
  deliberately not portable, but the restored device must become reachable
  again *without* waiting for the user to send first: peers keep transmitting
  on ratchets the new device never held. ("Session-reset markers" existed in
  the spec with no defined mechanism.)
- **Can the archived prekey bundles even re-handshake?** A stored contact
  bundle's one-time prekey was consumed by the original handshake; the peer
  deleted its secret, so a re-handshake referencing it is silently dropped.

## Decision

**Format** (`KKR1`, in `kult-store`): `magic ‖ Argon2id cost params ‖ salt ‖
sealed(postcard payload)`. The mnemonic is the standard BIP-39 encoding of 32
random bytes (24 English words, SHA-256 checksum); that entropy feeds the
existing `derive_kek` (Argon2id, params carried in the header so a
mobile-profile export restores anywhere) and the sealed blob is an ordinary
`StorageKey` AEAD envelope. Wrong mnemonic and corrupted file are
indistinguishable: uniform AEAD failure, no oracle. The wordlist and codec
live in-tree in `kult-crypto` (`no_std`, KAT-tested against the reference
vectors); no new dependency.

The same header and AEAD construction is versioned by magic as payload domains
grow: `KKR2` added sender-key group identities/history, `KKR3` added F5
user-authored local metadata (organization, drafts, preferences, and custom
icons), `KKR4` added sealed note-to-self history, and `KKR5` added terminal C4
ephemeral tombstones while excluding live ephemeral plaintext/manifests/media.
`KKR6` added C6 signed group authority state and consumed admin-request ids.
Legacy `KKR7` added the copied-root linked-device authority, certified
endpoints, convergence winners, and recovery state. Accepted ADR-0026 adds
root-free `KKR8`: the public account trust anchor, accepted `KDA2` proof,
eligible user state, certified contact endpoints, convergence winners, and
terminal tombstones remain, while the account root and all reusable live
authority/delivery material are absent. `KKR1` through `KKR7` remain explicit
decode-only migration or new-identity-reset inputs; production code cannot mint
another copied-root file, silently relabel one as root-free, or allow one to
resume the former account. The legacy-only-artifact flow decrypts the copied
root in memory, projects the bounded local archive directly into a fresh
root-free sibling, and publishes no intermediate legacy store. Live
cryptographic/session state and re-creatable caches remain excluded.

**Contents**: public account identity, accepted device-authority proof,
contacts (bundles, hints, petnames, verification
state), ordinary message history, terminal C4 tombstones, signed C6 group
authority, linked-device endpoints/convergence state, and the peers holding a
live session at export time, recorded as **session-reset markers**. Excluded on
purpose: the account root, local/contact device private keys, ratchet state
(resurrecting old message keys is a correctness and security hazard), own
prekey secrets (a restored vault must never honor a one-time prekey twice),
group sender/receiver chains, link/sync channel roots, rendezvous/wake
capabilities, queues, wire ids, resumable delivery state, live ephemeral
history/manifests/media, and stashes. Queued or sent ordinary history remains
only as failed local history.

**Restore** (`kult-node`): requires the separately held `.kra` offline account
authority and its independent phrase in addition to the `KKR8` file and backup
phrase. It opens the root transiently, builds a fresh store under a new
passphrase, creates a higher recovery epoch with one fresh device, revokes the
former active set, and mints a fresh prekey vault. On the first tick each reset
marker becomes a
proactive re-handshake, an **empty first flight** the receiver treats as
session maintenance (no phantom message, no receipt), emitted through the
existing `SessionEstablished` event. Because the archived bundle's one-time
prekey is spent, reset-marked initiations use **OPK-less PQXDH**
(`VerifiedBundle::without_opk`), the same mode DHT-published bundles already
use, on both the tick path and a send racing ahead of it.

## Alternatives considered

- **Depend on a mnemonic crate** (`bip39`, `tiny-bip39`): rejected: the
  entire artifact is a frozen wordlist plus ~60 lines of bit-packing; a
  dependency adds audit surface and cargo-deny friction for zero code we'd
  keep.
- **Derive the backup key straight from the mnemonic via BIP-39's own
  PBKDF2 seed step**: rejected: PBKDF2-SHA512@2048 is far weaker than the
  Argon2id profile the store already standardizes on, and wallet-seed
  compatibility is a non-goal (this phrase guards a file, not a keychain).
- **Export ratchet sessions** so restore needs no re-handshake: rejected by
  the spec and by the ratchet contract: replayed/forked ratchet state can
  resurrect message keys and desynchronize both ends invisibly.
- **Lazy re-handshake only** (first outbound send re-keys, no markers):
  rejected: a restored user who only *receives* would silently miss
  everything until they happened to reply; peers' sends land on tokens the
  new device cannot ever claim.
- **Full-database file copy as the backup**: rejected: it drags sessions,
  prekeys, and queues along (all wrong, above), pins the backup to the store
  passphrase instead of a mnemonic, and turns every schema change into a
  restore-compatibility hazard; a typed payload is the documented, versioned
  export format the spec demands.

## Consequences

- `kult`/`kultd` expose root-free backup plus separate offline-authority export
  and restore inputs (files written 0600 and phrases shown exactly once);
  `kult-ffi` mirrors them through `export_backup`,
  `export_account_recovery_authority`, and the `restore` constructor, so every
  shell inherits the same separation.
- Messages in flight across a restore are honestly lost (their session died
  with the old device); senders see undelivered states and their retries ride
  the fresh session after the automatic re-key. No fake continuity.
- A restored node listens on new addresses; peers with stale hints reach it
  again via the DHT republish (or out-of-band, as the tests do). Hint
  staleness is a pre-existing property of moving devices, not introduced here.
- Anyone holding a `KKR8` file and its phrase can read the eligible backup
  content but cannot authorize the stable identity without the separately held
  recovery authority. Anyone holding the `.kra` file and its phrase controls
  the identity and can revoke every device. No service can recover either pair
  for the user.
