# ADR-0011: Mnemonic-sealed backup files; sessions reset, never exported

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
icons), and `KKR4` adds sealed note-to-self history. Restore remains
backward-compatible with all earlier payload shapes;
live cryptographic/session state and re-creatable caches remain excluded.

**Contents**: identity, contacts (bundles, hints, petnames, verification
state), full message history, and the peers holding a live session at export
time, recorded as **session-reset markers**. Excluded on purpose: ratchet
state (resurrecting old message keys is a correctness and security hazard),
own prekey secrets (a restored vault must never honor a one-time prekey
twice), queues and stashes (in-flight envelopes belong to the dead sessions;
the senders' end-to-end retries are the source of reliability).

**Restore** (`kult-node`): builds a fresh store under a new passphrase, mints
a fresh prekey vault, and on the first tick turns each reset marker into a
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

- `kult`/`kultd` gain `backup` (RPC + CLI, file written 0600, mnemonic shown
  exactly once) and `--restore FILE` first-run startup; `kult-ffi` mirrors
  both (`export_backup`, `restore` constructor), so every shell inherits the
  feature: the M5 "backup/restore round-trips" acceptance line is now code.
- Messages in flight across a restore are honestly lost (their session died
  with the old device); senders see undelivered states and their retries ride
  the fresh session after the automatic re-key. No fake continuity.
- A restored node listens on new addresses; peers with stale hints reach it
  again via the DHT republish (or out-of-band, as the tests do). Hint
  staleness is a pre-existing property of moving devices, not introduced here.
- Anyone holding both the file and the phrase owns the identity; the docs
  already state this trade plainly (06 §5: no one can recover it *for* you,
  including us).
