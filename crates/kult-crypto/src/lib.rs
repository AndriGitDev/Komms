//! Komms cryptographic core.
//!
//! Implements the normative specification in `docs/04-cryptography.md`:
//!
//! - identity keys ([`Identity`], [`IdentityPublic`]) and kult addresses,
//! - signed prekey bundles ([`PrekeyBundle`]),
//! - the hybrid post-quantum PQXDH handshake ([`initiate`] / [`respond`]),
//! - Double Ratchet sessions with encrypted headers ([`Session`]),
//! - safety-number fingerprints ([`safety_number`]),
//! - sealed (encrypted-at-rest) session state,
//! - the Argon2id key-derivation profiles for storage keys.
//!
//! This crate performs **no I/O** and holds no global state. All randomness is
//! supplied by the caller as `&mut impl CryptoRngCore`. All secret material is
//! zeroized on drop.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod anonbox;
mod error;
mod fingerprint;
mod group;
mod handshake;
mod identity;
mod kdf;
mod mnemonic;
mod prekeys;
mod ratchet;
mod sealed;
mod util;
mod wordlist;

pub use anonbox::{open_anonymous, seal_anonymous};
pub use error::CryptoError;
pub use fingerprint::{safety_number, SafetyNumber};
pub use group::{
    GroupHeaderKey, GroupMessage, GroupReceiverChain, GroupSenderChain, GROUP_MAX_SKIP,
    GROUP_MAX_STORED_SKIPPED, GROUP_SKIPPED_TTL_SECS,
};
pub use handshake::{initiate, respond, InitialMessage};
pub use identity::{parse_address, Identity, IdentityPublic};
pub use kdf::{derive_kek, KdfProfile, KDF_PROFILE_DESKTOP, KDF_PROFILE_MOBILE};
pub use mnemonic::{mnemonic_from_entropy, mnemonic_to_entropy, MNEMONIC_WORDS};
pub use prekeys::{
    OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle, SignedPrekeySecret, VerifiedBundle,
    MLKEM768_CT_LEN, MLKEM768_DK_LEN, MLKEM768_EK_LEN,
};
pub use ratchet::{RatchetMessage, Session};
pub use ratchet::{MAX_SKIP, MAX_STORED_SKIPPED, SKIPPED_KEY_TTL_SECS};
pub use sealed::StorageKey;

/// Protocol version tag mixed into every associated-data string.
pub const PROTOCOL_VERSION: u8 = 1;

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// BLAKE3 bulk hashing for large payloads (files, media chunks).
///
/// Protocol-critical hashing uses SHA-256 (see the spec); this is the fast
/// path for content addressing by higher layers.
pub fn bulk_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
