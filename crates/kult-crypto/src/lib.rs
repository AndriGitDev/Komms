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

mod admission;
mod anonbox;
mod attachment;
mod call;
mod device;
mod device_authority;
mod device_link_authority;
mod error;
mod fingerprint;
mod group;
mod handshake;
mod identity;
mod kdf;
mod mnemonic;
mod prekeys;
mod ratchet;
mod recovery_authority;
mod sealed;
mod util;
mod wordlist;

pub use admission::{
    admission_bundle_digest, is_admission_extension, AdmissionDescriptor, AdmissionPolicy,
    AdmissionPuzzleProfile, VerifiedAdmission, ADMISSION_DESCRIPTOR_VERSION, ADMISSION_EPOCH_SECS,
    DEFAULT_ADMISSION_CLOCK_SKEW_SECS, DEFAULT_ADMISSION_DIFFICULTY,
    DEFAULT_ADMISSION_FIRST_CIPHERTEXT, MAX_ADMISSION_CLOCK_SKEW_SECS,
    MAX_ADMISSION_DESCRIPTOR_BYTES, MAX_ADMISSION_DIFFICULTY, MAX_ADMISSION_FIRST_CIPHERTEXT,
    MAX_ADMISSION_TOKEN_ISSUERS, MIN_ADMISSION_DIFFICULTY,
};
pub use anonbox::{open_anonymous, seal_anonymous};
pub use attachment::{
    attachment_pairwise_scope_id, open_attachment_chunk, seal_attachment_chunk,
    AttachmentChunkContext, AttachmentChunkScope, ATTACHMENT_CHUNK_DATA_LEN,
    ATTACHMENT_CHUNK_PLAINTEXT_LEN, ATTACHMENT_SEALED_CHUNK_LEN,
};
pub use call::{
    call_media_record_len, CallMediaContext, CallMediaFrame, CallMediaKind, CallMediaReceiver,
    CallMediaSender, CallRole, CALL_MEDIA_HEADER_LEN, CALL_MEDIA_MAGIC,
    CALL_MEDIA_RECORDS_PER_KEY_PHASE, CALL_MEDIA_REPLAY_WINDOW, CALL_MEDIA_TAG_LEN,
    MAX_CALL_MEDIA_FRAME_LEN, MAX_CALL_MEDIA_PAYLOAD_LEN,
};
pub use device::{
    DeviceCertificate, DeviceManifest, DeviceManifestEntry, DevicePrekeyBundle,
    MAX_DEVICE_MANIFEST_ENTRIES, MAX_DEVICE_NAME_BYTES, MAX_LINKED_DEVICES,
};
pub use device_authority::{
    DeviceAuthorityAuthorization, DeviceAuthorityCertificate, DeviceAuthorityEntry,
    DeviceAuthorityManifest, DeviceAuthorityRelation, DeviceAuthorityRootSignature,
    DeviceAuthoritySignature, DeviceAuthorityTransition, DeviceAuthorityTransitionKind,
    DEVICE_AUTHORITY_VERSION, MAX_AUTHORITY_DEVICES, MAX_AUTHORITY_DEVICE_NAME_BYTES,
    MAX_AUTHORITY_ENTRIES, MAX_DEVICE_AUTHORITY_BYTES, MAX_DEVICE_AUTHORITY_TRANSITIONS,
};
pub use device_link_authority::{
    seal_authority_device_link_recovery_package, ApprovedAuthorityDeviceLink,
    AuthorityDeviceLinkApproval, AuthorityDeviceLinkApprovalRequest, AuthorityDeviceLinkCode,
    AuthorityDeviceLinkOffer, AuthorityDeviceLinkResponse, AuthorityDevicePrekeyBundle,
    CompletedAuthorityDeviceLink, PendingAuthorityDeviceLinkSource,
    PendingAuthorityDeviceLinkTarget, PreparedAuthorityDeviceLink,
    MAX_AUTHORITY_LINK_TRANSFER_BYTES,
};
pub use error::CryptoError;
pub use fingerprint::{safety_number, SafetyNumber};
pub use group::{
    group_origin_tag, GroupHeaderKey, GroupMessage, GroupMessageHeader, GroupOriginContext,
    GroupOriginEnvelope, GroupReceiverChain, GroupSenderChain, GROUP_MAX_SKIP,
    GROUP_MAX_STORED_SKIPPED, GROUP_MESSAGE_VERSION_LEGACY, GROUP_MESSAGE_VERSION_ORIGIN,
    GROUP_ORIGIN_ENVELOPE_MAGIC, GROUP_ORIGIN_TAG_LEN, GROUP_SKIPPED_TTL_SECS,
};
pub use handshake::{initiate, respond, InitialMessage};
pub use identity::{
    parse_address, verify_group_admin_request_signature, verify_group_authority_state_signature,
    verify_group_owner_transfer_signature, verify_group_poll_moderation_signature, Identity,
    IdentityPublic,
};
pub use kdf::{derive_kek, KdfProfile, KDF_PROFILE_DESKTOP, KDF_PROFILE_MOBILE};
pub use mnemonic::{mnemonic_from_entropy, mnemonic_to_entropy, MNEMONIC_WORDS};
pub use prekeys::{
    OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle, SignedPrekeySecret, VerifiedBundle,
    MAX_PREKEY_BUNDLE_BYTES, MAX_PREKEY_RELAY_HINTS, MAX_PREKEY_RELAY_HINT_BYTES,
    MAX_PREKEY_RELAY_HINT_TOTAL_BYTES, MLKEM768_CT_LEN, MLKEM768_DK_LEN, MLKEM768_EK_LEN,
};
pub use ratchet::{RatchetMessage, Session};
pub use ratchet::{MAX_SKIP, MAX_STORED_SKIPPED, SKIPPED_KEY_TTL_SECS};
pub use recovery_authority::{
    account_recovery_authority_public, open_account_recovery_authority,
    seal_account_recovery_authority, ACCOUNT_RECOVERY_AUTHORITY_VERSION,
    MAX_ACCOUNT_RECOVERY_AUTHORITY_BYTES,
};
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
