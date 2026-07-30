//! Komms protocol layer.
//!
//! Everything between the crypto core and the transports:
//!
//! - [`Envelope`] — the only unit transports ever carry (spec §5),
//! - [`pad`] / [`unpad`] — size-bucket padding (spec §5),
//! - [`fragment`] / [`Reassembler`] — small-MTU links (LoRa ≈ 200 B,
//!   docs/05-transports.md §4.2),
//! - [`delivery_token`] / [`intro_token`] — sealed-sender addressing (spec §7),
//! - [`bundle_export`] / [`bundle_import`] — `.kkb` sneakernet bundles
//!   (docs/05-transports.md §5),
//! - [`decode_content`] / [`encode_text`] — versioned, encrypted message
//!   content with permanent legacy-text fallback (ADR-0014),
//! - [`CapabilityControl`] — authenticated content capability negotiation
//!   over the encrypted receipt lane (ADR-0014),
//! - [`ReceiptPayload`] — end-to-end encrypted delivery receipts and
//!   fragment NACKs.
//!
//! This crate never touches key material directly — only opaque values
//! handed over by `kult-crypto` — and performs no I/O.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod admission;
mod attachment;
mod attachment_bulk;
mod bundle;
mod call;
mod capability;
mod content;
mod device_sync;
mod discovery;
mod edit;
mod envelope;
mod ephemeral;
mod error;
mod fragmentation;
mod group;
mod group_authority;
mod mention;
mod padding;
mod poll;
mod receipt;
mod rendezvous;
mod token;
mod wake;

pub use admission::{
    admission_invitation_proof, solve_admission_puzzle, verify_admission_puzzle, AdmissionContext,
    AdmissionEnvelope, AdmissionProofKind, ADMISSION_ENVELOPE_HEADER_LEN,
    ADMISSION_ENVELOPE_VERSION, MAX_ADMISSION_ENVELOPE_BYTES, MAX_ADMISSION_PUZZLE_ATTEMPTS,
    MAX_ADMISSION_SEALED_FLIGHT_BYTES, MAX_ADMISSION_TARGET_BUNDLE_BYTES,
};
pub use attachment::{
    attachment_chunk_count, decode_attachment_manifest, encode_attachment_manifest,
    AttachmentManifest, AttachmentObject, AttachmentRole, DecodedAttachmentManifest,
    ATTACHMENT_CHUNK_DATA_LEN, ATTACHMENT_MANIFEST_VERSION, MAX_ATTACHMENT_FILENAME_LEN,
    MAX_ATTACHMENT_MANIFEST_LEN, MAX_ATTACHMENT_MEDIA_TYPE_LEN, MAX_PREVIEW_CHUNKS,
    MAX_PREVIEW_OBJECT_LEN, MAX_PRIMARY_CHUNKS, MAX_PRIMARY_OBJECT_LEN,
};
pub use attachment_bulk::{
    decode_attachment_bulk_record, encode_attachment_bulk_record, is_attachment_bulk_record,
    validate_missing_ranges, AttachmentBulkOperation, AttachmentBulkRecord, AttachmentReason,
    AttachmentScope, DecodedAttachmentBulkRecord, MissingRange, ATTACHMENT_BULK_HEADER_LEN,
    ATTACHMENT_BULK_MAGIC, ATTACHMENT_BULK_VERSION, ATTACHMENT_CHUNK_PLAINTEXT_LEN,
    ATTACHMENT_SEALED_CHUNK_LEN, MAX_ATTACHMENT_BULK_LEN, MAX_MISSING_RANGES,
};
pub use bundle::{
    bundle_export, bundle_import, BUNDLE_MAGIC, MAX_BUNDLE_BYTES, MAX_BUNDLE_ENVELOPES,
};
pub use call::{
    decode_call_control_payload, encode_call_control_payload, CallControl, CallHangupReason,
    DecodedCallControl, CALL_CONTROL_BOUND_LEN, CALL_CONTROL_HANGUP_LEN, CALL_CONTROL_HEADER_LEN,
    CALL_CONTROL_VERSION, MAX_CALL_CONTROL_LEN,
};
pub use capability::{
    is_capability_control, CapabilityControl, FormatCapabilities, CAPABILITY_CONTROL_VERSION,
    CAPABILITY_MAGIC, GROUP_ORIGIN_CAPABILITY_FORMAT, GROUP_ORIGIN_CAPABILITY_KIND,
    MAX_CAPABILITY_FORMATS, MAX_CAPABILITY_KINDS,
};
pub use content::{
    decode_content, encode_attachment, encode_call_control, encode_edit, encode_ephemeral,
    encode_group_authority, encode_mention, encode_poll, encode_text, DecodedContent,
    CONTENT_FORMAT_V1, CONTENT_HEADER_LEN, CONTENT_KIND_ATTACHMENT, CONTENT_KIND_CALL_CONTROL,
    CONTENT_KIND_EDIT, CONTENT_KIND_EPHEMERAL, CONTENT_KIND_GROUP_AUTHORITY, CONTENT_KIND_MENTION,
    CONTENT_KIND_POLL, CONTENT_KIND_TEXT, CONTENT_MAGIC, MAX_COLLECTION_ENTRIES,
    MAX_CONTENT_FRAME_LEN, MAX_CONTENT_PAYLOAD_LEN, MAX_NESTING_DEPTH,
};
pub use device_sync::{
    resolve_device_sync_events, AuthorityDeviceSyncBundle, DeviceSyncAuthority, DeviceSyncBundle,
    DeviceSyncEvent, DeviceSyncNamespace, OpenedAuthorityDeviceSyncBundle, OpenedDeviceSyncBundle,
    MAX_DEVICE_SYNC_BUNDLE_BYTES, MAX_DEVICE_SYNC_BUNDLE_EVENTS, MAX_DEVICE_SYNC_KEY_BYTES,
    MAX_DEVICE_SYNC_VALUE_BYTES,
};
pub use discovery::{
    is_discovery_upgrade_control, DiscoveryUpgradeControl, DISCOVERY_UPGRADE_MAGIC,
    DISCOVERY_UPGRADE_VERSION, MAX_DISCOVERY_UPGRADE_ROUTES, MAX_DISCOVERY_UPGRADE_ROUTE_BYTES,
};
pub use edit::{
    decode_edit_payload, encode_edit_payload, DecodedEdit, Edit, EDIT_HEADER_LEN,
    MAX_EDIT_PAYLOAD_LEN, MAX_EDIT_TEXT_LEN,
};
pub use envelope::{
    Envelope, EnvelopeKind, ENVELOPE_HEADER_LEN, ENVELOPE_V1_HEADER_LEN, ENVELOPE_V2_HEADER_LEN,
    ENVELOPE_VERSION_V1, ENVELOPE_VERSION_V2, MAX_ENVELOPE_BYTES,
};
pub use ephemeral::{
    decode_ephemeral_payload, encode_disappearing_text_payload,
    encode_view_once_attachment_payload, retention_bucket, DecodedEphemeral, Ephemeral,
    EPHEMERAL_HEADER_LEN, MAX_EPHEMERAL_LIFETIME_SECS, MAX_EPHEMERAL_PAYLOAD_LEN,
    MIN_EPHEMERAL_LIFETIME_SECS, RETENTION_BUCKET_SECS,
};
pub use error::ProtocolError;
pub use fragmentation::{
    fragment, Reassembler, FRAG_HEADER_LEN, MAX_FRAGMENTS, REASSEMBLY_WINDOW_SECS,
};
pub use group::{
    group_admin_request_signing_bytes, GroupAdminAction, GroupAdminRequest, GroupAdminResult,
    GroupAnnounce, GroupAuthorityAnnounce, GroupControlPayload, GroupMemberInfo,
    GroupOriginAnnounce, GroupOriginAuthorityAnnounce, MAX_GROUP_ADMIN_REQUESTS,
};
pub use group_authority::{
    decode_group_authority, encode_group_authority_state, group_authority_state_signing_bytes,
    owner_transfer_device_signing_bytes, owner_transfer_signing_bytes, DecodedGroupAuthority,
    GroupAuthorityMember, GroupRole, OwnerTransferCertificate, SignedGroupAuthorityState,
    GROUP_AUTHORITY_VERSION, LEGACY_GROUP_AUTHORITY_VERSION, MAX_GROUP_AUTHORITY_MEMBERS,
    MAX_GROUP_AUTHORITY_STATE_BYTES, MAX_GROUP_DEVICE_AUTHORITY_BYTES,
    MAX_GROUP_MEMBER_IDENTITY_LEN, MAX_GROUP_NAME_LEN,
};
pub use mention::{
    decode_mention_payload, encode_mention_payload, DecodedMention, Mention, MentionSpan,
    MentionSpans, MentionTargets, MAX_MENTION_PAYLOAD_LEN, MAX_MENTION_SPANS, MAX_MENTION_TARGETS,
    MAX_MENTION_TEXT_LEN, MENTION_HEADER_LEN, MENTION_SPAN_LEN, MENTION_TARGET_LEN,
    MENTION_VERSION,
};
pub use padding::{pad, pad_to_minimum, unpad, PAD_BUCKETS};
pub use poll::{
    decode_poll_payload, encode_poll_close_payload, encode_poll_create_payload,
    encode_poll_moderated_close_payload, encode_poll_vote_payload, poll_moderation_signing_bytes,
    DecodedPoll, Poll, PollClose, PollCreate, PollModeratedClose, PollOption, PollOptions,
    PollVote, PollVoteHead, PollVoteHeads, PollVoters, MAX_POLL_OPTIONS, MAX_POLL_OPTION_TEXT_LEN,
    MAX_POLL_QUESTION_LEN, MAX_POLL_VOTERS, MIN_POLL_OPTIONS, POLL_CLOSE_MANUAL, POLL_VERSION,
};
pub use receipt::ReceiptPayload;
pub use rendezvous::{
    is_rendezvous_provider_control, RendezvousLookupRequest, RendezvousProviderControl,
    RendezvousProviderDescriptor, RendezvousRegisterRequest, RendezvousRoute, RendezvousRouteKind,
    RendezvousRouteRecord, MAX_RENDEZVOUS_CONTROL_ORIGIN_BYTES, MAX_RENDEZVOUS_CONTROL_PROVIDERS,
    MAX_RENDEZVOUS_PROVIDER_CONTROL_BYTES, MAX_RENDEZVOUS_ROUTES, MAX_RENDEZVOUS_ROUTE_BYTES,
    RENDEZVOUS_CLOCK_SKEW_SECS, RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_LOOKUP_REQUEST_LEN,
    RENDEZVOUS_LOOKUP_RESPONSE_LEN, RENDEZVOUS_MALFORMED_RESPONSE_LEN, RENDEZVOUS_MEDIA_TYPE,
    RENDEZVOUS_PROVIDER_CONTROL_MAGIC, RENDEZVOUS_PROVIDER_CONTROL_VERSION,
    RENDEZVOUS_REGISTER_ACK_LEN, RENDEZVOUS_REGISTER_PATH, RENDEZVOUS_REGISTER_REQUEST_LEN,
    RENDEZVOUS_ROUTE_RECORD_VERSION,
};
pub use token::{delivery_token, epoch_day, intro_token, MailboxKey};
pub use wake::{
    canonical_wake_https_origin, is_wake_capability_control, verify_wake_generic_response,
    wake_generic_response, wake_provider_id, WakeCapability, WakeCapabilityControl,
    WakeCapabilityDescriptor, WakeCapabilityPayload, WakeEnvironment, WakePlatform, WakeProfile,
    WakeRegisterRequest, WakeRegisterResponse, WakeTriggerRequest, MAX_WAKE_APP_TOPIC_BYTES,
    MAX_WAKE_CAPABILITY_CONTROL_BYTES, MAX_WAKE_CONTROL_CAPABILITIES,
    MAX_WAKE_CONTROL_ORIGIN_BYTES, MAX_WAKE_PROVIDER_TOKEN_BYTES, WAKE_CAPABILITY_ASSOCIATED_DATA,
    WAKE_CAPABILITY_CONTROL_MAGIC, WAKE_CAPABILITY_CONTROL_VERSION, WAKE_CAPABILITY_LEN,
    WAKE_CAPABILITY_MAX_LIFETIME_SECS, WAKE_CAPABILITY_PLAINTEXT_LEN, WAKE_GENERIC_RESPONSE_LEN,
    WAKE_MEDIA_TYPE, WAKE_REGISTER_PATH, WAKE_REGISTER_REQUEST_LEN, WAKE_REGISTER_RESPONSE_LEN,
    WAKE_REVOKE_PATH, WAKE_TRIGGER_PATH, WAKE_TRIGGER_REQUEST_LEN, WAKE_VERSION,
};

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = core::result::Result<T, ProtocolError>;
