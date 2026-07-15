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

mod attachment;
mod attachment_bulk;
mod bundle;
mod capability;
mod content;
mod envelope;
mod error;
mod fragmentation;
mod group;
mod mention;
mod padding;
mod receipt;
mod token;

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
pub use bundle::{bundle_export, bundle_import, BUNDLE_MAGIC};
pub use capability::{
    is_capability_control, CapabilityControl, FormatCapabilities, CAPABILITY_CONTROL_VERSION,
    CAPABILITY_MAGIC, MAX_CAPABILITY_FORMATS, MAX_CAPABILITY_KINDS,
};
pub use content::{
    decode_content, encode_attachment, encode_mention, encode_text, DecodedContent,
    CONTENT_FORMAT_V1, CONTENT_HEADER_LEN, CONTENT_KIND_ATTACHMENT, CONTENT_KIND_MENTION,
    CONTENT_KIND_TEXT, CONTENT_MAGIC, MAX_COLLECTION_ENTRIES, MAX_CONTENT_FRAME_LEN,
    MAX_CONTENT_PAYLOAD_LEN, MAX_NESTING_DEPTH,
};
pub use envelope::{Envelope, EnvelopeKind, ENVELOPE_HEADER_LEN};
pub use error::ProtocolError;
pub use fragmentation::{fragment, Reassembler, FRAG_HEADER_LEN, REASSEMBLY_WINDOW_SECS};
pub use group::{GroupAnnounce, GroupControlPayload, GroupMemberInfo};
pub use mention::{
    decode_mention_payload, encode_mention_payload, DecodedMention, Mention, MentionSpan,
    MentionSpans, MentionTargets, MAX_MENTION_PAYLOAD_LEN, MAX_MENTION_SPANS, MAX_MENTION_TARGETS,
    MAX_MENTION_TEXT_LEN, MENTION_HEADER_LEN, MENTION_SPAN_LEN, MENTION_TARGET_LEN,
    MENTION_VERSION,
};
pub use padding::{pad, pad_to_minimum, unpad, PAD_BUCKETS};
pub use receipt::ReceiptPayload;
pub use token::{delivery_token, epoch_day, intro_token, MailboxKey};

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = core::result::Result<T, ProtocolError>;
