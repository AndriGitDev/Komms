//! KommsKult protocol layer.
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
//! - [`ReceiptPayload`] — end-to-end encrypted delivery receipts and
//!   fragment NACKs.
//!
//! This crate never touches key material directly — only opaque values
//! handed over by `kult-crypto` — and performs no I/O.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod bundle;
mod envelope;
mod error;
mod fragmentation;
mod padding;
mod receipt;
mod token;

pub use bundle::{bundle_export, bundle_import, BUNDLE_MAGIC};
pub use envelope::{Envelope, EnvelopeKind, ENVELOPE_HEADER_LEN};
pub use error::ProtocolError;
pub use fragmentation::{fragment, Reassembler, FRAG_HEADER_LEN, REASSEMBLY_WINDOW_SECS};
pub use padding::{pad, unpad, PAD_BUCKETS};
pub use receipt::ReceiptPayload;
pub use token::{delivery_token, epoch_day, intro_token, MailboxKey};

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = core::result::Result<T, ProtocolError>;
