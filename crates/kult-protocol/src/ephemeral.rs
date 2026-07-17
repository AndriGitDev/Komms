//! Canonical disappearing-text and view-once attachment payloads (ADR-0021).

use alloc::vec::Vec;

use crate::{
    decode_attachment_manifest, encode_attachment_manifest, AttachmentManifest,
    DecodedAttachmentManifest, ProtocolError, Result,
};

/// One hour: the relay-visible retention hint granularity.
pub const RETENTION_BUCKET_SECS: u64 = 3_600;
/// Longest supported ephemeral lifetime (30 days).
pub const MAX_EPHEMERAL_LIFETIME_SECS: u64 = 30 * 86_400;
/// Shortest supported ephemeral lifetime.
pub const MIN_EPHEMERAL_LIFETIME_SECS: u64 = 60;
/// Fixed bytes before the mode-specific body.
pub const EPHEMERAL_HEADER_LEN: usize = 1 + 1 + 2 + 8 + 8 + 4;
/// Maximum canonical ephemeral payload length.
pub const MAX_EPHEMERAL_PAYLOAD_LEN: usize = EPHEMERAL_HEADER_LEN + crate::MAX_CONTENT_PAYLOAD_LEN;

const EPHEMERAL_VERSION: u8 = 1;
const MODE_DISAPPEARING_TEXT: u8 = 1;
const MODE_VIEW_ONCE_ATTACHMENT: u8 = 2;

/// Return the canonical coarse relay-visible ceiling for an exact deadline.
pub fn retention_bucket(expires_at: u64) -> Result<u64> {
    let remainder = expires_at % RETENTION_BUCKET_SECS;
    if remainder == 0 {
        Ok(expires_at)
    } else {
        expires_at
            .checked_add(RETENTION_BUCKET_SECS - remainder)
            .ok_or(ProtocolError::Malformed)
    }
}

/// Borrowed supported ephemeral content.
///
/// The manifest variant intentionally stays borrowed and allocation-free at the
/// decoder boundary; boxing it would add heap work to every untrusted decode.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ephemeral<'a> {
    /// UTF-8 removed from local history at the exact authenticated deadline.
    DisappearingText {
        /// Exact Unix-seconds local expiry.
        expires_at: u64,
        /// Canonical hour-ceiling relay retention hint.
        retention_until: u64,
        /// Exact authenticated UTF-8.
        text: &'a str,
    },
    /// Attachment whose locally decryptable source is consumed on first open.
    ViewOnceAttachment {
        /// Exact Unix-seconds fallback expiry if it is never opened.
        expires_at: u64,
        /// Canonical hour-ceiling relay retention hint.
        retention_until: u64,
        /// Canonical borrowed attachment manifest.
        manifest: AttachmentManifest<'a>,
    },
}

/// Total classification of an authenticated ephemeral payload.
///
/// This mirrors the allocation-free borrowed content classification above.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedEphemeral<'a> {
    /// Canonical supported payload.
    Ephemeral(Ephemeral<'a>),
    /// A future mode or payload version.
    Unsupported,
    /// Bytes violate ADR-0021.
    Malformed,
}

/// Encode disappearing UTF-8 with exact and coarse deadlines bound together.
pub fn encode_disappearing_text_payload(expires_at: u64, text: &str) -> Result<Vec<u8>> {
    if text.is_empty() || text.len() > crate::MAX_CONTENT_PAYLOAD_LEN - EPHEMERAL_HEADER_LEN {
        return Err(
            if text.len() > crate::MAX_CONTENT_PAYLOAD_LEN - EPHEMERAL_HEADER_LEN {
                ProtocolError::TooLarge
            } else {
                ProtocolError::Malformed
            },
        );
    }
    encode_payload(MODE_DISAPPEARING_TEXT, expires_at, text.as_bytes())
}

/// Encode a view-once attachment manifest with exact and coarse deadlines.
pub fn encode_view_once_attachment_payload(
    expires_at: u64,
    manifest: &AttachmentManifest<'_>,
) -> Result<Vec<u8>> {
    let body = encode_attachment_manifest(manifest)?;
    encode_payload(MODE_VIEW_ONCE_ATTACHMENT, expires_at, &body)
}

fn encode_payload(mode: u8, expires_at: u64, body: &[u8]) -> Result<Vec<u8>> {
    let retention_until = retention_bucket(expires_at)?;
    let total = EPHEMERAL_HEADER_LEN
        .checked_add(body.len())
        .ok_or(ProtocolError::TooLarge)?;
    if total > MAX_EPHEMERAL_PAYLOAD_LEN || body.len() > u32::MAX as usize {
        return Err(ProtocolError::TooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.push(EPHEMERAL_VERSION);
    out.push(mode);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&expires_at.to_le_bytes());
    out.extend_from_slice(&retention_until.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Decode without allocating and require the exact/hint canonical relation.
pub fn decode_ephemeral_payload(bytes: &[u8]) -> DecodedEphemeral<'_> {
    if bytes.len() < EPHEMERAL_HEADER_LEN || bytes.len() > MAX_EPHEMERAL_PAYLOAD_LEN {
        return DecodedEphemeral::Malformed;
    }
    if bytes[0] != EPHEMERAL_VERSION {
        return DecodedEphemeral::Unsupported;
    }
    if bytes[2..4] != [0, 0] {
        return DecodedEphemeral::Unsupported;
    }
    let expires_at = u64::from_le_bytes(bytes[4..12].try_into().expect("fixed slice"));
    let retention_until = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed slice"));
    let body_len = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice")) as usize;
    if expires_at == 0
        || retention_bucket(expires_at).ok() != Some(retention_until)
        || body_len != bytes.len() - EPHEMERAL_HEADER_LEN
    {
        return DecodedEphemeral::Malformed;
    }
    let body = &bytes[EPHEMERAL_HEADER_LEN..];
    match bytes[1] {
        MODE_DISAPPEARING_TEXT => match core::str::from_utf8(body) {
            Ok(text) if !text.is_empty() => {
                DecodedEphemeral::Ephemeral(Ephemeral::DisappearingText {
                    expires_at,
                    retention_until,
                    text,
                })
            }
            _ => DecodedEphemeral::Malformed,
        },
        MODE_VIEW_ONCE_ATTACHMENT => match decode_attachment_manifest(body) {
            DecodedAttachmentManifest::Manifest(manifest) => {
                DecodedEphemeral::Ephemeral(Ephemeral::ViewOnceAttachment {
                    expires_at,
                    retention_until,
                    manifest,
                })
            }
            DecodedAttachmentManifest::Unsupported => DecodedEphemeral::Unsupported,
            DecodedAttachmentManifest::Malformed => DecodedEphemeral::Malformed,
        },
        _ => DecodedEphemeral::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn disappearing_text_round_trip_and_bucket_boundary() {
        let expires_at = 1_800_000_001;
        let encoded = encode_disappearing_text_payload(expires_at, "brief").unwrap();
        assert_eq!(
            decode_ephemeral_payload(&encoded),
            DecodedEphemeral::Ephemeral(Ephemeral::DisappearingText {
                expires_at,
                retention_until: 1_800_003_600,
                text: "brief",
            })
        );
        assert_eq!(retention_bucket(3_600).unwrap(), 3_600);
    }

    #[test]
    fn noncanonical_hint_reserved_bytes_and_trailing_data_fail() {
        let canonical = encode_disappearing_text_payload(7_201, "x").unwrap();
        let mut bad_hint = canonical.clone();
        bad_hint[12] ^= 1;
        assert_eq!(
            decode_ephemeral_payload(&bad_hint),
            DecodedEphemeral::Malformed
        );
        let mut reserved = canonical.clone();
        reserved[2] = 1;
        assert_eq!(
            decode_ephemeral_payload(&reserved),
            DecodedEphemeral::Unsupported
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode_ephemeral_payload(&trailing),
            DecodedEphemeral::Malformed
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let _ = decode_ephemeral_payload(&bytes);
        }
    }
}
