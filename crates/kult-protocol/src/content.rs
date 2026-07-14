//! Bounded message-content framing (ADR-0014).
//!
//! Content bytes are framed before padding and end-to-end encryption. The
//! decoder borrows the authenticated plaintext so callers can classify it
//! without allocating while the store retains the exact original bytes.

use alloc::vec::Vec;

use crate::{
    decode_attachment_manifest, encode_attachment_manifest, AttachmentManifest,
    DecodedAttachmentManifest, ProtocolError, Result,
};

/// Prefix that unambiguously distinguishes typed content from valid UTF-8.
pub const CONTENT_MAGIC: [u8; 4] = [0xff, b'K', b'M', b'C'];
/// The first content framing version.
pub const CONTENT_FORMAT_V1: u8 = 1;
/// The v1 kind assigned to UTF-8 text.
pub const CONTENT_KIND_TEXT: u16 = 1;
/// The v1 kind assigned to encrypted attachment manifests.
pub const CONTENT_KIND_ATTACHMENT: u16 = 2;
/// Size of the fixed v1 content header.
pub const CONTENT_HEADER_LEN: usize = 28;
/// Maximum unpadded content frame size.
pub const MAX_CONTENT_FRAME_LEN: usize = 65_535;
/// Maximum payload size inside a v1 content frame.
pub const MAX_CONTENT_PAYLOAD_LEN: usize = MAX_CONTENT_FRAME_LEN - CONTENT_HEADER_LEN;
/// Maximum collection entries permitted in future content payloads.
pub const MAX_COLLECTION_ENTRIES: usize = 64;
/// Maximum nested container or reference depth in future content payloads.
pub const MAX_NESTING_DEPTH: usize = 4;

/// Application-visible interpretation of authenticated, unpadded content.
///
/// Callers retain the original input bytes for `Unsupported` and `Malformed`
/// outcomes. Unknown bytes are deliberately never exposed as guessed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // keeps authenticated content classification allocation-free
pub enum DecodedContent<'a> {
    /// A permanent legacy path for valid UTF-8 messages without content magic.
    LegacyText(&'a str),
    /// A canonical v1 text frame.
    Text {
        /// Random author-minted id, scoped to the conversation and author.
        id: [u8; 16],
        /// Exact authenticated UTF-8 text, without normalization.
        text: &'a str,
    },
    /// A canonical v1 encrypted attachment offer.
    Attachment {
        /// Random author-minted manifest id, scoped to conversation and author.
        id: [u8; 16],
        /// Canonical borrowed attachment manifest.
        manifest: AttachmentManifest<'a>,
    },
    /// Authenticated bytes the current client cannot interpret.
    Unsupported {
        /// Known format version, when a typed prefix exposed one.
        format_version: Option<u8>,
        /// Known content kind, when the common v1 header exposed one.
        kind: Option<u16>,
    },
    /// A typed frame that violates the canonical framing contract.
    Malformed,
}

/// Encode UTF-8 text as a canonical v1 content frame.
pub fn encode_text(id: [u8; 16], text: &str) -> Result<Vec<u8>> {
    let payload = text.as_bytes();
    if payload.len() > MAX_CONTENT_PAYLOAD_LEN {
        return Err(ProtocolError::TooLarge);
    }

    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_TEXT.to_le_bytes());
    frame.push(0); // v1 reserved flags
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Encode a canonical attachment manifest as a v1 content frame.
pub fn encode_attachment(id: [u8; 16], manifest: &AttachmentManifest<'_>) -> Result<Vec<u8>> {
    let payload = encode_attachment_manifest(manifest)?;
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_ATTACHMENT.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Classify authenticated, unpadded message-content bytes.
///
/// This function is total for arbitrary input and allocates nothing. A magic
/// prefix always commits decoding to the typed path; malformed typed bytes
/// never fall back to legacy text.
pub fn decode_content(bytes: &[u8]) -> DecodedContent<'_> {
    if !bytes.starts_with(&CONTENT_MAGIC) {
        return match core::str::from_utf8(bytes) {
            Ok(text) => DecodedContent::LegacyText(text),
            Err(_) => DecodedContent::Unsupported {
                format_version: None,
                kind: None,
            },
        };
    }

    if bytes.len() > MAX_CONTENT_FRAME_LEN || bytes.len() < CONTENT_MAGIC.len() + 1 {
        return DecodedContent::Malformed;
    }

    let format_version = bytes[4];
    if format_version != CONTENT_FORMAT_V1 {
        return DecodedContent::Unsupported {
            format_version: Some(format_version),
            kind: None,
        };
    }

    if bytes.len() < CONTENT_HEADER_LEN {
        return DecodedContent::Malformed;
    }

    let kind = u16::from_le_bytes([bytes[5], bytes[6]]);
    let flags = bytes[7];
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[8..24]);
    let declared_len = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;

    if kind == 0
        || declared_len > MAX_CONTENT_PAYLOAD_LEN
        || declared_len != bytes.len() - CONTENT_HEADER_LEN
    {
        return DecodedContent::Malformed;
    }

    if flags != 0 {
        return DecodedContent::Unsupported {
            format_version: Some(format_version),
            kind: Some(kind),
        };
    }

    let payload = &bytes[CONTENT_HEADER_LEN..];
    match kind {
        CONTENT_KIND_TEXT => match core::str::from_utf8(payload) {
            Ok(text) => DecodedContent::Text { id, text },
            Err(_) => DecodedContent::Malformed,
        },
        CONTENT_KIND_ATTACHMENT => match decode_attachment_manifest(payload) {
            DecodedAttachmentManifest::Manifest(manifest) => {
                DecodedContent::Attachment { id, manifest }
            }
            DecodedAttachmentManifest::Unsupported => DecodedContent::Unsupported {
                format_version: Some(format_version),
                kind: Some(kind),
            },
            DecodedAttachmentManifest::Malformed => DecodedContent::Malformed,
        },
        _ => DecodedContent::Unsupported {
            format_version: Some(format_version),
            kind: Some(kind),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn text_golden_vector() {
        let id = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected = [
            0xff, 0x4b, 0x4d, 0x43, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x02, 0x00, 0x00, 0x00,
            0x68, 0x69,
        ];
        assert_eq!(encode_text(id, "hi").unwrap(), expected);
        assert_eq!(
            decode_content(&expected),
            DecodedContent::Text { id, text: "hi" }
        );
    }

    #[test]
    fn legacy_and_typed_paths_never_confuse_each_other() {
        assert_eq!(
            decode_content(b"hello"),
            DecodedContent::LegacyText("hello")
        );
        assert_eq!(decode_content(b""), DecodedContent::LegacyText(""));
        assert_eq!(
            decode_content(&[0xff, b'x']),
            DecodedContent::Unsupported {
                format_version: None,
                kind: None
            }
        );
        assert_eq!(decode_content(&CONTENT_MAGIC), DecodedContent::Malformed);
    }

    #[test]
    fn unknown_fields_are_unsupported_only_when_structurally_sound() {
        let mut frame = encode_text([7; 16], "x").unwrap();
        frame[4] = 2;
        assert_eq!(
            decode_content(&frame),
            DecodedContent::Unsupported {
                format_version: Some(2),
                kind: None
            }
        );

        frame = encode_text([7; 16], "x").unwrap();
        frame[5..7].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            decode_content(&frame),
            DecodedContent::Unsupported {
                format_version: Some(1),
                kind: Some(3)
            }
        );

        frame[7] = 1;
        frame[24..28].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(decode_content(&frame), DecodedContent::Malformed);
    }

    #[test]
    fn exact_boundaries_and_invalid_utf8() {
        let max = "a".repeat(MAX_CONTENT_PAYLOAD_LEN);
        let frame = encode_text([9; 16], &max).unwrap();
        assert_eq!(frame.len(), MAX_CONTENT_FRAME_LEN);
        assert!(matches!(
            decode_content(&frame),
            DecodedContent::Text { id, text }
                if id == [9; 16] && text.len() == MAX_CONTENT_PAYLOAD_LEN
        ));
        assert_eq!(
            encode_text([0; 16], &"a".repeat(MAX_CONTENT_PAYLOAD_LEN + 1)),
            Err(ProtocolError::TooLarge)
        );

        let mut invalid = encode_text([0; 16], "x").unwrap();
        invalid[CONTENT_HEADER_LEN] = 0xff;
        assert_eq!(decode_content(&invalid), DecodedContent::Malformed);
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let _ = decode_content(&bytes);
        }

        #[test]
        fn encoded_text_round_trips(id in any::<[u8; 16]>(), text in ".{0,4096}") {
            let frame = encode_text(id, &text).unwrap();
            prop_assert_eq!(
                decode_content(&frame),
                DecodedContent::Text { id, text: &text }
            );
        }
    }
}
