//! Bounded message-content framing (ADR-0014).
//!
//! Content bytes are framed before padding and end-to-end encryption. The
//! decoder borrows the authenticated plaintext so callers can classify it
//! without allocating while the store retains the exact original bytes.

use alloc::vec::Vec;

use crate::{
    decode_attachment_manifest, decode_edit_payload, decode_ephemeral_payload,
    decode_group_authority, decode_mention_payload, decode_poll_payload,
    encode_attachment_manifest, encode_edit_payload, encode_mention_payload, AttachmentManifest,
    DecodedAttachmentManifest, DecodedEdit, DecodedEphemeral, DecodedGroupAuthority,
    DecodedMention, DecodedPoll, Edit, Ephemeral, Mention, MentionSpan, Poll, ProtocolError,
    Result,
};

/// Prefix that unambiguously distinguishes typed content from valid UTF-8.
pub const CONTENT_MAGIC: [u8; 4] = [0xff, b'K', b'M', b'C'];
/// The first content framing version.
pub const CONTENT_FORMAT_V1: u8 = 1;
/// The v1 kind assigned to UTF-8 text.
pub const CONTENT_KIND_TEXT: u16 = 1;
/// The v1 kind assigned to encrypted attachment manifests.
pub const CONTENT_KIND_ATTACHMENT: u16 = 2;
/// The v1 kind assigned to canonical group mentions.
pub const CONTENT_KIND_MENTION: u16 = 3;
/// The v1 kind assigned to immutable authenticated message edits.
pub const CONTENT_KIND_EDIT: u16 = 4;
/// The v1 kind assigned to disappearing text and view-once attachments.
pub const CONTENT_KIND_EPHEMERAL: u16 = 5;
/// The v1 kind assigned to authenticated group poll events.
pub const CONTENT_KIND_POLL: u16 = 6;
/// The v1 kind assigned to owner-signed group authority state.
pub const CONTENT_KIND_GROUP_AUTHORITY: u16 = 7;
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
    /// A canonical v1 group mention. Conversation validity is enforced by
    /// the node because the common content decoder has no envelope context.
    Mention {
        /// Random author-minted id, scoped to conversation and author.
        id: [u8; 16],
        /// Exact fallback text plus stable semantic peer spans.
        mention: Mention<'a>,
    },
    /// A canonical v1 immutable message edit.
    Edit {
        /// Random author-minted id for this edit event.
        id: [u8; 16],
        /// Exact target, revision, and replacement text.
        edit: Edit<'a>,
    },
    /// Canonical v1 content with authenticated local/network retention semantics.
    Ephemeral {
        /// Random author-minted id, scoped to the conversation and author.
        id: [u8; 16],
        /// Exact supported ephemeral mode and payload.
        ephemeral: Ephemeral<'a>,
    },
    /// Canonical group-only poll creation, vote, or closure event.
    Poll {
        /// Random author-minted id for this exact poll event.
        id: [u8; 16],
        /// Exact supported poll event.
        poll: Poll<'a>,
    },
    /// Canonical group-only owner-signed role/authority state.
    GroupAuthority {
        /// Random event id for this exact committed state.
        id: [u8; 16],
        /// Exact canonical authority payload for authority-aware callers.
        payload: &'a [u8],
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

/// Encode a canonical group Mention as a v1 content frame.
pub fn encode_mention(id: [u8; 16], text: &str, spans: &[MentionSpan]) -> Result<Vec<u8>> {
    let payload = encode_mention_payload(text, spans)?;
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_MENTION.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Encode a canonical immutable Edit as a v1 content frame.
pub fn encode_edit(id: [u8; 16], edit: &Edit<'_>) -> Result<Vec<u8>> {
    let payload = encode_edit_payload(edit)?;
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_EDIT.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Wrap one canonical ephemeral payload in the common v1 content frame.
pub fn encode_ephemeral(id: [u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_CONTENT_PAYLOAD_LEN {
        return Err(ProtocolError::TooLarge);
    }
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_EPHEMERAL.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Wrap one canonical poll payload in the common v1 content frame.
pub fn encode_poll(id: [u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_CONTENT_PAYLOAD_LEN {
        return Err(ProtocolError::TooLarge);
    }
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_POLL.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Wrap one canonical group-authority payload in the common v1 content frame.
pub fn encode_group_authority(id: [u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_CONTENT_PAYLOAD_LEN {
        return Err(ProtocolError::TooLarge);
    }
    let mut frame = Vec::with_capacity(CONTENT_HEADER_LEN + payload.len());
    frame.extend_from_slice(&CONTENT_MAGIC);
    frame.push(CONTENT_FORMAT_V1);
    frame.extend_from_slice(&CONTENT_KIND_GROUP_AUTHORITY.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
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
        CONTENT_KIND_MENTION => match decode_mention_payload(payload) {
            DecodedMention::Mention(mention) => DecodedContent::Mention { id, mention },
            DecodedMention::Unsupported => DecodedContent::Unsupported {
                format_version: Some(format_version),
                kind: Some(kind),
            },
            DecodedMention::Malformed => DecodedContent::Malformed,
        },
        CONTENT_KIND_EDIT => match decode_edit_payload(payload) {
            DecodedEdit::Edit(edit) => DecodedContent::Edit { id, edit },
            DecodedEdit::Malformed => DecodedContent::Malformed,
        },
        CONTENT_KIND_EPHEMERAL => match decode_ephemeral_payload(payload) {
            DecodedEphemeral::Ephemeral(ephemeral) => DecodedContent::Ephemeral { id, ephemeral },
            DecodedEphemeral::Unsupported => DecodedContent::Unsupported {
                format_version: Some(format_version),
                kind: Some(kind),
            },
            DecodedEphemeral::Malformed => DecodedContent::Malformed,
        },
        CONTENT_KIND_POLL => match decode_poll_payload(payload) {
            DecodedPoll::Poll(poll) => DecodedContent::Poll { id, poll },
            DecodedPoll::Unsupported => DecodedContent::Unsupported {
                format_version: Some(format_version),
                kind: Some(kind),
            },
            DecodedPoll::Malformed => DecodedContent::Malformed,
        },
        CONTENT_KIND_GROUP_AUTHORITY => match decode_group_authority(payload) {
            DecodedGroupAuthority::State(_) => DecodedContent::GroupAuthority { id, payload },
            DecodedGroupAuthority::Unsupported => DecodedContent::Unsupported {
                format_version: Some(format_version),
                kind: Some(kind),
            },
            DecodedGroupAuthority::Malformed => DecodedContent::Malformed,
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
    use crate::{encode_poll_vote_payload, PollVote};
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
    fn mention_content_golden_vector() {
        let id = [0x11; 16];
        let frame = encode_mention(
            id,
            "x",
            &[MentionSpan {
                start: 0,
                end: 1,
                target: [0x22; 32],
            }],
        )
        .unwrap();

        let mut expected = vec![0xff, b'K', b'M', b'C', 1, 3, 0, 0];
        expected.extend_from_slice(&id);
        expected.extend_from_slice(&50u32.to_le_bytes());
        expected.extend_from_slice(&[1, 0, 1, 1, 1, 0, 0, 0]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.push(b'x');
        expected.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(frame, expected);

        assert!(matches!(
            decode_content(&frame),
            DecodedContent::Mention { id: decoded_id, mention }
                if decoded_id == id && mention.text == "x"
        ));
    }

    #[test]
    fn edit_content_golden_vector() {
        let id = [0x11; 16];
        let edit = Edit {
            target_author: [0x22; 32],
            target_content_id: [0x33; 16],
            revision: 7,
            text: "new",
        };
        let frame = encode_edit(id, &edit).unwrap();
        let mut expected = vec![0xff, b'K', b'M', b'C', 1, 4, 0, 0];
        expected.extend_from_slice(&id);
        expected.extend_from_slice(&63u32.to_le_bytes());
        expected.extend_from_slice(&edit.target_author);
        expected.extend_from_slice(&edit.target_content_id);
        expected.extend_from_slice(&edit.revision.to_le_bytes());
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.extend_from_slice(b"new");
        assert_eq!(frame, expected);
        assert_eq!(decode_content(&frame), DecodedContent::Edit { id, edit });
    }

    #[test]
    fn poll_content_round_trips_through_common_frame() {
        let id = [0x66; 16];
        let vote = PollVote {
            poll_author: [0x11; 32],
            poll_id: [0x22; 16],
            option_id: [0x33; 16],
            revision: 4,
        };
        let frame = encode_poll(id, &encode_poll_vote_payload(&vote).unwrap()).unwrap();
        assert!(matches!(
            decode_content(&frame),
            DecodedContent::Poll {
                id: decoded_id,
                poll: Poll::Vote(decoded_vote),
            } if decoded_id == id && decoded_vote == vote
        ));
        let mut future = frame;
        future[CONTENT_HEADER_LEN] = 2;
        assert_eq!(
            decode_content(&future),
            DecodedContent::Unsupported {
                format_version: Some(CONTENT_FORMAT_V1),
                kind: Some(CONTENT_KIND_POLL),
            }
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
        frame[5..7].copy_from_slice(&0x7fffu16.to_le_bytes());
        assert_eq!(
            decode_content(&frame),
            DecodedContent::Unsupported {
                format_version: Some(1),
                kind: Some(0x7fff)
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
