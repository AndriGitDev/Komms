//! Canonical immutable message-edit payloads (ADR-0020).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Fixed bytes before edit replacement UTF-8.
pub const EDIT_HEADER_LEN: usize = 32 + 16 + 8 + 4;
/// Maximum exact replacement text carried by an edit.
pub const MAX_EDIT_TEXT_LEN: usize = 16_384;
/// Maximum canonical edit payload length.
pub const MAX_EDIT_PAYLOAD_LEN: usize = EDIT_HEADER_LEN + MAX_EDIT_TEXT_LEN;

/// Borrowed canonical edit payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edit<'a> {
    /// Authenticated author of the original and this edit.
    pub target_author: [u8; 32],
    /// Original canonical Text content id.
    pub target_content_id: [u8; 16],
    /// Positive author-local monotonic revision.
    pub revision: u64,
    /// Exact replacement UTF-8.
    pub text: &'a str,
}

/// Total classification of an authenticated edit payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedEdit<'a> {
    /// Canonical supported payload.
    Edit(Edit<'a>),
    /// Payload violates ADR-0020.
    Malformed,
}

/// Encode one canonical edit payload.
pub fn encode_edit_payload(edit: &Edit<'_>) -> Result<Vec<u8>> {
    let text = edit.text.as_bytes();
    if edit.revision == 0 || text.is_empty() || text.len() > MAX_EDIT_TEXT_LEN {
        return Err(if text.len() > MAX_EDIT_TEXT_LEN {
            ProtocolError::TooLarge
        } else {
            ProtocolError::Malformed
        });
    }
    let mut out = Vec::with_capacity(EDIT_HEADER_LEN + text.len());
    out.extend_from_slice(&edit.target_author);
    out.extend_from_slice(&edit.target_content_id);
    out.extend_from_slice(&edit.revision.to_le_bytes());
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(text);
    Ok(out)
}

/// Decode an edit payload without allocating.
pub fn decode_edit_payload(bytes: &[u8]) -> DecodedEdit<'_> {
    if bytes.len() < EDIT_HEADER_LEN || bytes.len() > MAX_EDIT_PAYLOAD_LEN {
        return DecodedEdit::Malformed;
    }
    let mut target_author = [0u8; 32];
    target_author.copy_from_slice(&bytes[..32]);
    let mut target_content_id = [0u8; 16];
    target_content_id.copy_from_slice(&bytes[32..48]);
    let revision = u64::from_le_bytes(bytes[48..56].try_into().expect("fixed slice"));
    let text_len = u32::from_le_bytes(bytes[56..60].try_into().expect("fixed slice")) as usize;
    if revision == 0
        || text_len == 0
        || text_len > MAX_EDIT_TEXT_LEN
        || text_len != bytes.len() - EDIT_HEADER_LEN
    {
        return DecodedEdit::Malformed;
    }
    match core::str::from_utf8(&bytes[EDIT_HEADER_LEN..]) {
        Ok(text) => DecodedEdit::Edit(Edit {
            target_author,
            target_content_id,
            revision,
            text,
        }),
        Err(_) => DecodedEdit::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn exact_payload_round_trip_and_boundaries() {
        let edit = Edit {
            target_author: [0x11; 32],
            target_content_id: [0x22; 16],
            revision: 7,
            text: "revised \u{1f642}",
        };
        let encoded = encode_edit_payload(&edit).unwrap();
        assert_eq!(decode_edit_payload(&encoded), DecodedEdit::Edit(edit));
        assert!(encode_edit_payload(&Edit { text: "", ..edit }).is_err());
        assert!(encode_edit_payload(&Edit {
            revision: 0,
            ..edit
        })
        .is_err());
        assert!(encode_edit_payload(&Edit {
            text: &"x".repeat(MAX_EDIT_TEXT_LEN + 1),
            ..edit
        })
        .is_err());
    }

    #[test]
    fn malformed_lengths_utf8_revision_and_trailing_bytes_fail() {
        let edit = Edit {
            target_author: [1; 32],
            target_content_id: [2; 16],
            revision: 1,
            text: "ok",
        };
        let canonical = encode_edit_payload(&edit).unwrap();
        for length in 0..EDIT_HEADER_LEN {
            assert_eq!(
                decode_edit_payload(&canonical[..length]),
                DecodedEdit::Malformed
            );
        }
        let mut zero_revision = canonical.clone();
        zero_revision[48..56].fill(0);
        assert_eq!(decode_edit_payload(&zero_revision), DecodedEdit::Malformed);
        let mut bad_utf8 = canonical.clone();
        bad_utf8[EDIT_HEADER_LEN] = 0xff;
        assert_eq!(decode_edit_payload(&bad_utf8), DecodedEdit::Malformed);
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(decode_edit_payload(&trailing), DecodedEdit::Malformed);
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
            let _ = decode_edit_payload(&bytes);
        }

        #[test]
        fn canonical_text_round_trips(
            target_author in any::<[u8; 32]>(),
            target_content_id in any::<[u8; 16]>(),
            revision in 1u64..=u64::MAX,
            text in ".{1,4096}",
        ) {
            let edit = Edit {
                target_author,
                target_content_id,
                revision,
                text: &text,
            };
            let encoded = encode_edit_payload(&edit).unwrap();
            prop_assert_eq!(decode_edit_payload(&encoded), DecodedEdit::Edit(edit));
        }
    }
}
