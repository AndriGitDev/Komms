//! Canonical encrypted group-mention payloads (ADR-0016).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Mention payload version permanently assigned by ADR-0016.
pub const MENTION_VERSION: u8 = 1;
/// Fixed v1 mention payload header size.
pub const MENTION_HEADER_LEN: usize = 8;
/// Exact bytes in one stable peer target.
pub const MENTION_TARGET_LEN: usize = 32;
/// Exact bytes in one encoded mention span.
pub const MENTION_SPAN_LEN: usize = 9;
/// Maximum exact UTF-8 fallback text length.
pub const MAX_MENTION_TEXT_LEN: usize = 16_384;
/// Maximum unique peer targets.
pub const MAX_MENTION_TARGETS: usize = 64;
/// Maximum non-overlapping semantic spans.
pub const MAX_MENTION_SPANS: usize = 64;
/// Maximum canonical v1 mention payload length.
pub const MAX_MENTION_PAYLOAD_LEN: usize = MENTION_HEADER_LEN
    + MAX_MENTION_TARGETS * MENTION_TARGET_LEN
    + MAX_MENTION_TEXT_LEN
    + MAX_MENTION_SPANS * MENTION_SPAN_LEN;

/// One semantic mention span supplied to the canonical encoder or exposed by
/// the borrowed decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MentionSpan {
    /// Inclusive byte offset into the exact UTF-8 fallback text.
    pub start: u32,
    /// Exclusive byte offset into the exact UTF-8 fallback text.
    pub end: u32,
    /// Exact Ed25519 group peer identity key bytes.
    pub target: [u8; 32],
}

/// A canonical v1 mention borrowing exact authenticated text and table bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mention<'a> {
    /// Exact authenticated UTF-8 fallback text, never normalized.
    pub text: &'a str,
    targets: &'a [u8],
    spans: &'a [u8],
}

impl<'a> Mention<'a> {
    /// Number of sorted unique peer targets.
    pub fn target_count(self) -> usize {
        self.targets.len() / MENTION_TARGET_LEN
    }

    /// Number of sorted non-overlapping spans.
    pub fn span_count(self) -> usize {
        self.spans.len() / MENTION_SPAN_LEN
    }

    /// Iterate over exact stable target peer ids in canonical order.
    pub fn targets(self) -> MentionTargets<'a> {
        MentionTargets {
            remaining: self.targets,
        }
    }

    /// Iterate over semantic spans in canonical text order.
    pub fn spans(self) -> MentionSpans<'a> {
        MentionSpans {
            remaining: self.spans,
            targets: self.targets,
        }
    }
}

/// Iterator over a mention's canonical target table.
#[derive(Clone, Debug)]
pub struct MentionTargets<'a> {
    remaining: &'a [u8],
}

impl Iterator for MentionTargets<'_> {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.remaining.get(..MENTION_TARGET_LEN)?;
        let mut target = [0u8; 32];
        target.copy_from_slice(bytes);
        self.remaining = &self.remaining[MENTION_TARGET_LEN..];
        Some(target)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining.len() / MENTION_TARGET_LEN;
        (len, Some(len))
    }
}

impl ExactSizeIterator for MentionTargets<'_> {}

/// Iterator over decoded mention spans with resolved full target ids.
#[derive(Clone, Debug)]
pub struct MentionSpans<'a> {
    remaining: &'a [u8],
    targets: &'a [u8],
}

impl Iterator for MentionSpans<'_> {
    type Item = MentionSpan;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.remaining.get(..MENTION_SPAN_LEN)?;
        let start = u32::from_le_bytes(bytes[..4].try_into().ok()?);
        let end = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let target_index = bytes[8] as usize;
        let target_start = target_index.checked_mul(MENTION_TARGET_LEN)?;
        let target_bytes = self
            .targets
            .get(target_start..target_start + MENTION_TARGET_LEN)?;
        let mut target = [0u8; 32];
        target.copy_from_slice(target_bytes);
        self.remaining = &self.remaining[MENTION_SPAN_LEN..];
        Some(MentionSpan { start, end, target })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining.len() / MENTION_SPAN_LEN;
        (len, Some(len))
    }
}

impl ExactSizeIterator for MentionSpans<'_> {}

/// Classification of an authenticated Mention payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedMention<'a> {
    /// A supported canonical v1 mention.
    Mention(Mention<'a>),
    /// A bounded mention version or flag set this client does not understand.
    Unsupported,
    /// Bytes violating canonical v1 shape or bounds.
    Malformed,
}

/// Encode exact fallback text and explicit stable peer spans canonically.
///
/// Spans must already be sorted and non-overlapping. The target table is
/// deterministically collected, sorted, and deduplicated from those spans.
pub fn encode_mention_payload(text: &str, spans: &[MentionSpan]) -> Result<Vec<u8>> {
    validate_text_and_spans(text, spans)?;

    let mut targets = Vec::with_capacity(spans.len());
    for span in spans {
        targets.push(span.target);
    }
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() || targets.len() > MAX_MENTION_TARGETS {
        return Err(ProtocolError::TooLarge);
    }

    let target_bytes = targets
        .len()
        .checked_mul(MENTION_TARGET_LEN)
        .ok_or(ProtocolError::TooLarge)?;
    let span_bytes = spans
        .len()
        .checked_mul(MENTION_SPAN_LEN)
        .ok_or(ProtocolError::TooLarge)?;
    let payload_len = MENTION_HEADER_LEN
        .checked_add(target_bytes)
        .and_then(|len| len.checked_add(text.len()))
        .and_then(|len| len.checked_add(span_bytes))
        .ok_or(ProtocolError::TooLarge)?;
    if payload_len > MAX_MENTION_PAYLOAD_LEN {
        return Err(ProtocolError::TooLarge);
    }

    let mut out = Vec::with_capacity(payload_len);
    out.push(MENTION_VERSION);
    out.push(0);
    out.push(targets.len() as u8);
    out.push(spans.len() as u8);
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    for target in &targets {
        out.extend_from_slice(target);
    }
    out.extend_from_slice(text.as_bytes());
    for span in spans {
        let target_index = targets
            .binary_search(&span.target)
            .map_err(|_| ProtocolError::Malformed)?;
        out.extend_from_slice(&span.start.to_le_bytes());
        out.extend_from_slice(&span.end.to_le_bytes());
        out.push(target_index as u8);
    }
    debug_assert_eq!(out.len(), payload_len);
    Ok(out)
}

/// Decode and validate one complete authenticated Mention payload without
/// allocating.
pub fn decode_mention_payload(bytes: &[u8]) -> DecodedMention<'_> {
    if bytes.len() > MAX_MENTION_PAYLOAD_LEN || bytes.len() < MENTION_HEADER_LEN {
        return DecodedMention::Malformed;
    }
    match decode_v1(bytes) {
        Ok(_) if bytes[0] != MENTION_VERSION || bytes[1] != 0 => DecodedMention::Unsupported,
        Ok(mention) => DecodedMention::Mention(mention),
        Err(_) => DecodedMention::Malformed,
    }
}

fn decode_v1(bytes: &[u8]) -> Result<Mention<'_>> {
    let target_count = bytes[2] as usize;
    let span_count = bytes[3] as usize;
    let text_len = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ProtocolError::Malformed)?,
    ) as usize;
    if !(1..=MAX_MENTION_TARGETS).contains(&target_count)
        || !(1..=MAX_MENTION_SPANS).contains(&span_count)
        || !(1..=MAX_MENTION_TEXT_LEN).contains(&text_len)
    {
        return Err(ProtocolError::Malformed);
    }

    let target_len = target_count
        .checked_mul(MENTION_TARGET_LEN)
        .ok_or(ProtocolError::Malformed)?;
    let spans_len = span_count
        .checked_mul(MENTION_SPAN_LEN)
        .ok_or(ProtocolError::Malformed)?;
    let text_start = MENTION_HEADER_LEN
        .checked_add(target_len)
        .ok_or(ProtocolError::Malformed)?;
    let spans_start = text_start
        .checked_add(text_len)
        .ok_or(ProtocolError::Malformed)?;
    let expected = spans_start
        .checked_add(spans_len)
        .ok_or(ProtocolError::Malformed)?;
    if expected != bytes.len() {
        return Err(ProtocolError::Malformed);
    }

    let targets = &bytes[MENTION_HEADER_LEN..text_start];
    let mut previous_target: Option<&[u8]> = None;
    for target in targets.chunks_exact(MENTION_TARGET_LEN) {
        if previous_target.is_some_and(|previous| previous >= target) {
            return Err(ProtocolError::Malformed);
        }
        previous_target = Some(target);
    }

    let text = core::str::from_utf8(&bytes[text_start..spans_start])
        .map_err(|_| ProtocolError::Malformed)?;
    let encoded_spans = &bytes[spans_start..];
    let mut previous_end = 0usize;
    let mut used_targets = 0u64;
    for (index, span) in encoded_spans.chunks_exact(MENTION_SPAN_LEN).enumerate() {
        let start = u32::from_le_bytes(span[..4].try_into().map_err(|_| ProtocolError::Malformed)?)
            as usize;
        let end = u32::from_le_bytes(
            span[4..8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?,
        ) as usize;
        let target_index = span[8] as usize;
        if start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
            || (index > 0 && start < previous_end)
            || target_index >= target_count
        {
            return Err(ProtocolError::Malformed);
        }
        previous_end = end;
        used_targets |= 1u64 << target_index;
    }
    let all_targets = if target_count == 64 {
        u64::MAX
    } else {
        (1u64 << target_count) - 1
    };
    if used_targets != all_targets {
        return Err(ProtocolError::Malformed);
    }

    Ok(Mention {
        text,
        targets,
        spans: encoded_spans,
    })
}

fn validate_text_and_spans(text: &str, spans: &[MentionSpan]) -> Result<()> {
    if text.is_empty() || spans.is_empty() {
        return Err(ProtocolError::Malformed);
    }
    if text.len() > MAX_MENTION_TEXT_LEN || spans.len() > MAX_MENTION_SPANS {
        return Err(ProtocolError::TooLarge);
    }

    let mut previous_end = 0usize;
    for (index, span) in spans.iter().enumerate() {
        let start = span.start as usize;
        let end = span.end as usize;
        if start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
            || (index > 0 && start < previous_end)
        {
            return Err(ProtocolError::Malformed);
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn span(start: u32, end: u32, target: u8) -> MentionSpan {
        MentionSpan {
            start,
            end,
            target: [target; 32],
        }
    }

    #[test]
    fn minimum_golden_vector_is_exact() {
        let encoded = encode_mention_payload("x", &[span(0, 1, 0)]).unwrap();
        let mut expected = vec![1, 0, 1, 1, 1, 0, 0, 0];
        expected.extend_from_slice(&[0; 32]);
        expected.push(b'x');
        expected.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(encoded, expected);

        let DecodedMention::Mention(decoded) = decode_mention_payload(&expected) else {
            panic!("minimum golden vector did not decode");
        };
        assert_eq!(decoded.text, "x");
        assert_eq!(decoded.spans().collect::<Vec<_>>(), vec![span(0, 1, 0)]);
    }

    #[test]
    fn golden_vector_sorts_targets_and_resolves_repeated_target() {
        let text = "@Bob + @Alice + @Bob";
        let spans = [span(0, 4, 2), span(7, 13, 1), span(16, 20, 2)];
        let encoded = encode_mention_payload(text, &spans).unwrap();

        let mut expected = vec![1, 0, 2, 3, 20, 0, 0, 0];
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(text.as_bytes());
        expected.extend_from_slice(&[0, 0, 0, 0, 4, 0, 0, 0, 1]);
        expected.extend_from_slice(&[7, 0, 0, 0, 13, 0, 0, 0, 0]);
        expected.extend_from_slice(&[16, 0, 0, 0, 20, 0, 0, 0, 1]);
        assert_eq!(encoded, expected);

        let DecodedMention::Mention(decoded) = decode_mention_payload(&encoded) else {
            panic!("golden vector did not decode");
        };
        assert_eq!(decoded.text, text);
        assert_eq!(
            decoded.targets().collect::<Vec<_>>(),
            vec![[1; 32], [2; 32]]
        );
        assert_eq!(decoded.spans().collect::<Vec<_>>(), spans);
    }

    #[test]
    fn unicode_boundaries_are_exact_and_never_normalized() {
        let text = "x 👩🏽‍💻 e\u{301} \u{2067}עברית\u{2069}";
        let emoji_start = text.find('👩').unwrap();
        let emoji_end = emoji_start + "👩🏽‍💻".len();
        let combining_start = text.find('e').unwrap();
        let combining_end = combining_start + "e\u{301}".len();
        let bidi_start = text.find('\u{2067}').unwrap();
        let bidi_end = bidi_start + "\u{2067}עברית\u{2069}".len();
        let spans = [
            span(emoji_start as u32, emoji_end as u32, 1),
            span(combining_start as u32, combining_end as u32, 2),
            span(bidi_start as u32, bidi_end as u32, 1),
        ];
        let encoded = encode_mention_payload(text, &spans).unwrap();

        // This exact vector simultaneously pins a multi-scalar emoji grapheme,
        // a decomposed combining sequence, bidi isolation, and a repeated
        // target without normalizing or rewriting any authenticated bytes.
        let mut expected = vec![1, 0, 2, 3, text.len() as u8, 0, 0, 0];
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(text.as_bytes());
        for (start, end, target_index) in [
            (emoji_start, emoji_end, 0u8),
            (combining_start, combining_end, 1u8),
            (bidi_start, bidi_end, 0u8),
        ] {
            expected.extend_from_slice(&(start as u32).to_le_bytes());
            expected.extend_from_slice(&(end as u32).to_le_bytes());
            expected.push(target_index);
        }
        assert_eq!(encoded, expected);

        let DecodedMention::Mention(decoded) = decode_mention_payload(&encoded) else {
            panic!("unicode mention did not decode");
        };
        assert_eq!(decoded.text.as_bytes(), text.as_bytes());
        assert_eq!(decoded.spans().collect::<Vec<_>>(), spans);

        let mut invalid = spans;
        invalid[0].start += 1;
        assert_eq!(
            encode_mention_payload(text, &invalid),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn malformed_noncanonical_and_boundary_cases_fail_closed() {
        let valid = encode_mention_payload("@a @b", &[span(0, 2, 1), span(3, 5, 2)]).unwrap();

        let mut duplicate_targets = valid.clone();
        duplicate_targets[8 + 32..8 + 64].copy_from_slice(&[1; 32]);
        assert_eq!(
            decode_mention_payload(&duplicate_targets),
            DecodedMention::Malformed
        );

        let mut overlap = valid.clone();
        let spans_start = 8 + 64 + 5;
        overlap[spans_start + 9..spans_start + 13].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(decode_mention_payload(&overlap), DecodedMention::Malformed);

        let mut empty_range = valid.clone();
        empty_range[spans_start + 4..spans_start + 8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            decode_mention_payload(&empty_range),
            DecodedMention::Malformed
        );

        let mut out_of_range = valid.clone();
        out_of_range[spans_start + 4..spans_start + 8].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(
            decode_mention_payload(&out_of_range),
            DecodedMention::Malformed
        );

        let mut invalid_target_index = valid.clone();
        invalid_target_index[spans_start + 8] = 2;
        assert_eq!(
            decode_mention_payload(&invalid_target_index),
            DecodedMention::Malformed
        );

        let mut unused_target = valid.clone();
        unused_target[spans_start + 9 + 8] = 0;
        assert_eq!(
            decode_mention_payload(&unused_target),
            DecodedMention::Malformed
        );

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(decode_mention_payload(&trailing), DecodedMention::Malformed);
        assert_eq!(
            decode_mention_payload(&valid[..7]),
            DecodedMention::Malformed
        );

        let mut unsupported = valid.clone();
        unsupported[1] = 1;
        assert_eq!(
            decode_mention_payload(&unsupported),
            DecodedMention::Unsupported
        );

        let mut future_version = valid.clone();
        future_version[0] = 2;
        assert_eq!(
            decode_mention_payload(&future_version),
            DecodedMention::Unsupported
        );
        assert_eq!(
            decode_mention_payload(&[2, 0]),
            DecodedMention::Malformed,
            "an unknown version is unsupported only when its bounded shape is complete"
        );
        let mut malformed_future = future_version;
        malformed_future[spans_start + 8] = 2;
        assert_eq!(
            decode_mention_payload(&malformed_future),
            DecodedMention::Malformed
        );

        for (target_count, span_count, text_len) in [
            (0u8, 2u8, 5u32),
            (65, 2, 5),
            (2, 0, 5),
            (2, 65, 5),
            (2, 2, 0),
            (2, 2, (MAX_MENTION_TEXT_LEN + 1) as u32),
        ] {
            let mut invalid_header = valid.clone();
            invalid_header[2] = target_count;
            invalid_header[3] = span_count;
            invalid_header[4..8].copy_from_slice(&text_len.to_le_bytes());
            assert_eq!(
                decode_mention_payload(&invalid_header),
                DecodedMention::Malformed
            );
        }
    }

    #[test]
    fn exact_maximum_payload_round_trips() {
        let text = "x".repeat(MAX_MENTION_TEXT_LEN);
        let spans = (0..MAX_MENTION_SPANS)
            .map(|index| span(index as u32, index as u32 + 1, index as u8))
            .collect::<Vec<_>>();
        let encoded = encode_mention_payload(&text, &spans).unwrap();
        assert_eq!(encoded.len(), MAX_MENTION_PAYLOAD_LEN);
        let DecodedMention::Mention(decoded) = decode_mention_payload(&encoded) else {
            panic!("maximum mention did not decode");
        };
        assert_eq!(decoded.target_count(), MAX_MENTION_TARGETS);
        assert_eq!(decoded.span_count(), MAX_MENTION_SPANS);
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..20_000)) {
            let _ = decode_mention_payload(&bytes);
        }

        #[test]
        fn canonical_ascii_spans_round_trip(
            text in "[ -~]{1,256}",
            target in any::<[u8; 32]>()
        ) {
            let span = MentionSpan {
                start: 0,
                end: text.len() as u32,
                target,
            };
            let encoded = encode_mention_payload(&text, &[span]).unwrap();
            let DecodedMention::Mention(decoded) = decode_mention_payload(&encoded) else {
                prop_assert!(false, "canonical encoding did not decode");
                return Ok(());
            };
            prop_assert_eq!(decoded.text, text.as_str());
            prop_assert_eq!(decoded.spans().collect::<Vec<_>>(), vec![span]);
        }
    }
}
