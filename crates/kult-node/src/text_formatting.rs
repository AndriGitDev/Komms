//! Bounded, render-safe local formatting for authenticated UTF-8 message text.
//!
//! The source remains the stored and transmitted value. This module produces a
//! small display model made only of text, block roles, and inert style tokens;
//! it never interprets HTML, links, images, URLs, or executable content.

use crate::{NodeError, Result};

/// Maximum source size accepted by the local formatter.
pub const MAX_FORMAT_SOURCE_BYTES: usize = 64 * 1_024;
/// Maximum blocks emitted for one formatted message.
pub const MAX_FORMAT_BLOCKS: usize = 1_024;
/// Maximum styled runs emitted for one formatted message.
pub const MAX_FORMAT_RUNS: usize = 4_096;
/// Maximum supported nested inline delimiter depth.
pub const MAX_FORMAT_INLINE_DEPTH: usize = 4;
/// Maximum supported list indentation depth.
pub const MAX_FORMAT_LIST_DEPTH: u8 = 4;
/// Maximum inert highlight ranges accepted from an existing semantic layer.
pub const MAX_FORMAT_HIGHLIGHTS: usize = 64;

/// One inert inline presentation token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TextFormatStyle {
    /// Emphasized text.
    Emphasis,
    /// Strongly emphasized text.
    Strong,
    /// Inline monospace code.
    InlineCode,
    /// Existing semantic content, such as an authenticated Mention span.
    Highlight,
}

/// One render-safe block role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextFormatBlockKind {
    /// Ordinary text.
    Paragraph,
    /// Quoted text.
    Quote,
    /// One unordered list item.
    UnorderedListItem,
    /// One ordered list item.
    OrderedListItem,
    /// A fenced, inert monospace code block.
    CodeBlock,
}

/// Exact UTF-8 source range that receives an inert highlight style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextFormatHighlight {
    /// Inclusive UTF-8 byte offset in the exact source text.
    pub start: u32,
    /// Exclusive UTF-8 byte offset in the exact source text.
    pub end: u32,
}

/// One text run with a deterministic set of inert styles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormattedTextRun {
    /// Exact display text; shells must insert it only through native text APIs.
    pub text: String,
    /// Sorted, de-duplicated style tokens.
    pub styles: Vec<TextFormatStyle>,
}

/// One local display block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormattedTextBlock {
    /// Semantic block role.
    pub kind: TextFormatBlockKind,
    /// Zero-based list indentation; zero for non-list blocks.
    pub depth: u8,
    /// Ordered-list number, or zero for every other block kind.
    pub ordinal: u32,
    /// Display runs in exact order.
    pub runs: Vec<FormattedTextRun>,
}

/// Complete local formatting result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormattedText {
    /// Exact authenticated/stored source, unchanged.
    pub source: String,
    /// Readable inert text used for copy-as-plain-text across every shell.
    pub plain_text: String,
    /// Bounded render-safe blocks.
    pub blocks: Vec<FormattedTextBlock>,
    /// True when a complexity bound caused literal source rendering.
    pub used_fallback: bool,
}

#[derive(Clone, Debug)]
struct SourceRun {
    text: String,
    styles: Vec<TextFormatStyle>,
    source_start: usize,
    source_end: usize,
}

#[derive(Clone, Debug)]
struct SourceBlock {
    kind: TextFormatBlockKind,
    depth: u8,
    ordinal: u32,
    runs: Vec<SourceRun>,
}

#[derive(Clone, Copy)]
struct Line<'a> {
    text: &'a str,
    start: usize,
}

/// Parse exact source text into a bounded, render-safe local display model.
///
/// Existing semantic ranges may be supplied as inert highlights. They must be
/// canonical sorted, non-overlapping UTF-8 ranges. Formatting markers are never
/// added to storage or transmitted bytes.
pub fn format_text(source: &str, highlights: &[TextFormatHighlight]) -> Result<FormattedText> {
    if source.len() > MAX_FORMAT_SOURCE_BYTES {
        return Err(NodeError::InvalidTextFormatting);
    }
    validate_highlights(source, highlights)?;

    let lines = source_lines(source);
    let Some(mut blocks) = parse_blocks(&lines) else {
        return Ok(literal_fallback(source, highlights));
    };
    if apply_highlights(&mut blocks, highlights).is_none() {
        return Ok(literal_fallback(source, highlights));
    }
    let run_count = blocks.iter().map(|block| block.runs.len()).sum::<usize>();
    if blocks.len() > MAX_FORMAT_BLOCKS || run_count > MAX_FORMAT_RUNS {
        return Ok(literal_fallback(source, highlights));
    }

    let plain_text = copy_text(&blocks);
    Ok(FormattedText {
        source: source.to_owned(),
        plain_text,
        blocks: blocks
            .into_iter()
            .map(|block| FormattedTextBlock {
                kind: block.kind,
                depth: block.depth,
                ordinal: block.ordinal,
                runs: block
                    .runs
                    .into_iter()
                    .map(|run| FormattedTextRun {
                        text: run.text,
                        styles: run.styles,
                    })
                    .collect(),
            })
            .collect(),
        used_fallback: false,
    })
}

fn validate_highlights(source: &str, highlights: &[TextFormatHighlight]) -> Result<()> {
    if highlights.len() > MAX_FORMAT_HIGHLIGHTS {
        return Err(NodeError::InvalidTextFormatting);
    }
    let mut prior_end = 0usize;
    for highlight in highlights {
        let start = highlight.start as usize;
        let end = highlight.end as usize;
        if start < prior_end
            || start >= end
            || end > source.len()
            || !source.is_char_boundary(start)
            || !source.is_char_boundary(end)
        {
            return Err(NodeError::InvalidTextFormatting);
        }
        prior_end = end;
    }
    Ok(())
}

fn source_lines(source: &str) -> Vec<Line<'_>> {
    if source.is_empty() {
        return vec![Line { text: "", start: 0 }];
    }
    let mut lines = Vec::new();
    let mut start = 0usize;
    for piece in source.split_inclusive('\n') {
        let without_newline = piece.strip_suffix('\n').unwrap_or(piece);
        let text = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        lines.push(Line { text, start });
        start += piece.len();
    }
    if source.ends_with('\n') {
        lines.push(Line {
            text: "",
            start: source.len(),
        });
    }
    lines
}

fn parse_blocks(lines: &[Line<'_>]) -> Option<Vec<SourceBlock>> {
    let mut blocks = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        if line.text.trim().is_empty() {
            index += 1;
            continue;
        }
        if is_code_fence(line.text) {
            let opening_indent = line.text.len() - line.text.trim_start_matches(' ').len();
            if opening_indent > usize::from(MAX_FORMAT_LIST_DEPTH) * 2 {
                return None;
            }
            index += 1;
            let mut runs = Vec::new();
            while index < lines.len() && !is_closing_code_fence(lines[index].text) {
                if !runs.is_empty() {
                    let newline_start = lines[index].start.saturating_sub(1);
                    push_run(
                        &mut runs,
                        "\n",
                        &[TextFormatStyle::InlineCode],
                        newline_start,
                        lines[index].start,
                    );
                }
                push_run(
                    &mut runs,
                    lines[index].text,
                    &[TextFormatStyle::InlineCode],
                    lines[index].start,
                    lines[index].start + lines[index].text.len(),
                );
                index += 1;
            }
            if index < lines.len() {
                index += 1;
            }
            blocks.push(SourceBlock {
                kind: TextFormatBlockKind::CodeBlock,
                depth: 0,
                ordinal: 0,
                runs,
            });
        } else if let Some((content, offset)) = quote_content(line.text) {
            let mut runs = Vec::new();
            if !parse_inline(content, line.start + offset, 0, &[], &mut runs) {
                return None;
            }
            blocks.push(SourceBlock {
                kind: TextFormatBlockKind::Quote,
                depth: 0,
                ordinal: 0,
                runs,
            });
            index += 1;
        } else if let Some((kind, depth, ordinal, content, offset)) = list_content(line.text) {
            if depth > MAX_FORMAT_LIST_DEPTH {
                return None;
            }
            let mut runs = Vec::new();
            if !parse_inline(content, line.start + offset, 0, &[], &mut runs) {
                return None;
            }
            blocks.push(SourceBlock {
                kind,
                depth,
                ordinal,
                runs,
            });
            index += 1;
        } else {
            let mut runs = Vec::new();
            while index < lines.len()
                && !lines[index].text.trim().is_empty()
                && !is_code_fence(lines[index].text)
                && quote_content(lines[index].text).is_none()
                && list_content(lines[index].text).is_none()
            {
                if !runs.is_empty() {
                    let newline_start = lines[index].start.saturating_sub(1);
                    push_run(&mut runs, "\n", &[], newline_start, lines[index].start);
                }
                if !parse_inline(lines[index].text, lines[index].start, 0, &[], &mut runs) {
                    return None;
                }
                index += 1;
            }
            blocks.push(SourceBlock {
                kind: TextFormatBlockKind::Paragraph,
                depth: 0,
                ordinal: 0,
                runs,
            });
        }
        if blocks.len() > MAX_FORMAT_BLOCKS {
            return None;
        }
    }
    Some(blocks)
}

fn is_code_fence(line: &str) -> bool {
    let trimmed = line.trim_start_matches(' ');
    line.len() - trimmed.len() <= 3 && trimmed.starts_with("```")
}

fn is_closing_code_fence(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 3 && trimmed.chars().all(|value| value == '`')
}

fn quote_content(line: &str) -> Option<(&str, usize)> {
    let trimmed = line.trim_start_matches(' ');
    let indent = line.len() - trimmed.len();
    if indent > 3 || !trimmed.starts_with('>') {
        return None;
    }
    let after = &trimmed[1..];
    let space = usize::from(after.starts_with(' '));
    Some((&after[space..], indent + 1 + space))
}

fn list_content(line: &str) -> Option<(TextFormatBlockKind, u8, u32, &str, usize)> {
    let trimmed = line.trim_start_matches(' ');
    let indent = line.len() - trimmed.len();
    let depth = u8::try_from(indent / 2).ok()?;
    if let Some(rest) = trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "))
        .or_else(|| trimmed.strip_prefix("+ "))
    {
        return Some((
            TextFormatBlockKind::UnorderedListItem,
            depth,
            0,
            rest,
            indent + 2,
        ));
    }
    let digit_count = trimmed
        .bytes()
        .take_while(|value| value.is_ascii_digit())
        .count();
    if !(1..=9).contains(&digit_count) || !trimmed[digit_count..].starts_with(". ") {
        return None;
    }
    let ordinal = trimmed[..digit_count].parse::<u32>().ok()?;
    let offset = indent + digit_count + 2;
    Some((
        TextFormatBlockKind::OrderedListItem,
        depth,
        ordinal,
        &line[offset..],
        offset,
    ))
}

fn parse_inline(
    text: &str,
    source_base: usize,
    depth: usize,
    styles: &[TextFormatStyle],
    runs: &mut Vec<SourceRun>,
) -> bool {
    let mut cursor = 0usize;
    while cursor < text.len() {
        let next = text[cursor..]
            .bytes()
            .position(|value| matches!(value, b'`' | b'*' | b'_'))
            .map(|position| cursor + position)
            .unwrap_or(text.len());
        if next > cursor {
            push_run(
                runs,
                &text[cursor..next],
                styles,
                source_base + cursor,
                source_base + next,
            );
            cursor = next;
        }
        if cursor == text.len() {
            break;
        }

        let marker = text.as_bytes()[cursor];
        if marker == b'`' {
            if let Some(relative) = text[cursor + 1..].find('`') {
                let end = cursor + 1 + relative;
                if end > cursor + 1 {
                    let mut code_styles = styles.to_vec();
                    code_styles.push(TextFormatStyle::InlineCode);
                    push_run(
                        runs,
                        &text[cursor + 1..end],
                        &code_styles,
                        source_base + cursor + 1,
                        source_base + end,
                    );
                    cursor = end + 1;
                    continue;
                }
            }
            push_run(
                runs,
                &text[cursor..cursor + 1],
                styles,
                source_base + cursor,
                source_base + cursor + 1,
            );
            cursor += 1;
            continue;
        }

        let repeated = text[cursor..]
            .bytes()
            .take_while(|value| *value == marker)
            .count();
        if repeated > 3 {
            return false;
        }
        let (width, added): (usize, &[TextFormatStyle]) = if repeated == 3 {
            (3, &[TextFormatStyle::Emphasis, TextFormatStyle::Strong])
        } else if repeated == 2 {
            (2, &[TextFormatStyle::Strong])
        } else {
            (1, &[TextFormatStyle::Emphasis])
        };
        let delimiter = &text[cursor..cursor + width];
        let inner_start = cursor + width;
        if let Some(relative) = text[inner_start..].find(delimiter) {
            let inner_end = inner_start + relative;
            let inner = &text[inner_start..inner_end];
            if !inner.is_empty()
                && !inner.starts_with(char::is_whitespace)
                && !inner.ends_with(char::is_whitespace)
            {
                if depth >= MAX_FORMAT_INLINE_DEPTH {
                    return false;
                }
                let mut nested_styles = styles.to_vec();
                nested_styles.extend_from_slice(added);
                nested_styles.sort_unstable();
                nested_styles.dedup();
                if !parse_inline(
                    inner,
                    source_base + inner_start,
                    depth + 1,
                    &nested_styles,
                    runs,
                ) {
                    return false;
                }
                cursor = inner_end + width;
                continue;
            }
        }
        push_run(
            runs,
            &text[cursor..cursor + width],
            styles,
            source_base + cursor,
            source_base + cursor + width,
        );
        cursor += width;
        if runs.len() > MAX_FORMAT_RUNS {
            return false;
        }
    }
    true
}

fn push_run(
    runs: &mut Vec<SourceRun>,
    text: &str,
    styles: &[TextFormatStyle],
    source_start: usize,
    source_end: usize,
) {
    if text.is_empty() {
        return;
    }
    let mut styles = styles.to_vec();
    styles.sort_unstable();
    styles.dedup();
    runs.push(SourceRun {
        text: text.to_owned(),
        styles,
        source_start,
        source_end,
    });
}

fn apply_highlights(blocks: &mut [SourceBlock], highlights: &[TextFormatHighlight]) -> Option<()> {
    if highlights.is_empty() {
        return Some(());
    }
    for block in blocks {
        let mut rendered = Vec::new();
        for run in block.runs.drain(..) {
            let mut boundaries = vec![run.source_start, run.source_end];
            for highlight in highlights {
                let start = highlight.start as usize;
                let end = highlight.end as usize;
                if start > run.source_start && start < run.source_end {
                    boundaries.push(start);
                }
                if end > run.source_start && end < run.source_end {
                    boundaries.push(end);
                }
            }
            boundaries.sort_unstable();
            boundaries.dedup();
            for range in boundaries.windows(2) {
                let start = range[0];
                let end = range[1];
                let local_start = start.checked_sub(run.source_start)?;
                let local_end = end.checked_sub(run.source_start)?;
                if local_end > run.text.len()
                    || !run.text.is_char_boundary(local_start)
                    || !run.text.is_char_boundary(local_end)
                {
                    return None;
                }
                let mut styles = run.styles.clone();
                if highlights.iter().any(|highlight| {
                    start >= highlight.start as usize && end <= highlight.end as usize
                }) {
                    styles.push(TextFormatStyle::Highlight);
                    styles.sort_unstable();
                    styles.dedup();
                }
                push_run(
                    &mut rendered,
                    &run.text[local_start..local_end],
                    &styles,
                    start,
                    end,
                );
            }
        }
        block.runs = rendered;
    }
    Some(())
}

fn copy_text(blocks: &[SourceBlock]) -> String {
    let mut output = String::new();
    for (index, block) in blocks.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        match block.kind {
            TextFormatBlockKind::Paragraph | TextFormatBlockKind::CodeBlock => {}
            TextFormatBlockKind::Quote => output.push_str("> "),
            TextFormatBlockKind::UnorderedListItem => {
                output.push_str(&"  ".repeat(block.depth as usize));
                output.push_str("• ");
            }
            TextFormatBlockKind::OrderedListItem => {
                output.push_str(&"  ".repeat(block.depth as usize));
                output.push_str(&block.ordinal.to_string());
                output.push_str(". ");
            }
        }
        for run in &block.runs {
            output.push_str(&run.text);
        }
    }
    output
}

fn literal_fallback(source: &str, highlights: &[TextFormatHighlight]) -> FormattedText {
    let mut runs = Vec::new();
    let mut cursor = 0usize;
    for highlight in highlights {
        let start = highlight.start as usize;
        let end = highlight.end as usize;
        if start > cursor {
            runs.push(FormattedTextRun {
                text: source[cursor..start].to_owned(),
                styles: Vec::new(),
            });
        }
        runs.push(FormattedTextRun {
            text: source[start..end].to_owned(),
            styles: vec![TextFormatStyle::Highlight],
        });
        cursor = end;
    }
    if cursor < source.len() || runs.is_empty() {
        runs.push(FormattedTextRun {
            text: source[cursor..].to_owned(),
            styles: Vec::new(),
        });
    }
    FormattedText {
        source: source.to_owned(),
        plain_text: source.to_owned(),
        blocks: vec![FormattedTextBlock {
            kind: TextFormatBlockKind::Paragraph,
            depth: 0,
            ordinal: 0,
            runs,
        }],
        used_fallback: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_token(kind: TextFormatBlockKind) -> &'static str {
        match kind {
            TextFormatBlockKind::Paragraph => "paragraph",
            TextFormatBlockKind::Quote => "quote",
            TextFormatBlockKind::UnorderedListItem => "unordered_list_item",
            TextFormatBlockKind::OrderedListItem => "ordered_list_item",
            TextFormatBlockKind::CodeBlock => "code_block",
        }
    }

    fn style_token(style: TextFormatStyle) -> &'static str {
        match style {
            TextFormatStyle::Emphasis => "emphasis",
            TextFormatStyle::Strong => "strong",
            TextFormatStyle::InlineCode => "inline_code",
            TextFormatStyle::Highlight => "highlight",
        }
    }

    #[test]
    fn shared_parity_corpus_is_exact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/b9-text-formatting-parity.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let source = case["source"].as_str().unwrap();
            let highlights = case["highlights"]
                .as_array()
                .unwrap()
                .iter()
                .map(|highlight| TextFormatHighlight {
                    start: highlight["start"].as_u64().unwrap() as u32,
                    end: highlight["end"].as_u64().unwrap() as u32,
                })
                .collect::<Vec<_>>();
            let formatted = format_text(source, &highlights).unwrap();
            assert_eq!(formatted.source, source, "{}", case["name"]);
            assert_eq!(
                formatted.plain_text,
                case["plain_text"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert_eq!(
                formatted.used_fallback,
                case["used_fallback"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
            let kinds = formatted
                .blocks
                .iter()
                .map(|block| kind_token(block.kind))
                .collect::<Vec<_>>();
            assert_eq!(
                kinds,
                serde_json::from_value::<Vec<String>>(case["block_kinds"].clone()).unwrap()
            );
            let styles = formatted
                .blocks
                .iter()
                .flat_map(|block| &block.runs)
                .flat_map(|run| run.styles.iter().copied())
                .map(style_token)
                .collect::<std::collections::BTreeSet<_>>();
            for required in case["required_styles"].as_array().unwrap() {
                assert!(
                    styles.contains(required.as_str().unwrap()),
                    "{}",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn subset_is_inert_bounded_and_copyable() {
        let source = "*em* **strong** `code`\n> quote\n- item\n2. next\n```html\n<script src=https://evil.invalid></script>\n```";
        let formatted = format_text(source, &[]).unwrap();
        assert!(!formatted.used_fallback);
        assert_eq!(formatted.blocks.len(), 5);
        assert_eq!(formatted.blocks[0].kind, TextFormatBlockKind::Paragraph);
        assert_eq!(formatted.blocks[1].kind, TextFormatBlockKind::Quote);
        assert_eq!(
            formatted.blocks[2].kind,
            TextFormatBlockKind::UnorderedListItem
        );
        assert_eq!(
            formatted.blocks[3].kind,
            TextFormatBlockKind::OrderedListItem
        );
        assert_eq!(formatted.blocks[4].kind, TextFormatBlockKind::CodeBlock);
        assert_eq!(
            formatted.plain_text,
            "em strong code\n> quote\n• item\n2. next\n<script src=https://evil.invalid></script>"
        );
        assert!(formatted
            .blocks
            .iter()
            .flat_map(|block| &block.runs)
            .any(|run| run.styles.contains(&TextFormatStyle::Strong)));
        assert!(formatted.plain_text.contains("<script"));
    }

    #[test]
    fn links_images_html_bidi_and_unknown_syntax_stay_text() {
        let source =
            "[run](javascript:alert(1)) ![remote](https://evil.invalid/x.png) <b>x</b> \u{202e}abc";
        let formatted = format_text(source, &[]).unwrap();
        assert_eq!(formatted.plain_text, source);
        assert_eq!(formatted.blocks[0].runs[0].text, source);
        assert!(formatted.blocks[0].runs[0].styles.is_empty());
    }

    #[test]
    fn exact_source_highlights_compose_with_inline_styles() {
        let source = "**hello @Café**";
        let start = source.find('@').unwrap() as u32;
        let end = source.rfind("**").unwrap() as u32;
        let formatted = format_text(source, &[TextFormatHighlight { start, end }]).unwrap();
        let highlighted = formatted.blocks[0]
            .runs
            .iter()
            .find(|run| run.styles.contains(&TextFormatStyle::Highlight))
            .unwrap();
        assert_eq!(highlighted.text, "@Café");
        assert!(highlighted.styles.contains(&TextFormatStyle::Strong));
    }

    #[test]
    fn every_complexity_bound_falls_back_or_fails_closed() {
        let source = format!("{}x{}", "*".repeat(10), "*".repeat(10));
        assert!(format_text(&source, &[]).unwrap().used_fallback);

        let too_many_blocks = "item\n\n".repeat(MAX_FORMAT_BLOCKS + 1);
        assert!(format_text(&too_many_blocks, &[]).unwrap().used_fallback);

        let too_many_runs = "*x* ".repeat(MAX_FORMAT_RUNS + 1);
        assert!(format_text(&too_many_runs, &[]).unwrap().used_fallback);

        let too_deep_list = format!(
            "{}- item",
            " ".repeat((MAX_FORMAT_LIST_DEPTH as usize + 1) * 2)
        );
        assert!(format_text(&too_deep_list, &[]).unwrap().used_fallback);

        let highlighted_source = "x".repeat((MAX_FORMAT_HIGHLIGHTS + 1) * 2);
        let too_many_highlights = (0..=MAX_FORMAT_HIGHLIGHTS)
            .map(|index| TextFormatHighlight {
                start: (index * 2) as u32,
                end: (index * 2 + 1) as u32,
            })
            .collect::<Vec<_>>();
        assert!(format_text(&highlighted_source, &too_many_highlights).is_err());

        assert!(format_text("é", &[TextFormatHighlight { start: 1, end: 2 }]).is_err());
        assert!(format_text(&"x".repeat(MAX_FORMAT_SOURCE_BYTES + 1), &[]).is_err());
    }
}
