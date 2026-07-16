# 16: Safe Text Formatting

B9 is shipped as a local display feature across `kult-node`, strict RPC/CLI,
UniFFI, desktop, Android, and iOS. Komms stores and transmits the exact UTF-8
source a person wrote. Formatting is derived only on the receiving endpoint and
is never a second message representation.

## Supported source subset

The syntax is deliberately smaller than CommonMark:

| Source | Local presentation |
|---|---|
| `*emphasis*` or `_emphasis_` | Emphasis |
| `**strong**` or `__strong__` | Strong emphasis |
| `` `code` `` | Inline monospace code |
| triple-backtick fenced lines | Inert code block; an optional info string is ignored |
| `> quote` | Quote block |
| `- item`, `* item`, or `+ item` | Unordered list item |
| `1. item` | Ordered list item |

Strong and emphasis may nest within the shared depth bound. List indentation is
represented in two-space steps. This is a source-text convenience, not a claim
of full CommonMark compatibility: headings, tables, task lists, link parsing,
embedded media, and arbitrary block nesting are not supported.

## Active content is never interpreted

Raw HTML remains visible text. Markdown links and images remain visible source.
Komms does not turn any URL scheme into a link, fetch remote images, resolve
previews, run scripts, load styles, or hand formatted content to an HTML parser.
Desktop constructs a fixed set of DOM text/block elements and text nodes;
Android constructs `SpannableStringBuilder` styles; iOS constructs a native
`AttributedString`. None of those renderers creates `href`, `src`, or network
behavior from message content.

Formatting therefore adds no DNS, HTTP, analytics, preview, notification,
capability, queue, or transport work. It is not a sanitizer for exporting source
into some other rich-text engine; callers must use the bounded display model.

## Source, compatibility, and copy

- The authenticated source is unchanged in pairwise, group, note-to-self, and
  scheduled history. There is no store migration, backup bump, content kind,
  capability bit, negotiation, or envelope change.
- An older client shows the readable source markers. A newer client derives the
  same display model whether the source arrived as legacy text or typed `Text`.
- Copying formatted history produces a readable plain-text projection. Inline
  markers and code fences are removed; quote and list meaning remains as `>`,
  `•`, indentation, and ordered numbers.
- B17 mention spans remain authenticated UTF-8 byte ranges. The formatter
  composes them as an inert `highlight` style with emphasis, strong, or code;
  it never guesses a mention from free-form `@text`.

## Bounds and failure behavior

One formatting call accepts at most 64 KiB of UTF-8 source, 1,024 blocks, 4,096
display runs, inline nesting depth 4, list depth 4, and 64 sorted,
non-overlapping semantic highlight ranges. Highlights must use exact UTF-8
boundaries. Oversized source or invalid ranges return an error. Excessive supported-syntax
complexity does not partially reinterpret the message: the whole exact source
is returned as one literal paragraph with `used_fallback = true`.

The shared result contains only:

- exact `source` and readable `plain_text`;
- block roles (`paragraph`, `quote`, list item, or `code_block`);
- text runs with inert `emphasis`, `strong`, `inline_code`, and `highlight`
  tokens; and
- the literal-fallback flag.

There are no URLs, resources, callbacks, element attributes, or executable
objects in the model.

## Front doors

- Rust callers use `kult_node::format_text`.
- Local RPC uses strict `format_text { source, highlights }`; the CLI command is
  `kult format-text TEXT...` and prints the stable JSON model.
- Kotlin and Swift call `KultNode.formatText` through UniFFI; their `Session`
  wrappers expose the same operation.
- Every shipped bubble path—pairwise, group, note-to-self, and scheduled—uses
  this model. Native selection remains enabled for scalable, plain-text copy.

## Qualification

`fixtures/b9-text-formatting-parity.json` is the cross-surface conformance
corpus. Rust core, RPC, UniFFI, desktop, Kotlin, and Swift tests apply its exact
source, plain-text projection, block roles, fallback state, and highlight
ranges. Additional tests cover malformed UTF-8 offsets, source and complexity
limits, raw HTML, `javascript:` text, remote-image syntax, bidi controls, exact
source delivery/history, no delivery work, native source inventory, and the
absence of active-content APIs in each formatting renderer.

Manual release qualification should still exercise Dynamic Type/font scaling,
TalkBack/VoiceOver, keyboard selection and copy, high contrast, RTL paragraphs,
long code blocks, and mixed formatting-plus-mention content on real devices.
