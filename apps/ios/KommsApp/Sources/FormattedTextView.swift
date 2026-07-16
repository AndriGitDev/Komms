import KommsCore
import SwiftUI

/// A native-only rendering of the bounded shared text model.
struct FormattedTextView: View {
    let formatted: FormattedText

    var body: some View {
        Text(attributedText)
            .textSelection(.enabled)
            .accessibilityLabel(formatted.plainText)
    }

    private var attributedText: AttributedString {
        var output = AttributedString()
        for (index, block) in formatted.blocks.enumerated() {
            if index > 0 { output.append(AttributedString("\n")) }
            switch block.kind {
            case .paragraph, .codeBlock:
                break
            case .quote:
                output.append(AttributedString("> "))
            case .unorderedListItem:
                output.append(AttributedString(String(repeating: "  ", count: Int(block.depth)) + "• "))
            case .orderedListItem:
                output.append(AttributedString(
                    String(repeating: "  ", count: Int(block.depth)) + "\(block.ordinal). "))
            }
            for run in block.runs {
                var segment = AttributedString(run.text)
                var font = Font.body
                if run.styles.contains(.inlineCode) { font = font.monospaced() }
                if run.styles.contains(.strong) { font = font.bold() }
                if run.styles.contains(.emphasis) { font = font.italic() }
                segment.font = font
                if run.styles.contains(.inlineCode) {
                    segment.backgroundColor = Color.primary.opacity(0.08)
                }
                if run.styles.contains(.highlight) {
                    segment.backgroundColor = Color.yellow.opacity(0.28)
                    segment.underlineStyle = .single
                }
                output.append(segment)
            }
        }
        assert(String(output.characters) == formatted.plainText)
        return output
    }
}
