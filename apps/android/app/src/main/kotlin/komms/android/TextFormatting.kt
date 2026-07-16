package komms.android

import android.graphics.Typeface
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextPaint
import android.text.method.LinkMovementMethod
import android.text.style.BackgroundColorSpan
import android.text.style.ClickableSpan
import android.text.style.StyleSpan
import android.text.style.TypefaceSpan
import android.text.style.UnderlineSpan
import android.view.View
import android.widget.TextView
import uniffi.kult_ffi.FormattedText
import uniffi.kult_ffi.TextFormatBlockKind
import uniffi.kult_ffi.TextFormatStyle

/** A stored value paired with its shared, bounded local display model. */
data class RenderedMessage<T>(val value: T, val formatted: FormattedText)

private class SemanticHighlightSpan(private val label: String) : ClickableSpan() {
    override fun onClick(widget: View) = widget.announceForAccessibility(label)

    override fun updateDrawState(paint: TextPaint) {
        paint.bgColor = 0x334CAF50
        paint.isUnderlineText = true
        paint.typeface = Typeface.create(paint.typeface, Typeface.BOLD)
    }
}

/**
 * Build only native inert text spans from the shared model. The displayed
 * characters exactly equal `plainText`, so Android's selection action copies
 * readable plain text with no formatting markers.
 */
fun renderFormattedText(
    formatted: FormattedText,
    highlightLabels: List<String> = emptyList(),
): CharSequence {
    val output = SpannableStringBuilder()
    var highlightIndex = 0
    var continuingHighlight = false
    for ((blockIndex, block) in formatted.blocks.withIndex()) {
        if (blockIndex > 0) output.append('\n')
        when (block.kind) {
            TextFormatBlockKind.PARAGRAPH, TextFormatBlockKind.CODE_BLOCK -> Unit
            TextFormatBlockKind.QUOTE -> output.append("> ")
            TextFormatBlockKind.UNORDERED_LIST_ITEM -> {
                repeat(block.depth.toInt()) { output.append("  ") }
                output.append("• ")
            }
            TextFormatBlockKind.ORDERED_LIST_ITEM -> {
                repeat(block.depth.toInt()) { output.append("  ") }
                output.append(block.ordinal.toString()).append(". ")
            }
        }
        for (run in block.runs) {
            val start = output.length
            output.append(run.text)
            val end = output.length
            if (end == start) continue
            if (TextFormatStyle.EMPHASIS in run.styles) {
                output.setSpan(StyleSpan(Typeface.ITALIC), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            if (TextFormatStyle.STRONG in run.styles) {
                output.setSpan(StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            if (TextFormatStyle.INLINE_CODE in run.styles) {
                output.setSpan(TypefaceSpan("monospace"), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                output.setSpan(BackgroundColorSpan(0x22000000), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            val highlighted = TextFormatStyle.HIGHLIGHT in run.styles
            if (highlighted) {
                val labelIndex = if (continuingHighlight) {
                    (highlightIndex - 1).coerceAtLeast(0)
                } else {
                    highlightIndex
                }
                val label = highlightLabels.getOrNull(labelIndex) ?: "Highlighted mention"
                output.setSpan(SemanticHighlightSpan(label), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                output.setSpan(UnderlineSpan(), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                if (!continuingHighlight) highlightIndex += 1
            }
            continuingHighlight = highlighted
        }
        continuingHighlight = false
    }
    check(output.toString() == formatted.plainText) { "shared formatting projection mismatch" }
    return output
}

/** Apply formatted text with selection and optional accessible mention actions. */
fun TextView.showFormattedText(
    formatted: FormattedText,
    highlightLabels: List<String> = emptyList(),
) {
    text = renderFormattedText(formatted, highlightLabels)
    setTextIsSelectable(true)
    movementMethod = if (highlightLabels.isEmpty()) null else LinkMovementMethod.getInstance()
}
