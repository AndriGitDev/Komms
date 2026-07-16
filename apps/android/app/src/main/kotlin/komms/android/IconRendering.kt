package komms.android

import android.content.Context
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.Rect
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import uniffi.kult_ffi.CustomIcon

internal fun customIconDrawable(
    context: Context,
    icon: CustomIcon?,
    label: String,
    sizeDp: Int = 44,
): Drawable {
    val size = (sizeDp * context.resources.displayMetrics.density).toInt().coerceAtLeast(1)
    val bitmap = icon?.bytes?.let { bytes ->
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }
    return if (bitmap != null) {
        BitmapDrawable(context.resources, bitmap).apply {
            isAntiAlias = true
            bounds = Rect(0, 0, size, size)
        }
    } else {
        InitialsDrawable(initials(label), size)
    }
}

private fun initials(label: String): String {
    val words = label.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    if (words.isEmpty()) return "?"
    val first = words.first().firstOrNull()?.toString().orEmpty()
    val last = if (words.size > 1) words.last().firstOrNull()?.toString().orEmpty() else ""
    return (first + last).uppercase()
}

private class InitialsDrawable(
    private val initials: String,
    private val size: Int,
) : Drawable() {
    private val background = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.rgb(38, 139, 112) }
    private val text = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.WHITE
        textAlign = Paint.Align.CENTER
        textSize = size * 0.36f
        typeface = android.graphics.Typeface.DEFAULT_BOLD
    }

    init {
        bounds = Rect(0, 0, size, size)
    }

    override fun draw(canvas: Canvas) {
        val bounds = bounds
        val radius = minOf(bounds.width(), bounds.height()) / 2f
        canvas.drawCircle(bounds.exactCenterX(), bounds.exactCenterY(), radius, background)
        val baseline = bounds.exactCenterY() - (text.ascent() + text.descent()) / 2f
        canvas.drawText(initials, bounds.exactCenterX(), baseline, text)
    }

    override fun setAlpha(alpha: Int) {
        background.alpha = alpha
        text.alpha = alpha
    }

    override fun setColorFilter(colorFilter: android.graphics.ColorFilter?) {
        background.colorFilter = colorFilter
        text.colorFilter = colorFilter
    }

    @Deprecated("Deprecated in Android")
    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT

    override fun getIntrinsicWidth(): Int = size
    override fun getIntrinsicHeight(): Int = size
}
