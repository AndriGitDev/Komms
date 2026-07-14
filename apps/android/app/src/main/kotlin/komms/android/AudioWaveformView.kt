package komms.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import kotlin.math.max

/** Local-only waveform peaks; the values are never stored in attachment metadata. */
class AudioWaveformView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = context.getColor(R.color.primary)
        strokeWidth = resources.displayMetrics.density * 2f
    }
    private var peaks: List<UShort> = emptyList()

    fun submit(values: List<UShort>) {
        peaks = values
        contentDescription = context.getString(R.string.audio_waveform_description)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (peaks.isEmpty()) return
        val maximum = max(1, peaks.maxOf { it.toInt() })
        val step = width.toFloat() / peaks.size
        val middle = height / 2f
        peaks.forEachIndexed { index, peak ->
            val half = max(1f, middle * peak.toInt() / maximum)
            val x = (index + 0.5f) * step
            canvas.drawLine(x, middle - half, x, middle + half, paint)
        }
    }
}
