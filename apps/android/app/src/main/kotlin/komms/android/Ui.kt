package komms.android

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import uniffi.kult_ffi.FfiException
import komms.core.reasonText

/** The error text a user sees: the node's own words, nothing invented. */
fun errorText(e: Throwable): String = when (e) {
    is FfiException -> e.reasonText()
    else -> e.message ?: e.toString()
}

fun Context.toast(text: String) {
    Toast.makeText(this, text, Toast.LENGTH_LONG).show()
}

/**
 * Run blocking node work on [NodeHolder.executor], then deliver the result
 * (or the honest error text) on the UI thread — skipped if the activity is
 * already gone.
 */
fun <T> AppCompatActivity.runNode(
    work: () -> T,
    onError: (String) -> Unit = { toast(it) },
    onDone: (T) -> Unit,
) {
    NodeHolder.executor.execute {
        val result = runCatching(work)
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            result.fold(onDone) { e -> onError(errorText(e)) }
        }
    }
}
