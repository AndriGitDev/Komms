package komms.android

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject
import uniffi.kult_ffi.FfiException

/** Localized, bounded presentation for a typed failure at the UI boundary. */
fun Context.errorText(e: Throwable): String = when (e) {
    is FfiException.Startup -> getString(R.string.error_startup)
    is FfiException.Stopped -> getString(R.string.error_node_stopped)
    is FfiException.Folder -> getString(R.string.error_folder)
    is FfiException.Label -> getString(R.string.error_label)
    is FfiException.Pin -> getString(R.string.error_pin)
    is FfiException.Node -> getString(R.string.error_generic)
    is IllegalArgumentException -> getString(R.string.error_input)
    else -> getString(R.string.error_generic)
}

/** Source-key adapter for static shell copy and exact shared-core policy text. */
fun Context.localizedSource(source: String): String {
    val messageId = LocalizationSourceIds.get(this)[source] ?: return source
    val resourceId = resources.getIdentifier(messageId, "string", packageName)
    return if (resourceId == 0) source else getString(resourceId)
}

private object LocalizationSourceIds {
    @Volatile private var cached: Map<String, String>? = null

    fun get(context: Context): Map<String, String> {
        cached?.let { return it }
        return synchronized(this) {
            cached ?: context.resources
                .openRawResource(R.raw.localization_source_ids)
                .bufferedReader(Charsets.UTF_8)
                .use { reader ->
                    val document = JSONObject(reader.readText())
                    buildMap(document.length()) {
                        val keys = document.keys()
                        while (keys.hasNext()) {
                            val key = keys.next()
                            put(key, document.getString(key))
                        }
                    }
                }
                .also { cached = it }
        }
    }
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
            result.fold(onDone) { e -> onError(this.errorText(e)) }
        }
    }
}
