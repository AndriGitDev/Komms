package komms.android

import android.app.AlertDialog
import android.text.InputType
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.DateFormat
import java.util.Date
import uniffi.kult_ffi.EditVersion

/** Native, incognito-configured editor for one immutable message edit event. */
fun AppCompatActivity.showMessageEdit(
    initial: String,
    save: (String) -> Unit,
) {
    val density = resources.displayMetrics.density
    val content = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding((24 * density).toInt(), 0, (24 * density).toInt(), 0)
    }
    content.addView(TextView(this).apply {
        setText(R.string.message_edit_explanation)
    })
    val input = IncognitoEditText(this).apply {
        setText(initial)
        setSelection(text?.length ?: 0)
        minLines = 3
        maxLines = 8
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
    }
    content.addView(input)
    val dialog = AlertDialog.Builder(this)
        .setTitle(R.string.message_edit_title)
        .setView(content)
        .setPositiveButton(R.string.message_edit_save, null)
        .setNegativeButton(android.R.string.cancel, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val replacement = input.text?.toString().orEmpty()
            if (replacement.isEmpty()) {
                input.error = getString(R.string.message_edit_empty)
            } else {
                dialog.dismiss()
                save(replacement)
            }
        }
        input.requestFocus()
    }
    dialog.show()
}

/** Inspect the original and every valid immutable edit without guessing order. */
fun AppCompatActivity.showEditHistory(versions: List<EditVersion>) {
    val text = versions.asReversed().joinToString("\n\n") { version ->
        val label = if (version.revision == 0UL) {
            getString(R.string.message_history_original)
        } else {
            getString(R.string.message_history_revision, version.revision.toString())
        }
        val time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date(version.timestamp.toLong() * 1000))
        "$label · $time\n${version.body}"
    }
    AlertDialog.Builder(this)
        .setTitle(R.string.message_history_title)
        .setMessage(text)
        .setPositiveButton(android.R.string.ok, null)
        .show()
}
