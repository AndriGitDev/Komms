package komms.android

import android.app.AlertDialog
import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import uniffi.kult_ffi.ScheduledMessage

/** Shared pairwise/group editor for an absolute scheduled-send instant. */
fun AppCompatActivity.showScheduledEditor(
    initialBody: String,
    message: ScheduledMessage? = null,
    work: (String, ULong) -> Unit,
    onDone: () -> Unit,
) {
    val calendar = Calendar.getInstance().apply {
        timeInMillis = message?.notBefore?.toLong()?.times(1000)
            ?: (System.currentTimeMillis() + 30 * 60 * 1000)
        set(Calendar.SECOND, 0)
        set(Calendar.MILLISECOND, 0)
    }
    val body = IncognitoEditText(this).apply {
        setText(message?.body ?: initialBody)
        minLines = 2
        maxLines = 8
    }
    val instant = Button(this)
    val hint = TextView(this).apply {
        setText(R.string.scheduled_absolute_hint)
        textSize = 12f
        setTypeface(typeface, Typeface.ITALIC)
    }
    fun updateInstant() {
        instant.text = getString(
            R.string.scheduled_send_at,
            DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                .format(calendar.time),
        )
    }
    instant.setOnClickListener {
        DatePickerDialog(
            this,
            { _, year, month, day ->
                calendar.set(year, month, day)
                TimePickerDialog(
                    this,
                    { _, hour, minute ->
                        calendar.set(Calendar.HOUR_OF_DAY, hour)
                        calendar.set(Calendar.MINUTE, minute)
                        updateInstant()
                    },
                    calendar.get(Calendar.HOUR_OF_DAY),
                    calendar.get(Calendar.MINUTE),
                    android.text.format.DateFormat.is24HourFormat(this),
                ).show()
            },
            calendar.get(Calendar.YEAR),
            calendar.get(Calendar.MONTH),
            calendar.get(Calendar.DAY_OF_MONTH),
        ).show()
    }
    updateInstant()
    val content = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val pad = (20 * resources.displayMetrics.density).toInt()
        setPadding(pad, 0, pad, 0)
        addView(body, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ))
        addView(instant)
        addView(hint)
    }
    val dialog = AlertDialog.Builder(this)
        .setTitle(if (message == null) R.string.scheduled_dialog_new else R.string.scheduled_dialog_edit)
        .setView(content)
        .setPositiveButton(if (message == null) R.string.chat_schedule else R.string.scheduled_edit, null)
        .setNegativeButton(android.R.string.cancel, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val text = body.text.toString().trim()
            when {
                text.isEmpty() -> toast(getString(R.string.scheduled_need_body))
                calendar.timeInMillis <= System.currentTimeMillis() ->
                    toast(getString(R.string.scheduled_need_future))
                else -> {
                    dialog.dismiss()
                    runNode(work = { work(text, (calendar.timeInMillis / 1000).toULong()) }) {
                        onDone()
                    }
                }
            }
        }
    }
    dialog.show()
}

/** Render the conversation's still-editable scheduled rows below history. */
fun AppCompatActivity.renderScheduledOutbox(
    messages: List<ScheduledMessage>,
    edit: (ScheduledMessage) -> Unit,
    cancel: (ScheduledMessage) -> Unit,
) {
    val section = findViewById<View>(R.id.chat_scheduled_section)
    val rows = findViewById<LinearLayout>(R.id.chat_scheduled)
    rows.removeAllViews()
    section.visibility = if (messages.isEmpty()) View.GONE else View.VISIBLE
    for (message in messages.sortedBy { it.notBefore }) {
        val row = LayoutInflater.from(this)
            .inflate(R.layout.row_scheduled_message, rows, false)
        row.findViewById<TextView>(R.id.scheduled_body).text = message.body
        row.findViewById<TextView>(R.id.scheduled_time).text = getString(
            R.string.scheduled_send_at,
            DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                .format(Date(message.notBefore.toLong() * 1000)),
        )
        row.findViewById<Button>(R.id.scheduled_edit).setOnClickListener { edit(message) }
        row.findViewById<Button>(R.id.scheduled_cancel).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.scheduled_cancel_title)
                .setMessage(message.body)
                .setPositiveButton(R.string.scheduled_cancel_action) { _, _ -> cancel(message) }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
        rows.addView(row)
    }
}
