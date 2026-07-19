package komms.android

import android.app.AlertDialog
import android.os.Bundle
import android.text.InputFilter
import android.view.Gravity
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import uniffi.kult_ffi.Label
import uniffi.kult_ffi.LabelTarget

internal val labelColors = listOf(
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
)

internal fun AppCompatActivity.labelColorName(token: String): String = getString(
    when (token) {
        "red" -> R.string.label_color_red
        "orange" -> R.string.label_color_orange
        "yellow" -> R.string.label_color_yellow
        "green" -> R.string.label_color_green
        "teal" -> R.string.label_color_teal
        "blue" -> R.string.label_color_blue
        "purple" -> R.string.label_color_purple
        "pink" -> R.string.label_color_pink
        else -> R.string.label_color_neutral
    },
)

internal fun AppCompatActivity.labelSummary(label: Label): String =
    getString(R.string.label_accessible_summary, label.name, labelColorName(label.color), label.order.toLong() + 1)

private fun validLabelName(name: String): Boolean {
    if (name.isEmpty() || name.toByteArray(StandardCharsets.UTF_8).size > 256) return false
    val patternWhitespace = setOf(
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0x200e, 0x200f, 0x2028, 0x2029,
    )
    return name.codePoints().toArray().any { it !in patternWhitespace }
}

/** Native manager: TalkBack traverses create, stable rows, edit/delete, then stale cleanup. */
class LabelManagerActivity : SecureActivity() {
    private lateinit var content: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        title = getString(R.string.labels_title)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
        }
        status = TextView(this).apply {
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
            isFocusable = true
        }
        content.addView(Button(this).apply {
            text = getString(R.string.label_create)
            contentDescription = getString(R.string.label_create_description)
            setOnClickListener { editLabel(null) }
        })
        content.addView(status)
        setContentView(ScrollView(this).apply { addView(content) })
        applyEdgeToEdgeInsets()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.labels() to session.staleLabels() }) { (labels, stale) ->
            while (content.childCount > 2) content.removeViewAt(2)
            if (labels.isEmpty()) content.addView(text(getString(R.string.labels_empty)))
            labels.forEach { label ->
                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(0, dp(8), 0, dp(8))
                }
                row.addView(text(labelSummary(label)).apply {
                    textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                })
                row.addView(Button(this).apply {
                    text = getString(R.string.label_edit)
                    contentDescription = getString(R.string.label_edit_description, labelSummary(label))
                    setOnClickListener { editLabel(label) }
                })
                row.addView(Button(this).apply {
                    text = getString(R.string.label_delete)
                    contentDescription = getString(R.string.label_delete_description, labelSummary(label))
                    setOnClickListener { previewDelete(label) }
                })
                content.addView(row)
            }
            if (stale.isNotEmpty()) {
                content.addView(text(getString(R.string.label_stale_heading)).apply { textSize = 18f })
                content.addView(text(getString(R.string.label_stale_help)))
            }
            stale.forEach { record ->
                val target = when (record.target.kind.name) {
                    "NOTE_TO_SELF" -> getString(R.string.note_to_self_title)
                    "GROUP" -> getString(R.string.label_group_conversation)
                    else -> getString(R.string.label_contact_conversation)
                }
                content.addView(Button(this).apply {
                    text = getString(R.string.label_stale_cleanup, target)
                    contentDescription = getString(R.string.label_stale_cleanup_description, target)
                    setOnClickListener {
                        runNode(work = { session.cleanupStaleLabel(record.label, record.target) }) {
                            announce(getString(R.string.label_stale_cleaned, target))
                            refresh()
                        }
                    }
                })
            }
        }
    }

    private fun editLabel(existing: Label?) {
        val name = IncognitoEditText(this).apply {
            setText(existing?.name.orEmpty())
            hint = getString(R.string.label_name)
            textDirection = View.TEXT_DIRECTION_FIRST_STRONG
            filters = arrayOf(InputFilter.LengthFilter(256))
        }
        val color = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@LabelManagerActivity,
                android.R.layout.simple_spinner_dropdown_item,
                labelColors.map(::labelColorName),
            )
            setSelection(labelColors.indexOf(existing?.color).coerceAtLeast(0))
            contentDescription = getString(R.string.label_color)
        }
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), 0, dp(20), 0)
            addView(name)
            addView(color)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(if (existing == null) R.string.label_create else R.string.label_edit)
            .setView(form)
            .setPositiveButton(if (existing == null) R.string.label_create else R.string.label_save, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val exactName = name.text.toString()
                if (!validLabelName(exactName)) {
                    name.error = getString(R.string.label_invalid_name)
                    name.requestFocus()
                    return@setOnClickListener
                }
                val token = labelColors[color.selectedItemPosition]
                val session = NodeHolder.session ?: return@setOnClickListener
                runNode(work = {
                    if (existing == null) session.createLabel(exactName, token)
                    else session.updateLabel(existing.id, exactName, token)
                }) { saved ->
                    dialog.dismiss()
                    announce(getString(if (existing == null) R.string.label_created else R.string.label_updated, labelSummary(saved)))
                    refresh()
                }
            }
        }
        dialog.setOnCancelListener { announce(getString(R.string.label_edit_cancelled)) }
        dialog.show()
    }

    private fun previewDelete(label: Label) {
        val session = NodeHolder.session ?: return
        runNode(work = { session.labelDeleteAssignmentCount(label.id) }) { count ->
            AlertDialog.Builder(this)
                .setTitle(R.string.label_delete_title)
                .setMessage(getString(R.string.label_delete_review, labelSummary(label), count.toLong()))
                .setPositiveButton(R.string.label_delete) { _, _ ->
                    runNode(work = { session.deleteLabel(label.id, true) }) { deleted ->
                        announce(getString(R.string.label_deleted, deleted.toLong()))
                        refresh()
                    }
                }
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    announce(getString(R.string.label_delete_cancelled))
                }
                .show()
        }
    }

    private fun announce(message: String) {
        status.text = message
        status.announceForAccessibility(message)
        status.requestFocus()
    }

    private fun text(value: String) = TextView(this).apply { text = value; setPadding(0, dp(8), 0, dp(8)) }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}

/** Exact typed assignment UI shared by peer, group, and note-to-self screens. */
internal fun AppCompatActivity.showLabelAssignments(target: LabelTarget, targetName: String) {
    val session = NodeHolder.session ?: return
    runNode(work = { session.labels() to session.labelsForConversation(target) }) { (labels, current) ->
        if (labels.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle(R.string.labels_title)
                .setMessage(R.string.labels_empty_assignment)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return@runNode
        }
        val checked = current.map { it.id }.toMutableSet()
        val summaries = labels.map(::labelSummary).toTypedArray()
        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.label_assignment_title, targetName))
            .setMultiChoiceItems(summaries, labels.map { it.id in checked }.toBooleanArray()) { _, which, selected ->
                val label = labels[which]
                runNode(work = {
                    if (selected) session.assignLabel(label.id, target)
                    else session.unassignLabel(label.id, target)
                    session.labelsForConversation(target)
                }) { final ->
                    checked.clear()
                    checked.addAll(final.map { it.id })
                    val applied = label.id in checked
                    toast(getString(R.string.label_assignment_result, labelSummary(label), targetName, if (applied) getString(R.string.label_applied) else getString(R.string.label_removed), final.size))
                }
            }
            .setPositiveButton(R.string.label_done, null)
            .create()
        dialog.setOnShowListener {
            dialog.listView.contentDescription = getString(R.string.label_assignment_list_description, targetName)
        }
        dialog.show()
    }
}
