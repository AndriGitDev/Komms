package komms.android

import android.app.AlertDialog
import android.os.Bundle
import android.text.InputFilter
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import uniffi.kult_ffi.Folder
import uniffi.kult_ffi.FolderTarget

internal fun AppCompatActivity.folderSummary(folder: Folder): String =
    getString(R.string.folder_accessible_summary, folder.name, folder.order.toLong() + 1)

private fun validFolderName(name: String): Boolean {
    if (name.isEmpty() || name.toByteArray(StandardCharsets.UTF_8).size > 256) return false
    val patternWhitespace = setOf(
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0x200e, 0x200f, 0x2028, 0x2029,
    )
    return name.codePoints().toArray().any { it !in patternWhitespace }
}

/** TalkBack/switch/keyboard accessible manager with non-drag atomic reorder. */
class FolderManagerActivity : SecureActivity() {
    private lateinit var content: LinearLayout
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        title = getString(R.string.folders_title)
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
            text = getString(R.string.folder_create)
            contentDescription = getString(R.string.folder_create_description)
            setOnClickListener { editFolder(null) }
        })
        content.addView(status)
        setContentView(ScrollView(this).apply { addView(content) })
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
        runNode(work = { session.folders() to session.staleFolders() }) { (folders, stale) ->
            while (content.childCount > 2) content.removeViewAt(2)
            if (folders.isEmpty()) content.addView(text(getString(R.string.folders_empty)))
            folders.forEachIndexed { index, folder ->
                val row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(0, dp(8), 0, dp(8))
                }
                row.addView(text(folderSummary(folder)).apply {
                    textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                })
                row.addView(Button(this).apply {
                    text = "↑"
                    isEnabled = index > 0
                    contentDescription = getString(R.string.folder_move_up, folderSummary(folder))
                    setOnClickListener { reorder(folders, index, index - 1, folder) }
                })
                row.addView(Button(this).apply {
                    text = "↓"
                    isEnabled = index + 1 < folders.size
                    contentDescription = getString(R.string.folder_move_down, folderSummary(folder))
                    setOnClickListener { reorder(folders, index, index + 1, folder) }
                })
                row.addView(Button(this).apply {
                    text = getString(R.string.folder_edit)
                    contentDescription = getString(R.string.folder_edit_description, folderSummary(folder))
                    setOnClickListener { editFolder(folder) }
                })
                row.addView(Button(this).apply {
                    text = getString(R.string.folder_delete)
                    contentDescription = getString(R.string.folder_delete_description, folderSummary(folder))
                    setOnClickListener { previewDelete(folder) }
                })
                content.addView(row)
            }
            if (stale.isNotEmpty()) {
                content.addView(text(getString(R.string.folder_stale_heading)).apply { textSize = 18f })
                content.addView(text(getString(R.string.folder_stale_help)))
            }
            stale.forEach { record ->
                val target = when (record.target.kind.name) {
                    "NOTE_TO_SELF" -> getString(R.string.note_to_self_title)
                    "GROUP" -> getString(R.string.label_group_conversation)
                    else -> getString(R.string.label_contact_conversation)
                }
                content.addView(Button(this).apply {
                    text = getString(R.string.folder_stale_cleanup, target)
                    contentDescription = getString(R.string.folder_stale_cleanup_description, target)
                    setOnClickListener {
                        runNode(work = { session.cleanupStaleFolder(record.folder, record.target) }) {
                            announce(getString(R.string.folder_stale_cleaned, target))
                            refresh()
                        }
                    }
                })
            }
        }
    }

    private fun reorder(folders: List<Folder>, from: Int, to: Int, folder: Folder) {
        val ids = folders.map { it.id }.toMutableList()
        val moved = ids.removeAt(from)
        ids.add(to, moved)
        val session = NodeHolder.session ?: return
        runNode(work = { session.reorderFolders(ids) }) {
            announce(getString(R.string.folder_reordered, folderSummary(folder), to + 1))
            refresh()
        }
    }

    private fun editFolder(existing: Folder?) {
        val name = EditText(this).apply {
            setText(existing?.name.orEmpty())
            hint = getString(R.string.folder_name)
            textDirection = View.TEXT_DIRECTION_FIRST_STRONG
            filters = arrayOf(InputFilter.LengthFilter(256))
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(if (existing == null) R.string.folder_create else R.string.folder_edit)
            .setView(name)
            .setPositiveButton(if (existing == null) R.string.folder_create else R.string.folder_save, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val exactName = name.text.toString()
                if (!validFolderName(exactName)) {
                    name.error = getString(R.string.folder_invalid_name)
                    name.requestFocus()
                    return@setOnClickListener
                }
                val session = NodeHolder.session ?: return@setOnClickListener
                runNode(work = {
                    if (existing == null) session.createFolder(exactName)
                    else session.renameFolder(existing.id, exactName)
                }) { saved ->
                    dialog.dismiss()
                    announce(getString(if (existing == null) R.string.folder_created else R.string.folder_updated, folderSummary(saved)))
                    refresh()
                }
            }
        }
        dialog.setOnCancelListener { announce(getString(R.string.folder_edit_cancelled)) }
        dialog.show()
    }

    private fun previewDelete(folder: Folder) {
        val session = NodeHolder.session ?: return
        runNode(work = { session.folderDeleteAssignmentCount(folder.id) }) { count ->
            AlertDialog.Builder(this)
                .setTitle(R.string.folder_delete_title)
                .setMessage(getString(R.string.folder_delete_review, folderSummary(folder), count.toLong()))
                .setPositiveButton(R.string.folder_delete) { _, _ ->
                    runNode(work = { session.deleteFolder(folder.id, true) }) { deleted ->
                        announce(getString(R.string.folder_deleted, deleted.toLong()))
                        refresh()
                    }
                }
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    announce(getString(R.string.folder_delete_cancelled))
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

/** Explicit single-membership move UI shared by every conversation type. */
internal fun AppCompatActivity.showFolderAssignment(target: FolderTarget, targetName: String) {
    val session = NodeHolder.session ?: return
    runNode(work = { session.folders() to session.conversationFolder(target) }) { (folders, current) ->
        val names = (listOf(getString(R.string.folder_unfiled)) + folders.map(::folderSummary)).toTypedArray()
        val checked = current?.let { folder -> folders.indexOfFirst { it.id == folder.id } + 1 } ?: 0
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.folder_assignment_title, targetName))
            .setSingleChoiceItems(names, checked) { dialog, which ->
                runNode(work = {
                    if (which == 0) session.unfileConversation(target)
                    else session.moveToFolder(folders[which - 1].id, target)
                    session.conversationFolder(target)
                }) { final ->
                    val destination = final?.let(::folderSummary) ?: getString(R.string.folder_unfiled)
                    toast(getString(R.string.folder_assignment_result, targetName, destination))
                    dialog.dismiss()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
