package komms.android

import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.text.DateFormat
import java.util.Date
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.FolderTarget
import uniffi.kult_ffi.FolderTargetKind
import uniffi.kult_ffi.NoteMessage
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.LabelTargetKind

/** The reserved sealed local conversation. Notes have no transport or delivery state. */
class NoteToSelfActivity : SecureActivity() {
    private lateinit var conversation: String
    private val adapter = NoteMessagesAdapter()

    private val listener: (Event) -> Unit = { event ->
        if (event is Event.NoteToSelfMessageAdded && event.conversation == conversation) {
            runOnUiThread { refresh() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val session = NodeHolder.session ?: return finish()
        conversation = intent.getStringExtra("conversation") ?: return finish()
        if (conversation != session.noteToSelfId()) return finish()

        setContentView(R.layout.activity_chat)
        applyEdgeToEdgeInsets()
        configureComposerMenu()
        setSupportActionBar(findViewById(R.id.chat_toolbar))
        supportActionBar?.title = getString(R.string.note_to_self_title)
        supportActionBar?.subtitle = getString(R.string.note_local_only)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val list = findViewById<RecyclerView>(R.id.chat_messages)
        list.layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        list.adapter = adapter

        val input = findViewById<EditText>(R.id.chat_input)
        findViewById<android.view.View>(R.id.chat_send).setOnClickListener {
            val body = input.text.toString()
            if (body.isEmpty()) return@setOnClickListener
            val current = NodeHolder.session ?: return@setOnClickListener
            runNode(work = { current.sendNoteToSelf(body) }) {
                input.text.clear()
                refresh()
            }
        }
        NodeHolder.addListener(listener)
    }

    override fun onDestroy() {
        NodeHolder.removeListener(listener)
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.note_to_self, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        R.id.menu_folder -> {
            showFolderAssignment(
                FolderTarget(FolderTargetKind.NOTE_TO_SELF, null),
                getString(R.string.note_to_self_title),
            )
            true
        }
        R.id.menu_labels -> {
            showLabelAssignments(
                LabelTarget(LabelTargetKind.NOTE_TO_SELF, null),
                getString(R.string.note_to_self_title),
            )
            true
        }
        R.id.menu_pin -> {
            togglePin(uniffi.kult_ffi.PinTarget(uniffi.kult_ffi.PinTargetKind.NOTE_TO_SELF, null))
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun togglePin(target: uniffi.kult_ffi.PinTarget) {
        val session = NodeHolder.session ?: return
        runNode(work = {
            val wasPinned = session.pinState(target) != null
            if (wasPinned) session.unpinConversation(target) else session.pinConversation(target)
            !wasPinned
        }) { pinned -> toast(if (pinned) getString(R.string.pins_title) else getString(R.string.menu_pin_toggle)) }
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return
        val list = findViewById<RecyclerView>(R.id.chat_messages)
        runNode(work = {
            session.noteToSelfMessages().map { message ->
                RenderedMessage(message, session.formatText(message.body))
            }
        }) { messages ->
            adapter.submit(messages)
            if (messages.isNotEmpty()) list.scrollToPosition(messages.size - 1)
        }
    }
}

/** Local-only note bubbles, intentionally without delivery-state captions. */
private class NoteMessagesAdapter : RecyclerView.Adapter<NoteMessagesAdapter.Holder>() {
    private var items = listOf<RenderedMessage<NoteMessage>>()

    class Holder(view: android.view.View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<RenderedMessage<NoteMessage>>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(R.layout.row_message, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val rendered = items[position]
        val message = rendered.value
        val context = holder.itemView.context
        (holder.itemView as LinearLayout).gravity = Gravity.END
        holder.itemView.findViewById<LinearLayout>(R.id.message_bubble)
            .setBackgroundColor(context.getColor(R.color.bubble_out))
        holder.itemView.findViewById<TextView>(R.id.message_body)
            .showFormattedText(rendered.formatted)
        val time = DateFormat.getTimeInstance(DateFormat.SHORT)
            .format(Date(message.timestamp.toLong() * 1000))
        holder.itemView.findViewById<TextView>(R.id.message_meta).text =
            "$time · ${context.getString(R.string.note_local_only)}"
    }
}
