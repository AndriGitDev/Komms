package komms.android

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.text.DateFormat
import java.util.Date
import uniffi.kult_ffi.DeliveryState
import uniffi.kult_ffi.Direction
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.Message
import uniffi.kult_ffi.ScheduledConversation
import uniffi.kult_ffi.ScheduledMessage

/**
 * One conversation. Bubbles render the node's honest delivery ladder
 * verbatim: queued → sent → delivered, `received` for inbound, and the
 * "held — will send when a faster link exists" verdict while the only
 * route is an airtime-budgeted mesh link.
 */
class ChatActivity : AppCompatActivity() {
    private lateinit var peer: String
    private lateinit var contactName: String
    private val adapter = MessagesAdapter()

    private val listener: (Event) -> Unit = { event ->
        val relevant = when (event) {
            is Event.DeliveryUpdated -> true // ids are ours or cheap to refresh
            is Event.MessageReceived -> event.peer == peer
            is Event.AwaitingFasterLink -> true
            is Event.ScheduledMessageUpdated -> true
            is Event.ScheduledMessageCancelled -> true
            is Event.ScheduledMessageActivated -> true
            else -> false
        }
        if (relevant) runOnUiThread { refresh() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        peer = intent.getStringExtra("peer") ?: return finish()
        contactName = intent.getStringExtra("name") ?: peer.take(12)
        setContentView(R.layout.activity_chat)
        setSupportActionBar(findViewById(R.id.chat_toolbar))
        supportActionBar?.title = contactName
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val list = findViewById<RecyclerView>(R.id.chat_messages)
        list.layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        list.adapter = adapter

        val input = findViewById<EditText>(R.id.chat_input)
        findViewById<android.widget.Button>(R.id.chat_schedule).setOnClickListener {
            schedule(input, null)
        }
        findViewById<android.widget.Button>(R.id.chat_send).setOnClickListener {
            val body = input.text.toString()
            if (body.isEmpty()) return@setOnClickListener
            val session = NodeHolder.session ?: return@setOnClickListener
            runNode(work = { session.send(peer, body) }) {
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

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.chat, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menu_verify -> startActivity(
                Intent(this, VerifyActivity::class.java)
                    .putExtra("peer", peer)
                    .putExtra("name", contactName),
            )
            R.id.menu_hints -> editHints()
            else -> return super.onOptionsItemSelected(item)
        }
        return true
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return
        val list = findViewById<RecyclerView>(R.id.chat_messages)
        runNode(work = {
            ChatScreenState(
                messages = session.messages(peer),
                scheduled = session.scheduledMessages().filter {
                    it.conversation == ScheduledConversation.PEER && it.destination == peer
                },
            )
        }) { state ->
            adapter.submit(state.messages)
            renderScheduledOutbox(
                state.scheduled,
                edit = { schedule(findViewById(R.id.chat_input), it) },
                cancel = { cancel(it) },
            )
            if (state.messages.isNotEmpty()) list.scrollToPosition(state.messages.size - 1)
        }
    }

    private fun schedule(input: EditText, message: ScheduledMessage?) {
        val session = NodeHolder.session ?: return
        showScheduledEditor(
            initialBody = input.text.toString(),
            message = message,
            work = { body, notBefore ->
                if (message == null) session.schedule(peer, body, notBefore)
                else session.editScheduled(message.id, body, notBefore)
            },
        ) {
            if (message == null) input.text.clear()
            refresh()
        }
    }

    private fun cancel(message: ScheduledMessage) {
        val session = NodeHolder.session ?: return
        runNode(work = { session.cancelScheduled(message.id) }) { refresh() }
    }

    /** Replace this contact's delivery hints (one per line, `kind value`). */
    private fun editHints() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_hints, null)
        val field = view.findViewById<EditText>(R.id.hints_text)
        AlertDialog.Builder(this)
            .setTitle(R.string.hints_title)
            .setView(view)
            .setPositiveButton(R.string.hints_save) { _, _ ->
                val session = NodeHolder.session ?: return@setPositiveButton
                runNode(
                    work = { session.setHints(peer, parseHints(field.text.toString())) },
                ) { toast(getString(R.string.hints_saved)) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}

private data class ChatScreenState(
    val messages: List<Message>,
    val scheduled: List<ScheduledMessage>,
)

/** Message bubbles with the honest state caption. */
private class MessagesAdapter : RecyclerView.Adapter<MessagesAdapter.Holder>() {
    private var items = listOf<Message>()

    class Holder(view: android.view.View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<Message>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(
            LayoutInflater.from(parent.context)
                .inflate(R.layout.row_message, parent, false),
        )

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val message = items[position]
        val outbound = message.direction == Direction.OUTBOUND
        val row = holder.itemView as LinearLayout
        row.gravity = if (outbound) Gravity.END else Gravity.START
        val context = holder.itemView.context
        holder.itemView.findViewById<LinearLayout>(R.id.message_bubble).setBackgroundColor(
            context.getColor(if (outbound) R.color.bubble_out else R.color.bubble_in),
        )
        holder.itemView.findViewById<TextView>(R.id.message_body).text = message.body

        val state = when {
            message.id in NodeHolder.held -> context.getString(R.string.state_held)
            message.state == DeliveryState.QUEUED -> context.getString(R.string.state_queued)
            message.state == DeliveryState.SENT -> context.getString(R.string.state_sent)
            message.state == DeliveryState.DELIVERED -> context.getString(R.string.state_delivered)
            else -> "" // received: inbound rows carry no delivery caption
        }
        val time = DateFormat.getTimeInstance(DateFormat.SHORT)
            .format(Date(message.timestamp.toLong() * 1000))
        holder.itemView.findViewById<TextView>(R.id.message_meta).text =
            if (state.isEmpty()) time else "$time · $state"
    }
}
