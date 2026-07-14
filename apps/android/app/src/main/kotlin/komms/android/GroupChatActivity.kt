package komms.android

import android.app.AlertDialog
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.text.DateFormat
import java.util.Date
import uniffi.kult_ffi.Attachment
import uniffi.kult_ffi.AttachmentConversation
import uniffi.kult_ffi.ContentKind
import uniffi.kult_ffi.Contact
import uniffi.kult_ffi.DeliveryState
import uniffi.kult_ffi.Direction
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.Group
import uniffi.kult_ffi.GroupMessage
import uniffi.kult_ffi.ScheduledConversation
import uniffi.kult_ffi.ScheduledMessage

/**
 * A sender-key group conversation. The node store is authoritative: events
 * are refresh nudges, membership controls call the thin Session surface, and
 * outbound rows render a separate real delivery state for every recipient.
 */
class GroupChatActivity : AppCompatActivity() {
    private lateinit var groupId: String
    private lateinit var groupName: String
    private var contacts = listOf<Contact>()
    private val adapter = GroupMessagesAdapter { peer -> memberName(peer) }
    private lateinit var attachmentController: AttachmentController
    private lateinit var audioController: AudioMessageController

    private val listener: (Event) -> Unit = { event ->
        val relevant = when (event) {
            is Event.GroupMessageReceived -> event.group == groupId
            is Event.GroupDeliveryUpdated -> true // ids are cheap to refresh
            is Event.GroupUpdated -> event.group == groupId
            is Event.ScheduledMessageUpdated -> true
            is Event.ScheduledMessageCancelled -> true
            is Event.ScheduledMessageActivated -> true
            is Event.AttachmentUpdated ->
                ::attachmentController.isInitialized &&
                    attachmentController.isRelevant(event.attachment)
            else -> false
        }
        if (relevant) runOnUiThread { refresh() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        groupId = intent.getStringExtra("group") ?: return finish()
        groupName = intent.getStringExtra("name") ?: getString(R.string.group_default_name)
        setContentView(R.layout.activity_chat)
        setSupportActionBar(findViewById(R.id.chat_toolbar))
        supportActionBar?.title = groupName
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val list = findViewById<RecyclerView>(R.id.chat_messages)
        list.layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        list.adapter = adapter
        val attachmentList = findViewById<RecyclerView>(R.id.chat_attachments)
        attachmentList.layoutManager = LinearLayoutManager(this)
        audioController = AudioMessageController(
            activity = this,
            send = { session, file ->
                session.sendGroupAttachment(groupId, file, "audio/wav", "audio-message.wav")
            },
            carrierExplanation = { session -> session.groupAudioCarrierExplanation(groupId) },
            refresh = ::refresh,
        )
        attachmentController = AttachmentController(
            activity = this,
            belongsHere = {
                it.conversation == AttachmentConversation.GROUP && it.group == groupId
            },
            send = { session, path, mediaType, filename, preview ->
                if (preview == null) {
                    session.sendGroupAttachment(groupId, path, mediaType, filename)
                } else {
                    session.sendGroupAttachmentWithPreview(
                        groupId, path, mediaType, filename, preview,
                    )
                }
            },
            carrierExplanation = { session ->
                session.groupAttachmentCarrierExplanation(groupId)
            },
            bindAudio = audioController::bindAttachment,
            refresh = ::refresh,
            savedState = savedInstanceState,
        )

        val input = findViewById<EditText>(R.id.chat_input)
        findViewById<Button>(R.id.chat_schedule).setOnClickListener { schedule(input, null) }
        findViewById<Button>(R.id.chat_send).setOnClickListener {
            val body = input.text.toString()
            if (body.isEmpty()) return@setOnClickListener
            val session = NodeHolder.session ?: return@setOnClickListener
            runNode(work = { session.sendGroup(groupId, body) }) {
                input.text.clear()
                refresh()
            }
        }
        NodeHolder.addListener(listener)
    }

    override fun onDestroy() {
        NodeHolder.removeListener(listener)
        if (::attachmentController.isInitialized) attachmentController.close()
        if (::audioController.isInitialized) audioController.close()
        super.onDestroy()
    }

    override fun onStop() {
        if (::attachmentController.isInitialized) attachmentController.onStop()
        if (::audioController.isInitialized) audioController.onStop()
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        if (::attachmentController.isInitialized) attachmentController.saveState(outState)
        super.onSaveInstanceState(outState)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.group_chat, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_group_members -> {
                showMembers()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return
        val list = findViewById<RecyclerView>(R.id.chat_messages)
        runNode(
            work = {
                val group = session.groups().firstOrNull { it.id == groupId }
                GroupScreenState(
                    group = group,
                    contacts = session.contacts(),
                    messages = if (group == null) emptyList() else session.groupMessages(groupId),
                    scheduled = session.scheduledMessages().filter {
                        it.conversation == ScheduledConversation.GROUP && it.destination == groupId
                    },
                    attachments = session.attachments(),
                )
            },
        ) { state ->
            val group = state.group
            if (group == null) {
                toast(getString(R.string.group_no_longer_active))
                finish()
                return@runNode
            }
            contacts = state.contacts
            groupName = group.name
            supportActionBar?.title = group.name
            adapter.submit(state.messages)
            attachmentController.submit(state.attachments)
            renderScheduledOutbox(
                state.scheduled,
                edit = { schedule(findViewById(R.id.chat_input), it) },
                cancel = { cancel(it) },
            )
            if (adapter.itemCount > 0) list.scrollToPosition(adapter.itemCount - 1)
        }
    }

    private fun schedule(input: EditText, message: ScheduledMessage?) {
        val session = NodeHolder.session ?: return
        showScheduledEditor(
            initialBody = input.text.toString(),
            message = message,
            work = { body, notBefore ->
                if (message == null) session.scheduleGroup(groupId, body, notBefore)
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

    private fun memberName(peer: String): String {
        val self = NodeHolder.session?.peer
        return when {
            peer == self -> getString(R.string.group_you)
            else -> contacts.firstOrNull { it.peer == peer }?.name ?: peer.take(12) + "…"
        }
    }

    private fun showMembers() {
        val session = NodeHolder.session ?: return
        runNode(
            work = {
                session.groups().firstOrNull { it.id == groupId } to session.contacts()
            },
        ) { (group, availableContacts) ->
            if (group == null) {
                toast(getString(R.string.group_no_longer_active))
                finish()
                return@runNode
            }
            contacts = availableContacts
            showMembersDialog(group, availableContacts)
        }
    }

    private fun showMembersDialog(group: Group, availableContacts: List<Contact>) {
        val session = NodeHolder.session ?: return
        val self = session.peer
        val isCreator = group.creator == self
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_group_members, null)
        view.findViewById<TextView>(R.id.group_member_summary).text = if (isCreator) {
            resources.getQuantityString(
                R.plurals.group_summary_creator,
                group.members.size,
                group.members.size,
            )
        } else {
            resources.getQuantityString(
                R.plurals.group_summary_member,
                group.members.size,
                group.members.size,
                memberName(group.creator),
            )
        }
        val roster = view.findViewById<LinearLayout>(R.id.group_member_roster)
        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.group_members_title, group.name))
            .setView(view)
            .setNegativeButton(android.R.string.ok, null)
            .create()

        for (peer in group.members) {
            val row = LayoutInflater.from(this).inflate(R.layout.row_group_member, roster, false)
            row.findViewById<TextView>(R.id.group_member_name).text = memberName(peer)
            row.findViewById<TextView>(R.id.group_member_role).text = getString(
                if (peer == group.creator) R.string.group_role_creator else R.string.group_role_member,
            )
            row.findViewById<Button>(R.id.group_member_remove).apply {
                visibility = if (isCreator && peer != self) View.VISIBLE else View.GONE
                setOnClickListener { confirmRemove(dialog, group, peer) }
            }
            roster.addView(row)
        }

        val candidates = availableContacts.filter { it.peer !in group.members }
        view.findViewById<Button>(R.id.group_add_member).apply {
            visibility = if (isCreator && candidates.isNotEmpty()) View.VISIBLE else View.GONE
            setOnClickListener { chooseMemberToAdd(dialog, group, candidates) }
        }
        view.findViewById<Button>(R.id.group_leave).setOnClickListener {
            confirmLeave(dialog, group)
        }
        dialog.show()
    }

    private fun chooseMemberToAdd(dialog: AlertDialog, group: Group, candidates: List<Contact>) {
        AlertDialog.Builder(this)
            .setTitle(R.string.group_add_member_title)
            .setItems(candidates.map { it.name }.toTypedArray()) { _, index ->
                val session = NodeHolder.session ?: return@setItems
                runNode(work = { session.addGroupMember(group.id, candidates[index].peer) }) {
                    dialog.dismiss()
                    refresh()
                    toast(getString(R.string.group_member_added, candidates[index].name))
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmRemove(dialog: AlertDialog, group: Group, peer: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.group_remove_title)
            .setMessage(getString(R.string.group_remove_warning, memberName(peer)))
            .setPositiveButton(R.string.group_remove_action) { _, _ ->
                val session = NodeHolder.session ?: return@setPositiveButton
                runNode(work = { session.removeGroupMember(group.id, peer) }) {
                    dialog.dismiss()
                    refresh()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmLeave(dialog: AlertDialog, group: Group) {
        AlertDialog.Builder(this)
            .setTitle(R.string.group_leave_title)
            .setMessage(getString(R.string.group_leave_warning, group.name))
            .setPositiveButton(R.string.group_leave_action) { _, _ ->
                val session = NodeHolder.session ?: return@setPositiveButton
                runNode(work = { session.leaveGroup(group.id) }) {
                    dialog.dismiss()
                    finish()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}

private data class GroupScreenState(
    val group: Group?,
    val contacts: List<Contact>,
    val messages: List<GroupMessage>,
    val scheduled: List<ScheduledMessage>,
    val attachments: List<Attachment>,
)

/** Group bubbles with sender names inbound and per-recipient state outbound. */
private class GroupMessagesAdapter(
    private val memberName: (String) -> String,
) : RecyclerView.Adapter<GroupMessagesAdapter.Holder>() {
    private var items = listOf<GroupMessage>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<GroupMessage>) {
        items = list.filter { it.contentKind != ContentKind.ATTACHMENT }
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder = Holder(
        LayoutInflater.from(parent.context).inflate(R.layout.row_group_message, parent, false),
    )

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val message = items[position]
        val outbound = message.direction == Direction.OUTBOUND
        val row = holder.itemView as LinearLayout
        val context = holder.itemView.context
        row.gravity = if (outbound) Gravity.END else Gravity.START
        holder.itemView.findViewById<LinearLayout>(R.id.group_message_bubble).setBackgroundColor(
            context.getColor(if (outbound) R.color.bubble_out else R.color.bubble_in),
        )
        holder.itemView.findViewById<TextView>(R.id.group_message_sender).apply {
            visibility = if (outbound) View.GONE else View.VISIBLE
            text = memberName(message.sender)
        }
        holder.itemView.findViewById<TextView>(R.id.group_message_body).text = message.body
        holder.itemView.findViewById<TextView>(R.id.group_message_time).text =
            DateFormat.getTimeInstance(DateFormat.SHORT)
                .format(Date(message.timestamp.toLong() * 1000))
        holder.itemView.findViewById<TextView>(R.id.group_message_deliveries).apply {
            visibility = if (outbound) View.VISIBLE else View.GONE
            text = message.deliveries.joinToString("\n") { delivery ->
                context.getString(
                    R.string.group_delivery_row,
                    memberName(delivery.peer),
                    deliveryState(context = context, state = delivery.state),
                )
            }
        }
    }

    private fun deliveryState(context: android.content.Context, state: DeliveryState): String =
        when (state) {
            DeliveryState.QUEUED -> context.getString(R.string.state_queued)
            DeliveryState.SENT -> context.getString(R.string.state_sent)
            DeliveryState.DELIVERED -> context.getString(R.string.state_delivered)
            DeliveryState.RECEIVED -> context.getString(R.string.state_received)
        }
}
