package komms.android

import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.SpannableString
import android.text.Spanned
import android.text.TextPaint
import android.text.TextWatcher
import android.text.method.LinkMovementMethod
import android.text.style.ClickableSpan
import android.text.style.CharacterStyle
import android.view.inputmethod.BaseInputConnection
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.HorizontalScrollView
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
import uniffi.kult_ffi.GroupMentionCapability
import uniffi.kult_ffi.GroupMessage
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.LabelTargetKind
import uniffi.kult_ffi.MentionSpan
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
    private var currentGroup: Group? = null
    private var mentionCapability: GroupMentionCapability? = null
    private val draftMentions = mutableListOf<DraftMention>()
    private var suppressMentionWatcher = false

    private val listener: (Event) -> Unit = { event ->
        val relevant = when (event) {
            is Event.GroupMessageReceived -> event.group == groupId
            is Event.GroupDeliveryUpdated -> true // ids are cheap to refresh
            is Event.GroupUpdated -> event.group == groupId
            is Event.MentionReceived -> true
            is Event.SessionEstablished -> true
            is Event.ScheduledMessageUpdated -> true
            is Event.ScheduledMessageCancelled -> true
            is Event.ScheduledMessageActivated -> true
            is Event.AttachmentUpdated ->
                ::attachmentController.isInitialized &&
                    attachmentController.isRelevant(event.attachment)
            else -> false
        }
        if (relevant) runOnUiThread {
            if (event is Event.MentionReceived) {
                findViewById<TextView>(R.id.chat_mention_status).apply {
                    visibility = View.VISIBLE
                    text = getString(R.string.mention_notification_private)
                    announceForAccessibility(text)
                }
            }
            refresh()
        }
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
        findViewById<Button>(R.id.chat_mention).apply {
            visibility = View.VISIBLE
            setOnClickListener { showMentionPicker(input) }
        }
        restoreMentionDraft(input, savedInstanceState)
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {
                if (!suppressMentionWatcher) updateMentionsForEdit(start, start + count, after)
            }

            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) = Unit

            override fun afterTextChanged(text: Editable?) {
                if (!suppressMentionWatcher) {
                    applyComposerMentionSpans(input)
                    persistMentionDraft(input)
                }
            }
        })
        findViewById<Button>(R.id.chat_schedule).setOnClickListener { schedule(input, null) }
        findViewById<Button>(R.id.chat_send).setOnClickListener {
            val body = input.text.toString()
            if (body.isEmpty()) return@setOnClickListener
            sendDraft(input, body)
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
        outState.putString(STATE_MENTION_TEXT, findViewById<EditText>(R.id.chat_input).text.toString())
        outState.putStringArrayList(
            STATE_MENTIONS,
            ArrayList(draftMentions.map { "${it.start},${it.end},${it.target}" }),
        )
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
            R.id.menu_labels -> {
                showLabelAssignments(LabelTarget(LabelTargetKind.GROUP, groupId), groupName)
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
            currentGroup = group
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
            if (draftMentions.isNotEmpty()) revalidateMentionDraft()
        }
    }

    private fun showMentionPicker(input: EditText) {
        val session = NodeHolder.session ?: return
        runNode(
            work = {
                val group = session.groups().firstOrNull { it.id == groupId }
                    ?: error(getString(R.string.group_no_longer_active))
                Triple(group, session.contacts(), session.groupMentionCapability(groupId))
            },
        ) { (group, availableContacts, capability) ->
            currentGroup = group
            contacts = availableContacts
            mentionCapability = capability
            showMentionCapability(capability, group)
            val labels = group.members.map { memberLabel(it, group) }.toTypedArray()
            AlertDialog.Builder(this)
                .setTitle(R.string.mention_picker_title)
                .setItems(labels) { _, index -> insertMention(input, group.members[index], capability) }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun memberLabel(peer: String, group: Group? = currentGroup): String {
        val base = memberName(peer)
        val members = group?.members ?: return base
        val duplicates = members.count { memberName(it) == base }
        return if (duplicates < 2) {
            base
        } else {
            "\u2068$base\u2069, group member ${members.indexOf(peer) + 1}"
        }
    }

    private fun showMentionCapability(capability: GroupMentionCapability, group: Group) {
        val status = findViewById<TextView>(R.id.chat_mention_status)
        status.visibility = View.VISIBLE
        status.text = if (capability.supported) {
            getString(R.string.mention_ready)
        } else {
            getString(
                R.string.mention_unavailable,
                capability.issues.joinToString { "${memberLabel(it.peer, group)} (${it.reason.name.lowercase()})" },
            )
        }
        status.announceForAccessibility(status.text)
    }

    private fun insertMention(
        input: EditText,
        peer: String,
        capability: GroupMentionCapability,
    ) {
        BaseInputConnection.removeComposingSpans(input.text)
        val start = input.selectionStart.coerceAtLeast(0)
        val end = input.selectionEnd.coerceAtLeast(start)
        val visible = "@${memberName(peer)}"
        updateMentionsForEdit(start, end, visible.length)
        suppressMentionWatcher = true
        input.text.replace(start, end, visible)
        suppressMentionWatcher = false
        draftMentions += DraftMention(start, start + visible.length, peer)
        draftMentions.sortBy { it.start }
        mentionCapability = capability
        input.setSelection(start + visible.length)
        applyComposerMentionSpans(input)
        persistMentionDraft(input)
        findViewById<TextView>(R.id.chat_mention_status).apply {
            visibility = View.VISIBLE
            text = getString(R.string.mention_inserted, memberLabel(peer))
            announceForAccessibility(text)
        }
    }

    private fun updateMentionsForEdit(start: Int, oldEnd: Int, replacementLength: Int) {
        if (draftMentions.isEmpty()) return
        val delta = replacementLength - (oldEnd - start)
        val removed = mutableListOf<DraftMention>()
        val updated = draftMentions.mapNotNull { mention ->
            if (start == oldEnd) {
                when {
                    start <= mention.start -> mention.copy(
                        start = mention.start + delta,
                        end = mention.end + delta,
                    )
                    start >= mention.end -> mention
                    else -> {
                        removed += mention
                        null
                    }
                }
            } else {
                when {
                    oldEnd <= mention.start -> mention.copy(
                        start = mention.start + delta,
                        end = mention.end + delta,
                    )
                    start >= mention.end -> mention
                    else -> {
                        removed += mention
                        null
                    }
                }
            }
        }
        draftMentions.clear()
        draftMentions += updated
        if (removed.isNotEmpty()) {
            findViewById<TextView>(R.id.chat_mention_status).apply {
                visibility = View.VISIBLE
                text = getString(R.string.mention_removed, memberLabel(removed.first().target))
                announceForAccessibility(text)
            }
        }
        renderMentionTokens()
    }

    private fun applyComposerMentionSpans(input: EditText) {
        input.text.getSpans(0, input.length(), MentionComposerSpan::class.java)
            .forEach(input.text::removeSpan)
        draftMentions.removeAll { it.start < 0 || it.end > input.length() || it.start >= it.end }
        draftMentions.forEach { mention ->
            input.text.setSpan(
                MentionComposerSpan(),
                mention.start,
                mention.end,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
            )
        }
        renderMentionTokens()
    }

    private fun renderMentionTokens() {
        val scroll = findViewById<HorizontalScrollView>(R.id.chat_mention_tokens_scroll)
        val tokens = findViewById<LinearLayout>(R.id.chat_mention_tokens)
        tokens.removeAllViews()
        scroll.visibility = if (draftMentions.isEmpty()) View.GONE else View.VISIBLE
        draftMentions.toList().forEach { mention ->
            val button = Button(this).apply {
                text = "${memberLabel(mention.target)} ×"
                contentDescription = getString(R.string.mention_remove_action, memberLabel(mention.target))
                isAllCaps = false
                setOnClickListener { removeMentionWithText(mention) }
            }
            tokens.addView(button)
        }
    }

    private fun removeMentionWithText(mention: DraftMention) {
        val input = findViewById<EditText>(R.id.chat_input)
        if (mention !in draftMentions || mention.end > input.length()) return
        draftMentions.remove(mention)
        updateMentionsForEdit(mention.start, mention.end, 0)
        suppressMentionWatcher = true
        input.text.delete(mention.start, mention.end)
        suppressMentionWatcher = false
        applyComposerMentionSpans(input)
        persistMentionDraft(input)
        input.requestFocus()
    }

    private fun revalidateMentionDraft() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.groupMentionCapability(groupId) }) { fresh ->
            if (mentionCapability?.reviewToken != fresh.reviewToken) {
                mentionCapability = fresh
                findViewById<TextView>(R.id.chat_mention_status).apply {
                    visibility = View.VISIBLE
                    text = getString(R.string.mention_review_again)
                    announceForAccessibility(text)
                }
            }
        }
    }

    private fun sendDraft(input: EditText, body: String) {
        val session = NodeHolder.session ?: return
        if (draftMentions.isEmpty()) {
            runNode(work = { session.sendGroup(groupId, body) }) {
                clearMentionDraft(input)
                refresh()
            }
            return
        }
        if (!wellFormedUnicode(body)) {
            toast("The draft contains invalid Unicode and cannot be sent.")
            return
        }
        runNode(work = { session.groupMentionCapability(groupId) }) { fresh ->
            val reviewed = mentionCapability
            if (reviewed == null || reviewed.reviewToken != fresh.reviewToken) {
                mentionCapability = fresh
                findViewById<TextView>(R.id.chat_mention_status).apply {
                    visibility = View.VISIBLE
                    text = getString(R.string.mention_review_again)
                    announceForAccessibility(text)
                }
                return@runNode
            }
            if (!fresh.supported) {
                AlertDialog.Builder(this)
                    .setTitle(R.string.mention_plain_title)
                    .setMessage(R.string.mention_plain_message)
                    .setPositiveButton(R.string.mention_plain_send) { _, _ ->
                        runNode(work = { session.sendGroup(groupId, body) }) {
                            clearMentionDraft(input)
                            refresh()
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
                return@runNode
            }
            val spans = mutableListOf<MentionSpan>()
            for (mention in draftMentions) {
                val start = utf8OffsetForUtf16(body, mention.start)
                val end = utf8OffsetForUtf16(body, mention.end)
                if (start == null || end == null) {
                    findViewById<TextView>(R.id.chat_mention_status).apply {
                        visibility = View.VISIBLE
                        text = getString(R.string.mention_invalid_range)
                        announceForAccessibility(text)
                    }
                    return@runNode
                }
                spans += MentionSpan(start = start, end = end, target = mention.target)
            }
            runNode(
                work = { session.sendGroupMention(groupId, body, spans, fresh.reviewToken) },
            ) {
                clearMentionDraft(input)
                refresh()
            }
        }
    }

    private fun clearMentionDraft(input: EditText) {
        suppressMentionWatcher = true
        input.text.clear()
        suppressMentionWatcher = false
        draftMentions.clear()
        mentionCapability = null
        renderMentionTokens()
        getSharedPreferences(PREFS_MENTION_DRAFTS, MODE_PRIVATE).edit()
            .remove("$groupId.text")
            .remove("$groupId.spans")
            .apply()
    }

    private fun persistMentionDraft(input: EditText) {
        getSharedPreferences(PREFS_MENTION_DRAFTS, MODE_PRIVATE).edit()
            .putString("$groupId.text", input.text.toString())
            .putString("$groupId.spans", draftMentions.joinToString(";") {
                "${it.start},${it.end},${it.target}"
            })
            .apply()
    }

    private fun restoreMentionDraft(input: EditText, state: Bundle?) {
        val preferences = getSharedPreferences(PREFS_MENTION_DRAFTS, MODE_PRIVATE)
        val text = state?.getString(STATE_MENTION_TEXT)
            ?: preferences.getString("$groupId.text", "").orEmpty()
        val encoded = state?.getStringArrayList(STATE_MENTIONS)?.joinToString(";")
            ?: preferences.getString("$groupId.spans", "").orEmpty()
        suppressMentionWatcher = true
        input.setText(text)
        suppressMentionWatcher = false
        draftMentions.clear()
        draftMentions += encoded.split(';').mapNotNull { item ->
            val fields = item.split(',', limit = 3)
            val start = fields.getOrNull(0)?.toIntOrNull() ?: return@mapNotNull null
            val end = fields.getOrNull(1)?.toIntOrNull() ?: return@mapNotNull null
            val target = fields.getOrNull(2) ?: return@mapNotNull null
            DraftMention(start, end, target).takeIf {
                start >= 0 && end > start && end <= text.length && target.length == 64
            }
        }
        input.setSelection(input.length())
        applyComposerMentionSpans(input)
    }

    private fun wellFormedUnicode(text: String): Boolean {
        var index = 0
        while (index < text.length) {
            val unit = text[index]
            if (Character.isHighSurrogate(unit)) {
                if (index + 1 >= text.length || !Character.isLowSurrogate(text[index + 1])) return false
                index += 2
            } else if (Character.isLowSurrogate(unit)) {
                return false
            } else {
                index += 1
            }
        }
        return true
    }

    private fun utf8OffsetForUtf16(text: String, offset: Int): UInt? {
        if (offset !in 0..text.length) return null
        if (offset > 0 && offset < text.length &&
            Character.isHighSurrogate(text[offset - 1]) && Character.isLowSurrogate(text[offset])
        ) {
            return null
        }
        val bytes = text.substring(0, offset).toByteArray(Charsets.UTF_8).size
        return bytes.toUInt()
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
        val contact = contacts.firstOrNull { it.peer == peer }
        return when {
            peer == self -> getString(R.string.group_you)
            contact != null -> contact.name
            currentGroup?.members?.contains(peer) == true ->
                "Group member ${(currentGroup?.members?.indexOf(peer) ?: 0) + 1}"
            else -> "Unavailable group member"
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

private data class DraftMention(val start: Int, val end: Int, val target: String)

private class MentionComposerSpan : CharacterStyle() {
    override fun updateDrawState(paint: TextPaint) {
        paint.bgColor = 0x334CAF50
        paint.isUnderlineText = true
        paint.typeface = Typeface.create(paint.typeface, Typeface.BOLD)
    }
}

private class HistoryMentionSpan(private val label: String) : ClickableSpan() {
    override fun onClick(widget: View) {
        widget.announceForAccessibility(label)
    }

    override fun updateDrawState(paint: TextPaint) {
        super.updateDrawState(paint)
        paint.bgColor = 0x334CAF50
        paint.isUnderlineText = true
        paint.typeface = Typeface.create(paint.typeface, Typeface.BOLD)
    }
}

private fun utf16OffsetForUtf8(text: String, requested: UInt): Int? {
    val target = requested.toInt()
    var bytes = 0
    var index = 0
    while (index < text.length) {
        if (bytes == target) return index
        val codePoint = Character.codePointAt(text, index)
        val character = String(Character.toChars(codePoint))
        bytes += character.toByteArray(Charsets.UTF_8).size
        index += Character.charCount(codePoint)
        if (bytes > target) return null
    }
    return index.takeIf { bytes == target }
}

private fun renderMentionText(
    message: GroupMessage,
    memberName: (String) -> String,
): CharSequence {
    if (message.contentKind != ContentKind.MENTION || message.mentionSpans.isEmpty()) {
        return message.body
    }
    val styled = SpannableString(message.body)
    var priorEnd = 0
    for (span in message.mentionSpans) {
        val start = utf16OffsetForUtf8(message.body, span.start) ?: return "Unsupported message — update Komms"
        val end = utf16OffsetForUtf8(message.body, span.end) ?: return "Unsupported message — update Komms"
        if (start < priorEnd || end <= start) return "Unsupported message — update Komms"
        styled.setSpan(
            HistoryMentionSpan("Mention of ${memberName(span.target)}"),
            start,
            end,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
        )
        priorEnd = end
    }
    return styled
}

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
        holder.itemView.findViewById<TextView>(R.id.group_message_body).apply {
            text = renderMentionText(message, memberName)
            movementMethod = if (message.contentKind == ContentKind.MENTION) {
                LinkMovementMethod.getInstance()
            } else {
                null
            }
        }
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

private const val PREFS_MENTION_DRAFTS = "protected-mention-drafts"
private const val STATE_MENTION_TEXT = "mention-text"
private const val STATE_MENTIONS = "mention-spans"
