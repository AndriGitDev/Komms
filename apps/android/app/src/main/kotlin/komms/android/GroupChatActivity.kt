package komms.android

import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.Spanned
import android.text.TextPaint
import android.text.TextWatcher
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
import uniffi.kult_ffi.FolderTarget
import uniffi.kult_ffi.FolderTargetKind
import uniffi.kult_ffi.Group
import uniffi.kult_ffi.GroupAuthority
import uniffi.kult_ffi.GroupMentionCapability
import uniffi.kult_ffi.GroupMessage
import uniffi.kult_ffi.GroupPoll
import uniffi.kult_ffi.GroupRole
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.LabelTargetKind
import uniffi.kult_ffi.MentionSpan
import uniffi.kult_ffi.ScheduledConversation
import uniffi.kult_ffi.ScheduledMessage
import uniffi.kult_ffi.TextFormatHighlight

/**
 * A sender-key group conversation. The node store is authoritative: events
 * are refresh nudges, membership controls call the thin Session surface, and
 * outbound rows render a separate real delivery state for every recipient.
 */
class GroupChatActivity : SecureActivity() {
    private lateinit var groupId: String
    private lateinit var groupName: String
    private var contacts = listOf<Contact>()
    private val adapter = GroupMessagesAdapter(
        memberName = { peer -> memberName(peer) },
        onEdit = ::editMessage,
        onHistory = { showEditHistory(it.versions) },
    )
    private lateinit var attachmentController: AttachmentController
    private lateinit var audioController: AudioMessageController
    private var currentGroup: Group? = null
    private var currentAuthority: GroupAuthority? = null
    private var mentionCapability: GroupMentionCapability? = null
    private val draftMentions = mutableListOf<DraftMention>()
    private var suppressMentionWatcher = false

    private val listener: (Event) -> Unit = { event ->
        val relevant = when (event) {
            is Event.GroupMessageReceived -> event.group == groupId
            is Event.GroupMessageEdited -> event.group == groupId
            is Event.GroupDeliveryUpdated -> true // ids are cheap to refresh
            is Event.GroupUpdated -> event.group == groupId
            is Event.PollUpdated -> event.group == groupId
            is Event.GroupAuthorityUpdated -> event.group == groupId
            is Event.GroupAdminRequestResolved -> event.group == groupId
            is Event.MentionReceived -> true
            is Event.SessionEstablished -> true
            is Event.ScheduledMessageUpdated -> true
            is Event.ScheduledMessageCancelled -> true
            is Event.ScheduledMessageActivated -> true
            is Event.AttachmentUpdated ->
                ::attachmentController.isInitialized &&
                    attachmentController.isRelevant(event.attachment)
            is Event.EphemeralRemoved ->
                event.conversationKind == "group" && event.conversationId == groupId
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
            send = { session, path, mediaType, filename, preview, viewOnce, lifetime ->
                if (viewOnce) {
                    session.sendGroupViewOnceAttachment(
                        groupId, path, mediaType, filename, preview, lifetime,
                    )
                } else if (preview == null) {
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
        configureEphemeralComposer {
            if (draftMentions.isNotEmpty()) {
                draftMentions.clear()
                renderMentionTokens()
                findViewById<TextView>(R.id.chat_mention_status).apply {
                    visibility = View.VISIBLE
                    text = "Semantic mentions were removed because disappearing text is a distinct authenticated content type."
                    announceForAccessibility(text)
                }
            }
        }
        findViewById<Button>(R.id.chat_mention).apply {
            visibility = View.VISIBLE
            setOnClickListener { showMentionPicker(input) }
        }
        findViewById<Button>(R.id.chat_poll).apply {
            visibility = View.VISIBLE
            setOnClickListener { showCreatePoll() }
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
            R.id.menu_folder -> {
                showFolderAssignment(FolderTarget(FolderTargetKind.GROUP, groupId), groupName)
                true
            }
            R.id.menu_pin -> {
                togglePin(uniffi.kult_ffi.PinTarget(uniffi.kult_ffi.PinTargetKind.GROUP, groupId))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun togglePin(target: uniffi.kult_ffi.PinTarget) {
        val session = NodeHolder.session ?: return
        runNode(work = {
            val wasPinned = session.pinState(target) != null
            if (wasPinned) session.unpinConversation(target) else session.pinConversation(target)
            !wasPinned
        }) { pinned -> toast(if (pinned) getString(R.string.pins_title) else getString(R.string.menu_pin_toggle)) }
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
                    messages = if (group == null) emptyList() else session.groupMessages(groupId)
                        .map { message ->
                            val highlights = if (message.contentKind == ContentKind.MENTION) {
                                message.mentionSpans.map { span ->
                                    TextFormatHighlight(span.start, span.end)
                                }
                            } else {
                                emptyList()
                            }
                            RenderedMessage(message, session.formatText(message.body, highlights))
                        },
                    scheduled = session.scheduledMessages().filter {
                        it.conversation == ScheduledConversation.GROUP && it.destination == groupId
                    }.map { message -> RenderedMessage(message, session.formatText(message.body)) },
                    attachments = session.attachments(),
                    polls = if (group == null) emptyList() else session.groupPolls(groupId),
                    authority = if (group == null) null else session.groupAuthority(groupId),
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
            currentAuthority = state.authority
            groupName = group.name
            supportActionBar?.title = group.name
            adapter.submit(state.messages)
            attachmentController.submit(state.attachments)
            renderPolls(state.polls)
            renderScheduledOutbox(
                state.scheduled,
                edit = { schedule(findViewById(R.id.chat_input), it) },
                cancel = { cancel(it) },
            )
            if (adapter.itemCount > 0) list.scrollToPosition(adapter.itemCount - 1)
            if (draftMentions.isNotEmpty()) revalidateMentionDraft()
        }
    }

    private fun renderPolls(polls: List<GroupPoll>) {
        val section = findViewById<View>(R.id.chat_poll_section)
        val container = findViewById<LinearLayout>(R.id.chat_polls)
        container.removeAllViews()
        section.visibility = if (polls.isEmpty()) View.GONE else View.VISIBLE
        polls.forEach { poll ->
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(16, 12, 16, 20)
                contentDescription = "Poll: ${poll.question}"
            }
            card.addView(TextView(this).apply {
                text = poll.question
                textSize = 18f
                setTypeface(typeface, Typeface.BOLD)
            })
            card.addView(TextView(this).apply {
                val moderatedBy = poll.moderatedBy
                text = if (poll.closed && moderatedBy != null) {
                    getString(R.string.poll_moderated_policy, memberLabel(moderatedBy))
                } else {
                    getString(if (poll.closed) R.string.poll_closed_policy else R.string.poll_open_policy)
                }
            })
            poll.options.forEach { option ->
                card.addView(Button(this).apply {
                    text = "${option.text} · ${option.votes}"
                    isEnabled = !poll.closed && poll.eligible
                    isSelected = option.selectedByMe
                    contentDescription = buildString {
                        append(option.text)
                        append(", ${option.votes} votes")
                        if (option.selectedByMe) append(", your choice")
                    }
                    setOnClickListener {
                        AlertDialog.Builder(this@GroupChatActivity)
                            .setTitle(R.string.poll_vote_confirm_title)
                            .setMessage(getString(R.string.poll_vote_confirm, option.text))
                            .setPositiveButton(R.string.poll_vote_action) { _, _ ->
                                val session = NodeHolder.session ?: return@setPositiveButton
                                runNode(work = {
                                    session.voteGroupPoll(groupId, poll.author, poll.id, option.id)
                                }) {
                                    toast(getString(R.string.poll_voted))
                                    refresh()
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .show()
                    }
                })
            }
            card.addView(TextView(this).apply {
                text = if (poll.votes.isEmpty()) {
                    getString(R.string.poll_no_votes)
                } else {
                    getString(
                        R.string.poll_visible_votes,
                        poll.votes.joinToString { vote ->
                            val choice = poll.options.firstOrNull { it.id == vote.optionId }?.text
                                ?: "unavailable choice"
                            "${memberLabel(vote.voter)} → $choice"
                        },
                    )
                }
            })
            if (poll.canClose) {
                card.addView(Button(this).apply {
                    text = getString(R.string.poll_close_action)
                    setOnClickListener {
                        AlertDialog.Builder(this@GroupChatActivity)
                            .setTitle(R.string.poll_close_confirm_title)
                            .setMessage(getString(R.string.poll_close_confirm, poll.question))
                            .setPositiveButton(R.string.poll_close_action) { _, _ ->
                                val session = NodeHolder.session ?: return@setPositiveButton
                                runNode(work = {
                                    session.closeGroupPoll(groupId, poll.author, poll.id)
                                }) {
                                    toast(getString(R.string.poll_closed))
                                    refresh()
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .show()
                    }
                })
            }
            if (!poll.closed && currentAuthority?.myRole in listOf(GroupRole.OWNER, GroupRole.ADMIN)) {
                card.addView(Button(this).apply {
                    text = getString(
                        if (currentAuthority?.myRole == GroupRole.OWNER) {
                            R.string.poll_moderate_action
                        } else {
                            R.string.poll_moderate_request_action
                        },
                    )
                    setOnClickListener {
                        AlertDialog.Builder(this@GroupChatActivity)
                            .setTitle(R.string.poll_moderate_confirm_title)
                            .setMessage(getString(R.string.poll_moderate_confirm, poll.question))
                            .setPositiveButton(text) { _, _ ->
                                val session = NodeHolder.session ?: return@setPositiveButton
                                runNode(work = {
                                    session.moderateGroupPollClose(groupId, poll.author, poll.id)
                                }) {
                                    toast(getString(R.string.poll_moderate_sent))
                                    refresh()
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .show()
                    }
                })
            }
            container.addView(card)
        }
    }

    private fun showCreatePoll() {
        val group = currentGroup ?: return
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 8, 32, 0)
        }
        content.addView(TextView(this).apply { text = getString(R.string.poll_visibility_policy) })
        val question = IncognitoEditText(this).apply {
            hint = getString(R.string.poll_question_hint)
            contentDescription = hint
        }
        content.addView(question)
        val choices = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(choices)
        val addChoice = Button(this).apply { text = getString(R.string.poll_add_choice) }

        fun refreshChoiceRows() {
            for (index in 0 until choices.childCount) {
                val row = choices.getChildAt(index) as LinearLayout
                val input = row.getChildAt(0) as EditText
                val remove = row.getChildAt(1) as Button
                input.hint = getString(R.string.poll_choice_hint, index + 1)
                input.contentDescription = input.hint
                remove.isEnabled = choices.childCount > 2
            }
            addChoice.isEnabled = choices.childCount < 12
        }

        fun addChoiceRow() {
            if (choices.childCount >= 12) return
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val input = IncognitoEditText(this)
            val remove = Button(this).apply {
                text = getString(android.R.string.cut)
                contentDescription = "Remove poll choice"
                setOnClickListener {
                    if (choices.childCount > 2) {
                        choices.removeView(row)
                        refreshChoiceRows()
                    }
                }
            }
            row.addView(input, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            row.addView(remove)
            choices.addView(row)
            refreshChoiceRows()
        }
        addChoiceRow()
        addChoiceRow()
        addChoice.setOnClickListener { addChoiceRow() }
        content.addView(addChoice)

        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.poll_create_title, group.name))
            .setView(content)
            .setPositiveButton(R.string.poll_create_visible, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val exactQuestion = question.text.toString()
                val exactChoices = (0 until choices.childCount).map { index ->
                    ((choices.getChildAt(index) as LinearLayout).getChildAt(0) as EditText).text.toString()
                }
                val problem = when {
                    exactQuestion.isBlank() -> getString(R.string.poll_need_question)
                    exactQuestion.toByteArray(Charsets.UTF_8).size > 1024 -> getString(R.string.poll_question_too_long)
                    exactChoices.size < 2 || exactChoices.any { it.isBlank() } -> getString(R.string.poll_need_choices)
                    exactChoices.any { it.toByteArray(Charsets.UTF_8).size > 256 } -> getString(R.string.poll_choice_too_long)
                    else -> null
                }
                if (problem != null) {
                    question.error = problem
                    question.announceForAccessibility(problem)
                    return@setOnClickListener
                }
                val session = NodeHolder.session ?: return@setOnClickListener
                runNode(work = {
                    session.createGroupPoll(groupId, exactQuestion, exactChoices)
                }) {
                    dialog.dismiss()
                    toast(getString(R.string.poll_created))
                    refresh()
                }
            }
        }
        dialog.show()
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
        val lifetime = selectedEphemeralLifetime()
        if (lifetime != null) {
            runNode(work = { session.sendGroupDisappearing(groupId, body, lifetime) }) {
                clearMentionDraft(input)
                refresh()
            }
            return
        }
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

    private fun editMessage(message: GroupMessage) {
        val session = NodeHolder.session ?: return
        if (message.direction != Direction.OUTBOUND || message.contentKind != ContentKind.TEXT) return
        showMessageEdit(message.body) { replacement ->
            runNode(
                work = {
                    session.editGroupMessage(groupId, session.peer, message.id, replacement)
                },
            ) { refresh() }
        }
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
                Triple(
                    session.groups().firstOrNull { it.id == groupId },
                    session.contacts(),
                    session.groupAuthority(groupId),
                )
            },
        ) { (group, availableContacts, authority) ->
            if (group == null) {
                toast(getString(R.string.group_no_longer_active))
                finish()
                return@runNode
            }
            contacts = availableContacts
            showMembersDialog(group, availableContacts, authority)
        }
    }

    private fun showMembersDialog(
        group: Group,
        availableContacts: List<Contact>,
        authority: GroupAuthority,
    ) {
        val session = NodeHolder.session ?: return
        val self = session.peer
        val isOwner = authority.myRole == GroupRole.OWNER
        val isAdmin = authority.myRole == GroupRole.ADMIN
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_group_members, null)
        val dialog = AlertDialog.Builder(this)
            .setTitle(getString(R.string.group_members_title, group.name))
            .setView(view)
            .setNegativeButton(android.R.string.ok, null)
            .create()
        view.findViewById<TextView>(R.id.group_member_summary).text = getString(
            R.string.group_authority_summary,
            group.members.size,
            memberName(authority.owner),
            authority.generation.toString(),
            if (authority.signed) getString(R.string.group_authority_signed) else getString(R.string.group_authority_legacy),
        )
        view.findViewById<EditText>(R.id.group_rename_input).apply {
            visibility = if (isOwner || isAdmin) View.VISIBLE else View.GONE
            setText(group.name)
        }
        view.findViewById<Button>(R.id.group_rename).apply {
            visibility = if (isOwner || isAdmin) View.VISIBLE else View.GONE
            text = getString(if (isOwner) R.string.group_rename_action else R.string.group_rename_request_action)
            setOnClickListener {
                val name = view.findViewById<EditText>(R.id.group_rename_input).text.toString().trim()
                if (name.isEmpty()) return@setOnClickListener
                runNode(work = { session.renameGroup(group.id, name) }) {
                    dialog.dismiss()
                    refresh()
                }
            }
        }
        val roster = view.findViewById<LinearLayout>(R.id.group_member_roster)
        for (member in authority.members) {
            val peer = member.peer
            val row = LayoutInflater.from(this).inflate(R.layout.row_group_member, roster, false)
            row.findViewById<TextView>(R.id.group_member_name).text = memberName(peer)
            row.findViewById<TextView>(R.id.group_member_role).text = member.role.name.lowercase()
            row.findViewById<Button>(R.id.group_member_role_action).apply {
                visibility = if (isOwner && member.role != GroupRole.OWNER) View.VISIBLE else View.GONE
                text = getString(if (member.role == GroupRole.ADMIN) R.string.group_make_member else R.string.group_make_admin)
                setOnClickListener {
                    val next = if (member.role == GroupRole.ADMIN) GroupRole.MEMBER else GroupRole.ADMIN
                    runNode(work = { session.setGroupRole(group.id, peer, next) }) {
                        dialog.dismiss()
                        refresh()
                    }
                }
            }
            row.findViewById<Button>(R.id.group_member_transfer_owner).apply {
                visibility = if (isOwner && member.role != GroupRole.OWNER) View.VISIBLE else View.GONE
                setOnClickListener {
                    runNode(work = { session.transferGroupOwner(group.id, peer) }) {
                        dialog.dismiss()
                        refresh()
                    }
                }
            }
            row.findViewById<Button>(R.id.group_member_remove).apply {
                visibility = if (
                    (isOwner && member.role != GroupRole.OWNER) ||
                    (isAdmin && member.role == GroupRole.MEMBER)
                ) View.VISIBLE else View.GONE
                setOnClickListener { confirmRemove(dialog, group, peer) }
            }
            roster.addView(row)
        }

        val candidates = availableContacts.filter { it.peer !in group.members }
        view.findViewById<Button>(R.id.group_add_member).apply {
            visibility = if ((isOwner || isAdmin) && candidates.isNotEmpty()) View.VISIBLE else View.GONE
            setOnClickListener { chooseMemberToAdd(dialog, group, candidates) }
        }
        view.findViewById<Button>(R.id.group_leave).setOnClickListener {
            if (isOwner) toast(getString(R.string.group_owner_must_transfer)) else confirmLeave(dialog, group)
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
    val messages: List<RenderedMessage<GroupMessage>>,
    val scheduled: List<RenderedMessage<ScheduledMessage>>,
    val attachments: List<Attachment>,
    val polls: List<GroupPoll>,
    val authority: GroupAuthority?,
)

private data class DraftMention(val start: Int, val end: Int, val target: String)

private class MentionComposerSpan : CharacterStyle() {
    override fun updateDrawState(paint: TextPaint) {
        paint.bgColor = 0x334CAF50
        paint.isUnderlineText = true
        paint.typeface = Typeface.create(paint.typeface, Typeface.BOLD)
    }
}

/** Group bubbles with sender names inbound and per-recipient state outbound. */
private class GroupMessagesAdapter(
    private val memberName: (String) -> String,
    private val onEdit: (GroupMessage) -> Unit,
    private val onHistory: (GroupMessage) -> Unit,
) : RecyclerView.Adapter<GroupMessagesAdapter.Holder>() {
    private var items = listOf<RenderedMessage<GroupMessage>>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<RenderedMessage<GroupMessage>>) {
        items = list.filter {
            it.value.contentKind != ContentKind.ATTACHMENT &&
                it.value.contentKind != ContentKind.VIEW_ONCE_ATTACHMENT
        }
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder = Holder(
        LayoutInflater.from(parent.context).inflate(R.layout.row_group_message, parent, false),
    )

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val rendered = items[position]
        val message = rendered.value
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
            val labels = message.mentionSpans.map { span -> "Mention of ${memberName(span.target)}" }
            showFormattedText(rendered.formatted, labels)
        }
        holder.itemView.findViewById<TextView>(R.id.group_message_time).text = buildString {
            append(
                DateFormat.getTimeInstance(DateFormat.SHORT)
                    .format(Date(message.timestamp.toLong() * 1000)),
            )
            if (message.edited) {
                append(" · ")
                append(context.getString(R.string.message_edited_revision, message.editRevision.toString()))
            }
            if (message.contentKind == ContentKind.DISAPPEARING_TEXT && message.expiresAt != null) {
                append(" · removes ")
                append(
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                        .format(Date(message.expiresAt!!.toLong() * 1000)),
                )
            }
        }
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
        holder.itemView.findViewById<Button>(R.id.group_message_edit).apply {
            visibility = if (outbound && message.contentKind == ContentKind.TEXT) {
                View.VISIBLE
            } else {
                View.GONE
            }
            setOnClickListener { onEdit(message) }
        }
        holder.itemView.findViewById<Button>(R.id.group_message_history).apply {
            visibility = if (message.edited && message.versions.isNotEmpty()) {
                View.VISIBLE
            } else {
                View.GONE
            }
            setOnClickListener { onHistory(message) }
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
