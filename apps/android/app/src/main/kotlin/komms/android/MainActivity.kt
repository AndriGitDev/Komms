package komms.android

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputFilter
import android.text.InputType
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import androidx.activity.result.contract.ActivityResultContracts
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import komms.core.NetworkSettings
import komms.core.bundleQrFrames
import uniffi.kult_ffi.Contact
import uniffi.kult_ffi.ContactNameAssessment
import uniffi.kult_ffi.ContactNameWarning
import uniffi.kult_ffi.ConnectionVerdict
import uniffi.kult_ffi.CustomIcon
import uniffi.kult_ffi.CustomIconTarget
import uniffi.kult_ffi.CustomIconTargetKind
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.Folder
import uniffi.kult_ffi.FolderSelection
import uniffi.kult_ffi.FolderSelectionKind
import uniffi.kult_ffi.FolderTarget
import uniffi.kult_ffi.FolderTargetKind
import uniffi.kult_ffi.Group
import uniffi.kult_ffi.Label
import uniffi.kult_ffi.LabelMatchMode
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.LabelTargetKind
import uniffi.kult_ffi.NatVerdict
import uniffi.kult_ffi.NetworkMode
import uniffi.kult_ffi.PinConversation
import uniffi.kult_ffi.PinTargetKind
import uniffi.kult_ffi.ProviderDirectoryVerdict

/**
 * Contacts + the transport-indicator header. All state shown is the
 * node's own: the status snapshot and the stored contact list, verbatim.
 */
class MainActivity : SecureActivity() {
    private val contacts = ContactsAdapter(
        onClick = { contact ->
            startActivity(
                Intent(this, ChatActivity::class.java)
                    .putExtra("peer", contact.peer)
                    .putExtra("name", contact.name),
            )
        },
        onRename = ::showRenameContact,
    )
    private val groups = GroupsAdapter { group ->
        openGroup(group.id, group.name)
    }
    private val pins = PinsAdapter { conversation -> openPinned(conversation) }
    private lateinit var labelPreferences: LabelFilterPreferences
    private var selectedLabels = listOf<String>()
    private var labelMode = "any"
    private var folderKind = "all"
    private var folderId: String? = null
    private var renderingLabelControls = false
    private var renderingFolderControls = false
    private var networkSettings = NetworkSettings()

    private val tick = Handler(Looper.getMainLooper())
    private val refreshLoop = object : Runnable {
        override fun run() {
            refreshStatus()
            tick.postDelayed(this, 3000)
        }
    }

    private val listener: (Event) -> Unit = { event ->
        runOnUiThread {
            when (event) {
                is Event.ContactAdded, is Event.ContactRenamed -> refreshLabelsAndLists(false)
                is Event.SessionEstablished -> onSessionEstablished(event.peer)
                is Event.MessageReceived -> refreshLabelsAndLists(false)
                is Event.MessageRequestReceived -> {
                    toast(getString(R.string.message_request_received))
                    invalidateOptionsMenu()
                }
                is Event.MessageRequestAccepted,
                is Event.MessageRequestDeleted,
                is Event.MessageRequestBlocked,
                is Event.MessageRequestExpired -> {
                    refreshLabelsAndLists(false)
                    invalidateOptionsMenu()
                }
                is Event.GroupUpdated -> refreshLabelsAndLists(false)
                is Event.GroupInvitationReceived -> {
                    toast(getString(R.string.group_invitation_received))
                    invalidateOptionsMenu()
                }
                is Event.GroupInvitationAccepted,
                is Event.GroupInvitationDeleted,
                is Event.GroupInvitationExpired -> {
                    refreshLabelsAndLists(false)
                    invalidateOptionsMenu()
                }
                is Event.GroupMessageReceived -> refreshLabelsAndLists(false)
                is Event.FoldersChanged -> refreshLabelsAndLists(true)
                is Event.LabelsChanged -> refreshLabelsAndLists(true)
                is Event.PinsChanged -> refreshLabelsAndLists(true)
                is Event.ThemeChanged -> Unit // ThemeController applies process-wide DayNight.
                is Event.CustomIconsChanged -> refreshLabelsAndLists(false)
                is Event.RendezvousConflict -> toast(getString(R.string.rendezvous_conflict))
                is Event.WakeConflict -> toast(getString(R.string.wake_conflict))
                else -> {}
            }
        }
    }

    /** Peers we already listed — a re-established session for one of these
     *  means their key or device changed, and the user must hear it. */
    private var knownPeers = setOf<String>()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return backToGate()
        setContentView(R.layout.activity_main)
        applyEdgeToEdgeInsets()
        setSupportActionBar(findViewById(R.id.main_toolbar))
        networkSettings = runCatching {
            NetworkSettings.load(KommsApp.dataDir(application))
        }.getOrDefault(NetworkSettings())
        labelPreferences = LabelFilterPreferences(this)
        labelPreferences.load().also {
            selectedLabels = it.ids
            labelMode = it.mode
            folderKind = it.folderKind
            folderId = it.folderId
        }

        findViewById<View>(R.id.main_filter_toggle).setOnClickListener {
            val panel = findViewById<View>(R.id.main_filters_panel)
            val showing = panel.visibility != View.VISIBLE
            panel.visibility = if (showing) View.VISIBLE else View.GONE
            (it as Button).setText(
                if (showing) R.string.main_filters_hide else R.string.main_filters_show,
            )
        }

        findViewById<View>(R.id.main_manage_folders).setOnClickListener {
            startActivity(Intent(this, FolderManagerActivity::class.java))
        }

        findViewById<View>(R.id.main_manage_labels).setOnClickListener {
            startActivity(Intent(this, LabelManagerActivity::class.java))
        }
        findViewById<RadioGroup>(R.id.main_label_filter_mode).setOnCheckedChangeListener { _, checked ->
            if (renderingLabelControls) return@setOnCheckedChangeListener
            labelMode = if (checked == R.id.main_label_filter_all) "all" else "any"
            persistLabelFilter()
            refreshLabelsAndLists(true)
        }
        findViewById<View>(R.id.main_label_filter_clear).setOnClickListener {
            selectedLabels = emptyList()
            persistLabelFilter()
            refreshLabelsAndLists(true)
        }

        findViewById<View>(R.id.main_note_to_self).setOnClickListener {
            val conversation = NodeHolder.session?.noteToSelfId() ?: return@setOnClickListener
            startActivity(
                Intent(this, NoteToSelfActivity::class.java)
                    .putExtra("conversation", conversation),
            )
        }
        findViewById<View>(R.id.main_empty_pair).setOnClickListener {
            startActivity(Intent(this, AddContactActivity::class.java))
        }

        val list = findViewById<RecyclerView>(R.id.main_contacts)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = contacts

        val groupList = findViewById<RecyclerView>(R.id.main_groups)
        groupList.layoutManager = LinearLayoutManager(this)
        groupList.adapter = groups
        val pinList = findViewById<RecyclerView>(R.id.main_pins)
        pinList.layoutManager = LinearLayoutManager(this)
        pinList.adapter = pins

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        NodeHolder.addListener(listener)
    }

    override fun onDestroy() {
        NodeHolder.removeListener(listener)
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        refreshAuthorityResetHistory()
        refreshLabelsAndLists(false)
        tick.post(refreshLoop)
    }

    override fun onPause() {
        tick.removeCallbacks(refreshLoop)
        super.onPause()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menu_add -> startActivity(Intent(this, AddContactActivity::class.java))
            R.id.menu_create_group -> showCreateGroup()
            R.id.menu_message_requests -> showMessageRequests()
            R.id.menu_pins -> showPinManager()
            R.id.menu_my_qr -> showMyQr()
            R.id.menu_settings -> startActivity(Intent(this, SettingsActivity::class.java))
            R.id.menu_lock -> lock()
            else -> return super.onOptionsItemSelected(item)
        }
        return true
    }

    private fun requestExpiry(expiresAt: ULong): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            .format(Date(expiresAt.toLong() * 1000L))

    private fun showMessageRequests() {
        val session = NodeHolder.session ?: return
        runNode(
            work = { session.messageRequests() to session.groupInvitations() },
        ) { (requests, invitations) ->
            val root = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                val spacing = (resources.displayMetrics.density * 12).toInt()
                setPadding(spacing, spacing, spacing, spacing)
            }
            root.addView(TextView(this).apply {
                setText(R.string.message_requests_intro)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
            })
            lateinit var dialog: AlertDialog
            if (requests.isEmpty() && invitations.isEmpty()) {
                root.addView(TextView(this).apply { setText(R.string.message_requests_empty) })
            }
            for (request in requests) {
                val card = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    val spacing = (resources.displayMetrics.density * 8).toInt()
                    setPadding(0, spacing, 0, spacing)
                }
                card.addView(TextView(this).apply {
                    setText(R.string.message_request_from_new)
                    textSize = 18f
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setAccessibilityHeading(true)
                    }
                })
                card.addView(TextView(this).apply {
                    text = getString(
                        R.string.message_request_expires,
                        requestExpiry(request.expiresAt),
                    )
                })
                card.addView(TextView(this).apply {
                    text = request.preview.ifBlank { getString(R.string.message_requests_empty) }
                    textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                    setPadding(0, 8, 0, 8)
                })
                card.addView(TextView(this).apply {
                    text = getString(R.string.message_request_safety, request.safetyNumber)
                })
                val name = IncognitoEditText(this).apply {
                    id = View.generateViewId()
                    hint = getString(R.string.message_request_name_hint)
                    setText(R.string.message_request_default_name)
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
                    filters = arrayOf(InputFilter.LengthFilter(256))
                }
                card.addView(TextView(this).apply {
                    text = getString(R.string.message_request_name_hint)
                    labelFor = name.id
                })
                card.addView(name)
                val actions = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                }
                actions.addView(Button(this).apply {
                    setText(R.string.message_request_accept)
                    setOnClickListener {
                        val localName = name.text.toString().trim()
                        if (localName.isEmpty()) {
                            name.error = getString(R.string.message_request_name_hint)
                            return@setOnClickListener
                        }
                        runNode(work = {
                            session.acceptMessageRequest(request.id, localName)
                        }) { peer ->
                            dialog.dismiss()
                            refreshLabelsAndLists(false)
                            startActivity(
                                Intent(this@MainActivity, ChatActivity::class.java)
                                    .putExtra("peer", peer)
                                    .putExtra("name", localName),
                            )
                        }
                    }
                })
                actions.addView(Button(this).apply {
                    setText(R.string.message_request_delete)
                    setOnClickListener {
                        runNode(work = { session.deleteMessageRequest(request.id) }) {
                            dialog.dismiss()
                            showMessageRequests()
                        }
                    }
                })
                actions.addView(Button(this).apply {
                    setText(R.string.message_request_block)
                    setOnClickListener {
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle(R.string.message_request_block_title)
                            .setMessage(R.string.message_request_block_explanation)
                            .setPositiveButton(R.string.message_request_block) { _, _ ->
                                runNode(work = { session.blockMessageRequest(request.id) }) {
                                    dialog.dismiss()
                                    showMessageRequests()
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .show()
                    }
                })
                card.addView(actions)
                root.addView(card)
            }
            for (invitation in invitations) {
                val card = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    val spacing = (resources.displayMetrics.density * 8).toInt()
                    setPadding(0, spacing, 0, spacing)
                }
                card.addView(TextView(this).apply {
                    setText(R.string.group_invitation_title)
                    textSize = 18f
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setAccessibilityHeading(true)
                    }
                })
                card.addView(TextView(this).apply {
                    text = invitation.name
                    textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                })
                card.addView(TextView(this).apply {
                    text = getString(
                        R.string.group_invitation_members,
                        invitation.memberCount.toLong(),
                        requestExpiry(invitation.expiresAt),
                    )
                })
                card.addView(TextView(this).apply {
                    setText(R.string.group_invitation_explanation)
                })
                val actions = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                }
                actions.addView(Button(this).apply {
                    setText(R.string.group_invitation_accept)
                    setOnClickListener {
                        runNode(work = {
                            session.acceptGroupInvitation(invitation.id)
                        }) { group ->
                            dialog.dismiss()
                            refreshLabelsAndLists(false)
                            openGroup(group, invitation.name)
                        }
                    }
                })
                actions.addView(Button(this).apply {
                    setText(R.string.message_request_delete)
                    setOnClickListener {
                        runNode(work = {
                            session.deleteGroupInvitation(invitation.id)
                        }) {
                            dialog.dismiss()
                            showMessageRequests()
                        }
                    }
                })
                card.addView(actions)
                root.addView(card)
            }
            dialog = AlertDialog.Builder(this)
                .setTitle(R.string.message_requests_title)
                .setView(ScrollView(this).apply { addView(root) })
                .setNegativeButton(android.R.string.cancel, null)
                .create()
            dialog.show()
        }
    }

    private fun refreshStatus() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.status() }, onError = {}) { s ->
            val nat = when (s.nat) {
                NatVerdict.PUBLIC -> getString(R.string.nat_public)
                NatVerdict.PRIVATE -> getString(R.string.nat_private)
                NatVerdict.UNKNOWN -> getString(R.string.nat_unknown)
            }
            val mode = when (s.mode) {
                NetworkMode.STANDARD -> getString(R.string.mode_standard)
                NetworkMode.PRIVATE -> getString(R.string.mode_private)
                NetworkMode.SOVEREIGN -> getString(R.string.mode_sovereign)
            }
            val connection = when (s.connection) {
                ConnectionVerdict.CONNECTED -> getString(R.string.connection_connected)
                ConnectionVerdict.FALLBACK_READY ->
                    getString(R.string.connection_fallback_ready)
                ConnectionVerdict.WAITING_FOR_ROUTE -> getString(R.string.connection_waiting)
            }
            val directory = when (s.providerDirectory) {
                ProviderDirectoryVerdict.NOT_CONFIGURED ->
                    getString(R.string.directory_not_configured)
                ProviderDirectoryVerdict.CURRENT -> getString(R.string.directory_current)
                ProviderDirectoryVerdict.RETAINED_LAST_VALID ->
                    getString(R.string.directory_retained)
                ProviderDirectoryVerdict.STALE -> getString(R.string.directory_stale)
                ProviderDirectoryVerdict.CONFLICT -> getString(R.string.directory_conflict)
                ProviderDirectoryVerdict.UNAVAILABLE ->
                    getString(R.string.directory_unavailable)
            }
            findViewById<TextView>(R.id.main_status).apply {
                val queued = if (s.queued == 0uL) {
                    ""
                } else {
                    getString(R.string.status_queued_suffix, s.queued.toLong())
                }
                text = getString(
                    R.string.status_summary, mode, connection, queued,
                )
                contentDescription = text
                setOnClickListener {
                    val mdns = getString(
                        if (networkSettings.mdns) {
                            R.string.discovery_mdns_enabled
                        } else {
                            R.string.discovery_mdns_disabled
                        },
                    )
                    val dht = if (networkSettings.bootstrap.isEmpty()) {
                        getString(R.string.discovery_dht_local_only)
                    } else {
                        getString(
                            R.string.discovery_dht_configured,
                            networkSettings.bootstrap.size,
                        )
                    }
                    val legacy = if (s.legacyDiscovery) {
                        getString(R.string.discovery_legacy_enabled)
                    } else {
                        getString(R.string.discovery_legacy_retired)
                    }
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle(R.string.node_details_title)
                        .setMessage(
                            getString(
                                R.string.status_details,
                                s.connectCode, s.address, nat, s.lanPeers.size,
                                s.scheduled.toLong(), s.queued.toLong(), s.transit.toLong(),
                                mdns, dht, legacy,
                                mode, connection, directory, s.connectedPeers.toLong(),
                            ),
                        )
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                }
            }
        }
    }

    private fun refreshAuthorityResetHistory() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.authorityResetHistory() }, onError = {}) { history ->
            findViewById<TextView>(R.id.main_authority_reset_history).apply {
                if (history == null) {
                    visibility = View.GONE
                    text = ""
                } else {
                    text = getString(
                        R.string.authority_reset_archive_summary,
                        getString(R.string.authority_reset_archive_title),
                        history.preservedPairwiseMessages.toLong(),
                        history.preservedNoteMessages.toLong(),
                        history.omittedGroups.toLong(),
                        history.omittedGroupMessages.toLong(),
                        history.pendingReverification.size,
                    )
                    contentDescription = text
                    visibility = View.VISIBLE
                }
            }
        }
    }

    private fun showPinManager() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.pins() }) { durable ->
            val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            durable.forEachIndexed { index, pin ->
                val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                row.addView(TextView(this).apply {
                    text = pin.displayName ?: if (pin.target.kind == PinTargetKind.NOTE_TO_SELF) getString(R.string.note_to_self_title) else getString(R.string.pin_unavailable)
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
                fun action(textId: Int, enabled: Boolean = true, block: () -> Unit) =
                    Button(this).apply { text = getString(textId); isEnabled = enabled; setOnClickListener { block() } }
                row.addView(action(R.string.pins_earlier, index > 0) {
                    val order = durable.map { it.target }.toMutableList().apply {
                        val previous = this[index - 1]; this[index - 1] = this[index]; this[index] = previous
                    }
                    runNode(work = { session.reorderPins(order) }) { refreshLabelsAndLists(true) }
                })
                row.addView(action(R.string.pins_later, index + 1 < durable.size) {
                    val order = durable.map { it.target }.toMutableList().apply {
                        val next = this[index + 1]; this[index + 1] = this[index]; this[index] = next
                    }
                    runNode(work = { session.reorderPins(order) }) { refreshLabelsAndLists(true) }
                })
                row.addView(action(if (pin.active) R.string.pins_unpin else R.string.pins_cleanup) {
                    runNode(work = {
                        if (pin.active) session.unpinConversation(pin.target) else session.cleanupStalePin(pin.target)
                    }) { refreshLabelsAndLists(true) }
                })
                root.addView(row)
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.pins_manage)
                .setView(ScrollView(this).apply { addView(root) })
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
    }

    private fun refreshContacts() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.contacts() }) { list ->
            knownPeers = list.map { it.peer }.toSet()
            contacts.submit(list)
            if (list.isNotEmpty()) {
                findViewById<View>(R.id.main_empty).visibility = View.GONE
                findViewById<View>(R.id.main_contacts_heading).visibility = View.VISIBLE
                findViewById<View>(R.id.main_contacts).visibility = View.VISIBLE
            }
        }
    }

    private fun showRenameContact(contact: Contact) {
        val name = IncognitoEditText(this).apply {
            setText(contact.name)
            hint = getString(R.string.contact_private_petname)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
            filters = arrayOf(InputFilter.LengthFilter(256))
            setSelectAllOnFocus(true)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.contact_rename_title)
            .setMessage(R.string.contact_rename_private_note)
            .setView(name)
            .setPositiveButton(R.string.contact_rename_review, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val proposed = name.text.toString()
                val session = NodeHolder.session ?: return@setOnClickListener
                runNode(
                    work = { session.assessContactName(contact.peer, proposed) },
                    onError = { error -> name.error = error },
                ) { assessment ->
                    if (assessment.warnings.isEmpty()) {
                        commitContactRename(dialog, contact, proposed, false)
                    } else {
                        AlertDialog.Builder(this)
                            .setTitle(R.string.contact_rename_warning_title)
                            .setMessage(contactNameWarningText(assessment))
                            .setPositiveButton(R.string.contact_rename_anyway) { _, _ ->
                                commitContactRename(dialog, contact, proposed, true)
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .show()
                    }
                }
            }
        }
        dialog.show()
    }

    private fun commitContactRename(
        editor: AlertDialog,
        contact: Contact,
        proposed: String,
        acceptWarnings: Boolean,
    ) {
        val session = NodeHolder.session ?: return
        runNode(work = { session.renameContact(contact.peer, proposed, acceptWarnings) }) { saved ->
            editor.dismiss()
            toast(getString(R.string.contact_rename_done, saved.normalizedName))
            refreshLabelsAndLists(true)
        }
    }

    private fun contactNameWarningText(assessment: ContactNameAssessment): String {
        val warnings = assessment.warnings.map { warning ->
            when (warning) {
                ContactNameWarning.DUPLICATE_NAME -> resources.getQuantityString(
                    R.plurals.contact_warning_duplicate,
                    assessment.duplicateCount.toInt(),
                    assessment.duplicateCount.toInt(),
                )
                ContactNameWarning.CONFUSABLE_NAME -> getString(R.string.contact_warning_confusable)
                ContactNameWarning.BIDIRECTIONAL_CONTROL -> getString(R.string.contact_warning_bidi)
                ContactNameWarning.INVISIBLE_CHARACTER -> getString(R.string.contact_warning_invisible)
            }
        }
        return warnings.joinToString("\n\n") + "\n\n" +
            getString(R.string.contact_warning_identity, assessment.normalizedName)
    }

    private fun persistLabelFilter() {
        labelPreferences.save(LabelFilterPreferences.State(selectedLabels, labelMode, folderKind, folderId))
    }

    private fun refreshLabelsAndLists(announce: Boolean) {
        val session = NodeHolder.session ?: return
        val requested = selectedLabels
        val requestedMode = labelMode
        runNode(work = {
            val labels = session.labels()
            val folders = session.folders()
            val folderUnavailable = folderKind == "folder" && folders.none { it.id == folderId }
            val requestedFolder = if (folderUnavailable) {
                FolderSelection(FolderSelectionKind.ALL, null)
            } else when (folderKind) {
                "unfiled" -> FolderSelection(FolderSelectionKind.UNFILED, null)
                "folder" -> FolderSelection(FolderSelectionKind.FOLDER, folderId)
                else -> FolderSelection(FolderSelectionKind.ALL, null)
            }
            val result = session.pinConversations(
                requestedFolder,
                requested,
                if (requestedMode == "all") LabelMatchMode.ALL else LabelMatchMode.ANY,
            )
            val contacts = session.contacts()
            val groups = session.groups()
            MainLabelSnapshot(
                labels = labels,
                folders = folders,
                folderSelection = result.selection,
                folderUnavailable = folderUnavailable,
                selected = result.selectedLabels,
                unavailableCount = result.unavailableLabels.size,
                matching = result.conversations.map { targetKey(it.target) }.toSet(),
                ordered = result.conversations,
                contacts = contacts,
                groups = groups,
                contactLabels = contacts.associate { contact ->
                    contact.peer to session.labelsForConversation(
                        LabelTarget(LabelTargetKind.PEER, contact.peer),
                    )
                },
                groupLabels = groups.associate { group ->
                    group.id to session.labelsForConversation(
                        LabelTarget(LabelTargetKind.GROUP, group.id),
                    )
                },
                noteLabels = session.labelsForConversation(
                    LabelTarget(LabelTargetKind.NOTE_TO_SELF, null),
                ),
                contactIcons = contacts.associate { contact ->
                    contact.peer to session.customIcon(
                        CustomIconTarget(CustomIconTargetKind.CONTACT, contact.peer),
                    )
                },
                groupIcons = groups.associate { group ->
                    group.id to session.customIcon(
                        CustomIconTarget(CustomIconTargetKind.GROUP, group.id),
                    )
                },
                folderIcons = folders.associate { folder ->
                    folder.id to session.customIcon(
                        CustomIconTarget(CustomIconTargetKind.FOLDER, folder.id),
                    )
                },
                noteIcon = session.customIcon(
                    CustomIconTarget(CustomIconTargetKind.NOTE_TO_SELF, null),
                ),
            )
        }) { snapshot ->
            selectedLabels = snapshot.selected
            folderKind = when (snapshot.folderSelection.kind) {
                FolderSelectionKind.UNFILED -> "unfiled"
                FolderSelectionKind.FOLDER -> "folder"
                FolderSelectionKind.ALL -> "all"
            }
            folderId = snapshot.folderSelection.id
            persistLabelFilter()
            renderFolderControls(snapshot.folders, snapshot.folderIcons)
            findViewById<TextView>(R.id.main_folder_filter_status).apply {
                text = if (snapshot.folderUnavailable) getString(R.string.folder_selection_unavailable) else ""
                if (snapshot.folderUnavailable) announceForAccessibility(text)
            }
            renderLabelControls(snapshot.labels)
            val pinnedKeys = snapshot.ordered.filter { it.pinned }.map { targetKey(it.target) }.toSet()
            val contactById = snapshot.contacts.associateBy { it.peer }
            val groupById = snapshot.groups.associateBy { it.id }
            val visibleContacts = snapshot.ordered.filter { !it.pinned && it.target.kind == PinTargetKind.PEER }
                .mapNotNull { it.target.id?.let(contactById::get) }
            val visibleGroups = snapshot.ordered.filter { !it.pinned && it.target.kind == PinTargetKind.GROUP }
                .mapNotNull { it.target.id?.let(groupById::get) }
            val iconMap = buildMap {
                snapshot.contactIcons.forEach { (id, icon) -> put("peer:$id", icon) }
                snapshot.groupIcons.forEach { (id, icon) -> put("group:$id", icon) }
                put("note_to_self:", snapshot.noteIcon)
            }
            pins.submit(snapshot.ordered.filter { it.pinned }, iconMap)
            knownPeers = snapshot.contacts.map { it.peer }.toSet()
            contacts.submit(
                visibleContacts,
                snapshot.contactLabels.mapValues { (_, labels) -> labelLines(labels) },
                snapshot.contactIcons,
            )
            groups.submit(
                visibleGroups,
                snapshot.groupLabels.mapValues { (_, labels) -> labelLines(labels) },
                snapshot.groupIcons,
            )
            val emptyInbox = visibleContacts.isEmpty() && visibleGroups.isEmpty()
            findViewById<View>(R.id.main_empty).visibility =
                if (emptyInbox) View.VISIBLE else View.GONE
            findViewById<View>(R.id.main_contacts_heading).visibility =
                if (emptyInbox) View.GONE else View.VISIBLE
            findViewById<View>(R.id.main_groups_heading).visibility =
                if (emptyInbox) View.GONE else View.VISIBLE
            findViewById<View>(R.id.main_contacts).visibility =
                if (visibleContacts.isEmpty()) View.GONE else View.VISIBLE
            findViewById<View>(R.id.main_groups).visibility =
                if (visibleGroups.isEmpty()) View.GONE else View.VISIBLE
            findViewById<TextView>(R.id.main_groups_empty).visibility =
                if (!emptyInbox && visibleGroups.isEmpty()) View.VISIBLE else View.GONE
            findViewById<Button>(R.id.main_note_to_self).apply {
                visibility = if ("note_to_self:" in snapshot.matching && "note_to_self:" !in pinnedKeys) View.VISIBLE else View.GONE
                text = buildString {
                    append(getString(R.string.note_to_self_title))
                    val lines = labelLines(snapshot.noteLabels)
                    if (lines.isNotEmpty()) append("\n").append(lines)
                }
                setCompoundDrawablesRelativeWithIntrinsicBounds(
                    customIconDrawable(this@MainActivity, snapshot.noteIcon, getString(R.string.note_to_self_title)),
                    null,
                    null,
                    null,
                )
                compoundDrawablePadding = (12 * resources.displayMetrics.density).toInt()
            }
            val status = findViewById<TextView>(R.id.main_label_filter_status)
            status.text = when {
                snapshot.unavailableCount > 0 -> getString(R.string.label_filter_unavailable, snapshot.unavailableCount)
                announce && selectedLabels.isNotEmpty() -> getString(R.string.label_filter_result, snapshot.matching.size, requestedMode)
                else -> ""
            }
            if (announce && status.text.isNotEmpty()) status.announceForAccessibility(status.text)
        }
    }

    private fun renderFolderControls(folders: List<Folder>, icons: Map<String, CustomIcon?>) {
        renderingFolderControls = true
        val root = findViewById<RadioGroup>(R.id.main_folder_filters)
        root.setOnCheckedChangeListener(null)
        root.removeAllViews()
        val choices = listOf(
            Triple("all", null, getString(R.string.folder_all)),
            Triple("unfiled", null, getString(R.string.folder_unfiled)),
        ) + folders.map { Triple("folder", it.id, folderSummary(it)) }
        choices.forEach { (kind, id, summary) ->
            root.addView(RadioButton(this).apply {
                this.id = View.generateViewId()
                text = summary
                textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                contentDescription = getString(R.string.folder_filter_description, summary)
                isChecked = kind == folderKind && (kind != "folder" || id == folderId)
                tag = Pair(kind, id)
                isFocusable = true
                nextFocusForwardId = View.NO_ID
                if (kind == "folder" && id != null) {
                    setCompoundDrawablesRelativeWithIntrinsicBounds(
                        customIconDrawable(this@MainActivity, icons[id], summary, 32),
                        null,
                        null,
                        null,
                    )
                    compoundDrawablePadding = (8 * resources.displayMetrics.density).toInt()
                }
            })
        }
        root.setOnCheckedChangeListener { group, checkedId ->
            if (renderingFolderControls) return@setOnCheckedChangeListener
            val selected = group.findViewById<RadioButton>(checkedId)?.tag as? Pair<*, *> ?: return@setOnCheckedChangeListener
            folderKind = selected.first as String
            folderId = selected.second as String?
            persistLabelFilter()
            refreshLabelsAndLists(true)
        }
        renderingFolderControls = false
    }

    private fun renderLabelControls(labels: List<Label>) {
        renderingLabelControls = true
        findViewById<RadioGroup>(R.id.main_label_filter_mode).check(
            if (labelMode == "all") R.id.main_label_filter_all else R.id.main_label_filter_any,
        )
        val root = findViewById<LinearLayout>(R.id.main_label_filters)
        root.removeAllViews()
        labels.forEach { label ->
            root.addView(CheckBox(this).apply {
                text = labelSummary(label)
                isChecked = label.id in selectedLabels
                textDirection = View.TEXT_DIRECTION_FIRST_STRONG
                contentDescription = getString(R.string.label_filter_heading) + ": " + labelSummary(label)
                setOnCheckedChangeListener { _, checked ->
                    selectedLabels = if (checked) (selectedLabels + label.id).distinct()
                    else selectedLabels.filterNot { it == label.id }
                    persistLabelFilter()
                    refreshLabelsAndLists(true)
                }
            })
        }
        findViewById<View>(R.id.main_label_filter_clear).visibility =
            if (selectedLabels.isEmpty()) View.GONE else View.VISIBLE
        renderingLabelControls = false
    }

    private fun labelLines(labels: List<Label>): String = labels.joinToString(" · ") { labelSummary(it) }

    private fun targetKey(target: LabelTarget): String = when (target.kind) {
        LabelTargetKind.PEER -> "peer:${target.id}"
        LabelTargetKind.GROUP -> "group:${target.id}"
        LabelTargetKind.NOTE_TO_SELF -> "note_to_self:"
    }

    private fun targetKey(target: FolderTarget): String = when (target.kind) {
        FolderTargetKind.PEER -> "peer:${target.id}"
        FolderTargetKind.GROUP -> "group:${target.id}"
        FolderTargetKind.NOTE_TO_SELF -> "note_to_self:"
    }

    private fun targetKey(target: uniffi.kult_ffi.PinTarget): String = when (target.kind) {
        PinTargetKind.PEER -> "peer:${target.id}"
        PinTargetKind.GROUP -> "group:${target.id}"
        PinTargetKind.NOTE_TO_SELF -> "note_to_self:"
    }

    private fun openPinned(conversation: PinConversation) {
        when (conversation.target.kind) {
            PinTargetKind.PEER -> {
                val id = conversation.target.id ?: return
                startActivity(Intent(this, ChatActivity::class.java).putExtra("peer", id).putExtra("name", conversation.displayName ?: id))
            }
            PinTargetKind.GROUP -> {
                val id = conversation.target.id ?: return
                openGroup(id, conversation.displayName ?: id)
            }
            PinTargetKind.NOTE_TO_SELF -> {
                val id = NodeHolder.session?.noteToSelfId() ?: return
                startActivity(Intent(this, NoteToSelfActivity::class.java).putExtra("conversation", id))
            }
        }
    }

    private fun refreshGroups() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.groups() }) { list ->
            groups.submit(list)
            if (list.isNotEmpty()) {
                findViewById<View>(R.id.main_empty).visibility = View.GONE
                findViewById<View>(R.id.main_groups_heading).visibility = View.VISIBLE
                findViewById<View>(R.id.main_groups).visibility = View.VISIBLE
            }
            findViewById<TextView>(R.id.main_groups_empty).visibility =
                if (list.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    /** Create a group from stored contacts; the node remains the source of
     * truth and the resulting id is opened only after creation succeeds. */
    private fun showCreateGroup() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.contacts() }) { list ->
            showCreateGroupDialog(list)
        }
    }

    private fun showCreateGroupDialog(availableContacts: List<Contact>) {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_create_group, null)
        val picker = view.findViewById<LinearLayout>(R.id.create_group_members)
        view.findViewById<TextView>(R.id.create_group_empty).visibility =
            if (availableContacts.isEmpty()) View.VISIBLE else View.GONE
        for (contact in availableContacts.sortedBy { it.name.lowercase() }) {
            picker.addView(CheckBox(this).apply {
                text = contact.name
                tag = contact.peer
            })
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.group_create_title)
            .setView(view)
            .setPositiveButton(R.string.group_create_action, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val name = view.findViewById<android.widget.EditText>(R.id.create_group_name)
                    .text.toString().trim()
                val members = (0 until picker.childCount)
                    .map { picker.getChildAt(it) }
                    .filterIsInstance<CheckBox>()
                    .filter { it.isChecked }
                    .map { it.tag as String }
                when {
                    name.isEmpty() -> toast(getString(R.string.group_need_name))
                    members.isEmpty() -> toast(getString(R.string.group_need_member))
                    else -> {
                        val session = NodeHolder.session ?: return@setOnClickListener
                        runNode(work = { session.createGroup(name, members) }) { id ->
                            dialog.dismiss()
                            refreshGroups()
                            openGroup(id, name)
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun openGroup(group: String, name: String) {
        startActivity(
            Intent(this, GroupChatActivity::class.java)
                .putExtra("group", group)
                .putExtra("name", name),
        )
    }

    private fun onSessionEstablished(peer: String) {
        if (peer !in knownPeers) {
            refreshLabelsAndLists(false)
            return
        }
        val name = contacts.nameOf(peer) ?: peer.take(12)
        AlertDialog.Builder(this)
            .setTitle(R.string.key_changed_title)
            .setMessage(getString(R.string.key_changed_body, name))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /** A ready signed prekey bundle in the compact, versioned pairing QR format. */
    private fun showMyQr() {
        val session = NodeHolder.session ?: return
        runNode(work = {
            Triple(session.myBundleHex(), session.connectCode, session.status().legacyDiscovery)
        }) { (hex, connectCode, legacyDiscovery) ->
            val view = LayoutInflater.from(this).inflate(R.layout.dialog_qr, null)
            val image = view.findViewById<ImageView>(R.id.qr_image)
            val caption = view.findViewById<TextView>(R.id.qr_caption)
            val modeButton = view.findViewById<Button>(R.id.qr_mode_button)
            val frames = bundleQrFrames(hex)
            var frame = 0
            var currentConnectCode = connectCode
            var showingPairing = false
            fun render() {
                if (showingPairing) {
                    image.setImageBitmap(pairingQrBitmap(frames[frame]))
                    image.contentDescription = getString(R.string.my_pairing_qr_description)
                    caption.text = if (frames.size == 1) {
                        getString(R.string.my_pairing_qr_caption)
                    } else {
                        getString(R.string.my_qr_frame, frame + 1, frames.size)
                    }
                    modeButton.setText(R.string.show_connect_qr)
                } else {
                    image.setImageBitmap(pairingQrBitmap(currentConnectCode))
                    image.contentDescription = getString(R.string.my_connect_qr_description)
                    caption.text = getString(R.string.my_qr_caption, currentConnectCode)
                    modeButton.setText(R.string.show_pairing_qr)
                }
            }
            render()
            val builder = AlertDialog.Builder(this)
                .setTitle(R.string.my_qr_title)
                .setView(view)
                .setNeutralButton(R.string.rotate_connect_code, null)
                .setPositiveButton(android.R.string.ok, null)
            if (legacyDiscovery) {
                builder.setNegativeButton(R.string.retire_legacy_discovery, null)
            }
            val dialog = builder.create()
            val handler = Handler(Looper.getMainLooper())
            val rotate = object : Runnable {
                override fun run() {
                    if (!dialog.isShowing || !showingPairing || frames.size < 2) return
                    frame = (frame + 1) % frames.size
                    render()
                    handler.postDelayed(this, 1_100)
                }
            }
            dialog.setOnShowListener {
                modeButton.setOnClickListener {
                    handler.removeCallbacks(rotate)
                    showingPairing = !showingPairing
                    frame = 0
                    render()
                    if (showingPairing && frames.size > 1) {
                        handler.postDelayed(rotate, 1_100)
                    }
                }
                dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                    AlertDialog.Builder(this)
                        .setTitle(R.string.rotate_connect_code)
                        .setMessage(R.string.rotate_connect_code_warning)
                        .setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.rotate_connect_code) { _, _ ->
                            runNode(work = { session.rotateConnectCode() }) { code ->
                                currentConnectCode = code
                                dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.visibility =
                                    View.GONE
                                render()
                                toast(getString(R.string.rotate_connect_code_done))
                            }
                        }
                        .show()
                }
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.setOnClickListener {
                    AlertDialog.Builder(this)
                        .setTitle(R.string.retire_legacy_discovery)
                        .setMessage(R.string.retire_legacy_discovery_warning)
                        .setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.retire_legacy_discovery) { _, _ ->
                            runNode(work = { session.retireLegacyDiscovery() }) {
                                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isEnabled = false
                                toast(getString(R.string.retire_legacy_discovery_done))
                            }
                        }
                        .show()
                }
            }
            dialog.setOnDismissListener { handler.removeCallbacks(rotate) }
            dialog.show()
        }
    }

    private fun lock() {
        stopService(Intent(this, NodeService::class.java))
        NodeHolder.stopAndClear()
        backToGate()
    }

    private fun backToGate() {
        startActivity(
            Intent(this, GateActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }
}

private data class MainLabelSnapshot(
    val labels: List<Label>,
    val folders: List<Folder>,
    val folderSelection: FolderSelection,
    val folderUnavailable: Boolean,
    val selected: List<String>,
    val unavailableCount: Int,
    val matching: Set<String>,
    val ordered: List<PinConversation>,
    val contacts: List<Contact>,
    val groups: List<Group>,
    val contactLabels: Map<String, List<Label>>,
    val groupLabels: Map<String, List<Label>>,
    val noteLabels: List<Label>,
    val contactIcons: Map<String, CustomIcon?>,
    val groupIcons: Map<String, CustomIcon?>,
    val folderIcons: Map<String, CustomIcon?>,
    val noteIcon: CustomIcon?,
)

/** Leading cross-type pinned block in persisted manual order. */
private class PinsAdapter(
    private val onClick: (PinConversation) -> Unit,
) : RecyclerView.Adapter<PinsAdapter.Holder>() {
    private var items = listOf<PinConversation>()
    private var icons = mapOf<String, CustomIcon?>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<PinConversation>, iconMap: Map<String, CustomIcon?> = icons) {
        items = list
        icons = iconMap
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(android.R.layout.simple_list_item_2, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val item = items[position]
        holder.itemView.findViewById<TextView>(android.R.id.text1).text =
            if (item.target.kind == PinTargetKind.NOTE_TO_SELF) holder.itemView.context.getString(R.string.note_to_self_title)
            else item.displayName ?: holder.itemView.context.getString(R.string.pin_unavailable)
        val iconKey = when (item.target.kind) {
            PinTargetKind.PEER -> "peer:${item.target.id}"
            PinTargetKind.GROUP -> "group:${item.target.id}"
            PinTargetKind.NOTE_TO_SELF -> "note_to_self:"
        }
        holder.itemView.findViewById<TextView>(android.R.id.text1).apply {
            setCompoundDrawablesRelativeWithIntrinsicBounds(
                customIconDrawable(context, icons[iconKey], text.toString(), 36),
                null,
                null,
                null,
            )
            compoundDrawablePadding = (8 * resources.displayMetrics.density).toInt()
        }
        holder.itemView.findViewById<TextView>(android.R.id.text2).text = holder.itemView.context.getString(R.string.pin_order, position + 1)
        holder.itemView.setOnClickListener { onClick(item) }
    }
}

/** Group rows: creator-controlled name plus authoritative roster size. */
private class GroupsAdapter(
    private val onClick: (Group) -> Unit,
) : RecyclerView.Adapter<GroupsAdapter.Holder>() {
    private var items = listOf<Group>()
    private var labels = mapOf<String, String>()
    private var icons = mapOf<String, CustomIcon?>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(
        list: List<Group>,
        labelText: Map<String, String> = labels,
        iconMap: Map<String, CustomIcon?> = icons,
    ) {
        items = list
        labels = labelText
        icons = iconMap
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(R.layout.row_group, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val group = items[position]
        holder.itemView.findViewById<TextView>(R.id.group_name).text = group.name
        holder.itemView.findViewById<ImageView>(R.id.group_icon).setImageDrawable(
            customIconDrawable(holder.itemView.context, icons[group.id], group.name),
        )
        holder.itemView.findViewById<TextView>(R.id.group_members).text =
            holder.itemView.context.resources.getQuantityString(
                R.plurals.group_member_count,
                group.members.size,
                group.members.size,
            )
        holder.itemView.findViewById<TextView>(R.id.group_labels).apply {
            text = labels[group.id].orEmpty()
            visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
        }
        holder.itemView.setOnClickListener { onClick(group) }
    }
}

/** Contact rows: name, short peer id, verified badge. */
private class ContactsAdapter(
    private val onClick: (Contact) -> Unit,
    private val onRename: (Contact) -> Unit,
) : RecyclerView.Adapter<ContactsAdapter.Holder>() {
    private var items = listOf<Contact>()
    private var labels = mapOf<String, String>()
    private var icons = mapOf<String, CustomIcon?>()

    class Holder(view: android.view.View) : RecyclerView.ViewHolder(view)

    fun submit(
        list: List<Contact>,
        labelText: Map<String, String> = labels,
        iconMap: Map<String, CustomIcon?> = icons,
    ) {
        items = list
        labels = labelText
        icons = iconMap
        notifyDataSetChanged()
    }

    fun nameOf(peer: String): String? = items.firstOrNull { it.peer == peer }?.name

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(
            LayoutInflater.from(parent.context)
                .inflate(R.layout.row_contact, parent, false),
        )

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val contact = items[position]
        holder.itemView.findViewById<TextView>(R.id.contact_name).text = contact.name
        holder.itemView.findViewById<ImageView>(R.id.contact_icon).setImageDrawable(
            customIconDrawable(holder.itemView.context, icons[contact.peer], contact.name),
        )
        holder.itemView.findViewById<TextView>(R.id.contact_peer).text =
            contact.peer.take(16) + "…"
        holder.itemView.findViewById<TextView>(R.id.contact_verified).visibility =
            if (contact.verified) android.view.View.VISIBLE else android.view.View.GONE
        holder.itemView.findViewById<TextView>(R.id.contact_labels).apply {
            text = labels[contact.peer].orEmpty()
            visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
        }
        holder.itemView.findViewById<Button>(R.id.contact_rename).setOnClickListener {
            onRename(contact)
        }
        holder.itemView.setOnClickListener { onClick(contact) }
    }
}
