package komms.android

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Menu
import android.view.MenuItem
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.ScrollView
import android.widget.RadioGroup
import android.widget.RadioButton
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File
import komms.core.bundleQrText
import uniffi.kult_ffi.Contact
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
import uniffi.kult_ffi.PinConversation
import uniffi.kult_ffi.PinTargetKind

/**
 * Contacts + the transport-indicator header. All state shown is the
 * node's own: the status snapshot and the stored contact list, verbatim.
 */
class MainActivity : AppCompatActivity() {
    private val contacts = ContactsAdapter { contact ->
        startActivity(
            Intent(this, ChatActivity::class.java)
                .putExtra("peer", contact.peer)
                .putExtra("name", contact.name),
        )
    }
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
                is Event.ContactAdded -> refreshLabelsAndLists(false)
                is Event.SessionEstablished -> onSessionEstablished(event.peer)
                is Event.MessageReceived -> refreshLabelsAndLists(false)
                is Event.GroupUpdated -> refreshLabelsAndLists(false)
                is Event.GroupMessageReceived -> refreshLabelsAndLists(false)
                is Event.FoldersChanged -> refreshLabelsAndLists(true)
                is Event.LabelsChanged -> refreshLabelsAndLists(true)
                is Event.PinsChanged -> refreshLabelsAndLists(true)
                is Event.ThemeChanged -> Unit // ThemeController applies process-wide DayNight.
                else -> {}
            }
        }
    }

    /** Peers we already listed — a re-established session for one of these
     *  means their key or device changed, and the user must hear it. */
    private var knownPeers = setOf<String>()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    private val createBackup =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri != null) exportBackup(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return backToGate()
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.main_toolbar))
        labelPreferences = LabelFilterPreferences(this)
        labelPreferences.load().also {
            selectedLabels = it.ids
            labelMode = it.mode
            folderKind = it.folderKind
            folderId = it.folderId
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
            R.id.menu_folders -> startActivity(Intent(this, FolderManagerActivity::class.java))
            R.id.menu_labels -> startActivity(Intent(this, LabelManagerActivity::class.java))
            R.id.menu_pins -> showPinManager()
            R.id.menu_my_qr -> showMyQr()
            R.id.menu_backup -> createBackup.launch("komms-backup.kkr")
            R.id.menu_settings -> startActivity(Intent(this, SettingsActivity::class.java))
            R.id.menu_lock -> lock()
            else -> return super.onOptionsItemSelected(item)
        }
        return true
    }

    private fun refreshStatus() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.status() }, onError = {}) { s ->
            val nat = when (s.nat) {
                NatVerdict.PUBLIC -> getString(R.string.nat_public)
                NatVerdict.PRIVATE -> getString(R.string.nat_private)
                NatVerdict.UNKNOWN -> getString(R.string.nat_unknown)
            }
            findViewById<TextView>(R.id.main_status).text = getString(
                R.string.status_line,
                s.address.take(12) + "…", nat, s.lanPeers.size, s.scheduled.toLong(),
                s.queued.toLong(), s.transit.toLong(),
            )
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
            findViewById<TextView>(R.id.main_empty).visibility =
                if (list.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE
        }
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
            renderFolderControls(snapshot.folders)
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
            pins.submit(snapshot.ordered.filter { it.pinned })
            knownPeers = snapshot.contacts.map { it.peer }.toSet()
            contacts.submit(visibleContacts, snapshot.contactLabels.mapValues { (_, labels) -> labelLines(labels) })
            groups.submit(visibleGroups, snapshot.groupLabels.mapValues { (_, labels) -> labelLines(labels) })
            findViewById<TextView>(R.id.main_empty).visibility =
                if (visibleContacts.isEmpty()) View.VISIBLE else View.GONE
            findViewById<TextView>(R.id.main_groups_empty).visibility =
                if (visibleGroups.isEmpty()) View.VISIBLE else View.GONE
            findViewById<Button>(R.id.main_note_to_self).apply {
                visibility = if ("note_to_self:" in snapshot.matching && "note_to_self:" !in pinnedKeys) View.VISIBLE else View.GONE
                text = buildString {
                    append(getString(R.string.note_to_self_title))
                    val lines = labelLines(snapshot.noteLabels)
                    if (lines.isNotEmpty()) append("\n").append(lines)
                }
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

    private fun renderFolderControls(folders: List<Folder>) {
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

    /** The pairing QR: a fresh prekey bundle, hex in alphanumeric mode —
     *  scannable by another phone or pasteable into `kult add`. */
    private fun showMyQr() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.myBundleHex() to session.address }) { (hex, address) ->
            val view = LayoutInflater.from(this).inflate(R.layout.dialog_qr, null)
            view.findViewById<ImageView>(R.id.qr_image).setImageBitmap(qrBitmap(bundleQrText(hex)))
            view.findViewById<TextView>(R.id.qr_caption).text =
                getString(R.string.my_qr_caption, address)
            AlertDialog.Builder(this)
                .setTitle(R.string.my_qr_title)
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
    }

    private fun exportBackup(uri: Uri) {
        val session = NodeHolder.session ?: return
        runNode(
            work = {
                // The node writes 0600 and refuses to overwrite; SAF hands
                // us a stream, so export to a unique temp path and copy.
                val local = File.createTempFile("backup", ".kkr", cacheDir)
                local.delete()
                val mnemonic = session.exportBackup(local)
                try {
                    contentResolver.openOutputStream(uri)!!.use { out ->
                        local.inputStream().use { it.copyTo(out) }
                    }
                } finally {
                    local.delete()
                }
                mnemonic
            },
        ) { mnemonic ->
            // Shown exactly once, never stored, never in the clipboard.
            AlertDialog.Builder(this)
                .setTitle(R.string.backup_done_title)
                .setMessage(getString(R.string.backup_done_body, mnemonic))
                .setCancelable(false)
                .setPositiveButton(R.string.backup_done_ack, null)
                .show()
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
)

/** Leading cross-type pinned block in persisted manual order. */
private class PinsAdapter(
    private val onClick: (PinConversation) -> Unit,
) : RecyclerView.Adapter<PinsAdapter.Holder>() {
    private var items = listOf<PinConversation>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<PinConversation>) {
        items = list
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

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<Group>, labelText: Map<String, String> = labels) {
        items = list
        labels = labelText
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(LayoutInflater.from(parent.context).inflate(R.layout.row_group, parent, false))

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val group = items[position]
        holder.itemView.findViewById<TextView>(R.id.group_name).text = group.name
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
) : RecyclerView.Adapter<ContactsAdapter.Holder>() {
    private var items = listOf<Contact>()
    private var labels = mapOf<String, String>()

    class Holder(view: android.view.View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<Contact>, labelText: Map<String, String> = labels) {
        items = list
        labels = labelText
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
        holder.itemView.findViewById<TextView>(R.id.contact_peer).text =
            contact.peer.take(16) + "…"
        holder.itemView.findViewById<TextView>(R.id.contact_verified).visibility =
            if (contact.verified) android.view.View.VISIBLE else android.view.View.GONE
        holder.itemView.findViewById<TextView>(R.id.contact_labels).apply {
            text = labels[contact.peer].orEmpty()
            visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
        }
        holder.itemView.setOnClickListener { onClick(contact) }
    }
}
