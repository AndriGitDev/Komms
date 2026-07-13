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
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.io.File
import komms.core.bundleQrText
import uniffi.kult_ffi.Contact
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.NatVerdict

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
                is Event.ContactAdded -> refreshContacts()
                is Event.SessionEstablished -> onSessionEstablished(event.peer)
                is Event.MessageReceived -> refreshContacts()
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

        val list = findViewById<RecyclerView>(R.id.main_contacts)
        list.layoutManager = LinearLayoutManager(this)
        list.adapter = contacts

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
        refreshContacts()
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
                s.address.take(12) + "…", nat, s.lanPeers.size, s.queued.toLong(), s.transit.toLong(),
            )
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

    private fun onSessionEstablished(peer: String) {
        if (peer !in knownPeers) {
            refreshContacts()
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

/** Contact rows: name, short peer id, verified badge. */
private class ContactsAdapter(
    private val onClick: (Contact) -> Unit,
) : RecyclerView.Adapter<ContactsAdapter.Holder>() {
    private var items = listOf<Contact>()

    class Holder(view: android.view.View) : RecyclerView.ViewHolder(view)

    fun submit(list: List<Contact>) {
        items = list.sortedBy { it.name.lowercase() }
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
        holder.itemView.setOnClickListener { onClick(contact) }
    }
}
