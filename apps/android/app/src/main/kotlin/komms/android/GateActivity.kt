package komms.android

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import java.io.File
import komms.core.NetworkSettings
import komms.core.Session
import komms.core.SettingsException
import uniffi.kult_ffi.KdfChoice

/**
 * The gate: create a new identity, unlock an existing store, or restore
 * from an encrypted `.kkr` backup + its 24-word mnemonic. Nothing else is
 * reachable until the node is running.
 */
class GateActivity : SecureActivity() {
    private lateinit var dataDir: File
    private var backupUri: Uri? = null
    private var startupDialog: AlertDialog? = null

    private val pickBackup =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            backupUri = uri
            findViewById<android.widget.TextView>(R.id.gate_backup_name).text =
                uri?.lastPathSegment ?: getString(R.string.gate_no_backup)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Process still holds a running node (e.g. relaunch from the
        // foreground-service notification): skip the gate.
        if (NodeHolder.session != null) {
            proceed()
            return
        }
        setContentView(R.layout.activity_gate)
        applyEdgeToEdgeInsets()
        dataDir = KommsApp.dataDir(application)

        val storeExists = File(dataDir, "node.db").exists()
        val passphrase = findViewById<android.widget.EditText>(R.id.gate_passphrase)
        val confirm = findViewById<android.widget.EditText>(R.id.gate_confirm)
        val unlock = findViewById<android.widget.Button>(R.id.gate_unlock)
        val restoreBlock = findViewById<View>(R.id.gate_restore_block)

        // Unlock vs. first-run create: same call — the node creates on
        // first run — but creating asks for the passphrase twice.
        confirm.visibility = if (storeExists) View.GONE else View.VISIBLE
        restoreBlock.visibility = if (storeExists) View.GONE else View.VISIBLE
        unlock.setText(if (storeExists) R.string.gate_unlock else R.string.gate_create)

        unlock.setOnClickListener {
            val pass = passphrase.text.toString()
            if (pass.isEmpty()) return@setOnClickListener toast(getString(R.string.gate_empty))
            if (!storeExists && pass != confirm.text.toString()) {
                return@setOnClickListener toast(getString(R.string.gate_mismatch))
            }
            showStartupDialog()
            busy(true)
            runNode(
                work = {
                    Session.open(dataDir, pass, loadSettings(), KdfChoice.MOBILE, NodeHolder.sink)
                        .also(ThemeController::reconcile)
                },
                onError = {
                    hideStartupDialog()
                    busy(false)
                    toast(it)
                },
            ) { session ->
                hideStartupDialog()
                NodeHolder.attach(session)
                proceed()
            }
        }

        findViewById<android.widget.Button>(R.id.gate_pick_backup).setOnClickListener {
            pickBackup.launch(arrayOf("*/*"))
        }

        findViewById<android.widget.Button>(R.id.gate_restore).setOnClickListener {
            val uri = backupUri ?: return@setOnClickListener toast(getString(R.string.gate_no_backup))
            val mnemonic = findViewById<android.widget.EditText>(R.id.gate_mnemonic)
                .text.toString().trim()
            val pass = passphrase.text.toString()
            if (pass.isEmpty()) return@setOnClickListener toast(getString(R.string.gate_empty))
            if (pass != confirm.text.toString()) {
                return@setOnClickListener toast(getString(R.string.gate_mismatch))
            }
            showStartupDialog()
            busy(true)
            runNode(
                work = {
                    // SAF gives a content:// stream; the FFI takes a path.
                    val local = File(cacheDir, "restore.kkr")
                    contentResolver.openInputStream(uri)!!.use { input ->
                        local.outputStream().use { input.copyTo(it) }
                    }
                    try {
                        Session.restore(
                            dataDir, pass, local, mnemonic,
                            loadSettings(), KdfChoice.MOBILE, NodeHolder.sink,
                        ).also(ThemeController::reconcile)
                    } finally {
                        local.delete()
                    }
                },
                onError = {
                    hideStartupDialog()
                    busy(false)
                    toast(it)
                },
            ) { session ->
                hideStartupDialog()
                NodeHolder.attach(session)
                proceed()
            }
        }

        findViewById<android.widget.Button>(R.id.gate_settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    override fun onDestroy() {
        hideStartupDialog()
        super.onDestroy()
    }

    /** Corrupt settings surface at the gate instead of silently reverting. */
    private fun loadSettings(): NetworkSettings = try {
        NetworkSettings.load(dataDir)
    } catch (e: SettingsException) {
        throw IllegalArgumentException(e.message)
    }

    private fun busy(on: Boolean) {
        findViewById<View>(R.id.gate_progress).visibility = if (on) View.VISIBLE else View.GONE
        findViewById<View>(R.id.gate_unlock).isEnabled = !on
        findViewById<View>(R.id.gate_restore).isEnabled = !on
    }

    private fun showStartupDialog() {
        if (startupDialog?.isShowing == true) return
        startupDialog = AlertDialog.Builder(this)
            .setTitle(R.string.gate_starting_title)
            .setMessage(R.string.gate_starting_message)
            .setCancelable(false)
            .create()
            .also(AlertDialog::show)
    }

    private fun hideStartupDialog() {
        startupDialog?.dismiss()
        startupDialog = null
    }

    private fun proceed() {
        startForegroundService(Intent(this, NodeService::class.java))
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
