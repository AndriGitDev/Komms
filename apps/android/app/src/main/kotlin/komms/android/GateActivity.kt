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
    private enum class AuthorityUpgradeKind { MIGRATION, RESET, LEGACY_BACKUP_RESET }

    private data class PendingAuthorityUpgrade(
        val kind: AuthorityUpgradeKind,
        val passphrase: String,
        val staged: File,
        val mnemonic: String,
        val newAddress: String?,
        val legacyBackup: Uri? = null,
        val backupMnemonic: String? = null,
    )

    private lateinit var dataDir: File
    private var backupUri: Uri? = null
    private var recoveryAuthorityUri: Uri? = null
    private var startupDialog: AlertDialog? = null
    private var pendingAuthorityUpgrade: PendingAuthorityUpgrade? = null

    private val pickBackup =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            backupUri = uri
            findViewById<android.widget.TextView>(R.id.gate_backup_name).text =
                uri?.lastPathSegment ?: getString(R.string.gate_no_backup)
        }

    private val pickRecoveryAuthority =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            recoveryAuthorityUri = uri
            findViewById<android.widget.TextView>(R.id.gate_recovery_authority_name).text =
                uri?.lastPathSegment ?: getString(R.string.gate_no_recovery_authority)
        }

    private val createRecoveryAuthority =
        registerForActivityResult(
            ActivityResultContracts.CreateDocument("application/octet-stream"),
        ) { uri ->
            if (uri == null) {
                showRecoveryAuthorityPrompt()
            } else {
                writeRecoveryAuthority(uri)
            }
        }

    private val createUpgradedAuthority =
        registerForActivityResult(
            ActivityResultContracts.CreateDocument("application/octet-stream"),
        ) { uri ->
            if (uri == null) {
                pendingAuthorityUpgrade?.let(::showAuthorityUpgradePrepared)
            } else {
                writeUpgradedAuthority(uri)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_gate)
        applyEdgeToEdgeInsets()
        dataDir = KommsApp.dataDir(application)
        if (NodeHolder.session == null) {
            cacheDir.listFiles()
                ?.filter {
                    it.name.startsWith("account-authority-") ||
                        it.name.startsWith("authority-upgrade-")
                }
                ?.forEach(File::delete)
        }

        // A recreation during mandatory first-run export must resume the
        // gate. Other live-session relaunches can proceed normally.
        if (NodeHolder.session != null) {
            if (NodeHolder.recoveryAuthorityOnboardingPending) {
                if (
                    NodeHolder.recoveryAuthorityWritten &&
                    NodeHolder.stagedRecoveryAuthorityMnemonic != null
                ) {
                    showRecoveryAuthorityPhrase(
                        checkNotNull(NodeHolder.stagedRecoveryAuthorityMnemonic),
                    )
                } else {
                    showRecoveryAuthorityPrompt()
                }
            } else {
                proceed()
            }
            return
        }

        val storeExists = File(dataDir, "node.db").exists()
        val passphrase = findViewById<android.widget.EditText>(R.id.gate_passphrase)
        val confirm = findViewById<android.widget.EditText>(R.id.gate_confirm)
        val unlock = findViewById<android.widget.Button>(R.id.gate_unlock)
        val restoreBlock = findViewById<View>(R.id.gate_restore_block)
        val restoreToggle = findViewById<android.widget.Button>(R.id.gate_restore_toggle)

        // Unlock vs. first-run create: same call — the node creates on
        // first run — but creating asks for the passphrase twice.
        confirm.visibility = if (storeExists) View.GONE else View.VISIBLE
        restoreBlock.visibility = View.GONE
        restoreToggle.visibility = if (storeExists) View.GONE else View.VISIBLE
        unlock.setText(if (storeExists) R.string.gate_unlock else R.string.gate_create)
        findViewById<android.widget.TextView>(R.id.gate_passphrase_help).setText(
            if (storeExists) {
                R.string.gate_passphrase_unlock_help
            } else {
                R.string.gate_passphrase_create_help
            },
        )
        restoreToggle.setOnClickListener {
            val showing = restoreBlock.visibility == View.VISIBLE
            restoreBlock.visibility = if (showing) View.GONE else View.VISIBLE
            restoreToggle.setText(
                if (showing) R.string.gate_restore_toggle else android.R.string.cancel,
            )
        }

        unlock.setOnClickListener {
            val pass = passphrase.text.toString()
            if (pass.isEmpty()) return@setOnClickListener toast(getString(R.string.gate_empty))
            if (!storeExists && pass != confirm.text.toString()) {
                return@setOnClickListener toast(getString(R.string.gate_mismatch))
            }
            if (!storeExists) {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putBoolean(PENDING_RECOVERY_AUTHORITY, true)
                    .commit()
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
                    when {
                        it.contains("explicit offline-authority migration is required") ->
                            showAuthorityUpgradePrompt(AuthorityUpgradeKind.MIGRATION, pass)
                        it.contains("authority reset with a new identity is required") ->
                            showAuthorityUpgradePrompt(AuthorityUpgradeKind.RESET, pass)
                        else -> toast(it)
                    }
                },
            ) { session ->
                hideStartupDialog()
                NodeHolder.attach(session)
                NativeWakeManager.onSessionAvailable(this)
                if (storeExists) {
                    if (
                        getSharedPreferences(PREFS, MODE_PRIVATE)
                            .getBoolean(PENDING_RECOVERY_AUTHORITY, false)
                    ) {
                        NodeHolder.beginRecoveryAuthorityOnboarding()
                        busy(false)
                        showRecoveryAuthorityPrompt(
                            getString(R.string.recovery_authority_interrupted),
                        )
                    } else {
                        proceed()
                    }
                } else {
                    NodeHolder.beginRecoveryAuthorityOnboarding()
                    busy(false)
                    showRecoveryAuthorityPrompt()
                }
            }
        }

        findViewById<android.widget.Button>(R.id.gate_pick_backup).setOnClickListener {
            pickBackup.launch(arrayOf("*/*"))
        }
        findViewById<android.widget.Button>(R.id.gate_pick_recovery_authority).setOnClickListener {
            pickRecoveryAuthority.launch(arrayOf("*/*"))
        }
        findViewById<android.widget.CheckBox>(R.id.gate_legacy_backup)
            .setOnCheckedChangeListener { _, legacy ->
                findViewById<View>(R.id.gate_legacy_warning).visibility =
                    if (legacy) View.VISIBLE else View.GONE
                findViewById<View>(R.id.gate_current_authority_fields).visibility =
                    if (legacy) View.GONE else View.VISIBLE
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
            if (findViewById<android.widget.CheckBox>(R.id.gate_legacy_backup).isChecked) {
                showAuthorityUpgradePrompt(
                    AuthorityUpgradeKind.LEGACY_BACKUP_RESET,
                    pass,
                    uri,
                    mnemonic,
                )
                return@setOnClickListener
            }
            val authorityUri = recoveryAuthorityUri
                ?: return@setOnClickListener toast(getString(R.string.gate_no_recovery_authority))
            val recoveryMnemonic =
                findViewById<android.widget.EditText>(R.id.gate_recovery_mnemonic)
                    .text.toString().trim()
            showStartupDialog()
            busy(true)
            runNode(
                work = {
                    // SAF gives a content:// stream; the FFI takes a path.
                    val local = File(cacheDir, "restore.kkr")
                    val localAuthority = File(cacheDir, "restore-authority.kra")
                    copyToLocal(uri, local)
                    copyToLocal(authorityUri, localAuthority)
                    try {
                        Session.restore(
                            dataDir, pass, local, mnemonic,
                            localAuthority, recoveryMnemonic,
                            loadSettings(), KdfChoice.MOBILE, NodeHolder.sink,
                        ).also(ThemeController::reconcile)
                    } finally {
                        local.delete()
                        localAuthority.delete()
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
                NativeWakeManager.onSessionAvailable(this)
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putBoolean(PENDING_RECOVERY_AUTHORITY, false)
                    .apply()
                proceed()
            }
        }

        findViewById<android.widget.Button>(R.id.gate_settings).setOnClickListener {
            startActivity(
                Intent(this, SettingsActivity::class.java)
                    .putExtra(SettingsActivity.EXTRA_NETWORK_ONLY, true),
            )
        }
    }

    override fun onDestroy() {
        hideStartupDialog()
        pendingAuthorityUpgrade?.staged?.delete()
        pendingAuthorityUpgrade = null
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

    private fun showRecoveryAuthorityPrompt(error: String? = null) {
        AlertDialog.Builder(this)
            .setTitle(R.string.recovery_authority_required_title)
            .setMessage(
                if (error == null) {
                    getString(R.string.recovery_authority_required_body)
                } else {
                    getString(R.string.recovery_authority_retry_body, error)
                },
            )
            .setCancelable(false)
            .setPositiveButton(R.string.recovery_authority_choose) { _, _ ->
                createRecoveryAuthority.launch(
                    getString(R.string.recovery_authority_filename),
                )
            }
            .show()
    }

    private fun writeRecoveryAuthority(uri: Uri) {
        val session = NodeHolder.session ?: return
        busy(true)
        runNode(
            work = {
                var staged = NodeHolder.stagedRecoveryAuthority
                var mnemonic = NodeHolder.stagedRecoveryAuthorityMnemonic
                if (staged == null || mnemonic == null) {
                    staged = File.createTempFile("account-authority-", ".kra", cacheDir)
                    check(staged.delete()) { "could not prepare protected authority export" }
                    mnemonic = session.exportAccountRecoveryAuthority(staged)
                    NodeHolder.stageRecoveryAuthority(staged, mnemonic)
                }
                val output = contentResolver.openOutputStream(uri, "w")
                    ?: error("the selected location could not be opened")
                output.use { destination ->
                    staged.inputStream().use { source -> source.copyTo(destination) }
                }
                mnemonic
            },
            onError = { error ->
                busy(false)
                showRecoveryAuthorityPrompt(error)
            },
        ) { mnemonic ->
            busy(false)
            NodeHolder.markRecoveryAuthorityWritten()
            showRecoveryAuthorityPhrase(mnemonic)
        }
    }

    private fun showRecoveryAuthorityPhrase(mnemonic: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.recovery_authority_done_title)
            .setMessage(getString(R.string.recovery_authority_done_body, mnemonic))
            .setCancelable(false)
            .setPositiveButton(R.string.recovery_authority_done_ack) { _, _ ->
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putBoolean(PENDING_RECOVERY_AUTHORITY, false)
                    .apply()
                NodeHolder.completeRecoveryAuthorityOnboarding()
                proceed()
            }
            .show()
    }

    private fun showAuthorityUpgradePrompt(
        kind: AuthorityUpgradeKind,
        passphrase: String,
        legacyBackup: Uri? = null,
        backupMnemonic: String? = null,
    ) {
        val reset = kind != AuthorityUpgradeKind.MIGRATION
        val message = if (kind == AuthorityUpgradeKind.LEGACY_BACKUP_RESET) {
            "This legacy backup contains an account root that may have been copied, so the former address cannot safely resume. Komms will decrypt it only into an unpublished migration projection, then publish a fresh account containing cleared petnames and accurately labelled local pairwise/note history. Groups, routes, sessions, devices, queues, and service capabilities will not transfer. Every retained contact must be re-verified."
        } else if (reset) {
            "This Alpha profile copied its account root to another device. Revocation cannot erase that copy. The safe upgrade creates a new account, clears all live route, session, device, group, and delivery authority, and keeps only clearly marked local pairwise/note history and petnames. Every retained contact must be re-verified."
        } else {
            "Komms found no linked-device root copy in this store. Keep this address only if you also never exported or copied a legacy KKR7 backup. If you did, choose the conservative new-identity reset. In-place migration keeps this device, petnames, and history after the root is saved as a separate offline authority."
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(
                if (reset) {
                    if (kind == AuthorityUpgradeKind.LEGACY_BACKUP_RESET) {
                        "Recover legacy backup with a new identity"
                    } else {
                        "Required new-identity security reset"
                    }
                } else {
                    "Required device-authority migration"
                },
            )
            .setMessage(message)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Prepare offline authority") { _, _ ->
                prepareAuthorityUpgrade(kind, passphrase, legacyBackup, backupMnemonic)
            }
        if (!reset) {
            dialog.setNeutralButton("I copied a legacy backup") { _, _ ->
                showAuthorityUpgradePrompt(AuthorityUpgradeKind.RESET, passphrase)
            }
        }
        dialog.show()
    }

    private fun prepareAuthorityUpgrade(
        kind: AuthorityUpgradeKind,
        passphrase: String,
        legacyBackup: Uri? = null,
        backupMnemonic: String? = null,
    ) {
        busy(true)
        runNode(
            work = {
                val staged = File.createTempFile("authority-upgrade-", ".kra", cacheDir)
                check(staged.delete()) { "could not prepare protected authority export" }
                try {
                    if (kind == AuthorityUpgradeKind.LEGACY_BACKUP_RESET) {
                        val prepared = Session.prepareLegacyBackupAuthorityReset(staged)
                        PendingAuthorityUpgrade(
                            kind,
                            passphrase,
                            staged,
                            prepared.recoveryMnemonic,
                            prepared.newAddress,
                            legacyBackup,
                            backupMnemonic,
                        )
                    } else if (kind == AuthorityUpgradeKind.RESET) {
                        val prepared = Session.prepareAlphaAuthorityReset(
                            dataDir,
                            passphrase,
                            staged,
                        )
                        PendingAuthorityUpgrade(
                            kind,
                            passphrase,
                            staged,
                            prepared.recoveryMnemonic,
                            prepared.newAddress,
                        )
                    } else {
                        PendingAuthorityUpgrade(
                            kind,
                            passphrase,
                            staged,
                            Session.prepareAlphaAuthorityMigration(
                                dataDir,
                                passphrase,
                                staged,
                            ),
                            null,
                        )
                    }
                } catch (error: Throwable) {
                    staged.delete()
                    throw error
                }
            },
            onError = { error ->
                busy(false)
                toast(error)
            },
        ) { prepared ->
            busy(false)
            pendingAuthorityUpgrade = prepared
            createUpgradedAuthority.launch(
                if (prepared.kind != AuthorityUpgradeKind.MIGRATION) {
                    "komms-new-account-authority.kra"
                } else {
                    "komms-account-authority.kra"
                },
            )
        }
    }

    private fun writeUpgradedAuthority(uri: Uri) {
        val prepared = pendingAuthorityUpgrade ?: return
        busy(true)
        runNode(
            work = {
                val output = contentResolver.openOutputStream(uri, "w")
                    ?: error("the selected location could not be opened")
                output.use { destination ->
                    prepared.staged.inputStream().use { source -> source.copyTo(destination) }
                }
                prepared
            },
            onError = { error ->
                busy(false)
                toast(error)
                showAuthorityUpgradePrepared(prepared)
            },
        ) {
            busy(false)
            showAuthorityUpgradePrepared(it)
        }
    }

    private fun showAuthorityUpgradePrepared(prepared: PendingAuthorityUpgrade) {
        val reset = prepared.kind != AuthorityUpgradeKind.MIGRATION
        val content = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            val padding = (20 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, 0)
        }
        content.addView(android.widget.TextView(this).apply {
            text = buildString {
                if (reset) {
                    append("New address:\n")
                    append(prepared.newAddress)
                    append("\n\n")
                }
                append("Write these 24 words down separately. They open only the saved offline authority file:\n\n")
                append(prepared.mnemonic)
            }
            setTextIsSelectable(true)
        })
        val confirm = android.widget.CheckBox(this).apply {
            text = if (reset) {
                "I stored both parts separately and understand my address and every safety number will change"
            } else {
                "I stored the authority file and its words separately"
            }
        }
        content.addView(confirm)
        val dialog = AlertDialog.Builder(this)
            .setTitle("Confirm security upgrade")
            .setView(content)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Complete", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (!confirm.isChecked) {
                    toast("Confirm the security statement before continuing.")
                    return@setOnClickListener
                }
                dialog.dismiss()
                completeAuthorityUpgrade(prepared)
            }
        }
        dialog.show()
    }

    private fun completeAuthorityUpgrade(prepared: PendingAuthorityUpgrade) {
        showStartupDialog()
        busy(true)
        runNode(
            work = {
                val settings = loadSettings()
                if (prepared.kind == AuthorityUpgradeKind.LEGACY_BACKUP_RESET) {
                    val backupUri = prepared.legacyBackup
                        ?: error("the legacy backup selection is no longer available")
                    val backupMnemonic = prepared.backupMnemonic
                        ?: error("the legacy backup phrase is no longer available")
                    val local = File(cacheDir, "legacy-reset.kkr")
                    copyToLocal(backupUri, local)
                    try {
                        Session.restore(
                            dataDir,
                            prepared.passphrase,
                            local,
                            backupMnemonic,
                            prepared.staged,
                            prepared.mnemonic,
                            settings,
                            KdfChoice.MOBILE,
                            NodeHolder.sink,
                        )
                    } finally {
                        local.delete()
                    }
                } else if (prepared.kind == AuthorityUpgradeKind.RESET) {
                    Session.resetAuthority(
                        dataDir,
                        prepared.passphrase,
                        prepared.staged,
                        prepared.mnemonic,
                        settings,
                        KdfChoice.MOBILE,
                        NodeHolder.sink,
                    )
                } else {
                    Session.migrateAuthority(
                        dataDir,
                        prepared.passphrase,
                        prepared.staged,
                        prepared.mnemonic,
                        settings,
                        KdfChoice.MOBILE,
                        NodeHolder.sink,
                    )
                }.also(ThemeController::reconcile)
            },
            onError = { error ->
                hideStartupDialog()
                busy(false)
                toast(error)
                showAuthorityUpgradePrepared(prepared)
            },
        ) { session ->
            hideStartupDialog()
            busy(false)
            prepared.staged.delete()
            pendingAuthorityUpgrade = null
            NodeHolder.attach(session)
            NativeWakeManager.onSessionAvailable(this)
            proceed()
        }
    }

    private fun copyToLocal(uri: Uri, destination: File) {
        destination.delete()
        val input = contentResolver.openInputStream(uri)
            ?: error("the selected file could not be opened")
        input.use { source ->
            destination.outputStream().use { source.copyTo(it) }
        }
    }

    private fun proceed() {
        startForegroundService(Intent(this, NodeService::class.java))
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private companion object {
        const val PREFS = "komms-onboarding"
        const val PENDING_RECOVERY_AUTHORITY = "recovery-authority-pending"
    }
}
