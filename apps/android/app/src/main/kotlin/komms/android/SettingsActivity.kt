package komms.android

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.Switch
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import java.io.File
import komms.core.NativeWakePreference
import komms.core.NetworkSettings
import komms.core.RendezvousSetting
import komms.core.SettingsException
import komms.core.WakeSetting
import komms.core.androidIncognitoKeyboardPolicy
import komms.core.androidScreenSecurityPolicy
import uniffi.kult_ffi.ThemePreference

/**
 * Network settings — the same knobs as `kultd`'s flags and the desktop
 * app's settings screen, persisted as secret-free `settings.json` in the
 * data directory. Applied when the node next starts (the unlock after a
 * lock), exactly like desktop.
 */
class SettingsActivity : SecureActivity() {
    companion object {
        const val EXTRA_NETWORK_ONLY = "komms.settings.NETWORK_ONLY"
    }

    private val createBackup =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri != null) exportBackup(uri)
        }

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            NativeWakeManager.onPermissionChanged(this)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        applyEdgeToEdgeInsets()
        setSupportActionBar(findViewById(R.id.settings_toolbar))
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        if (intent.getBooleanExtra(EXTRA_NETWORK_ONLY, false)) {
            findViewById<View>(R.id.settings_unlocked_sections).visibility = View.GONE
        }

        findViewById<Button>(R.id.settings_backup).setOnClickListener {
            createBackup.launch("komms-backup.kkr")
        }
        findViewById<Button>(R.id.settings_devices).setOnClickListener {
            startActivity(Intent(this, DeviceActivity::class.java))
        }
        findViewById<Button>(R.id.settings_folders).setOnClickListener {
            startActivity(Intent(this, FolderManagerActivity::class.java))
        }
        findViewById<Button>(R.id.settings_labels).setOnClickListener {
            startActivity(Intent(this, LabelManagerActivity::class.java))
        }
        findViewById<Button>(R.id.settings_icons).setOnClickListener {
            startActivity(Intent(this, CustomIconActivity::class.java))
        }

        val dataDir = KommsApp.dataDir(application)
        val theme = findViewById<RadioGroup>(R.id.set_theme)
        theme.check(
            when (ThemeController.cached()) {
                ThemePreference.SYSTEM -> R.id.set_theme_system
                ThemePreference.LIGHT -> R.id.set_theme_light
                ThemePreference.DARK -> R.id.set_theme_dark
            },
        )
        theme.setOnCheckedChangeListener { _, checked ->
            ThemeController.select(
                when (checked) {
                    R.id.set_theme_light -> ThemePreference.LIGHT
                    R.id.set_theme_dark -> ThemePreference.DARK
                    else -> ThemePreference.SYSTEM
                },
            )
        }
        val language = findViewById<RadioGroup>(R.id.set_language)
        language.check(LocaleController.checkedId())
        language.setOnCheckedChangeListener { _, checked ->
            LocaleController.select(LocaleController.preferenceFor(checked))
        }
        val screenSecurity = androidScreenSecurityPolicy()
        findViewById<TextView>(R.id.screen_security_mechanism).text =
            localizedSource(screenSecurity.mechanism)
        findViewById<TextView>(R.id.screen_security_limits).text =
            screenSecurity.limitations.joinToString(separator = "\n") {
                getString(R.string.screen_limitation_bullet, localizedSource(it))
            }
        val inputPrivacy = androidIncognitoKeyboardPolicy()
        findViewById<TextView>(R.id.incognito_keyboard_mechanism).text =
            localizedSource(inputPrivacy.mechanism)
        findViewById<TextView>(R.id.incognito_keyboard_limits).text =
            inputPrivacy.limitations.joinToString(separator = "\n") {
                getString(R.string.screen_limitation_bullet, localizedSource(it))
            }
        val nativeWake = findViewById<RadioGroup>(R.id.set_native_wake)
        nativeWake.check(
            when (NativeWakePreferences(this).load()) {
                NativeWakePreference.BACKGROUND_ONLY -> R.id.set_native_wake_background
                NativeWakePreference.GENERIC_VISIBLE -> R.id.set_native_wake_visible
                NativeWakePreference.DISABLED -> R.id.set_native_wake_disabled
            },
        )
        val wakeSupported = NativeWakePlatform.supported(this)
        for (index in 0 until nativeWake.childCount) {
            nativeWake.getChildAt(index).isEnabled = wakeSupported
        }
        findViewById<TextView>(R.id.native_wake_limitations).setText(
            if (wakeSupported) {
                R.string.native_wake_android_limits
            } else {
                R.string.native_wake_google_free
            },
        )
        val loaded = try {
            NetworkSettings.load(dataDir)
        } catch (e: SettingsException) {
            // Surface the corruption; edit from defaults without silently
            // overwriting until the user saves.
            toast(getString(R.string.error_settings))
            NetworkSettings()
        }

        val listen = findViewById<EditText>(R.id.set_listen)
        val bootstrap = findViewById<EditText>(R.id.set_bootstrap)
        val relay = findViewById<EditText>(R.id.set_relay)
        val mailboxes = findViewById<EditText>(R.id.set_mailboxes)
        val spool = findViewById<EditText>(R.id.set_spool)
        val meshTcp = findViewById<EditText>(R.id.set_mesh_tcp)
        val mode = findViewById<RadioGroup>(R.id.set_mode)
        val modeDisclosure = findViewById<TextView>(R.id.set_mode_disclosure)
        val standardDisclosure = findViewById<Switch>(R.id.set_standard_disclosure)
        val sovereignDirectRoutes = findViewById<Switch>(R.id.set_sovereign_direct_routes)
        val providerDirectory = findViewById<EditText>(R.id.set_provider_directory)
        val providerRoots = findViewById<EditText>(R.id.set_provider_roots)
        val rendezvous = findViewById<EditText>(R.id.set_rendezvous)
        val wake = findViewById<EditText>(R.id.set_wake)
        val torProxy = findViewById<EditText>(R.id.set_tor_proxy)
        val serveMailbox = findViewById<Switch>(R.id.set_serve_mailbox)
        val mdns = findViewById<Switch>(R.id.set_mdns)
        val bridge = findViewById<Switch>(R.id.set_bridge)

        mode.check(
            when (loaded.mode) {
                "private" -> R.id.set_mode_private
                "sovereign" -> R.id.set_mode_sovereign
                else -> R.id.set_mode_standard
            },
        )
        standardDisclosure.isChecked = loaded.standardDisclosureConfirmed
        sovereignDirectRoutes.isChecked = loaded.sovereignPublishDirectRoutes
        providerDirectory.setText(loaded.providerDirectory ?: "")
        providerRoots.setText(loaded.providerDirectoryRoots.joinToString("\n"))
        rendezvous.setText(
            loaded.rendezvous.joinToString("\n") { entry ->
                val access = when {
                    entry.standard && entry.privateViaTor -> "both"
                    entry.standard -> "standard"
                    else -> "private"
                }
                "${entry.origin},${entry.staticKey},$access"
            },
        )
        wake.setText(
            loaded.wake.joinToString("\n") { entry ->
                val access = when {
                    entry.standard && entry.privateViaTor -> "both"
                    entry.standard -> "standard"
                    else -> "private"
                }
                "${entry.origin},${entry.staticKey},$access"
            },
        )
        torProxy.setText(loaded.torProxy ?: "")
        listen.setText(loaded.listen.joinToString("\n"))
        bootstrap.setText(loaded.bootstrap.joinToString("\n"))
        relay.setText(loaded.relay ?: "")
        mailboxes.setText(loaded.mailboxes.joinToString("\n"))
        spool.setText(loaded.spool ?: "")
        meshTcp.setText(loaded.meshtasticTcp ?: "")
        serveMailbox.isChecked = loaded.serveMailbox
        mdns.isChecked = loaded.mdns
        bridge.isChecked = loaded.bridge
        updateModeDisclosure(
            mode.checkedRadioButtonId,
            modeDisclosure,
            standardDisclosure,
            sovereignDirectRoutes,
        )
        mode.setOnCheckedChangeListener { _, checked ->
            updateModeDisclosure(
                checked,
                modeDisclosure,
                standardDisclosure,
                sovereignDirectRoutes,
            )
        }

        findViewById<android.widget.Button>(R.id.settings_save).setOnClickListener {
            try {
                val edited = loaded.copy(
                    mode = selectedMode(mode.checkedRadioButtonId),
                    standardDisclosureConfirmed = standardDisclosure.isChecked,
                    sovereignPublishDirectRoutes = sovereignDirectRoutes.isChecked,
                    providerDirectory = blankToNull(providerDirectory),
                    providerDirectoryRoots = lines(providerRoots),
                    rendezvous = rendezvousLines(rendezvous),
                    wake = wakeLines(wake),
                    torProxy = blankToNull(torProxy),
                    listen = lines(listen),
                    bootstrap = lines(bootstrap),
                    relay = blankToNull(relay),
                    mailboxes = lines(mailboxes),
                    spool = blankToNull(spool),
                    meshtasticTcp = blankToNull(meshTcp),
                    serveMailbox = serveMailbox.isChecked,
                    mdns = mdns.isChecked,
                    bridge = bridge.isChecked,
                )
                if (
                    edited.mode == "standard" &&
                    edited.providerDirectory != null &&
                    !edited.standardDisclosureConfirmed
                ) {
                    throw SettingsException(getString(R.string.set_standard_confirmation_required))
                }
                if (
                    edited.mode == "private" &&
                    edited.torProxy == null &&
                    (
                        edited.providerDirectory != null ||
                            edited.rendezvous.any { it.privateViaTor } ||
                            edited.wake.any { it.privateViaTor }
                    )
                ) {
                    throw SettingsException(getString(R.string.set_private_tor_required))
                }
                val nativeWakeRuntimeChanged =
                    edited.mode != loaded.mode ||
                        edited.providerDirectory != loaded.providerDirectory ||
                        edited.providerDirectoryRoots != loaded.providerDirectoryRoots ||
                        edited.wake != loaded.wake ||
                        edited.torProxy != loaded.torProxy
                edited.save(dataDir)
                val wakePreference = when (nativeWake.checkedRadioButtonId) {
                    R.id.set_native_wake_background -> NativeWakePreference.BACKGROUND_ONLY
                    R.id.set_native_wake_visible -> NativeWakePreference.GENERIC_VISIBLE
                    else -> NativeWakePreference.DISABLED
                }
                NativeWakePreferences(this).save(
                    if (wakeSupported) wakePreference else NativeWakePreference.DISABLED,
                )
                if (
                    wakePreference == NativeWakePreference.GENERIC_VISIBLE &&
                    Build.VERSION.SDK_INT >= 33 &&
                    checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                    PackageManager.PERMISSION_GRANTED
                ) {
                    requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
                if (nativeWakeRuntimeChanged) {
                    NativeWakeManager.onNetworkSettingsChanged(this)
                } else {
                    NativeWakeManager.onPermissionChanged(this)
                }
                toast(getString(R.string.settings_saved))
                finish()
            } catch (e: Exception) {
                toast(getString(R.string.error_settings))
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun lines(field: EditText): List<String> =
        field.text.toString().lines().map { it.trim() }.filter { it.isNotEmpty() }

    private fun blankToNull(field: EditText): String? =
        field.text.toString().trim().ifEmpty { null }

    private fun selectedMode(checked: Int): String =
        when (checked) {
            R.id.set_mode_private -> "private"
            R.id.set_mode_sovereign -> "sovereign"
            else -> "standard"
        }

    private fun updateModeDisclosure(
        checked: Int,
        disclosure: TextView,
        standardConfirmation: Switch,
        sovereignDirectRoutes: Switch,
    ) {
        disclosure.setText(
            when (checked) {
                R.id.set_mode_private -> R.string.set_mode_private_disclosure
                R.id.set_mode_sovereign -> R.string.set_mode_sovereign_disclosure
                else -> R.string.set_mode_standard_disclosure
            },
        )
        standardConfirmation.visibility =
            if (checked == R.id.set_mode_standard) View.VISIBLE else View.GONE
        sovereignDirectRoutes.visibility =
            if (checked == R.id.set_mode_sovereign) View.VISIBLE else View.GONE
    }

    private fun rendezvousLines(field: EditText): List<RendezvousSetting> =
        lines(field).mapIndexed { index, line ->
            val parts = line.split(',').map(String::trim)
            if (
                parts.size != 3 ||
                !parts[0].startsWith("https://") ||
                !parts[1].matches(Regex("[0-9a-f]{64}"))
            ) {
                throw SettingsException(
                    getString(R.string.set_rendezvous_invalid, index + 1),
                )
            }
            val access = when (parts[2]) {
                "standard" -> true to false
                "private" -> false to true
                "both" -> true to true
                else -> throw SettingsException(
                    getString(R.string.set_rendezvous_invalid, index + 1),
                )
            }
            RendezvousSetting(
                origin = parts[0],
                staticKey = parts[1],
                standard = access.first,
                privateViaTor = access.second,
            )
        }

    private fun wakeLines(field: EditText): List<WakeSetting> =
        lines(field).mapIndexed { index, line ->
            val parts = line.split(',').map(String::trim)
            if (
                parts.size != 3 ||
                !parts[0].startsWith("https://") ||
                !parts[1].matches(Regex("[0-9a-f]{64}"))
            ) {
                throw SettingsException(getString(R.string.set_wake_invalid, index + 1))
            }
            val access = when (parts[2]) {
                "standard" -> true to false
                "private" -> false to true
                "both" -> true to true
                else -> throw SettingsException(
                    getString(R.string.set_wake_invalid, index + 1),
                )
            }
            WakeSetting(
                origin = parts[0],
                staticKey = parts[1],
                standard = access.first,
                privateViaTor = access.second,
            )
        }

    private fun exportBackup(uri: Uri) {
        val session = NodeHolder.session ?: return
        runNode(
            work = {
                val local = File.createTempFile("backup", ".kkr", cacheDir)
                local.delete()
                val mnemonic = session.exportBackup(local)
                try {
                    contentResolver.openOutputStream(uri)!!.use { output ->
                        local.inputStream().use { it.copyTo(output) }
                    }
                } finally {
                    local.delete()
                }
                mnemonic
            },
        ) { mnemonic ->
            AlertDialog.Builder(this)
                .setTitle(R.string.backup_done_title)
                .setMessage(getString(R.string.backup_done_body, mnemonic))
                .setCancelable(false)
                .setPositiveButton(R.string.backup_done_ack, null)
                .show()
        }
    }
}
