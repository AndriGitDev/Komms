package komms.android

import android.os.Bundle
import android.widget.EditText
import android.widget.Switch
import androidx.appcompat.app.AppCompatActivity
import komms.core.NetworkSettings
import komms.core.SettingsException

/**
 * Network settings — the same knobs as `kultd`'s flags and the desktop
 * app's settings screen, persisted as secret-free `settings.json` in the
 * data directory. Applied when the node next starts (the unlock after a
 * lock), exactly like desktop.
 */
class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        setSupportActionBar(findViewById(R.id.settings_toolbar))
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val dataDir = KommsApp.dataDir(application)
        val loaded = try {
            NetworkSettings.load(dataDir)
        } catch (e: SettingsException) {
            // Surface the corruption; edit from defaults without silently
            // overwriting until the user saves.
            toast(e.message ?: getString(R.string.settings_corrupt))
            NetworkSettings()
        }

        val listen = findViewById<EditText>(R.id.set_listen)
        val bootstrap = findViewById<EditText>(R.id.set_bootstrap)
        val relay = findViewById<EditText>(R.id.set_relay)
        val mailboxes = findViewById<EditText>(R.id.set_mailboxes)
        val spool = findViewById<EditText>(R.id.set_spool)
        val meshTcp = findViewById<EditText>(R.id.set_mesh_tcp)
        val serveMailbox = findViewById<Switch>(R.id.set_serve_mailbox)
        val mdns = findViewById<Switch>(R.id.set_mdns)
        val bridge = findViewById<Switch>(R.id.set_bridge)

        listen.setText(loaded.listen.joinToString("\n"))
        bootstrap.setText(loaded.bootstrap.joinToString("\n"))
        relay.setText(loaded.relay ?: "")
        mailboxes.setText(loaded.mailboxes.joinToString("\n"))
        spool.setText(loaded.spool ?: "")
        meshTcp.setText(loaded.meshtasticTcp ?: "")
        serveMailbox.isChecked = loaded.serveMailbox
        mdns.isChecked = loaded.mdns
        bridge.isChecked = loaded.bridge

        findViewById<android.widget.Button>(R.id.settings_save).setOnClickListener {
            val edited = loaded.copy(
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
            edited.save(dataDir)
            toast(getString(R.string.settings_saved))
            finish()
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
}
