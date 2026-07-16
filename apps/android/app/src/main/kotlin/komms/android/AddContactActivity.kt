package komms.android

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import komms.core.HintSpec

/**
 * Pairing: add a contact from their scanned/pasted prekey-bundle hex (with
 * optional delivery hints), or from their kult address alone via DHT
 * lookup. The same inputs `kult add` takes.
 */
class AddContactActivity : SecureActivity() {
    private val scan =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            result.data?.getStringExtra(ScanActivity.EXTRA_TEXT)?.let {
                findViewById<EditText>(R.id.add_bundle).setText(it)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        setContentView(R.layout.activity_add_contact)
        setSupportActionBar(findViewById(R.id.add_toolbar))
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val name = findViewById<EditText>(R.id.add_name)
        val bundle = findViewById<EditText>(R.id.add_bundle)
        val address = findViewById<EditText>(R.id.add_address)
        val hints = findViewById<EditText>(R.id.add_hints)

        findViewById<Button>(R.id.add_scan).setOnClickListener {
            scan.launch(ScanActivity.intent(this))
        }

        findViewById<Button>(R.id.add_from_bundle).setOnClickListener {
            val session = NodeHolder.session ?: return@setOnClickListener
            val contactName = name.text.toString().trim()
            if (contactName.isEmpty()) return@setOnClickListener toast(getString(R.string.add_need_name))
            runNode(
                work = {
                    session.addContact(
                        contactName,
                        bundle.text.toString(),
                        parseHints(hints.text.toString()),
                    )
                },
            ) {
                toast(getString(R.string.add_done, contactName))
                finish()
            }
        }

        findViewById<Button>(R.id.add_from_address).setOnClickListener {
            val session = NodeHolder.session ?: return@setOnClickListener
            val contactName = name.text.toString().trim()
            if (contactName.isEmpty()) return@setOnClickListener toast(getString(R.string.add_need_name))
            runNode(
                work = {
                    val peer = session.addContactByAddress(contactName, address.text.toString())
                    val extra = parseHints(hints.text.toString())
                    if (extra.isNotEmpty()) session.setHints(peer, extra)
                    peer
                },
            ) {
                toast(getString(R.string.add_done, contactName))
                finish()
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}

/**
 * One hint per line: `multiaddr /ip4/…`, `relay /ip4/…/p2p/…`,
 * `spool /path`, `mesh broadcast` or `mesh 42`. Same kinds (and the same
 * honest rejections) as the desktop hint editor.
 */
fun parseHints(text: String): List<HintSpec> =
    text.lines()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .map { line ->
            val kind = line.substringBefore(' ')
            val value = line.substringAfter(' ', "").trim()
            HintSpec(kind, value)
        }
