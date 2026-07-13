package komms.android

import android.os.Bundle
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import komms.core.safetyQrText

/**
 * Safety-number verification: both parties see the identical 60 digits and
 * the identical QR (also identical to the desktop app's). Compare
 * out-of-band — read the digits aloud, or scan each other's code — then
 * mark verified. A mismatch is shown in red and nothing is stored.
 */
class VerifyActivity : AppCompatActivity() {
    private lateinit var peer: String
    private var expectedQr: String? = null

    private val scan =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val scanned = result.data?.getStringExtra(ScanActivity.EXTRA_TEXT) ?: return@registerForActivityResult
            val expected = expectedQr ?: return@registerForActivityResult
            val verdict = findViewById<TextView>(R.id.verify_verdict)
            if (scanned.trim().equals(expected, ignoreCase = true)) {
                verdict.setText(R.string.verify_match)
                verdict.setTextColor(getColor(R.color.ok))
                findViewById<Button>(R.id.verify_mark).isEnabled = true
            } else {
                verdict.setText(R.string.verify_mismatch)
                verdict.setTextColor(getColor(R.color.danger))
                findViewById<Button>(R.id.verify_mark).isEnabled = false
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (NodeHolder.session == null) return finish()
        peer = intent.getStringExtra("peer") ?: return finish()
        val name = intent.getStringExtra("name") ?: peer.take(12)
        setContentView(R.layout.activity_verify)
        setSupportActionBar(findViewById(R.id.verify_toolbar))
        supportActionBar?.title = getString(R.string.verify_title, name)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val session = NodeHolder.session ?: return finish()
        runNode(work = { session.safetyNumber(peer) }) { sn ->
            expectedQr = safetyQrText(sn)
            findViewById<TextView>(R.id.verify_digits).text = sn.display
            findViewById<ImageView>(R.id.verify_qr).setImageBitmap(qrBitmap(safetyQrText(sn)))
        }

        findViewById<Button>(R.id.verify_scan).setOnClickListener {
            scan.launch(ScanActivity.intent(this))
        }

        // Digits compared aloud are as good as a scan: the button is live
        // from the start; scanning merely gates it on an actual match.
        findViewById<Button>(R.id.verify_mark).setOnClickListener {
            runNode(work = { session.markVerified(peer) }) {
                toast(getString(R.string.verify_done))
                finish()
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
