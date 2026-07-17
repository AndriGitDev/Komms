package komms.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import komms.core.deviceLinkQrText
import komms.core.hexEncode
import uniffi.kult_ffi.Event

/** Native C2 linked-device manager and explicit proximate link ceremony. */
class DeviceActivity : SecureActivity() {
    private lateinit var rows: LinearLayout
    private var scanTarget: IncognitoEditText? = null
    private val scanner = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            scanTarget?.setText(result.data?.getStringExtra(ScanActivity.EXTRA_TEXT).orEmpty())
        }
        scanTarget = null
    }
    private val nodeListener: (Event) -> Unit = { event ->
        if (event is Event.DevicesChanged || event is Event.DeviceLinkCompleted) {
            runOnUiThread { refresh() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Linked devices"
        val body = column()
        body.addView(TextView(this).apply {
            text = "Every installation has independent authenticated keys. Revocation is permanent."
        })
        body.addView(Button(this).apply {
            text = "Link another device"
            setOnClickListener { beginSourceLink() }
        })
        body.addView(Button(this).apply {
            text = "Link this new device"
            setOnClickListener { beginTargetLink() }
        })
        body.addView(Button(this).apply {
            text = "Import encrypted device sync"
            setOnClickListener { importSync() }
        })
        rows = column()
        body.addView(rows)
        setContentView(ScrollView(this).apply { addView(body) })
        NodeHolder.addListener(nodeListener)
        refresh()
    }

    override fun onDestroy() {
        NodeHolder.removeListener(nodeListener)
        super.onDestroy()
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return finish()
        runNode(work = { session.linkedDevices() }) { devices ->
            rows.removeAllViews()
            for (device in devices) {
                val row = column()
                row.contentDescription = buildString {
                    append(device.name)
                    append(if (device.current) ", this device" else ", linked device")
                    if (device.revokedAt != null) append(", permanently revoked")
                }
                row.addView(TextView(this).apply {
                    text = buildString {
                        append(device.name)
                        if (device.current) append(" · this device")
                        if (device.revokedAt != null) append(" · revoked")
                        append("\n")
                        append(device.id)
                    }
                    setTextIsSelectable(true)
                })
                if (device.revokedAt == null) {
                    row.addView(Button(this).apply {
                        text = "Rename ${device.name}"
                        setOnClickListener { rename(device.id, device.name) }
                    })
                    if (!device.current) {
                        row.addView(Button(this).apply {
                            text = "Export sync for ${device.name}"
                            setOnClickListener {
                                runNode(work = { session.exportDeviceSync(device.id) }) { showOpaque("Encrypted device sync", it) }
                            }
                        })
                        row.addView(Button(this).apply {
                            text = "Permanently revoke ${device.name}"
                            setOnClickListener { confirmRevoke(device.id, device.name) }
                        })
                    }
                }
                rows.addView(row)
            }
        }
    }

    private fun rename(device: String, prior: String) {
        val field = input(prior, false)
        AlertDialog.Builder(this)
            .setTitle("Rename linked device")
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Rename") { _, _ ->
                NodeHolder.session?.let { session ->
                    runNode(work = { session.renameLinkedDevice(device, field.text.toString()) }) { refresh() }
                }
            }
            .show()
    }

    private fun confirmRevoke(device: String, name: String) {
        AlertDialog.Builder(this)
            .setTitle("Permanently revoke $name?")
            .setMessage("This cannot be undone. The exact device immediately loses new delivery and sync access.")
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Revoke permanently") { _, _ ->
                NodeHolder.session?.let { session ->
                    runNode(work = { session.revokeLinkedDevice(device, confirmed = true) }) { refresh() }
                }
            }
            .show()
    }

    private fun beginSourceLink() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.beginDeviceLink() }) { offer ->
            val body = column()
            body.addView(TextView(this).apply {
                text = "Scan this ten-minute offer on a pristine installation. Nothing transfers before code comparison."
            })
            body.addView(ImageView(this).apply {
                setImageBitmap(qrBitmap(deviceLinkQrText(offer)))
                contentDescription = "Device link offer QR"
                adjustViewBounds = true
            })
            body.addView(input(offer, true))
            val response = input("", true)
            response.hint = "Response from new device"
            body.addView(response)
            AlertDialog.Builder(this)
                .setTitle("Link another device")
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Compare code") { _, _ -> compareAndApprove(response.text.toString()) }
                .show()
        }
    }

    private fun compareAndApprove(responseHex: String) {
        val session = NodeHolder.session ?: return
        runNode(work = { session.deviceLinkConfirmationCode(responseHex) }) { code ->
            val body = column()
            body.addView(TextView(this).apply {
                text = code
                textSize = 32f
                contentDescription = "Comparison code $code"
            })
            val contacts = CheckBox(this).apply { text = "Contacts and verification"; isChecked = true }
            val organization = CheckBox(this).apply { text = "Folders, labels, pins, icons, and appearance"; isChecked = true }
            val history = CheckBox(this).apply { text = "Non-ephemeral history" }
            val confirmed = CheckBox(this).apply { text = "I compared these six digits on both devices" }
            body.addView(contacts)
            body.addView(organization)
            body.addView(history)
            body.addView(confirmed)
            val dialog = AlertDialog.Builder(this)
                .setTitle("Compare both devices")
                .setView(body)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Approve", null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    if (!confirmed.isChecked) {
                        toast("Compare and confirm the six digits first")
                        return@setOnClickListener
                    }
                    dialog.dismiss()
                    runNode(work = {
                        session.approveDeviceLink(
                            responseHex,
                            contacts.isChecked,
                            organization.isChecked,
                            history.isChecked,
                            confirmed = true,
                        )
                    }) { showOpaque("Encrypted link package", it) }
                }
            }
            dialog.show()
        }
    }

    private fun beginTargetLink() {
        val session = NodeHolder.session ?: return
        val name = input("Android device", false)
        val offer = input("", true).apply { hint = "Scanned or pasted source offer" }
        val body = column()
        body.addView(name)
        body.addView(offer)
        body.addView(Button(this).apply {
            text = "Scan offer QR"
            setOnClickListener { scanTarget = offer; scanner.launch(ScanActivity.intent(this@DeviceActivity)) }
        })
        AlertDialog.Builder(this)
            .setTitle("Link this new device")
            .setMessage("Use only on a pristine installation.")
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Accept offer") { _, _ ->
                runNode(work = { session.acceptDeviceLink(offer.text.toString(), name.text.toString()) }) { accepted ->
                    targetConfirmation(
                        hexEncode(accepted.response),
                        accepted.confirmationCode,
                    )
                }
            }
            .show()
    }

    private fun targetConfirmation(responseHex: String, code: String) {
        val session = NodeHolder.session ?: return
        val packageField = input("", true).apply { hint = "Encrypted package from source" }
        val confirmed = CheckBox(this).apply { text = "I compared these six digits on both devices" }
        val body = column()
        body.addView(TextView(this).apply { text = code; textSize = 32f })
        body.addView(input(responseHex, true))
        body.addView(packageField)
        body.addView(confirmed)
        val dialog = AlertDialog.Builder(this)
            .setTitle("Comparison code")
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Complete link", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (!confirmed.isChecked) {
                    toast("Compare and confirm the six digits first")
                    return@setOnClickListener
                }
                runNode(work = { session.completeDeviceLink(packageField.text.toString(), true) }) {
                    dialog.dismiss()
                    toast("Device linked with independent keys")
                    refresh()
                }
            }
        }
        dialog.show()
    }

    private fun importSync() {
        val session = NodeHolder.session ?: return
        val field = input("", true).apply { hint = "Encrypted sync bundle" }
        AlertDialog.Builder(this)
            .setTitle("Import linked-device sync")
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Import") { _, _ ->
                runNode(work = { session.importDeviceSync(field.text.toString()) }) { inserted ->
                    toast("Imported $inserted new sync events")
                    refresh()
                }
            }
            .show()
    }

    private fun showOpaque(title: String, value: String) {
        val field = input(value, true)
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage("Transfer only to the intended linked installation.")
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Copy") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText(title, value))
            }
            .show()
    }

    private fun column() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(24, 16, 24, 16)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )
    }

    private fun input(value: String, technical: Boolean) = IncognitoEditText(this).apply {
        setText(value)
        inputType = if (technical) {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        } else {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        minLines = if (technical) 3 else 1
        setTextIsSelectable(true)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )
    }
}
