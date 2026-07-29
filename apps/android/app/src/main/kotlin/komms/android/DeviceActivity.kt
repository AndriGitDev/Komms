package komms.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import komms.core.deviceLinkQrFrames
import komms.core.hexEncode
import uniffi.kult_ffi.DeviceAuthorityConflictKind
import uniffi.kult_ffi.Event

/** Native C2 linked-device manager and explicit proximate link ceremony. */
class DeviceActivity : SecureActivity() {
    private lateinit var rows: LinearLayout
    private lateinit var conflicts: LinearLayout
    private var scanTarget: IncognitoEditText? = null
    private val scanner = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            scanTarget?.setText(result.data?.getStringExtra(ScanActivity.EXTRA_TEXT).orEmpty())
        }
        scanTarget = null
    }
    private val nodeListener: (Event) -> Unit = { event ->
        if (
            event is Event.DevicesChanged ||
            event is Event.DeviceLinkCompleted ||
            event is Event.DeviceAuthorityFork ||
            event is Event.DeviceRecoveryConflict
        ) {
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
        conflicts = column()
        body.addView(conflicts)
        body.addView(Button(this).apply {
            text = "Link another device"
            setOnClickListener { beginSourceLink() }
        })
        body.addView(Button(this).apply {
            text = "Link this new device"
            setOnClickListener { beginTargetLink() }
        })
        body.addView(Button(this).apply {
            text = "Approve another device’s link"
            setOnClickListener { approveAnotherRequest(link = true) }
        })
        body.addView(Button(this).apply {
            text = "Approve another device’s rename or revocation"
            setOnClickListener { approveAnotherRequest(link = false) }
        })
        body.addView(Button(this).apply {
            text = "Continue pending device change"
            setOnClickListener { continueAuthorityChange() }
        })
        body.addView(Button(this).apply {
            text = "Import encrypted device sync"
            setOnClickListener { importSync() }
        })
        rows = column()
        body.addView(rows)
        setContentView(ScrollView(this).apply { addView(body) })
        applyEdgeToEdgeInsets()
        NodeHolder.addListener(nodeListener)
        refresh()
    }

    override fun onDestroy() {
        NodeHolder.removeListener(nodeListener)
        super.onDestroy()
    }

    private fun refresh() {
        val session = NodeHolder.session ?: return finish()
        runNode(work = {
            Triple(
                session.linkedDevices(),
                session.deviceAuthorityConflicts(),
                session.contactAuthorityConflicts(),
            )
        }) { (devices, authorityConflicts, contactAuthorityConflicts) ->
            conflicts.removeAllViews()
            for (conflict in authorityConflicts) {
                conflicts.addView(TextView(this).apply {
                    text = when (conflict.kind) {
                        DeviceAuthorityConflictKind.FORK ->
                            "Security conflict: concurrent device-authority branches were detected in recovery epoch ${conflict.recoveryEpoch}. Authority is fail-closed and requires offline recovery."
                        DeviceAuthorityConflictKind.RECOVERY ->
                            "Security conflict: different recoveries claim epoch ${conflict.recoveryEpoch}. Authority is fail-closed; re-verify contacts after resolving with offline recovery."
                    }
                    contentDescription = text
                    setTextColor(getColor(R.color.danger))
                    setTextIsSelectable(true)
                })
            }
            for (conflict in contactAuthorityConflicts) {
                conflicts.addView(TextView(this).apply {
                    text = when (conflict.kind) {
                        DeviceAuthorityConflictKind.FORK ->
                            "Contact security conflict for ${conflict.account}: concurrent device-authority branches were detected in recovery epoch ${conflict.recoveryEpoch}. The accepted branch was retained; offline recovery is required."
                        DeviceAuthorityConflictKind.RECOVERY ->
                            "Contact security conflict for ${conflict.account}: different recoveries claim epoch ${conflict.recoveryEpoch}. The accepted branch was retained and verification was cleared."
                    }
                    contentDescription = text
                    setTextColor(getColor(R.color.danger))
                    setTextIsSelectable(true)
                })
            }
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
                    runNode(
                        work = { session.renameLinkedDevice(device, field.text.toString()) },
                        onError = ::authorityChangeError,
                    ) { refresh() }
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
                    runNode(
                        work = { session.revokeLinkedDevice(device, confirmed = true) },
                        onError = ::authorityChangeError,
                    ) { refresh() }
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
            val frames = deviceLinkQrFrames(offer)
            val image = ImageView(this).apply {
                contentDescription = "Device link offer QR"
                adjustViewBounds = true
            }
            val frameLabel = TextView(this)
            body.addView(image)
            body.addView(frameLabel)
            body.addView(input(offer, true))
            val response = input("", true)
            response.hint = "Response from new device"
            body.addView(response)
            var frame = 0
            fun renderFrame() {
                image.setImageBitmap(qrBitmap(frames[frame]))
                frameLabel.text = if (frames.size == 1) {
                    "Device link offer"
                } else {
                    "Device link frame ${frame + 1} of ${frames.size} · keep the scanner pointed here"
                }
            }
            renderFrame()
            val dialog = AlertDialog.Builder(this)
                .setTitle("Link another device")
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Compare code") { _, _ -> compareAndApprove(response.text.toString()) }
                .create()
            val handler = Handler(Looper.getMainLooper())
            val rotate = object : Runnable {
                override fun run() {
                    if (!dialog.isShowing) return
                    frame = (frame + 1) % frames.size
                    renderFrame()
                    handler.postDelayed(this, 1_100)
                }
            }
            dialog.setOnShowListener {
                if (frames.size > 1) handler.postDelayed(rotate, 1_100)
            }
            dialog.setOnDismissListener { handler.removeCallbacks(rotate) }
            dialog.show()
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
                    runNode(
                        work = {
                            session.approveDeviceLink(
                                responseHex,
                                contacts.isChecked,
                                organization.isChecked,
                                history.isChecked,
                                confirmed = true,
                            )
                        },
                        onError = { error ->
                            if (error.contains("additional active-device approval")) {
                                continueDeviceLink()
                            } else {
                                toast(error)
                            }
                        },
                    ) { showOpaque("Encrypted link package", it) }
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

    private fun authorityChangeError(error: String) {
        if (error.contains("additional active-device approval")) {
            continueAuthorityChange()
        } else {
            toast(error)
        }
    }

    private fun continueDeviceLink() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.deviceLinkApprovalRequest() }) { request ->
            val approval = input("", true).apply {
                hint = "Detached approval from another active device"
            }
            val body = column()
            body.addView(TextView(this).apply {
                text = "This exact add-device proposal needs another active device’s signature. Transfer the request to that device, then paste its detached approval here."
            })
            body.addView(input(request, true))
            body.addView(Button(this).apply {
                text = "Copy approval request"
                setOnClickListener { copyText("Device link approval request", request) }
            })
            body.addView(approval)
            val dialog = AlertDialog.Builder(this)
                .setTitle("Additional device approval required")
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Accept approval", null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    runNode(work = {
                        session.acceptDeviceLinkApproval(approval.text.toString())
                    }) { packageHex ->
                        if (packageHex == null) {
                            toast("Approval accepted; another active device is still required")
                        } else {
                            dialog.dismiss()
                            showOpaque("Encrypted link package", packageHex)
                        }
                    }
                }
            }
            dialog.show()
        }
    }

    private fun continueAuthorityChange() {
        val session = NodeHolder.session ?: return
        runNode(work = { session.deviceAuthorityApprovalRequest() }) { request ->
            val approval = input("", true).apply {
                hint = "Detached approval from another active device"
            }
            val body = column()
            body.addView(TextView(this).apply {
                text = "Transfer this exact pending rename or revocation proposal to another active device, then paste its detached approval."
            })
            body.addView(input(request, true))
            body.addView(Button(this).apply {
                text = "Copy approval request"
                setOnClickListener { copyText("Device authority approval request", request) }
            })
            body.addView(approval)
            val dialog = AlertDialog.Builder(this)
                .setTitle("Continue pending device change")
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Accept approval", null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    runNode(work = {
                        session.acceptDeviceAuthorityApproval(approval.text.toString())
                    }) { committed ->
                        if (committed) {
                            dialog.dismiss()
                            toast("Device authority change committed")
                            refresh()
                        } else {
                            toast("Approval accepted; another active device is still required")
                        }
                    }
                }
            }
            dialog.show()
        }
    }

    private fun approveAnotherRequest(link: Boolean) {
        val session = NodeHolder.session ?: return
        val request = input("", true).apply {
            hint = if (link) {
                "Add-device approval request"
            } else {
                "Rename or revocation approval request"
            }
        }
        val body = column()
        body.addView(TextView(this).apply {
            text = if (link) {
                "Verify and sign an exact pending add-device proposal from another active installation."
            } else {
                "Verify and sign an exact pending rename or revocation proposal from another active installation."
            }
        })
        body.addView(request)
        AlertDialog.Builder(this)
            .setTitle(
                if (link) {
                    "Approve another device’s link"
                } else {
                    "Approve another device’s change"
                },
            )
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Verify and approve") { _, _ ->
                runNode(work = {
                    if (link) {
                        session.approveDeviceLinkRequest(request.text.toString())
                    } else {
                        session.approveDeviceAuthorityRequest(request.text.toString())
                    }
                }) { detached ->
                    showOpaque("Detached device approval", detached)
                }
            }
            .show()
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
                copyText(title, value)
            }
            .show()
    }

    private fun copyText(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
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
