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
        title = localizedSource("Linked devices")
        val body = column()
        body.addView(TextView(this).apply {
            text = localizedSource(
                "Each installation has independent authenticated keys. Revocation is permanent and immediately excludes that exact device from new delivery and sync.",
            )
        })
        conflicts = column()
        body.addView(conflicts)
        body.addView(Button(this).apply {
            text = localizedSource("Link another device")
            setOnClickListener { beginSourceLink() }
        })
        body.addView(Button(this).apply {
            text = localizedSource("Link this new device")
            setOnClickListener { beginTargetLink() }
        })
        body.addView(Button(this).apply {
            text = localizedSource("Approve another device’s link")
            setOnClickListener { approveAnotherRequest(link = true) }
        })
        body.addView(Button(this).apply {
            text = localizedSource("Approve another device’s change")
            setOnClickListener { approveAnotherRequest(link = false) }
        })
        body.addView(Button(this).apply {
            text = localizedSource("Continue pending device change")
            setOnClickListener { continueAuthorityChange() }
        })
        body.addView(Button(this).apply {
            text = localizedSource("Import encrypted sync")
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
                        DeviceAuthorityConflictKind.FORK -> getString(
                            R.string.device_authority_fork,
                            conflict.recoveryEpoch.toLong(),
                        )
                        DeviceAuthorityConflictKind.RECOVERY -> getString(
                            R.string.device_authority_recovery_conflict,
                            conflict.recoveryEpoch.toLong(),
                        )
                    }
                    contentDescription = text
                    setTextColor(getColor(R.color.danger))
                    setTextIsSelectable(true)
                })
            }
            for (conflict in contactAuthorityConflicts) {
                conflicts.addView(TextView(this).apply {
                    text = when (conflict.kind) {
                        DeviceAuthorityConflictKind.FORK -> getString(
                            R.string.device_authority_contact_fork,
                            conflict.account,
                            conflict.recoveryEpoch.toLong(),
                        )
                        DeviceAuthorityConflictKind.RECOVERY -> getString(
                            R.string.device_authority_contact_recovery_conflict,
                            conflict.account,
                            conflict.recoveryEpoch.toLong(),
                        )
                    }
                    contentDescription = text
                    setTextColor(getColor(R.color.danger))
                    setTextIsSelectable(true)
                })
            }
            rows.removeAllViews()
            for (device in devices) {
                val row = column()
                val deviceKind = getString(
                    if (device.current) {
                        R.string.device_row_current
                    } else {
                        R.string.device_row_linked
                    },
                )
                val revokedSuffix = if (device.revokedAt != null) {
                    getString(R.string.device_row_revoked_suffix)
                } else {
                    ""
                }
                row.contentDescription = getString(
                    R.string.device_row_accessibility,
                    device.name,
                    deviceKind,
                    revokedSuffix,
                )
                row.addView(TextView(this).apply {
                    text = buildString {
                        append(device.name)
                        if (device.current) {
                            append(" · ")
                            append(localizedSource("This device"))
                        }
                        if (device.revokedAt != null) {
                            append(" · ")
                            append(localizedSource("Revoked"))
                        }
                        append("\n")
                        append(device.id)
                    }
                    setTextIsSelectable(true)
                })
                if (device.revokedAt == null) {
                    row.addView(Button(this).apply {
                        text = getString(R.string.device_rename_action, device.name)
                        setOnClickListener { rename(device.id, device.name) }
                    })
                    if (!device.current) {
                        row.addView(Button(this).apply {
                            text = getString(R.string.device_export_sync_action, device.name)
                            setOnClickListener {
                                runNode(work = { session.exportDeviceSync(device.id) }) {
                                    showOpaque(
                                        localizedSource("Encrypted device sync bundle"),
                                        it,
                                    )
                                }
                            }
                        })
                        row.addView(Button(this).apply {
                            text = getString(R.string.device_revoke_action, device.name)
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
            .setTitle(localizedSource("Rename linked device"))
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Rename")) { _, _ ->
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
            .setTitle(getString(R.string.device_revoke_confirmation, name))
            .setMessage(
                localizedSource(
                    "This cannot be undone. The exact device loses new delivery and sync access.",
                ),
            )
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Revoke permanently")) { _, _ ->
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
                text = localizedSource(
                    "Scan this ten-minute offer on a pristine installation. Nothing transfers before both screens show the same six digits.",
                )
            })
            val frames = deviceLinkQrFrames(offer)
            val image = ImageView(this).apply {
                contentDescription = getString(R.string.device_link_offer_accessibility)
                adjustViewBounds = true
            }
            val frameLabel = TextView(this)
            body.addView(image)
            body.addView(frameLabel)
            body.addView(input(offer, true))
            val response = input("", true)
            response.hint = localizedSource("Response from new device")
            body.addView(response)
            var frame = 0
            fun renderFrame() {
                image.setImageBitmap(qrBitmap(frames[frame]))
                frameLabel.text = if (frames.size == 1) {
                    getString(R.string.device_link_offer_caption)
                } else {
                    getString(
                        R.string.device_link_frame_caption,
                        frame + 1,
                        frames.size,
                    )
                }
                image.contentDescription = if (frames.size == 1) {
                    getString(R.string.device_link_offer_accessibility)
                } else {
                    getString(
                        R.string.device_link_frame_accessibility,
                        frame + 1,
                        frames.size,
                    )
                }
            }
            renderFrame()
            val dialog = AlertDialog.Builder(this)
                .setTitle(localizedSource("Link another device"))
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(localizedSource("Show comparison code")) { _, _ ->
                    compareAndApprove(response.text.toString())
                }
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
                contentDescription = getString(
                    R.string.comparison_code_accessibility,
                    code,
                )
            })
            val contacts = CheckBox(this).apply {
                text = localizedSource("Contacts and verification")
                isChecked = true
            }
            val organization = CheckBox(this).apply {
                text = localizedSource("Folders, labels, pins, icons, and appearance")
                isChecked = true
            }
            val history = CheckBox(this).apply {
                text = localizedSource("Non-ephemeral history")
            }
            val confirmed = CheckBox(this).apply {
                text = localizedSource("I compared the six digits")
            }
            body.addView(contacts)
            body.addView(organization)
            body.addView(history)
            body.addView(confirmed)
            val dialog = AlertDialog.Builder(this)
                .setTitle(localizedSource("Compare on both devices"))
                .setView(body)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(localizedSource("Approve and create package"), null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    if (!confirmed.isChecked) {
                        toast(getString(R.string.device_compare_required))
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
                    ) {
                        showOpaque(
                            localizedSource("Encrypted package for new device"),
                            it,
                        )
                    }
                }
            }
            dialog.show()
        }
    }

    private fun beginTargetLink() {
        val session = NodeHolder.session ?: return
        val name = input(getString(R.string.device_default_android_name), false)
        val offer = input("", true).apply { hint = localizedSource("Source offer") }
        val body = column()
        body.addView(name)
        body.addView(offer)
        body.addView(Button(this).apply {
            text = localizedSource("Scan offer QR")
            setOnClickListener { scanTarget = offer; scanner.launch(ScanActivity.intent(this@DeviceActivity)) }
        })
        AlertDialog.Builder(this)
            .setTitle(localizedSource("Link this new device"))
            .setMessage(
                localizedSource(
                    "Use only on a pristine installation. Scan or paste the source offer.",
                ),
            )
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Accept offer")) { _, _ ->
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
        val packageField = input("", true).apply {
            hint = localizedSource("Encrypted package for new device")
        }
        val confirmed = CheckBox(this).apply {
            text = localizedSource("I compared the six digits")
        }
        val body = column()
        body.addView(TextView(this).apply { text = code; textSize = 32f })
        body.addView(input(responseHex, true))
        body.addView(packageField)
        body.addView(confirmed)
        val dialog = AlertDialog.Builder(this)
            .setTitle(localizedSource("Compare on both devices"))
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Complete device link"), null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (!confirmed.isChecked) {
                    toast(getString(R.string.device_compare_required))
                    return@setOnClickListener
                }
                runNode(work = { session.completeDeviceLink(packageField.text.toString(), true) }) {
                    dialog.dismiss()
                    toast(getString(R.string.device_linked_success))
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
                hint = localizedSource("Detached approval from another active device")
            }
            val body = column()
            body.addView(TextView(this).apply {
                text = localizedSource(
                    "Transfer this exact add-device proposal to another active installation. Its detached signature cannot alter the proposal.",
                )
            })
            body.addView(input(request, true))
            body.addView(Button(this).apply {
                text = localizedSource("Copy approval request")
                setOnClickListener {
                    copyText(localizedSource("Approval request"), request)
                }
            })
            body.addView(approval)
            val dialog = AlertDialog.Builder(this)
                .setTitle(localizedSource("Additional active-device approval"))
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(localizedSource("Accept detached approval"), null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    runNode(work = {
                        session.acceptDeviceLinkApproval(approval.text.toString())
                    }) { packageHex ->
                        if (packageHex == null) {
                            toast(getString(R.string.device_approval_more_required))
                        } else {
                            dialog.dismiss()
                            showOpaque(
                                localizedSource("Encrypted package for new device"),
                                packageHex,
                            )
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
                hint = localizedSource("Detached approval from another active device")
            }
            val body = column()
            body.addView(TextView(this).apply {
                text = localizedSource(
                    "Transfer this exact pending rename or revocation proposal to another active device, then paste its detached approval.",
                )
            })
            body.addView(input(request, true))
            body.addView(Button(this).apply {
                text = localizedSource("Copy approval request")
                setOnClickListener {
                    copyText(localizedSource("Approval request"), request)
                }
            })
            body.addView(approval)
            val dialog = AlertDialog.Builder(this)
                .setTitle(localizedSource("Continue device change"))
                .setView(ScrollView(this).apply { addView(body) })
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(localizedSource("Accept detached approval"), null)
                .create()
            dialog.setOnShowListener {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    runNode(work = {
                        session.acceptDeviceAuthorityApproval(approval.text.toString())
                    }) { committed ->
                        if (committed) {
                            dialog.dismiss()
                            toast(getString(R.string.device_authority_committed))
                            refresh()
                        } else {
                            toast(getString(R.string.device_approval_more_required))
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
            hint = localizedSource("Approval request")
        }
        val body = column()
        body.addView(TextView(this).apply {
            text = if (link) {
                getString(R.string.device_approval_link_body)
            } else {
                getString(R.string.device_approval_change_body)
            }
        })
        body.addView(request)
        AlertDialog.Builder(this)
            .setTitle(
                if (link) {
                    getString(R.string.device_approval_link_title)
                } else {
                    getString(R.string.device_approval_change_title)
                },
            )
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Verify and approve")) { _, _ ->
                runNode(work = {
                    if (link) {
                        session.approveDeviceLinkRequest(request.text.toString())
                    } else {
                        session.approveDeviceAuthorityRequest(request.text.toString())
                    }
                }) { detached ->
                    showOpaque(localizedSource("Detached approval"), detached)
                }
            }
            .show()
    }

    private fun importSync() {
        val session = NodeHolder.session ?: return
        val field = input("", true).apply {
            hint = localizedSource("Encrypted device sync bundle")
        }
        AlertDialog.Builder(this)
            .setTitle(localizedSource("Import device sync"))
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Import encrypted sync")) { _, _ ->
                runNode(work = { session.importDeviceSync(field.text.toString()) }) { inserted ->
                    toast(
                        resources.getQuantityString(
                            R.plurals.device_imported_sync_events,
                            inserted.toInt(),
                            inserted.toLong(),
                        ),
                    )
                    refresh()
                }
            }
            .show()
    }

    private fun showOpaque(title: String, value: String) {
        val field = input(value, true)
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(
                localizedSource(
                    "Transfer only to the intended linked installation.",
                ),
            )
            .setView(field)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(localizedSource("Copy")) { _, _ ->
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
