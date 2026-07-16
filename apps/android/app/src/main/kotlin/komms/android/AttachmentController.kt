package komms.android

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.core.text.BidiFormatter
import androidx.recyclerview.widget.RecyclerView
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import komms.core.Session
import uniffi.kult_ffi.Attachment
import uniffi.kult_ffi.AttachmentDirection
import uniffi.kult_ffi.AttachmentFileWarning
import uniffi.kult_ffi.AttachmentObject
import uniffi.kult_ffi.AttachmentOpenPolicy
import uniffi.kult_ffi.AttachmentState
import uniffi.kult_ffi.ImageCrop
import uniffi.kult_ffi.ImageEditRecipe
import uniffi.kult_ffi.ImageEditRegion
import uniffi.kult_ffi.ImageEditRegionKind
import uniffi.kult_ffi.ImageInfo

private const val MAX_PRIMARY_BYTES = 512L * 1024L * 1024L
private const val COPY_BUFFER_BYTES = 64 * 1024
private const val PENDING_EXPORT_KEY = "komms.pending_attachment_export"
private const val IMAGE_SOURCE_LIMIT = 32L * 1024L * 1024L

/** Metadata hints from a caller-selected SAF document. */
private data class SelectedDocument(
    val file: File,
    val mediaType: String,
    val displayName: String?,
)

private data class AndroidImageRecipe(
    val crop: ImageCrop? = null,
    val rotation: UByte = 0u,
    val regions: List<ImageEditRegion> = emptyList(),
) {
    fun ffi() = ImageEditRecipe(crop, rotation, regions)
}

private data class PendingImage(
    val original: File,
    var finalAsset: File,
    var info: ImageInfo,
    val orientedWidth: UInt,
    val orientedHeight: UInt,
    var recipe: AndroidImageRecipe,
    val history: MutableList<AndroidImageRecipe>,
    val filename: String,
    var carrierSnapshot: String,
) {
    fun remove() {
        original.delete()
        finalAsset.delete()
    }
}

private sealed interface ConfirmationResult {
    data class Changed(val explanation: String) : ConfirmationResult
    data object Sent : ConfirmationResult
}

private sealed interface PreparedSelection {
    data class Image(val draft: PendingImage) : PreparedSelection
    data class Generic(val document: SelectedDocument, val carrier: String) : PreparedSelection
}

/**
 * Shared pairwise/group attachment UI. SAF owns every external path: input is
 * streamed into a unique app-private cache file, while export is first
 * written by the node to a protected app-private path and then streamed to
 * the destination URI the user selected.
 */
class AttachmentController(
    private val activity: AppCompatActivity,
    private val belongsHere: (Attachment) -> Boolean,
    private val send: (Session, File, String, String?, File?) -> String,
    private val carrierExplanation: (Session) -> String,
    private val bindAudio: (Attachment, LinearLayout) -> Unit,
    private val refresh: () -> Unit,
    savedState: Bundle?,
) {
    private val adapter = AttachmentAdapter(
        ::runAction,
        ::beginOpen,
        ::beginExport,
        ::bindPreview,
        bindAudio,
    )
    private val previewCache = mutableMapOf<String, Bitmap>()
    private val loadingPreviews = mutableSetOf<String>()
    private val openedFiles = mutableListOf<File>()
    private var pendingExport = savedState?.getString(PENDING_EXPORT_KEY)
    private var activeDialog: AlertDialog? = null
    private var activeImage: PendingImage? = null
    private val exportContract = MimeCreateDocument()

    private val openDocument = activity.registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) import(uri)
    }

    private val createDocument = activity.registerForActivityResult(exportContract) { uri ->
        val transfer = pendingExport
        pendingExport = null
        if (uri != null && transfer != null) export(transfer, uri)
    }

    init {
        cleanupPlaintextOrphans()
        activity.findViewById<RecyclerView>(R.id.chat_attachments).adapter = adapter
        activity.findViewById<Button>(R.id.chat_attach).setOnClickListener {
            openDocument.launch(arrayOf("*/*"))
        }
    }

    fun isRelevant(attachment: Attachment): Boolean = belongsHere(attachment)

    fun saveState(outState: Bundle) {
        pendingExport?.let { outState.putString(PENDING_EXPORT_KEY, it) }
    }

    fun submit(attachments: List<Attachment>) {
        val matching = attachments.filter(belongsHere)
        adapter.submit(matching)
        activity.findViewById<View>(R.id.chat_attachment_section).visibility =
            if (matching.isEmpty()) View.GONE else View.VISIBLE
    }

    private fun import(uri: Uri) {
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                val selected = stageDocument(uri)
                val finalAsset = File(
                    activity.cacheDir,
                    "komms-image-final-${UUID.randomUUID()}.png",
                )
                try {
                    val info = session.editImage(
                        selected.file,
                        finalAsset,
                        AndroidImageRecipe().ffi(),
                    )
                    PreparedSelection.Image(
                        PendingImage(
                            original = selected.file,
                            finalAsset = finalAsset,
                            info = info,
                            orientedWidth = info.width,
                            orientedHeight = info.height,
                            recipe = AndroidImageRecipe(),
                            history = mutableListOf(),
                            filename = selected.displayName
                                ?.substringBeforeLast('.', selected.displayName)
                                ?.plus(".png") ?: "edited-image.png",
                            carrierSnapshot = carrierExplanation(session),
                        ),
                    )
                } catch (error: Throwable) {
                    finalAsset.delete()
                    if (selected.isClaimedImage()) {
                        selected.file.delete()
                        throw error
                    }
                    PreparedSelection.Generic(selected, carrierExplanation(session))
                }
            },
        ) { prepared ->
            when (prepared) {
                is PreparedSelection.Image -> showImageEditor(prepared.draft)
                is PreparedSelection.Generic -> showGenericConfirmation(
                    prepared.document,
                    prepared.carrier,
                )
            }
        }
    }

    fun close() {
        activeDialog?.dismiss()
        activeDialog = null
        activeImage?.remove()
        activeImage = null
        previewCache.values.forEach { it.recycle() }
        previewCache.clear()
        openedFiles.forEach(File::delete)
        openedFiles.clear()
    }

    fun onStop() {
        activeDialog?.dismiss()
    }

    private fun SelectedDocument.isClaimedImage(): Boolean {
        val extension = displayName?.substringAfterLast('.', "")?.lowercase()
        return mediaType in setOf("image/jpeg", "image/png") || extension in setOf("jpg", "jpeg", "png")
    }

    private fun cleanupPlaintextOrphans() {
        val prefixes = listOf(
            "attachment-import-",
            "attachment-preview-",
            "attachment-export-",
            "attachment-open-",
            "komms-image-final-",
        )
        activity.cacheDir.listFiles()?.filter { file ->
            prefixes.any(file.name::startsWith)
        }?.forEach(File::delete)
    }

    private fun text(value: String): TextView = TextView(activity).apply {
        this.text = value
        setPadding(12, 8, 12, 8)
    }

    private fun numberField(label: String, value: UInt): EditText = IncognitoEditText(activity).apply {
        hint = label
        contentDescription = label
        inputType = InputType.TYPE_CLASS_NUMBER
        setText(value.toString())
    }

    private fun fieldValue(field: EditText, name: String): UInt =
        field.text.toString().toUIntOrNull()
            ?: throw IllegalArgumentException("$name must be a non-negative whole number")

    private fun centeredCrop(width: UInt, height: UInt, wide: UInt, high: UInt): ImageCrop {
        var cropWidth = width
        var cropHeight = (width.toULong() * high.toULong() / wide.toULong()).toUInt()
        if (cropHeight > height) {
            cropHeight = height
            cropWidth = (height.toULong() * wide.toULong() / high.toULong()).toUInt()
        }
        return ImageCrop(
            (width - cropWidth) / 2u,
            (height - cropHeight) / 2u,
            cropWidth,
            cropHeight,
        )
    }

    private fun showGenericConfirmation(selected: SelectedDocument, carrier: String) {
        var snapshot = carrier
        val carrierText = text(carrier).apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            addView(text("Review ${selected.displayName ?: "attachment"} before explicitly sending it."))
            addView(text("Type: ${selected.mediaType}"))
            addView(carrierText)
        }
        val dialog = AlertDialog.Builder(activity)
            .setTitle("Review attachment")
            .setView(content)
            .setNegativeButton("Discard") { _, _ -> selected.file.delete() }
            .setPositiveButton("Send attachment", null)
            .create()
        activeDialog = dialog
        dialog.setOnDismissListener {
            selected.file.delete()
            if (activeDialog === dialog) activeDialog = null
        }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val session = NodeHolder.session ?: return@setOnClickListener
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
                activity.runNode(
                    work = {
                        val latest = carrierExplanation(session)
                        if (latest != snapshot) {
                            ConfirmationResult.Changed(latest)
                        } else {
                            try {
                                send(
                                    session,
                                    selected.file,
                                    selected.mediaType,
                                    selected.displayName,
                                    null,
                                )
                                ConfirmationResult.Sent
                            } finally {
                                selected.file.delete()
                            }
                        }
                    },
                    onError = { error ->
                        selected.file.delete()
                        dialog.dismiss()
                        activity.toast(error)
                    },
                ) { result ->
                    when (result) {
                        is ConfirmationResult.Changed -> {
                            snapshot = result.explanation
                            carrierText.text = result.explanation
                            activity.toast("Carrier state changed. Review the updated explanation and confirm again.")
                            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = true
                        }
                        ConfirmationResult.Sent -> {
                            dialog.dismiss()
                            activity.toast(activity.getString(R.string.attachment_queued))
                            refresh()
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun showImageEditor(draft: PendingImage) {
        activeImage?.remove()
        activeImage = draft
        val column = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 12, 16, 12)
        }
        column.addView(text("Edits are local. The original is never sent. Review the exact final PNG before sending."))
        val preview = ImageView(activity).apply {
            adjustViewBounds = true
            contentDescription = "Exact final edited image review"
            minimumHeight = 240
        }
        val infoText = text("").apply { accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE }
        column.addView(preview)
        column.addView(infoText)

        val preset = Spinner(activity)
        val presets = listOf("Original", "Free", "Square 1:1", "4:3", "16:9")
        preset.adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, presets)
        preset.contentDescription = "Crop preset"
        column.addView(preset)
        val cropX = numberField("Crop X", 0u)
        val cropY = numberField("Crop Y", 0u)
        val cropWidth = numberField("Crop width", draft.orientedWidth)
        val cropHeight = numberField("Crop height", draft.orientedHeight)
        listOf(cropX, cropY, cropWidth, cropHeight).forEach(column::addView)

        val controls = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
        val applyCrop = Button(activity).apply { text = "Apply crop" }
        val rotateLeft = Button(activity).apply {
            text = "Rotate left"
            contentDescription = "Rotate 90 degrees counter-clockwise"
        }
        val rotateRight = Button(activity).apply {
            text = "Rotate right"
            contentDescription = "Rotate 90 degrees clockwise"
        }
        controls.addView(applyCrop)
        controls.addView(rotateLeft)
        controls.addView(rotateRight)
        column.addView(controls)

        column.addView(text("Add a user-positioned privacy region on the current final canvas."))
        val regionKind = Spinner(activity).apply {
            adapter = ArrayAdapter(
                activity,
                android.R.layout.simple_spinner_dropdown_item,
                listOf("Blur", "Pixelate"),
            )
            contentDescription = "Privacy operation"
        }
        column.addView(regionKind)
        val regionX = numberField("Region X", 0u)
        val regionY = numberField("Region Y", 0u)
        val regionWidth = numberField("Region width", minOf(64u, draft.info.width))
        val regionHeight = numberField("Region height", minOf(64u, draft.info.height))
        val regionStrength = numberField("Region strength", 8u)
        listOf(regionX, regionY, regionWidth, regionHeight, regionStrength).forEach(column::addView)
        val addRegion = Button(activity).apply { text = "Add privacy region" }
        val regionList = text("No privacy regions")
        column.addView(addRegion)
        column.addView(regionList)
        val historyControls = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
        val undo = Button(activity).apply { text = "Undo" }
        val reset = Button(activity).apply { text = "Reset" }
        historyControls.addView(undo)
        historyControls.addView(reset)
        column.addView(historyControls)
        val filename = IncognitoEditText(activity).apply {
            hint = "Display filename"
            setText(draft.filename)
        }
        val carrierText = text(draft.carrierSnapshot).apply {
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        column.addView(filename)
        column.addView(carrierText)
        val scroll = ScrollView(activity).apply { addView(column) }

        var reviewBitmap: Bitmap? = null
        fun render() {
            val replacement = BitmapFactory.decodeFile(draft.finalAsset.absolutePath)
                ?: throw IllegalArgumentException("exact final image could not be displayed")
            val old = reviewBitmap
            reviewBitmap = replacement
            preview.setImageBitmap(replacement)
            old?.recycle()
            infoText.text = "${draft.info.width} × ${draft.info.height} pixels · ${draft.info.encodedBytes} bytes · exact metadata-free PNG"
            regionList.text = if (draft.recipe.regions.isEmpty()) {
                "No privacy regions"
            } else {
                draft.recipe.regions.mapIndexed { index, region ->
                    "${index + 1}. ${region.kind.name.lowercase()} x ${region.x}, y ${region.y}, ${region.width} × ${region.height}, strength ${region.strength}"
                }.joinToString("\n")
            }
        }

        fun renderRecipe(recipe: AndroidImageRecipe, remember: Boolean = true) {
            val session = NodeHolder.session ?: return
            val replacement = File(
                activity.cacheDir,
                "komms-image-final-${UUID.randomUUID()}.png",
            )
            activity.runNode(
                work = {
                    try {
                        val info = session.editImage(draft.original, replacement, recipe.ffi())
                        Pair(info, replacement)
                    } catch (error: Throwable) {
                        replacement.delete()
                        throw error
                    }
                },
                onError = { error ->
                    draft.remove()
                    activeImage = null
                    activeDialog?.dismiss()
                    activity.toast(error)
                },
            ) { (info, file) ->
                if (activeImage !== draft) {
                    file.delete()
                    return@runNode
                }
                if (remember) draft.history.add(draft.recipe)
                draft.finalAsset.delete()
                draft.finalAsset = file
                draft.info = info
                draft.recipe = recipe
                render()
            }
        }

        fun chosenCrop(): ImageCrop? = when (preset.selectedItemPosition) {
            0 -> null
            1 -> ImageCrop(
                fieldValue(cropX, "crop X"),
                fieldValue(cropY, "crop Y"),
                fieldValue(cropWidth, "crop width"),
                fieldValue(cropHeight, "crop height"),
            )
            2 -> centeredCrop(draft.orientedWidth, draft.orientedHeight, 1u, 1u)
            3 -> centeredCrop(draft.orientedWidth, draft.orientedHeight, 4u, 3u)
            else -> centeredCrop(draft.orientedWidth, draft.orientedHeight, 16u, 9u)
        }

        applyCrop.setOnClickListener {
            runCatching { draft.recipe.copy(crop = chosenCrop()) }
                .fold(::renderRecipe) { activity.toast(errorText(it)) }
        }
        rotateLeft.setOnClickListener {
            renderRecipe(
                draft.recipe.copy(
                    rotation = ((draft.recipe.rotation.toInt() + 3) % 4).toUByte(),
                    regions = emptyList(),
                ),
            )
        }
        rotateRight.setOnClickListener {
            renderRecipe(
                draft.recipe.copy(
                    rotation = ((draft.recipe.rotation.toInt() + 1) % 4).toUByte(),
                    regions = emptyList(),
                ),
            )
        }
        addRegion.setOnClickListener {
            runCatching {
                ImageEditRegion(
                    if (regionKind.selectedItemPosition == 0) {
                        ImageEditRegionKind.BLUR
                    } else {
                        ImageEditRegionKind.PIXELATE
                    },
                    fieldValue(regionX, "region X"),
                    fieldValue(regionY, "region Y"),
                    fieldValue(regionWidth, "region width"),
                    fieldValue(regionHeight, "region height"),
                    fieldValue(regionStrength, "region strength"),
                )
            }.fold(
                { region -> renderRecipe(draft.recipe.copy(regions = draft.recipe.regions + region)) },
                { activity.toast(errorText(it)) },
            )
        }
        undo.setOnClickListener {
            draft.history.removeLastOrNull()?.let { renderRecipe(it, remember = false) }
        }
        reset.setOnClickListener {
            preset.setSelection(0)
            renderRecipe(AndroidImageRecipe())
        }

        val dialog = AlertDialog.Builder(activity)
            .setTitle("Edit and review image")
            .setView(scroll)
            .setNegativeButton("Discard", null)
            .setPositiveButton("Send exact final image", null)
            .create()
        activeDialog = dialog
        dialog.setOnDismissListener {
            reviewBitmap?.recycle()
            draft.remove()
            if (activeImage === draft) activeImage = null
            if (activeDialog === dialog) activeDialog = null
        }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener { dialog.dismiss() }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val session = NodeHolder.session ?: return@setOnClickListener
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
                activity.runNode(
                    work = {
                        val latest = carrierExplanation(session)
                        if (latest != draft.carrierSnapshot) {
                            ConfirmationResult.Changed(latest)
                        } else {
                            try {
                                session.probeImage(draft.finalAsset)
                                send(
                                    session,
                                    draft.finalAsset,
                                    "image/png",
                                    filename.text.toString().ifBlank { "edited-image.png" },
                                    null,
                                )
                                ConfirmationResult.Sent
                            } finally {
                                draft.remove()
                            }
                        }
                    },
                    onError = { error ->
                        draft.remove()
                        dialog.dismiss()
                        activity.toast(error)
                    },
                ) { result ->
                    when (result) {
                        is ConfirmationResult.Changed -> {
                            draft.carrierSnapshot = result.explanation
                            carrierText.text = result.explanation
                            activity.toast("Carrier state changed. Review the updated explanation and confirm again.")
                            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = true
                        }
                        ConfirmationResult.Sent -> {
                            dialog.dismiss()
                            activity.toast(activity.getString(R.string.attachment_queued))
                            refresh()
                        }
                    }
                }
            }
        }
        render()
        dialog.show()
    }

    private fun bindPreview(attachment: Attachment, image: ImageView) {
        val sealedPreview = attachment.objects.any {
            it.preview && it.state == AttachmentState.COMPLETE
        }
        val canonicalPrimary = attachment.state == AttachmentState.COMPLETE &&
            attachment.objects.any { !it.preview && it.mediaType == "image/png" }
        val available = sealedPreview || canonicalPrimary
        image.tag = attachment.transferId
        image.visibility = if (available) View.INVISIBLE else View.GONE
        if (!available) return
        previewCache[attachment.transferId]?.let {
            image.setImageBitmap(it)
            image.visibility = View.VISIBLE
            return
        }
        if (!loadingPreviews.add(attachment.transferId)) return
        val session = NodeHolder.session ?: run {
            loadingPreviews.remove(attachment.transferId)
            return
        }
        activity.runNode(
            work = {
                val protected = File(
                    activity.cacheDir,
                    "attachment-preview-${UUID.randomUUID()}.${if (sealedPreview) "jpg" else "png"}",
                )
                try {
                    if (sealedPreview) {
                        session.exportAttachmentPreview(attachment.transferId, protected)
                    } else {
                        session.exportAttachment(attachment.transferId, protected)
                        session.probeImage(protected)
                    }
                    BitmapFactory.decodeFile(protected.absolutePath)
                        ?: throw IllegalArgumentException(activity.getString(R.string.attachment_preview_failed))
                } finally {
                    protected.delete()
                }
            },
            onError = { loadingPreviews.remove(attachment.transferId) },
        ) { bitmap ->
            loadingPreviews.remove(attachment.transferId)
            previewCache[attachment.transferId] = bitmap
            if (image.tag == attachment.transferId) {
                image.setImageBitmap(bitmap)
                image.visibility = View.VISIBLE
            }
        }
    }

    private fun stageDocument(uri: Uri): SelectedDocument {
        val resolver = activity.contentResolver
        val displayName = queryDisplayName(resolver.query(uri, null, null, null, null))
        val mediaType = resolver.getType(uri)?.takeIf { it.isNotBlank() }
            ?: "application/octet-stream"
        val staged = File.createTempFile("attachment-import-", ".stage", activity.cacheDir)
        val selected = SelectedDocument(staged, mediaType, displayName)
        val maxBytes = if (selected.isClaimedImage()) IMAGE_SOURCE_LIMIT else MAX_PRIMARY_BYTES
        try {
            resolver.openInputStream(uri).use { input ->
                requireNotNull(input) { activity.getString(R.string.attachment_open_failed) }
                FileOutputStream(staged).use { output ->
                    val buffer = ByteArray(COPY_BUFFER_BYTES)
                    var copied = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        copied += read
                        require(copied <= maxBytes) {
                            if (maxBytes == IMAGE_SOURCE_LIMIT) {
                                "This image exceeds the 32 MiB editor limit"
                            } else {
                                activity.getString(R.string.attachment_too_large)
                            }
                        }
                        output.write(buffer, 0, read)
                    }
                    output.fd.sync()
                }
            }
            return selected
        } catch (error: Throwable) {
            staged.delete()
            throw error
        }
    }

    private fun queryDisplayName(cursor: Cursor?): String? = cursor?.use {
        val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (column >= 0 && it.moveToFirst()) it.getString(column) else null
    }

    private fun runAction(attachment: Attachment, action: AttachmentAction) {
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                when (action) {
                    AttachmentAction.ACCEPT -> session.acceptAttachment(attachment.transferId)
                    AttachmentAction.REJECT -> session.rejectAttachment(attachment.transferId)
                    AttachmentAction.CANCEL -> session.cancelAttachment(attachment.transferId)
                    AttachmentAction.PAUSE -> session.pauseAttachment(attachment.transferId)
                    AttachmentAction.RESUME -> session.resumeAttachment(attachment.transferId)
                }
            },
        ) { refresh() }
    }

    private fun beginExport(attachment: Attachment) {
        val primary = attachment.objects.firstOrNull { !it.preview } ?: attachment.objects.firstOrNull()
        if (primary == null) {
            activity.toast(activity.getString(R.string.attachment_missing_primary))
            return
        }
        pendingExport = attachment.transferId
        exportContract.mediaType = primary.mediaType.ifBlank { "application/octet-stream" }
        createDocument.launch(primary.filename ?: activity.getString(R.string.attachment_default_name))
    }

    private fun beginOpen(attachment: Attachment) {
        val primary = attachment.objects.firstOrNull { !it.preview } ?: return
        if (attachment.direction != AttachmentDirection.INBOUND ||
            attachment.state != AttachmentState.COMPLETE ||
            primary.presentation.openPolicy != AttachmentOpenPolicy.EXTERNAL_OPEN
        ) {
            activity.toast(activity.getString(R.string.attachment_export_only))
            return
        }
        AlertDialog.Builder(activity)
            .setTitle(R.string.attachment_open_title)
            .setMessage(
                activity.getString(
                    R.string.attachment_open_confirmation,
                    primary.filename ?: activity.getString(R.string.attachment_default_name),
                ),
            )
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.attachment_open) { _, _ -> open(attachment, primary) }
            .show()
    }

    private fun open(attachment: Attachment, primary: AttachmentObject) {
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                val extension = primary.filename
                    ?.substringAfterLast('.', "")
                    ?.takeIf { it.isNotEmpty() && it.length <= 16 && it.all(Char::isLetterOrDigit) }
                    ?: "bin"
                val protected = File(
                    activity.cacheDir,
                    "attachment-open-${UUID.randomUUID()}.$extension",
                )
                session.exportAttachment(attachment.transferId, protected)
                protected
            },
        ) { protected ->
            try {
                val uri = FileProvider.getUriForFile(
                    activity,
                    "${activity.packageName}.files",
                    protected,
                )
                val intent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, primary.mediaType)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                activity.startActivity(Intent.createChooser(intent, activity.getString(R.string.attachment_open_title)))
                openedFiles += protected
            } catch (error: Throwable) {
                protected.delete()
                activity.toast(error.message ?: activity.getString(R.string.attachment_open_failed))
            }
        }
    }

    private fun export(transfer: String, uri: Uri) {
        val session = NodeHolder.session ?: return
        activity.runNode(
            work = {
                val protected = File(
                    activity.cacheDir,
                    "attachment-export-${UUID.randomUUID()}",
                )
                try {
                    session.exportAttachment(transfer, protected)
                    protected.inputStream().use { input ->
                        activity.contentResolver.openOutputStream(uri, "w").use { output ->
                            requireNotNull(output) {
                                activity.getString(R.string.attachment_export_open_failed)
                            }
                            input.copyTo(output, COPY_BUFFER_BYTES)
                            output.flush()
                        }
                    }
                } finally {
                    protected.delete()
                }
            },
        ) {
            activity.toast(activity.getString(R.string.attachment_exported))
        }
    }
}

/** CreateDocument with the authenticated MIME hint selected at launch time. */
private class MimeCreateDocument : ActivityResultContracts.CreateDocument("*/*") {
    var mediaType: String = "application/octet-stream"

    override fun createIntent(context: Context, input: String): Intent =
        super.createIntent(context, input).setType(mediaType)
}

private enum class AttachmentAction { ACCEPT, REJECT, CANCEL, PAUSE, RESUME }

private class AttachmentAdapter(
    private val action: (Attachment, AttachmentAction) -> Unit,
    private val open: (Attachment) -> Unit,
    private val export: (Attachment) -> Unit,
    private val preview: (Attachment, ImageView) -> Unit,
    private val audio: (Attachment, LinearLayout) -> Unit,
) : RecyclerView.Adapter<AttachmentAdapter.Holder>() {
    private var items = listOf<Attachment>()

    class Holder(view: View) : RecyclerView.ViewHolder(view)

    fun submit(attachments: List<Attachment>) {
        items = attachments
        notifyDataSetChanged()
    }

    override fun getItemCount(): Int = items.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder = Holder(
        LayoutInflater.from(parent.context)
            .inflate(R.layout.row_attachment_transfer, parent, false),
    )

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val attachment = items[position]
        val view = holder.itemView
        val context = view.context
        val primary = attachment.objects.firstOrNull { !it.preview } ?: attachment.objects.firstOrNull()
        view.findViewById<TextView>(R.id.attachment_title).text = BidiFormatter.getInstance().unicodeWrap(
            primary?.filename ?: context.getString(R.string.attachment_default_name),
        )
        view.findViewById<TextView>(R.id.attachment_state).text = context.getString(
            R.string.attachment_direction_state,
            context.getString(
                if (attachment.direction == AttachmentDirection.INBOUND) {
                    R.string.attachment_inbound
                } else {
                    R.string.attachment_outbound
                },
            ),
            context.attachmentState(attachment.state),
        )
        preview(attachment, view.findViewById(R.id.attachment_preview_image))
        audio(attachment, view.findViewById(R.id.attachment_audio_container))

        view.findViewById<TextView>(R.id.attachment_safety).text =
            context.getString(R.string.attachment_safety_notice)
        view.findViewById<TextView>(R.id.attachment_warnings).apply {
            val messages = primary?.presentation?.warnings.orEmpty().map { context.attachmentWarning(it) }
            text = messages.joinToString("\n")
            visibility = if (messages.isEmpty()) View.GONE else View.VISIBLE
        }

        val objects = view.findViewById<LinearLayout>(R.id.attachment_objects)
        objects.removeAllViews()
        for (item in attachment.objects) objects.addView(objectRow(objects, item))

        val inbound = attachment.direction == AttachmentDirection.INBOUND
        val awaitingConsent = inbound && attachment.state in setOf(
            AttachmentState.OFFERED,
            AttachmentState.AWAITING_CONSENT,
        )
        val active = attachment.state in setOf(
            AttachmentState.OFFERED,
            AttachmentState.AWAITING_CONSENT,
            AttachmentState.QUEUED,
            AttachmentState.TRANSFERRING,
            AttachmentState.PAUSED,
        )
        bindButton(view, R.id.attachment_accept, awaitingConsent) {
            action(attachment, AttachmentAction.ACCEPT)
        }
        bindButton(view, R.id.attachment_reject, awaitingConsent) {
            action(attachment, AttachmentAction.REJECT)
        }
        bindButton(
            view,
            R.id.attachment_pause,
            !awaitingConsent && attachment.state in setOf(
                AttachmentState.OFFERED,
                AttachmentState.QUEUED,
                AttachmentState.TRANSFERRING,
            ),
        ) { action(attachment, AttachmentAction.PAUSE) }
        bindButton(view, R.id.attachment_resume, attachment.state == AttachmentState.PAUSED) {
            action(attachment, AttachmentAction.RESUME)
        }
        bindButton(view, R.id.attachment_cancel, !awaitingConsent && active) {
            action(attachment, AttachmentAction.CANCEL)
        }
        bindButton(
            view,
            R.id.attachment_open,
            inbound && attachment.state == AttachmentState.COMPLETE &&
                primary?.presentation?.openPolicy == AttachmentOpenPolicy.EXTERNAL_OPEN,
        ) { open(attachment) }
        bindButton(
            view,
            R.id.attachment_export,
            inbound && attachment.state == AttachmentState.COMPLETE,
        ) { export(attachment) }
    }

    private fun objectRow(parent: ViewGroup, item: AttachmentObject): View {
        val row = LayoutInflater.from(parent.context)
            .inflate(R.layout.row_attachment_object, parent, false)
        row.findViewById<TextView>(R.id.attachment_object_kind).text = parent.context.getString(
            R.string.attachment_object_kind,
            parent.context.getString(
                if (item.preview) R.string.attachment_preview else R.string.attachment_primary,
            ),
            item.mediaType,
        )
        row.findViewById<TextView>(R.id.attachment_object_progress).text = parent.context.getString(
            R.string.attachment_progress,
            item.verifiedBytes.toString(),
            item.totalBytes.toString(),
            parent.context.attachmentState(item.state),
        )
        row.findViewById<ProgressBar>(R.id.attachment_progress_bar).apply {
            max = 1000
            progress = if (item.totalBytes == 0uL) 0 else {
                ((item.verifiedBytes.coerceAtMost(item.totalBytes) * 1000uL) / item.totalBytes).toInt()
            }
        }
        return row
    }

    private fun bindButton(view: View, id: Int, visible: Boolean, listener: () -> Unit) {
        view.findViewById<Button>(id).apply {
            visibility = if (visible) View.VISIBLE else View.GONE
            setOnClickListener { listener() }
        }
    }
}

private fun Context.attachmentWarning(warning: AttachmentFileWarning): String = getString(
    when (warning) {
        AttachmentFileWarning.MEDIA_TYPE_MISMATCH -> R.string.attachment_warning_mismatch
        AttachmentFileWarning.DANGEROUS_TYPE -> R.string.attachment_warning_dangerous
        AttachmentFileWarning.UNRECOGNIZED_TYPE -> R.string.attachment_warning_unrecognized
        AttachmentFileWarning.MISSING_FILENAME -> R.string.attachment_warning_missing_name
    },
)

private fun Context.attachmentState(state: AttachmentState): String = getString(
    when (state) {
        AttachmentState.OFFERED -> R.string.attachment_state_offered
        AttachmentState.AWAITING_CONSENT -> R.string.attachment_state_awaiting_consent
        AttachmentState.QUEUED -> R.string.attachment_state_queued
        AttachmentState.TRANSFERRING -> R.string.attachment_state_transferring
        AttachmentState.PAUSED -> R.string.attachment_state_paused
        AttachmentState.COMPLETE -> R.string.attachment_state_complete
        AttachmentState.REJECTED -> R.string.attachment_state_rejected
        AttachmentState.CANCELLED -> R.string.attachment_state_cancelled
        AttachmentState.CORRUPT -> R.string.attachment_state_corrupt
        AttachmentState.UNAVAILABLE -> R.string.attachment_state_unavailable
    },
)
