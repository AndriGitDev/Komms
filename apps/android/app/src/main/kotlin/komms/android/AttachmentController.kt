package komms.android

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.RecyclerView
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import komms.core.Session
import uniffi.kult_ffi.Attachment
import uniffi.kult_ffi.AttachmentDirection
import uniffi.kult_ffi.AttachmentObject
import uniffi.kult_ffi.AttachmentState

private const val MAX_PRIMARY_BYTES = 512L * 1024L * 1024L
private const val COPY_BUFFER_BYTES = 64 * 1024
private const val MAX_PREVIEW_BYTES = 256 * 1024
private const val PREVIEW_EDGE = 512
private const val PENDING_EXPORT_KEY = "komms.pending_attachment_export"

/** Metadata hints from a caller-selected SAF document. */
private data class SelectedDocument(
    val file: File,
    val mediaType: String,
    val displayName: String?,
)

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
    private val refresh: () -> Unit,
    savedState: Bundle?,
) {
    private val adapter = AttachmentAdapter(::runAction, ::beginExport, ::bindPreview)
    private val previewCache = mutableMapOf<String, Bitmap>()
    private val loadingPreviews = mutableSetOf<String>()
    private var pendingExport = savedState?.getString(PENDING_EXPORT_KEY)
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
                var preview: File? = null
                try {
                    preview = generatePreview(selected)
                    send(session, selected.file, selected.mediaType, selected.displayName, preview)
                } finally {
                    preview?.delete()
                    selected.file.delete()
                }
            },
        ) {
            activity.toast(activity.getString(R.string.attachment_queued))
            refresh()
        }
    }

    fun close() {
        previewCache.values.forEach { it.recycle() }
        previewCache.clear()
    }

    private fun generatePreview(selected: SelectedDocument): File? {
        if (selected.mediaType !in setOf("image/jpeg", "image/png")) return null
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(selected.file.absolutePath, bounds)
        require(bounds.outWidth > 0 && bounds.outHeight > 0) {
            activity.getString(R.string.attachment_preview_failed)
        }
        require(bounds.outMimeType == "image/jpeg" || bounds.outMimeType == "image/png") {
            activity.getString(R.string.attachment_preview_failed)
        }
        var sample = 1
        while (bounds.outWidth.toLong() / sample > PREVIEW_EDGE.toLong() * 2 ||
            bounds.outHeight.toLong() / sample > PREVIEW_EDGE.toLong() * 2
        ) sample *= 2
        val decoded = BitmapFactory.decodeFile(
            selected.file.absolutePath,
            BitmapFactory.Options().apply { inSampleSize = sample },
        ) ?: throw IllegalArgumentException(activity.getString(R.string.attachment_preview_failed))
        try {
            for ((edge, quality) in listOf(512 to 82, 448 to 72, 384 to 62, 320 to 52)) {
                val scale = minOf(1f, edge.toFloat() / maxOf(decoded.width, decoded.height))
                val width = maxOf(1, (decoded.width * scale).toInt())
                val height = maxOf(1, (decoded.height * scale).toInt())
                val thumbnail = Bitmap.createScaledBitmap(decoded, width, height, true)
                val bytes = ByteArrayOutputStream().use { output ->
                    require(thumbnail.compress(Bitmap.CompressFormat.JPEG, quality, output))
                    output.toByteArray()
                }
                if (thumbnail !== decoded) thumbnail.recycle()
                if (bytes.size <= MAX_PREVIEW_BYTES) {
                    val file = File.createTempFile("attachment-preview-", ".jpg", activity.cacheDir)
                    FileOutputStream(file).use { output ->
                        output.write(bytes)
                        output.fd.sync()
                    }
                    return file
                }
            }
        } finally {
            decoded.recycle()
        }
        throw IllegalArgumentException(activity.getString(R.string.attachment_preview_failed))
    }

    private fun bindPreview(attachment: Attachment, image: ImageView) {
        val available = attachment.objects.any { it.preview && it.state == AttachmentState.COMPLETE }
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
                val protected = File(activity.cacheDir, "attachment-preview-${UUID.randomUUID()}.jpg")
                try {
                    session.exportAttachmentPreview(attachment.transferId, protected)
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
                        require(copied <= MAX_PRIMARY_BYTES) {
                            activity.getString(R.string.attachment_too_large)
                        }
                        output.write(buffer, 0, read)
                    }
                    output.fd.sync()
                }
            }
            return SelectedDocument(staged, mediaType, displayName)
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
    private val export: (Attachment) -> Unit,
    private val preview: (Attachment, ImageView) -> Unit,
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
        view.findViewById<TextView>(R.id.attachment_title).text =
            primary?.filename ?: context.getString(R.string.attachment_default_name)
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
