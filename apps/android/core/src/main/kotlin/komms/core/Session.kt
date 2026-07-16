// The Android shell's view of a running node: a thin, testable layer over
// `kult-ffi`'s KultNode, mirroring the desktop app's `session.rs`.
//
// Everything the UI can do goes through [Session] — activities call these
// methods (off the main thread) and nothing else. That keeps the whole
// behavior testable without an emulator: the e2e test drives two [Session]s
// through exactly this surface.
//
// The shell adds **no** protocol logic. Honesty rules from the core carry
// through verbatim: delivery states come from the node (`DELIVERED` means an
// end-to-end encrypted receipt), errors are the node's own words, and the
// backup mnemonic is returned exactly once and never stored.

package komms.core

import java.io.File
import uniffi.kult_ffi.Attachment
import uniffi.kult_ffi.AudioInfo
import uniffi.kult_ffi.CarrierCapability
import uniffi.kult_ffi.Config
import uniffi.kult_ffi.Contact
import uniffi.kult_ffi.CustomIcon
import uniffi.kult_ffi.CustomIconCrop
import uniffi.kult_ffi.CustomIconQuotaUsage
import uniffi.kult_ffi.CustomIconTarget
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.EventListener
import uniffi.kult_ffi.FfiException
import uniffi.kult_ffi.Folder
import uniffi.kult_ffi.FolderConversation
import uniffi.kult_ffi.FolderConversationResult
import uniffi.kult_ffi.FolderSelection
import uniffi.kult_ffi.FolderTarget
import uniffi.kult_ffi.Group
import uniffi.kult_ffi.GroupMentionCapability
import uniffi.kult_ffi.GroupMessage
import uniffi.kult_ffi.KdfChoice
import uniffi.kult_ffi.KultNode
import uniffi.kult_ffi.Label
import uniffi.kult_ffi.LabelConversation
import uniffi.kult_ffi.LabelFilterResult
import uniffi.kult_ffi.LabelMatchMode
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.Pin
import uniffi.kult_ffi.PinConversationResult
import uniffi.kult_ffi.PinTarget
import uniffi.kult_ffi.StaleLabel
import uniffi.kult_ffi.StaleFolder
import uniffi.kult_ffi.ImageEditRecipe
import uniffi.kult_ffi.ImageInfo
import uniffi.kult_ffi.Message
import uniffi.kult_ffi.MentionSpan
import uniffi.kult_ffi.NoteMessage
import uniffi.kult_ffi.SafetyNumber
import uniffi.kult_ffi.ScheduledMessage
import uniffi.kult_ffi.Status
import uniffi.kult_ffi.ThemeInfo
import uniffi.kult_ffi.ThemePreference
import uniffi.kult_ffi.defaultConfig
import uniffi.kult_ffi.canonicalizeRecordedAudio
import uniffi.kult_ffi.editImage as ffiEditImage
import uniffi.kult_ffi.probeRecordedAudio
import uniffi.kult_ffi.probeEditedImage

/**
 * Human-readable text for an FFI failure — the node's own words. (The
 * generated exception's `message` property wraps the field in
 * `reason=…` noise; the UI wants the reason verbatim.)
 */
fun FfiException.reasonText(): String = when (this) {
    is FfiException.Startup -> "startup: $reason"
    is FfiException.Node -> reason
    is FfiException.Folder -> reason
    is FfiException.Label -> reason
    is FfiException.Pin -> reason
    is FfiException.Stopped -> "node is stopped"
}

/** B18 resource limits and canonical presentation tokens. */
const val MAX_LABELS = 128
const val MAX_LABEL_ASSIGNMENTS = 8_192
const val MAX_LABELS_PER_CONVERSATION = 32
const val MAX_LABEL_NAME_BYTES = 256
val LABEL_COLORS: List<String> = listOf(
    "neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink",
)

/** B10 private local folder limits shared by every wrapper. */
const val MAX_FOLDERS = 128
/** Maximum durable conversation pins accepted for new creation. */
const val MAX_PINS = 8192
const val MAX_FOLDER_ASSIGNMENTS = 8_192
const val MAX_FOLDER_NAME_BYTES = 256
/** B12 semantic roles mapped to native adaptive resources by each shell. */
val THEME_SEMANTIC_ROLES: List<String> = listOf(
    "background", "surface", "surface_raised", "surface_hover", "border",
    "text_primary", "text_secondary", "accent", "on_accent", "danger",
    "warning", "success", "bubble_outgoing", "bubble_incoming", "focus",
)

private fun validateFolderWrite(name: String) {
    val fixedWhitespace = setOf(
        0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020,
        0x0085, 0x200e, 0x200f, 0x2028, 0x2029,
    )
    var offset = 0
    var fixedOnly = name.isNotEmpty()
    while (offset < name.length) {
        val scalar = name.codePointAt(offset)
        if (scalar !in fixedWhitespace) fixedOnly = false
        offset += Character.charCount(scalar)
    }
    require(name.isNotEmpty() && name.toByteArray(Charsets.UTF_8).size <= MAX_FOLDER_NAME_BYTES && !fixedOnly) {
        "invalid folder name"
    }
}

private fun validateLabelWrite(name: String, color: String) {
    val fixedWhitespace = setOf(
        0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020,
        0x0085, 0x200e, 0x200f, 0x2028, 0x2029,
    )
    var offset = 0
    var fixedOnly = name.isNotEmpty()
    while (offset < name.length) {
        val scalar = name.codePointAt(offset)
        if (scalar !in fixedWhitespace) fixedOnly = false
        offset += Character.charCount(scalar)
    }
    require(name.isNotEmpty() && name.toByteArray(Charsets.UTF_8).size <= MAX_LABEL_NAME_BYTES && !fixedOnly) {
        "invalid label name"
    }
    require(color in LABEL_COLORS) { "unsupported label color" }
}

/**
 * QR text for a prekey bundle's hex: uppercase keeps the QR in its compact
 * alphanumeric mode (hex decoding is case-insensitive everywhere), and the
 * payload is interoperable with the desktop app's pairing QR and
 * `kult bundle` / `kult add`.
 */
fun bundleQrText(bundleHex: String): String = bundleHex.uppercase()

/**
 * QR text for a safety number: uppercase hex of the raw 32-byte comparison
 * value — both parties render the identical code, on any platform.
 */
fun safetyQrText(sn: SafetyNumber): String = hexEncode(sn.qr).uppercase()

/** Where the shell delivers node events (the app marshals to its UI thread). */
typealias EventSink = (Event) -> Unit

/** Adapter: `kult-ffi`'s listener trait onto an [EventSink]. */
private class Forwarder(private val sink: EventSink) : EventListener {
    override fun onEvent(event: Event) = sink(event)
}

/**
 * A running node plus the shell-side conveniences the UI needs. Construct
 * with [Session.open] or [Session.restore]; methods are blocking — call
 * them off the UI thread. Errors surface as [FfiException] (the node's own
 * words — use [reasonText]) or [IllegalArgumentException] for input this
 * layer rejects before it reaches the node.
 */
class Session private constructor(private val node: KultNode) {

    /** This node's human-shareable kult address. */
    val address: String by lazy { node.address() }

    /** This node's peer id (hex). */
    val peer: String by lazy { node.peer() }

    /** Status snapshot for the UI's transport indicators. */
    fun status(): Status = node.status()

    /**
     * Export a fresh prekey bundle as pasteable hex. Render
     * [bundleQrText] of it for the pairing QR.
     */
    fun myBundleHex(): String = hexEncode(node.handshakeBundle())

    /**
     * Add a contact from pasted/scanned bundle hex, with delivery hints.
     * Returns the new contact's peer id.
     */
    fun addContact(name: String, bundleHex: String, hints: List<HintSpec>): String {
        val bundle = hexDecode(bundleHex)
            ?: throw IllegalArgumentException("bundle must be hex")
        return node.addContact(name, bundle, hints.toFfi())
    }

    /** Add a contact from their kult address alone (DHT lookup). */
    fun addContactByAddress(name: String, address: String): String =
        node.addContactByAddress(name, address.trim())

    /** All stored contacts. */
    fun contacts(): List<Contact> = node.contacts()

    /** Assess a proposed private local petname without mutation. */
    fun assessContactName(peer: String, name: String) = node.assessContactName(peer, name)

    /** Rename one contact by exact peer id after explicit warning review. */
    fun renameContact(peer: String, name: String, acceptWarnings: Boolean) =
        node.renameContact(peer, name, acceptWarnings)

    /** Message history with a peer. */
    fun messages(peer: String): List<Message> = node.messagesWith(peer)

    /** Queue a message; returns its id (progress arrives as events). */
    fun send(peer: String, body: String): String = node.send(peer, body)

    /**
     * Import one app-private, caller-selected path as a pairwise attachment.
     * The Android shell stages a SAF stream at this path and deletes it when
     * this blocking call returns.
     */
    fun sendAttachment(
        peer: String,
        path: File,
        mediaType: String,
        filename: String?,
    ): String = node.sendAttachment(peer, path.absolutePath, mediaType, filename)

    /** Import a pairwise attachment plus a locally generated sealed preview. */
    fun sendAttachmentWithPreview(
        peer: String,
        path: File,
        mediaType: String,
        filename: String?,
        preview: File,
    ): String = node.sendAttachmentWithPreview(
        peer, path.absolutePath, mediaType, filename, preview.absolutePath, "image/jpeg",
    )

    /** Import one app-private path as an encrypt-once group attachment. */
    fun sendGroupAttachment(
        group: String,
        path: File,
        mediaType: String,
        filename: String?,
    ): String = node.sendGroupAttachment(group, path.absolutePath, mediaType, filename)

    /** Import a group attachment plus a locally generated sealed preview. */
    fun sendGroupAttachmentWithPreview(
        group: String,
        path: File,
        mediaType: String,
        filename: String?,
        preview: File,
    ): String = node.sendGroupAttachmentWithPreview(
        group, path.absolutePath, mediaType, filename, preview.absolutePath, "image/jpeg",
    )

    /** Every supported transfer as render-safe state. */
    fun attachments(): List<Attachment> = node.attachments()

    /** Accept an inbound attachment offer. */
    fun acceptAttachment(transfer: String) = node.acceptAttachment(transfer)

    /** Durably reject an inbound attachment offer. */
    fun rejectAttachment(transfer: String) = node.rejectAttachment(transfer)

    /** Cancel local transfer work and release unreferenced partial data. */
    fun cancelAttachment(transfer: String) = node.cancelAttachment(transfer)

    /** Pause attachment work while retaining verified progress. */
    fun pauseAttachment(transfer: String) = node.pauseAttachment(transfer)

    /** Resume a paused transfer from durable verified progress. */
    fun resumeAttachment(transfer: String) = node.resumeAttachment(transfer)

    /**
     * Stream a completed primary object to a protected, new app-private path.
     * The Android shell then copies that file to the caller-selected SAF URI.
     */
    fun exportAttachment(transfer: String, path: File) =
        node.exportAttachment(transfer, path.absolutePath)

    /** Decrypt a sealed preview into a protected app-private path. */
    fun exportAttachmentPreview(transfer: String, path: File) =
        node.exportAttachmentPreview(transfer, path.absolutePath)

    /** Rewrite native PCM WAVE into Komms's bounded metadata-free profile. */
    fun canonicalizeAudio(source: File, destination: File): AudioInfo =
        canonicalizeRecordedAudio(source.absolutePath, destination.absolutePath)

    /** Validate canonical audio and derive duration/waveform only on this device. */
    fun probeAudio(path: File): AudioInfo = probeRecordedAudio(path.absolutePath)

    /** Apply the shared bounded image recipe into a protected create-new destination. */
    fun editImage(source: File, destination: File, recipe: ImageEditRecipe): ImageInfo =
        ffiEditImage(source.absolutePath, destination.absolutePath, recipe)

    /** Validate the exact metadata-free canonical image profile before import or preview. */
    fun probeImage(path: File): ImageInfo = probeEditedImage(path.absolutePath)

    /** Current authoritative carrier explanation for pairwise file/image confirmation. */
    fun attachmentCarrierExplanation(peer: String): String =
        carrierExplanation(listOf(peer), "attachment")

    /** Current authoritative carrier explanation for every current group recipient. */
    fun groupAttachmentCarrierExplanation(group: String): String {
        val members = groups().firstOrNull { it.id == group }
            ?.members?.filter { it != peer }
            ?: throw IllegalArgumentException("unknown group")
        return carrierExplanation(members, "attachment")
    }

    /** Current authoritative carrier explanation for pairwise audio confirmation. */
    fun audioCarrierExplanation(peer: String): String =
        carrierExplanation(listOf(peer), "audio")

    /** Current authoritative carrier explanation for every other current group member. */
    fun groupAudioCarrierExplanation(group: String): String {
        val members = groups().firstOrNull { it.id == group }
            ?.members?.filter { it != peer }
            ?: throw IllegalArgumentException("unknown group")
        return carrierExplanation(members, "audio")
    }

    private fun carrierExplanation(recipients: List<String>, subject: String): String {
        val snapshots = node.carrierCapabilities().associateBy { it.peer }
        val mesh = recipients.count {
            snapshots[it]?.capability == CarrierCapability.MESH_ONLY
        }
        val unavailable = recipients.count {
            snapshots[it]?.capability !in setOf(
                CarrierCapability.REALTIME,
                CarrierCapability.BULK,
                CarrierCapability.MESH_ONLY,
            )
        }
        return when {
            recipients.isEmpty() -> "This group has no other current recipients; no $subject delivery will be created."
            mesh > 0 && unavailable > 0 ->
                "$mesh recipient(s) have only a mesh route, so $subject waits for a faster link and emits zero manifest, chunk, missing-range, or other bulk mesh frames; " +
                    "$unavailable more have no fresh route. Recipients with a fresh realtime or bulk link can proceed."
            mesh > 0 -> "Will send when a faster link exists for $mesh recipient(s). This $subject emits zero manifest, chunk, missing-range, or other bulk mesh frames."
            unavailable > 0 -> "Will remain queued locally until $unavailable recipient(s) have a fresh faster link."
            else -> "Every current recipient has a fresh realtime or bulk link; normal attachment quotas apply."
        }
    }

    /** Schedule pairwise text at an absolute UTC Unix instant. */
    fun schedule(peer: String, body: String, notBefore: ULong): String =
        node.schedule(peer, body, notBefore)

    /** Schedule group text at an absolute UTC Unix instant. */
    fun scheduleGroup(group: String, body: String, notBefore: ULong): String =
        node.scheduleGroup(group, body, notBefore)

    /** Edit a scheduled message before activation. */
    fun editScheduled(message: String, body: String, notBefore: ULong) =
        node.editScheduled(message, body, notBefore)

    /** Cancel a scheduled message before activation. */
    fun cancelScheduled(message: String) = node.cancelScheduled(message)

    /** Full durable scheduled outbox. */
    fun scheduledMessages(): List<ScheduledMessage> = node.scheduledMessages()

    /** Stable reserved identity for the local note-to-self conversation. */
    fun noteToSelfId(): String = node.noteToSelfId()

    /** All sealed local-only note-to-self entries. */
    fun noteToSelfMessages(): List<NoteMessage> = node.noteToSelfMessages()

    /** Current safe system/light/dark choice and sealed persistence state. */
    fun theme(): ThemeInfo = node.theme()

    /** Idempotently persist one canonical private local appearance choice. */
    fun setTheme(preference: ThemePreference): Boolean = node.setTheme(preference)

    /** One canonical private local icon, or null for generated initials. */
    fun customIcon(target: CustomIconTarget): CustomIcon? = node.customIcon(target)

    /** Crop, sanitize, and seal a selected local JPEG/PNG. */
    fun setCustomIconFromPath(
        target: CustomIconTarget,
        source: File,
        crop: CustomIconCrop? = null,
    ): CustomIcon = node.setCustomIconFromPath(target, source.absolutePath, crop)

    /** Render and seal one bundled glyph token. */
    fun setBundledCustomIcon(target: CustomIconTarget, glyph: String): CustomIcon =
        node.setBundledCustomIcon(target, glyph)

    /** Remove one icon and return to generated initials. */
    fun clearCustomIcon(target: CustomIconTarget): Boolean = node.clearCustomIcon(target)

    /** Current sealed icon record and encoded-byte usage. */
    fun customIconUsage(): CustomIconQuotaUsage = node.customIconQuotaUsage()

    /** Append one sealed local-only note; no transport work is created. */
    fun sendNoteToSelf(body: String): String = node.sendNoteToSelf(body)

    /** Create a private folder with exact UTF-8. */
    fun createFolder(name: String): Folder {
        validateFolderWrite(name)
        return node.createFolder(name)
    }

    /** All folders in deterministic persisted manual order. */
    fun folders(): List<Folder> = node.folders()

    /** One folder by its explicit stable id. */
    fun folder(id: String): Folder = node.folder(id)

    /** Rename while retaining id, membership, and order. */
    fun renameFolder(id: String, name: String): Folder {
        validateFolderWrite(name)
        return node.renameFolder(id, name)
    }

    /** Atomically reorder the complete active folder id set. */
    fun reorderFolders(ids: List<String>): List<Folder> {
        require(ids.size <= MAX_FOLDERS) { "invalid folder order" }
        return node.reorderFolders(ids)
    }

    /** Assignment count shown before destructive deletion review. */
    fun folderDeleteAssignmentCount(id: String): ULong = node.folderDeleteAssignmentCount(id)

    /** Atomic delete cascade to virtual Unfiled; [confirm] must be true. */
    fun deleteFolder(id: String, confirm: Boolean): ULong = node.deleteFolder(id, confirm)

    /** Idempotently move one exact typed target into one exact folder. */
    fun moveToFolder(id: String, target: FolderTarget): Boolean = node.moveToFolder(id, target)

    /** Idempotently move one exact typed target to virtual Unfiled. */
    fun unfileConversation(target: FolderTarget): Boolean = node.unfileConversation(target)

    /** Active typed targets in one folder. */
    fun folderMembership(id: String): List<FolderConversation> = node.folderMembership(id)

    /** Active folder for one exact available typed target. */
    fun conversationFolder(target: FolderTarget): Folder? = node.conversationFolder(target)

    /** Folder-first navigation composed deterministically with label matching. */
    fun folderConversations(
        selection: FolderSelection,
        labels: List<String>,
        mode: LabelMatchMode,
    ): FolderConversationResult {
        require(labels.size <= MAX_LABELS) { "selected label count exceeds $MAX_LABELS" }
        return node.folderConversations(selection, labels, mode)
    }

    /** Render-safe stale local folder-assignment diagnostics. */
    fun staleFolders(): List<StaleFolder> = node.staleFolders()

    /** Remove one exact assignment only while it remains stale. */
    fun cleanupStaleFolder(id: String, target: FolderTarget): Boolean =
        node.cleanupStaleFolder(id, target)

    /** Create a private label with exact UTF-8 and canonical color. */
    fun createLabel(name: String, color: String): Label {
        validateLabelWrite(name, color)
        return node.createLabel(name, color)
    }

    /** All labels in stable local insertion order. */
    fun labels(): List<Label> = node.labels()

    /** One label by its explicit stable id. */
    fun label(id: String): Label = node.label(id)

    /** Rename/recolor while retaining id, membership, and order. */
    fun updateLabel(id: String, name: String, color: String): Label {
        validateLabelWrite(name, color)
        return node.updateLabel(id, name, color)
    }

    /** Membership count shown before destructive deletion review. */
    fun labelDeleteAssignmentCount(id: String): ULong = node.labelDeleteAssignmentCount(id)

    /** Atomic cascade; [confirm] must be true. */
    fun deleteLabel(id: String, confirm: Boolean): ULong = node.deleteLabel(id, confirm)

    /** Idempotently apply one explicit typed target. */
    fun assignLabel(id: String, target: LabelTarget): Boolean = node.assignLabel(id, target)

    /** Idempotently remove one explicit typed target. */
    fun unassignLabel(id: String, target: LabelTarget): Boolean = node.unassignLabel(id, target)

    /** Active typed targets for one label. */
    fun labelMembership(id: String): List<LabelConversation> = node.labelMembership(id)

    /** Active labels for one exact typed target. */
    fun labelsForConversation(target: LabelTarget): List<Label> = node.labelsForConversation(target)

    /** Render-safe stale local membership diagnostics. */
    fun staleLabels(): List<StaleLabel> = node.staleLabels()

    /** Remove one exact membership only while it remains stale. */
    fun cleanupStaleLabel(id: String, target: LabelTarget): Boolean =
        node.cleanupStaleLabel(id, target)

    /** Deterministic local any/all filter; empty ids mean no label filter. */
    fun filterLabels(ids: List<String>, mode: LabelMatchMode): LabelFilterResult {
        require(ids.size <= MAX_LABELS) { "selected label count exceeds $MAX_LABELS" }
        return node.filterLabels(ids, mode)
    }

    /** Idempotently append one exact available conversation to pin order. */
    fun pinConversation(target: PinTarget): Boolean = node.pinConversation(target)

    /** Idempotently remove one exact active or stale pin. */
    fun unpinConversation(target: PinTarget): Boolean = node.unpinConversation(target)

    /** Inspect one exact target's durable pin state. */
    fun pinState(target: PinTarget): Pin? = node.pinState(target)

    /** List every durable active or stale pin. */
    fun pins(): List<Pin> = node.pins()

    /** Atomically reorder the complete durable pin target set. */
    fun reorderPins(targets: List<PinTarget>): List<Pin> {
        require(targets.size <= MAX_PINS) { "pin reorder count exceeds $MAX_PINS" }
        return node.reorderPins(targets)
    }

    /** List unavailable durable pins. */
    fun stalePins(): List<Pin> = node.stalePins()

    /** Remove one exact pin only while unavailable. */
    fun cleanupStalePin(target: PinTarget): Boolean = node.cleanupStalePin(target)

    /** Compose folder, label, and pin-aware conversation ordering. */
    fun pinConversations(
        selection: FolderSelection,
        labels: List<String>,
        mode: LabelMatchMode,
    ): PinConversationResult {
        require(labels.size <= MAX_LABELS) { "selected label count exceeds $MAX_LABELS" }
        return node.pinConversations(selection, labels, mode)
    }

    /** Create a sender-key group from stored contacts; returns its id. */
    fun createGroup(name: String, members: List<String>): String =
        node.createGroup(name, members)

    /** All live groups, excluding secrets and sender chains. */
    fun groups(): List<Group> = node.groups()

    /** Message history for a group, including per-member delivery states. */
    fun groupMessages(group: String): List<GroupMessage> = node.groupMessages(group)

    /** Queue a group message; progress is reported independently per member. */
    fun sendGroup(group: String, body: String): String = node.sendGroup(group, body)

    /** Current exact-roster semantic Mention capability and review binding. */
    fun groupMentionCapability(group: String): GroupMentionCapability =
        node.groupMentionCapability(group)

    /** Send exact fallback text with explicit peer-targeted UTF-8 byte spans. */
    fun sendGroupMention(
        group: String,
        text: String,
        spans: List<MentionSpan>,
        reviewToken: String,
    ): String = node.sendGroupMention(group, text, spans, reviewToken)

    /** Add a stored contact to a group (creator only). */
    fun addGroupMember(group: String, peer: String) = node.addGroupMember(group, peer)

    /** Remove a member and rotate group keys (creator only). */
    fun removeGroupMember(group: String, peer: String) = node.removeGroupMember(group, peer)

    /** Leave a group; local message history remains stored. */
    fun leaveGroup(group: String) = node.leaveGroup(group)

    /** The safety number with a peer (render [safetyQrText] for the QR). */
    fun safetyNumber(peer: String): SafetyNumber = node.safetyNumber(peer)

    /** Record an out-of-band verification. */
    fun markVerified(peer: String) = node.markVerified(peer)

    /** Replace a contact's delivery hints. */
    fun setHints(peer: String, hints: List<HintSpec>) =
        node.setHints(peer, hints.toFfi())

    /** Publish the prekey bundle on the DHT now. */
    fun publish() = node.publish()

    /**
     * Write an encrypted backup file; returns the one-time 24-word
     * mnemonic. The shell shows it exactly once and keeps no copy.
     */
    fun exportBackup(path: File): String = node.exportBackup(path.absolutePath)

    /** Stop the node (idempotent; the handle is spent afterwards). */
    fun stop() = node.stop()

    companion object {
        /**
         * Open (or create on first run) the store in `dataDir` and start
         * the node. Blocking: Argon2id and transport binding happen before
         * this returns, so a wrong passphrase is a startup error — never a
         * broken half-running node. `kdf` is the cost profile for store
         * *creation* (the app passes [KdfChoice.MOBILE]).
         */
        fun open(
            dataDir: File,
            passphrase: String,
            settings: NetworkSettings,
            kdf: KdfChoice,
            sink: EventSink,
        ): Session = Session(
            KultNode.start(buildConfig(dataDir, passphrase, settings, kdf), Forwarder(sink)),
        )

        /**
         * First run only: restore from an encrypted backup file instead of
         * creating a fresh identity, then start.
         */
        fun restore(
            dataDir: File,
            passphrase: String,
            backupPath: File,
            mnemonic: String,
            settings: NetworkSettings,
            kdf: KdfChoice,
            sink: EventSink,
        ): Session = Session(
            KultNode.restore(
                buildConfig(dataDir, passphrase, settings, kdf),
                backupPath.absolutePath,
                mnemonic,
                Forwarder(sink),
            ),
        )

        /**
         * The FFI config for this data dir + settings: `kult-ffi`'s
         * baseline with the user's network settings on top.
         */
        private fun buildConfig(
            dataDir: File,
            passphrase: String,
            settings: NetworkSettings,
            kdf: KdfChoice,
        ): Config {
            val base = defaultConfig(dataDir.absolutePath, passphrase)
            return base.copy(
                kdf = kdf,
                // An emptied-out listen list falls back to the baseline
                // rather than silently starting a node nothing can dial.
                listen = settings.listen.ifEmpty { base.listen },
                bootstrap = settings.bootstrap,
                relay = settings.relay,
                mailboxes = settings.mailboxes,
                serveMailbox = settings.serveMailbox,
                mdns = settings.mdns,
                spool = settings.spool,
                meshtasticSerial = settings.meshtasticSerial,
                meshtasticTcp = settings.meshtasticTcp,
                bridge = settings.bridge,
            )
        }
    }
}
