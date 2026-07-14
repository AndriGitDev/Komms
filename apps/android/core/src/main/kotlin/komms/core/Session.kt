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
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.EventListener
import uniffi.kult_ffi.FfiException
import uniffi.kult_ffi.Group
import uniffi.kult_ffi.GroupMessage
import uniffi.kult_ffi.KdfChoice
import uniffi.kult_ffi.KultNode
import uniffi.kult_ffi.Message
import uniffi.kult_ffi.NoteMessage
import uniffi.kult_ffi.SafetyNumber
import uniffi.kult_ffi.ScheduledMessage
import uniffi.kult_ffi.Status
import uniffi.kult_ffi.defaultConfig
import uniffi.kult_ffi.canonicalizeRecordedAudio
import uniffi.kult_ffi.probeRecordedAudio

/**
 * Human-readable text for an FFI failure — the node's own words. (The
 * generated exception's `message` property wraps the field in
 * `reason=…` noise; the UI wants the reason verbatim.)
 */
fun FfiException.reasonText(): String = when (this) {
    is FfiException.Startup -> "startup: $reason"
    is FfiException.Node -> reason
    is FfiException.Stopped -> "node is stopped"
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

    /** Current authoritative carrier explanation for pairwise audio confirmation. */
    fun audioCarrierExplanation(peer: String): String =
        audioCarrierExplanation(listOf(peer))

    /** Current authoritative carrier explanation for every other current group member. */
    fun groupAudioCarrierExplanation(group: String): String {
        val members = groups().firstOrNull { it.id == group }
            ?.members?.filter { it != peer }
            ?: throw IllegalArgumentException("unknown group")
        return audioCarrierExplanation(members)
    }

    private fun audioCarrierExplanation(recipients: List<String>): String {
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
            recipients.isEmpty() -> "This group has no other current recipients; no audio delivery will be created."
            mesh > 0 && unavailable > 0 ->
                "$mesh recipient(s) have only a mesh route, so audio waits for a faster link and emits zero mesh bulk frames; " +
                    "$unavailable more have no fresh route. Recipients with a fresh realtime or bulk link can proceed."
            mesh > 0 -> "Will send when a faster link exists for $mesh recipient(s). Audio emits zero mesh bulk frames."
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

    /** Append one sealed local-only note; no transport work is created. */
    fun sendNoteToSelf(body: String): String = node.sendNoteToSelf(body)

    /** Create a sender-key group from stored contacts; returns its id. */
    fun createGroup(name: String, members: List<String>): String =
        node.createGroup(name, members)

    /** All live groups, excluding secrets and sender chains. */
    fun groups(): List<Group> = node.groups()

    /** Message history for a group, including per-member delivery states. */
    fun groupMessages(group: String): List<GroupMessage> = node.groupMessages(group)

    /** Queue a group message; progress is reported independently per member. */
    fun sendGroup(group: String, body: String): String = node.sendGroup(group, body)

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
