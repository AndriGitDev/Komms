// Android-shell acceptance: two full nodes driven through exactly the layer
// the activities call ([Session]) — pairing via the bundle *hex* a user
// scans or pastes, honest delivery states arriving as listener events,
// verification, settings persistence, and the backup → mnemonic → restore
// flow. Runs on the host JVM against the host-built `libkult_ffi`: same
// embedded runtime the phone runs, no emulator required.

package komms.core

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import uniffi.kult_ffi.AttachmentConversation
import uniffi.kult_ffi.AttachmentDirection
import uniffi.kult_ffi.AttachmentState
import uniffi.kult_ffi.ContentKind
import uniffi.kult_ffi.DeliveryState
import uniffi.kult_ffi.Direction
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.FfiException
import uniffi.kult_ffi.KdfChoice

/** Collects node events exactly as an activity's sink would. */
private class Events {
    private val all = mutableListOf<Event>()

    val sink: EventSink = { event -> synchronized(all) { all.add(event) } }

    fun <T : Event> wait(what: String, pred: (Event) -> T?): T {
        val deadline = System.nanoTime() + 30_000_000_000L
        while (true) {
            synchronized(all) { all.firstNotNullOfOrNull(pred) }?.let { return it }
            check(System.nanoTime() < deadline) { "timed out waiting for $what" }
            Thread.sleep(50)
        }
    }

    fun count(pred: (Event) -> Boolean): Int = synchronized(all) { all.count(pred) }
}

/** Hermetic settings: loopback QUIC only, no mDNS — hints are explicit. */
private fun testSettings() = NetworkSettings(
    listen = listOf("/ip4/127.0.0.1/udp/0/quic-v1"),
    mdns = false,
)

private fun open(dir: File, name: String, events: Events): Session {
    // Mirror the unlock flow: persist settings, then boot.
    val dataDir = File(dir, name)
    val settings = testSettings()
    settings.save(dataDir)
    return Session.open(dataDir, "test-passphrase", settings, KdfChoice.MOBILE, events.sink)
}

/** Poll status until a listen address is bound. */
private fun listenAddr(session: Session): String {
    val deadline = System.nanoTime() + 5_000_000_000L
    while (true) {
        session.status().listen.firstOrNull()?.let { return it }
        check(System.nanoTime() < deadline) { "no listen address within 5s" }
        Thread.sleep(50)
    }
}

private fun multiaddrHint(addr: String) = listOf(HintSpec("multiaddr", addr))

class SessionE2eTest {
    private fun canonicalAudio(samples: Int = 1_600): ByteArray {
        val dataBytes = samples * 2
        val bytes = ByteBuffer.allocate(44 + dataBytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes.put("RIFF".toByteArray()).putInt(36 + dataBytes).put("WAVEfmt ".toByteArray())
        bytes.putInt(16).putShort(1).putShort(1).putInt(16_000).putInt(32_000)
            .putShort(2).putShort(16).put("data".toByteArray()).putInt(dataBytes)
        repeat(samples) { bytes.putShort(((it % 2_000) - 1_000).toShort()) }
        return bytes.array()
    }
    private fun nativeAudioWithMetadata(canonical: ByteArray): ByteArray {
        val bytes = ByteBuffer.allocate(canonical.size + 12).order(ByteOrder.LITTLE_ENDIAN)
        bytes.put("RIFF".toByteArray()).putInt(canonical.size + 4)
        bytes.put(canonical, 8, 28)
        bytes.put("LIST".toByteArray()).putInt(4).put("leak".toByteArray())
        bytes.put(canonical, 36, canonical.size - 36)
        return bytes.array()
    }
    private fun tempDir(): File = Files.createTempDirectory("komms-e2e").toFile()

    @Test
    fun `two phones pair by scanned bundle hex and message`() {
        val dir = tempDir()
        val aEv = Events()
        val bEv = Events()
        val alice = open(dir, "alice", aEv)
        val bob = open(dir, "bob", bEv)

        // The status header's first snapshot is honest: nothing queued,
        // nothing bridged, no contacts, and a kult address to show.
        val status = alice.status()
        assertTrue(status.address.startsWith("kk1"))
        assertEquals(0uL, status.queued)
        assertEquals(0uL, status.transit)
        assertEquals(0uL, status.contacts)

        // Pairing exactly as the UI does it: each side renders its bundle
        // hex as a QR (uppercase, alphanumeric mode), the other scans it.
        val aBundle = alice.myBundleHex()
        val bBundle = bob.myBundleHex()
        assertNotNull(hexDecode(aBundle))
        val scanned = bundleQrText(bBundle) // what the camera hands back

        val aAddr = listenAddr(alice)
        val bAddr = listenAddr(bob)
        val bobPeer = alice.addContact("bob", scanned, multiaddrHint(bAddr))
        val alicePeer = bob.addContact("alice", aBundle, multiaddrHint(aAddr))

        // Send → the event stream walks the honest ladder.
        val msgId = alice.send(bobPeer, "hello from the phone")
        val got = bEv.wait("bob's message event") { it as? Event.MessageReceived }
        assertEquals(alicePeer, got.peer)
        assertEquals("hello from the phone", got.body)
        aEv.wait("alice's delivered event") {
            (it as? Event.DeliveryUpdated)
                ?.takeIf { e -> e.id == msgId && e.state == DeliveryState.DELIVERED }
        }
        assertTrue(alice.audioCarrierExplanation(bobPeer).contains("fresh realtime or bulk link"))

        // History rows carry what the bubbles render.
        val history = alice.messages(bobPeer)
        assertEquals(1, history.size)
        assertEquals(Direction.OUTBOUND, history[0].direction)
        assertEquals(DeliveryState.DELIVERED, history[0].state)
        val inbox = bob.messages(alicePeer)
        assertEquals(1, inbox.size)
        assertEquals(Direction.INBOUND, inbox[0].direction)
        assertEquals(DeliveryState.RECEIVED, inbox[0].state)

        // The SAF layer stages a content:// stream in app-private storage;
        // Session sees only that bounded path and the provider's untrusted
        // display hints. The transfer surface remains render-safe.
        val attachmentBytes = "android attachment bytes\u0000exact".toByteArray()
        val previewBytes = "android local jpeg preview".toByteArray()
        val source = File(dir, "android-source.bin").apply { writeBytes(attachmentBytes) }
        val preview = File(dir, "android-preview.jpg").apply { writeBytes(previewBytes) }
        val contentId = alice.sendAttachmentWithPreview(
            bobPeer,
            source,
            "application/octet-stream",
            "field-notes.bin",
            preview,
        )
        val outbound = alice.attachments().single { it.contentId == contentId }
        assertEquals(AttachmentConversation.PAIRWISE, outbound.conversation)
        assertEquals(AttachmentDirection.OUTBOUND, outbound.direction)
        assertEquals(2, outbound.objects.size)
        assertEquals("field-notes.bin", outbound.objects.first().filename)
        assertEquals(attachmentBytes.size.toULong(), outbound.objects.first().totalBytes)
        assertEquals("application/octet-stream", outbound.objects.first().mediaType)
        assertEquals(true, outbound.objects.last().preview)

        alice.pauseAttachment(outbound.transferId)
        assertEquals(
            AttachmentState.PAUSED,
            alice.attachments().single { it.transferId == outbound.transferId }.state,
        )
        alice.resumeAttachment(outbound.transferId)

        val offer = bEv.wait("pairwise attachment offer") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.contentId == contentId &&
                    event.attachment.direction == AttachmentDirection.INBOUND &&
                    event.attachment.peer == alicePeer
            }
        }.attachment
        assertEquals(AttachmentState.AWAITING_CONSENT, offer.state)
        assertEquals(0uL, offer.objects.first().verifiedBytes)
        bob.acceptAttachment(offer.transferId)
        bEv.wait("pairwise attachment completion") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.transferId == offer.transferId &&
                    event.attachment.state == AttachmentState.COMPLETE
            }
        }
        val received = bob.attachments().single { it.transferId == offer.transferId }
        assertEquals(attachmentBytes.size.toULong(), received.objects.first().verifiedBytes)
        assertEquals(previewBytes.size.toULong(), received.objects.last().verifiedBytes)

        // Android exports to a unique protected cache path first, then SAF
        // streams from it. The node refuses an existing local destination.
        val exported = File(dir, "android-export.bin")
        bob.exportAttachment(offer.transferId, exported)
        assertContentEquals(attachmentBytes, exported.readBytes())
        val exportedPreview = File(dir, "android-export-preview.jpg")
        bob.exportAttachmentPreview(offer.transferId, exportedPreview)
        assertContentEquals(previewBytes, exportedPreview.readBytes())
        assertFailsWith<FfiException> { bob.exportAttachment(offer.transferId, exported) }
        assertContentEquals(attachmentBytes, exported.readBytes())

        bob.rejectAttachment(offer.transferId)
        assertEquals(
            AttachmentState.REJECTED,
            bob.attachments().single { it.transferId == offer.transferId }.state,
        )
        alice.cancelAttachment(outbound.transferId)
        assertEquals(
            AttachmentState.CANCELLED,
            alice.attachments().single { it.transferId == outbound.transferId }.state,
        )

        val audioBytes = canonicalAudio()
        val nativeAudio = File(dir, "android-native-audio.wav").apply {
            writeBytes(nativeAudioWithMetadata(audioBytes))
        }
        val audio = File(dir, "android-audio-message.wav")
        assertEquals(100uL, alice.canonicalizeAudio(nativeAudio, audio).durationMs)
        assertContentEquals(audioBytes, audio.readBytes())
        assertEquals(100uL, alice.probeAudio(audio).durationMs)
        val audioContent = alice.sendAttachment(
            bobPeer, audio, "audio/wav", "audio-message.wav",
        )
        val audioOffer = bEv.wait("pairwise audio offer") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.contentId == audioContent &&
                    event.attachment.direction == AttachmentDirection.INBOUND
            }
        }.attachment
        bob.acceptAttachment(audioOffer.transferId)
        bEv.wait("pairwise audio completion") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.transferId == audioOffer.transferId &&
                    event.attachment.state == AttachmentState.COMPLETE
            }
        }
        val audioExport = File(dir, "android-audio-received.wav")
        bob.exportAttachment(audioOffer.transferId, audioExport)
        assertContentEquals(audioBytes, audioExport.readBytes())
        assertEquals(100uL, bob.probeAudio(audioExport).durationMs)

        // The verify screen: identical digits and QR payloads on both
        // ends (also identical to what the desktop app renders), and the
        // "mark verified" button reflects into the contact list badge.
        val snA = alice.safetyNumber(bobPeer)
        val snB = bob.safetyNumber(alicePeer)
        assertEquals(snA.digits, snB.digits)
        assertEquals(snA.display, snB.display)
        assertContentEquals(snA.qr, snB.qr)
        assertEquals(safetyQrText(snA), safetyQrText(snB))
        alice.markVerified(bobPeer)
        val contacts = alice.contacts()
        assertEquals(1, contacts.size)
        assertEquals("bob", contacts[0].name)
        assertTrue(contacts[0].verified)

        // The hints editor accepts a replacement and rejects garbage
        // honestly, before anything reaches the node.
        alice.setHints(bobPeer, listOf(HintSpec("mesh", "broadcast")))
        val bad = assertFailsWith<IllegalArgumentException> {
            alice.setHints(bobPeer, listOf(HintSpec("mesh", "over-the-rainbow")))
        }
        assertTrue("node number" in bad.message!!, "got: ${bad.message}")

        // Errors the composer surfaces are the node's own words.
        val unknown = assertFailsWith<FfiException.Node> {
            alice.send("00".repeat(32), "x")
        }
        assertTrue("not a stored contact" in unknown.reasonText(), "got: ${unknown.reasonText()}")
        assertFailsWith<IllegalArgumentException> {
            alice.addContact("mallory", "not hex!", emptyList())
        }

        alice.stop()
        bob.stop()
    }

    @Test
    fun `note to self is local sealed and durable`() {
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "notes", events)

        assertEquals("note_to_self", session.noteToSelfId())
        val id = session.sendNoteToSelf("remember the glacier map")
        val added = events.wait("local note event") {
            (it as? Event.NoteToSelfMessageAdded)?.takeIf { event -> event.id == id }
        }
        assertEquals(session.noteToSelfId(), added.conversation)
        assertEquals("remember the glacier map", added.body)
        assertEquals(0uL, session.status().queued)
        assertEquals(0uL, session.status().contacts)
        assertEquals("remember the glacier map", session.noteToSelfMessages().single().body)

        session.stop()
        session = open(dir, "notes", Events())
        assertEquals("note_to_self", session.noteToSelfMessages().single().conversation)
        assertEquals("remember the glacier map", session.noteToSelfMessages().single().body)
        assertEquals(0uL, session.status().queued)
        session.stop()
    }

    @Test
    fun `group ux creates manages messages and shows partial delivery`() {
        val dir = tempDir()
        val aEv = Events()
        val bEv = Events()

        // The embedded FFI runtime admits two live nodes per process. Capture
        // a real third identity first, then keep Carol offline so delivery can
        // be proven independently per member.
        val carol = open(dir, "group-carol", Events())
        val carolBundle = carol.myBundleHex()
        carol.stop()
        val alice = open(dir, "group-alice", aEv)
        val bob = open(dir, "group-bob", bEv)

        val aliceAddr = listenAddr(alice)
        val bobAddr = listenAddr(bob)
        val aliceBundle = alice.myBundleHex()
        val bobBundle = bob.myBundleHex()
        val bobPeer = alice.addContact("Bob", bobBundle, multiaddrHint(bobAddr))
        val carolPeer = alice.addContact(
            "Carol",
            carolBundle,
            multiaddrHint("/ip4/127.0.0.1/udp/9/quic-v1"),
        )
        val aliceAtBob = bob.addContact("Alice", aliceBundle, multiaddrHint(aliceAddr))

        // The create flow selects one stored contact; the creator then adds
        // another from the members screen.
        val group = alice.createGroup("Trail crew", listOf(bobPeer))
        bEv.wait("Bob's group invite") {
            (it as? Event.GroupUpdated)?.takeIf { event -> event.group == group }
        }
        var listed = alice.groups()
        assertEquals(1, listed.size)
        assertEquals(group, listed[0].id)
        assertEquals("Trail crew", listed[0].name)
        assertEquals(2, listed[0].members.size)

        // Capability negotiation is authenticated session state. Establish
        // the pairwise session before the group attachment composer asks the
        // node whether every recipient supports attachments.
        val capabilityProbe = alice.send(bobPeer, "attachment capability handshake")
        bEv.wait("attachment capability handshake") {
            (it as? Event.MessageReceived)?.takeIf { event ->
                event.peer == aliceAtBob && event.body == "attachment capability handshake"
            }
        }
        aEv.wait("attachment capability receipt") {
            (it as? Event.DeliveryUpdated)?.takeIf { event ->
                event.id == capabilityProbe && event.state == DeliveryState.DELIVERED
            }
        }

        // The same Session methods cover one encrypt-once group attachment.
        val groupBytes = canonicalAudio()
        val groupSource = File(dir, "android-group-source.wav").apply {
            writeBytes(groupBytes)
        }
        val groupContent = alice.sendGroupAttachment(
            group,
            groupSource,
            "audio/wav",
            "audio-message.wav",
        )
        val groupOffer = bEv.wait("group attachment offer") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.contentId == groupContent &&
                    event.attachment.conversation == AttachmentConversation.GROUP &&
                    event.attachment.group == group
            }
        }.attachment
        bob.acceptAttachment(groupOffer.transferId)
        bEv.wait("group attachment completion") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.transferId == groupOffer.transferId &&
                    event.attachment.state == AttachmentState.COMPLETE
            }
        }
        val groupExport = File(dir, "android-group-export.bin")
        bob.exportAttachment(groupOffer.transferId, groupExport)
        assertContentEquals(groupBytes, groupExport.readBytes())
        assertEquals(100uL, bob.probeAudio(groupExport).durationMs)

        alice.addGroupMember(group, carolPeer)
        listed = alice.groups()
        assertEquals(3, listed[0].members.size)

        // Only the creator gets roster controls; the node's explicit
        // authority error passes through the shell unchanged.
        val authority = assertFailsWith<FfiException.Node> {
            bob.addGroupMember(group, carolPeer)
        }
        assertTrue("creator" in authority.reasonText(), "got: ${authority.reasonText()}")

        // Bob receives while offline Carol remains queued/sent. Outbound
        // history exposes one truthful state per recipient.
        val first = alice.sendGroup(group, "Meet at the north trailhead")
        bEv.wait("Bob's group message") {
            (it as? Event.GroupMessageReceived)
                ?.takeIf { event -> event.group == group && event.body == "Meet at the north trailhead" }
        }
        aEv.wait("Bob's group copy delivered") {
            (it as? Event.GroupDeliveryUpdated)?.takeIf { event ->
                event.id == first && event.peer == bobPeer &&
                    event.state == DeliveryState.DELIVERED
            }
        }
        val allHistory = alice.groupMessages(group)
        assertEquals(1, allHistory.count { it.contentKind == ContentKind.ATTACHMENT })
        val history = allHistory.filter { it.contentKind != ContentKind.ATTACHMENT }
        assertEquals(1, history.size)
        assertEquals(Direction.OUTBOUND, history[0].direction)
        assertEquals(2, history[0].deliveries.size)
        assertEquals(
            DeliveryState.DELIVERED,
            history[0].deliveries.first { it.peer == bobPeer }.state,
        )
        assertTrue(
            history[0].deliveries.first { it.peer == carolPeer }.state in
                setOf(DeliveryState.QUEUED, DeliveryState.SENT),
        )
        val bobHistory = bob.groupMessages(group).filter {
            it.contentKind != ContentKind.ATTACHMENT
        }
        assertEquals(aliceAtBob, bobHistory[0].sender)
        assertEquals(Direction.INBOUND, bobHistory[0].direction)
        assertTrue(bobHistory[0].deliveries.isEmpty())

        // Creator removal rotates the roster immediately. A member can leave;
        // their live group disappears locally and the creator converges too.
        alice.removeGroupMember(group, carolPeer)
        assertEquals(2, alice.groups()[0].members.size)
        bob.leaveGroup(group)
        assertTrue(bob.groups().isEmpty())
        val deadline = System.nanoTime() + 30_000_000_000L
        while (alice.groups()[0].members.size != 1) {
            check(System.nanoTime() < deadline) { "creator did not apply Bob's leave" }
            Thread.sleep(50)
        }

        alice.stop()
        bob.stop()
    }

    @Test
    fun `backup mnemonic restore flow`() {
        val dir = tempDir()
        var aEv = Events()
        val bEv = Events()
        var alice = open(dir, "alice", aEv)
        val bob = open(dir, "bob", bEv)

        val aAddr = listenAddr(alice)
        val bAddr = listenAddr(bob)
        val bobPeer = alice.addContact("bob", bob.myBundleHex(), multiaddrHint(bAddr))
        val alicePeer = bob.addContact("alice", alice.myBundleHex(), multiaddrHint(aAddr))
        val msgId = alice.send(bobPeer, "before the backup")
        aEv.wait("delivered") {
            (it as? Event.DeliveryUpdated)
                ?.takeIf { e -> e.id == msgId && e.state == DeliveryState.DELIVERED }
        }
        alice.sendNoteToSelf("packed in the backup")

        // The backup dialog: mnemonic comes back exactly once, 24 words;
        // an existing file is refused, not clobbered.
        val backup = File(dir, "komms-backup.kkr")
        val mnemonic = alice.exportBackup(backup)
        assertEquals(24, mnemonic.split(Regex("\\s+")).count { it.isNotEmpty() })
        assertFailsWith<FfiException> { alice.exportBackup(backup) }

        val addressBefore = alice.address
        alice.stop()

        // The gate's restore tab: wrong mnemonic refused at startup…
        assertFailsWith<FfiException.Startup> {
            Session.restore(
                File(dir, "alice-wrong"), "new-pass", backup,
                "abandon ".repeat(23) + "art",
                testSettings(), KdfChoice.MOBILE, Events().sink,
            )
        }

        // …right mnemonic restores identity, contacts, and history.
        aEv = Events()
        alice = Session.restore(
            File(dir, "alice-new"), "new-pass", backup, mnemonic,
            testSettings(), KdfChoice.MOBILE, aEv.sink,
        )
        assertEquals(addressBefore, alice.address)
        assertEquals("bob", alice.contacts()[0].name)
        val history = alice.messages(bobPeer)
        assertEquals(1, history.size)
        assertEquals("before the backup", history[0].body)
        assertEquals("packed in the backup", alice.noteToSelfMessages().single().body)

        // The restored node re-handshakes automatically; after Bob learns
        // the new address, messaging resumes in both directions.
        val deadline = System.nanoTime() + 30_000_000_000L
        while (bEv.count { it is Event.SessionEstablished && it.peer == alicePeer } < 2) {
            check(System.nanoTime() < deadline) { "timed out waiting for re-key" }
            Thread.sleep(50)
        }
        bob.setHints(alicePeer, multiaddrHint(listenAddr(alice)))
        bob.send(alicePeer, "glad you're back")
        val got = aEv.wait("alice's message event") { it as? Event.MessageReceived }
        assertEquals("glad you're back", got.body)
        val reply = alice.send(bobPeer, "new phone, same me")
        aEv.wait("reply delivered") {
            (it as? Event.DeliveryUpdated)
                ?.takeIf { e -> e.id == reply && e.state == DeliveryState.DELIVERED }
        }

        alice.stop()
        bob.stop()
    }

    @Test
    fun `unlock refuses wrong passphrase and persists`() {
        val dir = tempDir()
        val alice = open(dir, "alice", Events())
        val address = alice.address
        alice.stop()

        // Wrong passphrase at the gate: an honest startup error.
        val err = assertFailsWith<FfiException.Startup> {
            Session.open(
                File(dir, "alice"), "wrong", testSettings(),
                KdfChoice.MOBILE, Events().sink,
            )
        }
        assertTrue(err.reasonText().startsWith("startup"), "got: ${err.reasonText()}")

        // Right passphrase: same identity. Settings persisted alongside.
        val again = open(dir, "alice", Events())
        assertEquals(address, again.address)
        assertFalse(NetworkSettings.load(File(dir, "alice")).mdns)
        again.stop()

        // A spent handle answers honestly instead of half-working.
        assertFailsWith<FfiException.Stopped> { again.status() }
    }
}
