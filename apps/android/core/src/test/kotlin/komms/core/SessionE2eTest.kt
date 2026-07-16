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
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import uniffi.kult_ffi.AttachmentConversation
import uniffi.kult_ffi.AttachmentDirection
import uniffi.kult_ffi.AttachmentState
import uniffi.kult_ffi.attachmentFilePresentation
import uniffi.kult_ffi.ContentKind
import uniffi.kult_ffi.ContactNameWarning
import uniffi.kult_ffi.CustomIconCrop
import uniffi.kult_ffi.CustomIconTarget
import uniffi.kult_ffi.CustomIconTargetKind
import uniffi.kult_ffi.DeliveryState
import uniffi.kult_ffi.Direction
import uniffi.kult_ffi.Event
import uniffi.kult_ffi.FfiException
import uniffi.kult_ffi.FolderErrorCode
import uniffi.kult_ffi.FolderSelection
import uniffi.kult_ffi.FolderSelectionKind
import uniffi.kult_ffi.FolderTarget
import uniffi.kult_ffi.FolderTargetKind
import uniffi.kult_ffi.KdfChoice
import uniffi.kult_ffi.ImageCrop
import uniffi.kult_ffi.ImageEditRecipe
import uniffi.kult_ffi.ImageEditRegion
import uniffi.kult_ffi.ImageEditRegionKind
import uniffi.kult_ffi.MentionSpan
import uniffi.kult_ffi.LabelErrorCode
import uniffi.kult_ffi.LabelMatchMode
import uniffi.kult_ffi.LabelTarget
import uniffi.kult_ffi.LabelTargetKind
import uniffi.kult_ffi.PinErrorCode
import uniffi.kult_ffi.PinTarget
import uniffi.kult_ffi.PinTargetKind
import uniffi.kult_ffi.ThemePreference
import uniffi.kult_ffi.TextFormatHighlight

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
    private val filePresentationFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(
            File(root, "fixtures/c1-file-presentation-parity.json").readText(),
        ).jsonObject
    }
    private val messageEditFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(
            File(root, "fixtures/c3-message-edit-parity.json").readText(),
        ).jsonObject
    }
    private val textFormattingFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b9-text-formatting-parity.json").readText()).jsonObject
    }
    private val contactRenameFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b5-contact-rename-parity.json").readText()).jsonObject
    }
    private val folderFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b10-folder-parity.json").readText()).jsonObject
    }
    private val labelFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b18-label-parity.json").readText()).jsonObject
    }
    private val pinFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b11-pin-parity.json").readText()).jsonObject
    }
    private val themeFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b12-theme-parity.json").readText()).jsonObject
    }
    private val customIconFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b13-custom-icon-parity.json").readText()).jsonObject
    }
    private val screenSecurityFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b14-screen-security-parity.json").readText()).jsonObject
    }
    private val incognitoKeyboardFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/b15-incognito-keyboard-parity.json").readText()).jsonObject
    }
    private val ephemeralFixture by lazy {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        Json.parseToJsonElement(File(root, "fixtures/c4-ephemeral-parity.json").readText()).jsonObject
    }

    @Test
    fun `Android ephemeral controls match the shared contract`() {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        assertEquals("5", ephemeralFixture.getValue("content_kind").jsonPrimitive.content)
        assertEquals(
            listOf("60", "3600", "86400", "604800", "2592000"),
            ephemeralFixture.getValue("text_lifetimes").jsonArray.map { it.jsonPrimitive.content },
        )
        val source = File(root, "apps/android/app/src/main/kotlin/komms/android").walkTopDown()
            .filter { it.extension == "kt" }.joinToString("\n") { it.readText() }
        assertTrue("sendDisappearing" in source)
        assertTrue("sendGroupDisappearing" in source)
        assertTrue("consumeViewOnceAttachment" in source)
        assertTrue("!attachment.viewOnce" in source)
    }

    @Test
    fun `message edit fixture has canonical wire and deterministic winner`() {
        val fixture = messageEditFixture
        val case = fixture.getValue("case").jsonObject
        val versions = case.getValue("expected_versions").jsonArray.map { it.jsonObject }
        assertEquals("komms-message-edit-parity-v1", fixture.getValue("schema").jsonPrimitive.content)
        assertEquals("1", fixture.getValue("content_format").jsonPrimitive.content)
        assertEquals("4", fixture.getValue("content_kind").jsonPrimitive.content)
        assertEquals("16384", fixture.getValue("maximum_text_bytes").jsonPrimitive.content)
        assertEquals("64", fixture.getValue("maximum_local_edits").jsonPrimitive.content)
        assertEquals(64, case.getValue("target_author").jsonPrimitive.content.length)
        assertEquals(32, case.getValue("target_content_id").jsonPrimitive.content.length)
        assertEquals(
            listOf("0", "1", "2", "2"),
            versions.map { it.getValue("revision").jsonPrimitive.content },
        )
        assertEquals("2", case.getValue("winning_revision").jsonPrimitive.content)
        assertEquals("deterministic winner", case.getValue("winning_text").jsonPrimitive.content)
        assertEquals(
            case.getValue("winning_text").jsonPrimitive.content,
            versions.last().getValue("text").jsonPrimitive.content,
        )
        assertTrue(versions.all { it.getValue("id").jsonPrimitive.content.length == 32 })
    }

    @Test
    fun `file presentation policy matches shared fail closed fixture`() {
        for (case in filePresentationFixture["cases"]!!.jsonArray) {
            val value = case.jsonObject
            val filename = value["filename"]
                ?.jsonPrimitive
                ?.takeUnless { it.toString() == "null" }
                ?.content
            val result = attachmentFilePresentation(
                value["media_type"]!!.jsonPrimitive.content,
                filename,
            )
            assertEquals(value["kind"]!!.jsonPrimitive.content, result.kind.name.lowercase())
            assertEquals(
                value["open_policy"]!!.jsonPrimitive.content,
                result.openPolicy.name.lowercase(),
            )
            assertEquals(
                value["warnings"]!!.jsonArray.map { it.jsonPrimitive.content },
                result.warnings.map { it.name.lowercase() },
            )
        }
    }

    @Test
    fun `incognito keyboard policy is always on before a node opens`() {
        val policy = androidIncognitoKeyboardPolicy()
        val expected = incognitoKeyboardFixture["platforms"]!!.jsonObject["android"]!!.jsonObject
        assertTrue(policy.alwaysOn)
        assertTrue(policy.appliesBeforeUnlock)
        assertEquals(
            expected["personalized_learning"]!!.jsonPrimitive.content,
            policy.personalizedLearning.name.lowercase(),
        )
        assertEquals(
            incognitoKeyboardFixture["protected_fields"]!!.jsonArray.map { it.jsonPrimitive.content },
            policy.protectedFields,
        )
        assertTrue(policy.mechanism.contains("no-personalized-learning"))
        assertTrue(policy.limitations.any { it.contains("request") })
    }

    @Test
    fun `text formatting matches the shared inert corpus`() {
        val dir = tempDir()
        val session = open(dir, "text-formatting", Events())
        for (case in textFormattingFixture.getValue("cases").jsonArray) {
            val record = case.jsonObject
            val highlights = record.getValue("highlights").jsonArray.map { highlight ->
                val range = highlight.jsonObject
                TextFormatHighlight(
                    range.getValue("start").jsonPrimitive.content.toUInt(),
                    range.getValue("end").jsonPrimitive.content.toUInt(),
                )
            }
            val formatted = session.formatText(
                record.getValue("source").jsonPrimitive.content,
                highlights,
            )
            assertEquals(record.getValue("source").jsonPrimitive.content, formatted.source)
            assertEquals(record.getValue("plain_text").jsonPrimitive.content, formatted.plainText)
            assertEquals(
                record.getValue("used_fallback").jsonPrimitive.content.toBoolean(),
                formatted.usedFallback,
            )
            assertEquals(
                record.getValue("block_kinds").jsonArray.map { it.jsonPrimitive.content },
                formatted.blocks.map { it.kind.name.lowercase() },
            )
        }
        session.stop()
    }

    @Test
    fun `private contact rename is normalized warned duplicate capable and restart safe`() {
        val fixture = contactRenameFixture
        val dir = tempDir()
        val events = Events()
        var alice = open(dir, "contact-rename-alice", events)
        val bob = open(dir, "contact-rename-bob", Events())
        alice.addContact(
            fixture.getValue("duplicate_name").jsonPrimitive.content,
            alice.myBundleHex(),
            emptyList(),
        )
        val bobPeer = alice.addContact("Bob", bob.myBundleHex(), emptyList())
        val queuedBefore = alice.status().queued

        val normalized = alice.renameContact(
            bobPeer,
            fixture.getValue("decomposed_name").jsonPrimitive.content,
            false,
        )
        assertEquals(
            fixture.getValue("normalized_name").jsonPrimitive.content,
            normalized.normalizedName,
        )
        assertTrue(normalized.changedByNormalization)

        val duplicate = alice.assessContactName(
            bobPeer,
            fixture.getValue("duplicate_name").jsonPrimitive.content,
        )
        assertEquals(1u, duplicate.duplicateCount)
        assertEquals(listOf(ContactNameWarning.DUPLICATE_NAME), duplicate.warnings)
        assertFailsWith<FfiException.Node> {
            alice.renameContact(
                bobPeer,
                fixture.getValue("duplicate_name").jsonPrimitive.content,
                false,
            )
        }
        alice.renameContact(
            bobPeer,
            fixture.getValue("duplicate_name").jsonPrimitive.content,
            true,
        )
        assertEquals(
            2,
            alice.contacts().count {
                it.name == fixture.getValue("duplicate_name").jsonPrimitive.content
            },
        )
        events.wait("contact renamed") { event ->
            (event as? Event.ContactRenamed)?.takeIf { it.peer == bobPeer }
        }
        assertEquals(queuedBefore, alice.status().queued)
        alice.stop()

        alice = open(dir, "contact-rename-alice", Events())
        assertEquals(
            fixture.getValue("duplicate_name").jsonPrimitive.content,
            alice.contacts().single { it.peer == bobPeer }.name,
        )
        alice.stop()
        bob.stop()
    }

    @Test
    fun `every Android textual editor uses the incognito class and secrets are masked`() {
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        val app = File(root, "apps/android/app/src/main")
        val layouts = File(app, "res/layout").walkTopDown()
            .filter { it.isFile && it.extension == "xml" }
            .joinToString("\n") { it.readText() }
        assertFalse(Regex("<\\s*EditText\\b").containsMatchIn(layouts))
        assertEquals(16, Regex("<komms\\.android\\.IncognitoEditText\\b").findAll(layouts).count())

        val kotlin = File(app, "kotlin/komms/android").walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "IncognitoEditText.kt" }
            .joinToString("\n") { it.readText() }
        assertFalse(Regex("\\bEditText\\s*\\(").containsMatchIn(kotlin))

        val editor = File(app, "kotlin/komms/android/IncognitoEditText.kt").readText()
        assertTrue(editor.contains("IME_FLAG_NO_PERSONALIZED_LEARNING"))
        assertTrue(editor.contains("TYPE_TEXT_FLAG_NO_SUGGESTIONS"))
        val gate = File(app, "res/layout/activity_gate.xml").readText()
        assertTrue(
            Regex("gate_mnemonic[\\s\\S]*textPassword\\|textNoSuggestions")
                .containsMatchIn(gate),
        )
    }

    @Test
    fun `screen security policy is always on before a node opens`() {
        val policy = androidScreenSecurityPolicy()
        val expected = screenSecurityFixture["platforms"]!!.jsonObject["android"]!!.jsonObject
        assertTrue(policy.alwaysOn)
        assertEquals(
            expected["capture_prevention"]!!.jsonPrimitive.content,
            policy.capturePrevention.name.lowercase(),
        )
        assertEquals(
            expected["background_obscuring"]!!.jsonPrimitive.content,
            policy.backgroundObscuring.name.lowercase(),
        )
        assertTrue(policy.mechanism.contains("FLAG_SECURE"))
        assertTrue(policy.limitations.isNotEmpty())
    }

    @Test
    fun `private theme defaults persists restarts and emits one local event`() {
        assertEquals(
            listOf("system", "light", "dark"),
            themeFixture["preferences"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(
            THEME_SEMANTIC_ROLES,
            themeFixture["semantic_roles"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "theme", events)
        val queued = session.status().queued
        assertEquals(ThemePreference.SYSTEM, session.theme().preference)
        assertFalse(session.theme().persisted)
        assertTrue(session.setTheme(ThemePreference.DARK))
        assertFalse(session.setTheme(ThemePreference.DARK))
        events.wait("theme changed") { it as? Event.ThemeChanged }
        assertEquals(queued, session.status().queued)
        session.stop()

        session = open(dir, "theme", Events())
        assertEquals(ThemePreference.DARK, session.theme().preference)
        assertTrue(session.theme().persisted)
        session.stop()
    }

    @Test
    fun `private custom icons are canonical local and durable through android session`() {
        assertEquals(
            listOf("contact", "group", "folder", "note_to_self"),
            customIconFixture.getValue("target_types").jsonArray.map { it.jsonPrimitive.content },
        )
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "icons", events)
        val queued = session.status().queued
        val note = CustomIconTarget(CustomIconTargetKind.NOTE_TO_SELF, null)
        assertEquals(null, session.customIcon(note))
        val noteIcon = session.setBundledCustomIcon(note, "compass")
        assertEquals("image/png", noteIcon.mediaType)
        assertEquals(256u, noteIcon.width)
        assertEquals(256u, noteIcon.height)
        assertContentEquals(byteArrayOf(-119, 80, 78, 71, 13, 10, 26, 10), noteIcon.bytes.take(8).toByteArray())
        events.wait("custom icons changed") { it as? Event.CustomIconsChanged }

        val folder = session.createFolder("Icon target")
        val folderTarget = CustomIconTarget(CustomIconTargetKind.FOLDER, folder.id)
        val source = File(dir, "android-icon.png").apply { writeBytes(imageSource()) }
        val folderIcon = session.setCustomIconFromPath(
            folderTarget,
            source,
            CustomIconCrop(0u, 0u, 3u, 3u),
        )
        assertNotEquals(noteIcon.bytes.toList(), folderIcon.bytes.toList())
        val usage = session.customIconUsage()
        assertEquals(2uL, usage.records)
        assertEquals((noteIcon.bytes.size + folderIcon.bytes.size).toULong(), usage.bytes)
        assertEquals(queued, session.status().queued)
        assertTrue(session.clearCustomIcon(folderTarget))
        assertFalse(session.clearCustomIcon(folderTarget))
        assertEquals(null, session.customIcon(folderTarget))
        session.stop()

        session = open(dir, "icons", Events())
        assertContentEquals(noteIcon.bytes, assertNotNull(session.customIcon(note)).bytes)
        session.stop()
    }
    private fun imageSource(): ByteArray = Base64.getDecoder().decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAADAgMAAADJmkZVAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAMUExURRAgMHhwaODAoP///zpo6RQAAAADdFJOU9nZ2dfb3kcAAAABYktHRAMRDEzyAAAAB3RJTUUH6gcOFCoDxLmvWQAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0wNy0xNFQyMDo0MjowMyswMDowMANuTXIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMDctMTRUMjA6NDI6MDMrMDA6MDByM/XOAAAAKHRFWHRkYXRlOnRpbWVzdGFtcAAyMDI2LTA3LTE0VDIwOjQyOjAzKzAwOjAwJSbUEQAAAA5JREFUCNdjYGAIZVgFAAGvAQCmulOkAAAAAElFTkSuQmCC",
    )

    private fun imageRecipe() = ImageEditRecipe(
        ImageCrop(1u, 0u, 3u, 3u),
        1u.toUByte(),
        listOf(
            ImageEditRegion(ImageEditRegionKind.PIXELATE, 0u, 0u, 2u, 2u, 2u),
            ImageEditRegion(ImageEditRegionKind.BLUR, 1u, 0u, 2u, 3u, 1u),
        ),
    )

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
        val formattedSource = "**hello** from Android ![pixel](https://invalid.test/p.png)"
        val msgId = alice.send(bobPeer, formattedSource)
        val got = bEv.wait("bob's message event") { it as? Event.MessageReceived }
        assertEquals(alicePeer, got.peer)
        assertEquals(formattedSource, got.body)
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
        assertEquals(formattedSource, history[0].body)
        val inbox = bob.messages(alicePeer)
        assertEquals(1, inbox.size)
        assertEquals(Direction.INBOUND, inbox[0].direction)
        assertEquals(DeliveryState.RECEIVED, inbox[0].state)
        assertEquals(formattedSource, inbox[0].body)

        val hour = ephemeralFixture.getValue("text_lifetimes").jsonArray[1]
            .jsonPrimitive.content.toULong()
        val temporary = alice.sendDisappearing(bobPeer, "temporary Android text", hour)
        val temporaryEvent = bEv.wait("Android disappearing message") {
            (it as? Event.MessageReceived)?.takeIf { event ->
                event.id == temporary && event.contentKind == ContentKind.DISAPPEARING_TEXT &&
                    event.expiresAt != null
            }
        }
        val temporaryRow = bob.messages(alicePeer).single { it.id == temporary }
        assertEquals(ContentKind.DISAPPEARING_TEXT, temporaryRow.contentKind)
        assertEquals(temporaryEvent.expiresAt, temporaryRow.expiresAt)

        Thread.sleep(300)
        val editable = alice.send(bobPeer, "Android edit original")
        bEv.wait("Bob's canonical Android Text") {
            (it as? Event.MessageReceived)?.takeIf { event ->
                event.id == editable && event.contentKind == ContentKind.TEXT
            }
        }
        aEv.wait("Android editable delivery") {
            (it as? Event.DeliveryUpdated)?.takeIf { event ->
                event.id == editable && event.state == DeliveryState.DELIVERED
            }
        }
        val edit = alice.editMessage(
            bobPeer, alicePeer, editable, "Android edit revised",
        )
        bEv.wait("Android pairwise edit refresh") {
            (it as? Event.MessageEdited)?.takeIf { event ->
                event.peer == alicePeer && event.targetContentId == editable
            }
        }
        aEv.wait("Android edit delivery") {
            (it as? Event.DeliveryUpdated)?.takeIf { event ->
                event.id == edit && event.state == DeliveryState.DELIVERED
            }
        }
        listOf(alice.messages(bobPeer), bob.messages(alicePeer)).forEach { messages ->
            assertEquals(3, messages.size, "Edit events are not standalone rows")
            val message = messages.single { it.id == editable }
            assertEquals("Android edit revised", message.body)
            assertTrue(message.edited)
            assertEquals(1uL, message.editRevision)
            assertEquals(
                listOf("Android edit original", "Android edit revised"),
                message.versions.map { it.body },
            )
        }

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

        val onceBytes = "Android view-once bytes".toByteArray()
        val onceSource = File(dir, "android-view-once.bin").apply { writeBytes(onceBytes) }
        val onceId = alice.sendViewOnceAttachment(
            bobPeer, onceSource, "application/octet-stream", "reveal-once.bin",
            lifetimeSeconds = hour,
        )
        val onceOffer = bEv.wait("Android view-once offer") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.contentId == onceId && event.attachment.viewOnce
            }
        }.attachment
        assertNotNull(onceOffer.expiresAt)
        bob.acceptAttachment(onceOffer.transferId)
        bEv.wait("Android view-once completion") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.transferId == onceOffer.transferId &&
                    event.attachment.state == AttachmentState.COMPLETE
            }
        }
        assertFailsWith<FfiException> {
            bob.exportAttachment(onceOffer.transferId, File(dir, "forbidden-view-once.bin"))
        }
        val onceOutput = File(dir, "android-view-once-output.bin")
        bob.consumeViewOnceAttachment(onceOffer.transferId, onceOutput)
        assertContentEquals(onceBytes, onceOutput.readBytes())
        assertFailsWith<FfiException> {
            bob.consumeViewOnceAttachment(
                onceOffer.transferId, File(dir, "android-view-once-second.bin"),
            )
        }

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

        // Every platform wrapper passes the same integer recipe to Rust and
        // imports only the exact canonical result, never the selected source.
        val imageSource = File(dir, "android-selected-image.png").apply {
            writeBytes(imageSource())
        }
        val imageFinal = File(dir, "android-edited-image.png")
        val imageDirect = File(dir, "android-edited-image-direct.png")
        val imageInfo = alice.editImage(imageSource, imageFinal, imageRecipe())
        uniffi.kult_ffi.editImage(
            imageSource.absolutePath,
            imageDirect.absolutePath,
            imageRecipe(),
        )
        assertContentEquals(imageDirect.readBytes(), imageFinal.readBytes())
        assertEquals(imageInfo, alice.probeImage(imageFinal))
        val imageContent = alice.sendAttachment(
            bobPeer, imageFinal, "image/png", "edited-image.png",
        )
        val imageOffer = bEv.wait("pairwise edited image offer") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.contentId == imageContent &&
                    event.attachment.direction == AttachmentDirection.INBOUND
            }
        }.attachment
        bob.acceptAttachment(imageOffer.transferId)
        bEv.wait("pairwise edited image completion") {
            (it as? Event.AttachmentUpdated)?.takeIf { event ->
                event.attachment.transferId == imageOffer.transferId &&
                    event.attachment.state == AttachmentState.COMPLETE
            }
        }
        val imageExport = File(dir, "android-edited-image-received.png")
        bob.exportAttachment(imageOffer.transferId, imageExport)
        assertContentEquals(imageFinal.readBytes(), imageExport.readBytes())
        assertEquals(imageInfo, bob.probeImage(imageExport))

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
        val selectedImage = File(dir, "android-group-selected.png").apply {
            writeBytes(imageSource())
        }
        val groupSource = File(dir, "android-group-edited.png")
        val directImage = File(dir, "android-group-edited-direct.png")
        val groupImageInfo = alice.editImage(selectedImage, groupSource, imageRecipe())
        uniffi.kult_ffi.editImage(
            selectedImage.absolutePath,
            directImage.absolutePath,
            imageRecipe(),
        )
        assertContentEquals(directImage.readBytes(), groupSource.readBytes())
        val groupContent = alice.sendGroupAttachment(
            group,
            groupSource,
            "image/png",
            "edited-image.png",
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
        assertContentEquals(groupSource.readBytes(), groupExport.readBytes())
        assertEquals(groupImageInfo, bob.probeImage(groupExport))

        // The Android Session exposes the exact native poll contract. Poll
        // events refresh dedicated cards and never become chat-message rows.
        val messageRowsBeforePoll = alice.groupMessages(group).size
        val pollId = alice.createGroupPoll(
            group,
            "Which route? 🗻",
            listOf("North ridge", "River path"),
        )
        bEv.wait("Bob's Android poll") {
            (it as? Event.PollUpdated)?.takeIf { event ->
                event.group == group && event.pollId == pollId
            }
        }
        val bobPoll = bob.groupPolls(group).single()
        assertEquals("Which route? 🗻", bobPoll.question)
        assertTrue(bobPoll.votesVisible)
        assertFalse(bobPoll.anonymous)
        assertEquals("manual_creator_snapshot", bobPoll.closePolicy)
        assertFalse(bobPoll.canClose)
        bob.voteGroupPoll(group, bobPoll.author, pollId, bobPoll.options[0].id)
        aEv.wait("Bob's first Android poll vote") {
            (it as? Event.PollUpdated)?.takeIf { event -> event.pollId == pollId }
        }
        val changedOption = bobPoll.options[1].id
        bob.voteGroupPoll(group, bobPoll.author, pollId, changedOption)
        val pollChangeDeadline = System.nanoTime() + 30_000_000_000L
        while (alice.groupPolls(group).single().votes.singleOrNull()?.optionId != changedOption) {
            check(System.nanoTime() < pollChangeDeadline) { "timed out waiting for changed poll vote" }
            Thread.sleep(50)
        }
        val changedPoll = alice.groupPolls(group).single()
        assertEquals(1, changedPoll.votes.size)
        assertEquals(changedOption, changedPoll.votes.single().optionId)
        assertTrue(changedPoll.canClose)
        alice.closeGroupPoll(group, changedPoll.author, pollId)
        val pollCloseDeadline = System.nanoTime() + 30_000_000_000L
        while (!bob.groupPolls(group).single().closed) {
            check(System.nanoTime() < pollCloseDeadline) { "timed out waiting for closed poll" }
            Thread.sleep(50)
        }
        assertTrue(bob.groupPolls(group).single().closed)
        assertEquals(messageRowsBeforePoll, alice.groupMessages(group).size)
        assertEquals(messageRowsBeforePoll, bob.groupMessages(group).size)

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
        Thread.sleep(300)
        val editable = alice.sendGroup(group, "Android group edit original")
        bEv.wait("Bob's editable Android group Text") {
            (it as? Event.GroupMessageReceived)?.takeIf { event ->
                event.id == editable && event.contentKind == ContentKind.TEXT
            }
        }
        aEv.wait("Android editable group delivery") {
            (it as? Event.GroupDeliveryUpdated)?.takeIf { event ->
                event.id == editable && event.peer == bobPeer &&
                    event.state == DeliveryState.DELIVERED
            }
        }
        val edit = alice.editGroupMessage(
            group, aliceAtBob, editable, "Android group edit revised",
        )
        bEv.wait("Android group edit refresh") {
            (it as? Event.GroupMessageEdited)?.takeIf { event ->
                event.group == group && event.sender == aliceAtBob &&
                    event.targetContentId == editable
            }
        }
        aEv.wait("Android group edit delivery") {
            (it as? Event.GroupDeliveryUpdated)?.takeIf { event ->
                event.id == edit && event.peer == bobPeer &&
                    event.state == DeliveryState.DELIVERED
            }
        }
        listOf(alice.groupMessages(group), bob.groupMessages(group)).forEach { messages ->
            val message = messages.single { it.id == editable }
            assertEquals("Android group edit revised", message.body)
            assertTrue(message.edited)
            assertEquals(1uL, message.editRevision)
            assertEquals(2, message.versions.size)
        }
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
    fun `group mentions preserve exact utf8 spans and notify only the target`() {
        val dir = tempDir()
        val aEv = Events()
        val bEv = Events()
        val alice = open(dir, "mention-alice", aEv)
        val bob = open(dir, "mention-bob", bEv)

        try {
            val aliceAddr = listenAddr(alice)
            val bobAddr = listenAddr(bob)
            val bobPeer = alice.addContact(
                "Same name", bob.myBundleHex(), multiaddrHint(bobAddr),
            )
            val aliceAtBob = bob.addContact(
                "Same name", alice.myBundleHex(), multiaddrHint(aliceAddr),
            )
            val group = alice.createGroup("Unicode crew", listOf(bobPeer))
            bEv.wait("mention group invite") {
                (it as? Event.GroupUpdated)?.takeIf { event -> event.group == group }
            }

            val handshake = alice.send(bobPeer, "mention capability handshake")
            bEv.wait("mention capability handshake") {
                (it as? Event.MessageReceived)?.takeIf { event ->
                    event.peer == aliceAtBob && event.body == "mention capability handshake"
                }
            }
            aEv.wait("mention capability receipt") {
                (it as? Event.DeliveryUpdated)?.takeIf { event ->
                    event.id == handshake && event.state == DeliveryState.DELIVERED
                }
            }

            val capabilityDeadline = System.nanoTime() + 5_000_000_000L
            var capability = alice.groupMentionCapability(group)
            while (!capability.supported) {
                check(System.nanoTime() < capabilityDeadline) {
                    "mention capability did not become supported: ${capability.issues}"
                }
                Thread.sleep(50)
                capability = alice.groupMentionCapability(group)
            }
            assertTrue(capability.issues.isEmpty())

            assertFailsWith<FfiException> {
                alice.sendGroupMention(
                    group,
                    "👩",
                    listOf(MentionSpan(1u, 4u, bobPeer)),
                    capability.reviewToken,
                )
            }
            assertTrue(
                alice.groupMessages(group).isEmpty(),
                "invalid Kotlin byte ranges must fail before persistence or send",
            )

            val text = "Meet 👩🏽‍🚀 @Same name by e\u0301ast"
            val visible = "@Same name"
            val startIndex = text.indexOf(visible)
            val start = text.substring(0, startIndex).toByteArray(Charsets.UTF_8).size.toUInt()
            val end = start + visible.toByteArray(Charsets.UTF_8).size.toUInt()
            val expectedSpans = listOf(MentionSpan(start, end, bobPeer))
            val mentionId = alice.sendGroupMention(
                group,
                text,
                expectedSpans,
                capability.reviewToken,
            )
            val received = bEv.wait("semantic mention") {
                (it as? Event.GroupMessageReceived)?.takeIf { event ->
                    event.id == mentionId && event.group == group &&
                        event.body == text && event.contentKind == ContentKind.MENTION
                }
            }
            assertEquals(expectedSpans, received.mentionSpans)
            val signal = bEv.wait("local mention signal") {
                (it as? Event.MentionReceived)?.takeIf { event -> event.id == received.id }
            }
            assertEquals(received.id, signal.id)

            val stored = bob.groupMessages(group).single { it.id == received.id }
            assertEquals(text, stored.body)
            assertEquals(ContentKind.MENTION, stored.contentKind)
            assertEquals(expectedSpans, stored.mentionSpans)

            val plainId = alice.sendGroup(group, text)
            bEv.wait("plain fallback") {
                (it as? Event.GroupMessageReceived)?.takeIf { event ->
                    event.id == plainId && event.body == text &&
                        event.contentKind == ContentKind.TEXT && event.mentionSpans.isEmpty()
                }
            }
            aEv.wait("plain fallback receipt") {
                (it as? Event.GroupDeliveryUpdated)?.takeIf { event ->
                    event.id == plainId && event.peer == bobPeer &&
                        event.state == DeliveryState.DELIVERED
                }
            }
            Thread.sleep(100)
            assertEquals(1, bEv.count { it is Event.MentionReceived })
        } finally {
            alice.stop()
            bob.stop()
        }
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

    @Test
    fun `private labels are exact typed local and restart safe`() {
        val fixture = labelFixture
        val duplicateName = fixture.getValue("duplicate_name").jsonPrimitive.content
        val colors = fixture.getValue("create_colors").jsonArray.map { it.jsonPrimitive.content }
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "labels", events)
        val queuedBefore = session.status().queued
        val peer = session.addContact("\u2067duplicate\u2069", session.myBundleHex(), emptyList())
        val group = session.createGroup("e\u0301 group", emptyList())
        val first = session.createLabel(duplicateName, colors[0])
        val second = session.createLabel(duplicateName, colors[1])
        assertNotEquals(first.id, second.id)
        assertEquals(
            fixture.getValue("expected_orders").jsonArray.map { it.jsonPrimitive.content.toUInt() },
            listOf(first.order, second.order),
        )
        events.wait("labels changed") { it as? Event.LabelsChanged }

        val peerTarget = LabelTarget(LabelTargetKind.PEER, peer)
        val groupTarget = LabelTarget(LabelTargetKind.GROUP, group)
        val noteTarget = LabelTarget(LabelTargetKind.NOTE_TO_SELF, null)
        listOf(peerTarget, groupTarget, noteTarget).forEach {
            assertTrue(session.assignLabel(first.id, it))
        }
        listOf(groupTarget, noteTarget).forEach {
            assertTrue(session.assignLabel(second.id, it))
        }
        assertFalse(session.assignLabel(second.id, noteTarget))
        assertEquals(3, session.labelMembership(first.id).size)
        assertEquals(
            listOf(LabelTargetKind.PEER, LabelTargetKind.GROUP, LabelTargetKind.NOTE_TO_SELF),
            session.labelMembership(first.id).map { it.target.kind },
        )
        assertEquals(
            fixture.getValue("membership_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.labelMembership(first.id).map { it.target.kind.name.lowercase() },
        )
        assertEquals(
            listOf(first.id),
            session.filterLabels(listOf(first.id, first.id), LabelMatchMode.ANY).selected,
        )
        assertEquals(
            fixture.getValue("match_any_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.filterLabels(listOf(first.id), LabelMatchMode.ANY).conversations
                .map { it.target.kind.name.lowercase() },
        )
        assertEquals(
            fixture.getValue("match_all_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.filterLabels(listOf(first.id, second.id), LabelMatchMode.ALL).conversations
                .map { it.target.kind.name.lowercase() },
        )
        val updated = session.updateLabel(
            first.id,
            fixture.getValue("renamed_name").jsonPrimitive.content,
            fixture.getValue("renamed_color").jsonPrimitive.content,
        )
        assertEquals(first.id, updated.id)
        assertEquals(0u, updated.order)
        val assignmentCount = fixture.getValue("expected_assignment_count").jsonPrimitive.content.toULong()
        assertEquals(assignmentCount, session.labelDeleteAssignmentCount(first.id))
        assertFailsWith<FfiException.Label> { session.deleteLabel(first.id, false) }
        assertFailsWith<IllegalArgumentException> {
            session.createLabel(fixture.getValue("whitespace_only_name").jsonPrimitive.content, "red")
        }
        assertFailsWith<IllegalArgumentException> {
            session.createLabel("valid", fixture.getValue("unsupported_color").jsonPrimitive.content)
        }
        val invalid = assertFailsWith<FfiException.Label> {
            session.label(fixture.getValue("invalid_id").jsonPrimitive.content)
        }
        assertEquals(LabelErrorCode.INVALID_ID, invalid.code)
        assertEquals(queuedBefore, session.status().queued)
        session.stop()

        session = open(dir, "labels", Events())
        assertEquals(listOf(first.id, second.id), session.labels().map { it.id })
        assertEquals(3, session.labelMembership(first.id).size)
        assertEquals(assignmentCount, session.deleteLabel(first.id, true))
        assertEquals(listOf(second.id), session.labelsForConversation(noteTarget).map { it.id })
        assertTrue(session.staleLabels().isEmpty())
        session.stop()
    }

    @Test
    fun `private folders are exact typed composed local and restart safe`() {
        val fixture = folderFixture
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "folders", events)
        val queuedBefore = session.status().queued
        val peer = session.addContact("\u2067duplicate\u2069", session.myBundleHex(), emptyList())
        val group = session.createGroup("e\u0301 group", emptyList())
        val first = session.createFolder(fixture.getValue("duplicate_name").jsonPrimitive.content)
        val second = session.createFolder(fixture.getValue("duplicate_name").jsonPrimitive.content)
        assertNotEquals(first.id, second.id)
        assertEquals(
            fixture.getValue("expected_initial_orders").jsonArray.map { it.jsonPrimitive.content.toUInt() },
            listOf(first.order, second.order),
        )
        events.wait("folders changed") { it as? Event.FoldersChanged }
        assertEquals(
            listOf(second.id, first.id),
            session.reorderFolders(listOf(second.id, first.id)).map { it.id },
        )

        val peerTarget = FolderTarget(FolderTargetKind.PEER, peer)
        val groupTarget = FolderTarget(FolderTargetKind.GROUP, group)
        val noteTarget = FolderTarget(FolderTargetKind.NOTE_TO_SELF, null)
        assertTrue(session.moveToFolder(first.id, peerTarget))
        assertTrue(session.moveToFolder(first.id, groupTarget))
        assertTrue(session.moveToFolder(second.id, noteTarget))
        assertFalse(session.moveToFolder(second.id, noteTarget))
        assertEquals(
            fixture.getValue("first_folder_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.folderMembership(first.id).map { it.target.kind.name.lowercase() },
        )

        val label = session.createLabel("folder composition", "teal")
        assertTrue(session.assignLabel(label.id, LabelTarget(LabelTargetKind.PEER, peer)))
        assertTrue(session.assignLabel(label.id, LabelTarget(LabelTargetKind.GROUP, group)))
        val composed = session.folderConversations(
            FolderSelection(FolderSelectionKind.FOLDER, first.id),
            listOf(label.id),
            LabelMatchMode.ANY,
        )
        assertEquals(
            fixture.getValue("folder_then_any_label_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            composed.conversations.map { it.target.kind.name.lowercase() },
        )
        assertTrue(session.unfileConversation(peerTarget))
        assertFalse(session.unfileConversation(peerTarget))
        assertEquals(
            fixture.getValue("unfiled_after_move_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.folderConversations(
                FolderSelection(FolderSelectionKind.UNFILED, null), emptyList(), LabelMatchMode.ANY,
            ).conversations.map { it.target.kind.name.lowercase() },
        )
        assertEquals(second.id, session.conversationFolder(noteTarget)?.id)
        assertFailsWith<FfiException.Folder> { session.deleteFolder(first.id, false) }
        assertFailsWith<IllegalArgumentException> {
            session.createFolder(fixture.getValue("whitespace_only_name").jsonPrimitive.content)
        }
        val invalid = assertFailsWith<FfiException.Folder> {
            session.folder(fixture.getValue("invalid_id").jsonPrimitive.content)
        }
        assertEquals(FolderErrorCode.INVALID_ID, invalid.code)
        assertEquals(queuedBefore, session.status().queued)
        session.stop()

        session = open(dir, "folders", Events())
        assertEquals(listOf(second.id, first.id), session.folders().map { it.id })
        assertEquals(1uL, session.folderDeleteAssignmentCount(first.id))
        assertEquals(1uL, session.deleteFolder(first.id, true))
        assertTrue(session.folderMembership(session.createFolder(first.name).id).isEmpty())
        assertTrue(session.staleFolders().isEmpty())
        session.stop()
    }

    @Test
    fun `private pins are typed ordered local and restart safe`() {
        val fixture = pinFixture
        val dir = tempDir()
        val events = Events()
        var session = open(dir, "pins", events)
        val queuedBefore = session.status().queued
        val peer = session.addContact("same name", session.myBundleHex(), emptyList())
        val group = session.createGroup("same name", emptyList())
        val targets = listOf(
            PinTarget(PinTargetKind.PEER, peer),
            PinTarget(PinTargetKind.GROUP, group),
            PinTarget(PinTargetKind.NOTE_TO_SELF, null),
        )
        targets.forEach { assertTrue(session.pinConversation(it)) }
        assertFalse(session.pinConversation(targets[0]))
        events.wait("pins changed") { it as? Event.PinsChanged }
        assertEquals(
            fixture.getValue("initial_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            session.pins().map { it.target.kind.name.lowercase() },
        )
        val reordered = targets.reversed()
        assertEquals(reordered, session.reorderPins(reordered).map { it.target })
        val incomplete = assertFailsWith<FfiException.Pin> { session.reorderPins(listOf(targets[0])) }
        assertEquals(PinErrorCode.INVALID_ORDER, incomplete.code)
        val composed = session.pinConversations(
            FolderSelection(FolderSelectionKind.ALL, null), emptyList(), LabelMatchMode.ANY,
        )
        assertEquals(
            fixture.getValue("composed_pinned_target_kinds").jsonArray.map { it.jsonPrimitive.content },
            composed.conversations.take(3).map { it.target.kind.name.lowercase() },
        )
        assertTrue(composed.conversations.take(3).all { it.pinned })
        assertTrue(session.stalePins().isEmpty())
        assertEquals(queuedBefore, session.status().queued)
        session.stop()

        session = open(dir, "pins", Events())
        assertEquals(reordered, session.pins().map { it.target })
        assertTrue(session.unpinConversation(targets[0]))
        assertFalse(session.unpinConversation(targets[0]))
        session.stop()
    }
}
