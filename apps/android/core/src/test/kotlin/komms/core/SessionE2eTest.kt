// Android-shell acceptance: two full nodes driven through exactly the layer
// the activities call ([Session]) — pairing via the bundle *hex* a user
// scans or pastes, honest delivery states arriving as listener events,
// verification, settings persistence, and the backup → mnemonic → restore
// flow. Runs on the host JVM against the host-built `libkult_ffi`: same
// embedded runtime the phone runs, no emulator required.

package komms.core

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
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

        // History rows carry what the bubbles render.
        val history = alice.messages(bobPeer)
        assertEquals(1, history.size)
        assertEquals(Direction.OUTBOUND, history[0].direction)
        assertEquals(DeliveryState.DELIVERED, history[0].state)
        val inbox = bob.messages(alicePeer)
        assertEquals(1, inbox.size)
        assertEquals(Direction.INBOUND, inbox[0].direction)
        assertEquals(DeliveryState.RECEIVED, inbox[0].state)

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
