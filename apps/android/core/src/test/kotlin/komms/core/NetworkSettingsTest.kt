package komms.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NetworkSettingsTest {
    private fun tempDir(): File =
        File.createTempFile("komms-settings", "").let {
            it.delete()
            it.mkdirs()
            it.deleteOnExit()
            it
        }

    @Test
    fun `round trips and defaults when absent`() {
        val dir = tempDir()
        val loaded = NetworkSettings.load(dir)
        assertTrue(loaded.mdns && loaded.bridge && loaded.bootstrap.isEmpty())

        val edited = loaded.copy(
            bootstrap = listOf("/dns4/example.org/udp/4001/quic-v1/p2p/xyz"),
            mdns = false,
        )
        edited.save(dir)
        val back = NetworkSettings.load(dir)
        assertEquals(edited.bootstrap, back.bootstrap)
        assertFalse(back.mdns)

        File(dir, "settings.json").writeText("{ nope")
        val err = assertFailsWith<SettingsException> { NetworkSettings.load(dir) }
        assertTrue("corrupt" in err.message!!, "got: ${err.message}")
    }

    @Test
    fun `desktop settings file parses unchanged`() {
        // One committed snake_case contract is consumed unchanged by every shell.
        val dir = tempDir()
        val root = File(checkNotNull(System.getProperty("komms.repo.root")))
        File(root, "fixtures/operating-mode-settings-v1.json")
            .copyTo(File(dir, "settings.json"))
        val s = NetworkSettings.load(dir)
        assertEquals("private", s.mode)
        assertTrue(s.standardDisclosureConfirmed)
        assertEquals("providers.json", s.providerDirectory)
        assertEquals(1, s.providerDirectoryRoots.size)
        assertEquals("https://rendezvous.example.org", s.rendezvous.single().origin)
        assertTrue(s.rendezvous.single().standard && s.rendezvous.single().privateViaTor)
        assertEquals("127.0.0.1:9050", s.torProxy)
        assertEquals(listOf("/ip4/0.0.0.0/udp/7001/quic-v1"), s.listen)
        assertEquals("radio.local:4403", s.meshtasticTcp)
        assertEquals(1, s.mailboxes.size)
    }

    @Test
    fun `unknown operating mode fails closed`() {
        val dir = tempDir()
        File(dir, "settings.json").writeText("""{"mode":"public"}""")
        val err = assertFailsWith<SettingsException> { NetworkSettings.load(dir) }
        assertTrue("unsupported operating mode" in err.message!!)
    }
}
