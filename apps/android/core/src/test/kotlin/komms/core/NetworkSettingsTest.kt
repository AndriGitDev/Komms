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
        // Verbatim shape the desktop app writes (serde, snake_case).
        val dir = tempDir()
        File(dir, "settings.json").writeText(
            """
            {
              "listen": ["/ip4/0.0.0.0/udp/7001/quic-v1"],
              "bootstrap": [],
              "relay": null,
              "mailboxes": ["/ip4/9.9.9.9/tcp/1/p2p/x"],
              "serve_mailbox": false,
              "mdns": true,
              "spool": null,
              "meshtastic_serial": null,
              "meshtastic_tcp": "radio.local:4403",
              "bridge": true
            }
            """.trimIndent(),
        )
        val s = NetworkSettings.load(dir)
        assertEquals(listOf("/ip4/0.0.0.0/udp/7001/quic-v1"), s.listen)
        assertEquals("radio.local:4403", s.meshtasticTcp)
        assertEquals(listOf("/ip4/9.9.9.9/tcp/1/p2p/x"), s.mailboxes)
    }
}
