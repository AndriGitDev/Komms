package komms.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import uniffi.kult_ffi.Hint

class HintsTest {
    @Test
    fun `hints convert and reject garbage`() {
        assertTrue(HintSpec("multiaddr", "/ip4/1.2.3.4/tcp/1").toFfi() is Hint.Multiaddr)
        assertEquals(Hint.Mesh(UInt.MAX_VALUE), HintSpec("mesh", "broadcast").toFfi())
        assertEquals(Hint.Mesh(42u), HintSpec("mesh", "42").toFfi())
        assertTrue(HintSpec("relay", "/ip4/1.2.3.4/tcp/1/p2p/x").toFfi() is Hint.Relay)
        assertTrue(HintSpec("spool", "/mnt/usb/spool").toFfi() is Hint.Spool)

        val bad = assertFailsWith<IllegalArgumentException> {
            HintSpec("mesh", "not-a-number").toFfi()
        }
        assertTrue("node number" in bad.message!!, "got: ${bad.message}")
        assertFailsWith<IllegalArgumentException> { HintSpec("teleport", "x").toFfi() }
        assertFailsWith<IllegalArgumentException> { HintSpec("relay", "  ").toFfi() }
    }
}
