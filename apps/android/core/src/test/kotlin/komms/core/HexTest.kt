package komms.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class HexTest {
    @Test
    fun `round trips and tolerates noise`() {
        val bytes = byteArrayOf(0x00, 0x7f, 0xab.toByte(), 0xff.toByte())
        val hex = hexEncode(bytes)
        assertEquals("007fabff", hex)
        assertContentEquals(bytes, hexDecode(hex))
        // Scanned input arrives uppercase/wrapped — decoding must not care.
        assertContentEquals(bytes, hexDecode("00 7F\nAB\tff"))
        assertNull(hexDecode("007"))
        assertNull(hexDecode("zz"))
    }

    @Test
    fun `qr payloads are uppercase alphanumeric-mode hex`() {
        assertEquals("00ABFF", bundleQrText("00abff"))
    }
}
