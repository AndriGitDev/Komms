package komms.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
    fun `base45 matches RFC 9285 vectors and rejects malformed groups`() {
        assertEquals("BB8", base45Encode("AB".encodeToByteArray()))
        assertEquals("%69 VD92EX0", base45Encode("Hello!!".encodeToByteArray()))
        assertEquals("UJCLQE7W581", base45Encode("base-45".encodeToByteArray()))
        assertContentEquals("ietf!".encodeToByteArray(), base45Decode("QED8WEX0"))
        assertNull(base45Decode("A"))
        assertNull(base45Decode(":::"))
    }

    @Test
    fun `pairing QR is compact and legacy hex remains accepted`() {
        val bytes = ByteArray(1_500) { (it * 31).toByte() }
        val hex = hexEncode(bytes)
        val qr = bundleQrText(hex)
        assertTrue(qr.startsWith(BUNDLE_QR_PREFIX))
        assertTrue(qr.length < hex.length)
        assertContentEquals(bytes, decodeBundleInput(qr))
        assertContentEquals(bytes, decodeBundleInput(hex.uppercase()))
    }

    @Test
    fun `animated pairing frames are bounded and assemble out of order`() {
        val bytes = ByteArray(1_584) { (it * 31).toByte() }
        val frames = bundleQrFrames(hexEncode(bytes))
        assertEquals(4, frames.size)
        assertTrue(frames.all { it.startsWith("KOMMS:B2:001F3E5D7C9BBAD9:") })
        assertTrue(frames.all { it.length < 700 })

        val assembler = BundleQrAssembler()
        val order = listOf(2, 0, 3, 1)
        var complete: String? = null
        for (index in order) {
            complete = assembler.accept(frames[index])?.completeText ?: complete
        }
        assertContentEquals(bytes, decodeBundleInput(complete!!))
    }
}
