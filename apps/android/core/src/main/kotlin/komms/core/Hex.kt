// Hex helpers shared by every pairing surface. Encoding is lowercase (the
// same convention as `kult` and the desktop app); decoding is
// case-insensitive and whitespace-tolerant, because QR scanners and
// terminals both like to wrap or upcase long strings.

package komms.core

/** Lowercase hex encoding. */
fun hexEncode(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (b in bytes) {
        append(Character.forDigit((b.toInt() shr 4) and 0xf, 16))
        append(Character.forDigit(b.toInt() and 0xf, 16))
    }
}

/**
 * Hex decoding: case-insensitive, whitespace-tolerant. `null` on odd
 * length or non-hex input — callers surface that honestly instead of
 * guessing.
 */
fun hexDecode(s: String): ByteArray? {
    val digits = ArrayList<Int>(s.length)
    for (c in s) {
        if (c.isWhitespace()) continue
        val d = Character.digit(c, 16)
        if (d < 0) return null
        digits.add(d)
    }
    if (digits.size % 2 != 0) return null
    return ByteArray(digits.size / 2) { i ->
        ((digits[2 * i] shl 4) or digits[2 * i + 1]).toByte()
    }
}
