// Hex helpers shared by every pairing surface. Encoding is lowercase (the
// same convention as `kult` and the desktop app); decoding is
// case-insensitive and whitespace-tolerant, because QR scanners and
// terminals both like to wrap or upcase long strings.

package komms.core

private const val BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \$%*+-./:"
internal const val BUNDLE_QR_PREFIX = "KOMMS:B1:"
internal const val BUNDLE_QR_FRAME_PREFIX = "KOMMS:B2:"
private const val BUNDLE_QR_CHUNK_BYTES = 420
private const val MAX_BUNDLE_QR_PARTS = 64
private const val MAX_BUNDLE_QR_CHARS = 16_384

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

/** RFC 9285 Base45, whose alphabet stays in QR alphanumeric mode. */
internal fun base45Encode(bytes: ByteArray): String = buildString((bytes.size * 3 + 1) / 2) {
    var index = 0
    while (index + 1 < bytes.size) {
        var value = (bytes[index].toInt() and 0xff) * 256 +
            (bytes[index + 1].toInt() and 0xff)
        append(BASE45_ALPHABET[value % 45])
        value /= 45
        append(BASE45_ALPHABET[value % 45])
        append(BASE45_ALPHABET[value / 45])
        index += 2
    }
    if (index < bytes.size) {
        val value = bytes[index].toInt() and 0xff
        append(BASE45_ALPHABET[value % 45])
        append(BASE45_ALPHABET[value / 45])
    }
}

/** Strict RFC 9285 decoding. Invalid groups and oversized QR input fail closed. */
internal fun base45Decode(text: String): ByteArray? {
    if (text.length > MAX_BUNDLE_QR_CHARS || text.length % 3 == 1) return null
    val output = ArrayList<Byte>((text.length * 2) / 3)
    var index = 0
    while (index < text.length) {
        val remaining = text.length - index
        val first = BASE45_ALPHABET.indexOf(text[index])
        val second = if (remaining >= 2) BASE45_ALPHABET.indexOf(text[index + 1]) else -1
        if (first < 0 || second < 0) return null
        if (remaining == 2) {
            val value = first + second * 45
            if (value > 255) return null
            output.add(value.toByte())
            index += 2
        } else {
            val third = BASE45_ALPHABET.indexOf(text[index + 2])
            if (third < 0) return null
            val value = first + second * 45 + third * 45 * 45
            if (value > 65_535) return null
            output.add((value / 256).toByte())
            output.add((value % 256).toByte())
            index += 3
        }
    }
    return output.toByteArray()
}

/** Accept the versioned compact QR payload and legacy/pasteable bundle hex. */
internal fun decodeBundleInput(text: String): ByteArray? =
    if (text.startsWith(BUNDLE_QR_PREFIX)) {
        base45Decode(text.substring(BUNDLE_QR_PREFIX.length))
    } else {
        hexDecode(text)
    }

/** Split one post-quantum bundle into camera-friendly QR frames. */
internal fun encodeBundleQrFrames(bundle: ByteArray): List<String> {
    require(bundle.isNotEmpty()) { "bundle must not be empty" }
    val total = (bundle.size + BUNDLE_QR_CHUNK_BYTES - 1) / BUNDLE_QR_CHUNK_BYTES
    require(total <= MAX_BUNDLE_QR_PARTS) { "bundle needs too many QR frames" }
    val identifier = hexEncode(bundle.copyOfRange(0, minOf(8, bundle.size))).uppercase()
    return (0 until total).map { index ->
        val start = index * BUNDLE_QR_CHUNK_BYTES
        val end = minOf(start + BUNDLE_QR_CHUNK_BYTES, bundle.size)
        "$BUNDLE_QR_FRAME_PREFIX$identifier:${index + 1}:$total:${bundle.size}:" +
            base45Encode(bundle.copyOfRange(start, end))
    }
}

private data class BundleQrFrame(
    val identifier: String,
    val index: Int,
    val total: Int,
    val length: Int,
    val bytes: ByteArray,
)

private fun decodeBundleQrFrame(text: String): BundleQrFrame? {
    if (!text.startsWith(BUNDLE_QR_FRAME_PREFIX)) return null
    val fields = text.substring(BUNDLE_QR_FRAME_PREFIX.length).split(':', limit = 5)
    if (fields.size != 5) return null
    val identifier = fields[0]
    val index = fields[1].toIntOrNull() ?: return null
    val total = fields[2].toIntOrNull() ?: return null
    val length = fields[3].toIntOrNull() ?: return null
    val bytes = base45Decode(fields[4]) ?: return null
    if (
        identifier.isEmpty() ||
        identifier.length > 16 ||
        identifier.any { !it.isDigit() && it !in 'A'..'F' } ||
        total !in 1..MAX_BUNDLE_QR_PARTS ||
        index !in 1..total ||
        length !in 1..MAX_BUNDLE_QR_CHARS ||
        bytes.isEmpty() ||
        bytes.size > BUNDLE_QR_CHUNK_BYTES
    ) {
        return null
    }
    return BundleQrFrame(identifier, index, total, length, bytes)
}

/** One scanner update while collecting an order-independent B2 bundle. */
data class BundleQrScanProgress(
    val received: Int,
    val total: Int,
    val completeText: String? = null,
)

/**
 * Collect animated B2 frames. B1 and legacy single-code values pass through
 * immediately, so the same scanner remains compatible with older releases.
 */
class BundleQrAssembler {
    private var identifier: String? = null
    private var total = 0
    private var length = 0
    private val parts = mutableMapOf<Int, ByteArray>()

    fun accept(text: String): BundleQrScanProgress? {
        if (!text.startsWith(BUNDLE_QR_FRAME_PREFIX)) {
            return BundleQrScanProgress(1, 1, text)
        }
        val frame = decodeBundleQrFrame(text) ?: return null
        if (
            identifier != frame.identifier ||
            total != frame.total ||
            length != frame.length
        ) {
            identifier = frame.identifier
            total = frame.total
            length = frame.length
            parts.clear()
        }
        val previous = parts[frame.index]
        if (previous != null && !previous.contentEquals(frame.bytes)) return null
        parts[frame.index] = frame.bytes
        if (parts.size != total) return BundleQrScanProgress(parts.size, total)

        val bundle = ByteArray(length)
        var offset = 0
        for (index in 1..total) {
            val part = parts[index] ?: return BundleQrScanProgress(parts.size, total)
            if (offset + part.size > bundle.size) return null
            part.copyInto(bundle, offset)
            offset += part.size
        }
        if (offset != length) return null
        val actualIdentifier =
            hexEncode(bundle.copyOfRange(0, minOf(8, bundle.size))).uppercase()
        if (actualIdentifier != identifier) return null
        return BundleQrScanProgress(total, total, BUNDLE_QR_PREFIX + base45Encode(bundle))
    }
}
