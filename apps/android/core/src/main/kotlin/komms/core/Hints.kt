// Delivery hints as the UI edits them: a `kind` tag plus one string value —
// the exact shape (and error wording) the desktop app's hint editor uses.

package komms.core

import uniffi.kult_ffi.Hint

/** One editable delivery hint. `kind` is `multiaddr`, `relay`, `spool`, or `mesh`. */
data class HintSpec(val kind: String, val value: String) {
    /**
     * Convert to the FFI hint.
     *
     * @throws IllegalArgumentException on an unknown kind, an empty value,
     *   or a mesh value that is neither a node number nor `broadcast`.
     */
    fun toFfi(): Hint {
        val v = value.trim()
        require(v.isNotEmpty()) { "hint value must not be empty" }
        return when (kind) {
            "multiaddr" -> Hint.Multiaddr(v)
            "relay" -> Hint.Relay(v)
            "spool" -> Hint.Spool(v)
            "mesh" -> Hint.Mesh(
                if (v.equals("broadcast", ignoreCase = true)) {
                    UInt.MAX_VALUE
                } else {
                    v.toUIntOrNull() ?: throw IllegalArgumentException(
                        "mesh hint must be a node number or `broadcast`, got `$v`",
                    )
                },
            )
            else -> throw IllegalArgumentException("unknown hint kind `$kind`")
        }
    }
}

/** Convert a whole hint list, failing on the first bad entry. */
fun List<HintSpec>.toFfi(): List<Hint> = map { it.toFfi() }
