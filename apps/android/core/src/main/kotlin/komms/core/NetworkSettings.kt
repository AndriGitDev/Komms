// Network configuration the user can edit before unlocking. Persisted as
// plain JSON next to the store — the same information as `kultd`'s
// command-line flags and **no secrets** (the store passphrase and
// everything inside the store never touch this file).
//
// Field names are snake_case on disk, so a `settings.json` written by the
// desktop app parses here unchanged (and vice versa).

package komms.core

import java.io.File
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A present-but-unreadable settings file. */
class SettingsException(message: String) : Exception(message)

/** The network knobs, mirroring `kultd`'s flags and the desktop app. */
@Serializable
data class NetworkSettings(
    /**
     * Multiaddrs to listen on. The default binds QUIC + TCP on OS-assigned
     * ports; pin a port here for port-forwarding setups.
     */
    val listen: List<String> = listOf(
        "/ip4/0.0.0.0/udp/0/quic-v1",
        "/ip4/0.0.0.0/tcp/0",
    ),
    /**
     * DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
     * discovery then never leaves this node (mDNS still works).
     */
    val bootstrap: List<String> = emptyList(),
    /**
     * Relay to reserve a circuit at when NAT-ed (defaults to the first
     * bootstrap peer when unset).
     */
    val relay: String? = null,
    /** Mailbox relays to check in with. */
    val mailboxes: List<String> = emptyList(),
    /** Volunteer bounded mailbox service for others. */
    @SerialName("serve_mailbox") val serveMailbox: Boolean = false,
    /** Announce/discover on the local network (zero-config LAN delivery). */
    val mdns: Boolean = true,
    /** Also receive from a sneakernet spool directory. */
    val spool: String? = null,
    /**
     * Attach a Meshtastic radio on this USB-serial port (needs a build
     * with the `meshtastic` feature).
     */
    @SerialName("meshtastic_serial") val meshtasticSerial: String? = null,
    /** Attach a Meshtastic radio via its network API (`host:4403`). */
    @SerialName("meshtastic_tcp") val meshtasticTcp: String? = null,
    /**
     * Bridge third-party sealed traffic between mesh and internet
     * (ADR-0009); active only while a radio is attached.
     */
    val bridge: Boolean = true,
) {
    /** Persist to `dataDir` (creating it if needed). */
    fun save(dataDir: File) {
        dataDir.mkdirs()
        fileIn(dataDir).writeText(json.encodeToString(serializer(), this))
    }

    companion object {
        private val json = Json {
            prettyPrint = true
            encodeDefaults = true
            ignoreUnknownKeys = true
        }

        private fun fileIn(dataDir: File) = File(dataDir, "settings.json")

        /**
         * Load from `dataDir`, falling back to defaults when absent. A
         * present-but-corrupt file is a [SettingsException] — silently
         * reverting a user's network configuration would be a lie.
         */
        fun load(dataDir: File): NetworkSettings {
            val file = fileIn(dataDir)
            if (!file.exists()) return NetworkSettings()
            val text = try {
                file.readText()
            } catch (e: java.io.IOException) {
                throw SettingsException("settings.json: ${e.message}")
            }
            try {
                return json.decodeFromString(serializer(), text)
            } catch (e: kotlinx.serialization.SerializationException) {
                throw SettingsException("settings.json is corrupt: ${e.message}")
            }
        }
    }
}
