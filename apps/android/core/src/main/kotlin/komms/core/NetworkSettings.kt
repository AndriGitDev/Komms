// Network configuration the user can edit before unlocking. Persisted as
// plain JSON next to the store — the same information as `kultd`'s
// command-line flags and **no secrets** (the store passphrase and
// everything inside the store never touch this file).
//
// Field names are snake_case on disk, so a `settings.json` written by the
// desktop app parses here unchanged (and vice versa).

package komms.core

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A present-but-unreadable settings file. */
class SettingsException(message: String) : Exception(message)

/** The network knobs, mirroring `kultd`'s flags and the desktop app. */
@Serializable
data class RendezvousSetting(
    /** Canonical HTTPS provider origin. */
    val origin: String,
    /** SHA-256 of the provider leaf TLS certificate, lowercase hex. */
    @SerialName("static_key") val staticKey: String,
    /** Whether direct Standard access is allowed. */
    val standard: Boolean,
    /** Whether Private mode may reach it through Tor. */
    @SerialName("private_via_tor") val privateViaTor: Boolean,
)

/** One separately keyed native-wake gateway. */
@Serializable
data class WakeSetting(
    /** Canonical HTTPS provider origin. */
    val origin: String,
    /** SHA-256 of the provider leaf TLS certificate, lowercase hex. */
    @SerialName("static_key") val staticKey: String,
    /** Whether direct Standard access is allowed. */
    val standard: Boolean,
    /** Whether Private mode may reach it through Tor. */
    @SerialName("private_via_tor") val privateViaTor: Boolean,
)

/** The network knobs, mirroring `kultd`'s flags and the desktop app. */
@Serializable
data class NetworkSettings(
    /** `standard`, `private`, or `sovereign`. */
    val mode: String = "standard",
    /** Standard provider disclosure was reviewed before first optional use. */
    @SerialName("standard_disclosure_confirmed")
    val standardDisclosureConfirmed: Boolean = false,
    /** Advanced Sovereign direct-route publication acknowledgement. */
    @SerialName("sovereign_publish_direct_routes")
    val sovereignPublishDirectRoutes: Boolean = false,
    /** Candidate signed provider-directory JSON. */
    @SerialName("provider_directory") val providerDirectory: String? = null,
    /** Trusted offline directory keys, lowercase hex. */
    @SerialName("provider_directory_roots")
    val providerDirectoryRoots: List<String> = emptyList(),
    /** User-selected rendezvous providers. */
    val rendezvous: List<RendezvousSetting> = emptyList(),
    /** User-selected native-wake gateways, never inferred from rendezvous. */
    val wake: List<WakeSetting> = emptyList(),
    /** Explicit loopback Tor SOCKS5 endpoint for Private rendezvous. */
    @SerialName("tor_proxy") val torProxy: String? = null,
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
        require(mode in setOf("standard", "private", "sovereign")) {
            "unsupported operating mode"
        }
        val destination = fileIn(dataDir)
        val temporary = File.createTempFile(".settings-", ".json", dataDir)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(json.encodeToString(serializer(), this).toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            try {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                )
            }
        } finally {
            temporary.delete()
        }
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
                val settings = json.decodeFromString(serializer(), text)
                if (settings.mode !in setOf("standard", "private", "sovereign")) {
                    throw SettingsException("settings.json has an unsupported operating mode")
                }
                return settings
            } catch (e: kotlinx.serialization.SerializationException) {
                throw SettingsException("settings.json is corrupt: ${e.message}")
            }
        }
    }
}
