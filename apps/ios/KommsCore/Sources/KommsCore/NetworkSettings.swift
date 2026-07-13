// Network configuration the user can edit before unlocking. Persisted as
// plain JSON next to the store — the same information as `kultd`'s
// command-line flags and **no secrets** (the store passphrase and
// everything inside the store never touch this file).
//
// Field names are snake_case on disk, so a `settings.json` written by the
// desktop or Android app parses here unchanged (and vice versa).

import Foundation

/// A present-but-unreadable settings file.
public struct SettingsError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// The network knobs, mirroring `kultd`'s flags and the other shells.
public struct NetworkSettings: Codable, Equatable {
    /// Multiaddrs to listen on. The default binds QUIC + TCP on OS-assigned
    /// ports; pin a port here for port-forwarding setups.
    public var listen: [String]
    /// DHT bootstrap peers (multiaddrs with `/p2p/…`). Empty is fine —
    /// discovery then never leaves this node (mDNS still works).
    public var bootstrap: [String]
    /// Relay to reserve a circuit at when NAT-ed (defaults to the first
    /// bootstrap peer when unset).
    public var relay: String?
    /// Mailbox relays to check in with.
    public var mailboxes: [String]
    /// Volunteer bounded mailbox service for others.
    public var serveMailbox: Bool
    /// Announce/discover on the local network (zero-config LAN delivery).
    public var mdns: Bool
    /// Also receive from a sneakernet spool directory.
    public var spool: String?
    /// Attach a Meshtastic radio on this USB-serial port (needs a build
    /// with the `meshtastic` feature).
    public var meshtasticSerial: String?
    /// Attach a Meshtastic radio via its network API (`host:4403`).
    public var meshtasticTcp: String?
    /// Bridge third-party sealed traffic between mesh and internet
    /// (ADR-0009); active only while a radio is attached.
    public var bridge: Bool

    enum CodingKeys: String, CodingKey {
        case listen, bootstrap, relay, mailboxes
        case serveMailbox = "serve_mailbox"
        case mdns, spool
        case meshtasticSerial = "meshtastic_serial"
        case meshtasticTcp = "meshtastic_tcp"
        case bridge
    }

    public init(
        listen: [String] = ["/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"],
        bootstrap: [String] = [],
        relay: String? = nil,
        mailboxes: [String] = [],
        serveMailbox: Bool = false,
        mdns: Bool = true,
        spool: String? = nil,
        meshtasticSerial: String? = nil,
        meshtasticTcp: String? = nil,
        bridge: Bool = true
    ) {
        self.listen = listen
        self.bootstrap = bootstrap
        self.relay = relay
        self.mailboxes = mailboxes
        self.serveMailbox = serveMailbox
        self.mdns = mdns
        self.spool = spool
        self.meshtasticSerial = meshtasticSerial
        self.meshtasticTcp = meshtasticTcp
        self.bridge = bridge
    }

    // Absent fields fall back to the defaults above, so files written by
    // older (or other-platform) builds keep parsing.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = NetworkSettings()
        listen = try c.decodeIfPresent([String].self, forKey: .listen) ?? d.listen
        bootstrap = try c.decodeIfPresent([String].self, forKey: .bootstrap) ?? d.bootstrap
        relay = try c.decodeIfPresent(String.self, forKey: .relay)
        mailboxes = try c.decodeIfPresent([String].self, forKey: .mailboxes) ?? d.mailboxes
        serveMailbox = try c.decodeIfPresent(Bool.self, forKey: .serveMailbox) ?? d.serveMailbox
        mdns = try c.decodeIfPresent(Bool.self, forKey: .mdns) ?? d.mdns
        spool = try c.decodeIfPresent(String.self, forKey: .spool)
        meshtasticSerial = try c.decodeIfPresent(String.self, forKey: .meshtasticSerial)
        meshtasticTcp = try c.decodeIfPresent(String.self, forKey: .meshtasticTcp)
        bridge = try c.decodeIfPresent(Bool.self, forKey: .bridge) ?? d.bridge
    }

    private static func fileIn(_ dataDir: URL) -> URL {
        dataDir.appendingPathComponent("settings.json")
    }

    /// Persist to `dataDir` (creating it if needed).
    public func save(to dataDir: URL) throws {
        try FileManager.default.createDirectory(
            at: dataDir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Self.fileIn(dataDir))
    }

    /// Load from `dataDir`, falling back to defaults when absent. A
    /// present-but-corrupt file is a ``SettingsError`` — silently reverting
    /// a user's network configuration would be a lie.
    public static func load(from dataDir: URL) throws -> NetworkSettings {
        let file = fileIn(dataDir)
        guard FileManager.default.fileExists(atPath: file.path) else {
            return NetworkSettings()
        }
        let data: Data
        do {
            data = try Data(contentsOf: file)
        } catch {
            throw SettingsError("settings.json: \(error)")
        }
        do {
            return try JSONDecoder().decode(NetworkSettings.self, from: data)
        } catch {
            throw SettingsError("settings.json is corrupt: \(error)")
        }
    }
}
