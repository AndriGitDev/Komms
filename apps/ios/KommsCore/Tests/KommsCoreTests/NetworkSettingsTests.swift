import Foundation
import XCTest

@testable import KommsCore

final class NetworkSettingsTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-settings-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testRoundTripsAndDefaultsWhenAbsent() throws {
        let dir = try tempDir()
        let loaded = try NetworkSettings.load(from: dir)
        XCTAssertTrue(loaded.mdns && loaded.bridge && loaded.bootstrap.isEmpty)

        var edited = loaded
        edited.bootstrap = ["/dns4/example.org/udp/4001/quic-v1/p2p/xyz"]
        edited.mdns = false
        try edited.save(to: dir)
        let back = try NetworkSettings.load(from: dir)
        XCTAssertEqual(edited.bootstrap, back.bootstrap)
        XCTAssertFalse(back.mdns)

        try "{ nope".write(
            to: dir.appendingPathComponent("settings.json"),
            atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try NetworkSettings.load(from: dir)) { err in
            let msg = (err as? SettingsError)?.message ?? ""
            XCTAssertTrue(msg.contains("corrupt"), "got: \(msg)")
        }
    }

    func testDesktopSettingsFileParsesUnchanged() throws {
        // Verbatim shape the desktop app writes (serde, snake_case).
        let dir = try tempDir()
        try """
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
        """.write(
            to: dir.appendingPathComponent("settings.json"),
            atomically: true, encoding: .utf8)
        let s = try NetworkSettings.load(from: dir)
        XCTAssertEqual(["/ip4/0.0.0.0/udp/7001/quic-v1"], s.listen)
        XCTAssertEqual("radio.local:4403", s.meshtasticTcp)
        XCTAssertEqual(["/ip4/9.9.9.9/tcp/1/p2p/x"], s.mailboxes)
    }
}
