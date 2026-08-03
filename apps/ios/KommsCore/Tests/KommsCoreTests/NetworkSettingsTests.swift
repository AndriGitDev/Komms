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
        // One committed snake_case contract is consumed unchanged by every shell.
        let dir = try tempDir()
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let fixture = root.appendingPathComponent("fixtures/operating-mode-settings-v1.json")
        try FileManager.default.copyItem(
            at: fixture,
            to: dir.appendingPathComponent("settings.json")
        )
        let s = try NetworkSettings.load(from: dir)
        XCTAssertEqual("private", s.mode)
        XCTAssertTrue(s.standardDisclosureConfirmed)
        XCTAssertEqual("providers.json", s.providerDirectory)
        XCTAssertEqual(1, s.providerDirectoryRoots.count)
        XCTAssertEqual("https://rendezvous.example.org", s.rendezvous.first?.origin)
        XCTAssertTrue(s.rendezvous.first?.standard == true)
        XCTAssertTrue(s.rendezvous.first?.privateViaTor == true)
        XCTAssertEqual("https://wake.example.org", s.wake.first?.origin)
        XCTAssertTrue(s.wake.first?.standard == true)
        XCTAssertTrue(s.wake.first?.privateViaTor == true)
        XCTAssertEqual("127.0.0.1:9050", s.torProxy)
        XCTAssertEqual(["/ip4/0.0.0.0/udp/7001/quic-v1"], s.listen)
        XCTAssertEqual("radio.local:4403", s.meshtasticTcp)
        XCTAssertEqual(1, s.mailboxes.count)
    }

    func testUnknownOperatingModeFailsClosed() throws {
        let dir = try tempDir()
        try #"{"mode":"public"}"#.write(
            to: dir.appendingPathComponent("settings.json"),
            atomically: true,
            encoding: .utf8
        )
        XCTAssertThrowsError(try NetworkSettings.load(from: dir)) { error in
            XCTAssertTrue(String(describing: error).contains("unsupported operating mode"))
        }
    }
}
