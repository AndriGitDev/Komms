// iOS-shell acceptance: two full nodes driven through exactly the layer the
// SwiftUI views call (`Session`) — pairing via the bundle *hex* a user scans
// or pastes, honest delivery states arriving as listener events,
// verification, settings persistence, and the backup → mnemonic → restore
// flow. Runs on the host (Linux or macOS) against the host-built
// `libkult_ffi`: same embedded runtime the phone runs, no simulator required.

import Foundation
import XCTest

@testable import KommsCore

private struct Timeout: Error, CustomStringConvertible {
    let what: String
    var description: String { "timed out waiting for \(what)" }
}

private struct ContactRenameParityFixture: Decodable {
    let decomposedName: String
    let normalizedName: String
    let duplicateName: String

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b5-contact-rename-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct TextFormattingParityFixture: Decodable {
    struct Highlight: Decodable { let start: UInt32; let end: UInt32 }
    struct Case: Decodable {
        let name: String
        let source: String
        let highlights: [Highlight]
        let plainText: String
        let usedFallback: Bool
        let blockKinds: [String]
    }
    let cases: [Case]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b9-text-formatting-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct FilePresentationParityFixture: Decodable {
    struct Case: Decodable {
        let mediaType: String
        let filename: String?
        let kind: String
        let openPolicy: String
        let warnings: [String]
    }
    let cases: [Case]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/c1-file-presentation-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct MessageEditParityFixture: Decodable {
    struct Version: Decodable {
        let id: String
        let revision: UInt64
        let text: String
    }
    struct Case: Decodable {
        let targetAuthor: String
        let targetContentId: String
        let expectedVersions: [Version]
        let winningRevision: UInt64
        let winningText: String
    }
    let schema: String
    let contentFormat: UInt8
    let contentKind: UInt8
    let maximumTextBytes: UInt64
    let maximumLocalEdits: UInt64
    let `case`: Case

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/c3-message-edit-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct EphemeralParityFixture: Decodable {
    let schema: String
    let contentKind: UInt8
    let textLifetimes: [UInt64]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/c4-ephemeral-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private func fileKindName(_ kind: AttachmentFileKind) -> String {
    switch kind {
    case .image: "image"
    case .audio: "audio"
    case .video: "video"
    case .document: "document"
    case .archive: "archive"
    case .executable: "executable"
    case .other: "other"
    }
}

private func openPolicyName(_ policy: AttachmentOpenPolicy) -> String {
    switch policy {
    case .protectedMedia: "protected_media"
    case .externalOpen: "external_open"
    case .exportOnly: "export_only"
    }
}

private func fileWarningName(_ warning: AttachmentFileWarning) -> String {
    switch warning {
    case .mediaTypeMismatch: "media_type_mismatch"
    case .dangerousType: "dangerous_type"
    case .unrecognizedType: "unrecognized_type"
    case .missingFilename: "missing_filename"
    }
}

private struct LabelParityFixture: Decodable {
    let duplicateName: String
    let createColors: [String]
    let expectedOrders: [UInt32]
    let membershipTargetKinds: [String]
    let matchAnyTargetKinds: [String]
    let matchAllTargetKinds: [String]
    let renamedName: String
    let renamedColor: String
    let whitespaceOnlyName: String
    let unsupportedColor: String
    let invalidId: String
    let expectedAssignmentCount: UInt64

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b18-label-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct FolderParityFixture: Decodable {
    let duplicateName: String
    let expectedInitialOrders: [UInt32]
    let firstFolderTargetKinds: [String]
    let folderThenAnyLabelTargetKinds: [String]
    let unfiledAfterMoveTargetKinds: [String]
    let whitespaceOnlyName: String
    let invalidId: String
    let expectedDeleteAssignmentCount: UInt64

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b10-folder-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct PinParityFixture: Decodable {
    let initialTargetKinds: [String]
    let composedPinnedTargetKinds: [String]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b11-pin-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct ThemeParityFixture: Decodable {
    let preferenceKey: String
    let preferences: [String]
    let `default`: String
    let semanticRoles: [String]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b12-theme-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct CustomIconParityFixture: Decodable {
    let targetTypes: [String]
    let bundledGlyphs: [String]

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b13-custom-icon-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private struct ScreenSecurityParityFixture: Decodable {
    struct Platform: Decodable {
        let capturePrevention: String
        let backgroundObscuring: String
        let captureDetection: String
        let rapidLock: String
    }
    struct Platforms: Decodable {
        let android: Platform
        let ios: Platform
        let desktop: Platform
    }
    let platforms: Platforms
    let iosUniversalScreenshotBlocking: Bool

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b14-screen-security-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private func screenSecurityLevelName(_ level: ScreenSecurityLevel) -> String {
    switch level {
    case .platformEnforced: "platform_enforced"
    case .bestEffort: "best_effort"
    case .unavailable: "unavailable"
    }
}

private struct IncognitoKeyboardParityFixture: Decodable {
    struct Platform: Decodable {
        let personalizedLearning: String
        let suggestions: String
        let spellcheck: String
        let secretTextMasking: String
    }
    struct Platforms: Decodable {
        let android: Platform
        let ios: Platform
        let desktop: Platform
    }
    let appliesBeforeUnlock: Bool
    let protectedFields: [String]
    let platforms: Platforms

    static func load() throws -> Self {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("fixtures/b15-incognito-keyboard-parity.json"))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Self.self, from: data)
    }
}

private func incognitoKeyboardLevelName(_ level: IncognitoKeyboardLevel) -> String {
    switch level {
    case .platformEnforced: "platform_enforced"
    case .platformRequested: "platform_requested"
    case .bestEffort: "best_effort"
    case .unavailable: "unavailable"
    }
}

private func labelTargetKindName(_ kind: LabelTargetKind) -> String {
    switch kind {
    case .peer: "peer"
    case .group: "group"
    case .noteToSelf: "note_to_self"
    }
}

private func folderTargetKindName(_ kind: FolderTargetKind) -> String {
    switch kind {
    case .peer: "peer"
    case .group: "group"
    case .noteToSelf: "note_to_self"
    }
}

private func pinTargetKindName(_ kind: PinTargetKind) -> String {
    switch kind {
    case .peer: "peer"
    case .group: "group"
    case .noteToSelf: "note_to_self"
    }
}

/// Collects node events exactly as the app's sink would.
private final class Events: @unchecked Sendable {
    private var all: [Event] = []
    private let lock = NSLock()

    var sink: EventSink {
        { event in
            self.lock.lock()
            self.all.append(event)
            self.lock.unlock()
        }
    }

    func wait<T>(_ what: String, _ pred: (Event) -> T?) throws -> T {
        let deadline = Date().addingTimeInterval(30)
        while true {
            lock.lock()
            let hit = all.compactMap(pred).first
            lock.unlock()
            if let hit { return hit }
            guard Date() < deadline else { throw Timeout(what: what) }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    func count(_ pred: (Event) -> Bool) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return all.filter(pred).count
    }
}

/// Hermetic settings: loopback QUIC only, no mDNS — hints are explicit.
private func testSettings() -> NetworkSettings {
    NetworkSettings(listen: ["/ip4/127.0.0.1/udp/0/quic-v1"], mdns: false)
}

private func open(_ dir: URL, _ name: String, _ events: Events) throws -> Session {
    // Mirror the unlock flow: persist settings, then boot.
    let dataDir = dir.appendingPathComponent(name)
    let settings = testSettings()
    try settings.save(to: dataDir)
    return try Session.open(
        dataDir: dataDir, passphrase: "test-passphrase",
        settings: settings, kdf: .mobile, sink: events.sink)
}

/// Poll status until a listen address is bound.
private func listenAddr(_ session: Session) throws -> String {
    let deadline = Date().addingTimeInterval(5)
    while true {
        if let addr = try session.status().listen.first { return addr }
        guard Date() < deadline else { throw Timeout(what: "a listen address") }
        Thread.sleep(forTimeInterval: 0.05)
    }
}

private func multiaddrHint(_ addr: String) -> [HintSpec] { [HintSpec("multiaddr", addr)] }

private func canonicalAudio(samples: Int = 1_600) -> Data {
    func le16(_ value: Int) -> [UInt8] {
        [UInt8(value & 0xff), UInt8((value >> 8) & 0xff)]
    }
    func le32(_ value: Int) -> [UInt8] {
        le16(value & 0xffff) + le16((value >> 16) & 0xffff)
    }
    let dataBytes = samples * 2
    var bytes = Data("RIFF".utf8)
    bytes.append(contentsOf: le32(36 + dataBytes))
    bytes.append(Data("WAVEfmt ".utf8))
    bytes.append(contentsOf: le32(16))
    bytes.append(contentsOf: le16(1) + le16(1) + le32(16_000) + le32(32_000))
    bytes.append(contentsOf: le16(2) + le16(16))
    bytes.append(Data("data".utf8))
    bytes.append(contentsOf: le32(dataBytes))
    for index in 0..<samples {
        bytes.append(contentsOf: le16((index % 2_000) - 1_000))
    }
    return bytes
}

private func nativeAudioWithMetadata(_ canonical: Data) -> Data {
    func le32(_ value: Int) -> [UInt8] {
        [UInt8(value & 0xff), UInt8((value >> 8) & 0xff),
         UInt8((value >> 16) & 0xff), UInt8((value >> 24) & 0xff)]
    }
    var bytes = Data("RIFF".utf8)
    bytes.append(contentsOf: le32(canonical.count + 4))
    bytes.append(contentsOf: canonical[8..<36])
    bytes.append(Data("LIST".utf8))
    bytes.append(contentsOf: le32(4))
    bytes.append(Data("leak".utf8))
    bytes.append(contentsOf: canonical[36..<canonical.count])
    return bytes
}

private func imageSource() -> Data {
    Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAQAAAADAgMAAADJmkZVAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAMUExURRAgMHhwaODAoP///zpo6RQAAAADdFJOU9nZ2dfb3kcAAAABYktHRAMRDEzyAAAAB3RJTUUH6gcOFCoDxLmvWQAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0wNy0xNFQyMDo0MjowMyswMDowMANuTXIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMDctMTRUMjA6NDI6MDMrMDA6MDByM/XOAAAAKHRFWHRkYXRlOnRpbWVzdGFtcAAyMDI2LTA3LTE0VDIwOjQyOjAzKzAwOjAwJSbUEQAAAA5JREFUCNdjYGAIZVgFAAGvAQCmulOkAAAAAElFTkSuQmCC")!
}

private func imageRecipe() -> ImageEditRecipe {
    ImageEditRecipe(
        crop: ImageCrop(x: 1, y: 0, width: 3, height: 3),
        rotationQuarterTurns: 1,
        regions: [
            ImageEditRegion(
                kind: .pixelate, x: 0, y: 0, width: 2, height: 2, strength: 2),
            ImageEditRegion(
                kind: .blur, x: 1, y: 0, width: 2, height: 3, strength: 1),
        ])
}

final class SessionE2eTests: XCTestCase {
    func testMessageEditSharedFixtureHasCanonicalWireAndWinner() throws {
        let fixture = try MessageEditParityFixture.load()
        XCTAssertEqual("komms-message-edit-parity-v1", fixture.schema)
        XCTAssertEqual(1, fixture.contentFormat)
        XCTAssertEqual(4, fixture.contentKind)
        XCTAssertEqual(16_384, fixture.maximumTextBytes)
        XCTAssertEqual(64, fixture.maximumLocalEdits)
        XCTAssertEqual(64, fixture.case.targetAuthor.count)
        XCTAssertEqual(32, fixture.case.targetContentId.count)
        XCTAssertEqual([0, 1, 2, 2], fixture.case.expectedVersions.map(\.revision))
        XCTAssertEqual(2, fixture.case.winningRevision)
        XCTAssertEqual("deterministic winner", fixture.case.winningText)
        XCTAssertEqual(fixture.case.winningText, fixture.case.expectedVersions.last?.text)
        XCTAssertTrue(fixture.case.expectedVersions.allSatisfy { $0.id.count == 32 })
    }

    func testFilePresentationMatchesSharedFailClosedFixture() throws {
        let fixture = try FilePresentationParityFixture.load()
        for record in fixture.cases {
            let result = attachmentFilePresentation(
                mediaType: record.mediaType,
                filename: record.filename)
            XCTAssertEqual(record.kind, fileKindName(result.kind))
            XCTAssertEqual(record.openPolicy, openPolicyName(result.openPolicy))
            XCTAssertEqual(record.warnings, result.warnings.map(fileWarningName))
        }
    }

    func testTextFormattingMatchesSharedInertCorpus() throws {
        let fixture = try TextFormattingParityFixture.load()
        let session = try open(try tempDir(), "text-formatting", Events())
        for record in fixture.cases {
            let formatted = try session.formatText(
                source: record.source,
                highlights: record.highlights.map {
                    TextFormatHighlight(start: $0.start, end: $0.end)
                })
            XCTAssertEqual(record.source, formatted.source, record.name)
            XCTAssertEqual(record.plainText, formatted.plainText, record.name)
            XCTAssertEqual(record.usedFallback, formatted.usedFallback, record.name)
            XCTAssertEqual(record.blockKinds, formatted.blocks.map { block in
                switch block.kind {
                case .paragraph: "paragraph"
                case .quote: "quote"
                case .unorderedListItem: "unordered_list_item"
                case .orderedListItem: "ordered_list_item"
                case .codeBlock: "code_block"
                }
            }, record.name)
        }
        session.stop()
    }

    func testPrivateContactRenameIsNormalizedWarnedDuplicateCapableAndRestartSafe() throws {
        let fixture = try ContactRenameParityFixture.load()
        let dir = try tempDir()
        let events = Events()
        var alice = try open(dir, "contact-rename-alice", events)
        let bob = try open(dir, "contact-rename-bob", Events())
        _ = try alice.addContact(name: fixture.duplicateName, bundleHex: alice.myBundleHex(), hints: [])
        let bobPeer = try alice.addContact(name: "Bob", bundleHex: bob.myBundleHex(), hints: [])
        let queuedBefore = try alice.status().queued

        let normalized = try alice.renameContact(
            peer: bobPeer, name: fixture.decomposedName, acceptWarnings: false)
        XCTAssertEqual(fixture.normalizedName, normalized.normalizedName)
        XCTAssertTrue(normalized.changedByNormalization)

        let duplicate = try alice.assessContactName(peer: bobPeer, name: fixture.duplicateName)
        XCTAssertEqual(1, duplicate.duplicateCount)
        XCTAssertEqual([.duplicateName], duplicate.warnings)
        XCTAssertThrowsError(try alice.renameContact(
            peer: bobPeer, name: fixture.duplicateName, acceptWarnings: false))
        _ = try alice.renameContact(
            peer: bobPeer, name: fixture.duplicateName, acceptWarnings: true)
        XCTAssertEqual(2, try alice.contacts().filter { $0.name == fixture.duplicateName }.count)
        _ = try events.wait("contact renamed") { event -> String? in
            if case .contactRenamed(let peer, _) = event, peer == bobPeer { return peer }
            return nil
        }
        XCTAssertEqual(queuedBefore, try alice.status().queued)
        alice.stop()

        alice = try open(dir, "contact-rename-alice", Events())
        XCTAssertEqual(
            fixture.duplicateName,
            try alice.contacts().first(where: { $0.peer == bobPeer })?.name)
        alice.stop()
        bob.stop()
    }

    func testIncognitoKeyboardPolicyAndEveryIOSFieldAreCoveredBeforeUnlock() throws {
        let fixture = try IncognitoKeyboardParityFixture.load()
        let policy = incognitoKeyboardPolicy(platform: .ios)
        XCTAssertTrue(policy.alwaysOn)
        XCTAssertTrue(policy.appliesBeforeUnlock)
        XCTAssertEqual(fixture.protectedFields, policy.protectedFields)
        XCTAssertEqual(
            fixture.platforms.ios.personalizedLearning,
            incognitoKeyboardLevelName(policy.personalizedLearning))
        XCTAssertEqual(
            fixture.platforms.ios.secretTextMasking,
            incognitoKeyboardLevelName(policy.secretTextMasking))
        XCTAssertTrue(policy.limitations.contains(where: { $0.contains("third-party") }))

        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let source = root.appendingPathComponent("apps/ios/KommsApp/Sources")
        let files = try FileManager.default.contentsOfDirectory(at: source, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
        let text = try files.map { try String(contentsOf: $0, encoding: .utf8) }.joined(separator: "\n")
        let occurrences = { (needle: String) in text.components(separatedBy: needle).count - 1 }
        let editors = occurrences("TextField(") + occurrences("SecureField(") + occurrences("TextEditor(")
        XCTAssertEqual(24, editors)
        XCTAssertEqual(editors, occurrences(".incognitoKeyboard("))
        let gate = try String(contentsOf: source.appendingPathComponent("GateView.swift"), encoding: .utf8)
        XCTAssertTrue(gate.contains("SecureField(\"24-word mnemonic\""))
    }

    func testScreenSecurityPolicyIsAvailableBeforeUnlockAndDoesNotOverclaimIOS() throws {
        let fixture = try ScreenSecurityParityFixture.load()
        let policy = screenSecurityPolicy(platform: .ios)
        XCTAssertTrue(policy.alwaysOn)
        XCTAssertEqual(
            fixture.platforms.ios.capturePrevention,
            screenSecurityLevelName(policy.capturePrevention))
        XCTAssertEqual(
            fixture.platforms.ios.backgroundObscuring,
            screenSecurityLevelName(policy.backgroundObscuring))
        XCTAssertEqual(
            fixture.platforms.ios.captureDetection,
            screenSecurityLevelName(policy.captureDetection))
        XCTAssertFalse(fixture.iosUniversalScreenshotBlocking)
        XCTAssertTrue(policy.limitations.contains(where: { $0.contains("screenshots") }))
    }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-e2e-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testIOSEphemeralControlsMatchSharedContract() throws {
        let fixture = try EphemeralParityFixture.load()
        XCTAssertEqual("komms-c4-ephemeral-parity-v1", fixture.schema)
        XCTAssertEqual(5, fixture.contentKind)
        XCTAssertEqual([60, 3_600, 86_400, 604_800, 2_592_000], fixture.textLifetimes)

        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { root.deleteLastPathComponent() }
        let app = root.appendingPathComponent("apps/ios/KommsApp/Sources")
        let source = try ["AppModel.swift", "ChatView.swift", "GroupChatView.swift", "AttachmentView.swift"]
            .map { try String(contentsOf: app.appendingPathComponent($0), encoding: .utf8) }
            .joined(separator: "\n")
        XCTAssertTrue(source.contains("sendDisappearing"))
        XCTAssertTrue(source.contains("sendGroupDisappearing"))
        XCTAssertTrue(source.contains("consumeViewOnceAttachment"))
        XCTAssertTrue(source.contains("!attachment.viewOnce"))
    }

    func testPrivateThemeDefaultsPersistsRestartsAndEmitsOneLocalEvent() throws {
        let fixture = try ThemeParityFixture.load()
        XCTAssertEqual("appearance.theme", fixture.preferenceKey)
        XCTAssertEqual(["system", "light", "dark"], fixture.preferences)
        XCTAssertEqual("system", fixture.default)
        XCTAssertEqual(themeSemanticRoles, fixture.semanticRoles)
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "theme", events)
        let queued = try session.status().queued
        XCTAssertEqual(.system, try session.theme().preference)
        XCTAssertFalse(try session.theme().persisted)
        XCTAssertTrue(try session.setTheme(.dark))
        XCTAssertFalse(try session.setTheme(.dark))
        _ = try events.wait("theme changed") { event -> Void? in
            if case .themeChanged = event { return () }
            return nil
        }
        XCTAssertEqual(queued, try session.status().queued)
        session.stop()

        session = try open(dir, "theme", Events())
        XCTAssertEqual(.dark, try session.theme().preference)
        XCTAssertTrue(try session.theme().persisted)
        session.stop()
    }

    func testPrivateCustomIconsAreCanonicalLocalAndDurableThroughIOSSession() throws {
        let fixture = try CustomIconParityFixture.load()
        XCTAssertEqual(["contact", "group", "folder", "note_to_self"], fixture.targetTypes)
        XCTAssertEqual("compass", fixture.bundledGlyphs.last)
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "icons", events)
        let queued = try session.status().queued
        let note = CustomIconTarget(kind: .noteToSelf, id: nil)
        XCTAssertNil(try session.customIcon(target: note))
        let noteIcon = try session.setCustomIcon(target: note, glyph: "compass")
        XCTAssertEqual("image/png", noteIcon.mediaType)
        XCTAssertEqual(256, noteIcon.width)
        XCTAssertEqual(256, noteIcon.height)
        XCTAssertEqual(Data([137, 80, 78, 71, 13, 10, 26, 10]), Data(noteIcon.bytes.prefix(8)))
        _ = try events.wait("custom icons changed") { event -> Void? in
            if case .customIconsChanged = event { return () }
            return nil
        }

        let folder = try session.createFolder(name: "Icon target")
        let folderTarget = CustomIconTarget(kind: .folder, id: folder.id)
        let source = dir.appendingPathComponent("ios-icon.png")
        try imageSource().write(to: source)
        let folderIcon = try session.setCustomIcon(
            target: folderTarget,
            source: source,
            crop: CustomIconCrop(x: 0, y: 0, width: 3, height: 3))
        XCTAssertNotEqual(noteIcon.bytes, folderIcon.bytes)
        let usage = try session.customIconUsage()
        XCTAssertEqual(2, usage.records)
        XCTAssertEqual(UInt64(noteIcon.bytes.count + folderIcon.bytes.count), usage.bytes)
        XCTAssertEqual(queued, try session.status().queued)
        XCTAssertTrue(try session.clearCustomIcon(target: folderTarget))
        XCTAssertFalse(try session.clearCustomIcon(target: folderTarget))
        XCTAssertNil(try session.customIcon(target: folderTarget))
        session.stop()

        session = try open(dir, "icons", Events())
        XCTAssertEqual(noteIcon.bytes, try XCTUnwrap(session.customIcon(target: note)).bytes)
        session.stop()
    }

    func testTwoPhonesPairByScannedBundleHexAndMessage() throws {
        let dir = try tempDir()
        let aEv = Events()
        let bEv = Events()
        let alice = try open(dir, "alice", aEv)
        let bob = try open(dir, "bob", bEv)

        // The status header's first snapshot is honest: nothing queued,
        // nothing bridged, no contacts, and a kult address to show.
        let status = try alice.status()
        XCTAssertTrue(status.address.hasPrefix("kk1"))
        XCTAssertEqual(0, status.queued)
        XCTAssertEqual(0, status.transit)
        XCTAssertEqual(0, status.contacts)

        // Pairing exactly as the UI does it: each side renders its bundle
        // hex as a QR (uppercase, alphanumeric mode), the other scans it.
        let aBundle = try alice.myBundleHex()
        let bBundle = try bob.myBundleHex()
        XCTAssertNotNil(hexDecode(aBundle))
        let scanned = bundleQrText(bBundle) // what the camera hands back

        let aAddr = try listenAddr(alice)
        let bAddr = try listenAddr(bob)
        let bobPeer = try alice.addContact(name: "bob", bundleHex: scanned, hints: multiaddrHint(bAddr))
        let alicePeer = try bob.addContact(name: "alice", bundleHex: aBundle, hints: multiaddrHint(aAddr))

        // Send → the event stream walks the honest ladder.
        let formattedSource = "**hello** from iOS ![pixel](https://invalid.test/p.png)"
        let msgId = try alice.send(peer: bobPeer, body: formattedSource)
        let got = try bEv.wait("bob's message event") { event -> (peer: String, body: String)? in
            if case let .messageReceived(peer, _, _, body, _, _) = event { return (peer, body) }
            return nil
        }
        XCTAssertEqual(alicePeer, got.peer)
        XCTAssertEqual(formattedSource, got.body)
        _ = try aEv.wait("alice's delivered event") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event, id == msgId, state == .delivered {
                return ()
            }
            return nil
        }
        XCTAssertTrue(
            try alice.audioCarrierExplanation(peer: bobPeer)
                .contains("fresh realtime or bulk link"))

        // History rows carry what the bubbles render.
        let history = try alice.messages(peer: bobPeer)
        XCTAssertEqual(1, history.count)
        XCTAssertEqual(.outbound, history[0].direction)
        XCTAssertEqual(.delivered, history[0].state)
        XCTAssertEqual(formattedSource, history[0].body)
        let inbox = try bob.messages(peer: alicePeer)
        XCTAssertEqual(1, inbox.count)
        XCTAssertEqual(.inbound, inbox[0].direction)
        XCTAssertEqual(.received, inbox[0].state)
        XCTAssertEqual(formattedSource, inbox[0].body)

        Thread.sleep(forTimeInterval: 0.3)
        let editable = try alice.send(peer: bobPeer, body: "iOS edit original")
        _ = try bEv.wait("Bob's canonical iOS Text") { event -> Void? in
            if case let .messageReceived(_, id, _, _, kind, _) = event,
               id == editable, kind == .text { return () }
            return nil
        }
        _ = try aEv.wait("iOS editable delivery") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event,
               id == editable, state == .delivered { return () }
            return nil
        }
        let edit = try alice.editMessage(
            peer: bobPeer,
            targetAuthor: alicePeer,
            targetContentId: editable,
            text: "iOS edit revised")
        _ = try bEv.wait("iOS pairwise edit refresh") { event -> Void? in
            if case let .messageEdited(peer, targetContentId) = event,
               peer == alicePeer, targetContentId == editable { return () }
            return nil
        }
        _ = try aEv.wait("iOS edit delivery") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event,
               id == edit, state == .delivered { return () }
            return nil
        }
        for messages in [try alice.messages(peer: bobPeer), try bob.messages(peer: alicePeer)] {
            XCTAssertEqual(2, messages.count, "Edit events are not standalone rows")
            let message = try XCTUnwrap(messages.first(where: { $0.id == editable }))
            XCTAssertEqual("iOS edit revised", message.body)
            XCTAssertTrue(message.edited)
            XCTAssertEqual(1, message.editRevision)
            XCTAssertEqual(["iOS edit original", "iOS edit revised"], message.versions.map(\.body))
        }

        // The document picker grants a security-scoped URL; the app stages a
        // bounded app-private copy before Session imports it. The render-safe
        // transfer surface exposes exact authenticated metadata and progress.
        let attachmentBytes = Data("iOS attachment bytes\u{0}exact".utf8)
        let previewBytes = Data("iOS local jpeg preview".utf8)
        let source = dir.appendingPathComponent("ios-source.bin")
        let preview = dir.appendingPathComponent("ios-preview.jpg")
        try attachmentBytes.write(to: source)
        try previewBytes.write(to: preview)
        let contentId = try alice.sendAttachmentWithPreview(
            peer: bobPeer,
            path: source,
            mediaType: "application/octet-stream",
            filename: "field-notes.bin",
            preview: preview)
        let outbound = try XCTUnwrap(
            alice.attachments().first(where: { $0.contentId == contentId }))
        XCTAssertEqual(.pairwise, outbound.conversation)
        XCTAssertEqual(.outbound, outbound.direction)
        XCTAssertEqual(2, outbound.objects.count)
        XCTAssertEqual("field-notes.bin", outbound.objects.first?.filename)
        XCTAssertEqual(UInt64(attachmentBytes.count), outbound.objects.first?.totalBytes)
        XCTAssertEqual("application/octet-stream", outbound.objects.first?.mediaType)

        try alice.pauseAttachment(transfer: outbound.transferId)
        XCTAssertEqual(
            .paused,
            try alice.attachments().first(where: { $0.transferId == outbound.transferId })?.state)
        try alice.resumeAttachment(transfer: outbound.transferId)

        let offer = try bEv.wait("pairwise attachment offer") { event -> Attachment? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.contentId == contentId,
               attachment.direction == .inbound,
               attachment.peer == alicePeer {
                return attachment
            }
            return nil
        }
        XCTAssertEqual(.awaitingConsent, offer.state)
        XCTAssertEqual(0, offer.objects.first?.verifiedBytes)
        try bob.acceptAttachment(transfer: offer.transferId)
        _ = try bEv.wait("pairwise attachment completion") { event -> Void? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.transferId == offer.transferId,
               attachment.state == .complete {
                return ()
            }
            return nil
        }
        let received = try XCTUnwrap(
            bob.attachments().first(where: { $0.transferId == offer.transferId }))
        XCTAssertEqual(UInt64(attachmentBytes.count), received.objects.first?.verifiedBytes)
        XCTAssertEqual(UInt64(previewBytes.count), received.objects.last?.verifiedBytes)

        // iOS exports to a unique protected source URL before presenting the
        // system destination picker. The node refuses an existing path.
        let exported = dir.appendingPathComponent("ios-export.bin")
        try bob.exportAttachment(transfer: offer.transferId, to: exported)
        XCTAssertEqual(attachmentBytes, try Data(contentsOf: exported))
        let exportedPreview = dir.appendingPathComponent("ios-export-preview.jpg")
        try bob.exportAttachmentPreview(transfer: offer.transferId, to: exportedPreview)
        XCTAssertEqual(previewBytes, try Data(contentsOf: exportedPreview))
        XCTAssertThrowsError(
            try bob.exportAttachment(transfer: offer.transferId, to: exported))
        XCTAssertEqual(attachmentBytes, try Data(contentsOf: exported))

        try bob.rejectAttachment(transfer: offer.transferId)
        XCTAssertEqual(
            .rejected,
            try bob.attachments().first(where: { $0.transferId == offer.transferId })?.state)
        try alice.cancelAttachment(transfer: outbound.transferId)
        XCTAssertEqual(
            .cancelled,
            try alice.attachments().first(where: { $0.transferId == outbound.transferId })?.state)

        let audioBytes = canonicalAudio()
        let nativeAudio = dir.appendingPathComponent("ios-native-audio.wav")
        try nativeAudioWithMetadata(audioBytes).write(to: nativeAudio)
        let audioSource = dir.appendingPathComponent("ios-audio-message.wav")
        XCTAssertEqual(
            100,
            try alice.canonicalizeAudio(source: nativeAudio, destination: audioSource).durationMs)
        XCTAssertEqual(audioBytes, try Data(contentsOf: audioSource))
        XCTAssertEqual(100, try alice.probeAudio(audioSource).durationMs)
        let audioContent = try alice.sendAttachment(
            peer: bobPeer, path: audioSource, mediaType: "audio/wav",
            filename: "audio-message.wav")
        let audioOffer = try bEv.wait("pairwise audio offer") { event -> Attachment? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.contentId == audioContent,
               attachment.direction == .inbound {
                return attachment
            }
            return nil
        }
        try bob.acceptAttachment(transfer: audioOffer.transferId)
        _ = try bEv.wait("pairwise audio completion") { event -> Void? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.transferId == audioOffer.transferId,
               attachment.state == .complete { return () }
            return nil
        }
        let audioExport = dir.appendingPathComponent("ios-audio-received.wav")
        try bob.exportAttachment(transfer: audioOffer.transferId, to: audioExport)
        XCTAssertEqual(audioBytes, try Data(contentsOf: audioExport))
        XCTAssertEqual(100, try bob.probeAudio(audioExport).durationMs)

        // Every platform wrapper passes the same integer recipe to Rust and
        // imports only the exact canonical result, never the selected source.
        let imageSourceURL = dir.appendingPathComponent("ios-selected-image.png")
        let imageFinal = dir.appendingPathComponent("ios-edited-image.png")
        let imageDirect = dir.appendingPathComponent("ios-edited-image-direct.png")
        try imageSource().write(to: imageSourceURL)
        let imageInfo = try alice.renderEditedImage(
            source: imageSourceURL, destination: imageFinal, recipe: imageRecipe())
        _ = try editImage(
            source: imageSourceURL.path, destination: imageDirect.path, recipe: imageRecipe())
        XCTAssertEqual(try Data(contentsOf: imageDirect), try Data(contentsOf: imageFinal))
        XCTAssertEqual(imageInfo, try alice.probeImage(imageFinal))
        let imageContent = try alice.sendAttachment(
            peer: bobPeer, path: imageFinal, mediaType: "image/png",
            filename: "edited-image.png")
        let imageOffer = try bEv.wait("pairwise edited image offer") { event -> Attachment? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.contentId == imageContent,
               attachment.direction == .inbound {
                return attachment
            }
            return nil
        }
        try bob.acceptAttachment(transfer: imageOffer.transferId)
        _ = try bEv.wait("pairwise edited image completion") { event -> Void? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.transferId == imageOffer.transferId,
               attachment.state == .complete { return () }
            return nil
        }
        let imageExport = dir.appendingPathComponent("ios-edited-image-received.png")
        try bob.exportAttachment(transfer: imageOffer.transferId, to: imageExport)
        XCTAssertEqual(try Data(contentsOf: imageFinal), try Data(contentsOf: imageExport))
        XCTAssertEqual(imageInfo, try bob.probeImage(imageExport))

        // The verify screen: identical digits and QR payloads on both ends
        // (also identical to what the desktop and Android apps render), and
        // the "mark verified" button reflects into the contact list badge.
        let snA = try alice.safetyNumber(peer: bobPeer)
        let snB = try bob.safetyNumber(peer: alicePeer)
        XCTAssertEqual(snA.digits, snB.digits)
        XCTAssertEqual(snA.display, snB.display)
        XCTAssertEqual(snA.qr, snB.qr)
        XCTAssertEqual(safetyQrText(snA), safetyQrText(snB))
        try alice.markVerified(peer: bobPeer)
        let contacts = try alice.contacts()
        XCTAssertEqual(1, contacts.count)
        XCTAssertEqual("bob", contacts[0].name)
        XCTAssertTrue(contacts[0].verified)

        // The hints editor accepts a replacement and rejects garbage
        // honestly, before anything reaches the node.
        try alice.setHints(peer: bobPeer, hints: [HintSpec("mesh", "broadcast")])
        XCTAssertThrowsError(
            try alice.setHints(peer: bobPeer, hints: [HintSpec("mesh", "over-the-rainbow")])
        ) { err in
            let msg = (err as? InputError)?.message ?? ""
            XCTAssertTrue(msg.contains("node number"), "got: \(msg)")
        }

        // Errors the composer surfaces are the node's own words.
        XCTAssertThrowsError(
            try alice.send(peer: String(repeating: "00", count: 32), body: "x")
        ) { err in
            guard let ffi = err as? FfiError, case .Node = ffi else {
                return XCTFail("expected FfiError.Node, got: \(err)")
            }
            XCTAssertTrue(
                ffi.reasonText.contains("not a stored contact"),
                "got: \(ffi.reasonText)")
        }
        XCTAssertThrowsError(
            try alice.addContact(name: "mallory", bundleHex: "not hex!", hints: [])
        ) { err in
            XCTAssertTrue(err is InputError, "got: \(err)")
        }

        alice.stop()
        bob.stop()
    }

    func testNoteToSelfIsLocalSealedAndDurable() throws {
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "notes", events)

        XCTAssertEqual("note_to_self", session.noteToSelfId())
        let id = try session.sendNoteToSelf(body: "remember the glacier map")
        let added = try events.wait("local note event") {
            event -> (conversation: String, body: String)? in
            if case let .noteToSelfMessageAdded(conversation, eventId, _, body) = event,
               eventId == id {
                return (conversation, body)
            }
            return nil
        }
        XCTAssertEqual(session.noteToSelfId(), added.conversation)
        XCTAssertEqual("remember the glacier map", added.body)
        XCTAssertEqual(0, try session.status().queued)
        XCTAssertEqual(0, try session.status().contacts)
        XCTAssertEqual("remember the glacier map", try session.noteToSelfMessages().first?.body)

        session.stop()
        session = try open(dir, "notes", Events())
        let history = try session.noteToSelfMessages()
        XCTAssertEqual("note_to_self", history.first?.conversation)
        XCTAssertEqual("remember the glacier map", history.first?.body)
        XCTAssertEqual(0, try session.status().queued)
        session.stop()
    }

    func testGroupUXCreatesManagesMessagesAndShowsPartialDelivery() throws {
        let dir = try tempDir()
        let aEv = Events()
        let bEv = Events()

        // The embedded FFI runtime admits two live nodes per process. Capture
        // a real third identity first, then keep Carol offline so delivery can
        // be proven independently per member.
        let carol = try open(dir, "group-carol", Events())
        let carolBundle = try carol.myBundleHex()
        carol.stop()
        let alice = try open(dir, "group-alice", aEv)
        let bob = try open(dir, "group-bob", bEv)
        defer {
            alice.stop()
            bob.stop()
        }

        let aliceAddr = try listenAddr(alice)
        let bobAddr = try listenAddr(bob)
        let aliceBundle = try alice.myBundleHex()
        let bobBundle = try bob.myBundleHex()
        let bobPeer = try alice.addContact(
            name: "Bob", bundleHex: bobBundle, hints: multiaddrHint(bobAddr))
        let carolPeer = try alice.addContact(
            name: "Carol", bundleHex: carolBundle,
            hints: multiaddrHint("/ip4/127.0.0.1/udp/9/quic-v1"))
        let aliceAtBob = try bob.addContact(
            name: "Alice", bundleHex: aliceBundle, hints: multiaddrHint(aliceAddr))

        // The create flow selects one stored contact; the creator then adds
        // another from the members screen.
        let group = try alice.createGroup(name: "Trail crew", members: [bobPeer])
        _ = try bEv.wait("Bob's group invite") { event -> Void? in
            if case let .groupUpdated(updated) = event, updated == group { return () }
            return nil
        }
        var listed = try alice.groups()
        XCTAssertEqual(1, listed.count)
        XCTAssertEqual(group, listed[0].id)
        XCTAssertEqual("Trail crew", listed[0].name)
        XCTAssertEqual(2, listed[0].members.count)

        // Capability negotiation is authenticated session state. Establish
        // the pairwise session before the group attachment composer asks the
        // node whether every recipient supports attachments.
        let capabilityProbe = try alice.send(
            peer: bobPeer, body: "attachment capability handshake")
        _ = try bEv.wait("attachment capability handshake") { event -> Void? in
            if case let .messageReceived(peer, _, _, body, _, _) = event,
               peer == aliceAtBob, body == "attachment capability handshake" {
                return ()
            }
            return nil
        }
        _ = try aEv.wait("attachment capability receipt") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event,
               id == capabilityProbe, state == .delivered {
                return ()
            }
            return nil
        }

        // The same Session surface covers one encrypt-once group attachment.
        let selectedImage = dir.appendingPathComponent("ios-group-selected.png")
        let groupSource = dir.appendingPathComponent("ios-group-edited.png")
        let directImage = dir.appendingPathComponent("ios-group-edited-direct.png")
        try imageSource().write(to: selectedImage)
        let groupImageInfo = try alice.renderEditedImage(
            source: selectedImage, destination: groupSource, recipe: imageRecipe())
        _ = try editImage(
            source: selectedImage.path, destination: directImage.path, recipe: imageRecipe())
        XCTAssertEqual(try Data(contentsOf: directImage), try Data(contentsOf: groupSource))
        let groupContent = try alice.sendGroupAttachment(
            group: group,
            path: groupSource,
            mediaType: "image/png",
            filename: "edited-image.png")
        let groupOffer = try bEv.wait("group attachment offer") { event -> Attachment? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.contentId == groupContent,
               attachment.conversation == .group,
               attachment.group == group {
                return attachment
            }
            return nil
        }
        try bob.acceptAttachment(transfer: groupOffer.transferId)
        _ = try bEv.wait("group attachment completion") { event -> Void? in
            if case let .attachmentUpdated(attachment) = event,
               attachment.transferId == groupOffer.transferId,
               attachment.state == .complete {
                return ()
            }
            return nil
        }
        let groupExport = dir.appendingPathComponent("ios-group-export.bin")
        try bob.exportAttachment(transfer: groupOffer.transferId, to: groupExport)
        XCTAssertEqual(try Data(contentsOf: groupSource), try Data(contentsOf: groupExport))
        XCTAssertEqual(groupImageInfo, try bob.probeImage(groupExport))

        // The Swift Session exposes the exact native poll contract. Polls
        // refresh dedicated cards and never become chat-message rows.
        let messageRowsBeforePoll = try alice.groupMessages(group: group).count
        let pollId = try alice.createGroupPoll(
            group: group,
            question: "Which route? 🗻",
            options: ["North ridge", "River path"])
        _ = try bEv.wait("Bob's iOS poll") { event -> Void? in
            if case let .pollUpdated(updatedGroup, _, updatedPoll) = event,
               updatedGroup == group, updatedPoll == pollId { return () }
            return nil
        }
        let bobPoll = try XCTUnwrap(bob.groupPolls(group: group).first)
        XCTAssertEqual("Which route? 🗻", bobPoll.question)
        XCTAssertTrue(bobPoll.votesVisible)
        XCTAssertFalse(bobPoll.anonymous)
        XCTAssertEqual("manual_creator_snapshot", bobPoll.closePolicy)
        XCTAssertFalse(bobPoll.canClose)
        _ = try bob.voteGroupPoll(
            group: group, pollAuthor: bobPoll.author, pollId: pollId,
            optionId: bobPoll.options[0].id)
        _ = try aEv.wait("Bob's first iOS poll vote") { event -> Void? in
            if case let .pollUpdated(_, _, updatedPoll) = event,
               updatedPoll == pollId { return () }
            return nil
        }
        let changedOption = bobPoll.options[1].id
        _ = try bob.voteGroupPoll(
            group: group, pollAuthor: bobPoll.author, pollId: pollId,
            optionId: changedOption)
        let pollChangeDeadline = Date().addingTimeInterval(30)
        while try alice.groupPolls(group: group).first?.votes.first?.optionId != changedOption {
            guard Date() < pollChangeDeadline else {
                throw Timeout(what: "changed iOS poll vote")
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let changedPoll = try XCTUnwrap(alice.groupPolls(group: group).first)
        XCTAssertEqual(1, changedPoll.votes.count)
        XCTAssertEqual(changedOption, changedPoll.votes[0].optionId)
        XCTAssertTrue(changedPoll.canClose)
        _ = try alice.closeGroupPoll(
            group: group, pollAuthor: changedPoll.author, pollId: pollId)
        let pollCloseDeadline = Date().addingTimeInterval(30)
        while try bob.groupPolls(group: group).first?.closed != true {
            guard Date() < pollCloseDeadline else {
                throw Timeout(what: "closed iOS poll")
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertTrue(try XCTUnwrap(bob.groupPolls(group: group).first).closed)
        XCTAssertEqual(messageRowsBeforePoll, try alice.groupMessages(group: group).count)
        XCTAssertEqual(messageRowsBeforePoll, try bob.groupMessages(group: group).count)

        try alice.addGroupMember(group: group, peer: carolPeer)
        listed = try alice.groups()
        XCTAssertEqual(3, listed[0].members.count)

        // Only the creator gets roster controls; the node's explicit
        // authority error passes through the shell unchanged.
        XCTAssertThrowsError(try bob.addGroupMember(group: group, peer: carolPeer)) { error in
            guard let ffi = error as? FfiError, case .Node = ffi else {
                return XCTFail("expected FfiError.Node, got: \(error)")
            }
            XCTAssertTrue(ffi.reasonText.contains("creator"), "got: \(ffi.reasonText)")
        }

        // Bob receives while offline Carol remains queued/sent. Outbound
        // history exposes one truthful state per recipient.
        let first = try alice.sendGroup(group: group, body: "Meet at the north trailhead")
        _ = try bEv.wait("Bob's group message") { event -> Void? in
            if case let .groupMessageReceived(receivedGroup, _, _, _, body, _, _, _) = event,
               receivedGroup == group, body == "Meet at the north trailhead" {
                return ()
            }
            return nil
        }
        _ = try aEv.wait("Bob's group copy delivered") { event -> Void? in
            if case let .groupDeliveryUpdated(id, peer, state) = event,
               id == first, peer == bobPeer, state == .delivered {
                return ()
            }
            return nil
        }
        let allHistory = try alice.groupMessages(group: group)
        XCTAssertEqual(1, allHistory.filter { $0.contentKind == .attachment }.count)
        let history = allHistory.filter { $0.contentKind != .attachment }
        XCTAssertEqual(1, history.count)
        XCTAssertEqual(.outbound, history[0].direction)
        XCTAssertEqual(2, history[0].deliveries.count)
        XCTAssertEqual(
            .delivered,
            history[0].deliveries.first(where: { $0.peer == bobPeer })?.state)
        let carolState = history[0].deliveries.first(where: { $0.peer == carolPeer })?.state
        XCTAssertTrue(carolState == .queued || carolState == .sent)
        let bobHistory = try bob.groupMessages(group: group).filter {
            $0.contentKind != .attachment
        }
        XCTAssertEqual(aliceAtBob, bobHistory[0].sender)
        XCTAssertEqual(.inbound, bobHistory[0].direction)
        XCTAssertTrue(bobHistory[0].deliveries.isEmpty)

        // Creator removal rotates the roster immediately. A member can leave;
        // their live group disappears locally and the creator converges too.
        try alice.removeGroupMember(group: group, peer: carolPeer)
        XCTAssertEqual(2, try alice.groups()[0].members.count)
        Thread.sleep(forTimeInterval: 0.3)
        let editable = try alice.sendGroup(group: group, body: "iOS group edit original")
        _ = try bEv.wait("Bob's editable iOS group Text") { event -> Void? in
            if case let .groupMessageReceived(_, _, id, _, _, kind, _, _) = event,
               id == editable, kind == .text { return () }
            return nil
        }
        _ = try aEv.wait("iOS editable group delivery") { event -> Void? in
            if case let .groupDeliveryUpdated(id, peer, state) = event,
               id == editable, peer == bobPeer, state == .delivered { return () }
            return nil
        }
        let edit = try alice.editGroupMessage(
            group: group,
            targetAuthor: aliceAtBob,
            targetContentId: editable,
            text: "iOS group edit revised")
        _ = try bEv.wait("iOS group edit refresh") { event -> Void? in
            if case let .groupMessageEdited(editedGroup, sender, targetContentId) = event,
               editedGroup == group, sender == aliceAtBob,
               targetContentId == editable { return () }
            return nil
        }
        _ = try aEv.wait("iOS group edit delivery") { event -> Void? in
            if case let .groupDeliveryUpdated(id, peer, state) = event,
               id == edit, peer == bobPeer, state == .delivered { return () }
            return nil
        }
        for messages in [try alice.groupMessages(group: group), try bob.groupMessages(group: group)] {
            let message = try XCTUnwrap(messages.first(where: { $0.id == editable }))
            XCTAssertEqual("iOS group edit revised", message.body)
            XCTAssertTrue(message.edited)
            XCTAssertEqual(1, message.editRevision)
            XCTAssertEqual(2, message.versions.count)
        }
        try bob.leaveGroup(group: group)
        XCTAssertTrue(try bob.groups().isEmpty)
        let deadline = Date().addingTimeInterval(30)
        while try alice.groups()[0].members.count != 1 {
            guard Date() < deadline else { throw Timeout(what: "creator applying Bob's leave") }
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    func testGroupMentionsPreserveExactUTF8SpansAndNotifyOnlyTheTarget() throws {
        let dir = try tempDir()
        let aEv = Events()
        let bEv = Events()
        let alice = try open(dir, "mention-alice", aEv)
        let bob = try open(dir, "mention-bob", bEv)
        defer {
            alice.stop()
            bob.stop()
        }

        let aliceAddr = try listenAddr(alice)
        let bobAddr = try listenAddr(bob)
        let bobPeer = try alice.addContact(
            name: "Same name", bundleHex: bob.myBundleHex(), hints: multiaddrHint(bobAddr))
        let aliceAtBob = try bob.addContact(
            name: "Same name", bundleHex: alice.myBundleHex(), hints: multiaddrHint(aliceAddr))
        let group = try alice.createGroup(name: "Unicode crew", members: [bobPeer])
        _ = try bEv.wait("mention group invite") { event -> Void? in
            if case let .groupUpdated(updated) = event, updated == group { return () }
            return nil
        }

        let handshake = try alice.send(peer: bobPeer, body: "mention capability handshake")
        _ = try bEv.wait("mention capability handshake") { event -> Void? in
            if case let .messageReceived(peer, _, _, body, _, _) = event,
               peer == aliceAtBob, body == "mention capability handshake" { return () }
            return nil
        }
        _ = try aEv.wait("mention capability receipt") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event,
               id == handshake, state == .delivered { return () }
            return nil
        }

        let capabilityDeadline = Date().addingTimeInterval(5)
        var capability = try alice.groupMentionCapability(group: group)
        while !capability.supported {
            guard Date() < capabilityDeadline else {
                throw Timeout(what: "mention capability support: \(capability.issues)")
            }
            Thread.sleep(forTimeInterval: 0.05)
            capability = try alice.groupMentionCapability(group: group)
        }
        XCTAssertTrue(capability.issues.isEmpty)

        XCTAssertThrowsError(
            try alice.sendGroupMention(
                group: group,
                text: "👩",
                spans: [MentionSpan(start: 1, end: 4, target: bobPeer)],
                reviewToken: capability.reviewToken))
        XCTAssertTrue(
            try alice.groupMessages(group: group).isEmpty,
            "Invalid Swift byte ranges must fail before persistence or send")

        let text = "Meet 👩🏽‍🚀 @Same name by e\u{301}ast"
        let visible = "@Same name"
        let visibleRange = try XCTUnwrap(text.range(of: visible))
        let start = UInt32(text[..<visibleRange.lowerBound].utf8.count)
        let end = start + UInt32(visible.utf8.count)
        let expectedSpans = [MentionSpan(start: start, end: end, target: bobPeer)]
        let mentionId = try alice.sendGroupMention(
            group: group,
            text: text,
            spans: expectedSpans,
            reviewToken: capability.reviewToken)
        let received = try bEv.wait("semantic mention") { event -> (
            id: String, spans: [MentionSpan]
        )? in
            if case let .groupMessageReceived(
                receivedGroup, _, id, _, body, kind, _, spans
            ) = event,
               id == mentionId, receivedGroup == group, body == text, kind == .mention {
                return (id, spans)
            }
            return nil
        }
        XCTAssertEqual(expectedSpans, received.spans)
        _ = try bEv.wait("local mention signal") { event -> Void? in
            if case let .mentionReceived(id) = event, id == received.id { return () }
            return nil
        }

        let stored = try XCTUnwrap(
            bob.groupMessages(group: group).first(where: { $0.id == received.id }))
        XCTAssertEqual(text, stored.body)
        XCTAssertEqual(.mention, stored.contentKind)
        XCTAssertEqual(expectedSpans, stored.mentionSpans)

        let plainId = try alice.sendGroup(group: group, body: text)
        _ = try bEv.wait("plain fallback") { event -> Void? in
            if case let .groupMessageReceived(_, _, id, _, body, kind, _, spans) = event,
               id == plainId, body == text, kind == .text, spans.isEmpty { return () }
            return nil
        }
        _ = try aEv.wait("plain fallback receipt") { event -> Void? in
            if case let .groupDeliveryUpdated(id, peer, state) = event,
               id == plainId, peer == bobPeer, state == .delivered { return () }
            return nil
        }
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(1, bEv.count {
            if case .mentionReceived = $0 { return true }
            return false
        })
    }

    func testBackupMnemonicRestoreFlow() throws {
        let dir = try tempDir()
        var aEv = Events()
        let bEv = Events()
        var alice = try open(dir, "alice", aEv)
        let bob = try open(dir, "bob", bEv)

        let aAddr = try listenAddr(alice)
        let bAddr = try listenAddr(bob)
        let bobPeer = try alice.addContact(
            name: "bob", bundleHex: try bob.myBundleHex(), hints: multiaddrHint(bAddr))
        let alicePeer = try bob.addContact(
            name: "alice", bundleHex: try alice.myBundleHex(), hints: multiaddrHint(aAddr))
        let msgId = try alice.send(peer: bobPeer, body: "before the backup")
        _ = try aEv.wait("delivered") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event, id == msgId, state == .delivered {
                return ()
            }
            return nil
        }
        _ = try alice.sendNoteToSelf(body: "packed in the backup")

        // The backup sheet: mnemonic comes back exactly once, 24 words; an
        // existing file is refused, not clobbered.
        let backup = dir.appendingPathComponent("komms-backup.kkr")
        let mnemonic = try alice.exportBackup(to: backup)
        XCTAssertEqual(24, mnemonic.split(whereSeparator: { $0.isWhitespace }).count)
        XCTAssertThrowsError(try alice.exportBackup(to: backup))

        let addressBefore = alice.address
        alice.stop()

        // The gate's restore tab: wrong mnemonic refused at startup…
        XCTAssertThrowsError(
            try Session.restore(
                dataDir: dir.appendingPathComponent("alice-wrong"), passphrase: "new-pass",
                backupPath: backup,
                mnemonic: String(repeating: "abandon ", count: 23) + "art",
                settings: testSettings(), kdf: .mobile, sink: Events().sink)
        ) { err in
            guard let ffi = err as? FfiError, case .Startup = ffi else {
                return XCTFail("expected FfiError.Startup, got: \(err)")
            }
        }

        // …right mnemonic restores identity, contacts, and history.
        aEv = Events()
        alice = try Session.restore(
            dataDir: dir.appendingPathComponent("alice-new"), passphrase: "new-pass",
            backupPath: backup, mnemonic: mnemonic,
            settings: testSettings(), kdf: .mobile, sink: aEv.sink)
        XCTAssertEqual(addressBefore, alice.address)
        XCTAssertEqual("bob", try alice.contacts()[0].name)
        let history = try alice.messages(peer: bobPeer)
        XCTAssertEqual(1, history.count)
        XCTAssertEqual("before the backup", history[0].body)
        XCTAssertEqual("packed in the backup", try alice.noteToSelfMessages().first?.body)

        // The restored node re-handshakes automatically; after Bob learns
        // the new address, messaging resumes in both directions.
        let deadline = Date().addingTimeInterval(30)
        while bEv.count({ event in
            if case let .sessionEstablished(peer) = event { return peer == alicePeer }
            return false
        }) < 2 {
            guard Date() < deadline else { throw Timeout(what: "re-key") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        try bob.setHints(peer: alicePeer, hints: multiaddrHint(try listenAddr(alice)))
        _ = try bob.send(peer: alicePeer, body: "glad you're back")
        let got = try aEv.wait("alice's message event") { event -> String? in
            if case let .messageReceived(_, _, _, body, _, _) = event { return body }
            return nil
        }
        XCTAssertEqual("glad you're back", got)
        let reply = try alice.send(peer: bobPeer, body: "new phone, same me")
        _ = try aEv.wait("reply delivered") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event, id == reply, state == .delivered {
                return ()
            }
            return nil
        }

        alice.stop()
        bob.stop()
    }

    func testUnlockRefusesWrongPassphraseAndPersists() throws {
        let dir = try tempDir()
        let alice = try open(dir, "alice", Events())
        let address = alice.address
        alice.stop()

        // Wrong passphrase at the gate: an honest startup error.
        XCTAssertThrowsError(
            try Session.open(
                dataDir: dir.appendingPathComponent("alice"), passphrase: "wrong",
                settings: testSettings(), kdf: .mobile, sink: Events().sink)
        ) { err in
            guard let ffi = err as? FfiError else {
                return XCTFail("expected FfiError, got: \(err)")
            }
            XCTAssertTrue(ffi.reasonText.hasPrefix("startup"), "got: \(ffi.reasonText)")
        }

        // Right passphrase: same identity. Settings persisted alongside.
        let again = try open(dir, "alice", Events())
        XCTAssertEqual(address, again.address)
        XCTAssertFalse(try NetworkSettings.load(from: dir.appendingPathComponent("alice")).mdns)
        again.stop()

        // A spent handle answers honestly instead of half-working.
        XCTAssertThrowsError(try again.status()) { err in
            guard let ffi = err as? FfiError, case .Stopped = ffi else {
                return XCTFail("expected FfiError.Stopped, got: \(err)")
            }
        }
    }

    func testPrivateLabelsAreExactTypedLocalAndRestartSafe() throws {
        let fixture = try LabelParityFixture.load()
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "labels", events)
        let queuedBefore = try session.status().queued
        let peer = try session.addContact(
            name: "\u{2067}duplicate\u{2069}", bundleHex: session.myBundleHex(), hints: [])
        let group = try session.createGroup(name: "e\u{301} group", members: [])
        let first = try session.createLabel(name: fixture.duplicateName, color: fixture.createColors[0])
        let second = try session.createLabel(name: fixture.duplicateName, color: fixture.createColors[1])
        XCTAssertNotEqual(first.id, second.id)
        XCTAssertEqual(fixture.expectedOrders, [first.order, second.order])
        _ = try events.wait("labels changed") { event -> Void? in
            if case .labelsChanged = event { return () }
            return nil
        }

        let peerTarget = LabelTarget(kind: .peer, id: peer)
        let groupTarget = LabelTarget(kind: .group, id: group)
        let noteTarget = LabelTarget(kind: .noteToSelf, id: nil)
        for target in [peerTarget, groupTarget, noteTarget] {
            XCTAssertTrue(try session.assignLabel(id: first.id, target: target))
        }
        for target in [groupTarget, noteTarget] {
            XCTAssertTrue(try session.assignLabel(id: second.id, target: target))
        }
        XCTAssertFalse(try session.assignLabel(id: second.id, target: noteTarget))
        XCTAssertEqual(3, try session.labelMembership(id: first.id).count)
        XCTAssertEqual(
            [.peer, .group, .noteToSelf],
            try session.labelMembership(id: first.id).map(\.target.kind))
        XCTAssertEqual(
            fixture.membershipTargetKinds,
            try session.labelMembership(id: first.id).map { labelTargetKindName($0.target.kind) })
        XCTAssertEqual(
            [first.id],
            try session.filterLabels(ids: [first.id, first.id], mode: .any).selected)
        XCTAssertEqual(
            fixture.matchAnyTargetKinds,
            try session.filterLabels(ids: [first.id], mode: .any).conversations
                .map { labelTargetKindName($0.target.kind) })
        XCTAssertEqual(
            fixture.matchAllTargetKinds,
            try session.filterLabels(ids: [first.id, second.id], mode: .all).conversations
                .map { labelTargetKindName($0.target.kind) })
        let updated = try session.updateLabel(
            id: first.id, name: fixture.renamedName, color: fixture.renamedColor)
        XCTAssertEqual(first.id, updated.id)
        XCTAssertEqual(0, updated.order)
        XCTAssertEqual(fixture.expectedAssignmentCount, try session.labelDeleteAssignmentCount(id: first.id))
        XCTAssertThrowsError(try session.deleteLabel(id: first.id, confirm: false))
        XCTAssertThrowsError(try session.createLabel(name: fixture.whitespaceOnlyName, color: "red"))
        XCTAssertThrowsError(try session.createLabel(name: "valid", color: fixture.unsupportedColor))
        XCTAssertThrowsError(try session.label(id: fixture.invalidId)) { error in
            guard let ffi = error as? FfiError,
                  case .Label(let code, _) = ffi else {
                return XCTFail("expected structured label error, got: \(error)")
            }
            XCTAssertEqual(.invalidId, code)
        }
        XCTAssertEqual(queuedBefore, try session.status().queued)
        session.stop()

        session = try open(dir, "labels", Events())
        XCTAssertEqual([first.id, second.id], try session.labels().map(\.id))
        XCTAssertEqual(3, try session.labelMembership(id: first.id).count)
        XCTAssertEqual(fixture.expectedAssignmentCount, try session.deleteLabel(id: first.id, confirm: true))
        XCTAssertEqual(
            [second.id], try session.labelsForConversation(target: noteTarget).map(\.id))
        XCTAssertTrue(try session.staleLabels().isEmpty)
        session.stop()
    }

    func testPrivateFoldersAreExactTypedComposedLocalAndRestartSafe() throws {
        let fixture = try FolderParityFixture.load()
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "folders", events)
        let queuedBefore = try session.status().queued
        let peer = try session.addContact(
            name: "\u{2067}duplicate\u{2069}", bundleHex: session.myBundleHex(), hints: [])
        let group = try session.createGroup(name: "e\u{301} group", members: [])
        let first = try session.createFolder(name: fixture.duplicateName)
        let second = try session.createFolder(name: fixture.duplicateName)
        XCTAssertNotEqual(first.id, second.id)
        XCTAssertEqual(fixture.expectedInitialOrders, [first.order, second.order])
        _ = try events.wait("folders changed") { event -> Void? in
            if case .foldersChanged = event { return () }
            return nil
        }
        XCTAssertEqual(
            [second.id, first.id],
            try session.reorderFolders(ids: [second.id, first.id]).map(\.id))

        let peerTarget = FolderTarget(kind: .peer, id: peer)
        let groupTarget = FolderTarget(kind: .group, id: group)
        let noteTarget = FolderTarget(kind: .noteToSelf, id: nil)
        XCTAssertTrue(try session.moveToFolder(id: first.id, target: peerTarget))
        XCTAssertTrue(try session.moveToFolder(id: first.id, target: groupTarget))
        XCTAssertTrue(try session.moveToFolder(id: second.id, target: noteTarget))
        XCTAssertFalse(try session.moveToFolder(id: second.id, target: noteTarget))
        XCTAssertEqual(
            fixture.firstFolderTargetKinds,
            try session.folderMembership(id: first.id).map {
                folderTargetKindName($0.target.kind)
            })

        let label = try session.createLabel(name: "folder composition", color: "teal")
        XCTAssertTrue(try session.assignLabel(
            id: label.id, target: LabelTarget(kind: .peer, id: peer)))
        XCTAssertTrue(try session.assignLabel(
            id: label.id, target: LabelTarget(kind: .group, id: group)))
        XCTAssertEqual(
            fixture.folderThenAnyLabelTargetKinds,
            try session.folderConversations(
                selection: FolderSelection(kind: .folder, id: first.id),
                labels: [label.id], mode: .any
            ).conversations.map { folderTargetKindName($0.target.kind) })

        XCTAssertTrue(try session.unfileConversation(target: peerTarget))
        XCTAssertFalse(try session.unfileConversation(target: peerTarget))
        XCTAssertEqual(
            fixture.unfiledAfterMoveTargetKinds,
            try session.folderConversations(
                selection: FolderSelection(kind: .unfiled, id: nil), labels: [], mode: .any
            ).conversations.map { folderTargetKindName($0.target.kind) })
        XCTAssertEqual(second.id, try session.conversationFolder(target: noteTarget)?.id)
        XCTAssertThrowsError(try session.deleteFolder(id: first.id, confirm: false))
        XCTAssertThrowsError(try session.createFolder(name: fixture.whitespaceOnlyName))
        XCTAssertThrowsError(try session.folder(id: fixture.invalidId)) { error in
            guard let ffi = error as? FfiError,
                  case .Folder(let code, _) = ffi else {
                return XCTFail("expected structured folder error, got: \(error)")
            }
            XCTAssertEqual(.invalidId, code)
        }
        XCTAssertEqual(queuedBefore, try session.status().queued)
        session.stop()

        session = try open(dir, "folders", Events())
        XCTAssertEqual([second.id, first.id], try session.folders().map(\.id))
        XCTAssertEqual(
            fixture.expectedDeleteAssignmentCount,
            try session.folderDeleteAssignmentCount(id: first.id))
        XCTAssertEqual(
            fixture.expectedDeleteAssignmentCount,
            try session.deleteFolder(id: first.id, confirm: true))
        let replacement = try session.createFolder(name: first.name)
        XCTAssertNotEqual(replacement.id, first.id)
        XCTAssertTrue(try session.folderMembership(id: replacement.id).isEmpty)
        XCTAssertTrue(try session.staleFolders().isEmpty)
        session.stop()
    }

    func testPrivatePinsAreTypedOrderedLocalAndRestartSafe() throws {
        let fixture = try PinParityFixture.load()
        let dir = try tempDir()
        let events = Events()
        var session = try open(dir, "pins", events)
        let queuedBefore = try session.status().queued
        let peer = try session.addContact(
            name: "same name", bundleHex: session.myBundleHex(), hints: [])
        let group = try session.createGroup(name: "same name", members: [])
        let targets = [
            PinTarget(kind: .peer, id: peer),
            PinTarget(kind: .group, id: group),
            PinTarget(kind: .noteToSelf, id: nil),
        ]
        for target in targets { XCTAssertTrue(try session.pinConversation(target: target)) }
        XCTAssertFalse(try session.pinConversation(target: targets[0]))
        _ = try events.wait("pins changed") { event -> Void? in
            if case .pinsChanged = event { return () }
            return nil
        }
        XCTAssertEqual(
            fixture.initialTargetKinds,
            try session.pins().map { pinTargetKindName($0.target.kind) })
        let reordered = Array(targets.reversed())
        XCTAssertEqual(reordered, try session.reorderPins(targets: reordered).map(\.target))
        XCTAssertThrowsError(try session.reorderPins(targets: [targets[0]]))
        let composed = try session.pinConversations(
            selection: FolderSelection(kind: .all, id: nil), labels: [], mode: .any)
        XCTAssertEqual(
            fixture.composedPinnedTargetKinds,
            composed.conversations.prefix(3).map { pinTargetKindName($0.target.kind) })
        XCTAssertTrue(composed.conversations.prefix(3).allSatisfy(\.pinned))
        XCTAssertTrue(try session.stalePins().isEmpty)
        XCTAssertEqual(queuedBefore, try session.status().queued)
        session.stop()

        session = try open(dir, "pins", Events())
        XCTAssertEqual(reordered, try session.pins().map(\.target))
        XCTAssertTrue(try session.unpinConversation(target: targets[0]))
        XCTAssertFalse(try session.unpinConversation(target: targets[0]))
        session.stop()
    }
}
