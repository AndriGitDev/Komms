// The app's single observable state holder: owns the `Session`, marshals
// node events onto the main actor, and dispatches every blocking node call
// off it. Views never touch `kult-ffi` types' lifecycle directly.
//
// Honesty rules carry through verbatim: delivery states and errors are the
// node's own words (`reasonText`), key changes are surfaced as banners,
// never hidden, and the backup mnemonic passes through exactly once.

import Foundation
import ImageIO
import KommsCore
import UIKit
import UniformTypeIdentifiers

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var session: Session?
    @Published private(set) var contacts: [Contact] = []
    @Published private(set) var histories: [String: [Message]] = [:] // peer → history
    @Published private(set) var groups: [Group] = []
    @Published private(set) var groupHistories: [String: [GroupMessage]] = [:]
    @Published private(set) var scheduledMessages: [ScheduledMessage] = []
    @Published private(set) var attachments: [Attachment] = []
    @Published private(set) var noteHistory: [NoteMessage] = []
    @Published private(set) var status: Status?
    /// Surfaced node happenings: key changes, held-for-faster-link verdicts.
    @Published var notices: [String] = []

    /// Where the node lives: Application Support, excluded from iCloud/iTunes
    /// backup — portability is the user-held `.kkr` file, not Apple's servers.
    let dataDir: URL = {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("komms/node", isDirectory: true)
    }()

    private var refreshTimer: Timer?

    /// True on first run: no store yet, so the gate offers create/restore.
    var storeExists: Bool {
        FileManager.default.fileExists(atPath: dataDir.appendingPathComponent("node.db").path)
    }

    // MARK: session lifecycle

    /// Run a blocking node call off the main actor.
    nonisolated private func run<T: Sendable>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(with: Result { try work() })
            }
        }
    }

    private func sink() -> EventSink {
        { [weak self] event in
            Task { @MainActor in self?.handle(event) }
        }
    }

    /// Open (or create on first run) and start the node. Blocking work
    /// happens off-actor; a wrong passphrase surfaces as the node's own
    /// startup error.
    func unlock(passphrase: String) async throws {
        let dir = dataDir
        let settings = try NetworkSettings.load(from: dir)
        let sink = sink()
        let session = try await run {
            try Session.open(
                dataDir: dir, passphrase: passphrase,
                settings: settings, kdf: .mobile, sink: sink)
        }
        adopt(session)
        try? excludeFromBackup(dir)
    }

    /// First run only: restore identity, contacts, and history from an
    /// encrypted `.kkr` backup plus its 24-word mnemonic.
    func restore(backup: URL, mnemonic: String, passphrase: String) async throws {
        let dir = dataDir
        let settings = try NetworkSettings.load(from: dir)
        let sink = sink()
        let session = try await run {
            try Session.restore(
                dataDir: dir, passphrase: passphrase,
                backupPath: backup, mnemonic: mnemonic,
                settings: settings, kdf: .mobile, sink: sink)
        }
        adopt(session)
        try? excludeFromBackup(dir)
    }

    /// Stop the node and return to the gate.
    func lock() {
        refreshTimer?.invalidate()
        refreshTimer = nil
        session?.stop()
        session = nil
        contacts = []
        histories = [:]
        groups = []
        groupHistories = [:]
        scheduledMessages = []
        attachments = []
        noteHistory = []
        status = nil
        notices = []
    }

    private func adopt(_ session: Session) {
        self.session = session
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) {
            [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        Task { await refresh() }
    }

    private func excludeFromBackup(_ dir: URL) throws {
        var url = dir
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }

    // MARK: events

    private func handle(_ event: Event) {
        switch event {
        case .scheduledMessageUpdated, .scheduledMessageCancelled,
             .scheduledMessageActivated, .deliveryUpdated, .messageReceived,
             .noteToSelfMessageAdded,
             .carrierCapabilityChanged,
             .groupUpdated, .groupMessageReceived, .groupDeliveryUpdated,
             .attachmentUpdated:
            Task { await refresh() }
        case .contactAdded:
            Task { await refresh() }
        case .sessionEstablished(let peer):
            // A re-establishment for a known contact means their key or
            // device changed — say so, next to their name.
            if let known = contacts.first(where: { $0.peer == peer }) {
                notices.append(
                    "Session with \(known.name) re-established — their key or device "
                    + "may have changed. Verify safety numbers again.")
            }
            Task { await refresh() }
        case .awaitingFasterLink:
            notices.append("A message is held — will send when a faster link exists.")
        }
    }

    // MARK: queries

    /// Refresh status, contacts, groups, and the histories the UI follows.
    func refresh() async {
        guard let session else { return }
        let peers = Array(histories.keys)
        let followedGroups = Array(groupHistories.keys)
        do {
            let snapshot = try await run { () -> (
                Status, [Contact], [String: [Message]], [Group], [String: [GroupMessage]],
                [ScheduledMessage], [Attachment], [NoteMessage]
            ) in
                var fresh: [String: [Message]] = [:]
                for peer in peers {
                    fresh[peer] = try session.messages(peer: peer)
                }
                let liveGroups = try session.groups()
                let liveIds = Set(liveGroups.map(\.id))
                var freshGroups: [String: [GroupMessage]] = [:]
                for group in followedGroups where liveIds.contains(group) {
                    freshGroups[group] = try session.groupMessages(group: group)
                }
                return (
                    try session.status(), try session.contacts(), fresh,
                    liveGroups, freshGroups, try session.scheduledMessages(),
                    try session.attachments(), try session.noteToSelfMessages())
            }
            status = snapshot.0
            contacts = snapshot.1
            histories.merge(snapshot.2) { _, new in new }
            groups = snapshot.3
            groupHistories.merge(snapshot.4) { _, new in new }
            scheduledMessages = snapshot.5
            attachments = snapshot.6
            noteHistory = snapshot.7
        } catch {
            // A stopped handle answers honestly; the gate is already up.
        }
    }

    /// Start following a conversation (loads its history).
    func follow(peer: String) async throws {
        guard let session else { return }
        let history = try await run { try session.messages(peer: peer) }
        histories[peer] = history
    }

    /// Start following a group conversation (loads its persisted history).
    func followGroup(group: String) async throws {
        guard let session else { return }
        let history = try await run { try session.groupMessages(group: group) }
        groupHistories[group] = history
    }

    /// Stable identity used by the local note-to-self route in every shell.
    func noteToSelfId() -> String { session?.noteToSelfId() ?? "" }

    // MARK: commands (all forwarded verbatim to the session layer)

    func send(peer: String, body: String) async throws {
        guard let session else { return }
        _ = try await run { try session.send(peer: peer, body: body) }
        await refresh()
    }

    func sendAttachment(
        peer: String,
        source: URL,
        mediaType: String,
        filename: String?
    ) async throws {
        guard let session else { return }
        let staged = try await run { try stageAttachment(source, mediaType: mediaType) }
        defer { staged.remove() }
        _ = try await run {
            if let preview = staged.preview {
                try session.sendAttachmentWithPreview(
                    peer: peer, path: staged.primary, mediaType: mediaType,
                    filename: filename, preview: preview)
            } else {
                try session.sendAttachment(
                    peer: peer, path: staged.primary, mediaType: mediaType, filename: filename)
            }
        }
        await refresh()
    }

    func sendGroupAttachment(
        group: String,
        source: URL,
        mediaType: String,
        filename: String?
    ) async throws {
        guard let session else { return }
        let staged = try await run { try stageAttachment(source, mediaType: mediaType) }
        defer { staged.remove() }
        _ = try await run {
            if let preview = staged.preview {
                try session.sendGroupAttachmentWithPreview(
                    group: group, path: staged.primary, mediaType: mediaType,
                    filename: filename, preview: preview)
            } else {
                try session.sendGroupAttachment(
                    group: group, path: staged.primary, mediaType: mediaType, filename: filename)
            }
        }
        await refresh()
    }

    func acceptAttachment(transfer: String) async throws {
        try await attachmentAction { try $0.acceptAttachment(transfer: transfer) }
    }

    func rejectAttachment(transfer: String) async throws {
        try await attachmentAction { try $0.rejectAttachment(transfer: transfer) }
    }

    func cancelAttachment(transfer: String) async throws {
        try await attachmentAction { try $0.cancelAttachment(transfer: transfer) }
    }

    func pauseAttachment(transfer: String) async throws {
        try await attachmentAction { try $0.pauseAttachment(transfer: transfer) }
    }

    func resumeAttachment(transfer: String) async throws {
        try await attachmentAction { try $0.resumeAttachment(transfer: transfer) }
    }

    /// Materialize a completed primary object at a unique app-private URL.
    /// The document picker exports a copy, then the view deletes this source.
    func prepareAttachmentExport(transfer: String, filename: String?) async throws -> URL {
        guard let session else { throw InputError("node is locked") }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-export-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let basename = URL(fileURLWithPath: filename ?? "attachment").lastPathComponent
        let destination = directory.appendingPathComponent(
            basename.isEmpty ? "attachment" : basename, isDirectory: false)
        do {
            try await run { try session.exportAttachment(transfer: transfer, to: destination) }
            return destination
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    /// Materialize a sealed preview only long enough to read its bounded
    /// bytes for UIKit, then remove the plaintext path.
    func attachmentPreview(transfer: String) async throws -> Data {
        guard let session else { throw InputError("node is locked") }
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-render-preview-\(UUID().uuidString).jpg")
        defer { try? FileManager.default.removeItem(at: path) }
        try await run { try session.exportAttachmentPreview(transfer: transfer, to: path) }
        let data = try Data(contentsOf: path, options: .mappedIfSafe)
        guard data.count <= previewLimit else {
            throw InputError("attachment preview exceeds the 256 KiB limit")
        }
        return data
    }

    private func attachmentAction(_ action: @escaping @Sendable (Session) throws -> Void) async throws {
        guard let session else { return }
        try await run { try action(session) }
        await refresh()
    }

    func schedule(peer: String, body: String, notBefore: Date) async throws {
        guard let session else { return }
        let instant = try scheduledInstant(notBefore)
        _ = try await run {
            try session.schedule(peer: peer, body: body, notBefore: instant)
        }
        await refresh()
    }

    func scheduleGroup(group: String, body: String, notBefore: Date) async throws {
        guard let session else { return }
        let instant = try scheduledInstant(notBefore)
        _ = try await run {
            try session.scheduleGroup(group: group, body: body, notBefore: instant)
        }
        await refresh()
    }

    func editScheduled(message: String, body: String, notBefore: Date) async throws {
        guard let session else { return }
        let instant = try scheduledInstant(notBefore)
        try await run {
            try session.editScheduled(message: message, body: body, notBefore: instant)
        }
        await refresh()
    }

    func cancelScheduled(message: String) async throws {
        guard let session else { return }
        try await run { try session.cancelScheduled(message: message) }
        await refresh()
    }

    private func scheduledInstant(_ date: Date) throws -> UInt64 {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw InputError("choose a valid send time")
        }
        return UInt64(seconds)
    }

    func sendNoteToSelf(body: String) async throws {
        guard let session else { return }
        _ = try await run { try session.sendNoteToSelf(body: body) }
        await refresh()
    }

    func createGroup(name: String, members: [String]) async throws -> String {
        guard let session else { throw InputError("node is locked") }
        let id = try await run { try session.createGroup(name: name, members: members) }
        await refresh()
        return id
    }

    func sendGroup(group: String, body: String) async throws {
        guard let session else { return }
        _ = try await run { try session.sendGroup(group: group, body: body) }
        await refresh()
    }

    func addGroupMember(group: String, peer: String) async throws {
        guard let session else { return }
        try await run { try session.addGroupMember(group: group, peer: peer) }
        await refresh()
    }

    func removeGroupMember(group: String, peer: String) async throws {
        guard let session else { return }
        try await run { try session.removeGroupMember(group: group, peer: peer) }
        await refresh()
    }

    func leaveGroup(group: String) async throws {
        guard let session else { return }
        try await run { try session.leaveGroup(group: group) }
        await refresh()
    }

    func myBundleHex() async throws -> String {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.myBundleHex() }
    }

    func addContact(name: String, bundleHex: String, hints: [HintSpec]) async throws {
        guard let session else { return }
        _ = try await run {
            try session.addContact(name: name, bundleHex: bundleHex, hints: hints)
        }
        await refresh()
    }

    func addContact(name: String, address: String) async throws {
        guard let session else { return }
        _ = try await run { try session.addContact(name: name, address: address) }
        await refresh()
    }

    func safetyNumber(peer: String) async throws -> SafetyNumber {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.safetyNumber(peer: peer) }
    }

    func markVerified(peer: String) async throws {
        guard let session else { return }
        try await run { try session.markVerified(peer: peer) }
        await refresh()
    }

    func setHints(peer: String, hints: [HintSpec]) async throws {
        guard let session else { return }
        try await run { try session.setHints(peer: peer, hints: hints) }
    }

    /// Write the encrypted backup and hand back the one-time mnemonic.
    func exportBackup(to path: URL) async throws -> String {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.exportBackup(to: path) }
    }
}

private let attachmentLimit = 512 * 1024 * 1024
private let attachmentCopySize = 64 * 1024
private let previewLimit = 256 * 1024

private struct StagedAttachment: Sendable {
    let primary: URL
    let preview: URL?

    func remove() {
        try? FileManager.default.removeItem(at: primary)
        if let preview { try? FileManager.default.removeItem(at: preview) }
    }
}

/// Copy one security-scoped provider document into a unique app-private file
/// with bounded memory and an explicit size ceiling. The caller holds the
/// security scope open for this blocking operation.
private func stageAttachment(_ source: URL, mediaType: String) throws -> StagedAttachment {
    let staged = FileManager.default.temporaryDirectory
        .appendingPathComponent("komms-attachment-\(UUID().uuidString)")
    guard FileManager.default.createFile(atPath: staged.path, contents: nil) else {
        throw InputError("the selected document could not be staged")
    }
    do {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = try FileHandle(forWritingTo: staged)
        defer { try? output.close() }
        var copied = 0
        while let chunk = try input.read(upToCount: attachmentCopySize), !chunk.isEmpty {
            copied += chunk.count
            guard copied <= attachmentLimit else {
                throw InputError("this attachment exceeds the 512 MiB limit")
            }
            try output.write(contentsOf: chunk)
        }
        try output.synchronize()
        let preview = try generateImagePreview(staged, mediaType: mediaType)
        return StagedAttachment(primary: staged, preview: preview)
    } catch {
        try? FileManager.default.removeItem(at: staged)
        throw error
    }
}

private func generateImagePreview(_ source: URL, mediaType: String) throws -> URL? {
    guard mediaType == "image/jpeg" || mediaType == "image/png" else { return nil }
    guard let imageSource = CGImageSourceCreateWithURL(source as CFURL, nil) else {
        throw InputError("this image could not be safely previewed")
    }
    guard let sourceType = CGImageSourceGetType(imageSource),
          sourceType == UTType.jpeg.identifier as CFString
            || sourceType == UTType.png.identifier as CFString
    else {
        throw InputError("the selected content is not JPEG or PNG")
    }
    for (edge, quality) in [(512, 0.82), (448, 0.72), (384, 0.62), (320, 0.52)] {
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: edge,
            kCGImageSourceShouldCacheImmediately: false,
        ]
        guard let thumbnail = CGImageSourceCreateThumbnailAtIndex(
            imageSource, 0, options as CFDictionary)
        else { continue }
        guard let data = UIImage(cgImage: thumbnail).jpegData(compressionQuality: quality) else {
            continue
        }
        if data.count <= previewLimit {
            let path = FileManager.default.temporaryDirectory
                .appendingPathComponent("komms-preview-\(UUID().uuidString).jpg")
            try data.write(to: path, options: [.atomic, .completeFileProtection])
            return path
        }
    }
    throw InputError("this image could not fit the 256 KiB preview limit")
}

/// One error string for any failure the UI shows: the node's words for FFI
/// errors, this layer's words for input it rejected.
func errorText(_ error: Error) -> String {
    if let ffi = error as? FfiError { return ffi.reasonText }
    if let input = error as? InputError { return input.message }
    if let settings = error as? SettingsError { return settings.message }
    return String(describing: error)
}
