// The app's single observable state holder: owns the `Session`, marshals
// node events onto the main actor, and dispatches every blocking node call
// off it. Views never touch `kult-ffi` types' lifecycle directly.
//
// Honesty rules carry through verbatim: delivery states and errors are the
// node's own words (`reasonText`), key changes are surfaced as banners,
// never hidden, and the backup mnemonic passes through exactly once.

import Foundation
import KommsCore
import SwiftUI

private enum ThemePreferenceStore {
    static let key = "komms.appearance.theme"

    static func load() -> ThemePreference {
        switch UserDefaults.standard.string(forKey: key) {
        case "light": return .light
        case "dark": return .dark
        default: return .system
        }
    }

    static func save(_ preference: ThemePreference) {
        let token = switch preference {
        case .system: "system"
        case .light: "light"
        case .dark: "dark"
        }
        UserDefaults.standard.set(token, forKey: key)
    }
}

extension ThemePreference {
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var session: Session?
    @Published private(set) var contacts: [Contact] = []
    @Published private(set) var histories: [String: [Message]] = [:] // peer → history
    @Published private(set) var groups: [KommsCore.Group] = []
    @Published private(set) var groupHistories: [String: [GroupMessage]] = [:]
    @Published private(set) var scheduledMessages: [ScheduledMessage] = []
    @Published private(set) var attachments: [Attachment] = []
    @Published private(set) var noteHistory: [NoteMessage] = []
    @Published private(set) var status: Status?
    @Published private(set) var folders: [KommsCore.Folder] = []
    @Published private(set) var staleFolderRecords: [StaleFolder] = []
    @Published private(set) var folderSelection = FolderSelection(kind: .all, id: nil)
    @Published private(set) var labels: [KommsCore.Label] = []
    @Published private(set) var staleLabelRecords: [StaleLabel] = []
    @Published private(set) var conversationLabels: [String: [KommsCore.Label]] = [:]
    @Published private(set) var matchingLabelTargets: Set<String> = []
    @Published private(set) var selectedLabelIds: [String] = []
    @Published private(set) var labelFilterMode: LabelMatchMode = .any
    @Published private(set) var pins: [Pin] = []
    @Published private(set) var pinRows: [PinConversation] = []
    @Published private(set) var stalePinRecords: [Pin] = []
    @Published private(set) var themePreference: ThemePreference = ThemePreferenceStore.load()
    @Published private(set) var customIcons: [CustomIconTarget: CustomIcon] = [:]
    @Published private(set) var customIconUsage = CustomIconQuotaUsage(records: 0, bytes: 0)
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

    init() {
        let filter = LabelFilterStore.load()
        selectedLabelIds = filter.ids
        labelFilterMode = filter.mode == "all" ? .all : .any
        folderSelection = switch filter.folderKind {
        case "unfiled": FolderSelection(kind: .unfiled, id: nil)
        case "folder": FolderSelection(kind: .folder, id: filter.folderId)
        default: FolderSelection(kind: .all, id: nil)
        }
        let temporary = FileManager.default.temporaryDirectory
        let entries = try? FileManager.default.contentsOfDirectory(
            at: temporary, includingPropertiesForKeys: nil
        )
        let plaintextPrefixes = [
            "komms-audio-", "komms-attachment-", "komms-image-final-",
            "komms-render-preview-", "komms-render-image-", "komms-export-",
        ]
        entries?.filter { url in
            plaintextPrefixes.contains { url.lastPathComponent.hasPrefix($0) }
        }.forEach { try? FileManager.default.removeItem(at: $0) }
    }

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
        await adopt(session)
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
        await adopt(session)
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
        folders = []
        staleFolderRecords = []
        labels = []
        staleLabelRecords = []
        conversationLabels = [:]
        matchingLabelTargets = []
        pins = []
        pinRows = []
        stalePinRecords = []
        customIcons = [:]
        customIconUsage = CustomIconQuotaUsage(records: 0, bytes: 0)
    }

    private func adopt(_ session: Session) async {
        if let info = try? await run({ try session.theme() }) {
            if info.persisted {
                themePreference = info.preference
                ThemePreferenceStore.save(info.preference)
            } else {
                let cached = themePreference
                _ = try? await run { try session.setTheme(cached) }
            }
        }
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
        case .themeChanged:
            Task { await refreshTheme() }
        case .customIconsChanged:
            Task { await refresh() }
        case .scheduledMessageUpdated, .scheduledMessageCancelled,
             .scheduledMessageActivated, .deliveryUpdated, .messageReceived,
             .noteToSelfMessageAdded,
             .carrierCapabilityChanged,
             .groupUpdated, .groupMessageReceived, .groupDeliveryUpdated,
             .attachmentUpdated, .foldersChanged, .labelsChanged, .pinsChanged:
            Task { await refresh() }
        case .mentionReceived:
            notices.append("You were mentioned in a group.")
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

    func setTheme(_ preference: ThemePreference) async {
        themePreference = preference
        ThemePreferenceStore.save(preference)
        guard let session else { return }
        _ = try? await run { try session.setTheme(preference) }
    }

    private func refreshTheme() async {
        guard let session, let info = try? await run({ try session.theme() }) else { return }
        themePreference = info.preference
        ThemePreferenceStore.save(info.preference)
    }

    // MARK: queries

    /// Refresh status, contacts, groups, and the histories the UI follows.
    func refresh() async {
        guard let session else { return }
        let peers = Array(histories.keys)
        let followedGroups = Array(groupHistories.keys)
        do {
            let selected = selectedLabelIds
            let filterMode = labelFilterMode
            let requestedFolder = folderSelection
            let snapshot = try await run { () -> AppRefreshSnapshot in
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
                let liveContacts = try session.contacts()
                let folders = try session.folders()
                let missingFolder = requestedFolder.kind == .folder &&
                    folders.contains(where: { $0.id == requestedFolder.id }) == false
                let appliedFolder = missingFolder
                    ? FolderSelection(kind: .all, id: nil) : requestedFolder
                let filter = try session.pinConversations(
                    selection: appliedFolder, labels: selected, mode: filterMode)
                var memberships: [String: [KommsCore.Label]] = [:]
                for contact in liveContacts {
                    let target = LabelTarget(kind: .peer, id: contact.peer)
                    memberships[AppModel.labelTargetKey(target)] =
                        try session.labelsForConversation(target: target)
                }
                for group in liveGroups {
                    let target = LabelTarget(kind: .group, id: group.id)
                    memberships[AppModel.labelTargetKey(target)] =
                        try session.labelsForConversation(target: target)
                }
                let note = LabelTarget(kind: .noteToSelf, id: nil)
                memberships[AppModel.labelTargetKey(note)] =
                    try session.labelsForConversation(target: note)
                var icons: [CustomIconTarget: CustomIcon] = [:]
                let noteIconTarget = CustomIconTarget(kind: .noteToSelf, id: nil)
                if let icon = try session.customIcon(target: noteIconTarget) {
                    icons[noteIconTarget] = icon
                }
                for contact in liveContacts {
                    let target = CustomIconTarget(kind: .contact, id: contact.peer)
                    if let icon = try session.customIcon(target: target) { icons[target] = icon }
                }
                for group in liveGroups {
                    let target = CustomIconTarget(kind: .group, id: group.id)
                    if let icon = try session.customIcon(target: target) { icons[target] = icon }
                }
                for folder in folders {
                    let target = CustomIconTarget(kind: .folder, id: folder.id)
                    if let icon = try session.customIcon(target: target) { icons[target] = icon }
                }
                return AppRefreshSnapshot(
                    status: try session.status(), contacts: liveContacts, histories: fresh,
                    groups: liveGroups, groupHistories: freshGroups,
                    scheduled: try session.scheduledMessages(), attachments: try session.attachments(),
                    notes: try session.noteToSelfMessages(), folders: folders,
                    staleFolders: try session.staleFolders(), folderWasMissing: missingFolder,
                    labels: try session.labels(), stale: try session.staleLabels(),
                    filter: filter, memberships: memberships,
                    pins: try session.pins(), stalePins: try session.stalePins(),
                    customIcons: icons, customIconUsage: try session.customIconUsage())
            }
            status = snapshot.status
            contacts = snapshot.contacts
            histories.merge(snapshot.histories) { _, new in new }
            groups = snapshot.groups
            groupHistories.merge(snapshot.groupHistories) { _, new in new }
            scheduledMessages = snapshot.scheduled
            attachments = snapshot.attachments
            noteHistory = snapshot.notes
            folders = snapshot.folders
            staleFolderRecords = snapshot.staleFolders
            folderSelection = snapshot.filter.selection
            labels = snapshot.labels
            staleLabelRecords = snapshot.stale
            conversationLabels = snapshot.memberships
            matchingLabelTargets = Set(snapshot.filter.conversations.map { Self.labelTargetKey($0.target) })
            pins = snapshot.pins
            pinRows = snapshot.filter.conversations
            stalePinRecords = snapshot.stalePins
            customIcons = snapshot.customIcons
            customIconUsage = snapshot.customIconUsage
            if snapshot.folderWasMissing {
                notices.append("The selected private folder is unavailable; showing All conversations.")
            }
            if snapshot.filter.unavailableLabels.isEmpty == false {
                notices.append("\(snapshot.filter.unavailableLabels.count) unavailable selected label(s) were removed.")
            }
            selectedLabelIds = snapshot.filter.selectedLabels
            persistLabelFilter()
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

    func customIcon(for target: CustomIconTarget) -> CustomIcon? { customIcons[target] }

    func setCustomIcon(target: CustomIconTarget, glyph: String) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.setCustomIcon(target: target, glyph: glyph) }
        await refresh()
    }

    func setCustomIcon(target: CustomIconTarget, source: URL) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.setCustomIcon(target: target, source: source) }
        await refresh()
    }

    func clearCustomIcon(target: CustomIconTarget) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.clearCustomIcon(target: target) }
        await refresh()
    }

    nonisolated static func labelTargetKey(_ target: LabelTarget) -> String {
        switch target.kind {
        case .peer: return "peer:\(target.id ?? "")"
        case .group: return "group:\(target.id ?? "")"
        case .noteToSelf: return "note_to_self:"
        }
    }

    nonisolated static func labelTargetKey(_ target: FolderTarget) -> String {
        switch target.kind {
        case .peer: return "peer:\(target.id ?? "")"
        case .group: return "group:\(target.id ?? "")"
        case .noteToSelf: return "note_to_self:"
        }
    }

    nonisolated static func labelTargetKey(_ target: PinTarget) -> String {
        switch target.kind {
        case .peer: return "peer:\(target.id ?? "")"
        case .group: return "group:\(target.id ?? "")"
        case .noteToSelf: return "note_to_self:"
        }
    }

    func isPinned(_ target: PinTarget) -> Bool {
        pins.contains { Self.labelTargetKey($0.target) == Self.labelTargetKey(target) }
    }

    func togglePin(_ target: PinTarget) {
        guard let session else { return }
        Task {
            do {
                if isPinned(target) { _ = try await run { try session.unpinConversation(target: target) } }
                else { _ = try await run { try session.pinConversation(target: target) } }
                await refresh()
            } catch { notices.append(error.localizedDescription) }
        }
    }

    func movePin(_ target: PinTarget, by offset: Int) {
        guard let session,
              let index = pins.firstIndex(where: { Self.labelTargetKey($0.target) == Self.labelTargetKey(target) })
        else { return }
        let destination = index + offset
        guard pins.indices.contains(destination) else { return }
        var order = pins.map(\.target)
        order.swapAt(index, destination)
        Task {
            do { _ = try await run { try session.reorderPins(targets: order) }; await refresh() }
            catch { notices.append(error.localizedDescription) }
        }
    }

    func cleanupStalePin(_ target: PinTarget) {
        guard let session else { return }
        Task {
            do { _ = try await run { try session.cleanupStalePin(target: target) }; await refresh() }
            catch { notices.append(error.localizedDescription) }
        }
    }

    func labelsForTarget(_ target: LabelTarget) -> [KommsCore.Label] {
        conversationLabels[Self.labelTargetKey(target)] ?? []
    }

    func targetMatchesLabelFilter(_ target: LabelTarget) -> Bool {
        matchingLabelTargets.contains(Self.labelTargetKey(target))
    }

    func selectFolder(_ selection: FolderSelection) {
        folderSelection = selection
        persistLabelFilter()
        Task { await refresh() }
    }

    func setLabelSelected(_ id: String, selected: Bool) {
        if selected && selectedLabelIds.contains(id) == false { selectedLabelIds.append(id) }
        else { selectedLabelIds.removeAll { $0 == id } }
        persistLabelFilter()
        Task { await refresh() }
    }

    func setLabelFilterMode(_ mode: LabelMatchMode) {
        labelFilterMode = mode
        persistLabelFilter()
        Task { await refresh() }
    }

    func clearLabelFilter() {
        selectedLabelIds = []
        persistLabelFilter()
        Task { await refresh() }
    }

    private func persistLabelFilter() {
        let folderKind: String
        switch folderSelection.kind {
        case .all: folderKind = "all"
        case .unfiled: folderKind = "unfiled"
        case .folder: folderKind = "folder"
        }
        LabelFilterStore.save(.init(
            ids: selectedLabelIds,
            mode: labelFilterMode == .all ? "all" : "any",
            folderKind: folderKind,
            folderId: folderSelection.id))
    }

    // MARK: commands (all forwarded verbatim to the session layer)

    func send(peer: String, body: String) async throws {
        guard let session else { return }
        _ = try await run { try session.send(peer: peer, body: body) }
        await refresh()
    }

    /// Stage a security-scoped document privately. Content-verified JPEG/PNG
    /// enters the shared editor; every other file enters explicit F4 review.
    func prepareAttachment(
        source: URL, mediaType: String, filename: String?
    ) async throws -> PreparedAttachment {
        guard let session else { throw InputError("node is locked") }
        let claimedImage = isClaimedImage(mediaType: mediaType, filename: filename)
        return try await run {
            let original = try stageProtectedAttachment(
                source, maxBytes: claimedImage ? imageSourceLimit : attachmentLimit)
            let final = FileManager.default.temporaryDirectory
                .appendingPathComponent("komms-image-final-\(UUID().uuidString).png")
            do {
                let recipe = LocalImageRecipe()
                let info = try session.renderEditedImage(
                    source: original, destination: final, recipe: recipe.ffi())
                try protectTransient(final)
                return PreparedAttachment(image: PreparedImage(
                    original: original,
                    finalAsset: final,
                    orientedWidth: info.width,
                    orientedHeight: info.height,
                    width: info.width,
                    height: info.height,
                    encodedBytes: info.encodedBytes,
                    recipe: recipe,
                    filename: outputImageName(filename)))
            } catch {
                try? FileManager.default.removeItem(at: final)
                if claimedImage {
                    try? FileManager.default.removeItem(at: original)
                    throw error
                }
                return PreparedAttachment(
                    generic: PreparedFile(
                        staged: original, mediaType: mediaType,
                        filename: filename ?? "attachment"))
            }
        }
    }

    /// Replace one exact final image through the shared deterministic helper.
    func updatePreparedImage(
        _ image: PreparedImage, recipe: LocalImageRecipe
    ) async throws -> PreparedImage {
        guard let session else { throw InputError("node is locked") }
        return try await run {
            let replacement = FileManager.default.temporaryDirectory
                .appendingPathComponent("komms-image-final-\(UUID().uuidString).png")
            do {
                let info = try session.renderEditedImage(
                    source: image.original, destination: replacement, recipe: recipe.ffi())
                try protectTransient(replacement)
                var updated = image
                updated.finalAsset = replacement
                updated.width = info.width
                updated.height = info.height
                updated.encodedBytes = info.encodedBytes
                updated.recipe = recipe
                return updated
            } catch {
                try? FileManager.default.removeItem(at: replacement)
                throw error
            }
        }
    }

    /// Authoritative F4 wording shown before every file/image send action.
    func attachmentCarrierExplanation(destination: AttachmentDestination) async throws -> String {
        guard let session else { throw InputError("node is locked") }
        return try await run {
            switch destination {
            case .peer(let peer): return try session.attachmentCarrierExplanation(peer: peer)
            case .group(let group):
                return try session.groupAttachmentCarrierExplanation(group: group)
            }
        }
    }

    /// Recheck the F4 snapshot and import the reviewed protected path. A
    /// changed explanation is returned as a typed local error for reconfirmation.
    func sendPreparedAttachment(
        destination: AttachmentDestination,
        prepared: PreparedAttachment,
        expectedCarrier: String
    ) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run {
            let current: String
            switch destination {
            case .peer(let peer): current = try session.attachmentCarrierExplanation(peer: peer)
            case .group(let group):
                current = try session.groupAttachmentCarrierExplanation(group: group)
            }
            guard current == expectedCarrier else {
                throw InputError("carrier_changed:\(current)")
            }
            switch (destination, prepared.kind) {
            case (.peer(let peer), .generic(let file)):
                return try session.sendAttachment(
                    peer: peer, path: file.staged, mediaType: file.mediaType,
                    filename: file.filename)
            case (.group(let group), .generic(let file)):
                return try session.sendGroupAttachment(
                    group: group, path: file.staged, mediaType: file.mediaType,
                    filename: file.filename)
            case (.peer(let peer), .image(let image)):
                _ = try session.probeImage(image.finalAsset)
                return try session.sendAttachment(
                    peer: peer, path: image.finalAsset, mediaType: "image/png",
                    filename: image.filename)
            case (.group(let group), .image(let image)):
                _ = try session.probeImage(image.finalAsset)
                return try session.sendGroupAttachment(
                    group: group, path: image.finalAsset, mediaType: "image/png",
                    filename: image.filename)
            }
        }
        prepared.remove()
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
        try protectTransient(directory)
        let basename = URL(fileURLWithPath: filename ?? "attachment").lastPathComponent
        let destination = directory.appendingPathComponent(
            basename.isEmpty ? "attachment" : basename, isDirectory: false)
        do {
            try await run {
                try session.exportAttachment(transfer: transfer, to: destination)
                try protectTransient(destination)
            }
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
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-render-preview-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try protectTransient(directory)
        let path = directory.appendingPathComponent("preview.jpg")
        defer { try? FileManager.default.removeItem(at: directory) }
        try await run {
            try session.exportAttachmentPreview(transfer: transfer, to: path)
            try protectTransient(path)
        }
        let data = try Data(contentsOf: path, options: .mappedIfSafe)
        guard data.count <= previewLimit else {
            throw InputError("attachment preview exceeds the 256 KiB limit")
        }
        return data
    }

    /// Materialize a completed canonical edited primary only long enough to
    /// validate and render its exact protected bytes.
    func attachmentImage(transfer: String) async throws -> Data {
        guard let session else { throw InputError("node is locked") }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-render-image-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try protectTransient(directory)
        let path = directory.appendingPathComponent("image.png")
        defer { try? FileManager.default.removeItem(at: directory) }
        let info = try await run {
            try session.exportAttachment(transfer: transfer, to: path)
            try protectTransient(path)
            return try session.probeImage(path)
        }
        let data = try Data(contentsOf: path, options: .mappedIfSafe)
        guard UInt64(data.count) == info.encodedBytes else {
            throw InputError("canonical edited image changed during protected preview")
        }
        return data
    }

    /// Canonicalize a native linear-PCM WAVE recording, strip every extra
    /// chunk, and derive duration/waveform locally before review.
    func prepareAudioReview(source: URL) async throws -> ProtectedAudio {
        guard let session else { throw InputError("node is locked") }
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-audio-\(UUID().uuidString).wav")
        defer { try? FileManager.default.removeItem(at: source) }
        do {
            let info = try await run {
                try session.canonicalizeAudio(source: source, destination: destination)
            }
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: destination.path)
            return ProtectedAudio(file: destination, info: info)
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    /// Authoritative F4 wording shown before the explicit send action.
    func audioCarrierExplanation(destination: RecordedAudioDestination) async throws -> String {
        guard let session else { throw InputError("node is locked") }
        return try await run {
            switch destination {
            case .peer(let peer): return try session.audioCarrierExplanation(peer: peer)
            case .group(let group): return try session.groupAudioCarrierExplanation(group: group)
            }
        }
    }

    /// Import one reviewed canonical clip through the ordinary F3 attachment path.
    func sendRecordedAudio(
        destination: RecordedAudioDestination,
        audio: ProtectedAudio
    ) async throws {
        guard let session else { throw InputError("node is locked") }
        let file = audio.file
        _ = try await run {
            switch destination {
            case .peer(let peer):
                return try session.sendAttachment(
                    peer: peer, path: file, mediaType: "audio/wav",
                    filename: "audio-message.wav")
            case .group(let group):
                return try session.sendGroupAttachment(
                    group: group, path: file, mediaType: "audio/wav",
                    filename: "audio-message.wav")
            }
        }
        audio.remove()
        await refresh()
    }

    /// Materialize a completed clip through a protected transient for explicit
    /// local playback. The view removes it when playback ends or disappears.
    func attachmentAudio(transfer: String) async throws -> ProtectedAudio {
        guard let session else { throw InputError("node is locked") }
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-audio-playback-\(UUID().uuidString).wav")
        do {
            let info = try await run {
                try session.exportAttachment(transfer: transfer, to: path)
                return try session.probeAudio(path)
            }
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete], ofItemAtPath: path.path)
            return ProtectedAudio(file: path, info: info)
        } catch {
            try? FileManager.default.removeItem(at: path)
            throw error
        }
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

    func groupMentionCapability(group: String) async throws -> GroupMentionCapability {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.groupMentionCapability(group: group) }
    }

    func sendGroupMention(
        group: String,
        text: String,
        spans: [MentionSpan],
        reviewToken: String
    ) async throws {
        guard let session else { return }
        _ = try await run {
            try session.sendGroupMention(
                group: group, text: text, spans: spans, reviewToken: reviewToken)
        }
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

    func createFolder(name: String) async throws -> KommsCore.Folder {
        guard let session else { throw InputError("node is locked") }
        let folder = try await run { try session.createFolder(name: name) }
        await refresh()
        return folder
    }

    func renameFolder(id: String, name: String) async throws -> KommsCore.Folder {
        guard let session else { throw InputError("node is locked") }
        let folder = try await run { try session.renameFolder(id: id, name: name) }
        await refresh()
        return folder
    }

    func reorderFolders(ids: [String]) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.reorderFolders(ids: ids) }
        await refresh()
    }

    func folderDeleteAssignmentCount(id: String) async throws -> UInt64 {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.folderDeleteAssignmentCount(id: id) }
    }

    func deleteFolder(id: String) async throws -> UInt64 {
        guard let session else { throw InputError("node is locked") }
        let count = try await run { try session.deleteFolder(id: id, confirm: true) }
        await refresh()
        return count
    }

    func conversationFolder(target: FolderTarget) async throws -> KommsCore.Folder? {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.conversationFolder(target: target) }
    }

    func setFolder(_ id: String?, target: FolderTarget) async throws -> KommsCore.Folder? {
        guard let session else { throw InputError("node is locked") }
        let final = try await run {
            if let id { _ = try session.moveToFolder(id: id, target: target) }
            else { _ = try session.unfileConversation(target: target) }
            return try session.conversationFolder(target: target)
        }
        await refresh()
        return final
    }

    func cleanupStaleFolder(id: String, target: FolderTarget) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.cleanupStaleFolder(id: id, target: target) }
        await refresh()
    }

    func createLabel(name: String, color: String) async throws -> KommsCore.Label {
        guard let session else { throw InputError("node is locked") }
        let label = try await run { try session.createLabel(name: name, color: color) }
        await refresh()
        return label
    }

    func updateLabel(id: String, name: String, color: String) async throws -> KommsCore.Label {
        guard let session else { throw InputError("node is locked") }
        let label = try await run { try session.updateLabel(id: id, name: name, color: color) }
        await refresh()
        return label
    }

    func labelDeleteAssignmentCount(id: String) async throws -> UInt64 {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.labelDeleteAssignmentCount(id: id) }
    }

    func deleteLabel(id: String) async throws -> UInt64 {
        guard let session else { throw InputError("node is locked") }
        let count = try await run { try session.deleteLabel(id: id, confirm: true) }
        await refresh()
        return count
    }

    func setLabel(_ id: String, assigned: Bool, target: LabelTarget) async throws -> [KommsCore.Label] {
        guard let session else { throw InputError("node is locked") }
        let final = try await run {
            if assigned { _ = try session.assignLabel(id: id, target: target) }
            else { _ = try session.unassignLabel(id: id, target: target) }
            return try session.labelsForConversation(target: target)
        }
        conversationLabels[Self.labelTargetKey(target)] = final
        return final
    }

    func cleanupStaleLabel(id: String, target: LabelTarget) async throws {
        guard let session else { throw InputError("node is locked") }
        _ = try await run { try session.cleanupStaleLabel(id: id, target: target) }
        await refresh()
    }

    /// Write the encrypted backup and hand back the one-time mnemonic.
    func exportBackup(to path: URL) async throws -> String {
        guard let session else { throw InputError("node is locked") }
        return try await run { try session.exportBackup(to: path) }
    }
}

private struct AppRefreshSnapshot: Sendable {
    let status: Status
    let contacts: [Contact]
    let histories: [String: [Message]]
    let groups: [KommsCore.Group]
    let groupHistories: [String: [GroupMessage]]
    let scheduled: [ScheduledMessage]
    let attachments: [Attachment]
    let notes: [NoteMessage]
    let folders: [KommsCore.Folder]
    let staleFolders: [StaleFolder]
    let folderWasMissing: Bool
    let labels: [KommsCore.Label]
    let stale: [StaleLabel]
    let filter: PinConversationResult
    let memberships: [String: [KommsCore.Label]]
    let pins: [Pin]
    let stalePins: [Pin]
    let customIcons: [CustomIconTarget: CustomIcon]
    let customIconUsage: CustomIconQuotaUsage
}

private let attachmentLimit = 512 * 1024 * 1024
private let attachmentCopySize = 64 * 1024
private let imageSourceLimit = 32 * 1024 * 1024
private let previewLimit = 256 * 1024

struct LocalImageCrop: Sendable, Equatable {
    var x: UInt32
    var y: UInt32
    var width: UInt32
    var height: UInt32

    func ffi() -> ImageCrop { ImageCrop(x: x, y: y, width: width, height: height) }
}

enum LocalImageRegionKind: String, Sendable, CaseIterable {
    case blur
    case pixelate
}

struct LocalImageRegion: Sendable, Equatable, Identifiable {
    let id = UUID()
    var kind: LocalImageRegionKind
    var x: UInt32
    var y: UInt32
    var width: UInt32
    var height: UInt32
    var strength: UInt32

    func ffi() -> ImageEditRegion {
        ImageEditRegion(
            kind: kind == .blur ? .blur : .pixelate,
            x: x, y: y, width: width, height: height, strength: strength)
    }
}

struct LocalImageRecipe: Sendable, Equatable {
    var crop: LocalImageCrop?
    var rotation: UInt8
    var regions: [LocalImageRegion]

    init(crop: LocalImageCrop? = nil, rotation: UInt8 = 0, regions: [LocalImageRegion] = []) {
        self.crop = crop
        self.rotation = rotation
        self.regions = regions
    }

    func ffi() -> ImageEditRecipe {
        ImageEditRecipe(
            crop: crop?.ffi(), rotationQuarterTurns: rotation,
            regions: regions.map { $0.ffi() })
    }
}

struct PreparedImage: Sendable {
    let original: URL
    var finalAsset: URL
    let orientedWidth: UInt32
    let orientedHeight: UInt32
    var width: UInt32
    var height: UInt32
    var encodedBytes: UInt64
    var recipe: LocalImageRecipe
    var filename: String
}

struct PreparedFile: Sendable {
    let staged: URL
    let mediaType: String
    var filename: String
}

enum PreparedAttachmentKind: Sendable {
    case image(PreparedImage)
    case generic(PreparedFile)
}

struct PreparedAttachment: Identifiable, Sendable {
    let id = UUID()
    var kind: PreparedAttachmentKind

    init(image: PreparedImage) { kind = .image(image) }
    init(generic: PreparedFile) { kind = .generic(generic) }

    func remove() {
        switch kind {
        case .image(let image):
            try? FileManager.default.removeItem(at: image.original)
            try? FileManager.default.removeItem(at: image.finalAsset)
        case .generic(let file):
            try? FileManager.default.removeItem(at: file.staged)
        }
    }
}

/// Copy one security-scoped provider document into a unique app-private file
/// with bounded memory and an explicit size ceiling. The caller holds the
/// security scope open for this blocking operation.
private func stageProtectedAttachment(_ source: URL, maxBytes: Int) throws -> URL {
    let staged = FileManager.default.temporaryDirectory
        .appendingPathComponent("komms-attachment-\(UUID().uuidString)")
    guard FileManager.default.createFile(atPath: staged.path, contents: nil) else {
        throw InputError("the selected document could not be staged")
    }
    do {
        try protectTransient(staged)
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = try FileHandle(forWritingTo: staged)
        defer { try? output.close() }
        var copied = 0
        while let chunk = try input.read(upToCount: attachmentCopySize), !chunk.isEmpty {
            copied += chunk.count
            guard copied <= maxBytes else {
                throw InputError("this selection exceeds the protected staging limit")
            }
            try output.write(contentsOf: chunk)
        }
        try output.synchronize()
        return staged
    } catch {
        try? FileManager.default.removeItem(at: staged)
        throw error
    }
}

private func protectTransient(_ url: URL) throws {
    try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    var protected = url
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    try protected.setResourceValues(values)
}

private func isClaimedImage(mediaType: String, filename: String?) -> Bool {
    let ext = filename.map { URL(fileURLWithPath: $0).pathExtension.lowercased() }
    return mediaType == "image/jpeg" || mediaType == "image/png"
        || ext == "jpg" || ext == "jpeg" || ext == "png"
}

private func outputImageName(_ filename: String?) -> String {
    guard let filename, !filename.isEmpty else { return "edited-image.png" }
    let stem = (filename as NSString).deletingPathExtension
    return (stem.isEmpty ? "edited-image" : stem) + ".png"
}

/// One error string for any failure the UI shows: the node's words for FFI
/// errors, this layer's words for input it rejected.
func errorText(_ error: Error) -> String {
    if let ffi = error as? FfiError { return ffi.reasonText }
    if let input = error as? InputError { return input.message }
    if let settings = error as? SettingsError { return settings.message }
    return String(describing: error)
}
