// The iOS shell's view of a running node: a thin, testable layer over
// `kult-ffi`'s KultNode, mirroring the desktop app's `session.rs` and the
// Android shell's `Session.kt`.
//
// Everything the UI can do goes through `Session` — views call these
// methods (off the main thread) and nothing else. That keeps the whole
// behavior testable without a simulator: the e2e test drives two `Session`s
// through exactly this surface, on Linux or macOS.
//
// The shell adds **no** protocol logic. Honesty rules from the core carry
// through verbatim: delivery states come from the node (`delivered` means an
// end-to-end encrypted receipt), errors are the node's own words, and the
// backup mnemonic is returned exactly once and never stored.

import Foundation

extension FfiError {
    /// Human-readable text for an FFI failure — the node's own words.
    public var reasonText: String {
        switch self {
        case .Startup(let reason): return "startup: \(reason)"
        case .Node(let reason): return reason
        case .Stopped: return "node is stopped"
        }
    }
}

/// QR text for a prekey bundle's hex: uppercase keeps the QR in its compact
/// alphanumeric mode (hex decoding is case-insensitive everywhere), and the
/// payload is interoperable with the desktop and Android pairing QRs and
/// `kult bundle` / `kult add`.
public func bundleQrText(_ bundleHex: String) -> String { bundleHex.uppercased() }

/// QR text for a safety number: uppercase hex of the raw 32-byte comparison
/// value — both parties render the identical code, on any platform.
public func safetyQrText(_ sn: SafetyNumber) -> String { hexEncode(sn.qr).uppercased() }

/// Where the shell delivers node events. Called on `kult-ffi`'s dedicated
/// event thread — the app marshals to its main actor.
public typealias EventSink = @Sendable (Event) -> Void

/// Adapter: `kult-ffi`'s listener protocol onto an ``EventSink``.
private final class Forwarder: EventListener {
    private let sink: EventSink
    init(_ sink: @escaping EventSink) { self.sink = sink }
    func onEvent(event: Event) { sink(event) }
}

/// A running node plus the shell-side conveniences the UI needs. Construct
/// with ``Session/open(dataDir:passphrase:settings:kdf:sink:)`` or
/// ``Session/restore(dataDir:passphrase:backupPath:mnemonic:settings:kdf:sink:)``;
/// methods are blocking — call them off the main thread. Errors surface as
/// `FfiError` (the node's own words — use ``FfiError/reasonText``) or
/// ``InputError`` for input this layer rejects before it reaches the node.
public final class Session: @unchecked Sendable {
    private let node: KultNode

    private init(node: KultNode) { self.node = node }

    /// This node's human-shareable kult address.
    public var address: String { node.address() }

    /// This node's peer id (hex).
    public var peer: String { node.peer() }

    /// Status snapshot for the UI's transport indicators.
    public func status() throws -> Status { try node.status() }

    /// Export a fresh prekey bundle as pasteable hex. Render
    /// ``bundleQrText(_:)`` of it for the pairing QR.
    public func myBundleHex() throws -> String { hexEncode(try node.handshakeBundle()) }

    /// Add a contact from pasted/scanned bundle hex, with delivery hints.
    /// Returns the new contact's peer id.
    public func addContact(name: String, bundleHex: String, hints: [HintSpec]) throws -> String {
        guard let bundle = hexDecode(bundleHex) else {
            throw InputError("bundle must be hex")
        }
        return try node.addContact(name: name, bundle: bundle, hints: hints.toFfi())
    }

    /// Add a contact from their kult address alone (DHT lookup).
    public func addContact(name: String, address: String) throws -> String {
        try node.addContactByAddress(
            name: name,
            address: address.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// All stored contacts.
    public func contacts() throws -> [Contact] { try node.contacts() }

    /// Message history with a peer.
    public func messages(peer: String) throws -> [Message] { try node.messagesWith(peer: peer) }

    /// Queue a message; returns its id (progress arrives as events).
    public func send(peer: String, body: String) throws -> String {
        try node.send(peer: peer, body: body)
    }

    /// Import one app-private, caller-selected path as a pairwise attachment.
    /// The SwiftUI shell stages a security-scoped document at this path and
    /// deletes it after this blocking call returns.
    public func sendAttachment(
        peer: String,
        path: URL,
        mediaType: String,
        filename: String?
    ) throws -> String {
        try node.sendAttachment(
            peer: peer, path: path.path, mediaType: mediaType, filename: filename)
    }

    /// Import a pairwise attachment plus a locally generated sealed preview.
    public func sendAttachmentWithPreview(
        peer: String,
        path: URL,
        mediaType: String,
        filename: String?,
        preview: URL
    ) throws -> String {
        try node.sendAttachmentWithPreview(
            peer: peer, path: path.path, mediaType: mediaType, filename: filename,
            previewPath: preview.path, previewMediaType: "image/jpeg")
    }

    /// Import one app-private path as an encrypt-once group attachment.
    public func sendGroupAttachment(
        group: String,
        path: URL,
        mediaType: String,
        filename: String?
    ) throws -> String {
        try node.sendGroupAttachment(
            group: group, path: path.path, mediaType: mediaType, filename: filename)
    }

    /// Import a group attachment plus a locally generated sealed preview.
    public func sendGroupAttachmentWithPreview(
        group: String,
        path: URL,
        mediaType: String,
        filename: String?,
        preview: URL
    ) throws -> String {
        try node.sendGroupAttachmentWithPreview(
            group: group, path: path.path, mediaType: mediaType, filename: filename,
            previewPath: preview.path, previewMediaType: "image/jpeg")
    }

    /// Every supported transfer as render-safe state.
    public func attachments() throws -> [Attachment] { try node.attachments() }

    /// Accept an inbound attachment offer.
    public func acceptAttachment(transfer: String) throws {
        try node.acceptAttachment(transfer: transfer)
    }

    /// Durably reject an inbound attachment offer.
    public func rejectAttachment(transfer: String) throws {
        try node.rejectAttachment(transfer: transfer)
    }

    /// Cancel local transfer work and release unreferenced partial data.
    public func cancelAttachment(transfer: String) throws {
        try node.cancelAttachment(transfer: transfer)
    }

    /// Pause attachment work while retaining verified progress.
    public func pauseAttachment(transfer: String) throws {
        try node.pauseAttachment(transfer: transfer)
    }

    /// Resume a paused transfer from durable verified progress.
    public func resumeAttachment(transfer: String) throws {
        try node.resumeAttachment(transfer: transfer)
    }

    /// Stream a completed primary object to a protected, new app-private path.
    public func exportAttachment(transfer: String, to path: URL) throws {
        try node.exportAttachment(transfer: transfer, path: path.path)
    }

    /// Decrypt a sealed preview into a protected app-private path.
    public func exportAttachmentPreview(transfer: String, to path: URL) throws {
        try node.exportAttachmentPreview(transfer: transfer, path: path.path)
    }

    /// Rewrite native PCM WAVE into Komms's bounded metadata-free profile.
    public func canonicalizeAudio(source: URL, destination: URL) throws -> AudioInfo {
        try canonicalizeRecordedAudio(source: source.path, destination: destination.path)
    }

    /// Validate canonical audio and derive duration/waveform only on this device.
    public func probeAudio(_ path: URL) throws -> AudioInfo {
        try probeRecordedAudio(path: path.path)
    }

    /// Apply the shared bounded image recipe into a protected create-new destination.
    public func renderEditedImage(
        source: URL, destination: URL, recipe: ImageEditRecipe
    ) throws -> ImageInfo {
        try editImage(source: source.path, destination: destination.path, recipe: recipe)
    }

    /// Validate the exact metadata-free canonical image profile before import or preview.
    public func probeImage(_ path: URL) throws -> ImageInfo {
        try probeEditedImage(path: path.path)
    }

    /// Current authoritative carrier explanation for pairwise file/image confirmation.
    public func attachmentCarrierExplanation(peer: String) throws -> String {
        try carrierExplanation(recipients: [peer], subject: "attachment")
    }

    /// Current authoritative carrier explanation for every current group recipient.
    public func groupAttachmentCarrierExplanation(group: String) throws -> String {
        guard let group = try groups().first(where: { $0.id == group }) else {
            throw InputError("unknown group")
        }
        return try carrierExplanation(
            recipients: group.members.filter { $0 != peer }, subject: "attachment")
    }

    /// Current authoritative carrier explanation for pairwise audio confirmation.
    public func audioCarrierExplanation(peer: String) throws -> String {
        try carrierExplanation(recipients: [peer], subject: "audio")
    }

    /// Current authoritative carrier explanation for every other current group member.
    public func groupAudioCarrierExplanation(group: String) throws -> String {
        guard let group = try groups().first(where: { $0.id == group }) else {
            throw InputError("unknown group")
        }
        return try carrierExplanation(
            recipients: group.members.filter { $0 != peer }, subject: "audio")
    }

    private func carrierExplanation(recipients: [String], subject: String) throws -> String {
        let snapshots = Dictionary(uniqueKeysWithValues: try node.carrierCapabilities().map {
            ($0.peer, $0.capability)
        })
        let mesh = recipients.filter { snapshots[$0] == .meshOnly }.count
        let unavailable = recipients.filter {
            guard let capability = snapshots[$0] else { return true }
            return capability != .realtime && capability != .bulk && capability != .meshOnly
        }.count
        if recipients.isEmpty {
            return "This group has no other current recipients; no \(subject) delivery will be created."
        }
        if mesh > 0 && unavailable > 0 {
            return "\(mesh) recipient(s) have only a mesh route, so \(subject) waits for a faster link and emits zero manifest, chunk, missing-range, or other bulk mesh frames; "
                + "\(unavailable) more have no fresh route. Recipients with a fresh realtime or bulk link can proceed."
        }
        if mesh > 0 {
            return "Will send when a faster link exists for \(mesh) recipient(s). This \(subject) emits zero manifest, chunk, missing-range, or other bulk mesh frames."
        }
        if unavailable > 0 {
            return "Will remain queued locally until \(unavailable) recipient(s) have a fresh faster link."
        }
        return "Every current recipient has a fresh realtime or bulk link; normal attachment quotas apply."
    }

    /// Schedule pairwise text at an absolute UTC Unix instant.
    public func schedule(peer: String, body: String, notBefore: UInt64) throws -> String {
        try node.schedule(peer: peer, body: body, notBefore: notBefore)
    }

    /// Schedule group text at an absolute UTC Unix instant.
    public func scheduleGroup(group: String, body: String, notBefore: UInt64) throws -> String {
        try node.scheduleGroup(group: group, body: body, notBefore: notBefore)
    }

    /// Edit text and/or the UTC instant before activation.
    public func editScheduled(message: String, body: String, notBefore: UInt64) throws {
        try node.editScheduled(message: message, body: body, notBefore: notBefore)
    }

    /// Cancel a scheduled message before activation.
    public func cancelScheduled(message: String) throws {
        try node.cancelScheduled(message: message)
    }

    /// Full durable scheduled outbox.
    public func scheduledMessages() throws -> [ScheduledMessage] {
        try node.scheduledMessages()
    }

    /// Stable reserved identity for the local note-to-self conversation.
    public func noteToSelfId() -> String { node.noteToSelfId() }

    /// All sealed local-only note-to-self entries.
    public func noteToSelfMessages() throws -> [NoteMessage] { try node.noteToSelfMessages() }

    /// Append one sealed local-only note; no transport work is created.
    public func sendNoteToSelf(body: String) throws -> String {
        try node.sendNoteToSelf(body: body)
    }

    /// Create a sender-key group from stored contacts; returns its id.
    public func createGroup(name: String, members: [String]) throws -> String {
        try node.createGroup(name: name, members: members)
    }

    /// All live groups, excluding secrets and sender chains.
    public func groups() throws -> [Group] { try node.groups() }

    /// Message history for a group, including per-member delivery states.
    public func groupMessages(group: String) throws -> [GroupMessage] {
        try node.groupMessages(group: group)
    }

    /// Queue a group message; progress is reported independently per member.
    public func sendGroup(group: String, body: String) throws -> String {
        try node.sendGroup(group: group, body: body)
    }

    /// Add a stored contact to a group (creator only).
    public func addGroupMember(group: String, peer: String) throws {
        try node.addGroupMember(group: group, peer: peer)
    }

    /// Remove a member and rotate group keys (creator only).
    public func removeGroupMember(group: String, peer: String) throws {
        try node.removeGroupMember(group: group, peer: peer)
    }

    /// Leave a group; local message history remains stored.
    public func leaveGroup(group: String) throws { try node.leaveGroup(group: group) }

    /// The safety number with a peer (render ``safetyQrText(_:)`` for the QR).
    public func safetyNumber(peer: String) throws -> SafetyNumber {
        try node.safetyNumber(peer: peer)
    }

    /// Record an out-of-band verification.
    public func markVerified(peer: String) throws { try node.markVerified(peer: peer) }

    /// Replace a contact's delivery hints.
    public func setHints(peer: String, hints: [HintSpec]) throws {
        try node.setHints(peer: peer, hints: hints.toFfi())
    }

    /// Publish the prekey bundle on the DHT now.
    public func publish() throws { try node.publish() }

    /// Write an encrypted backup file; returns the one-time 24-word
    /// mnemonic. The shell shows it exactly once and keeps no copy.
    public func exportBackup(to path: URL) throws -> String {
        try node.exportBackup(path: path.path)
    }

    /// Stop the node (idempotent; the handle is spent afterwards).
    public func stop() { node.stop() }

    /// Open (or create on first run) the store in `dataDir` and start the
    /// node. Blocking: Argon2id and transport binding happen before this
    /// returns, so a wrong passphrase is a startup error — never a broken
    /// half-running node. `kdf` is the cost profile for store *creation*
    /// (the app passes `.mobile`).
    public static func open(
        dataDir: URL,
        passphrase: String,
        settings: NetworkSettings,
        kdf: KdfChoice,
        sink: @escaping EventSink
    ) throws -> Session {
        Session(
            node: try KultNode.start(
                config: buildConfig(dataDir: dataDir, passphrase: passphrase,
                                    settings: settings, kdf: kdf),
                listener: Forwarder(sink)))
    }

    /// First run only: restore from an encrypted backup file instead of
    /// creating a fresh identity, then start.
    public static func restore(
        dataDir: URL,
        passphrase: String,
        backupPath: URL,
        mnemonic: String,
        settings: NetworkSettings,
        kdf: KdfChoice,
        sink: @escaping EventSink
    ) throws -> Session {
        Session(
            node: try KultNode.restore(
                config: buildConfig(dataDir: dataDir, passphrase: passphrase,
                                    settings: settings, kdf: kdf),
                backupPath: backupPath.path,
                mnemonic: mnemonic,
                listener: Forwarder(sink)))
    }

    /// The FFI config for this data dir + settings: `kult-ffi`'s baseline
    /// with the user's network settings on top.
    private static func buildConfig(
        dataDir: URL,
        passphrase: String,
        settings: NetworkSettings,
        kdf: KdfChoice
    ) -> Config {
        var config = defaultConfig(dataDir: dataDir.path, passphrase: passphrase)
        config.kdf = kdf
        // An emptied-out listen list falls back to the baseline rather
        // than silently starting a node nothing can dial.
        if !settings.listen.isEmpty { config.listen = settings.listen }
        config.bootstrap = settings.bootstrap
        config.relay = settings.relay
        config.mailboxes = settings.mailboxes
        config.serveMailbox = settings.serveMailbox
        config.mdns = settings.mdns
        config.spool = settings.spool
        config.meshtasticSerial = settings.meshtasticSerial
        config.meshtasticTcp = settings.meshtasticTcp
        config.bridge = settings.bridge
        return config
    }
}
