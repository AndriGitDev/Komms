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

final class SessionE2eTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("komms-e2e-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
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
        let msgId = try alice.send(peer: bobPeer, body: "hello from the phone")
        let got = try bEv.wait("bob's message event") { event -> (peer: String, body: String)? in
            if case let .messageReceived(peer, _, _, body, _) = event { return (peer, body) }
            return nil
        }
        XCTAssertEqual(alicePeer, got.peer)
        XCTAssertEqual("hello from the phone", got.body)
        _ = try aEv.wait("alice's delivered event") { event -> Void? in
            if case let .deliveryUpdated(id, state) = event, id == msgId, state == .delivered {
                return ()
            }
            return nil
        }

        // History rows carry what the bubbles render.
        let history = try alice.messages(peer: bobPeer)
        XCTAssertEqual(1, history.count)
        XCTAssertEqual(.outbound, history[0].direction)
        XCTAssertEqual(.delivered, history[0].state)
        let inbox = try bob.messages(peer: alicePeer)
        XCTAssertEqual(1, inbox.count)
        XCTAssertEqual(.inbound, inbox[0].direction)
        XCTAssertEqual(.received, inbox[0].state)

        // The document picker grants a security-scoped URL; the app stages a
        // bounded app-private copy before Session imports it. The render-safe
        // transfer surface exposes exact authenticated metadata and progress.
        let attachmentBytes = Data("iOS attachment bytes\u{0}exact".utf8)
        let source = dir.appendingPathComponent("ios-source.bin")
        try attachmentBytes.write(to: source)
        let contentId = try alice.sendAttachment(
            peer: bobPeer,
            path: source,
            mediaType: "application/octet-stream",
            filename: "field-notes.bin")
        let outbound = try XCTUnwrap(
            alice.attachments().first(where: { $0.contentId == contentId }))
        XCTAssertEqual(.pairwise, outbound.conversation)
        XCTAssertEqual(.outbound, outbound.direction)
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

        // iOS exports to a unique protected source URL before presenting the
        // system destination picker. The node refuses an existing path.
        let exported = dir.appendingPathComponent("ios-export.bin")
        try bob.exportAttachment(transfer: offer.transferId, to: exported)
        XCTAssertEqual(attachmentBytes, try Data(contentsOf: exported))
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
            if case let .messageReceived(peer, _, _, body, _) = event,
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
        let groupBytes = Data("one encrypted iOS group object".utf8)
        let groupSource = dir.appendingPathComponent("ios-group-source.bin")
        try groupBytes.write(to: groupSource)
        let groupContent = try alice.sendGroupAttachment(
            group: group,
            path: groupSource,
            mediaType: "application/octet-stream",
            filename: "route.bin")
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
        XCTAssertEqual(groupBytes, try Data(contentsOf: groupExport))

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
            if case let .groupMessageReceived(receivedGroup, _, _, _, body, _) = event,
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
        try bob.leaveGroup(group: group)
        XCTAssertTrue(try bob.groups().isEmpty)
        let deadline = Date().addingTimeInterval(30)
        while try alice.groups()[0].members.count != 1 {
            guard Date() < deadline else { throw Timeout(what: "creator applying Bob's leave") }
            Thread.sleep(forTimeInterval: 0.05)
        }
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
            if case let .messageReceived(_, _, _, body, _) = event { return body }
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
}
