import Foundation
import XCTest

@testable import KommsCore

final class HintsTests: XCTestCase {
    func testHintsConvertAndRejectGarbage() throws {
        XCTAssertEqual(
            try HintSpec("multiaddr", "/ip4/1.2.3.4/tcp/1").toFfi(),
            .multiaddr(addr: "/ip4/1.2.3.4/tcp/1"))
        XCTAssertEqual(try HintSpec("mesh", "broadcast").toFfi(), .mesh(node: UInt32.max))
        XCTAssertEqual(try HintSpec("mesh", "42").toFfi(), .mesh(node: 42))
        XCTAssertEqual(
            try HintSpec("relay", "/ip4/1.2.3.4/tcp/1/p2p/x").toFfi(),
            .relay(addr: "/ip4/1.2.3.4/tcp/1/p2p/x"))
        XCTAssertEqual(try HintSpec("spool", "/mnt/usb/spool").toFfi(), .spool(path: "/mnt/usb/spool"))

        XCTAssertThrowsError(try HintSpec("mesh", "not-a-number").toFfi()) { err in
            let msg = (err as? InputError)?.message ?? ""
            XCTAssertTrue(msg.contains("node number"), "got: \(msg)")
        }
        XCTAssertThrowsError(try HintSpec("teleport", "x").toFfi())
        XCTAssertThrowsError(try HintSpec("relay", "  ").toFfi())
    }
}
