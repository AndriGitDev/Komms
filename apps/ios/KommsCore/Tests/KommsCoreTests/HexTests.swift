import Foundation
import XCTest

@testable import KommsCore

final class HexTests: XCTestCase {
    func testRoundTripsAndToleratesNoise() {
        let bytes = Data([0x00, 0x7f, 0xab, 0xff])
        let hex = hexEncode(bytes)
        XCTAssertEqual("007fabff", hex)
        XCTAssertEqual(bytes, hexDecode(hex))
        // Scanned input arrives uppercase/wrapped — decoding must not care.
        XCTAssertEqual(bytes, hexDecode("00 7F\nAB\tff"))
        XCTAssertNil(hexDecode("007"))
        XCTAssertNil(hexDecode("zz"))
    }

    func testQrPayloadsAreUppercaseAlphanumericModeHex() {
        XCTAssertEqual("00ABFF", bundleQrText("00abff"))
    }
}
