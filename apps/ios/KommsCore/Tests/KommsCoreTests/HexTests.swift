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

    func testBase45MatchesRfc9285VectorsAndRejectsMalformedGroups() {
        XCTAssertEqual("BB8", base45Encode(Data("AB".utf8)))
        XCTAssertEqual("%69 VD92EX0", base45Encode(Data("Hello!!".utf8)))
        XCTAssertEqual("UJCLQE7W581", base45Encode(Data("base-45".utf8)))
        XCTAssertEqual(Data("ietf!".utf8), base45Decode("QED8WEX0"))
        XCTAssertNil(base45Decode("A"))
        XCTAssertNil(base45Decode(":::"))
    }

    func testPairingQrIsCompactAndLegacyHexRemainsAccepted() {
        let bytes = Data((0..<1_500).map { UInt8(truncatingIfNeeded: $0 * 31) })
        let hex = hexEncode(bytes)
        let qr = bundleQrText(hex)
        XCTAssertTrue(qr.hasPrefix(bundleQrPrefix))
        XCTAssertLessThan(qr.count, hex.count)
        XCTAssertEqual(bytes, decodeBundleInput(qr))
        XCTAssertEqual(bytes, decodeBundleInput(hex.uppercased()))
    }

    func testAnimatedPairingFramesAreBoundedAndAssembleOutOfOrder() {
        let bytes = Data((0..<1_584).map { UInt8(truncatingIfNeeded: $0 * 31) })
        let frames = bundleQrFrames(hexEncode(bytes))
        XCTAssertEqual(4, frames.count)
        XCTAssertTrue(frames.allSatisfy { $0.hasPrefix("KOMMS:B2:001F3E5D7C9BBAD9:") })
        XCTAssertTrue(frames.allSatisfy { $0.count < 700 })

        let assembler = BundleQrAssembler()
        var complete: String?
        for index in [2, 0, 3, 1] {
            complete = assembler.accept(frames[index])?.completeText ?? complete
        }
        XCTAssertEqual(bytes, decodeBundleInput(complete!))
    }
}
