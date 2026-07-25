// Hex helpers shared by every pairing surface. Encoding is lowercase (the
// same convention as `kult`, the desktop app, and the Android shell);
// decoding is case-insensitive and whitespace-tolerant, because QR scanners
// and terminals both like to wrap or upcase long strings.

import Foundation

private let hexDigits: [Character] = Array("0123456789abcdef")
private let base45Alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".utf8)
let bundleQrPrefix = "KOMMS:B1:"
private let bundleQrFramePrefix = "KOMMS:B2:"
private let bundleQrChunkBytes = 420
private let maxBundleQrParts = 64
private let maxBundleQrCharacters = 16_384

/// Lowercase hex encoding.
public func hexEncode(_ bytes: Data) -> String {
    var out = String()
    out.reserveCapacity(bytes.count * 2)
    for b in bytes {
        out.append(hexDigits[Int(b >> 4)])
        out.append(hexDigits[Int(b & 0xf)])
    }
    return out
}

/// Hex decoding: case-insensitive, whitespace-tolerant. `nil` on odd
/// length or non-hex input — callers surface that honestly instead of
/// guessing.
public func hexDecode(_ s: String) -> Data? {
    var digits: [UInt8] = []
    digits.reserveCapacity(s.count)
    for c in s {
        if c.isWhitespace { continue }
        guard let d = c.hexDigitValue else { return nil }
        digits.append(UInt8(d))
    }
    guard digits.count % 2 == 0 else { return nil }
    var out = Data(capacity: digits.count / 2)
    for i in stride(from: 0, to: digits.count, by: 2) {
        out.append((digits[i] << 4) | digits[i + 1])
    }
    return out
}

/// RFC 9285 Base45, whose alphabet stays in QR alphanumeric mode.
func base45Encode(_ data: Data) -> String {
    let bytes = Array(data)
    var output: [UInt8] = []
    output.reserveCapacity((bytes.count * 3 + 1) / 2)
    var index = 0
    while index + 1 < bytes.count {
        var value = Int(bytes[index]) * 256 + Int(bytes[index + 1])
        output.append(base45Alphabet[value % 45])
        value /= 45
        output.append(base45Alphabet[value % 45])
        output.append(base45Alphabet[value / 45])
        index += 2
    }
    if index < bytes.count {
        let value = Int(bytes[index])
        output.append(base45Alphabet[value % 45])
        output.append(base45Alphabet[value / 45])
    }
    return String(decoding: output, as: UTF8.self)
}

/// Strict RFC 9285 decoding. Invalid groups and oversized QR input fail closed.
func base45Decode(_ text: String) -> Data? {
    let encoded = Array(text.utf8)
    guard encoded.count <= maxBundleQrCharacters, encoded.count % 3 != 1 else {
        return nil
    }
    func value(_ byte: UInt8) -> Int? {
        base45Alphabet.firstIndex(of: byte)
    }
    var output = Data(capacity: encoded.count * 2 / 3)
    var index = 0
    while index < encoded.count {
        let remaining = encoded.count - index
        guard let first = value(encoded[index]),
              remaining >= 2,
              let second = value(encoded[index + 1]) else {
            return nil
        }
        if remaining == 2 {
            let decoded = first + second * 45
            guard decoded <= 255 else { return nil }
            output.append(UInt8(decoded))
            index += 2
        } else {
            guard let third = value(encoded[index + 2]) else { return nil }
            let decoded = first + second * 45 + third * 45 * 45
            guard decoded <= 65_535 else { return nil }
            output.append(UInt8(decoded / 256))
            output.append(UInt8(decoded % 256))
            index += 3
        }
    }
    return output
}

/// Accept the versioned compact QR payload and legacy/pasteable bundle hex.
func decodeBundleInput(_ text: String) -> Data? {
    if text.hasPrefix(bundleQrPrefix) {
        return base45Decode(String(text.dropFirst(bundleQrPrefix.count)))
    }
    return hexDecode(text)
}

/// Split one post-quantum bundle into camera-friendly QR frames.
func encodeBundleQrFrames(_ bundle: Data) -> [String] {
    guard !bundle.isEmpty else { return [] }
    let total = (bundle.count + bundleQrChunkBytes - 1) / bundleQrChunkBytes
    guard total <= maxBundleQrParts else { return [] }
    let identifier = hexEncode(bundle.prefix(8)).uppercased()
    return (0..<total).map { index in
        let start = index * bundleQrChunkBytes
        let end = min(start + bundleQrChunkBytes, bundle.count)
        let chunk = bundle.subdata(in: start..<end)
        return "\(bundleQrFramePrefix)\(identifier):\(index + 1):\(total):\(bundle.count):\(base45Encode(chunk))"
    }
}

private struct BundleQrFrame {
    let identifier: String
    let index: Int
    let total: Int
    let length: Int
    let bytes: Data
}

private func decodeBundleQrFrame(_ text: String) -> BundleQrFrame? {
    guard text.hasPrefix(bundleQrFramePrefix) else { return nil }
    let body = text.dropFirst(bundleQrFramePrefix.count)
    let fields = body.split(separator: ":", maxSplits: 4, omittingEmptySubsequences: false)
    guard
        fields.count == 5,
        !fields[0].isEmpty,
        fields[0].count <= 16,
        fields[0].utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) }),
        let index = Int(fields[1]),
        let total = Int(fields[2]),
        let length = Int(fields[3]),
        (1...maxBundleQrParts).contains(total),
        (1...total).contains(index),
        (1...maxBundleQrCharacters).contains(length),
        let bytes = base45Decode(String(fields[4])),
        !bytes.isEmpty,
        bytes.count <= bundleQrChunkBytes
    else {
        return nil
    }
    return BundleQrFrame(
        identifier: String(fields[0]),
        index: index,
        total: total,
        length: length,
        bytes: bytes
    )
}

/// One scanner update while collecting an order-independent B2 bundle.
public struct BundleQrScanProgress {
    public let received: Int
    public let total: Int
    public let completeText: String?
}

/// Collect B2 frames while retaining B1 and legacy single-code compatibility.
public final class BundleQrAssembler {
    private var identifier: String?
    private var total = 0
    private var length = 0
    private var parts: [Int: Data] = [:]

    public init() {}

    public func accept(_ text: String) -> BundleQrScanProgress? {
        guard text.hasPrefix(bundleQrFramePrefix) else {
            return BundleQrScanProgress(received: 1, total: 1, completeText: text)
        }
        guard let frame = decodeBundleQrFrame(text) else { return nil }
        if
            identifier != frame.identifier ||
            total != frame.total ||
            length != frame.length
        {
            identifier = frame.identifier
            total = frame.total
            length = frame.length
            parts.removeAll(keepingCapacity: true)
        }
        if let previous = parts[frame.index], previous != frame.bytes { return nil }
        parts[frame.index] = frame.bytes
        guard parts.count == total else {
            return BundleQrScanProgress(received: parts.count, total: total, completeText: nil)
        }

        var bundle = Data(capacity: length)
        for index in 1...total {
            guard let part = parts[index], bundle.count + part.count <= length else { return nil }
            bundle.append(part)
        }
        guard bundle.count == length else { return nil }
        let actualIdentifier = hexEncode(bundle.prefix(8)).uppercased()
        guard actualIdentifier == identifier else { return nil }
        return BundleQrScanProgress(
            received: total,
            total: total,
            completeText: bundleQrPrefix + base45Encode(bundle)
        )
    }
}
