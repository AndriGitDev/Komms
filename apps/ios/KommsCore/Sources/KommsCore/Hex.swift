// Hex helpers shared by every pairing surface. Encoding is lowercase (the
// same convention as `kult`, the desktop app, and the Android shell);
// decoding is case-insensitive and whitespace-tolerant, because QR scanners
// and terminals both like to wrap or upcase long strings.

import Foundation

private let hexDigits: [Character] = Array("0123456789abcdef")

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
