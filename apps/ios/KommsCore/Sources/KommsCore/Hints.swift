// Delivery hints as the UI edits them: a `kind` tag plus one string value —
// the exact shape (and error wording) the desktop app's and Android shell's
// hint editors use.

import Foundation

/// Input this layer rejects before it reaches the node — the Swift
/// counterpart of the other shells' argument errors, message verbatim.
public struct InputError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// One editable delivery hint. `kind` is `multiaddr`, `relay`, `spool`, or `mesh`.
public struct HintSpec: Equatable {
    public var kind: String
    public var value: String

    public init(_ kind: String, _ value: String) {
        self.kind = kind
        self.value = value
    }

    /// Convert to the FFI hint.
    ///
    /// Throws ``InputError`` on an unknown kind, an empty value, or a mesh
    /// value that is neither a node number nor `broadcast`.
    public func toFfi() throws -> Hint {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty else { throw InputError("hint value must not be empty") }
        switch kind {
        case "multiaddr": return .multiaddr(addr: v)
        case "relay": return .relay(addr: v)
        case "spool": return .spool(path: v)
        case "mesh":
            if v.lowercased() == "broadcast" { return .mesh(node: UInt32.max) }
            guard let node = UInt32(v) else {
                throw InputError("mesh hint must be a node number or `broadcast`, got `\(v)`")
            }
            return .mesh(node: node)
        default: throw InputError("unknown hint kind `\(kind)`")
        }
    }
}

extension Array where Element == HintSpec {
    /// Convert a whole hint list, failing on the first bad entry.
    public func toFfi() throws -> [Hint] { try map { try $0.toFfi() } }
}
