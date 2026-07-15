import Foundation
import Security

/// Device-only Keychain state for selected private label ids and any/all mode.
/// It never enters scene restoration, previews, UserDefaults, iCloud, or logs.
enum LabelFilterStore {
    struct State: Codable {
        var ids: [String]
        var mode: String
    }

    private static let service = "is.andri.komms.private-label-filter"
    private static let account = "selected-labels-v1"

    static func load() -> State {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let decoded = try? JSONDecoder().decode(State.self, from: data)
        else { return State(ids: [], mode: "any") }
        let ids = Array(decoded.ids.filter { $0.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil }.prefix(128))
        return State(ids: Array(NSOrderedSet(array: ids)) as? [String] ?? ids,
                     mode: decoded.mode == "all" ? "all" : "any")
    }

    static func save(_ state: State) {
        let safe = State(
            ids: Array(state.ids.filter { $0.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil }.prefix(128)),
            mode: state.mode == "all" ? "all" : "any")
        guard let data = try? JSONEncoder().encode(safe) else { return }
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insertion = baseQuery
            attributes.forEach { insertion[$0.key] = $0.value }
            SecItemAdd(insertion as CFDictionary, nil)
        }
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
    }
}
