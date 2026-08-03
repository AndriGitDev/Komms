import Foundation
import KommsCore

enum L10n {
    private static let defaultLocale = "en-US"
    private static let supported = Set(["en-US", "is"])
    private static let firstStrongIsolate = "\u{2068}"
    private static let popDirectionalIsolate = "\u{2069}"
    private static let catalogs: [String: [String: Any]] = loadCatalogs()
    private static let sourceIds: [String: String] = {
        guard let messages = catalogs[defaultLocale] else { return [:] }
        var ids: [String: String] = [:]
        for (id, value) in messages {
            guard let source = value as? String, !source.contains("%") else { continue }
            ids[source] = ids[source] ?? id
        }
        return ids
    }()

    static var activeLocale: String {
        let override = UserDefaults.standard.string(forKey: "komms.locale")
        if let override, supported.contains(override) { return override }
        let preferred = Locale.preferredLanguages.first ?? defaultLocale
        return preferred.lowercased().hasPrefix("is") ? "is" : defaultLocale
    }

    static func text(_ id: String, _ arguments: Any...) -> String {
        guard let template = template(id: id, count: nil) else {
            return catalogs[defaultLocale]?[id] as? String ?? ""
        }
        return format(template, arguments: arguments)
    }

    static func plural(
        _ id: String,
        count: Int,
        _ arguments: Any...
    ) -> String {
        guard let template = template(id: id, count: count) else { return "" }
        return format(template, arguments: arguments.isEmpty ? [count] : arguments)
    }

    /// Translate an exact canonical source value returned by shared core policy.
    static func source(_ source: String) -> String {
        guard let id = sourceIds[source] else { return source }
        return text(id)
    }

    static func error(_ error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .Startup: return text("error_startup")
            case .Stopped: return text("error_node_stopped")
            case .Folder: return text("error_folder")
            case .Label: return text("error_label")
            case .Pin: return text("error_pin")
            case .Node: return text("error_generic")
            }
        }
        if error is InputError { return text("error_input") }
        if error is SettingsError { return text("error_settings") }
        return text("error_generic")
    }

    private static func template(id: String, count: Int?) -> String? {
        let selected = catalogs[activeLocale]?[id] ?? catalogs[defaultLocale]?[id]
        if let text = selected as? String {
            return count == nil ? text : nil
        }
        guard
            let count,
            let plural = selected as? [String: String]
        else {
            return nil
        }
        let form: String
        if activeLocale == "is" {
            form = count % 10 == 1 && count % 100 != 11 ? "one" : "other"
        } else {
            form = count == 1 ? "one" : "other"
        }
        return plural[form] ?? plural["other"]
    }

    private static func format(_ template: String, arguments: [Any]) -> String {
        let pattern = #"%(?:([1-9][0-9]*)\$)?([sd%])"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else {
            return ""
        }
        let mutable = NSMutableString(string: template)
        let matches = expression.matches(
            in: template,
            range: NSRange(location: 0, length: mutable.length)
        )
        var implicitPosition = 0
        let source = template as NSString
        let replacements = matches.map { match -> (NSTextCheckingResult, String, Int?) in
            let kind = source.substring(with: match.range(at: 2))
            if kind == "%" {
                return (match, kind, nil)
            }
            let explicitRange = match.range(at: 1)
            let position: Int
            if explicitRange.location != NSNotFound {
                position = (Int(source.substring(with: explicitRange)) ?? 1) - 1
            } else {
                position = implicitPosition
                implicitPosition += 1
            }
            return (match, kind, position)
        }
        for (match, kind, position) in replacements.reversed() {
            if kind == "%" {
                mutable.replaceCharacters(in: match.range, with: "%")
                continue
            }
            guard let position else {
                mutable.replaceCharacters(in: match.range, with: "")
                continue
            }
            guard arguments.indices.contains(position) else {
                mutable.replaceCharacters(in: match.range, with: "")
                continue
            }
            let replacement: String
            if kind == "d", let integer = arguments[position] as? Int {
                replacement = integer.formatted(.number.locale(Locale(identifier: activeLocale)))
            } else if kind == "s" {
                replacement = firstStrongIsolate
                    + String(describing: arguments[position])
                    + popDirectionalIsolate
            } else {
                replacement = ""
            }
            mutable.replaceCharacters(in: match.range, with: replacement)
        }
        return mutable as String
    }

    private static func loadCatalogs() -> [String: [String: Any]] {
        var loaded: [String: [String: Any]] = [:]
        for locale in supported.sorted() {
            let url = Bundle.main.url(
                forResource: locale,
                withExtension: "json",
                subdirectory: "Localization"
            ) ?? Bundle.main.url(forResource: locale, withExtension: "json")
            guard
                let url,
                let data = try? Data(contentsOf: url),
                let document = try? JSONSerialization.jsonObject(with: data)
                    as? [String: Any],
                document["schema"] as? String == "komms-localization-catalog/v1",
                document["locale"] as? String == locale,
                document["direction"] as? String == "ltr",
                let messages = document["messages"] as? [String: Any]
            else {
                continue
            }
            loaded[locale] = messages
        }
        precondition(loaded[defaultLocale] != nil, "default localization catalog missing")
        return loaded
    }
}
