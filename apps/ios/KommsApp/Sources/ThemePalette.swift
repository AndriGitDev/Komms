import SwiftUI

/// B12 semantic roles. Platform colors remain adaptive so Increase Contrast,
/// Differentiate Without Color, and native light/dark resolution stay live.
enum ThemePalette {
    static let background = Color(uiColor: .systemBackground)
    static let surface = Color(uiColor: .secondarySystemBackground)
    static let surfaceRaised = Color(uiColor: .tertiarySystemBackground)
    static let border = Color(uiColor: .separator)
    static let textPrimary = Color(uiColor: .label)
    static let textSecondary = Color(uiColor: .secondaryLabel)
    static let accent = Color.accentColor
    static let danger = Color(uiColor: .systemRed)
    static let warning = Color(uiColor: .systemOrange)
    static let success = Color(uiColor: .systemGreen)
}
