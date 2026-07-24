import SwiftUI

/// Shared Komms brand roles. The light palette follows the warm editorial
/// komms.org landing page; dark mode follows its technical explainer.
enum ThemePalette {
    static let background = adaptive(light: 0xFAFAFA, dark: 0x0F2633)
    static let surface = adaptive(light: 0xFFFFFF, dark: 0x153746)
    static let surfaceRaised = adaptive(light: 0xFFF8DC, dark: 0x193F4F)
    static let border = adaptive(light: 0xE4E1D8, dark: 0x345563)
    static let textPrimary = adaptive(light: 0x1A1A1A, dark: 0xFAFAFA)
    static let textSecondary = adaptive(light: 0x6B6B6B, dark: 0xDCE6E8)
    static let accent = adaptive(light: 0xB83431, dark: 0xF2B705)
    static let onAccent = adaptive(light: 0xFFFFFF, dark: 0x1A1A1A)
    static let brand = Color(
        red: Double(0xF2) / 255, green: Double(0xB7) / 255, blue: Double(0x05) / 255)
    static let deep = Color(
        red: Double(0x0F) / 255, green: Double(0x26) / 255, blue: Double(0x33) / 255)
    static let danger = adaptive(light: 0xB83431, dark: 0xFF8B82)
    static let warning = adaptive(light: 0x805900, dark: 0xF2B705)
    static let success = adaptive(light: 0x28734B, dark: 0x84D6A5)

    private static func adaptive(light: Int, dark: Int) -> Color {
        Color(uiColor: UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

private extension UIColor {
    convenience init(rgb: Int) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8) & 0xFF) / 255,
            blue: CGFloat(rgb & 0xFF) / 255,
            alpha: 1)
    }
}

struct KommsBrandLockup: View {
    var compact = false

    var body: some View {
        HStack(spacing: compact ? 10 : 14) {
            KommsMark()
                .frame(width: compact ? 38 : 64, height: compact ? 38 : 64)
                .accessibilityHidden(true)
            Text("Komms")
                .font(compact ? .title2.weight(.bold) : .largeTitle.weight(.bold))
                .foregroundStyle(ThemePalette.textPrimary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Komms")
    }
}

/// Vector reconstruction of the geometric K from KommsOrg's product icon.
struct KommsMark: View {
    var body: some View {
        GeometryReader { proxy in
            let scale = min(proxy.size.width, proxy.size.height) / 192
            ZStack {
                RoundedRectangle(cornerRadius: 31 * scale, style: .continuous)
                    .fill(ThemePalette.brand)
                Path { path in
                    path.move(to: point(24, 25, scale))
                    path.addLine(to: point(67, 25, scale))
                    path.addLine(to: point(67, 80, scale))
                    path.addLine(to: point(116, 25, scale))
                    path.addLine(to: point(169, 25, scale))
                    path.addLine(to: point(108, 91, scale))
                    path.addLine(to: point(24, 91, scale))
                    path.closeSubpath()

                    path.move(to: point(24, 99, scale))
                    path.addLine(to: point(108, 99, scale))
                    path.addLine(to: point(169, 167, scale))
                    path.addLine(to: point(116, 167, scale))
                    path.addLine(to: point(79, 117, scale))
                    path.addLine(to: point(67, 130, scale))
                    path.addLine(to: point(67, 167, scale))
                    path.addLine(to: point(24, 167, scale))
                    path.closeSubpath()
                }
                .fill(ThemePalette.deep)
            }
        }
        .aspectRatio(1, contentMode: .fit)
    }

    private func point(_ x: CGFloat, _ y: CGFloat, _ scale: CGFloat) -> CGPoint {
        CGPoint(x: x * scale, y: y * scale)
    }
}
