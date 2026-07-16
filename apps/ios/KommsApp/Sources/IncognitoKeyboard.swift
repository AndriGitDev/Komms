import SwiftUI

/// B15 per-field input traits. These are always on, including before unlock.
/// iOS does not expose a public per-field guarantee against personalized
/// learning, so the UI and shared policy deliberately describe this as
/// best-effort for non-secure fields.
private struct IncognitoKeyboardModifier: ViewModifier {
    let capitalization: TextInputAutocapitalization

    func body(content: Content) -> some View {
        content
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(capitalization)
    }
}

extension View {
    func incognitoKeyboard(
        capitalization: TextInputAutocapitalization = .never
    ) -> some View {
        modifier(IncognitoKeyboardModifier(capitalization: capitalization))
    }
}
