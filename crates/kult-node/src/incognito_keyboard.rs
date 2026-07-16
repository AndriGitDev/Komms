//! Canonical B15 input-privacy promises shared by every front door.
//!
//! Incognito keyboard behavior is deliberately an always-on shell policy, not
//! sealed user metadata. It must protect the unlock and restore fields before
//! a node or store exists. Native shells apply the controls; this module keeps
//! their user-visible claims exact, bounded, and testable.

/// Shipped platform whose input-privacy policy is being described.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncognitoKeyboardPlatform {
    /// Android application input controls.
    Android,
    /// iOS application input controls.
    Ios,
    /// Tauri desktop webview input controls.
    Desktop,
}

impl IncognitoKeyboardPlatform {
    /// Canonical lower-case wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Desktop => "desktop",
        }
    }
}

/// Strength of one native input-privacy capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncognitoKeyboardLevel {
    /// The platform itself enforces the narrowly named behavior.
    PlatformEnforced,
    /// Komms sets a documented platform control that an input method may ignore.
    PlatformRequested,
    /// Komms supplies the strongest available hint, without an enforcement API.
    BestEffort,
    /// The platform exposes no honest per-field control for this behavior.
    Unavailable,
}

impl IncognitoKeyboardLevel {
    /// Canonical snake-case wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformEnforced => "platform_enforced",
            Self::PlatformRequested => "platform_requested",
            Self::BestEffort => "best_effort",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Field classes that every shell must cover now and when adding new inputs.
pub const INCOGNITO_KEYBOARD_PROTECTED_FIELDS: [&str; 5] =
    ["message", "search", "passphrase", "mnemonic", "name"];

/// Render-safe, secret-free B15 policy for one shipped platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncognitoKeyboardPolicy {
    /// Platform this policy describes.
    pub platform: IncognitoKeyboardPlatform,
    /// Always true: input privacy cannot be disabled.
    pub always_on: bool,
    /// Always true: passphrase and restore inputs are covered before unlock.
    pub applies_before_unlock: bool,
    /// Per-field control over personalized keyboard learning.
    pub personalized_learning: IncognitoKeyboardLevel,
    /// Per-field autocorrection and prediction control.
    pub suggestions: IncognitoKeyboardLevel,
    /// Per-field spelling-service control.
    pub spellcheck: IncognitoKeyboardLevel,
    /// Visual masking strength for passphrases and recovery mnemonics.
    pub secret_text_masking: IncognitoKeyboardLevel,
    /// Required semantic field classes, including future search inputs.
    pub protected_fields: &'static [&'static str],
    /// Short user-visible native mechanism description.
    pub mechanism: &'static str,
    /// Honest limits that must accompany the capability claims.
    pub limitations: &'static [&'static str],
}

/// Return the immutable B15 policy for a shipped platform.
pub const fn incognito_keyboard_policy(
    platform: IncognitoKeyboardPlatform,
) -> IncognitoKeyboardPolicy {
    match platform {
        IncognitoKeyboardPlatform::Android => IncognitoKeyboardPolicy {
            platform,
            always_on: true,
            applies_before_unlock: true,
            personalized_learning: IncognitoKeyboardLevel::PlatformRequested,
            suggestions: IncognitoKeyboardLevel::PlatformRequested,
            spellcheck: IncognitoKeyboardLevel::PlatformRequested,
            secret_text_masking: IncognitoKeyboardLevel::PlatformEnforced,
            protected_fields: &INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
            mechanism: "Every Komms text editor requests Android no-personalized-learning and no-suggestions behavior; passphrases and recovery mnemonics are masked.",
            limitations: &[
                "Android documents IME_FLAG_NO_PERSONALIZED_LEARNING as a request, not a guarantee; an input method may ignore it.",
                "A compromised device, accessibility or overlay abuse, a malicious input method, and external observation remain outside this guarantee.",
            ],
        },
        IncognitoKeyboardPlatform::Ios => IncognitoKeyboardPolicy {
            platform,
            always_on: true,
            applies_before_unlock: true,
            personalized_learning: IncognitoKeyboardLevel::Unavailable,
            suggestions: IncognitoKeyboardLevel::BestEffort,
            spellcheck: IncognitoKeyboardLevel::BestEffort,
            secret_text_masking: IncognitoKeyboardLevel::PlatformEnforced,
            protected_fields: &INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
            mechanism: "Every Komms text editor disables autocorrection; passphrases and recovery mnemonics use SecureField.",
            limitations: &[
                "iOS exposes no public per-field switch that guarantees personalized keyboard learning is disabled.",
                "Non-secure fields still depend on system and third-party keyboards respecting text-input traits; secure fields use the system keyboard.",
            ],
        },
        IncognitoKeyboardPlatform::Desktop => IncognitoKeyboardPolicy {
            platform,
            always_on: true,
            applies_before_unlock: true,
            personalized_learning: IncognitoKeyboardLevel::Unavailable,
            suggestions: IncognitoKeyboardLevel::BestEffort,
            spellcheck: IncognitoKeyboardLevel::BestEffort,
            secret_text_masking: IncognitoKeyboardLevel::BestEffort,
            protected_fields: &INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
            mechanism: "Every Komms textual webview input disables autocomplete, autocorrect, autocapitalization, and spellcheck; secrets use password inputs.",
            limitations: &[
                "Desktop HTML input attributes are hints that the webview, operating system, input method, or writing tools may ignore.",
                "Privileged software, a compromised host, physical keyboards with their own storage, and external observation remain outside this guarantee.",
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_cover_required_fields_without_overclaiming_learning_control() {
        let android = incognito_keyboard_policy(IncognitoKeyboardPlatform::Android);
        let ios = incognito_keyboard_policy(IncognitoKeyboardPlatform::Ios);
        let desktop = incognito_keyboard_policy(IncognitoKeyboardPlatform::Desktop);

        assert!(android.always_on && ios.always_on && desktop.always_on);
        assert!(android.applies_before_unlock && ios.applies_before_unlock);
        assert_eq!(
            android.personalized_learning,
            IncognitoKeyboardLevel::PlatformRequested
        );
        assert_eq!(
            ios.personalized_learning,
            IncognitoKeyboardLevel::Unavailable
        );
        assert_eq!(
            desktop.personalized_learning,
            IncognitoKeyboardLevel::Unavailable
        );
        assert_eq!(
            android.protected_fields,
            INCOGNITO_KEYBOARD_PROTECTED_FIELDS
        );
        assert!(android
            .limitations
            .iter()
            .any(|text| text.contains("request")));
        assert!(ios
            .limitations
            .iter()
            .any(|text| text.contains("third-party")));
        assert!(desktop
            .limitations
            .iter()
            .any(|text| text.contains("webview")));
    }
}
