//! Canonical B14 screen-security promises shared by every front door.
//!
//! Screen protection is deliberately an always-on shell policy, not sealed
//! user metadata: it must already apply to the unlock screen and while the
//! encrypted store is closed. Platform shells enforce these capabilities;
//! this module keeps their user-visible claims exact and testable.

/// Platform shell whose screen-security guarantees are being described.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenSecurityPlatform {
    /// Android application window.
    Android,
    /// iOS application scene.
    Ios,
    /// Tauri desktop application window.
    Desktop,
}

impl ScreenSecurityPlatform {
    /// Canonical lower-case wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Desktop => "desktop",
        }
    }
}

/// Strength of one native screen-security capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenSecurityLevel {
    /// The supported OS API is enabled for the whole Komms surface.
    PlatformEnforced,
    /// Komms requests protection, but the compositor or OS may ignore it.
    BestEffort,
    /// The platform exposes no honest way to provide this capability.
    Unavailable,
}

impl ScreenSecurityLevel {
    /// Canonical snake-case wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformEnforced => "platform_enforced",
            Self::BestEffort => "best_effort",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Render-safe, secret-free B14 policy for one shipped platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenSecurityPolicy {
    /// Platform this policy describes.
    pub platform: ScreenSecurityPlatform,
    /// Always true: protection cannot be disabled and applies before unlock.
    pub always_on: bool,
    /// Screenshot and screen-recording prevention strength.
    pub capture_prevention: ScreenSecurityLevel,
    /// App-switcher, task-preview, or recent-window obscuring strength.
    pub background_obscuring: ScreenSecurityLevel,
    /// Live screen-capture detection strength.
    pub capture_detection: ScreenSecurityLevel,
    /// Immediate user-triggered session lock strength.
    pub rapid_lock: ScreenSecurityLevel,
    /// Short user-visible native mechanism description.
    pub mechanism: &'static str,
    /// Honest limits that must accompany the capability claims.
    pub limitations: &'static [&'static str],
}

/// Return the immutable B14 policy for a shipped platform.
pub const fn screen_security_policy(platform: ScreenSecurityPlatform) -> ScreenSecurityPolicy {
    match platform {
        ScreenSecurityPlatform::Android => ScreenSecurityPolicy {
            platform,
            always_on: true,
            capture_prevention: ScreenSecurityLevel::PlatformEnforced,
            background_obscuring: ScreenSecurityLevel::PlatformEnforced,
            capture_detection: ScreenSecurityLevel::Unavailable,
            rapid_lock: ScreenSecurityLevel::Unavailable,
            mechanism: "Android FLAG_SECURE protects every Komms activity.",
            limitations: &[
                "A compromised device, accessibility or overlay abuse, and an external camera remain outside this guarantee.",
                "Android does not provide Komms a reliable callback for every blocked capture attempt.",
            ],
        },
        ScreenSecurityPlatform::Ios => ScreenSecurityPolicy {
            platform,
            always_on: true,
            capture_prevention: ScreenSecurityLevel::Unavailable,
            background_obscuring: ScreenSecurityLevel::PlatformEnforced,
            capture_detection: ScreenSecurityLevel::PlatformEnforced,
            rapid_lock: ScreenSecurityLevel::Unavailable,
            mechanism: "Komms covers inactive scenes and live captured screens with a privacy shield.",
            limitations: &[
                "iOS does not let Komms universally block still screenshots.",
                "Capture notification can arrive after recording or mirroring has begun.",
            ],
        },
        ScreenSecurityPlatform::Desktop => ScreenSecurityPolicy {
            platform,
            always_on: true,
            capture_prevention: ScreenSecurityLevel::BestEffort,
            background_obscuring: ScreenSecurityLevel::BestEffort,
            capture_detection: ScreenSecurityLevel::Unavailable,
            rapid_lock: ScreenSecurityLevel::PlatformEnforced,
            mechanism: "Komms requests native content protection and locks immediately with Ctrl/Cmd+Shift+L.",
            limitations: &[
                "Desktop capture and task-preview protection depends on the operating system, window server, and compositor.",
                "Other software with sufficient privilege and an external camera remain outside this guarantee.",
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_are_always_on_and_make_platform_limits_explicit() {
        let android = screen_security_policy(ScreenSecurityPlatform::Android);
        let ios = screen_security_policy(ScreenSecurityPlatform::Ios);
        let desktop = screen_security_policy(ScreenSecurityPlatform::Desktop);

        assert!(android.always_on && ios.always_on && desktop.always_on);
        assert_eq!(
            android.capture_prevention,
            ScreenSecurityLevel::PlatformEnforced
        );
        assert_eq!(ios.capture_prevention, ScreenSecurityLevel::Unavailable);
        assert!(ios
            .limitations
            .iter()
            .any(|text| text.contains("screenshots")));
        assert_eq!(desktop.capture_prevention, ScreenSecurityLevel::BestEffort);
        assert_eq!(desktop.rapid_lock, ScreenSecurityLevel::PlatformEnforced);
        assert!(desktop
            .limitations
            .iter()
            .any(|text| text.contains("compositor")));
    }
}
