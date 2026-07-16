use kult_node::{screen_security_policy, ScreenSecurityLevel, ScreenSecurityPlatform};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b14-screen-security-parity.json"
    ))
    .expect("valid shared B14 fixture")
}

fn level(value: ScreenSecurityLevel) -> &'static str {
    value.as_str()
}

#[test]
fn shared_policy_matches_every_shipped_platform_and_has_no_delivery_surface() {
    let fixture = fixture();
    for platform in [
        ScreenSecurityPlatform::Android,
        ScreenSecurityPlatform::Ios,
        ScreenSecurityPlatform::Desktop,
    ] {
        let policy = screen_security_policy(platform);
        let expected = &fixture["platforms"][platform.as_str()];
        assert!(policy.always_on);
        assert_eq!(
            level(policy.capture_prevention),
            expected["capture_prevention"]
        );
        assert_eq!(
            level(policy.background_obscuring),
            expected["background_obscuring"]
        );
        assert_eq!(
            level(policy.capture_detection),
            expected["capture_detection"]
        );
        assert_eq!(level(policy.rapid_lock), expected["rapid_lock"]);
        assert!(!policy.mechanism.is_empty());
        assert!(!policy.limitations.is_empty());
    }

    assert_eq!(fixture["stored_preference"], false);
    assert_eq!(fixture["network_behavior"]["envelope"], false);
    assert_eq!(fixture["network_behavior"]["capability"], false);
    assert_eq!(fixture["network_behavior"]["notification"], false);
    assert_eq!(fixture["network_behavior"]["transport_work"], false);
    assert_eq!(fixture["ios_universal_screenshot_blocking"], false);
}
