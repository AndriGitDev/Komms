use kult_node::{
    incognito_keyboard_policy, IncognitoKeyboardLevel, IncognitoKeyboardPlatform,
    INCOGNITO_KEYBOARD_PROTECTED_FIELDS,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b15-incognito-keyboard-parity.json"
    ))
    .expect("valid shared B15 fixture")
}

fn level(value: IncognitoKeyboardLevel) -> &'static str {
    value.as_str()
}

#[test]
fn shared_policy_matches_every_platform_and_has_no_storage_or_delivery_surface() {
    let fixture = fixture();
    assert_eq!(
        fixture["protected_fields"],
        serde_json::json!(INCOGNITO_KEYBOARD_PROTECTED_FIELDS)
    );

    for platform in [
        IncognitoKeyboardPlatform::Android,
        IncognitoKeyboardPlatform::Ios,
        IncognitoKeyboardPlatform::Desktop,
    ] {
        let policy = incognito_keyboard_policy(platform);
        let expected = &fixture["platforms"][platform.as_str()];
        assert!(policy.always_on);
        assert!(policy.applies_before_unlock);
        assert_eq!(
            level(policy.personalized_learning),
            expected["personalized_learning"]
        );
        assert_eq!(level(policy.suggestions), expected["suggestions"]);
        assert_eq!(level(policy.spellcheck), expected["spellcheck"]);
        assert_eq!(
            level(policy.secret_text_masking),
            expected["secret_text_masking"]
        );
        assert_eq!(policy.protected_fields, INCOGNITO_KEYBOARD_PROTECTED_FIELDS);
        assert!(!policy.mechanism.is_empty());
        assert!(!policy.limitations.is_empty());
    }

    assert_eq!(fixture["stored_preference"], false);
    assert_eq!(fixture["network_behavior"]["envelope"], false);
    assert_eq!(fixture["network_behavior"]["capability"], false);
    assert_eq!(fixture["network_behavior"]["notification"], false);
    assert_eq!(fixture["network_behavior"]["transport_work"], false);
}
