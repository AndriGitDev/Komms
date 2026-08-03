//! Fuzz every ADR-0019 fixed-shape body and authenticated capability control.
#![no_main]

use kult_protocol::{
    verify_wake_generic_response, wake_generic_response, WakeCapability, WakeCapabilityControl,
    WakeCapabilityDescriptor, WakeCapabilityPayload, WakeEnvironment, WakePlatform, WakeProfile,
    WakeRegisterRequest, WakeRegisterResponse, WakeTriggerRequest, WAKE_CAPABILITY_PLAINTEXT_LEN,
};
use libfuzzer_sys::fuzz_target;

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(index as u8)
}

fn word(data: &[u8], offset: usize) -> u64 {
    (0..8).fold(0u64, |value, index| {
        (value << 8) | u64::from(byte(data, offset + index))
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(payload) = WakeCapabilityPayload::decode(data) {
        let encoded = payload.encode().unwrap();
        assert_eq!(WakeCapabilityPayload::decode(&encoded).unwrap(), payload);
    }
    if let Ok(capability) = WakeCapability::from_bytes(data) {
        assert_eq!(
            WakeCapability::from_bytes(capability.as_bytes()).unwrap(),
            capability
        );
    }
    if let Ok(register) = WakeRegisterRequest::decode(data) {
        let encoded = register.encode().unwrap();
        assert_eq!(WakeRegisterRequest::decode(&encoded).unwrap(), register);
    }
    if let Ok(response) = WakeRegisterResponse::decode(data) {
        let encoded = response.encode().unwrap();
        assert_eq!(WakeRegisterResponse::decode(&encoded).unwrap(), response);
    }
    if let Ok(trigger) = WakeTriggerRequest::decode(data) {
        let encoded = trigger.encode().unwrap();
        assert_eq!(WakeTriggerRequest::decode(&encoded).unwrap(), trigger);
    }
    if let Ok(control) = WakeCapabilityControl::decode(data) {
        let encoded = control.encode().unwrap();
        assert_eq!(WakeCapabilityControl::decode(&encoded).unwrap(), control);
    }
    let _ = verify_wake_generic_response(data);

    // Exercise canonical paths during short smoke runs as well as malformed
    // inputs, so fixed widths and namespace bytes are not coverage barriers.
    let expires_at = word(data, 0).max(1);
    let token = (0..32).map(|index| byte(data, index)).collect::<Vec<_>>();
    let payload = WakeCapabilityPayload {
        platform: if byte(data, 32) & 1 == 0 {
            WakePlatform::Apns
        } else {
            WakePlatform::Fcm
        },
        environment: if byte(data, 33) & 1 == 0 {
            WakeEnvironment::Development
        } else {
            WakeEnvironment::Production
        },
        profile: if byte(data, 34) & 1 == 0 {
            WakeProfile::BackgroundOnly
        } else {
            WakeProfile::GenericVisible
        },
        expires_at,
        capability_id: [byte(data, 35).max(1); 16],
        provider_token: token.clone(),
        app_topic: format!("is.komms.fuzz{}", byte(data, 36)).into_bytes(),
    };
    let encoded_payload = payload.encode().unwrap();
    assert_eq!(
        WakeCapabilityPayload::decode(&encoded_payload).unwrap(),
        payload
    );

    let register = WakeRegisterRequest {
        platform: payload.platform,
        environment: payload.environment,
        profile: payload.profile,
        provider_token: token,
        app_topic: payload.app_topic.clone(),
        request_nonce: [byte(data, 37).max(1); 16],
    };
    let encoded_register = register.encode().unwrap();
    assert_eq!(
        WakeRegisterRequest::decode(&encoded_register).unwrap(),
        register
    );

    let capability = WakeCapability::from_parts(
        u32::from(byte(data, 38)).max(1),
        [byte(data, 39).max(1); 24],
        &[byte(data, 40).max(1); WAKE_CAPABILITY_PLAINTEXT_LEN + 16],
    )
    .unwrap();
    let response = WakeRegisterResponse::issued(expires_at, capability.clone()).unwrap();
    let encoded_response = response.encode().unwrap();
    assert_eq!(
        WakeRegisterResponse::decode(&encoded_response).unwrap(),
        response
    );

    let trigger = WakeTriggerRequest {
        capability: capability.clone(),
        request_nonce: [byte(data, 41).max(1); 16],
    };
    let encoded_trigger = trigger.encode().unwrap();
    assert_eq!(
        WakeTriggerRequest::decode(&encoded_trigger).unwrap(),
        trigger
    );
    verify_wake_generic_response(&wake_generic_response()).unwrap();

    let control = WakeCapabilityControl {
        sender_account: [byte(data, 42).max(1); 32],
        sender_device: [byte(data, 43).max(1); 32],
        recipient_account: [byte(data, 44).max(1); 32],
        recipient_device: [byte(data, 45).max(1); 32],
        authority_generation: word(data, 46).max(1),
        generation: word(data, 54).max(1),
        capabilities: vec![WakeCapabilityDescriptor {
            origin: format!("https://wake-{}.example", byte(data, 62)),
            static_key: [byte(data, 63).max(1); 32],
            expires_at,
            capability,
        }],
    };
    let encoded_control = control.encode().unwrap();
    assert_eq!(
        WakeCapabilityControl::decode(&encoded_control).unwrap(),
        control
    );
});
