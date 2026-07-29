//! Fuzz: recipient-scoped group-origin wrappers are strict and panic-free.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = kult_crypto::GroupOriginEnvelope::decode(data) {
        let encoded = envelope.encode();
        assert_eq!(
            kult_crypto::GroupOriginEnvelope::decode(&encoded).unwrap(),
            envelope
        );
        let context = kult_crypto::GroupOriginContext {
            group_id: [1; 32],
            sender_account: [2; 32],
            sender_device: [3; 32],
            recipient_account: [4; 32],
            recipient_device: [5; 32],
            sender_chain_key_id: [6; 16],
            envelope_content_id: [7; 16],
            authenticated_retention: Some(8),
        };
        let _ = envelope.verify(&[9; 32], &context);
    }
});
