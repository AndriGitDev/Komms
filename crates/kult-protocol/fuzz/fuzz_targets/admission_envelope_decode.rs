//! Fuzz: first-contact admission parsing is bounded, canonical, and panic-free.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = kult_protocol::AdmissionEnvelope::decode(data) {
        let encoded = envelope.encode().unwrap();
        assert!(encoded.len() <= kult_protocol::MAX_ADMISSION_ENVELOPE_BYTES);
        assert_eq!(
            kult_protocol::AdmissionEnvelope::decode(&encoded).unwrap(),
            envelope
        );
    }
});
