//! Fuzz: Envelope wire parsing must never panic; round-trips when it parses.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = kult_protocol::Envelope::decode(data) {
        let encoded = env.try_encode().unwrap();
        assert!(encoded.len() <= kult_protocol::MAX_ENVELOPE_BYTES);
        assert_eq!(kult_protocol::Envelope::decode(&encoded).unwrap(), env);
    }
});
