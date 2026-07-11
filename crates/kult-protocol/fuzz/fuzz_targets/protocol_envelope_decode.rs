//! Fuzz: Envelope wire parsing must never panic; round-trips when it parses.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = kult_protocol::Envelope::decode(data) {
        assert_eq!(kult_protocol::Envelope::decode(&env.encode()).unwrap(), env);
    }
});
