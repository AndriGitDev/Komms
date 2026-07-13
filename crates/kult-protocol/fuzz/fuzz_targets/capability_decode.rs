//! Fuzz: capability parsing must never panic; canonical controls round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(control) = kult_protocol::CapabilityControl::decode(data) {
        let encoded = control.encode().unwrap();
        assert_eq!(kult_protocol::CapabilityControl::decode(&encoded).unwrap(), control);
    }
});
