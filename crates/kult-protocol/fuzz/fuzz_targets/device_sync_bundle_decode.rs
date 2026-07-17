//! Fuzz: linked-device sync outer decoding is bounded, strict, and panic-free.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = kult_protocol::DeviceSyncBundle::decode(data) {
        let encoded = bundle.encode().unwrap();
        assert_eq!(kult_protocol::DeviceSyncBundle::decode(&encoded).unwrap(), bundle);
    }
});
