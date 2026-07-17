//! Fuzz: certified per-device prekey wrappers are strict and panic-free.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = kult_crypto::DevicePrekeyBundle::decode(data) {
        let _ = bundle.verify(1_800_000_000);
        if let Ok(encoded) = bundle.encode() {
            let decoded = kult_crypto::DevicePrekeyBundle::decode(&encoded).unwrap();
            let _ = decoded.verify(1_800_000_000);
        }
    }
});
