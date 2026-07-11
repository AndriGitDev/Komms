//! Fuzz: PrekeyBundle parsing/verification must never panic
//! (spec §11, obligation 4).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = kult_crypto::PrekeyBundle::decode(data) {
        let _ = bundle.verify(1_800_000_000);
    }
});
