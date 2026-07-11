//! Fuzz: InitialMessage parsing must never panic (spec §11, obligation 4).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kult_crypto::InitialMessage::decode(data);
});
