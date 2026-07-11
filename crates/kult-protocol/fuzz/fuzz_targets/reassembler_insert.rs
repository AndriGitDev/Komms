//! Fuzz: reassembler must never panic on arbitrary fragment streams.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = kult_protocol::Reassembler::new();
    for chunk in data.chunks(64) {
        let _ = r.insert(chunk, 1_800_000_000);
    }
});
