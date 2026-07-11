//! Fuzz: RatchetMessage wire parsing must never panic (spec §11, obligation 4).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = kult_crypto::RatchetMessage::decode(data) {
        // Round-trip property on anything that parses.
        let re = msg.encode();
        assert_eq!(kult_crypto::RatchetMessage::decode(&re).unwrap(), msg);
    }
});
