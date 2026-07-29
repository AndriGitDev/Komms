//! Fuzz: pairwise-encrypted group controls are strict and panic-free.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(control) = kult_protocol::GroupControlPayload::decode(data) {
        let encoded = control.encode();
        assert_eq!(
            kult_protocol::GroupControlPayload::decode(&encoded).unwrap(),
            control
        );
    }
});
