#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kult_protocol::decode_ephemeral_payload(data);
});
