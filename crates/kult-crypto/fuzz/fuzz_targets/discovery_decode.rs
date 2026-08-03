//! Fuzz: Connect-code and fixed discovery-record parsing are panic-free.
#![no_main]

use libfuzzer_sys::fuzz_target;

const FIXED_CODE: &str = "kc2aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeavbh5ipi";

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(code) = kult_crypto::ConnectCode::parse(text) {
            let encoded = code.encode();
            assert_eq!(kult_crypto::ConnectCode::parse(&encoded).unwrap(), code);
        }
    }

    let code = kult_crypto::ConnectCode::parse(FIXED_CODE).unwrap();
    let epoch = data
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    let now = data
        .get(8..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    let record = data.get(16..).unwrap_or_default();
    let _ = kult_crypto::open_discovery_record(&code, epoch, record, now);
});
