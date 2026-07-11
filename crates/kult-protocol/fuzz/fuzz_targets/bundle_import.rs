//! Fuzz: bundle parsing must never panic and re-export round-trips.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envs) = kult_protocol::bundle_import(data) {
        let re = kult_protocol::bundle_export(&envs);
        assert_eq!(kult_protocol::bundle_import(&re).unwrap(), envs);
    }
});
