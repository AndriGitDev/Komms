//! Fuzz: authenticated discovery-control parsing is bounded and canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(control) = kult_protocol::DiscoveryUpgradeControl::decode(data) {
        let encoded = control.encode().unwrap();
        assert_eq!(
            kult_protocol::DiscoveryUpgradeControl::decode(&encoded).unwrap(),
            control
        );
    }
});
