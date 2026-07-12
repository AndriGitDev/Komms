//! Fuzz: mnemonic phrase parsing must never panic, and every accepted
//! phrase must round-trip to the identical canonical encoding.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(phrase) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(entropy) = kult_crypto::mnemonic_to_entropy(phrase) {
        let canonical = kult_crypto::mnemonic_from_entropy(&entropy);
        let re = kult_crypto::mnemonic_to_entropy(&canonical).expect("canonical decodes");
        assert_eq!(*re, *entropy);
    }
});
