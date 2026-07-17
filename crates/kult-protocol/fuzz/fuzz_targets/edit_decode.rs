//! Fuzz: Edit payload classification is total and canonical values re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedEdit::Edit(edit) = kult_protocol::decode_edit_payload(data) {
        let encoded = kult_protocol::encode_edit_payload(&edit).unwrap();
        assert_eq!(encoded, data);
        assert_eq!(
            kult_protocol::decode_edit_payload(&encoded),
            kult_protocol::DecodedEdit::Edit(edit)
        );
    }
});
