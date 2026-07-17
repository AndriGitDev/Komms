//! Fuzz: call-control classification is total and canonical values re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedCallControl::Control(control) =
        kult_protocol::decode_call_control_payload(data)
    {
        let encoded = kult_protocol::encode_call_control_payload(&control).unwrap();
        assert_eq!(encoded, data);
        assert_eq!(
            kult_protocol::decode_call_control_payload(&encoded),
            kult_protocol::DecodedCallControl::Control(control)
        );
    }
});
