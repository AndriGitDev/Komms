//! Fuzz: C6 group-authority decoding is total and canonical values re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedGroupAuthority::State(state) =
        kult_protocol::decode_group_authority(data)
    {
        let encoded = kult_protocol::encode_group_authority_state(&state).unwrap();
        assert_eq!(encoded, data);
    }
});
