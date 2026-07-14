//! Fuzz: content classification must be total; canonical text round-trips.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = kult_protocol::decode_content(data);
    if let kult_protocol::DecodedContent::Text { id, text } = decoded {
        let encoded = kult_protocol::encode_text(id, text).unwrap();
        assert_eq!(kult_protocol::decode_content(&encoded), decoded);
    }
    if let kult_protocol::DecodedContent::Attachment { id, manifest } = decoded {
        let encoded = kult_protocol::encode_attachment(id, &manifest).unwrap();
        assert_eq!(kult_protocol::decode_content(&encoded), decoded);
    }
});
