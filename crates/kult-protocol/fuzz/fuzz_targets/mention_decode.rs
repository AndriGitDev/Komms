//! Fuzz: Mention payload classification is total and canonical values re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedMention::Mention(mention) =
        kult_protocol::decode_mention_payload(data)
    {
        let spans = mention.spans().collect::<Vec<_>>();
        let encoded = kult_protocol::encode_mention_payload(mention.text, &spans).unwrap();
        assert_eq!(encoded, data);
        assert_eq!(
            kult_protocol::decode_mention_payload(&encoded),
            kult_protocol::DecodedMention::Mention(mention)
        );
    }
});
