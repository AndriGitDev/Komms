//! Fuzz: attachment-manifest classification is total and canonical manifests round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedAttachmentManifest::Manifest(manifest) =
        kult_protocol::decode_attachment_manifest(data)
    {
        let encoded = kult_protocol::encode_attachment_manifest(&manifest).unwrap();
        assert_eq!(encoded, data);
    }
});
