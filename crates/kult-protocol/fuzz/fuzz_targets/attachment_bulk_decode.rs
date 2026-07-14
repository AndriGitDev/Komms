//! Fuzz: KAB bulk-record classification is total and canonical records round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let kult_protocol::DecodedAttachmentBulkRecord::Record(record) =
        kult_protocol::decode_attachment_bulk_record(data)
    {
        let encoded = kult_protocol::encode_attachment_bulk_record(&record).unwrap();
        assert_eq!(encoded, data);
    }
});
