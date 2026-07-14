//! Fuzz: fixed-record attachment opening is total and successful opens reseal identically.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let context = kult_crypto::AttachmentChunkContext {
        scope: kult_crypto::AttachmentChunkScope::Pairwise,
        scope_id: [1; 32],
        manifest_author: [2; 32],
        manifest_content_id: [3; 16],
        object_id: [4; 16],
        role: 0,
        total_len: 1,
        chunk_count: 1,
        content_hash: [5; 32],
    };
    let key = [6; 32];
    if let Ok(plaintext) = kult_crypto::open_attachment_chunk(&key, &context, 0, data) {
        let resealed = kult_crypto::seal_attachment_chunk(&key, &context, 0, &plaintext).unwrap();
        assert_eq!(resealed, data);
    }
});
