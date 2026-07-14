//! Fuzz: missing-range validation is total under arbitrary counts and boundaries.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let chunk_count = u32::from_le_bytes(data[..4].try_into().unwrap());
    let ranges: Vec<_> = data[4..]
        .chunks_exact(8)
        .take(80)
        .map(|encoded| kult_protocol::MissingRange {
            start: u32::from_le_bytes(encoded[..4].try_into().unwrap()),
            count: u32::from_le_bytes(encoded[4..].try_into().unwrap()),
        })
        .collect();
    let _ = kult_protocol::validate_missing_ranges(&ranges, chunk_count);
});
