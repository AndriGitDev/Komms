//! Fuzz: fixed-width rendezvous authentication rejects arbitrary records
//! without panics, truncation, or variable-shape parsing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, Error, RngCore};

struct FuzzRng(u64);

impl RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        // A deterministic xorshift stream is sufficient here: this is only
        // nonce input for exercising authenticated open, never production
        // randomness.
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for FuzzRng {}

fuzz_target!(|data: &[u8]| {
    let recipient = kult_crypto::Identity::from_bytes(&[1u8; 64]).public();
    let provider =
        kult_crypto::rendezvous_provider_id(b"https://fuzz.example", &[2u8; 32]).unwrap();
    let keys =
        kult_crypto::derive_rendezvous_epoch_keys(&[3u8; 32], &provider, &recipient, 42).unwrap();

    // Arbitrary bytes exercise every fail-closed length/authentication path.
    let _ = kult_crypto::open_rendezvous_record(&keys, data);

    // Also keep every input on a valid authenticated path so the fuzzer reaches
    // past the fixed-size and Poly1305 gates instead of spending its entire
    // budget on immediate rejection.
    let mut plaintext = [0u8; kult_crypto::RENDEZVOUS_RECORD_PLAINTEXT_LEN];
    let copied = data.len().min(plaintext.len());
    plaintext[..copied].copy_from_slice(&data[..copied]);
    let seed = data
        .iter()
        .take(8)
        .enumerate()
        .fold(0x4b52_5631_1818_0001u64, |seed, (index, byte)| {
            seed ^ (u64::from(*byte) << (index * 8))
        });
    let mut rng = FuzzRng(seed.max(1));
    let sealed = kult_crypto::seal_rendezvous_record(&keys, &plaintext, &mut rng);
    let opened = kult_crypto::open_rendezvous_record(&keys, &sealed).unwrap();
    assert_eq!(*opened, plaintext);
});
