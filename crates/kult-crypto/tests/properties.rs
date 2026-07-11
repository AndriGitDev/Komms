//! Property tests (spec §11, obligation 3): under arbitrary loss/reorder
//! within the normative bounds, every delivered message decrypts; the
//! wire codecs round-trip; parsers never panic.

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{
    initiate, respond, Identity, InitialMessage, PqPrekeySecret, PrekeyBundle, RatchetMessage,
    SignedPrekeySecret,
};

const NOW: u64 = 1_800_000_000;

fn sessions(seed: u64) -> (kult_crypto::Session, kult_crypto::Session, StdRng) {
    let mut rng = StdRng::seed_from_u64(seed);
    let alice = Identity::generate(&mut rng);
    let bob = Identity::generate(&mut rng);
    let spk = SignedPrekeySecret::generate(&mut rng, 1);
    let pqspk = PqPrekeySecret::generate(&mut rng, 1);
    let bundle = PrekeyBundle::build(&bob, &spk, &pqspk, None, NOW + 1000, vec![])
        .verify(NOW)
        .unwrap();
    let (a, init) = initiate(&alice, &bundle, b"init", NOW, &mut rng).unwrap();
    let (b, _) = respond(&bob, &spk, &pqspk, None, &init, NOW, &mut rng).unwrap();
    (a, b, rng)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Random per-burst delivery permutations and drops (within MAX_SKIP):
    /// everything that arrives decrypts to what was sent.
    #[test]
    fn delivered_messages_always_decrypt(
        seed in any::<u64>(),
        bursts in prop::collection::vec(
            (1usize..15, prop::collection::vec(any::<u8>(), 0..8)),
            1..12,
        ),
    ) {
        let (mut a, mut b, mut rng) = sessions(seed);
        let mut dir_a = true;
        for (n, drop_pattern) in bursts {
            let (tx, rx) = if dir_a { (&mut a, &mut b) } else { (&mut b, &mut a) };
            let mut batch: Vec<(Vec<u8>, RatchetMessage)> = (0..n)
                .map(|i| {
                    let body = vec![i as u8; i + 1];
                    let m = tx.encrypt(&mut rng, NOW, &body, b"ad");
                    (body, m)
                })
                .collect();
            // Drop a subset (bounded — far below MAX_SKIP).
            let mut idx = 0usize;
            batch.retain(|_| {
                let keep = drop_pattern.get(idx).map_or(true, |d| d % 4 != 0);
                idx += 1;
                keep
            });
            batch.reverse(); // worst-case reorder
            for (body, m) in &batch {
                let pt = rx.decrypt(&mut rng, NOW, m, b"ad").unwrap();
                prop_assert_eq!(pt, body.clone());
            }
            dir_a = !dir_a;
        }
    }

    /// RatchetMessage encode/decode is the identity.
    #[test]
    fn ratchet_message_roundtrip(seed in any::<u64>(), body in prop::collection::vec(any::<u8>(), 0..512)) {
        let (mut a, _b, mut rng) = sessions(seed);
        let m = a.encrypt(&mut rng, NOW, &body, &[]);
        let decoded = RatchetMessage::decode(&m.encode()).unwrap();
        prop_assert_eq!(m, decoded);
    }

    /// Parsers never panic on arbitrary bytes (fuzz obligation, cheap form).
    #[test]
    fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = RatchetMessage::decode(&bytes);
        let _ = InitialMessage::decode(&bytes);
        let _ = PrekeyBundle::decode(&bytes);
    }

    /// A flipped bit anywhere in a message must never decrypt successfully.
    #[test]
    fn bitflips_never_authenticate(seed in any::<u64>(), pos_seed in any::<usize>()) {
        let (mut a, mut b, mut rng) = sessions(seed);
        let m = a.encrypt(&mut rng, NOW, b"integrity", &[]);
        let mut wire = m.encode();
        let pos = 1 + (pos_seed % (wire.len() - 1)); // skip version byte
        wire[pos] ^= 1;
        if let Ok(tampered) = RatchetMessage::decode(&wire) {
            prop_assert!(b.decrypt(&mut rng, NOW, &tampered, &[]).is_err());
        }
    }
}
