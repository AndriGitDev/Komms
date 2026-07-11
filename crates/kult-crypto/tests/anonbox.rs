//! Anonymous sealed-box tests: only the addressed identity opens it, and any
//! tampering fails uniformly.

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{open_anonymous, seal_anonymous, Identity};

#[test]
fn anonbox_roundtrip_wrong_recipient_and_tamper() {
    let mut rng = StdRng::seed_from_u64(21);
    let bob = Identity::generate(&mut rng);
    let eve = Identity::generate(&mut rng);

    let sealed = seal_anonymous(&bob.public(), b"ad", b"first contact", &mut rng);
    assert_eq!(
        open_anonymous(&bob, b"ad", &sealed).unwrap(),
        b"first contact"
    );

    // Wrong recipient, wrong AD, and any bit-flip all fail.
    assert!(open_anonymous(&eve, b"ad", &sealed).is_err());
    assert!(open_anonymous(&bob, b"other-ad", &sealed).is_err());
    for pos in [0, 31, 32, 55, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 1;
        assert!(open_anonymous(&bob, b"ad", &bad).is_err());
    }
    // Truncation never panics.
    for len in [0, 31, 32, 55] {
        assert!(open_anonymous(&bob, b"ad", &sealed[..len]).is_err());
    }

    // Sealing the same plaintext twice yields unlinkable ciphertexts.
    let sealed2 = seal_anonymous(&bob.public(), b"ad", b"first contact", &mut rng);
    assert_ne!(sealed, sealed2);
}
