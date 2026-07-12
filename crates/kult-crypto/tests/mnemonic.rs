//! Mnemonic known-answer tests against the official BIP-39 English test
//! vectors (trezor/python-mnemonic), plus round-trip and rejection cases.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use kult_crypto::{mnemonic_from_entropy, mnemonic_to_entropy, CryptoError, MNEMONIC_WORDS};

/// The four 256-bit vectors from the reference test set.
const VECTORS: &[(&str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon art",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave \
         sausage worth useful legal winner thank year wave sausage worth title",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd \
         amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
         zoo zoo zoo vote",
    ),
    (
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book \
         happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    ),
];

fn unhex(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap();
    bytes.try_into().unwrap()
}

fn normalize(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn known_answer_vectors() {
    for (entropy_hex, phrase) in VECTORS {
        let entropy = unhex(entropy_hex);
        let expected = normalize(phrase);
        assert_eq!(*mnemonic_from_entropy(&entropy), expected);
        assert_eq!(*mnemonic_to_entropy(&expected).unwrap(), entropy);
    }
}

#[test]
fn round_trip_random_entropy() {
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..64 {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let phrase = mnemonic_from_entropy(&entropy);
        assert_eq!(phrase.split(' ').count(), MNEMONIC_WORDS);
        assert_eq!(*mnemonic_to_entropy(&phrase).unwrap(), entropy);
    }
}

#[test]
fn decode_is_forgiving_about_presentation_only() {
    let entropy = unhex(VECTORS[4].0);
    let phrase = normalize(VECTORS[4].1);
    let shouted = phrase.to_uppercase();
    let ragged = phrase.replace(' ', "\n  ");
    assert_eq!(*mnemonic_to_entropy(&shouted).unwrap(), entropy);
    assert_eq!(*mnemonic_to_entropy(&ragged).unwrap(), entropy);
    assert_eq!(
        *mnemonic_to_entropy(&format!("  {phrase}  ")).unwrap(),
        entropy
    );
}

#[test]
fn decode_rejects_bad_phrases() {
    let phrase = normalize(VECTORS[0].1);

    // A swapped word breaks the checksum.
    let swapped = phrase.replacen("art", "zoo", 1);
    assert_eq!(
        mnemonic_to_entropy(&swapped).unwrap_err(),
        CryptoError::InvalidMnemonic
    );

    // A word outside the list.
    let unknown = phrase.replacen("art", "notaword", 1);
    assert_eq!(
        mnemonic_to_entropy(&unknown).unwrap_err(),
        CryptoError::InvalidMnemonic
    );

    // Wrong word counts.
    let short = phrase.rsplit_once(' ').unwrap().0;
    assert_eq!(
        mnemonic_to_entropy(short).unwrap_err(),
        CryptoError::InvalidMnemonic
    );
    assert_eq!(
        mnemonic_to_entropy(&format!("{phrase} abandon")).unwrap_err(),
        CryptoError::InvalidMnemonic
    );
    assert_eq!(
        mnemonic_to_entropy("").unwrap_err(),
        CryptoError::InvalidMnemonic
    );
}
