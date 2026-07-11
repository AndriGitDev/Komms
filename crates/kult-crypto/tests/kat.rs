//! Known-answer tests against published vectors (spec §11, obligation 1).

use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 7748 §6.1 — X25519 Diffie-Hellman vector.
#[test]
fn x25519_rfc7748() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let a_priv: [u8; 32] =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap();
    let b_priv: [u8; 32] =
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .unwrap()
            .try_into()
            .unwrap();
    let a = StaticSecret::from(a_priv);
    let b = StaticSecret::from(b_priv);
    assert_eq!(
        PublicKey::from(&a).as_bytes().as_slice(),
        hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap()
    );
    assert_eq!(
        PublicKey::from(&b).as_bytes().as_slice(),
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap()
    );
    let shared = a.diffie_hellman(&PublicKey::from(&b));
    assert_eq!(
        shared.as_bytes().as_slice(),
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap()
    );
}

/// RFC 8032 §7.1 — Ed25519 TEST 1 (empty message).
#[test]
fn ed25519_rfc8032_test1() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    let secret: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let sk = SigningKey::from_bytes(&secret);
    assert_eq!(
        sk.verifying_key().as_bytes().as_slice(),
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap()
    );
    let sig = sk.sign(b"");
    let expected = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();
    assert_eq!(sig.to_bytes().as_slice(), expected);
    let sig2 = Signature::from_bytes(&expected.try_into().unwrap());
    sk.verifying_key().verify(b"", &sig2).unwrap();
}

/// draft-irtf-cfrg-xchacha §A.3 — XChaCha20-Poly1305 AEAD vector.
#[test]
fn xchacha20poly1305_draft_vector() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let key: [u8; 32] =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let cipher = XChaCha20Poly1305::new(&key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    let expected_ct = hex::decode(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
         21f9664c97637da9768812f615c68b13b52e",
    )
    .unwrap();
    let expected_tag = hex::decode("c0875924c1c7987947deafd8780acf49").unwrap();

    assert_eq!(&ct[..expected_ct.len()], expected_ct.as_slice());
    assert_eq!(&ct[expected_ct.len()..], expected_tag.as_slice());

    let pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(pt, plaintext);
}

/// RFC 5869 §A.1 — HKDF-SHA-256 test case 1.
#[test]
fn hkdf_rfc5869_case1() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(
        okm.as_slice(),
        hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
        .unwrap()
    );
}

/// RFC 9106 §5.3 — Argon2id test vector (t=3, m=32 KiB, p=4, with secret+ad).
#[test]
fn argon2id_rfc9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, KeyId, ParamsBuilder, Version};
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];

    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&ad).unwrap())
        .keyid(KeyId::new(&[]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let a2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    a2.hash_password_into(&password, &salt, &mut out).unwrap();
    assert_eq!(
        out.as_slice(),
        hex::decode("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659").unwrap()
    );
}

/// ML-KEM-768: encapsulation/decapsulation round-trip and size invariants
/// (full NIST KATs live upstream in the `ml-kem` crate; this pins our usage).
#[test]
fn mlkem768_roundtrip_and_sizes() {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    assert_eq!(ek.as_bytes().len(), kult_crypto::MLKEM768_EK_LEN);
    assert_eq!(dk.as_bytes().len(), kult_crypto::MLKEM768_DK_LEN);
    let (ct, ss1) = ek.encapsulate(&mut rng).unwrap();
    assert_eq!(ct.len(), kult_crypto::MLKEM768_CT_LEN);
    let ss2 = dk.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2);
}
