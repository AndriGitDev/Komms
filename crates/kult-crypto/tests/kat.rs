//! Known-answer tests against published vectors (spec §11, obligation 1).

use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

fn public_case(id: &str) -> Value {
    let document: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/cases/primitives.json"
    ))
    .unwrap();
    document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("missing public conformance case {id}"))
        .clone()
}

fn vector_hex(value: &Value) -> Vec<u8> {
    if let Some(value) = value.as_str() {
        return hex::decode(value).unwrap();
    }
    if let Some(value) = value.get("$utf8_hex").and_then(Value::as_str) {
        return value.as_bytes().to_vec();
    }
    if let Some(repeat) = value.get("$repeat_hex") {
        let byte = u8::from_str_radix(repeat["byte_hex"].as_str().unwrap(), 16).unwrap();
        let count = repeat["bytes"].as_u64().unwrap() as usize;
        return vec![byte; count];
    }
    panic!("public primitive vector field is not a supported hex expression");
}

fn fixed<const N: usize>(value: &Value) -> [u8; N] {
    vector_hex(value).try_into().unwrap()
}

/// RFC 7748 §6.1 — X25519 Diffie-Hellman vector.
#[test]
fn x25519_rfc7748() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let case = public_case("x25519-rfc7748-6.1");
    let arguments = &case["arguments"];
    let expected = &case["expected"]["result"];
    let a_priv = fixed(&arguments["alice_secret_hex"]);
    let b_priv = fixed(&arguments["bob_secret_hex"]);
    let a = StaticSecret::from(a_priv);
    let b = StaticSecret::from(b_priv);
    assert_eq!(
        PublicKey::from(&a).as_bytes().as_slice(),
        vector_hex(&expected["alice_public_hex"])
    );
    assert_eq!(
        PublicKey::from(&b).as_bytes().as_slice(),
        vector_hex(&expected["bob_public_hex"])
    );
    let shared = a.diffie_hellman(&PublicKey::from(&b));
    assert_eq!(
        shared.as_bytes().as_slice(),
        vector_hex(&expected["shared_secret_hex"])
    );
}

/// RFC 8032 §7.1 — Ed25519 TEST 1 (empty message).
#[test]
fn ed25519_rfc8032_test1() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    let case = public_case("ed25519-rfc8032-7.1");
    let arguments = &case["arguments"];
    let expected = &case["expected"]["result"];
    let secret = fixed(&arguments["secret_hex"]);
    let message = vector_hex(&arguments["message_hex"]);
    let sk = SigningKey::from_bytes(&secret);
    assert_eq!(
        sk.verifying_key().as_bytes().as_slice(),
        vector_hex(&expected["public_hex"])
    );
    let signature = sk.sign(&message);
    let expected_signature = vector_hex(&expected["signature_hex"]);
    assert_eq!(signature.to_bytes().as_slice(), expected_signature);
    let signature = Signature::from_bytes(&expected_signature.try_into().unwrap());
    sk.verifying_key().verify(&message, &signature).unwrap();
}

/// draft-irtf-cfrg-xchacha §A.3 — XChaCha20-Poly1305 AEAD vector.
#[test]
fn xchacha20poly1305_draft_vector() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let case = public_case("xchacha20poly1305-irtf-a.3");
    let arguments = &case["arguments"];
    let expected = &case["expected"]["result"];
    let key = fixed(&arguments["key_hex"]);
    let nonce = vector_hex(&arguments["nonce_hex"]);
    let aad = vector_hex(&arguments["aad_hex"]);
    let plaintext = vector_hex(&arguments["plaintext_hex"]);

    let cipher = XChaCha20Poly1305::new(&key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(ct, vector_hex(&expected["sealed_hex"]));

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
    let case = public_case("hkdf-sha256-rfc5869-a.1");
    let arguments = &case["arguments"];
    let expected = &case["expected"]["result"];
    let ikm = vector_hex(&arguments["ikm_hex"]);
    let salt = vector_hex(&arguments["salt_hex"]);
    let info = vector_hex(&arguments["info_hex"]);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; arguments["output_len"].as_u64().unwrap() as usize];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, vector_hex(&expected["okm_hex"]));
}

/// RFC 9106 §5.3 — Argon2id test vector (t=3, m=32 KiB, p=4, with secret+ad).
#[test]
fn argon2id_rfc9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, KeyId, ParamsBuilder, Version};
    let case = public_case("argon2id-rfc9106-5.3");
    let arguments = &case["arguments"];
    let expected = &case["expected"]["result"];
    let password = vector_hex(&arguments["password_hex"]);
    let salt = vector_hex(&arguments["salt_hex"]);
    let secret = vector_hex(&arguments["secret_hex"]);
    let ad = vector_hex(&arguments["associated_data_hex"]);

    let params = ParamsBuilder::new()
        .m_cost(arguments["memory_kib"].as_u64().unwrap() as u32)
        .t_cost(arguments["iterations"].as_u64().unwrap() as u32)
        .p_cost(arguments["parallelism"].as_u64().unwrap() as u32)
        .data(AssociatedData::new(&ad).unwrap())
        .keyid(KeyId::new(&[]).unwrap())
        .output_len(arguments["output_len"].as_u64().unwrap() as usize)
        .build()
        .unwrap();
    let a2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = vec![0u8; arguments["output_len"].as_u64().unwrap() as usize];
    a2.hash_password_into(&password, &salt, &mut out).unwrap();
    assert_eq!(out, vector_hex(&expected["output_hex"]));
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
