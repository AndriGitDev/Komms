//! Anonymous sealed box: encrypt to a recipient's identity without revealing
//! the sender to observers. Used to wrap handshake first-flights so the
//! initiator's identity travels inside AEAD, preserving the sealed-sender
//! property of docs/04-cryptography.md §7 from the very first envelope.
//!
//! Construction (crypto_box-seal style, XChaCha20-Poly1305):
//! `eph ← X25519 keypair; k = HKDF(DH(eph, IK_B_x), salt = eph_pub ‖ IK_B_x,
//! info = "KK-anon-box-v1"); out = eph_pub ‖ AEAD_k(pt)`.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{util, CryptoError, Identity, IdentityPublic, Result};

const INFO: &[u8] = b"KK-anon-box-v1";

fn box_key(dh: &[u8; 32], eph_pub: &[u8; 32], recipient_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient_x);
    util::hkdf32(Some(&salt), dh, INFO)
}

/// Seal `plaintext` to `recipient` anonymously. The recipient must have been
/// verified ([`IdentityPublic::verify`]) or obtained from a verified bundle.
pub fn seal_anonymous(
    recipient: &IdentityPublic,
    ad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Vec<u8> {
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph = StaticSecret::from(eph_bytes);
    Zeroizing::new(eph_bytes);
    let eph_pub = *PublicKey::from(&eph).as_bytes();
    let dh = Zeroizing::new(*eph.diffie_hellman(&PublicKey::from(recipient.x)).as_bytes());
    let k = box_key(&dh, &eph_pub, &recipient.x);

    let sealed = util::aead_seal(&k, ad, plaintext, rng);
    let mut out = Vec::with_capacity(32 + sealed.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&sealed);
    out
}

/// Open an anonymous box addressed to `me`. Uniform error on any failure.
pub fn open_anonymous(me: &Identity, ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 32 + util::NONCE_LEN + util::TAG_LEN {
        return Err(CryptoError::MessageAuthentication);
    }
    let eph_pub: [u8; 32] = sealed[..32].try_into().expect("length checked");
    let dh = me.dh(&eph_pub);
    let my_x = me.public().x;
    let k = box_key(&dh, &eph_pub, &my_x);
    util::aead_open(&k, ad, &sealed[32..])
}
