//! Hybrid post-quantum PQXDH handshake (spec §3): X25519 X3DH extended with
//! ML-KEM-768 so the session root secret requires breaking **both**.

use alloc::vec::Vec;

use ml_kem::kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::prekeys::{
    OneTimePrekeySecret, PqPrekeySecret, SignedPrekeySecret, VerifiedBundle, MLKEM768_CT_LEN,
};
use crate::ratchet::{RatchetMessage, Session};
use crate::{util, CryptoError, Identity, IdentityPublic, Result};

const PQXDH_INFO: &[u8] = b"Komms-PQXDH-v1";
const INFO_HKA: &[u8] = b"KK-hka";
const INFO_NHKB: &[u8] = b"KK-nhkb";
const INFO_MAILBOX: &[u8] = b"KK-mailbox";

/// The initiator's first flight: everything the responder needs to derive the
/// session, plus the first Double-Ratchet message.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    /// Initiator's public identity.
    pub initiator: IdentityPublic,
    /// Initiator's ephemeral X25519 public key.
    pub ek: [u8; 32],
    /// Which signed prekey the initiator used.
    pub spk_id: u32,
    /// Which PQ signed prekey the initiator used.
    pub pqspk_id: u32,
    /// Which one-time prekey was consumed, if any.
    pub opk_id: Option<u32>,
    /// ML-KEM-768 ciphertext ([`MLKEM768_CT_LEN`] bytes).
    pub kem_ct: Vec<u8>,
    /// First ratchet message (encoded), bound to the handshake transcript.
    pub first: Vec<u8>,
}

impl InitialMessage {
    /// Postcard-encode for transport.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("initial message serialization cannot fail")
    }

    /// Parse from bytes. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| CryptoError::Serialization)
    }
}

/// Transcript hash binding every handshake element; doubles as the session id
/// and is mixed into all session associated data.
#[allow(clippy::too_many_arguments)]
fn transcript(
    initiator: &IdentityPublic,
    responder: &IdentityPublic,
    spk: &[u8; 32],
    pqspk: &[u8],
    ek: &[u8; 32],
    kem_ct: &[u8],
    opk: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PQXDH_INFO);
    h.update(initiator.ed);
    h.update(initiator.x);
    h.update(responder.ed);
    h.update(responder.x);
    h.update(spk);
    h.update(pqspk);
    h.update(ek);
    h.update(kem_ct);
    match opk {
        Some(k) => {
            h.update([1u8]);
            h.update(k);
        }
        None => h.update([0u8]),
    }
    h.finalize().into()
}

/// Root secret plus the two initial header keys (hka, nhkb).
type RootKeys = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

/// `SK_root = HKDF(0xFF*32 || DH1..DH4 || KEM_ss)` per spec §3, plus the two
/// initial header keys for the header-encrypted ratchet.
fn derive_root(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    kem_ss: &[u8; 32],
) -> RootKeys {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 6));
    ikm.extend_from_slice(&[0xFF; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d) = dh4 {
        ikm.extend_from_slice(d);
    }
    ikm.extend_from_slice(kem_ss);
    let salt = [0u8; 32];
    let sk_root = util::hkdf32(Some(&salt), &ikm, PQXDH_INFO);
    let hka = util::hkdf32(None, sk_root.as_ref(), INFO_HKA);
    let nhkb = util::hkdf32(None, sk_root.as_ref(), INFO_NHKB);
    (sk_root, hka, nhkb)
}

/// Initiate a session against a **verified** prekey bundle, producing the
/// session and the first flight carrying `first_payload`.
pub fn initiate(
    me: &Identity,
    bundle: &VerifiedBundle,
    first_payload: &[u8],
    now_secs: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<(Session, InitialMessage)> {
    let b = bundle.bundle();

    // Ephemeral X25519 key.
    let mut ek_bytes = [0u8; 32];
    rng.fill_bytes(&mut ek_bytes);
    let ek_secret = StaticSecret::from(ek_bytes);
    let ek_pub = *PublicKey::from(&ek_secret).as_bytes();
    Zeroizing::new(ek_bytes);

    // Classical DHs (spec §3).
    let dh1 = me.dh(&b.spk);
    let dh2 = Zeroizing::new(
        *ek_secret
            .diffie_hellman(&PublicKey::from(b.identity.x))
            .as_bytes(),
    );
    let dh3 = Zeroizing::new(*ek_secret.diffie_hellman(&PublicKey::from(b.spk)).as_bytes());
    let dh4 = b.opk.map(|(_, opk_pub)| {
        Zeroizing::new(
            *ek_secret
                .diffie_hellman(&PublicKey::from(opk_pub))
                .as_bytes(),
        )
    });

    // Post-quantum encapsulation.
    let ek_arr = b.pqspk[..]
        .try_into()
        .map_err(|_| CryptoError::InvalidBundle)?;
    let kem_ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
    let (kem_ct, kem_ss_raw) = kem_ek
        .encapsulate(rng)
        .map_err(|_| CryptoError::InvalidBundle)?;
    let mut kem_ss = Zeroizing::new([0u8; 32]);
    kem_ss.copy_from_slice(&kem_ss_raw);
    let kem_ct_bytes: Vec<u8> = kem_ct.to_vec();

    let (sk_root, hka, nhkb) = derive_root(&dh1, &dh2, &dh3, dh4.as_deref(), &kem_ss);

    let session_id = transcript(
        &me.public(),
        &b.identity,
        &b.spk,
        &b.pqspk,
        &ek_pub,
        &kem_ct_bytes,
        b.opk.map(|(_, p)| p).as_ref(),
    );

    let mailbox = util::hkdf32(None, sk_root.as_ref(), INFO_MAILBOX);
    let mut session =
        Session::init_initiator(rng, session_id, &sk_root, &b.spk, &hka, &nhkb, *mailbox);
    let first = session.encrypt(rng, now_secs, first_payload, &[]);

    let msg = InitialMessage {
        initiator: me.public(),
        ek: ek_pub,
        spk_id: b.spk_id,
        pqspk_id: b.pqspk_id,
        opk_id: b.opk.map(|(id, _)| id),
        kem_ct: kem_ct_bytes,
        first: first.encode(),
    };
    Ok((session, msg))
}

/// Respond to an [`InitialMessage`] using the prekey secrets it references
/// (looked up by id by the caller — this crate does no storage). Returns the
/// established session and the decrypted first payload.
///
/// The consumed one-time prekey must be deleted by the caller afterwards.
pub fn respond(
    me: &Identity,
    spk: &SignedPrekeySecret,
    pqspk: &PqPrekeySecret,
    opk: Option<&OneTimePrekeySecret>,
    msg: &InitialMessage,
    now_secs: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<(Session, Vec<u8>)> {
    // Consistency: the message must reference exactly the secrets provided.
    if msg.spk_id != spk.id
        || msg.pqspk_id != pqspk.id
        || msg.opk_id != opk.map(|k| k.id)
        || msg.kem_ct.len() != MLKEM768_CT_LEN
    {
        return Err(CryptoError::HandshakeMismatch);
    }
    msg.initiator.verify()?;

    let dh1 = spk.dh(&msg.initiator.x);
    let dh2 = me.dh(&msg.ek);
    let dh3 = spk.dh(&msg.ek);
    let dh4 = opk.map(|k| k.dh(&msg.ek));
    let kem_ss = pqspk.decapsulate(&msg.kem_ct)?;

    let (sk_root, hka, nhkb) = derive_root(&dh1, &dh2, &dh3, dh4.as_deref(), &kem_ss);

    let session_id = transcript(
        &msg.initiator,
        &me.public(),
        &spk.public(),
        pqspk.public(),
        &msg.ek,
        &msg.kem_ct,
        opk.map(|k| k.public()).as_ref(),
    );

    let spk_priv = spk.to_bytes();
    let mailbox = util::hkdf32(None, sk_root.as_ref(), INFO_MAILBOX);
    let mut session =
        Session::init_responder(session_id, &sk_root, &spk_priv, &hka, &nhkb, *mailbox);
    let first = RatchetMessage::decode(&msg.first)?;
    let payload = session.decrypt(rng, now_secs, &first, &[])?;
    Ok((session, payload))
}
