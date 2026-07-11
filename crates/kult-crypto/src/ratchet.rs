//! Double Ratchet with header encryption (the Signal "HE" variant), with the
//! delay-tolerance parameters fixed in docs/04-cryptography.md §4.
//!
//! Normative parameters (do not change without an ADR):
//! `MAX_SKIP = 1000`, skipped-key store cap `2000` (LRU), skipped-key TTL 30 days.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{util, CryptoError, Result, PROTOCOL_VERSION};

/// Maximum message keys skipped within a single receiving chain.
pub const MAX_SKIP: u32 = 1000;
/// Maximum skipped message keys stored per session (LRU-evicted beyond this).
pub const MAX_STORED_SKIPPED: usize = 2000;
/// Skipped-key time-to-live in seconds (30 days).
pub const SKIPPED_KEY_TTL_SECS: u64 = 30 * 86_400;

/// Plaintext ratchet header: sender's current ratchet key and counters.
/// Encoded as 40 bytes: `dh(32) || pn(4, LE) || n(4, LE)`.
const HEADER_LEN: usize = 40;
/// Encrypted header length: nonce(24) + header(40) + tag(16).
const ENC_HEADER_LEN: usize = util::NONCE_LEN + HEADER_LEN + util::TAG_LEN;

/// KDF info strings (spec §4).
const INFO_ROOT: &[u8] = b"KK-root";
const INFO_CHAIN: &[u8] = b"KK-chain";
const INFO_MSG: &[u8] = b"KK-msg";
const HDR_AD_DOMAIN: &[u8] = b"KK-hdr";

/// A single encrypted ratchet message.
///
/// Wire layout (`encode`): `version(1) || enc_header(80) || nonce(24) || ct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetMessage {
    enc_header: [u8; ENC_HEADER_LEN],
    nonce: [u8; util::NONCE_LEN],
    ct: Vec<u8>,
}

impl RatchetMessage {
    /// Serialize to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ENC_HEADER_LEN + util::NONCE_LEN + self.ct.len());
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.enc_header);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse from the wire format. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + ENC_HEADER_LEN + util::NONCE_LEN + util::TAG_LEN {
            return Err(CryptoError::InvalidMessage);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(CryptoError::InvalidMessage);
        }
        let mut enc_header = [0u8; ENC_HEADER_LEN];
        enc_header.copy_from_slice(&bytes[1..1 + ENC_HEADER_LEN]);
        let mut nonce = [0u8; util::NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + ENC_HEADER_LEN..1 + ENC_HEADER_LEN + util::NONCE_LEN]);
        Ok(Self {
            enc_header,
            nonce,
            ct: bytes[1 + ENC_HEADER_LEN + util::NONCE_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Copy)]
struct Header {
    dh: [u8; 32],
    pn: u32,
    n: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(CryptoError::InvalidMessage);
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        Ok(Self {
            dh,
            pn: u32::from_le_bytes(bytes[32..36].try_into().expect("length checked")),
            n: u32::from_le_bytes(bytes[36..40].try_into().expect("length checked")),
        })
    }
}

/// A skipped message key, retained for late/out-of-order delivery.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    hk: [u8; 32],
    n: u32,
    mk: [u8; 32],
    stored_at: u64,
}

/// Double Ratchet session state (header-encryption variant).
///
/// Opaque and serializable only through [`Session::seal`] /
/// [`Session::unseal`] — plaintext state never leaves this type.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session {
    session_id: [u8; 32],
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: [u8; 32],
    nhkr: [u8; 32],
    ns: u32,
    nr: u32,
    pn: u32,
    mailbox: [u8; 32],
    skipped: Vec<SkippedKey>,
}

/// `KDF_RK_HE`: (root key, DH output) → (root key, chain key, next header key).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut okm = Zeroizing::new([0u8; 96]);
    util::hkdf_expand(Some(rk), dh_out, INFO_ROOT, okm.as_mut());
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    let mut nhk = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..64]);
    nhk.copy_from_slice(&okm[64..]);
    (new_rk, ck, nhk)
}

/// `KDF_CK`: chain key → (next chain key, message key).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = util::hkdf32(None, ck, INFO_CHAIN);
    let mk = util::hkdf32(None, ck, INFO_MSG);
    (*next, *mk)
}

fn dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let secret = StaticSecret::from(*priv_bytes);
    Zeroizing::new(
        *secret
            .diffie_hellman(&PublicKey::from(*pub_bytes))
            .as_bytes(),
    )
}

impl Session {
    /// Initialize as the handshake **initiator** (Alice).
    ///
    /// `their_ratchet_pub` is the responder's signed prekey, which doubles as
    /// their initial ratchet key. `shared_hka`/`shared_nhkb` are the initial
    /// header keys derived from the handshake root secret.
    pub(crate) fn init_initiator(
        rng: &mut impl CryptoRngCore,
        session_id: [u8; 32],
        sk_root: &[u8; 32],
        their_ratchet_pub: &[u8; 32],
        shared_hka: &[u8; 32],
        shared_nhkb: &[u8; 32],
        mailbox: [u8; 32],
    ) -> Self {
        let mut priv_bytes = [0u8; 32];
        rng.fill_bytes(&mut priv_bytes);
        let dhs = StaticSecret::from(priv_bytes);
        let dhs_pub = *PublicKey::from(&dhs).as_bytes();
        let dh_out = dh(&priv_bytes, their_ratchet_pub);
        let (rk, cks, nhks) = kdf_rk(sk_root, &dh_out);
        Self {
            session_id,
            dhs_priv: priv_bytes,
            dhs_pub,
            dhr: Some(*their_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            hks: Some(*shared_hka),
            hkr: None,
            nhks,
            nhkr: *shared_nhkb,
            ns: 0,
            nr: 0,
            pn: 0,
            mailbox,
            skipped: Vec::new(),
        }
    }

    /// Initialize as the handshake **responder** (Bob). `ratchet_priv` is the
    /// private half of the signed prekey used in the handshake.
    pub(crate) fn init_responder(
        session_id: [u8; 32],
        sk_root: &[u8; 32],
        ratchet_priv: &[u8; 32],
        shared_hka: &[u8; 32],
        shared_nhkb: &[u8; 32],
        mailbox: [u8; 32],
    ) -> Self {
        let dhs = StaticSecret::from(*ratchet_priv);
        let dhs_pub = *PublicKey::from(&dhs).as_bytes();
        Self {
            session_id,
            dhs_priv: *ratchet_priv,
            dhs_pub,
            dhr: None,
            rk: *sk_root,
            cks: None,
            ckr: None,
            hks: None,
            hkr: None,
            nhks: *shared_nhkb,
            nhkr: *shared_hka,
            ns: 0,
            nr: 0,
            pn: 0,
            mailbox,
            skipped: Vec::new(),
        }
    }

    /// Stable identifier derived from the handshake transcript.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The per-pair mailbox secret for delivery-token derivation
    /// (spec §7). Both parties hold the identical value; `kult-protocol`
    /// turns it into rotating tokens.
    pub fn mailbox_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.mailbox)
    }

    fn base_ad(&self) -> [u8; 33] {
        let mut ad = [0u8; 33];
        ad[..32].copy_from_slice(&self.session_id);
        ad[32] = PROTOCOL_VERSION;
        ad
    }

    fn header_ad(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(33 + HDR_AD_DOMAIN.len());
        ad.extend_from_slice(&self.base_ad());
        ad.extend_from_slice(HDR_AD_DOMAIN);
        ad
    }

    /// Full payload AD: session binding || encrypted header || caller AD.
    fn payload_ad(&self, enc_header: &[u8; ENC_HEADER_LEN], user_ad: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(33 + ENC_HEADER_LEN + user_ad.len());
        ad.extend_from_slice(&self.base_ad());
        ad.extend_from_slice(enc_header);
        ad.extend_from_slice(user_ad);
        ad
    }

    /// Encrypt `plaintext`. `now_secs` (Unix time) drives skipped-key TTL
    /// housekeeping; `user_ad` is additional authenticated data supplied by
    /// the protocol layer (may be empty).
    pub fn encrypt(
        &mut self,
        rng: &mut impl CryptoRngCore,
        now_secs: u64,
        plaintext: &[u8],
        user_ad: &[u8],
    ) -> RatchetMessage {
        self.purge_expired(now_secs);
        let cks = self
            .cks
            .expect("sending chain always exists after session init");
        let (next_ck, mk) = kdf_ck(&cks);
        self.cks = Some(next_ck);

        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        let hks = self
            .hks
            .expect("sending header key always exists when sending chain does");
        let hdr_ad = self.header_ad();
        let sealed_hdr = util::aead_seal(&hks, &hdr_ad, &header.encode(), rng);
        let mut enc_header = [0u8; ENC_HEADER_LEN];
        enc_header.copy_from_slice(&sealed_hdr);

        let mut nonce = [0u8; util::NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let ad = self.payload_ad(&enc_header, user_ad);
        let ct = util::aead_encrypt_with_nonce(&mk, &nonce, &ad, plaintext);
        Zeroizing::new(mk);

        self.ns += 1;
        RatchetMessage {
            enc_header,
            nonce,
            ct,
        }
    }

    /// Decrypt a message, tolerating loss and reordering within the
    /// normative bounds. Fails closed beyond them.
    ///
    /// `rng` supplies fresh randomness for the sending ratchet keypair
    /// generated when the peer's DH ratchet step is processed (required for
    /// post-compromise security).
    pub fn decrypt(
        &mut self,
        rng: &mut impl CryptoRngCore,
        now_secs: u64,
        msg: &RatchetMessage,
        user_ad: &[u8],
    ) -> Result<Vec<u8>> {
        self.purge_expired(now_secs);

        // 1. A message from a chain we already passed (skipped key)?
        if let Some(pt) = self.try_skipped(msg, user_ad)? {
            return Ok(pt);
        }

        let hdr_ad = self.header_ad();

        // 2. Current receiving header key.
        if let Some(hkr) = self.hkr {
            if let Ok(hdr_bytes) = util::aead_open(&hkr, &hdr_ad, &msg.enc_header) {
                let header = Header::decode(&hdr_bytes)?;
                if header.n < self.nr {
                    // Belongs to the current chain's past but wasn't in the
                    // skipped store: replay or key already consumed.
                    return Err(CryptoError::MessageAuthentication);
                }
                self.skip_message_keys(header.n, now_secs)?;
                return self.decrypt_current(msg, user_ad);
            }
        }

        // 3. Next header key → the sender performed a DH ratchet step.
        if let Ok(hdr_bytes) = util::aead_open(&self.nhkr, &hdr_ad, &msg.enc_header) {
            let header = Header::decode(&hdr_bytes)?;
            self.skip_message_keys(header.pn, now_secs)?; // finish old chain
            self.dh_ratchet(rng, &header);
            self.skip_message_keys(header.n, now_secs)?;
            return self.decrypt_current(msg, user_ad);
        }

        Err(CryptoError::HeaderAuthentication)
    }

    /// Serialize and AEAD-seal the state for storage (spec §8).
    pub fn seal(&self, key: &crate::StorageKey, rng: &mut impl CryptoRngCore) -> Vec<u8> {
        crate::sealed::seal_session(self, key, rng)
    }

    /// Reverse of [`Session::seal`].
    pub fn unseal(bytes: &[u8], key: &crate::StorageKey) -> Result<Self> {
        crate::sealed::unseal_session(bytes, key)
    }

    // ---- internals -------------------------------------------------------

    fn decrypt_current(&mut self, msg: &RatchetMessage, user_ad: &[u8]) -> Result<Vec<u8>> {
        let ckr = self.ckr.expect("receiving chain exists at this point");
        let (next_ck, mk) = kdf_ck(&ckr);
        let ad = self.payload_ad(&msg.enc_header, user_ad);
        let pt = util::aead_decrypt_with_nonce(&mk, &msg.nonce, &ad, &msg.ct)?;
        // Commit state only after successful authentication.
        self.ckr = Some(next_ck);
        self.nr += 1;
        Zeroizing::new(mk);
        Ok(pt)
    }

    fn try_skipped(&mut self, msg: &RatchetMessage, user_ad: &[u8]) -> Result<Option<Vec<u8>>> {
        let hdr_ad = self.header_ad();
        let mut tried: Vec<[u8; 32]> = Vec::new();
        let mut hit: Option<usize> = None;

        'outer: for sk in self.skipped.iter() {
            if tried.iter().any(|t| t == &sk.hk) {
                continue;
            }
            tried.push(sk.hk);
            if let Ok(hdr_bytes) = util::aead_open(&sk.hk, &hdr_ad, &msg.enc_header) {
                let header = Header::decode(&hdr_bytes)?;
                // Joint (header key, N) lookup, per the Signal HE spec. A
                // decryptable header with no stored entry is NOT necessarily
                // a replay: skipped entries share their hk with the live
                // receiving chain, so fresh in-order messages land here too —
                // fall through to normal processing, whose `n < nr` check
                // rejects genuine replays.
                for (j, cand) in self.skipped.iter().enumerate() {
                    if cand.hk == sk.hk && cand.n == header.n {
                        hit = Some(j);
                        break 'outer;
                    }
                }
                break;
            }
        }

        let Some(idx) = hit else {
            return Ok(None);
        };
        let mk = self.skipped[idx].mk;
        let ad = self.payload_ad(&msg.enc_header, user_ad);
        let pt = util::aead_decrypt_with_nonce(&mk, &msg.nonce, &ad, &msg.ct)?;
        self.skipped.remove(idx);
        Ok(Some(pt))
    }

    fn skip_message_keys(&mut self, until: u32, now_secs: u64) -> Result<()> {
        if until > self.nr.saturating_add(MAX_SKIP) {
            return Err(CryptoError::TooManySkipped);
        }
        let Some(mut ckr) = self.ckr else {
            // No receiving chain yet (responder before first ratchet):
            // nothing to skip; header.pn of the first chain is 0.
            return if until == 0 {
                Ok(())
            } else {
                Err(CryptoError::TooManySkipped)
            };
        };
        let hkr = self
            .hkr
            .expect("receiving header key exists whenever receiving chain does");
        while self.nr < until {
            let (next_ck, mk) = kdf_ck(&ckr);
            self.skipped.push(SkippedKey {
                hk: hkr,
                n: self.nr,
                mk,
                stored_at: now_secs,
            });
            ckr = next_ck;
            self.nr += 1;
        }
        self.ckr = Some(ckr);
        // LRU cap (spec: 2000 per session).
        while self.skipped.len() > MAX_STORED_SKIPPED {
            self.skipped.remove(0);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, rng: &mut impl CryptoRngCore, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(header.dh);

        // Receiving side of the step.
        let dh_recv = dh(&self.dhs_priv, &header.dh);
        let (rk, ckr, nhkr) = kdf_rk(&self.rk, &dh_recv);
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = nhkr;

        // Sending side: fresh ratchet keypair (post-compromise security
        // depends on this randomness being new, never derived).
        let mut priv_bytes = [0u8; 32];
        rng.fill_bytes(&mut priv_bytes);
        let dhs = StaticSecret::from(priv_bytes);
        self.dhs_pub = *PublicKey::from(&dhs).as_bytes();
        self.dhs_priv = priv_bytes;
        let dh_send = dh(&self.dhs_priv, &header.dh);
        let (rk, cks, nhks) = kdf_rk(&self.rk, &dh_send);
        self.rk = rk;
        self.cks = Some(cks);
        self.nhks = nhks;
    }

    fn purge_expired(&mut self, now_secs: u64) {
        self.skipped
            .retain(|sk| now_secs.saturating_sub(sk.stored_at) <= SKIPPED_KEY_TTL_SECS);
    }
}
