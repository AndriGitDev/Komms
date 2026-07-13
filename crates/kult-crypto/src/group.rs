//! Sender-key group messaging (docs/04-cryptography.md §6, ADR-0012).
//!
//! Per group, each member holds a **sending chain** — a forward-only
//! symmetric ratchet identified by a random 16-byte key id — and one
//! **receiving chain** per co-member, learned over the pairwise Double
//! Ratchet sessions. A group message is encrypted once under the sender's
//! current message key and fanned out; the header naming the chain
//! (`key_id ‖ iteration`) is AEAD-sealed under a group header key derived
//! from the group secret, so intermediaries see uniformly random bytes and
//! cannot link one sender's traffic across the daily token rotation.
//!
//! There is no DH step and no signature (the spec's Ed25519-free
//! construction): forward secrecy per sender comes from the chain, post-
//! compromise security from rotation, and authenticity is membership-level —
//! any member holding a chain could forge as its owner, a documented v1
//! trade (ADR-0012).
//!
//! Delay-tolerance bounds mirror the pairwise ratchet: `GROUP_MAX_SKIP`
//! per message, `GROUP_MAX_STORED_SKIPPED` stored keys per chain
//! (LRU-evicted), 30-day skipped-key TTL.

use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{util, CryptoError, Result, PROTOCOL_VERSION};

/// Maximum messages skipped forward within a receiving chain per arrival.
pub const GROUP_MAX_SKIP: u32 = 1000;
/// Maximum skipped message keys stored per receiving chain (LRU beyond).
pub const GROUP_MAX_STORED_SKIPPED: usize = 2000;
/// Skipped-key time-to-live in seconds (30 days).
pub const GROUP_SKIPPED_TTL_SECS: u64 = 30 * 86_400;

/// KDF info strings (spec §6, ADR-0012).
const INFO_CHAIN: &[u8] = b"KK-group-chain";
const INFO_MSG: &[u8] = b"KK-group-msg";
const INFO_HDR_KEY: &[u8] = b"KK-group-hdr";
const HDR_AD_DOMAIN: &[u8] = b"KK-group-hdr-v1";
const MSG_AD_DOMAIN: &[u8] = b"KK-group-msg-v1";

/// Header plaintext: `key_id(16) ‖ iteration(4 LE)`.
const HDR_PLAIN_LEN: usize = 16 + 4;
/// Sealed header: nonce(24) + plaintext(20) + tag(16).
const ENC_HDR_LEN: usize = util::NONCE_LEN + HDR_PLAIN_LEN + util::TAG_LEN;

/// `KDF_CK` for group chains: chain key → (next chain key, message key).
fn kdf_gck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = util::hkdf32(None, ck, INFO_CHAIN);
    let mk = util::hkdf32(None, ck, INFO_MSG);
    (*next, *mk)
}

/// The group header key: seals the `key_id ‖ iteration` routing header of
/// every group message. Derived from the group secret, so only members can
/// read (or link) chain identifiers; rotated with the secret on removal.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GroupHeaderKey([u8; 32]);

impl GroupHeaderKey {
    /// Derive from the 32-byte group secret.
    pub fn derive(group_secret: &[u8; 32]) -> Self {
        Self(*util::hkdf32(None, group_secret, INFO_HDR_KEY))
    }
}

fn header_ad() -> [u8; 16] {
    let mut ad = [0u8; 16];
    ad[..HDR_AD_DOMAIN.len()].copy_from_slice(HDR_AD_DOMAIN);
    ad[HDR_AD_DOMAIN.len()] = PROTOCOL_VERSION;
    ad
}

/// Full payload AD: domain ‖ version ‖ group id ‖ sealed header — binding
/// the ciphertext to its group and its routing header.
fn payload_ad(group_id: &[u8; 32], enc_header: &[u8; ENC_HDR_LEN]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(MSG_AD_DOMAIN.len() + 1 + 32 + ENC_HDR_LEN);
    ad.extend_from_slice(MSG_AD_DOMAIN);
    ad.push(PROTOCOL_VERSION);
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(enc_header);
    ad
}

/// A single encrypted group message.
///
/// Wire layout (`encode`): `version(1) ‖ enc_header(60) ‖ nonce(24) ‖ ct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    enc_header: [u8; ENC_HDR_LEN],
    nonce: [u8; util::NONCE_LEN],
    ct: Vec<u8>,
}

impl GroupMessage {
    /// Serialize to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ENC_HDR_LEN + util::NONCE_LEN + self.ct.len());
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.enc_header);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse from the wire format. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + ENC_HDR_LEN + util::NONCE_LEN + util::TAG_LEN {
            return Err(CryptoError::InvalidMessage);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(CryptoError::InvalidMessage);
        }
        let mut enc_header = [0u8; ENC_HDR_LEN];
        enc_header.copy_from_slice(&bytes[1..1 + ENC_HDR_LEN]);
        let mut nonce = [0u8; util::NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + ENC_HDR_LEN..1 + ENC_HDR_LEN + util::NONCE_LEN]);
        Ok(Self {
            enc_header,
            nonce,
            ct: bytes[1 + ENC_HDR_LEN + util::NONCE_LEN..].to_vec(),
        })
    }

    /// Open the routing header with a group's header key, yielding the
    /// sending chain's key id and the message's iteration. Fails uniformly
    /// for "not this group" and "tampered" — callers try their few groups.
    pub fn open_header(&self, hk: &GroupHeaderKey) -> Result<([u8; 16], u32)> {
        let plain = Zeroizing::new(util::aead_open(&hk.0, &header_ad(), &self.enc_header)?);
        if plain.len() != HDR_PLAIN_LEN {
            return Err(CryptoError::InvalidMessage);
        }
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&plain[..16]);
        let iteration = u32::from_le_bytes(plain[16..].try_into().expect("length checked"));
        Ok((key_id, iteration))
    }
}

/// This device's sending chain for one group — one "sender-key epoch".
/// Rotation replaces the whole value (fresh key id, fresh chain key).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupSenderChain {
    key_id: [u8; 16],
    chain_key: [u8; 32],
    iteration: u32,
}

impl GroupSenderChain {
    /// Mint a fresh chain (group creation, join, or rotation).
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut key_id = [0u8; 16];
        rng.fill_bytes(&mut key_id);
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);
        Self {
            key_id,
            chain_key,
            iteration: 0,
        }
    }

    /// The chain's public-to-members identifier.
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Next message's iteration (== messages sent so far on this chain).
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Snapshot the current state for an announce: whoever receives it can
    /// read from this iteration on, and nothing earlier (docs/04 §6 —
    /// joining grants no history).
    pub fn snapshot(&self) -> ([u8; 16], Zeroizing<[u8; 32]>, u32) {
        (self.key_id, Zeroizing::new(self.chain_key), self.iteration)
    }

    /// Encrypt one (already padded) plaintext for the group, advancing the
    /// chain. The same [`GroupMessage`] fans out to every member.
    pub fn seal(
        &mut self,
        hk: &GroupHeaderKey,
        group_id: &[u8; 32],
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> GroupMessage {
        let (next_ck, mk) = kdf_gck(&self.chain_key);

        let mut hdr_plain = Zeroizing::new([0u8; HDR_PLAIN_LEN]);
        hdr_plain[..16].copy_from_slice(&self.key_id);
        hdr_plain[16..].copy_from_slice(&self.iteration.to_le_bytes());
        let sealed_hdr = util::aead_seal(&hk.0, &header_ad(), hdr_plain.as_ref(), rng);
        let mut enc_header = [0u8; ENC_HDR_LEN];
        enc_header.copy_from_slice(&sealed_hdr);

        let mut nonce = [0u8; util::NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let ad = payload_ad(group_id, &enc_header);
        let ct = util::aead_encrypt_with_nonce(&mk, &nonce, &ad, plaintext);
        Zeroizing::new(mk);

        self.chain_key = next_ck;
        self.iteration += 1;
        GroupMessage {
            enc_header,
            nonce,
            ct,
        }
    }
}

/// A skipped group message key, retained for late/out-of-order delivery.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct GroupSkippedKey {
    n: u32,
    mk: [u8; 32],
    stored_at: u64,
}

/// A co-member's receiving chain: their announced snapshot, ratcheted
/// forward as their messages arrive, with skipped keys stored for the
/// loss/reorder the slow carriers guarantee.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupReceiverChain {
    key_id: [u8; 16],
    chain_key: [u8; 32],
    iteration: u32,
    skipped: Vec<GroupSkippedKey>,
}

impl GroupReceiverChain {
    /// Adopt an announced chain snapshot (key id, chain key, iteration).
    pub fn new(key_id: [u8; 16], chain_key: &[u8; 32], iteration: u32) -> Self {
        Self {
            key_id,
            chain_key: *chain_key,
            iteration,
            skipped: Vec::new(),
        }
    }

    /// The chain identifier this receiver tracks.
    pub fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Decrypt a group message whose opened header claimed `iteration` on
    /// this chain. Tolerates loss and reordering within the normative
    /// bounds; fails closed beyond them, and rejects replays (a consumed
    /// iteration is gone from the skipped store).
    pub fn open(
        &mut self,
        group_id: &[u8; 32],
        msg: &GroupMessage,
        iteration: u32,
        now_secs: u64,
    ) -> Result<Vec<u8>> {
        self.skipped
            .retain(|sk| now_secs.saturating_sub(sk.stored_at) <= GROUP_SKIPPED_TTL_SECS);
        let ad = payload_ad(group_id, &msg.enc_header);

        // A message from the chain's past: only a stored skipped key can
        // open it, and it is consumed on success.
        if iteration < self.iteration {
            let Some(idx) = self.skipped.iter().position(|sk| sk.n == iteration) else {
                return Err(CryptoError::MessageAuthentication);
            };
            let mk = self.skipped[idx].mk;
            let pt = util::aead_decrypt_with_nonce(&mk, &msg.nonce, &ad, &msg.ct)?;
            self.skipped.remove(idx);
            return Ok(pt);
        }

        // Skip forward, storing keys for the gap (bounded).
        if iteration > self.iteration.saturating_add(GROUP_MAX_SKIP) {
            return Err(CryptoError::TooManySkipped);
        }
        while self.iteration < iteration {
            let (next_ck, mk) = kdf_gck(&self.chain_key);
            self.skipped.push(GroupSkippedKey {
                n: self.iteration,
                mk,
                stored_at: now_secs,
            });
            self.chain_key = next_ck;
            self.iteration += 1;
        }
        while self.skipped.len() > GROUP_MAX_STORED_SKIPPED {
            self.skipped.remove(0);
        }

        // The claimed message itself: commit the chain step only after
        // successful authentication (the skipped keys above stay — they
        // belong to genuinely missing messages either way).
        let (next_ck, mk) = kdf_gck(&self.chain_key);
        let pt = util::aead_decrypt_with_nonce(&mk, &msg.nonce, &ad, &msg.ct)?;
        Zeroizing::new(mk);
        self.chain_key = next_ck;
        self.iteration += 1;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::RngCore;

    const GID: [u8; 32] = [7u8; 32];
    const NOW: u64 = 1_800_000_000;

    fn setup() -> (StdRng, GroupHeaderKey, GroupSenderChain, GroupReceiverChain) {
        let mut rng = StdRng::seed_from_u64(42);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let hk = GroupHeaderKey::derive(&secret);
        let sender = GroupSenderChain::generate(&mut rng);
        let (key_id, ck, iter) = sender.snapshot();
        let receiver = GroupReceiverChain::new(key_id, &ck, iter);
        (rng, hk, sender, receiver)
    }

    #[test]
    fn round_trip_in_order() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        for i in 0..10u32 {
            let msg = sender.seal(&hk, &GID, format!("m{i}").as_bytes(), &mut rng);
            let wire = msg.encode();
            let parsed = GroupMessage::decode(&wire).unwrap();
            let (key_id, iter) = parsed.open_header(&hk).unwrap();
            assert_eq!(key_id, receiver.key_id());
            assert_eq!(iter, i);
            let pt = receiver.open(&GID, &parsed, iter, NOW).unwrap();
            assert_eq!(pt, format!("m{i}").as_bytes());
        }
    }

    #[test]
    fn loss_reorder_and_replay() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        let msgs: Vec<GroupMessage> = (0..5)
            .map(|i| sender.seal(&hk, &GID, &[i as u8], &mut rng))
            .collect();
        // Deliver 4 first (0..3 skipped), then 1, then 1 again (replay).
        let (_, i4) = msgs[4].open_header(&hk).unwrap();
        assert_eq!(receiver.open(&GID, &msgs[4], i4, NOW).unwrap(), vec![4]);
        let (_, i1) = msgs[1].open_header(&hk).unwrap();
        assert_eq!(receiver.open(&GID, &msgs[1], i1, NOW).unwrap(), vec![1]);
        assert!(receiver.open(&GID, &msgs[1], i1, NOW).is_err(), "replay");
        // 0, 2, 3 still readable from the skipped store.
        for i in [0usize, 2, 3] {
            let (_, it) = msgs[i].open_header(&hk).unwrap();
            assert_eq!(
                receiver.open(&GID, &msgs[i], it, NOW).unwrap(),
                vec![i as u8]
            );
        }
    }

    #[test]
    fn skip_bound_fails_closed() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        for _ in 0..=GROUP_MAX_SKIP {
            sender.seal(&hk, &GID, b"burn", &mut rng);
        }
        let msg = sender.seal(&hk, &GID, b"too far", &mut rng);
        let (_, iter) = msg.open_header(&hk).unwrap();
        assert!(matches!(
            receiver.open(&GID, &msg, iter, NOW),
            Err(CryptoError::TooManySkipped)
        ));
    }

    #[test]
    fn wrong_header_key_and_wrong_group_fail() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        let msg = sender.seal(&hk, &GID, b"hi", &mut rng);
        let other = GroupHeaderKey::derive(&[9u8; 32]);
        assert!(msg.open_header(&other).is_err());
        let (_, iter) = msg.open_header(&hk).unwrap();
        assert!(
            receiver.open(&[8u8; 32], &msg, iter, NOW).is_err(),
            "group id is bound into the payload AD"
        );
    }

    #[test]
    fn tampered_iteration_rejected_without_burning_the_chain() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        let m0 = sender.seal(&hk, &GID, b"real", &mut rng);
        let (_, i0) = m0.open_header(&hk).unwrap();
        // Claim a future iteration for the same ciphertext: payload AEAD
        // fails (wrong mk), and the real message still decrypts afterwards.
        assert!(receiver.open(&GID, &m0, i0 + 3, NOW).is_err());
        assert_eq!(receiver.open(&GID, &m0, i0, NOW).unwrap(), b"real");
    }

    #[test]
    fn snapshot_grants_no_history() {
        let (mut rng, hk, mut sender, _receiver) = setup();
        let early = sender.seal(&hk, &GID, b"before join", &mut rng);
        let (key_id, ck, iter) = sender.snapshot();
        let mut late_joiner = GroupReceiverChain::new(key_id, &ck, iter);
        let (_, i_early) = early.open_header(&hk).unwrap();
        assert!(late_joiner.open(&GID, &early, i_early, NOW).is_err());
        let after = sender.seal(&hk, &GID, b"after join", &mut rng);
        let (_, i_after) = after.open_header(&hk).unwrap();
        assert_eq!(
            late_joiner.open(&GID, &after, i_after, NOW).unwrap(),
            b"after join"
        );
    }

    #[test]
    fn state_serialization_round_trips() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        let m0 = sender.seal(&hk, &GID, b"one", &mut rng);
        let sender_bytes = postcard::to_allocvec(&sender).unwrap();
        let receiver_bytes = postcard::to_allocvec(&receiver).unwrap();
        let mut sender2: GroupSenderChain = postcard::from_bytes(&sender_bytes).unwrap();
        let mut receiver2: GroupReceiverChain = postcard::from_bytes(&receiver_bytes).unwrap();
        let (_, i0) = m0.open_header(&hk).unwrap();
        assert_eq!(receiver2.open(&GID, &m0, i0, NOW).unwrap(), b"one");
        let m1 = sender2.seal(&hk, &GID, b"two", &mut rng);
        let (_, i1) = m1.open_header(&hk).unwrap();
        assert_eq!(receiver.open(&GID, &m1, i1, NOW).unwrap(), b"two");
        drop(receiver2);
    }
}
