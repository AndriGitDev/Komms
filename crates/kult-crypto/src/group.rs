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
//! Legacy v1 messages have only membership-level authenticity. ADR-0029's v2
//! shape additionally places the event id inside the encrypted group header
//! and wraps the shared ciphertext in a distinct recipient-device HMAC. The
//! receiver verifies that tag before advancing this symmetric chain. This
//! retains one group ciphertext and recipient deniability while preventing a
//! member from forging another member to a third-party recipient.
//!
//! Delay-tolerance bounds mirror the pairwise ratchet: `GROUP_MAX_SKIP`
//! per message, `GROUP_MAX_STORED_SKIPPED` stored keys per chain
//! (LRU-evicted), 30-day skipped-key TTL.

use alloc::{vec, vec::Vec};

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{util, CryptoError, Result};

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
const ORIGIN_DOMAIN: &[u8] = b"Komms-Group-Origin-v1";

/// Legacy membership-authenticated sender-key message version.
pub const GROUP_MESSAGE_VERSION_LEGACY: u8 = 1;
/// Recipient-origin-authenticated sender-key message version.
pub const GROUP_MESSAGE_VERSION_ORIGIN: u8 = 2;
/// Origin wrapper magic and version.
pub const GROUP_ORIGIN_ENVELOPE_MAGIC: [u8; 4] = [0xff, b'K', b'G', 1];
/// Fixed recipient-origin tag length.
pub const GROUP_ORIGIN_TAG_LEN: usize = 32;

/// Legacy header plaintext: `key_id(16) ‖ iteration(4 LE)`.
const LEGACY_HDR_PLAIN_LEN: usize = 16 + 4;
/// Origin header plaintext: legacy fields plus the encrypted event id.
const ORIGIN_HDR_PLAIN_LEN: usize = LEGACY_HDR_PLAIN_LEN + 16;

fn header_plain_len(version: u8) -> Option<usize> {
    match version {
        GROUP_MESSAGE_VERSION_LEGACY => Some(LEGACY_HDR_PLAIN_LEN),
        GROUP_MESSAGE_VERSION_ORIGIN => Some(ORIGIN_HDR_PLAIN_LEN),
        _ => None,
    }
}

fn enc_header_len(version: u8) -> Option<usize> {
    header_plain_len(version).map(|plain| util::NONCE_LEN + plain + util::TAG_LEN)
}

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

fn header_ad(version: u8) -> [u8; 16] {
    let mut ad = [0u8; 16];
    ad[..HDR_AD_DOMAIN.len()].copy_from_slice(HDR_AD_DOMAIN);
    ad[HDR_AD_DOMAIN.len()] = version;
    ad
}

/// Full payload AD: domain ‖ version ‖ group id ‖ sealed header — binding
/// the ciphertext to its group and its routing header.
fn payload_ad(group_id: &[u8; 32], version: u8, enc_header: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(MSG_AD_DOMAIN.len() + 1 + 32 + enc_header.len());
    ad.extend_from_slice(MSG_AD_DOMAIN);
    ad.push(version);
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(enc_header);
    ad
}

/// Decrypted routing fields from a sender-key group header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupMessageHeader {
    /// Sender-chain identifier.
    pub key_id: [u8; 16],
    /// Message iteration on that chain.
    pub iteration: u32,
    /// Authenticated event id carried by origin-authenticated v2 messages.
    pub content_id: Option<[u8; 16]>,
}

/// A single encrypted group message.
///
/// Wire layout (`encode`):
/// `version(1) ‖ enc_header(version-sized) ‖ nonce(24) ‖ ct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    version: u8,
    enc_header: Vec<u8>,
    nonce: [u8; util::NONCE_LEN],
    ct: Vec<u8>,
}

impl GroupMessage {
    /// Serialize to the wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + self.enc_header.len() + util::NONCE_LEN + self.ct.len());
        out.push(self.version);
        out.extend_from_slice(&self.enc_header);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse from the wire format. Never panics on arbitrary input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(&version) = bytes.first() else {
            return Err(CryptoError::InvalidMessage);
        };
        let Some(enc_header_len) = enc_header_len(version) else {
            return Err(CryptoError::InvalidMessage);
        };
        if bytes.len() < 1 + enc_header_len + util::NONCE_LEN + util::TAG_LEN {
            return Err(CryptoError::InvalidMessage);
        }
        let enc_header = bytes[1..1 + enc_header_len].to_vec();
        let mut nonce = [0u8; util::NONCE_LEN];
        nonce.copy_from_slice(&bytes[1 + enc_header_len..1 + enc_header_len + util::NONCE_LEN]);
        Ok(Self {
            version,
            enc_header,
            nonce,
            ct: bytes[1 + enc_header_len + util::NONCE_LEN..].to_vec(),
        })
    }

    /// Sender-key wire version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Open the routing header with a group's header key, yielding the
    /// sending chain's key id and the message's iteration. Fails uniformly
    /// for "not this group" and "tampered" — callers try their few groups.
    pub fn open_header(&self, hk: &GroupHeaderKey) -> Result<([u8; 16], u32)> {
        let header = self.open_header_details(hk)?;
        Ok((header.key_id, header.iteration))
    }

    /// Open all versioned routing fields without advancing a sender chain.
    pub fn open_header_details(&self, hk: &GroupHeaderKey) -> Result<GroupMessageHeader> {
        let Some(expected_len) = header_plain_len(self.version) else {
            return Err(CryptoError::InvalidMessage);
        };
        let plain = Zeroizing::new(util::aead_open(
            &hk.0,
            &header_ad(self.version),
            &self.enc_header,
        )?);
        if plain.len() != expected_len {
            return Err(CryptoError::InvalidMessage);
        }
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&plain[..16]);
        let iteration = u32::from_le_bytes(plain[16..20].try_into().expect("fixed checked slice"));
        let content_id = if self.version == GROUP_MESSAGE_VERSION_ORIGIN {
            Some(
                plain[20..36]
                    .try_into()
                    .expect("origin header length checked"),
            )
        } else {
            None
        };
        Ok(GroupMessageHeader {
            key_id,
            iteration,
            content_id,
        })
    }
}

/// Fixed-width fields authenticated separately for one recipient device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupOriginContext {
    /// Group conversation id.
    pub group_id: [u8; 32],
    /// Stable sending account identity.
    pub sender_account: [u8; 32],
    /// Certified sending physical device.
    pub sender_device: [u8; 32],
    /// Stable receiving account identity.
    pub recipient_account: [u8; 32],
    /// Certified receiving physical device.
    pub recipient_device: [u8; 32],
    /// Exact sender-chain id opened from the sealed group header.
    pub sender_chain_key_id: [u8; 16],
    /// Exact event id opened from the sealed group header.
    pub envelope_content_id: [u8; 16],
    /// Authenticated coarse retention bucket; zero on the wire means absent.
    pub authenticated_retention: Option<u64>,
}

/// One recipient-scoped wrapper around an unchanged shared group ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupOriginEnvelope {
    shared: GroupMessage,
    tag: [u8; GROUP_ORIGIN_TAG_LEN],
}

impl GroupOriginEnvelope {
    /// Authenticate one already encrypted shared group message for a single
    /// recipient device.
    pub fn seal(
        shared: GroupMessage,
        origin_key: &[u8; 32],
        context: &GroupOriginContext,
    ) -> Result<Self> {
        if shared.version != GROUP_MESSAGE_VERSION_ORIGIN || *origin_key == [0u8; 32] {
            return Err(CryptoError::InvalidKey);
        }
        let tag = group_origin_tag(origin_key, context, &shared.encode());
        Ok(Self { shared, tag })
    }

    /// Reassemble an already authenticated recipient wrapper from its shared
    /// ciphertext and stored tag. This does not verify the tag; receivers
    /// must call [`Self::verify`] with the exact recipient origin key.
    pub fn from_parts(shared: GroupMessage, tag: [u8; GROUP_ORIGIN_TAG_LEN]) -> Result<Self> {
        if shared.version != GROUP_MESSAGE_VERSION_ORIGIN {
            return Err(CryptoError::InvalidMessage);
        }
        Ok(Self { shared, tag })
    }

    /// Strictly decode the bounded wrapper and its shared v2 message.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let minimum = GROUP_ORIGIN_ENVELOPE_MAGIC.len() + 4 + GROUP_ORIGIN_TAG_LEN;
        if bytes.len() < minimum || !bytes.starts_with(&GROUP_ORIGIN_ENVELOPE_MAGIC) {
            return Err(CryptoError::InvalidMessage);
        }
        let shared_len =
            u32::from_le_bytes(bytes[4..8].try_into().expect("fixed origin wrapper header"))
                as usize;
        let expected = 8usize
            .checked_add(shared_len)
            .and_then(|value| value.checked_add(GROUP_ORIGIN_TAG_LEN))
            .ok_or(CryptoError::InvalidMessage)?;
        if shared_len == 0 || expected != bytes.len() {
            return Err(CryptoError::InvalidMessage);
        }
        let shared = GroupMessage::decode(&bytes[8..8 + shared_len])?;
        if shared.version != GROUP_MESSAGE_VERSION_ORIGIN {
            return Err(CryptoError::InvalidMessage);
        }
        let mut tag = [0u8; GROUP_ORIGIN_TAG_LEN];
        tag.copy_from_slice(&bytes[8 + shared_len..]);
        Ok(Self { shared, tag })
    }

    /// Encode the exact versioned recipient wrapper.
    pub fn encode(&self) -> Vec<u8> {
        let shared = self.shared.encode();
        let shared_len = u32::try_from(shared.len()).expect("group message is protocol bounded");
        let mut out = Vec::with_capacity(
            GROUP_ORIGIN_ENVELOPE_MAGIC.len() + 4 + shared.len() + self.tag.len(),
        );
        out.extend_from_slice(&GROUP_ORIGIN_ENVELOPE_MAGIC);
        out.extend_from_slice(&shared_len.to_le_bytes());
        out.extend_from_slice(&shared);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Verify the recipient tag in constant time without advancing a group
    /// sender chain.
    pub fn verify(&self, origin_key: &[u8; 32], context: &GroupOriginContext) -> Result<()> {
        if *origin_key == [0u8; 32] {
            return Err(CryptoError::InvalidKey);
        }
        let expected = group_origin_tag(origin_key, context, &self.shared.encode());
        if bool::from(expected.ct_eq(&self.tag)) {
            Ok(())
        } else {
            Err(CryptoError::MessageAuthentication)
        }
    }

    /// The shared ciphertext, identical across every recipient wrapper.
    pub fn shared(&self) -> &GroupMessage {
        &self.shared
    }

    /// Copy the fixed recipient tag for bounded local pending fan-out.
    pub fn tag(&self) -> [u8; GROUP_ORIGIN_TAG_LEN] {
        self.tag
    }
}

/// Compute the normative ADR-0029 HMAC for vectors and recipient wrappers.
pub fn group_origin_tag(
    origin_key: &[u8; 32],
    context: &GroupOriginContext,
    shared_group_ciphertext: &[u8],
) -> [u8; GROUP_ORIGIN_TAG_LEN] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(origin_key).expect("HMAC accepts every 32-byte key");
    mac.update(ORIGIN_DOMAIN);
    mac.update(&context.group_id);
    mac.update(&context.sender_account);
    mac.update(&context.sender_device);
    mac.update(&context.recipient_account);
    mac.update(&context.recipient_device);
    mac.update(&context.sender_chain_key_id);
    mac.update(&context.envelope_content_id);
    mac.update(
        &context
            .authenticated_retention
            .unwrap_or_default()
            .to_le_bytes(),
    );
    mac.update(&Sha256::digest(shared_group_ciphertext));
    mac.finalize().into_bytes().into()
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
        self.seal_versioned(
            hk,
            group_id,
            plaintext,
            None,
            GROUP_MESSAGE_VERSION_LEGACY,
            rng,
        )
    }

    /// Encrypt one padded plaintext with an event id hidden inside the v2
    /// sealed header. The result is still one shared ciphertext.
    pub fn seal_origin(
        &mut self,
        hk: &GroupHeaderKey,
        group_id: &[u8; 32],
        content_id: [u8; 16],
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> GroupMessage {
        self.seal_versioned(
            hk,
            group_id,
            plaintext,
            Some(content_id),
            GROUP_MESSAGE_VERSION_ORIGIN,
            rng,
        )
    }

    fn seal_versioned(
        &mut self,
        hk: &GroupHeaderKey,
        group_id: &[u8; 32],
        plaintext: &[u8],
        content_id: Option<[u8; 16]>,
        version: u8,
        rng: &mut impl CryptoRngCore,
    ) -> GroupMessage {
        let (next_ck, mk) = kdf_gck(&self.chain_key);

        let header_len = header_plain_len(version).expect("supported sender-key version");
        let mut hdr_plain = Zeroizing::new(vec![0u8; header_len]);
        hdr_plain[..16].copy_from_slice(&self.key_id);
        hdr_plain[16..20].copy_from_slice(&self.iteration.to_le_bytes());
        if let Some(content_id) = content_id {
            hdr_plain[20..36].copy_from_slice(&content_id);
        }
        let enc_header = util::aead_seal(&hk.0, &header_ad(version), hdr_plain.as_ref(), rng);

        let mut nonce = [0u8; util::NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let ad = payload_ad(group_id, version, &enc_header);
        let ct = util::aead_encrypt_with_nonce(&mk, &nonce, &ad, plaintext);
        Zeroizing::new(mk);

        self.chain_key = next_ck;
        self.iteration += 1;
        GroupMessage {
            version,
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
        let ad = payload_ad(group_id, msg.version, &msg.enc_header);

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
    fn origin_wrapper_binds_exact_recipient_before_chain_advance() {
        let (mut rng, hk, mut sender, mut receiver) = setup();
        let content_id = [8u8; 16];
        let shared = sender.seal_origin(&hk, &GID, content_id, b"origin", &mut rng);
        let header = shared.open_header_details(&hk).unwrap();
        assert_eq!(header.content_id, Some(content_id));
        let context = GroupOriginContext {
            group_id: GID,
            sender_account: [1; 32],
            sender_device: [2; 32],
            recipient_account: [3; 32],
            recipient_device: [4; 32],
            sender_chain_key_id: header.key_id,
            envelope_content_id: content_id,
            authenticated_retention: None,
        };
        let key = [9u8; 32];
        let wrapped = GroupOriginEnvelope::seal(shared.clone(), &key, &context).unwrap();
        let encoded = wrapped.encode();
        let decoded = GroupOriginEnvelope::decode(&encoded).unwrap();
        decoded.verify(&key, &context).unwrap();

        let mut wrong_contexts = Vec::new();
        let mut wrong = context;
        wrong.group_id = [5; 32];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.sender_account = [5; 32];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.sender_device = [5; 32];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.recipient_account = [5; 32];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.recipient_device = [5; 32];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.sender_chain_key_id = [5; 16];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.envelope_content_id = [5; 16];
        wrong_contexts.push(wrong);
        let mut wrong = context;
        wrong.authenticated_retention = Some(3_600);
        wrong_contexts.push(wrong);
        for wrong in wrong_contexts {
            assert_eq!(
                decoded.verify(&key, &wrong),
                Err(CryptoError::MessageAuthentication)
            );
        }
        assert_eq!(
            decoded.verify(&[8; 32], &context),
            Err(CryptoError::MessageAuthentication)
        );

        let mut bad_tag = encoded.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        assert_eq!(
            GroupOriginEnvelope::decode(&bad_tag)
                .unwrap()
                .verify(&key, &context),
            Err(CryptoError::MessageAuthentication)
        );
        let mut bad_shared = encoded.clone();
        bad_shared[8 + shared.enc_header.len() + shared.nonce.len()] ^= 1;
        assert_eq!(
            GroupOriginEnvelope::decode(&bad_shared)
                .unwrap()
                .verify(&key, &context),
            Err(CryptoError::MessageAuthentication)
        );

        // Every rejected wrapper left the receiving chain untouched.
        assert_eq!(
            receiver
                .open(&GID, decoded.shared(), header.iteration, NOW)
                .unwrap(),
            b"origin"
        );
    }

    #[test]
    fn origin_tag_has_a_fixed_width_known_answer() {
        let context = GroupOriginContext {
            group_id: [1; 32],
            sender_account: [2; 32],
            sender_device: [3; 32],
            recipient_account: [4; 32],
            recipient_device: [5; 32],
            sender_chain_key_id: [6; 16],
            envelope_content_id: [7; 16],
            authenticated_retention: Some(3_600),
        };
        assert_eq!(
            hex::encode(group_origin_tag(&[0x0b; 32], &context, &[0xaa, 0xbb])),
            "3e9fd722009f51ca36b46529718b0b97600af905a5c8b78aa1ab08c378029982"
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
