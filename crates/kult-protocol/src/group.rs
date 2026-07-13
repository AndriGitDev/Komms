//! Group control payloads (ADR-0012): the end-to-end encrypted plumbing of
//! sender-key groups. A `GroupControlPayload` is postcard-encoded, padded,
//! and travels as the *plaintext* of a pairwise ratchet message inside an
//! envelope of kind `GroupControl` — intermediaries see only another sealed
//! envelope.
//!
//! One shape carries everything: an **announce** bundles the group state
//! (roster, secret, generation — honored only when the sender is the
//! group's creator) with the sender's current chain snapshot (honored from
//! any member), so invites, membership updates, re-keys, rotations, and
//! redistributions are all the same message and any one of them is enough
//! context to start decrypting its sender.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ProtocolError, Result};

/// A roster entry: the member's peer id plus their encoded public identity
/// (opaque bytes here; the runtime decodes it to create contact stubs and
/// resolve prekey bundles for members it has never met).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct GroupMemberInfo {
    /// The member's Ed25519 identity key bytes.
    pub peer: [u8; 32],
    /// Their full encoded public identity (may be empty in non-creator
    /// announces, which never carry roster authority anyway).
    pub identity: Vec<u8>,
}

/// Group state + the sender's current sender key, in one message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupAnnounce {
    /// The group id (random 32 bytes, minted at creation).
    pub group: [u8; 32],
    /// Display name (creator-controlled).
    pub name: String,
    /// The managing member: the only peer whose roster/secret/generation
    /// are honored.
    pub creator: [u8; 32],
    /// Full roster including the creator. Ignored unless the announce's
    /// pairwise-authenticated sender *is* the creator.
    pub members: Vec<GroupMemberInfo>,
    /// The group secret (header-key input). Creator-controlled.
    pub secret: [u8; 32],
    /// Monotonic roster generation — stale announces never regress
    /// membership.
    pub generation: u64,
    /// The sender's chain id.
    pub key_id: [u8; 16],
    /// The sender's chain key at `iteration` (a snapshot frozen at
    /// entitlement time — receivers read from here on, never earlier).
    pub chain_key: [u8; 32],
    /// First iteration readable with `chain_key`.
    pub iteration: u32,
}

/// Group control content (always encrypted end-to-end before transport).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum GroupControlPayload {
    /// Group state + sender key (see [`GroupAnnounce`]).
    Announce(GroupAnnounce),
    /// The sender is leaving this group.
    Leave {
        /// The group id.
        group: [u8; 32],
    },
    /// The sender — honored only when they are the group's creator —
    /// removes the *receiver* from the group. Deliberately carries nothing
    /// else: the re-keyed group state must never reach the removed member.
    Remove {
        /// The group id.
        group: [u8; 32],
    },
}

impl GroupControlPayload {
    /// Postcard-encode (pad with [`crate::pad`] before encrypting).
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("group control serialization cannot fail")
    }

    /// Parse a decrypted group control payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| ProtocolError::Malformed)
    }
}
