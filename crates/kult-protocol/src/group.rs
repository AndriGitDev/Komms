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

/// Maximum signed admin request ids retained per group before compaction.
pub const MAX_GROUP_ADMIN_REQUESTS: usize = 4_096;

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

/// One C6 self-contained signed-state announce plus the sender's chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupAuthorityAnnounce {
    /// Group id.
    pub group: [u8; 32],
    /// Winning authority event id.
    pub state_id: [u8; 16],
    /// Canonical signed authority payload (kind 7 payload only).
    pub state_payload: Vec<u8>,
    /// Current secret whose SHA-256 is bound by `state_payload`.
    pub secret: [u8; 32],
    /// Announcing member's chain id.
    pub key_id: [u8; 16],
    /// Frozen chain key snapshot.
    pub chain_key: [u8; 32],
    /// First readable iteration.
    pub iteration: u32,
}

/// Bounded operation an admin may request from the current owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum GroupAdminAction {
    /// Invite an exact identified peer.
    Invite(GroupMemberInfo),
    /// Remove an ordinary member (never owner/admin).
    Remove {
        /// Ordinary member to exclude.
        peer: [u8; 32],
    },
    /// Replace the exact group name.
    Rename {
        /// Exact replacement group name.
        name: String,
    },
    /// Close any poll through an owner-signed moderation event.
    ModeratePoll {
        /// Poll creator.
        poll_author: [u8; 32],
        /// Stable poll id.
        poll_id: [u8; 16],
    },
}

/// One identity-signed, exact-generation admin request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupAdminRequest {
    /// Random deduplication id.
    pub request_id: [u8; 16],
    /// Target group.
    pub group: [u8; 32],
    /// Exact authority generation at authorship.
    pub base_generation: u64,
    /// Fixed requested operation.
    pub action: GroupAdminAction,
    /// Domain-separated requester signature (exactly 64 bytes).
    pub signature: Vec<u8>,
}

/// Owner-authenticated terminal result for one admin request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct GroupAdminResult {
    /// Target group.
    pub group: [u8; 32],
    /// Exact request id.
    pub request_id: [u8; 16],
    /// Whether the owner committed the request.
    pub accepted: bool,
    /// Authority generation after terminal processing.
    pub generation: u64,
    /// Winning state event id when accepted.
    pub state_id: Option<[u8; 16]>,
    /// Stable rejection reason: 0 accepted, 1 stale, 2 unauthorized, 3 invalid.
    pub reason: u8,
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
    /// C6 signed authority state plus an entitled sender-chain snapshot.
    AuthorityAnnounce(GroupAuthorityAnnounce),
    /// C6 signed request from an admin to the current owner.
    AdminRequest(GroupAdminRequest),
    /// Pairwise-authenticated terminal owner response.
    AdminResult(GroupAdminResult),
    /// Self-contained signed removal notice; deliberately carries no secret.
    AuthorityRemove {
        /// Group id.
        group: [u8; 32],
        /// Winning authority event id.
        state_id: [u8; 16],
        /// Canonical signed authority payload proving exclusion.
        state_payload: Vec<u8>,
    },
}

impl GroupControlPayload {
    /// Postcard-encode (pad with [`crate::pad`] before encrypting).
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("group control serialization cannot fail")
    }

    /// Parse a decrypted group control payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload: Self = postcard::from_bytes(bytes).map_err(|_| ProtocolError::Malformed)?;
        match &payload {
            Self::AuthorityAnnounce(value) => {
                if value.state_payload.len() > crate::MAX_CONTENT_PAYLOAD_LEN {
                    return Err(ProtocolError::TooLarge);
                }
            }
            Self::AdminRequest(value) => {
                if value.signature.len() != 64 {
                    return Err(ProtocolError::Malformed);
                }
                let _ = group_admin_request_signing_bytes(value)?;
            }
            Self::AdminResult(value) => {
                if value.reason > 3 || value.accepted != (value.reason == 0) {
                    return Err(ProtocolError::Malformed);
                }
            }
            Self::AuthorityRemove { state_payload, .. }
                if state_payload.len() > crate::MAX_CONTENT_PAYLOAD_LEN =>
            {
                return Err(ProtocolError::TooLarge);
            }
            _ => {}
        }
        Ok(payload)
    }
}

/// Canonical bytes covered by an admin request's identity signature.
pub fn group_admin_request_signing_bytes(request: &GroupAdminRequest) -> Result<Vec<u8>> {
    if request.base_generation == 0 {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&request.request_id);
    out.extend_from_slice(&request.group);
    out.extend_from_slice(&request.base_generation.to_le_bytes());
    match &request.action {
        GroupAdminAction::Invite(member) => {
            if member.identity.is_empty()
                || member.identity.len() > crate::MAX_GROUP_MEMBER_IDENTITY_LEN
            {
                return Err(ProtocolError::Malformed);
            }
            out.push(1);
            out.extend_from_slice(&member.peer);
            out.extend_from_slice(&(member.identity.len() as u16).to_le_bytes());
            out.extend_from_slice(&member.identity);
        }
        GroupAdminAction::Remove { peer } => {
            out.push(2);
            out.extend_from_slice(peer);
        }
        GroupAdminAction::Rename { name } => {
            if name.is_empty() || name.len() > crate::MAX_GROUP_NAME_LEN {
                return Err(ProtocolError::Malformed);
            }
            out.push(3);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        GroupAdminAction::ModeratePoll {
            poll_author,
            poll_id,
        } => {
            out.push(4);
            out.extend_from_slice(poll_author);
            out.extend_from_slice(poll_id);
        }
    }
    Ok(out)
}
