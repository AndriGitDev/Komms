//! Canonical signed group-authority state (ADR-0023).

use alloc::{boxed::Box, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::{ProtocolError, Result};

/// First supported authority payload version.
pub const GROUP_AUTHORITY_VERSION: u8 = 1;
/// Maximum exact UTF-8 group name.
pub const MAX_GROUP_NAME_LEN: usize = 256;
/// Maximum encoded public identity per member.
pub const MAX_GROUP_MEMBER_IDENTITY_LEN: usize = 512;
/// Maximum roster and ownership-chain length.
pub const MAX_GROUP_AUTHORITY_MEMBERS: usize = 64;

const OP_STATE: u8 = 1;
const HEADER_LEN: usize = 4 + 32 + 8 + 8 + 32 + 32 + 32 + 16 + 2 + 1 + 1 + 32;
const MEMBER_HEADER_LEN: usize = 35;
const TRANSFER_LEN: usize = 160;

/// Fixed C6 role vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GroupRole {
    /// The one serialized authority root.
    Owner = 1,
    /// May submit bounded generation-bound administration requests.
    Admin = 2,
    /// Ordinary participant.
    Member = 3,
}

impl GroupRole {
    fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Owner),
            2 => Some(Self::Admin),
            3 => Some(Self::Member),
            _ => None,
        }
    }
}

/// One roster identity and role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAuthorityMember {
    /// Ed25519 peer identity.
    pub peer: [u8; 32],
    /// Full encoded public identity.
    pub identity: Vec<u8>,
    /// Fixed role.
    pub role: GroupRole,
}

/// One certificate in the original-owner to current-owner chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTransferCertificate {
    /// Group being transferred.
    pub group: [u8; 32],
    /// Positive next owner epoch.
    pub epoch: u64,
    /// Exact authority generation which enacts this transfer.
    pub generation: u64,
    /// Winning authority state immediately before this transfer.
    pub prior_state_id: [u8; 16],
    /// Authority signing the transfer.
    pub from_owner: [u8; 32],
    /// Existing member receiving ownership.
    pub to_owner: [u8; 32],
    /// Domain-separated Ed25519 signature by `from_owner`.
    pub signature: [u8; 64],
}

/// Complete authority-signed public authority state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGroupAuthorityState {
    /// Group id.
    pub group: [u8; 32],
    /// Monotonic state generation.
    pub generation: u64,
    /// Ownership-transfer epoch.
    pub owner_epoch: u64,
    /// Immutable creator/root owner.
    pub original_owner: [u8; 32],
    /// Current owner.
    pub owner: [u8; 32],
    /// Identity authorizing this state; the prior owner for a transfer state.
    pub signer: [u8; 32],
    /// Prior winning authority event id; zero for initial upgrade/invite.
    pub prior_state_id: [u8; 16],
    /// Exact group name.
    pub name: String,
    /// Sorted full roster with exactly one owner.
    pub members: Vec<GroupAuthorityMember>,
    /// SHA-256 of the current group secret.
    pub secret_hash: [u8; 32],
    /// Ordered ownership-transfer chain.
    pub transfers: Vec<OwnerTransferCertificate>,
    /// Signature by `signer` over canonical state bytes.
    pub signature: [u8; 64],
}

/// Total authority-payload classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedGroupAuthority {
    /// Canonical supported state.
    State(Box<SignedGroupAuthorityState>),
    /// Future payload version.
    Unsupported,
    /// Malformed/noncanonical input.
    Malformed,
}

/// Canonical bytes signed by one owner-transfer certificate.
pub fn owner_transfer_signing_bytes(
    group: [u8; 32],
    epoch: u64,
    generation: u64,
    prior_state_id: [u8; 16],
    from_owner: [u8; 32],
    to_owner: [u8; 32],
) -> Result<Vec<u8>> {
    if epoch == 0 || generation == 0 || prior_state_id == [0; 16] || from_owner == to_owner {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&group);
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&prior_state_id);
    out.extend_from_slice(&from_owner);
    out.extend_from_slice(&to_owner);
    Ok(out)
}

/// Canonical state bytes covered by the exact authorizing signer's signature.
pub fn group_authority_state_signing_bytes(state: &SignedGroupAuthorityState) -> Result<Vec<u8>> {
    validate_state(state)?;
    let members_len = state.members.iter().try_fold(0usize, |sum, member| {
        sum.checked_add(MEMBER_HEADER_LEN + member.identity.len())
            .ok_or(ProtocolError::TooLarge)
    })?;
    let capacity = HEADER_LEN
        .checked_add(state.name.len())
        .and_then(|n| n.checked_add(members_len))
        .and_then(|n| n.checked_add(state.transfers.len() * TRANSFER_LEN))
        .ok_or(ProtocolError::TooLarge)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&[GROUP_AUTHORITY_VERSION, OP_STATE, 0, 0]);
    out.extend_from_slice(&state.group);
    out.extend_from_slice(&state.generation.to_le_bytes());
    out.extend_from_slice(&state.owner_epoch.to_le_bytes());
    out.extend_from_slice(&state.original_owner);
    out.extend_from_slice(&state.owner);
    out.extend_from_slice(&state.signer);
    out.extend_from_slice(&state.prior_state_id);
    out.extend_from_slice(&(state.name.len() as u16).to_le_bytes());
    out.push(state.members.len() as u8);
    out.push(state.transfers.len() as u8);
    out.extend_from_slice(&state.secret_hash);
    out.extend_from_slice(state.name.as_bytes());
    for member in &state.members {
        out.extend_from_slice(&member.peer);
        out.push(member.role as u8);
        out.extend_from_slice(&(member.identity.len() as u16).to_le_bytes());
        out.extend_from_slice(&member.identity);
    }
    for transfer in &state.transfers {
        out.extend_from_slice(&transfer.epoch.to_le_bytes());
        out.extend_from_slice(&transfer.generation.to_le_bytes());
        out.extend_from_slice(&transfer.prior_state_id);
        out.extend_from_slice(&transfer.from_owner);
        out.extend_from_slice(&transfer.to_owner);
        out.extend_from_slice(&transfer.signature);
    }
    Ok(out)
}

/// Encode one canonical signed authority state.
pub fn encode_group_authority_state(state: &SignedGroupAuthorityState) -> Result<Vec<u8>> {
    let mut out = group_authority_state_signing_bytes(state)?;
    out.extend_from_slice(&state.signature);
    Ok(out)
}

/// Decode strictly with explicit bounds and trailing-byte rejection.
pub fn decode_group_authority(bytes: &[u8]) -> DecodedGroupAuthority {
    if bytes.len() < 4 {
        return DecodedGroupAuthority::Malformed;
    }
    if bytes[0] != GROUP_AUTHORITY_VERSION {
        return DecodedGroupAuthority::Unsupported;
    }
    if bytes[1] != OP_STATE || bytes[2] != 0 || bytes[3] != 0 || bytes.len() < HEADER_LEN + 64 {
        return DecodedGroupAuthority::Malformed;
    }
    decode_state(bytes)
        .map(Box::new)
        .map(DecodedGroupAuthority::State)
        .unwrap_or(DecodedGroupAuthority::Malformed)
}

fn decode_state(bytes: &[u8]) -> Result<SignedGroupAuthorityState> {
    let mut at = 4;
    let group = array(take(bytes, &mut at, 32)?)?;
    let generation = u64::from_le_bytes(array(take(bytes, &mut at, 8)?)?);
    let owner_epoch = u64::from_le_bytes(array(take(bytes, &mut at, 8)?)?);
    let original_owner = array(take(bytes, &mut at, 32)?)?;
    let owner = array(take(bytes, &mut at, 32)?)?;
    let signer = array(take(bytes, &mut at, 32)?)?;
    let prior_state_id = array(take(bytes, &mut at, 16)?)?;
    let name_len = u16::from_le_bytes(array(take(bytes, &mut at, 2)?)?) as usize;
    let member_count = take(bytes, &mut at, 1)?[0] as usize;
    let transfer_count = take(bytes, &mut at, 1)?[0] as usize;
    let secret_hash = array(take(bytes, &mut at, 32)?)?;
    if name_len == 0
        || name_len > MAX_GROUP_NAME_LEN
        || member_count == 0
        || member_count > MAX_GROUP_AUTHORITY_MEMBERS
        || transfer_count > MAX_GROUP_AUTHORITY_MEMBERS
    {
        return Err(ProtocolError::Malformed);
    }
    let name = core::str::from_utf8(take(bytes, &mut at, name_len)?)
        .map_err(|_| ProtocolError::Malformed)?
        .into();
    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        let peer = array(take(bytes, &mut at, 32)?)?;
        let role =
            GroupRole::decode(take(bytes, &mut at, 1)?[0]).ok_or(ProtocolError::Malformed)?;
        let identity_len = u16::from_le_bytes(array(take(bytes, &mut at, 2)?)?) as usize;
        if identity_len == 0 || identity_len > MAX_GROUP_MEMBER_IDENTITY_LEN {
            return Err(ProtocolError::Malformed);
        }
        members.push(GroupAuthorityMember {
            peer,
            role,
            identity: take(bytes, &mut at, identity_len)?.to_vec(),
        });
    }
    let mut transfers = Vec::with_capacity(transfer_count);
    for _ in 0..transfer_count {
        transfers.push(OwnerTransferCertificate {
            group,
            epoch: u64::from_le_bytes(array(take(bytes, &mut at, 8)?)?),
            generation: u64::from_le_bytes(array(take(bytes, &mut at, 8)?)?),
            prior_state_id: array(take(bytes, &mut at, 16)?)?,
            from_owner: array(take(bytes, &mut at, 32)?)?,
            to_owner: array(take(bytes, &mut at, 32)?)?,
            signature: array(take(bytes, &mut at, 64)?)?,
        });
    }
    let signature = array(take(bytes, &mut at, 64)?)?;
    if at != bytes.len() {
        return Err(ProtocolError::Malformed);
    }
    let state = SignedGroupAuthorityState {
        group,
        generation,
        owner_epoch,
        original_owner,
        owner,
        signer,
        prior_state_id,
        name,
        members,
        secret_hash,
        transfers,
        signature,
    };
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &SignedGroupAuthorityState) -> Result<()> {
    if state.generation == 0
        || state.name.is_empty()
        || state.name.len() > MAX_GROUP_NAME_LEN
        || state.members.is_empty()
        || state.members.len() > MAX_GROUP_AUTHORITY_MEMBERS
        || state.transfers.len() > MAX_GROUP_AUTHORITY_MEMBERS
        || state.owner_epoch as usize != state.transfers.len()
    {
        return Err(ProtocolError::Malformed);
    }
    let mut previous = None;
    let mut owner_count = 0;
    for member in &state.members {
        if member.identity.is_empty() || member.identity.len() > MAX_GROUP_MEMBER_IDENTITY_LEN {
            return Err(ProtocolError::Malformed);
        }
        if previous.is_some_and(|peer| peer >= member.peer) {
            return Err(ProtocolError::Malformed);
        }
        previous = Some(member.peer);
        if member.role == GroupRole::Owner {
            owner_count += 1;
            if member.peer != state.owner {
                return Err(ProtocolError::Malformed);
            }
        }
    }
    if owner_count != 1 {
        return Err(ProtocolError::Malformed);
    }
    let mut expected_owner = state.original_owner;
    let mut previous_transfer_generation = 0;
    for (index, transfer) in state.transfers.iter().enumerate() {
        if transfer.group != state.group
            || transfer.epoch != index as u64 + 1
            || transfer.generation <= previous_transfer_generation
            || transfer.generation > state.generation
            || transfer.prior_state_id == [0; 16]
            || transfer.from_owner != expected_owner
            || transfer.from_owner == transfer.to_owner
        {
            return Err(ProtocolError::Malformed);
        }
        previous_transfer_generation = transfer.generation;
        expected_owner = transfer.to_owner;
    }
    if expected_owner != state.owner {
        return Err(ProtocolError::Malformed);
    }
    if let Some(transfer) = state.transfers.last() {
        if state.signer == state.owner {
            if state.generation <= transfer.generation {
                return Err(ProtocolError::Malformed);
            }
        } else if transfer.from_owner != state.signer
            || transfer.to_owner != state.owner
            || transfer.generation != state.generation
            || transfer.prior_state_id != state.prior_state_id
        {
            return Err(ProtocolError::Malformed);
        }
    } else if state.signer != state.owner {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = at.checked_add(len).ok_or(ProtocolError::Malformed)?;
    let value = bytes.get(*at..end).ok_or(ProtocolError::Malformed)?;
    *at = end;
    Ok(value)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| ProtocolError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn state() -> SignedGroupAuthorityState {
        SignedGroupAuthorityState {
            group: [1; 32],
            generation: 7,
            owner_epoch: 1,
            original_owner: [2; 32],
            owner: [3; 32],
            signer: [2; 32],
            prior_state_id: [4; 16],
            name: "Exact 🧭 group".into(),
            members: vec![
                GroupAuthorityMember {
                    peer: [3; 32],
                    identity: vec![5; 128],
                    role: GroupRole::Owner,
                },
                GroupAuthorityMember {
                    peer: [6; 32],
                    identity: vec![7; 128],
                    role: GroupRole::Admin,
                },
            ],
            secret_hash: [8; 32],
            transfers: vec![OwnerTransferCertificate {
                group: [1; 32],
                epoch: 1,
                generation: 7,
                prior_state_id: [4; 16],
                from_owner: [2; 32],
                to_owner: [3; 32],
                signature: [9; 64],
            }],
            signature: [10; 64],
        }
    }

    #[test]
    fn authority_state_round_trips_exactly() {
        let expected = state();
        let encoded = encode_group_authority_state(&expected).unwrap();
        assert_eq!(
            decode_group_authority(&encoded),
            DecodedGroupAuthority::State(Box::new(expected))
        );
    }

    #[test]
    fn noncanonical_state_and_trailing_bytes_fail_closed() {
        let mut invalid = state();
        invalid.members[0].role = GroupRole::Admin;
        assert!(encode_group_authority_state(&invalid).is_err());
        let mut encoded = encode_group_authority_state(&state()).unwrap();
        encoded.push(0);
        assert_eq!(
            decode_group_authority(&encoded),
            DecodedGroupAuthority::Malformed
        );
    }

    #[test]
    fn prior_owner_can_sign_only_the_exact_transfer_state() {
        let mut later = state();
        later.generation += 1;
        later.prior_state_id = [11; 16];
        assert!(encode_group_authority_state(&later).is_err());

        later.signer = later.owner;
        assert!(encode_group_authority_state(&later).is_ok());

        let mut premature_new_owner = state();
        premature_new_owner.signer = premature_new_owner.owner;
        assert!(encode_group_authority_state(&premature_new_owner).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
            let _ = decode_group_authority(&bytes);
        }
    }
}
