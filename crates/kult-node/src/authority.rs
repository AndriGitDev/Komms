//! Signed owner-serialized group authority (ADR-0023).

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

use kult_crypto::{
    verify_group_admin_request_signature, verify_group_authority_state_signature,
    verify_group_owner_transfer_signature, GroupReceiverChain, GroupSenderChain, IdentityPublic,
};
use kult_protocol::{
    decode_group_authority, encode_group_authority, encode_group_authority_state,
    group_admin_request_signing_bytes, group_authority_state_signing_bytes,
    owner_transfer_signing_bytes, DecodedGroupAuthority, GroupAdminAction, GroupAdminRequest,
    GroupAdminResult, GroupAuthorityAnnounce, GroupAuthorityMember, GroupControlPayload,
    GroupMemberInfo, GroupRole, OwnerTransferCertificate, SignedGroupAuthorityState,
    CONTENT_KIND_GROUP_AUTHORITY, MAX_GROUP_ADMIN_REQUESTS, MAX_GROUP_NAME_LEN,
};
use kult_store::{GroupAuthorityRecord, GroupMember, GroupRecord};

use crate::{Event, GroupAuthorityInfo, GroupMemberRoleInfo, Node, NodeError, Result};

const ID_RETRY_LIMIT: usize = 16;

impl Node {
    /// Current render-safe C6 authority, synthesizing legacy creator/member roles.
    pub fn group_authority(&self, group: &[u8; 32]) -> Result<GroupAuthorityInfo> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if let Some(stored) = self.store.get_group_authority(group)? {
            let state = decode_stored(&stored)?;
            let members = state
                .members
                .iter()
                .map(|member| GroupMemberRoleInfo {
                    peer: member.peer,
                    role: member.role,
                })
                .collect::<Vec<_>>();
            return Ok(GroupAuthorityInfo {
                group: *group,
                signed: true,
                original_owner: state.original_owner,
                owner: state.owner,
                owner_epoch: state.owner_epoch,
                generation: state.generation,
                my_role: members
                    .iter()
                    .find(|member| member.peer == me)
                    .map(|m| m.role),
                members,
            });
        }
        let mut members = rec
            .members
            .iter()
            .map(|member| GroupMemberRoleInfo {
                peer: member.peer,
                role: if member.peer == rec.creator {
                    GroupRole::Owner
                } else {
                    GroupRole::Member
                },
            })
            .collect::<Vec<_>>();
        members.sort_unstable_by_key(|member| member.peer);
        Ok(GroupAuthorityInfo {
            group: *group,
            signed: false,
            original_owner: rec.creator,
            owner: rec.creator,
            owner_epoch: 0,
            generation: rec.generation,
            my_role: members
                .iter()
                .find(|member| member.peer == me)
                .map(|m| m.role),
            members,
        })
    }

    /// Capability-gated upgrade from legacy creator authority to signed C6 state.
    pub fn group_upgrade_authority(
        &mut self,
        group: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if let Some(authority) = self.store.get_group_authority(group)? {
            return Ok(authority.state_id);
        }
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if rec.creator != me {
            return Err(NodeError::NotGroupOwner);
        }
        self.ensure_group_role_support(&rec)?;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let state = SignedGroupAuthorityState {
            group: *group,
            generation: rec
                .generation
                .checked_add(1)
                .ok_or(NodeError::InvalidGroupAuthority)?,
            owner_epoch: 0,
            original_owner: me,
            owner: me,
            signer: me,
            prior_state_id: [0; 16],
            name: rec.name.clone(),
            members: authority_members(&rec, me),
            secret_hash: hash_secret(&secret),
            transfers: Vec::new(),
            signature: [0; 64],
        };
        self.commit_authority_state(state, secret, now, rng)
    }

    /// Owner-only exact group rename; admins use a signed request.
    pub fn group_rename(
        &mut self,
        group: &[u8; 32],
        name: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if name.is_empty() || name.len() > MAX_GROUP_NAME_LEN {
            return Err(NodeError::InvalidGroupAuthority);
        }
        self.ensure_signed_authority(group, now, rng)?;
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        let me = self.identity.public().ed;
        if state.owner != me {
            if state
                .members
                .iter()
                .any(|member| member.peer == me && member.role == GroupRole::Admin)
            {
                return self.queue_admin_request(
                    &state,
                    GroupAdminAction::Rename {
                        name: name.to_owned(),
                    },
                    now,
                    rng,
                );
            }
            return Err(NodeError::NotGroupOwner);
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(NodeError::InvalidGroupAuthority)?;
        state.prior_state_id = stored.state_id;
        state.name = name.to_owned();
        state.signer = state.owner;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        state.secret_hash = hash_secret(&secret);
        state.signature = [0; 64];
        self.commit_authority_state(state, secret, now, rng)
    }

    /// Owner-only grant/revoke of the fixed admin role.
    pub fn group_set_role(
        &mut self,
        group: &[u8; 32],
        peer: [u8; 32],
        role: GroupRole,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if role == GroupRole::Owner {
            return Err(NodeError::InvalidGroupRole);
        }
        self.ensure_signed_authority(group, now, rng)?;
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        self.require_owner(&state)?;
        if peer == state.owner {
            return Err(NodeError::LastGroupOwner);
        }
        let member = state
            .members
            .iter_mut()
            .find(|member| member.peer == peer)
            .ok_or(NodeError::UnknownPeer)?;
        if member.role == role {
            return Ok(stored.state_id);
        }
        member.role = role;
        state.signer = state.owner;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(NodeError::InvalidGroupAuthority)?;
        state.prior_state_id = stored.state_id;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        state.secret_hash = hash_secret(&secret);
        state.signature = [0; 64];
        self.commit_authority_state(state, secret, now, rng)
    }

    /// Owner-only transfer to an existing member; the prior owner becomes admin.
    pub fn group_transfer_owner(
        &mut self,
        group: &[u8; 32],
        new_owner: [u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.ensure_signed_authority(group, now, rng)?;
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        self.require_owner(&state)?;
        if new_owner == state.owner || !state.members.iter().any(|member| member.peer == new_owner)
        {
            return Err(NodeError::InvalidGroupRole);
        }
        let epoch = state
            .owner_epoch
            .checked_add(1)
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let transfer_bytes = owner_transfer_signing_bytes(
            *group,
            epoch,
            generation,
            stored.state_id,
            state.owner,
            new_owner,
        )
        .map_err(|_| NodeError::InvalidGroupAuthority)?;
        state.transfers.push(OwnerTransferCertificate {
            group: *group,
            epoch,
            generation,
            prior_state_id: stored.state_id,
            from_owner: state.owner,
            to_owner: new_owner,
            signature: self.identity.sign_group_owner_transfer(&transfer_bytes),
        });
        for member in &mut state.members {
            if member.peer == state.owner {
                member.role = GroupRole::Admin;
            } else if member.peer == new_owner {
                member.role = GroupRole::Owner;
            }
        }
        state.owner = new_owner;
        state.signer = self.identity.public().ed;
        state.owner_epoch = epoch;
        state.generation = generation;
        state.prior_state_id = stored.state_id;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        state.secret_hash = hash_secret(&secret);
        // The transfer state itself is still authorized by the old owner.
        state.signature = [0; 64];
        self.commit_authority_state_signed_by(state, secret, now, rng, self.identity.public().ed)
    }

    pub(crate) fn group_authority_add_member(
        &mut self,
        group: &[u8; 32],
        member: GroupMember,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.ensure_signed_authority(group, now, rng)?;
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        let me = self.identity.public().ed;
        if state.owner != me {
            if state
                .members
                .iter()
                .any(|entry| entry.peer == me && entry.role == GroupRole::Admin)
            {
                return self.queue_admin_request(
                    &state,
                    GroupAdminAction::Invite(GroupMemberInfo {
                        peer: member.peer,
                        identity: member.identity,
                    }),
                    now,
                    rng,
                );
            }
            return Err(NodeError::NotGroupOwner);
        }
        if state.members.iter().any(|entry| entry.peer == member.peer) {
            return Ok(stored.state_id);
        }
        state.members.push(GroupAuthorityMember {
            peer: member.peer,
            identity: member.identity,
            role: GroupRole::Member,
        });
        state.members.sort_unstable_by_key(|entry| entry.peer);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        prepare_next_state(&mut state, stored.state_id, &secret)?;
        self.commit_authority_state(state, secret, now, rng)
    }

    pub(crate) fn group_authority_remove_member(
        &mut self,
        group: &[u8; 32],
        peer: [u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.ensure_signed_authority(group, now, rng)?;
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        let me = self.identity.public().ed;
        let target_role = state
            .members
            .iter()
            .find(|entry| entry.peer == peer)
            .map(|entry| entry.role)
            .ok_or(NodeError::UnknownPeer)?;
        if peer == state.owner {
            return Err(NodeError::LastGroupOwner);
        }
        if state.owner != me {
            let admin = state
                .members
                .iter()
                .any(|entry| entry.peer == me && entry.role == GroupRole::Admin);
            if admin && target_role == GroupRole::Member {
                return self.queue_admin_request(
                    &state,
                    GroupAdminAction::Remove { peer },
                    now,
                    rng,
                );
            }
            return Err(NodeError::NotGroupOwner);
        }
        state.members.retain(|entry| entry.peer != peer);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        prepare_next_state(&mut state, stored.state_id, &secret)?;
        let state_id = self.commit_authority_state(state, secret, now, rng)?;
        let authority = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::CorruptState)?;
        self.queue_group_control(
            &peer,
            &GroupControlPayload::AuthorityRemove {
                group: *group,
                state_id,
                state_payload: authority.state_payload,
            },
            now,
            rng,
        )?;
        Ok(state_id)
    }

    pub(crate) fn queue_admin_action(
        &mut self,
        group: &[u8; 32],
        action: GroupAdminAction,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let state = decode_stored(&stored)?;
        self.queue_admin_request(&state, action, now, rng)
    }

    fn queue_admin_request(
        &mut self,
        state: &SignedGroupAuthorityState,
        action: GroupAdminAction,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let consumed = self
            .store
            .get_group_authority(&state.group)?
            .map(|record| record.consumed_requests)
            .unwrap_or_default();
        let request_id = (0..ID_RETRY_LIMIT)
            .find_map(|_| {
                let mut candidate = [0u8; 16];
                rng.fill_bytes(&mut candidate);
                (!consumed.contains(&candidate)).then_some(candidate)
            })
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut request = GroupAdminRequest {
            request_id,
            group: state.group,
            base_generation: state.generation,
            action,
            signature: Vec::new(),
        };
        let signing = group_admin_request_signing_bytes(&request)
            .map_err(|_| NodeError::InvalidGroupAuthority)?;
        request.signature = self.identity.sign_group_admin_request(&signing).to_vec();
        self.queue_group_control(
            &state.owner,
            &GroupControlPayload::AdminRequest(request),
            now,
            rng,
        )?;
        Ok(request_id)
    }

    pub(crate) fn ensure_signed_authority(
        &mut self,
        group: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if self.store.get_group_authority(group)?.is_none() {
            self.group_upgrade_authority(group, now, rng)?;
        }
        Ok(())
    }

    fn require_owner(&self, state: &SignedGroupAuthorityState) -> Result<()> {
        if state.owner != self.identity.public().ed {
            return Err(NodeError::NotGroupOwner);
        }
        Ok(())
    }

    pub(crate) fn advance_authority(
        &mut self,
        group: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let stored = self
            .store
            .get_group_authority(group)?
            .ok_or(NodeError::InvalidGroupAuthority)?;
        let mut state = decode_stored(&stored)?;
        self.require_owner(&state)?;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        prepare_next_state(&mut state, stored.state_id, &secret)?;
        self.commit_authority_state(state, secret, now, rng)
    }

    fn ensure_group_role_support(&self, rec: &GroupRecord) -> Result<()> {
        let me = self.identity.public().ed;
        for peer in rec
            .members
            .iter()
            .map(|member| member.peer)
            .filter(|peer| *peer != me)
        {
            if !self.peer_supports_kind(&peer, CONTENT_KIND_GROUP_AUTHORITY)? {
                return Err(NodeError::GroupRolesUnsupported);
            }
        }
        Ok(())
    }

    fn commit_authority_state(
        &mut self,
        state: SignedGroupAuthorityState,
        secret: [u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let signer = state.signer;
        self.commit_authority_state_signed_by(state, secret, now, rng, signer)
    }

    fn commit_authority_state_signed_by(
        &mut self,
        mut state: SignedGroupAuthorityState,
        secret: [u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
        signer: [u8; 32],
    ) -> Result<[u8; 16]> {
        if signer != self.identity.public().ed {
            return Err(NodeError::NotGroupOwner);
        }
        let id = self.mint_authority_id(&state.group, rng)?;
        let signing = group_authority_state_signing_bytes(&state)
            .map_err(|_| NodeError::InvalidGroupAuthority)?;
        state.signature = self.identity.sign_group_authority_state(&signing);
        verify_authority_state(&state, Some(&secret))?;
        let payload =
            encode_group_authority_state(&state).map_err(|_| NodeError::InvalidGroupAuthority)?;
        let wire =
            encode_group_authority(id, &payload).map_err(|_| NodeError::InvalidGroupAuthority)?;
        self.group_send_content_with_id(&state.group, wire, id, now, now, rng)?;

        // Reload because sending advanced the old sender chain.
        let mut rec = self
            .store
            .get_group(&state.group)?
            .ok_or(NodeError::UnknownGroup)?;
        rec.prev_secret = Some(rec.secret);
        rec.secret = secret;
        rec.name = state.name.clone();
        rec.creator = state.owner;
        rec.generation = state.generation;
        rec.members = state
            .members
            .iter()
            .map(|member| GroupMember {
                peer: member.peer,
                identity: member.identity.clone(),
            })
            .collect();
        self.rotate_group(&mut rec, rng)?;
        self.store.put_group(&rec, rng)?;
        let consumed_requests = self
            .store
            .get_group_authority(&state.group)?
            .map(|record| record.consumed_requests)
            .unwrap_or_default();
        self.store.put_group_authority(
            &GroupAuthorityRecord {
                group: state.group,
                state_id: id,
                state_payload: payload,
                consumed_requests,
            },
            rng,
        )?;
        self.events
            .push_back(Event::GroupUpdated { group: state.group });
        Ok(id)
    }

    fn mint_authority_id(
        &self,
        group: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let existing = self.store.group_messages(group)?;
        for _ in 0..ID_RETRY_LIMIT {
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            if id != [0; 16] && !existing.iter().any(|record| record.id == id) {
                return Ok(id);
            }
        }
        Err(NodeError::InvalidGroupAuthority)
    }

    pub(crate) fn apply_authority_announce(
        &mut self,
        peer: [u8; 32],
        announce: &GroupAuthorityAnnounce,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<bool> {
        let DecodedGroupAuthority::State(state) = decode_group_authority(&announce.state_payload)
        else {
            return Ok(true);
        };
        if state.group != announce.group
            || !state.members.iter().any(|member| member.peer == peer)
            || verify_authority_state(&state, Some(&announce.secret)).is_err()
        {
            return Ok(true);
        }
        let me = self.identity.public().ed;
        if !state.members.iter().any(|member| member.peer == me) {
            return Ok(false);
        }
        let current_authority = self.store.get_group_authority(&state.group)?;
        let current_state = current_authority.as_ref().map(decode_stored).transpose()?;
        if let Some(current) = &current_state {
            if current.original_owner != state.original_owner {
                return Ok(true);
            }
            if state.generation > current.generation
                && !transfer_chain_extends(&current.transfers, &state.transfers)
            {
                // Once one same-generation ownership fork wins locally, a
                // later state rooted in the losing transfer chain cannot use
                // a larger generation to take the replica back.
                return Ok(true);
            }
        } else if let Some(group) = self.store.get_group(&state.group)? {
            if group.creator != state.original_owner {
                return Ok(true);
            }
        }
        let adopt = current_state.as_ref().is_none_or(|current| {
            state.generation > current.generation
                || (state.generation == current.generation
                    && announce.state_id
                        < current_authority
                            .as_ref()
                            .expect("state has record")
                            .state_id)
        });
        let current_winner = current_authority
            .as_ref()
            .is_some_and(|record| record.state_id == announce.state_id);
        if !adopt && !current_winner {
            // A losing fork or older state must never replace a receiver
            // chain belonging to the accepted generation.
            return Ok(true);
        }
        let mut rec = match self.store.get_group(&state.group)? {
            Some(rec) => rec,
            None => {
                let chain = GroupSenderChain::generate(rng);
                GroupRecord {
                    id: state.group,
                    name: state.name.clone(),
                    creator: state.owner,
                    members: state_members(&state),
                    secret: announce.secret,
                    prev_secret: None,
                    generation: state.generation,
                    sender_chain: crate::groups::encode_chain(&chain)?,
                    sent_since_rotation: 0,
                    pending: crate::groups::pending_for(
                        &chain,
                        state.members.iter().map(|member| member.peer),
                        &me,
                    ),
                }
            }
        };
        if adopt {
            let stubs = state
                .members
                .iter()
                .map(|member| GroupMemberInfo {
                    peer: member.peer,
                    identity: member.identity.clone(),
                })
                .collect::<Vec<_>>();
            self.adopt_roster_stubs(&stubs, rng)?;
            let old_peers = rec
                .members
                .iter()
                .map(|member| member.peer)
                .collect::<Vec<_>>();
            for old in old_peers {
                if !state.members.iter().any(|member| member.peer == old) {
                    self.store.delete_group_chain(&state.group, &old)?;
                }
            }
            rec.prev_secret = (rec.secret != announce.secret).then_some(rec.secret);
            rec.secret = announce.secret;
            rec.name = state.name.clone();
            rec.creator = state.owner;
            rec.members = state_members(&state);
            rec.generation = state.generation;
            self.rotate_group(&mut rec, rng)?;
            self.store.put_group(&rec, rng)?;
            self.store.put_group_authority(
                &GroupAuthorityRecord {
                    group: state.group,
                    state_id: announce.state_id,
                    state_payload: announce.state_payload.clone(),
                    consumed_requests: current_authority
                        .map(|record| record.consumed_requests)
                        .unwrap_or_default(),
                },
                rng,
            )?;
            self.events
                .push_back(Event::GroupUpdated { group: state.group });
        }
        if rec.members.iter().any(|member| member.peer == peer) {
            let replace = match self.store.get_group_chain(&state.group, &peer)? {
                Some(blob) => postcard::from_bytes::<GroupReceiverChain>(&blob)
                    .map(|chain| chain.key_id() != announce.key_id)
                    .unwrap_or(true),
                None => true,
            };
            if replace {
                let chain = GroupReceiverChain::new(
                    announce.key_id,
                    &announce.chain_key,
                    announce.iteration,
                );
                let encoded = postcard::to_allocvec(&chain).map_err(|_| NodeError::CorruptState)?;
                self.store
                    .put_group_chain(&state.group, &peer, &encoded, rng)?;
                *established = true;
            }
        }
        Ok(true)
    }

    pub(crate) fn apply_authority_remove(
        &mut self,
        peer: [u8; 32],
        group: &[u8; 32],
        state_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<bool> {
        let DecodedGroupAuthority::State(state) = decode_group_authority(payload) else {
            return Ok(true);
        };
        if state.group != *group
            || state.signer != peer
            || state
                .members
                .iter()
                .any(|member| member.peer == self.identity.public().ed)
            || verify_authority_state(&state, None).is_err()
        {
            return Ok(true);
        }
        if let Some(current) = self.store.get_group_authority(group)? {
            let current_state = decode_stored(&current)?;
            if state.original_owner != current_state.original_owner
                || (state.generation > current_state.generation
                    && !transfer_chain_extends(&current_state.transfers, &state.transfers))
                || state.generation < current_state.generation
                || (state.generation == current_state.generation && *state_id >= current.state_id)
            {
                return Ok(true);
            }
        }
        self.store.delete_group(group)?;
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(true)
    }

    pub(crate) fn apply_group_admin_request(
        &mut self,
        peer: [u8; 32],
        request: &GroupAdminRequest,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(mut stored) = self.store.get_group_authority(&request.group)? else {
            return Ok(true);
        };
        if stored.consumed_requests.contains(&request.request_id) {
            return Ok(true);
        }
        let state = decode_stored(&stored)?;
        let signature: [u8; 64] = match request.signature.as_slice().try_into() {
            Ok(signature) => signature,
            Err(_) => return Ok(true),
        };
        let signing = match group_admin_request_signing_bytes(request) {
            Ok(signing) => signing,
            Err(_) => return Ok(true),
        };
        let is_admin = state
            .members
            .iter()
            .any(|member| member.peer == peer && member.role == GroupRole::Admin);
        let authorized = state.owner == self.identity.public().ed
            && request.base_generation == state.generation
            && is_admin
            && verify_group_admin_request_signature(&peer, &signing, &signature).is_ok();
        let result = if authorized {
            match &request.action {
                GroupAdminAction::Rename { name } => {
                    self.group_rename(&request.group, name, now, rng).map(Some)
                }
                GroupAdminAction::Invite(member) => self
                    .group_authority_add_member(
                        &request.group,
                        GroupMember {
                            peer: member.peer,
                            identity: member.identity.clone(),
                        },
                        now,
                        rng,
                    )
                    .map(Some),
                GroupAdminAction::Remove { peer } => self
                    .group_authority_remove_member(&request.group, *peer, now, rng)
                    .map(Some),
                GroupAdminAction::ModeratePoll {
                    poll_author,
                    poll_id,
                } => self
                    .group_moderate_poll_close(&request.group, *poll_author, *poll_id, now, rng)
                    .map(Some),
            }
        } else {
            Err(NodeError::InvalidGroupAuthority)
        };
        stored = self
            .store
            .get_group_authority(&request.group)?
            .unwrap_or(stored);
        stored.consumed_requests.push(request.request_id);
        if stored.consumed_requests.len() > MAX_GROUP_ADMIN_REQUESTS {
            let excess = stored.consumed_requests.len() - MAX_GROUP_ADMIN_REQUESTS;
            stored.consumed_requests.drain(..excess);
        }
        self.store.put_group_authority(&stored, rng)?;
        let (accepted, state_id, reason) = match result {
            Ok(state_id) => (true, state_id, 0),
            Err(NodeError::InvalidGroupAuthority) => (false, None, 2),
            Err(_) => (false, None, 3),
        };
        let response = GroupControlPayload::AdminResult(GroupAdminResult {
            group: request.group,
            request_id: request.request_id,
            accepted,
            generation: self.group_authority(&request.group)?.generation,
            state_id,
            reason,
        });
        self.queue_group_control(&peer, &response, now, rng)?;
        Ok(true)
    }

    pub(crate) fn apply_group_admin_result(
        &mut self,
        peer: [u8; 32],
        result: &GroupAdminResult,
    ) -> Result<bool> {
        let info = self.group_authority(&result.group)?;
        // The pairwise result and signed authority announce use independent
        // queued envelopes, so the result may arrive first. Authenticate it
        // against the currently accepted owner, but do not discard honest UI
        // status merely because the durable signed state is still in flight.
        if peer != info.owner {
            return Ok(true);
        }
        self.events.push_back(Event::GroupAdminRequestResolved {
            group: result.group,
            request_id: result.request_id,
            accepted: result.accepted,
            generation: result.generation,
            state_id: result.state_id,
            reason: result.reason,
        });
        Ok(true)
    }
}

pub(crate) fn decode_stored(record: &GroupAuthorityRecord) -> Result<SignedGroupAuthorityState> {
    match decode_group_authority(&record.state_payload) {
        DecodedGroupAuthority::State(state) if state.group == record.group => Ok(*state),
        _ => Err(NodeError::CorruptState),
    }
}

pub(crate) fn verify_authority_state(
    state: &SignedGroupAuthorityState,
    secret: Option<&[u8; 32]>,
) -> Result<()> {
    let signing =
        group_authority_state_signing_bytes(state).map_err(|_| NodeError::InvalidGroupAuthority)?;
    verify_group_authority_state_signature(&state.signer, &signing, &state.signature)
        .map_err(|_| NodeError::InvalidGroupAuthority)?;
    for transfer in &state.transfers {
        let bytes = owner_transfer_signing_bytes(
            transfer.group,
            transfer.epoch,
            transfer.generation,
            transfer.prior_state_id,
            transfer.from_owner,
            transfer.to_owner,
        )
        .map_err(|_| NodeError::InvalidGroupAuthority)?;
        verify_group_owner_transfer_signature(&transfer.from_owner, &bytes, &transfer.signature)
            .map_err(|_| NodeError::InvalidGroupAuthority)?;
    }
    for member in &state.members {
        let identity: IdentityPublic =
            postcard::from_bytes(&member.identity).map_err(|_| NodeError::InvalidGroupAuthority)?;
        if identity.ed != member.peer || identity.verify().is_err() {
            return Err(NodeError::InvalidGroupAuthority);
        }
    }
    if secret.is_some_and(|value| hash_secret(value) != state.secret_hash) {
        return Err(NodeError::InvalidGroupAuthority);
    }
    Ok(())
}

fn authority_members(rec: &GroupRecord, owner: [u8; 32]) -> Vec<GroupAuthorityMember> {
    let mut members = rec
        .members
        .iter()
        .map(|member| GroupAuthorityMember {
            peer: member.peer,
            identity: member.identity.clone(),
            role: if member.peer == owner {
                GroupRole::Owner
            } else {
                GroupRole::Member
            },
        })
        .collect::<Vec<_>>();
    members.sort_unstable_by_key(|member| member.peer);
    members
}

fn state_members(state: &SignedGroupAuthorityState) -> Vec<GroupMember> {
    state
        .members
        .iter()
        .map(|member| GroupMember {
            peer: member.peer,
            identity: member.identity.clone(),
        })
        .collect()
}

fn prepare_next_state(
    state: &mut SignedGroupAuthorityState,
    prior_state_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<()> {
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or(NodeError::InvalidGroupAuthority)?;
    state.prior_state_id = prior_state_id;
    state.signer = state.owner;
    state.secret_hash = hash_secret(secret);
    state.signature = [0; 64];
    Ok(())
}

fn hash_secret(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn transfer_chain_extends(
    accepted: &[OwnerTransferCertificate],
    candidate: &[OwnerTransferCertificate],
) -> bool {
    candidate.len() >= accepted.len() && candidate.iter().take(accepted.len()).eq(accepted.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(
        epoch: u64,
        from_owner: u8,
        to_owner: u8,
        signature: u8,
    ) -> OwnerTransferCertificate {
        OwnerTransferCertificate {
            group: [1; 32],
            epoch,
            generation: epoch + 10,
            prior_state_id: [epoch as u8; 16],
            from_owner: [from_owner; 32],
            to_owner: [to_owner; 32],
            signature: [signature; 64],
        }
    }

    #[test]
    fn accepted_transfer_fork_only_advances_through_its_exact_prefix() {
        let first = transfer(1, 2, 3, 4);
        let accepted = vec![first.clone()];
        assert!(transfer_chain_extends(&accepted, &accepted));
        assert!(transfer_chain_extends(
            &accepted,
            &[first.clone(), transfer(2, 3, 5, 6)]
        ));
        assert!(!transfer_chain_extends(
            &accepted,
            &[transfer(1, 2, 7, 8), transfer(2, 7, 5, 9)]
        ));
        assert!(!transfer_chain_extends(&accepted, &[]));
    }
}
