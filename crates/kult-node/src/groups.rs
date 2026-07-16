//! Sender-key groups (docs/04-cryptography.md §6, ADR-0012): group
//! management commands, the announce plane, encrypt-once fan-out, and the
//! group receive path. Everything here rides the existing pairwise
//! machinery — announces travel as ratchet-encrypted `GroupControl`
//! envelopes, group ciphertexts fan out under each pair's rotating delivery
//! tokens, and the ordinary encrypted receipts drive both the per-member
//! delivery ladder and announce acknowledgment.

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use kult_crypto::{
    GroupHeaderKey, GroupMessage, GroupReceiverChain, GroupSenderChain, IdentityPublic,
};
use kult_protocol::{
    decode_content, delivery_token, encode_disappearing_text_payload, encode_edit,
    encode_ephemeral, encode_mention, encode_text, epoch_day, pad, retention_bucket, unpad,
    DecodedContent, Edit, Envelope, EnvelopeKind, Ephemeral, GroupAnnounce, GroupControlPayload,
    GroupMemberInfo, MailboxKey, CONTENT_FORMAT_V1, CONTENT_KIND_EDIT, CONTENT_KIND_EPHEMERAL,
    CONTENT_KIND_MENTION, MAX_EDIT_TEXT_LEN, MAX_EPHEMERAL_LIFETIME_SECS,
    MIN_EPHEMERAL_LIFETIME_SECS,
};
use kult_store::{
    ContactRecord, DeliveryState, Direction, EphemeralConversation, EphemeralMode, EphemeralRecord,
    EphemeralState, GroupDelivery, GroupMember, GroupMessageRecord, GroupRecord, PendingAnnounce,
    QueueClass, QueueItem,
};

use crate::api::{
    GroupInfo, GroupMentionCapability, MentionCapabilityIssue, MentionCapabilityIssueReason,
    MentionSpan, ResolvedGroupMessage,
};
use crate::{Consumed, ContentStatus, Event, Node, NodeError, Result, MAX_MESSAGE_EDITS};

/// Rotate the sending chain after this many messages (PCS via periodic
/// rotation, spec §6).
const GROUP_ROTATE_MSGS: u32 = 1000;

/// End-to-end resend pacing for unacknowledged announces. Transport-level
/// retries handle a flaky link; this covers an envelope lost in transit
/// outright (a member missing one announce is deaf to its sender).
const GROUP_ANNOUNCE_RETRY_SECS: u64 = 900;

impl Node {
    // ---- commands -----------------------------------------------------------

    /// Create a group with stored contacts. This node becomes the creator —
    /// the single writer for roster, name, and group secret (ADR-0012).
    /// Announces (invite + sender key in one message) queue on the next
    /// [`Node::tick`]. Returns the group id.
    pub fn create_group(
        &mut self,
        name: &str,
        members: &[[u8; 32]],
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let me = self.identity.public().ed;
        let my_identity =
            postcard::to_allocvec(&self.identity.public()).map_err(|_| NodeError::CorruptState)?;
        let mut roster = vec![GroupMember {
            peer: me,
            identity: my_identity,
        }];
        for peer in members {
            if *peer == me || roster.iter().any(|m| &m.peer == peer) {
                continue;
            }
            let contact = self
                .store
                .get_contact(peer)?
                .ok_or(NodeError::UnknownPeer)?;
            roster.push(GroupMember {
                peer: *peer,
                identity: contact.identity,
            });
        }

        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let chain = GroupSenderChain::generate(rng);
        let pending = pending_for(&chain, roster.iter().map(|m| m.peer), &me);
        self.store.put_group(
            &GroupRecord {
                id,
                name: name.to_owned(),
                creator: me,
                members: roster,
                secret,
                prev_secret: None,
                generation: 1,
                sender_chain: encode_chain(&chain)?,
                sent_since_rotation: 0,
                pending,
            },
            rng,
        )?;
        self.events.push_back(Event::GroupUpdated { group: id });
        Ok(id)
    }

    /// All stored groups, without their secrets.
    pub fn groups(&self) -> Result<Vec<GroupInfo>> {
        Ok(self
            .store
            .groups()?
            .into_iter()
            .map(|g| GroupInfo {
                id: g.id,
                name: g.name,
                creator: g.creator,
                members: g.members.iter().map(|m| m.peer).collect(),
            })
            .collect())
    }

    /// Message history for a group, in insertion order.
    pub fn group_messages(&self, group: &[u8; 32]) -> Result<Vec<GroupMessageRecord>> {
        Ok(self.store.group_messages(group)?)
    }

    /// Group read model with immutable Edit events resolved and hidden from
    /// the ordinary row sequence.
    pub fn resolved_group_messages(&self, group: &[u8; 32]) -> Result<Vec<ResolvedGroupMessage>> {
        Ok(crate::edits::resolve_group(
            self.store.group_messages(group)?,
        ))
    }

    /// Queue a message to a group: persisted `Queued` per member before any
    /// crypto runs, encrypted **once** on this node's sending chain, fanned
    /// out to every member with a live session; members whose session is
    /// still forming keep their honest `Queued` state and are served by the
    /// tick as soon as it exists. Returns the group message record id.
    pub fn group_send(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        // The generic group API is the permanent text/legacy path. A caller
        // must not smuggle an already-encoded Mention around the exact-roster
        // capability and review-token gate below.
        match decode_content(body) {
            DecodedContent::Mention { .. } => return Err(NodeError::InvalidMention),
            DecodedContent::Edit { .. } => return Err(NodeError::InvalidEdit),
            DecodedContent::Ephemeral { .. } => return Err(NodeError::InvalidEphemeral),
            _ => {}
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.group_send_with_id(group, body, id, now, now, rng)
    }

    pub(crate) fn group_send_with_id(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        let mut all_members_support_text = true;
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.peer_supports_text(&member.peer)? {
                all_members_support_text = false;
                break;
            }
        }
        let wire_content = if all_members_support_text {
            match core::str::from_utf8(body) {
                Ok(text) => encode_text(id, text)?,
                Err(_) => body.to_vec(),
            }
        } else {
            body.to_vec()
        };
        self.group_send_content_with_id(group, wire_content, id, timestamp, now, rng)
    }

    /// Current exact Mention capability intersection and review binding.
    pub fn group_mention_capability(&self, group: &[u8; 32]) -> Result<GroupMentionCapability> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        let mut members = rec.members.iter().collect::<Vec<_>>();
        members.sort_unstable_by_key(|member| member.peer);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"KK-group-mention-review-v1");
        hasher.update(&rec.id);
        hasher.update(&rec.generation.to_le_bytes());
        hasher.update(&(rec.name.len() as u32).to_le_bytes());
        hasher.update(rec.name.as_bytes());
        let mut issues = Vec::new();
        for member in members {
            let state = if member.peer == me {
                1u8
            } else {
                match self.store.get_capabilities(&member.peer)? {
                    None => 0,
                    Some(capabilities)
                        if capabilities.supports(CONTENT_FORMAT_V1, CONTENT_KIND_MENTION) =>
                    {
                        1
                    }
                    Some(_) => 2,
                }
            };
            hasher.update(&member.peer);
            hasher.update(&[state]);
            hasher.update(&(member.identity.len() as u32).to_le_bytes());
            hasher.update(&member.identity);
            let local_name = self
                .store
                .get_contact(&member.peer)?
                .map(|contact| contact.name)
                .unwrap_or_default();
            hasher.update(&(local_name.len() as u32).to_le_bytes());
            hasher.update(local_name.as_bytes());
            if member.peer != me && state != 1 {
                issues.push(MentionCapabilityIssue {
                    peer: member.peer,
                    reason: if state == 0 {
                        MentionCapabilityIssueReason::Unknown
                    } else {
                        MentionCapabilityIssueReason::Unsupported
                    },
                });
            }
        }
        let mut review_token = [0u8; 16];
        review_token.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(GroupMentionCapability {
            group: rec.id,
            review_token,
            issues,
        })
    }

    /// Queue canonical group Mention content after atomic roster, local
    /// presentation mapping, and authenticated capability revalidation.
    pub fn group_send_mention(
        &mut self,
        group: &[u8; 32],
        text: &str,
        spans: &[MentionSpan],
        review_token: [u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let verdict = self.group_mention_capability(group)?;
        if !bool::from(review_token.ct_eq(&verdict.review_token)) {
            return Err(NodeError::MentionReviewRequired);
        }
        if !verdict.supported() {
            return Err(NodeError::MentionUnsupported);
        }
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        if spans
            .iter()
            .any(|span| !rec.members.iter().any(|member| member.peer == span.target))
        {
            return Err(NodeError::InvalidMention);
        }
        let protocol_spans = spans.iter().copied().map(Into::into).collect::<Vec<_>>();
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let wire_content =
            encode_mention(id, text, &protocol_spans).map_err(|_| NodeError::InvalidMention)?;
        self.group_send_content_with_id(group, wire_content, id, now, now, rng)
    }

    /// Queue an immutable edit for this identity's exact canonical group Text.
    pub fn group_edit_message(
        &mut self,
        group: &[u8; 32],
        target_author: [u8; 32],
        target_content_id: [u8; 16],
        text: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if target_author != me
            || text.is_empty()
            || text.len() > MAX_EDIT_TEXT_LEN
            || !rec.members.iter().any(|member| member.peer == me)
        {
            return Err(NodeError::InvalidEdit);
        }
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.peer_supports_kind(&member.peer, CONTENT_KIND_EDIT)? {
                return Err(NodeError::EditUnsupported);
            }
        }
        let records = self.store.group_messages(group)?;
        if !records.iter().any(|record| {
            record.sender == me
                && record.direction == Direction::Outbound
                && matches!(
                    decode_content(&record.body),
                    DecodedContent::Text { id, .. } if id == target_content_id
                )
        }) {
            return Err(NodeError::InvalidEdit);
        }
        let revisions = records.iter().filter_map(|record| {
            if record.sender != me || record.direction != Direction::Outbound {
                return None;
            }
            match decode_content(&record.body) {
                DecodedContent::Edit { edit, .. }
                    if edit.target_author == me && edit.target_content_id == target_content_id =>
                {
                    Some(edit.revision)
                }
                _ => None,
            }
        });
        let mut count = 0usize;
        let mut revision = 0u64;
        for value in revisions {
            count += 1;
            revision = revision.max(value);
        }
        if count >= MAX_MESSAGE_EDITS {
            return Err(NodeError::EditLimit);
        }
        revision = revision.checked_add(1).ok_or(NodeError::EditLimit)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let wire_content = encode_edit(
            id,
            &Edit {
                target_author: me,
                target_content_id,
                revision,
                text,
            },
        )?;
        self.group_send_content_with_id(group, wire_content, id, now, now, rng)
    }

    /// Queue disappearing UTF-8 only after every current co-member has
    /// authenticated exact ephemeral support.
    pub fn group_send_disappearing_message(
        &mut self,
        group: &[u8; 32],
        text: &str,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if text.is_empty()
            || !(MIN_EPHEMERAL_LIFETIME_SECS..=MAX_EPHEMERAL_LIFETIME_SECS).contains(&lifetime_secs)
        {
            return Err(NodeError::InvalidEphemeral);
        }
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if !rec.members.iter().any(|member| member.peer == me) {
            return Err(NodeError::InvalidEphemeral);
        }
        for member in rec.members.iter().filter(|member| member.peer != me) {
            if !self.sessions.contains_key(&member.peer)
                || !self.peer_supports_kind(&member.peer, CONTENT_KIND_EPHEMERAL)?
            {
                return Err(NodeError::EphemeralUnsupported);
            }
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(NodeError::InvalidEphemeral)?;
        let retention_until = retention_bucket(expires_at)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let payload = encode_disappearing_text_payload(expires_at, text)?;
        let wire_content = encode_ephemeral(id, &payload)?;
        self.store.put_ephemeral_record(
            &EphemeralRecord {
                conversation: EphemeralConversation::Group(*group),
                author: me,
                content_id: id,
                expires_at,
                mode: EphemeralMode::DisappearingText,
                state: EphemeralState::Active,
                transfer_ids: Vec::new(),
            },
            rng,
        )?;
        self.group_send_content_with_id_retention(
            group,
            wire_content,
            id,
            now,
            now,
            Some(retention_until),
            rng,
        )
    }

    fn group_send_content_with_id(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.group_send_content_with_id_retention(
            group,
            wire_content,
            id,
            timestamp,
            now,
            None,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // canonical group send plus optional relay hint
    fn group_send_content_with_id_retention(
        &mut self,
        group: &[u8; 32],
        wire_content: Vec<u8>,
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        retention_until: Option<u64>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let mut rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        let mut record = GroupMessageRecord {
            id,
            group: *group,
            sender: me,
            direction: Direction::Outbound,
            timestamp,
            body: wire_content.clone(),
            deliveries: rec
                .members
                .iter()
                .filter(|m| m.peer != me)
                .map(|m| GroupDelivery {
                    peer: m.peer,
                    wire_id: None,
                    state: DeliveryState::Queued,
                })
                .collect(),
            wire_body: None,
        };
        self.store.put_group_message(&record, rng)?;
        for d in &record.deliveries {
            self.events.push_back(Event::GroupDeliveryUpdated {
                id,
                peer: d.peer,
                state: DeliveryState::Queued,
            });
        }

        // A spent chain rotates before it encrypts anything else (PCS).
        if rec.sent_since_rotation >= GROUP_ROTATE_MSGS {
            self.rotate_group(&mut rec, rng)?;
        }

        let mut chain = decode_chain(&rec.sender_chain)?;
        let hk = GroupHeaderKey::derive(&rec.secret);
        let wire = chain.seal(&hk, group, &pad(&wire_content)?, rng).encode();
        rec.sender_chain = encode_chain(&chain)?;
        rec.sent_since_rotation += 1;

        let mut unserved = false;
        for d in record.deliveries.iter_mut() {
            match self.queue_group_copy(
                &d.peer,
                &wire,
                id,
                QueueClass::Normal,
                retention_until,
                now,
                rng,
            )? {
                Some(cid) => d.wire_id = Some(cid),
                None => unserved = true,
            }
        }
        record.wire_body = unserved.then_some(wire);
        self.store.update_group_message(&record, rng)?;
        self.store.put_group(&rec, rng)?;
        Ok(id)
    }

    /// Add a stored contact to a group (creator only). Existing members
    /// learn the roster and the new member gets everything through the same
    /// announce shape.
    pub fn group_add(
        &mut self,
        group: &[u8; 32],
        peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if rec.creator != me {
            return Err(NodeError::NotGroupCreator);
        }
        if rec.members.iter().any(|m| &m.peer == peer) {
            return Ok(()); // already in — idempotent
        }
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        rec.members.push(GroupMember {
            peer: *peer,
            identity: contact.identity,
        });
        rec.generation += 1;

        // The newcomer needs our chain from *now* (no history); everyone
        // else needs the new roster — served members get a fresh announce
        // entry, unserved ones already have one.
        let chain = decode_chain(&rec.sender_chain)?;
        let (key_id, chain_key, iteration) = chain.snapshot();
        for member in rec.members.clone() {
            if member.peer == me || rec.pending.iter().any(|p| p.peer == member.peer) {
                continue;
            }
            rec.pending.push(PendingAnnounce {
                peer: member.peer,
                key_id,
                chain_key: *chain_key,
                iteration,
                wire_id: None,
                last_sent: 0,
            });
        }
        self.store.put_group(&rec, rng)?;
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(())
    }

    /// Remove a member (creator only): fresh group secret, bumped
    /// generation, own chain rotated, announces to every remaining member —
    /// and a removal notice (never the new secret) to the removed one.
    pub fn group_remove(
        &mut self,
        group: &[u8; 32],
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.identity.public().ed;
        if peer == &me {
            return self.group_leave(group, now, rng);
        }
        let mut rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        if rec.creator != me {
            return Err(NodeError::NotGroupCreator);
        }
        if !rec.members.iter().any(|m| &m.peer == peer) {
            return Err(NodeError::UnknownPeer);
        }
        rec.members.retain(|m| &m.peer != peer);
        self.store.delete_group_chain(group, peer)?;
        rec.generation += 1;
        rec.prev_secret = Some(rec.secret);
        rng.fill_bytes(&mut rec.secret);
        self.rotate_group(&mut rec, rng)?; // also drops the removed peer's pending entry
        self.store.put_group(&rec, rng)?;
        // Best effort: keys are already rotated whether or not this lands.
        self.queue_group_control(
            peer,
            &GroupControlPayload::Remove { group: *group },
            now,
            rng,
        )?;
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(())
    }

    /// Leave a group: tell every member (best effort — the survivors rotate
    /// on receipt), then drop the group locally. History stays; it is this
    /// device's data.
    pub fn group_leave(
        &mut self,
        group: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        for member in &rec.members {
            if member.peer == me {
                continue;
            }
            self.queue_group_control(
                &member.peer,
                &GroupControlPayload::Leave { group: *group },
                now,
                rng,
            )?;
        }
        self.store.delete_group(group)?;
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(())
    }

    // ---- the tick's group upkeep --------------------------------------------

    /// Flush due announces (initiating pairwise sessions where a bundle is
    /// stored or the DHT can produce one) and serve late fan-out: members
    /// whose session appeared after a group message was queued get their
    /// copy of the retained ciphertext now.
    pub(crate) async fn tick_groups(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.identity.public().ed;
        let queued_ids: HashSet<[u8; 16]> = self
            .store
            .queue_all()?
            .iter()
            .map(|(_, item)| item.envelope.content_id())
            .collect();

        for mut rec in self.store.groups()? {
            let mut dirty = false;
            let mut pending = std::mem::take(&mut rec.pending);
            for entry in pending.iter_mut() {
                // Due when never attempted, or when the retry window passed
                // and the last envelope is out of the queue (a queued one is
                // still the transport scheduler's problem, not ours).
                let never_tried = entry.last_sent == 0;
                let resend_due = entry.last_sent != 0
                    && now.saturating_sub(entry.last_sent) >= GROUP_ANNOUNCE_RETRY_SECS
                    && entry.wire_id.is_none_or(|w| !queued_ids.contains(&w));
                if !(never_tried || resend_due) {
                    continue;
                }
                self.resolve_group_peer_bundle(&entry.peer, now, rng)
                    .await?;
                let announce = GroupControlPayload::Announce(GroupAnnounce {
                    group: rec.id,
                    name: rec.name.clone(),
                    creator: rec.creator,
                    // Roster authority is the creator's alone; anyone else
                    // sends it empty (ignored on receipt either way).
                    members: if rec.creator == me {
                        rec.members
                            .iter()
                            .map(|m| GroupMemberInfo {
                                peer: m.peer,
                                identity: m.identity.clone(),
                            })
                            .collect()
                    } else {
                        Vec::new()
                    },
                    secret: rec.secret,
                    generation: rec.generation,
                    key_id: entry.key_id,
                    chain_key: entry.chain_key,
                    iteration: entry.iteration,
                });
                entry.wire_id = self.queue_group_control(&entry.peer, &announce, now, rng)?;
                entry.last_sent = now; // paces the next attempt either way
                dirty = true;
            }
            rec.pending = pending;
            if dirty {
                self.store.put_group(&rec, rng)?;
            }
        }

        // Late fan-out from retained ciphertexts.
        for mut record in self.store.all_group_messages()? {
            let Some(wire) = record.wire_body.clone() else {
                continue;
            };
            let mut changed = false;
            let mut unserved = false;
            for d in record.deliveries.iter_mut() {
                if d.wire_id.is_some() {
                    continue;
                }
                match self.queue_group_copy(
                    &d.peer,
                    &wire,
                    record.id,
                    QueueClass::Normal,
                    ephemeral_retention(&record.body),
                    now,
                    rng,
                )? {
                    Some(cid) => {
                        d.wire_id = Some(cid);
                        changed = true;
                    }
                    None => unserved = true,
                }
            }
            if !unserved {
                record.wire_body = None;
                changed = true;
            }
            if changed {
                self.store.update_group_message(&record, rng)?;
            }
        }
        Ok(())
    }

    /// A pairwise session with `peer` was (re-)established from an inbound
    /// handshake: if they co-member any group, make sure an announce is
    /// owed to them — their device may have restored and lost every
    /// receiving chain (ADR-0012). Existing entries keep their (older, more
    /// capable) snapshot and simply resend on the fresh session.
    pub(crate) fn groups_on_session_established(
        &mut self,
        peer: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.identity.public().ed;
        if peer == &me {
            return Ok(());
        }
        for mut rec in self.store.groups()? {
            if !rec.members.iter().any(|m| &m.peer == peer) {
                continue;
            }
            match rec.pending.iter_mut().find(|p| &p.peer == peer) {
                Some(entry) => {
                    entry.wire_id = None;
                    entry.last_sent = 0;
                }
                None => {
                    let chain = decode_chain(&rec.sender_chain)?;
                    let (key_id, chain_key, iteration) = chain.snapshot();
                    rec.pending.push(PendingAnnounce {
                        peer: *peer,
                        key_id,
                        chain_key: *chain_key,
                        iteration,
                        wire_id: None,
                        last_sent: 0,
                    });
                }
            }
            self.store.put_group(&rec, rng)?;
        }
        Ok(())
    }

    // ---- receive path --------------------------------------------------------

    /// Consume a `GroupMessage` envelope. The delivery token names the
    /// pairwise session it rode under (so foreign traffic never reaches the
    /// group trial-decrypt); the sealed header names the chain. Anything
    /// whose group or chain is not known yet stashes — "announce still in
    /// flight" gets the same cure as "handshake still in flight".
    pub(crate) fn consume_group_message(
        &mut self,
        env: &Envelope,
        now: u64,
        rng: &mut impl CryptoRngCore,
        acks: &mut Vec<([u8; 32], [u8; 16])>,
    ) -> Result<Consumed> {
        let Some(peer) = self.match_session(&env.token, now) else {
            return Ok(Consumed::Later);
        };
        let me = self.identity.public().ed;
        let done = |node: &mut Self| -> Result<Consumed> {
            node.store.mark_seen(&env.content_id())?;
            Ok(Consumed::Done)
        };
        let Ok(msg) = GroupMessage::decode(&env.body) else {
            return done(self);
        };

        for rec in self.store.groups()? {
            if !rec.members.iter().any(|m| m.peer == peer) {
                continue;
            }
            // Current header key first; the previous one covers in-flight
            // traffic crossing a re-key (kept one generation deep).
            let mut opened = None;
            for secret in core::iter::once(rec.secret).chain(rec.prev_secret) {
                let hk = GroupHeaderKey::derive(&secret);
                if let Ok(header) = msg.open_header(&hk) {
                    opened = Some(header);
                    break;
                }
            }
            let Some((key_id, iteration)) = opened else {
                continue;
            };
            let Some(blob) = self.store.get_group_chain(&rec.id, &peer)? else {
                return Ok(Consumed::Later); // sender's announce still in flight
            };
            let mut chain: GroupReceiverChain =
                postcard::from_bytes(&blob).map_err(|_| NodeError::CorruptState)?;
            if chain.key_id() != key_id {
                return Ok(Consumed::Later); // rotation announce still in flight
            }
            let Ok(padded) = chain.open(&rec.id, &msg, iteration, now) else {
                // Tampered or replayed — permanent, honest failure.
                return done(self);
            };
            let encoded = postcard::to_allocvec(&chain).map_err(|_| NodeError::CorruptState)?;
            self.store.put_group_chain(&rec.id, &peer, &encoded, rng)?;
            let Ok(body) = unpad(&padded) else {
                return done(self);
            };

            let decoded = decode_content(&body);
            let authenticated_retention = match decoded {
                DecodedContent::Ephemeral { ephemeral, .. } => Some(match ephemeral {
                    Ephemeral::DisappearingText {
                        retention_until, ..
                    }
                    | Ephemeral::ViewOnceAttachment {
                        retention_until, ..
                    } => retention_until,
                }),
                _ => None,
            };
            if env.retention_until != authenticated_retention {
                return done(self);
            }
            let decoded_is_edit = matches!(decoded, DecodedContent::Edit { .. });
            if let DecodedContent::Text { id, .. }
            | DecodedContent::Attachment { id, .. }
            | DecodedContent::Mention { id, .. }
            | DecodedContent::Edit { id, .. }
            | DecodedContent::Ephemeral { id, .. } = decoded
            {
                let conversation = EphemeralConversation::Group(rec.id);
                if self
                    .store
                    .get_ephemeral_record(&conversation, &peer, &id)?
                    .is_some()
                {
                    acks.push((peer, env.content_id()));
                    return done(self);
                }
                let duplicate = self.store.group_messages(&rec.id)?.iter().any(|record| {
                    record.direction == Direction::Inbound
                        && record.sender == peer
                        && matches!(
                            decode_content(&record.body),
                            DecodedContent::Text { id: stored_id, .. }
                                | DecodedContent::Attachment { id: stored_id, .. }
                                | DecodedContent::Mention { id: stored_id, .. }
                                | DecodedContent::Edit { id: stored_id, .. }
                                | DecodedContent::Ephemeral { id: stored_id, .. }
                                if stored_id == id
                        )
                });
                if duplicate {
                    acks.push((peer, env.content_id()));
                    return done(self);
                }
            }
            let mut mentions_local_peer = false;
            let (id, event_body, content) = match decoded {
                DecodedContent::LegacyText(text) => {
                    let mut id = [0u8; 16];
                    rng.fill_bytes(&mut id);
                    (id, text.as_bytes().to_vec(), ContentStatus::LegacyText)
                }
                DecodedContent::Text { id, text } => {
                    (id, text.as_bytes().to_vec(), ContentStatus::Text { id })
                }
                DecodedContent::Attachment { id, manifest } => {
                    let entitled_peers = rec.members.iter().map(|member| member.peer).collect();
                    let transfer = self.record_group_attachment_offer(
                        crate::attachment::GroupAttachmentOffer {
                            group: rec.id,
                            author: peer,
                            entitled_peers,
                        },
                        id,
                        &manifest,
                        now,
                        rng,
                    )?;
                    self.emit_attachment_update(&transfer)?;
                    (id, Vec::new(), ContentStatus::Attachment { id, transfer })
                }
                DecodedContent::Mention { id, mention } => {
                    let spans = mention.spans().map(MentionSpan::from).collect::<Vec<_>>();
                    mentions_local_peer = spans.iter().any(|span| span.target == me);
                    (
                        id,
                        mention.text.as_bytes().to_vec(),
                        ContentStatus::Mention { id, spans },
                    )
                }
                DecodedContent::Edit { id, edit } if edit.target_author == peer => (
                    id,
                    Vec::new(),
                    ContentStatus::Edit {
                        id,
                        target_author: edit.target_author,
                        target_content_id: edit.target_content_id,
                        revision: edit.revision,
                    },
                ),
                DecodedContent::Edit { id, .. } => (id, Vec::new(), ContentStatus::Malformed),
                DecodedContent::Ephemeral {
                    id,
                    ephemeral:
                        Ephemeral::DisappearingText {
                            expires_at, text, ..
                        },
                } => {
                    let state = if now >= expires_at {
                        EphemeralState::Expired
                    } else {
                        EphemeralState::Active
                    };
                    self.store.put_ephemeral_record(
                        &EphemeralRecord {
                            conversation: EphemeralConversation::Group(rec.id),
                            author: peer,
                            content_id: id,
                            expires_at,
                            mode: EphemeralMode::DisappearingText,
                            state,
                            transfer_ids: Vec::new(),
                        },
                        rng,
                    )?;
                    if state == EphemeralState::Expired {
                        self.events.push_back(Event::EphemeralRemoved {
                            conversation: EphemeralConversation::Group(rec.id),
                            author: peer,
                            content_id: id,
                            reason: state,
                        });
                        acks.push((peer, env.content_id()));
                        return done(self);
                    }
                    (
                        id,
                        text.as_bytes().to_vec(),
                        ContentStatus::DisappearingText { id, expires_at },
                    )
                }
                DecodedContent::Ephemeral {
                    id,
                    ephemeral:
                        Ephemeral::ViewOnceAttachment {
                            expires_at,
                            manifest,
                            ..
                        },
                } => {
                    if now >= expires_at {
                        self.store.put_ephemeral_record(
                            &EphemeralRecord {
                                conversation: EphemeralConversation::Group(rec.id),
                                author: peer,
                                content_id: id,
                                expires_at,
                                mode: EphemeralMode::ViewOnceAttachment,
                                state: EphemeralState::Expired,
                                transfer_ids: Vec::new(),
                            },
                            rng,
                        )?;
                        self.events.push_back(Event::EphemeralRemoved {
                            conversation: EphemeralConversation::Group(rec.id),
                            author: peer,
                            content_id: id,
                            reason: EphemeralState::Expired,
                        });
                        acks.push((peer, env.content_id()));
                        return done(self);
                    }
                    let entitled_peers = rec.members.iter().map(|member| member.peer).collect();
                    let transfer = self.record_group_attachment_offer(
                        crate::attachment::GroupAttachmentOffer {
                            group: rec.id,
                            author: peer,
                            entitled_peers,
                        },
                        id,
                        &manifest,
                        now,
                        rng,
                    )?;
                    self.store.put_ephemeral_record(
                        &EphemeralRecord {
                            conversation: EphemeralConversation::Group(rec.id),
                            author: peer,
                            content_id: id,
                            expires_at,
                            mode: EphemeralMode::ViewOnceAttachment,
                            state: EphemeralState::Active,
                            transfer_ids: vec![transfer],
                        },
                        rng,
                    )?;
                    self.emit_attachment_update(&transfer)?;
                    (
                        id,
                        Vec::new(),
                        ContentStatus::ViewOnceAttachment {
                            id,
                            transfer,
                            expires_at,
                        },
                    )
                }
                DecodedContent::Unsupported {
                    format_version,
                    kind,
                } => {
                    let mut id = [0u8; 16];
                    rng.fill_bytes(&mut id);
                    (
                        id,
                        Vec::new(),
                        ContentStatus::Unsupported {
                            format_version,
                            kind,
                        },
                    )
                }
                DecodedContent::Malformed => {
                    let mut id = [0u8; 16];
                    rng.fill_bytes(&mut id);
                    (id, Vec::new(), ContentStatus::Malformed)
                }
            };
            self.store.put_group_message(
                &GroupMessageRecord {
                    id,
                    group: rec.id,
                    sender: peer,
                    direction: Direction::Inbound,
                    timestamp: now,
                    body,
                    deliveries: Vec::new(),
                    wire_body: None,
                },
                rng,
            )?;
            match content {
                ContentStatus::Edit {
                    target_content_id, ..
                } => self.events.push_back(Event::GroupMessageEdited {
                    group: rec.id,
                    sender: peer,
                    target_content_id,
                }),
                ContentStatus::Malformed if decoded_is_edit => {}
                _ => self.events.push_back(Event::GroupMessageReceived {
                    group: rec.id,
                    sender: peer,
                    id,
                    timestamp: now,
                    body: event_body,
                    content,
                }),
            }
            if mentions_local_peer {
                self.events.push_back(Event::MentionReceived { id });
            }
            acks.push((peer, env.content_id()));
            return done(self);
        }
        // No group of this sender opened the header: the invite may still
        // be in flight (or the message is junk — the pending TTL bounds it).
        Ok(Consumed::Later)
    }

    /// Apply a decrypted `GroupControl` payload from `peer`. Returns whether
    /// it was applied — unapplied controls are **not** acknowledged, so the
    /// sender's paced resend arrives after the missing context (e.g. a
    /// co-member's announce racing the creator's invite).
    pub(crate) fn apply_group_control(
        &mut self,
        peer: [u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<bool> {
        let Ok(payload) = GroupControlPayload::decode(body) else {
            return Ok(true); // malformed is terminal — ack so it is not resent
        };
        let _ = now;
        match &payload {
            GroupControlPayload::Announce(a) => {
                self.apply_group_announce(peer, a, rng, established)
            }
            GroupControlPayload::Leave { group } => self.apply_group_leave(peer, group, rng),
            GroupControlPayload::Remove { group } => {
                self.apply_group_remove_notice(peer, group, rng)
            }
        }
    }

    fn apply_group_announce(
        &mut self,
        peer: [u8; 32],
        a: &GroupAnnounce,
        rng: &mut impl CryptoRngCore,
        established: &mut bool,
    ) -> Result<bool> {
        let me = self.identity.public().ed;
        let rec = match self.store.get_group(&a.group)? {
            None => {
                // An invite: only the claimed creator's announce creates
                // the group, and it must list both of us.
                if a.creator != peer
                    || !a.members.iter().any(|m| m.peer == me)
                    || !a.members.iter().any(|m| m.peer == peer)
                {
                    return Ok(false);
                }
                self.adopt_roster_stubs(&a.members, rng)?;
                let chain = GroupSenderChain::generate(rng);
                let members: Vec<GroupMember> = a
                    .members
                    .iter()
                    .map(|m| GroupMember {
                        peer: m.peer,
                        identity: m.identity.clone(),
                    })
                    .collect();
                let pending = pending_for(&chain, members.iter().map(|m| m.peer), &me);
                let rec = GroupRecord {
                    id: a.group,
                    name: a.name.clone(),
                    creator: a.creator,
                    members,
                    secret: a.secret,
                    prev_secret: None,
                    generation: a.generation,
                    sender_chain: encode_chain(&chain)?,
                    sent_since_rotation: 0,
                    pending,
                };
                self.events
                    .push_back(Event::GroupUpdated { group: a.group });
                rec
            }
            Some(mut rec) => {
                if peer == rec.creator && a.generation > rec.generation {
                    if !a.members.iter().any(|m| m.peer == me) {
                        // The creator's newer roster omits us: removed.
                        self.store.delete_group(&rec.id)?;
                        self.events
                            .push_back(Event::GroupUpdated { group: a.group });
                        return Ok(true);
                    }
                    let old: HashSet<[u8; 32]> = rec.members.iter().map(|m| m.peer).collect();
                    let new: HashSet<[u8; 32]> = a.members.iter().map(|m| m.peer).collect();
                    for gone in old.difference(&new) {
                        self.store.delete_group_chain(&rec.id, gone)?;
                    }
                    rec.pending.retain(|p| new.contains(&p.peer));
                    self.adopt_roster_stubs(&a.members, rng)?;
                    rec.members = a
                        .members
                        .iter()
                        .map(|m| GroupMember {
                            peer: m.peer,
                            identity: m.identity.clone(),
                        })
                        .collect();
                    rec.name = a.name.clone();
                    rec.generation = a.generation;
                    if rec.secret != a.secret {
                        rec.prev_secret = Some(rec.secret);
                        rec.secret = a.secret;
                    }
                    if old.difference(&new).next().is_some() {
                        // Someone was removed: every remaining member
                        // rotates (spec §6).
                        self.rotate_group(&mut rec, rng)?;
                    } else {
                        // Pure additions: newcomers get our current chain.
                        let chain = decode_chain(&rec.sender_chain)?;
                        let (key_id, chain_key, iteration) = chain.snapshot();
                        for added in new.difference(&old) {
                            if added == &me || rec.pending.iter().any(|p| &p.peer == added) {
                                continue;
                            }
                            rec.pending.push(PendingAnnounce {
                                peer: *added,
                                key_id,
                                chain_key: *chain_key,
                                iteration,
                                wire_id: None,
                                last_sent: 0,
                            });
                        }
                    }
                    self.events
                        .push_back(Event::GroupUpdated { group: a.group });
                }
                rec
            }
        };

        // The sender-key half: honored from any current member.
        if !rec.members.iter().any(|m| m.peer == peer) {
            return Ok(false);
        }
        let replace = match self.store.get_group_chain(&rec.id, &peer)? {
            // Same chain id: the stored state reads from an earlier (or
            // equal) iteration — strictly more capable, keep it.
            Some(blob) => postcard::from_bytes::<GroupReceiverChain>(&blob)
                .map(|c| c.key_id() != a.key_id)
                .unwrap_or(true),
            None => true,
        };
        if replace {
            let chain = GroupReceiverChain::new(a.key_id, &a.chain_key, a.iteration);
            let encoded = postcard::to_allocvec(&chain).map_err(|_| NodeError::CorruptState)?;
            self.store.put_group_chain(&rec.id, &peer, &encoded, rng)?;
            // Stashed group messages on this chain may decrypt now.
            *established = true;
        }
        self.store.put_group(&rec, rng)?;
        Ok(true)
    }

    fn apply_group_leave(
        &mut self,
        peer: [u8; 32],
        group: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(mut rec) = self.store.get_group(group)? else {
            return Ok(true); // unknown group: terminal no-op
        };
        if !rec.members.iter().any(|m| m.peer == peer) {
            return Ok(true);
        }
        rec.members.retain(|m| m.peer != peer);
        self.store.delete_group_chain(group, &peer)?;
        let me = self.identity.public().ed;
        if rec.creator == me {
            // Authority: re-key the shrunk roster so the leaver cannot even
            // header-decrypt what follows.
            rec.generation += 1;
            rec.prev_secret = Some(rec.secret);
            rng.fill_bytes(&mut rec.secret);
        }
        // Every remaining member rotates on membership shrink (spec §6).
        self.rotate_group(&mut rec, rng)?;
        self.store.put_group(&rec, rng)?;
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(true)
    }

    fn apply_group_remove_notice(
        &mut self,
        peer: [u8; 32],
        group: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let _ = rng;
        let Some(rec) = self.store.get_group(group)? else {
            return Ok(true);
        };
        if rec.creator != peer {
            return Ok(true); // only the creator removes; anything else is noise
        }
        self.store.delete_group(group)?; // history stays
        self.events.push_back(Event::GroupUpdated { group: *group });
        Ok(true)
    }

    // ---- receipts and delivery ladder ----------------------------------------

    /// Receipt acks from `peer`: retire acknowledged announces and advance
    /// per-member deliveries of outbound group messages.
    pub(crate) fn apply_group_receipt(
        &mut self,
        peer: &[u8; 32],
        acks: &[[u8; 16]],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if acks.is_empty() {
            return Ok(());
        }
        let acked = |wire: &[u8; 16]| -> bool { acks.iter().any(|a| bool::from(a.ct_eq(wire))) };
        for mut rec in self.store.groups()? {
            let before = rec.pending.len();
            rec.pending
                .retain(|p| !(&p.peer == peer && p.wire_id.as_ref().is_some_and(&acked)));
            if rec.pending.len() != before {
                self.store.put_group(&rec, rng)?;
            }
        }
        for mut record in self.store.all_group_messages()? {
            let mut changed = false;
            for d in record.deliveries.iter_mut() {
                if &d.peer == peer
                    && d.state != DeliveryState::Delivered
                    && d.wire_id.as_ref().is_some_and(&acked)
                {
                    d.state = DeliveryState::Delivered;
                    changed = true;
                    self.events.push_back(Event::GroupDeliveryUpdated {
                        id: record.id,
                        peer: *peer,
                        state: DeliveryState::Delivered,
                    });
                }
            }
            if changed {
                self.store.update_group_message(&record, rng)?;
            }
        }
        Ok(())
    }

    /// A member's envelope copy was handed to a link: `Queued` → `Sent`.
    pub(crate) fn group_mark_sent(
        &mut self,
        peer: &[u8; 32],
        group_msg_id: &[u8; 16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for mut record in self.store.all_group_messages()? {
            if &record.id != group_msg_id {
                continue;
            }
            for d in record.deliveries.iter_mut() {
                if &d.peer == peer && d.state == DeliveryState::Queued {
                    d.state = DeliveryState::Sent;
                    self.events.push_back(Event::GroupDeliveryUpdated {
                        id: *group_msg_id,
                        peer: *peer,
                        state: DeliveryState::Sent,
                    });
                    self.store.update_group_message(&record, rng)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    // ---- internals -------------------------------------------------------

    /// Fresh sending chain, everything reset: announces owed to the whole
    /// roster with the new snapshot.
    fn rotate_group(&mut self, rec: &mut GroupRecord, rng: &mut impl CryptoRngCore) -> Result<()> {
        let me = self.identity.public().ed;
        let chain = GroupSenderChain::generate(rng);
        rec.pending = pending_for(&chain, rec.members.iter().map(|m| m.peer), &me);
        rec.sender_chain = encode_chain(&chain)?;
        rec.sent_since_rotation = 0;
        Ok(())
    }

    /// Contact stubs for roster members we have never met: identity only,
    /// no bundle, no hints — the DHT (or a later out-of-band exchange)
    /// fills those in, exactly like a contact learned from an inbound
    /// handshake.
    fn adopt_roster_stubs(
        &mut self,
        members: &[GroupMemberInfo],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let me = self.identity.public().ed;
        for m in members {
            if m.peer == me || m.identity.is_empty() || self.store.get_contact(&m.peer)?.is_some() {
                continue;
            }
            // Never store an identity blob that does not belong to the peer
            // id it is filed under.
            let Ok(identity) = postcard::from_bytes::<IdentityPublic>(&m.identity) else {
                continue;
            };
            if identity.ed != m.peer {
                continue;
            }
            self.store.put_contact(
                &ContactRecord {
                    peer: m.peer,
                    identity: m.identity.clone(),
                    name: String::new(),
                    bundle: Vec::new(),
                    hints: Vec::new(),
                    verified: false,
                },
                rng,
            )?;
            self.events.push_back(Event::ContactAdded { peer: m.peer });
        }
        Ok(())
    }

    /// One member's copy of a group ciphertext, if their pairwise session
    /// exists (the delivery token needs it). `None` means "not yet" — the
    /// tick retries once the session appears.
    #[allow(clippy::too_many_arguments)] // exact fan-out identity, timing, and retention inputs
    fn queue_group_copy(
        &mut self,
        peer: &[u8; 32],
        wire: &[u8],
        group_msg_id: [u8; 16],
        class: QueueClass,
        retention_until: Option<u64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<[u8; 16]>> {
        let Some(session) = self.sessions.get(peer) else {
            return Ok(None);
        };
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            peer,
        );
        let envelope = match retention_until {
            Some(deadline) => {
                Envelope::new_retained(EnvelopeKind::GroupMessage, token, deadline, wire.to_vec())?
            }
            None => Envelope::new(EnvelopeKind::GroupMessage, token, wire.to_vec()),
        };
        let cid = envelope.content_id();
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                group_msg_id: Some(group_msg_id),
                class,
                envelope,
            },
            rng,
        )?;
        Ok(Some(cid))
    }

    /// Encrypt one already-persisted Attachment manifest exactly once on the
    /// group's sender chain and queue its pairwise envelope copies as bulk.
    /// The attachment engine calls this only after every intended member has
    /// authenticated support and a fresh non-airtime route.
    pub(crate) fn queue_group_attachment_manifest(
        &mut self,
        group: &[u8; 32],
        content_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let mut rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let mut record = self
            .store
            .group_messages(group)?
            .into_iter()
            .find(|record| record.direction == Direction::Outbound && &record.id == content_id)
            .ok_or(NodeError::UnknownAttachment)?;
        if record
            .deliveries
            .iter()
            .any(|delivery| delivery.wire_id.is_some())
        {
            return Ok(false);
        }
        if record
            .deliveries
            .iter()
            .any(|delivery| !self.sessions.contains_key(&delivery.peer))
        {
            return Ok(false);
        }
        if rec.sent_since_rotation >= GROUP_ROTATE_MSGS {
            self.rotate_group(&mut rec, rng)?;
        }
        let mut chain = decode_chain(&rec.sender_chain)?;
        let hk = GroupHeaderKey::derive(&rec.secret);
        let wire = chain.seal(&hk, group, &pad(&record.body)?, rng).encode();
        rec.sender_chain = encode_chain(&chain)?;
        rec.sent_since_rotation += 1;
        for delivery in record.deliveries.iter_mut() {
            delivery.wire_id = self.queue_group_copy(
                &delivery.peer,
                &wire,
                record.id,
                QueueClass::Bulk,
                ephemeral_retention(&record.body),
                now,
                rng,
            )?;
            if delivery.wire_id.is_none() {
                return Ok(false);
            }
        }
        record.wire_body = None;
        self.store.update_group_message(&record, rng)?;
        self.store.put_group(&rec, rng)?;
        Ok(true)
    }

    /// Encrypt and queue one control payload to a peer over the pairwise
    /// session, initiating one from the stored bundle if none exists
    /// (announces to strangers ride right behind the handshake, like a
    /// first message does). `None` means the peer is unreachable *for now* —
    /// no bundle and no session; the announce plane's pacing retries.
    fn queue_group_control(
        &mut self,
        peer: &[u8; 32],
        payload: &GroupControlPayload,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Option<[u8; 16]>> {
        if !self.sessions.contains_key(peer) {
            let Some(contact) = self.store.get_contact(peer)? else {
                return Ok(None);
            };
            if contact.bundle.is_empty() {
                return Ok(None);
            }
            // An empty first flight; the control message rides behind it.
            let Ok(flight) = self.initiate_session(peer, &contact.bundle, &pad(&[])?, now, rng)
            else {
                return Ok(None); // e.g. the bundle expired — paced retry
            };
            self.store.queue_push(
                &QueueItem {
                    peer: *peer,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Normal,
                    envelope: flight,
                },
                rng,
            )?;
        }
        let session = self
            .sessions
            .get_mut(peer)
            .expect("session just ensured above");
        let bytes = zeroize::Zeroizing::new(payload.encode());
        let msg = session.encrypt(rng, now, &pad(&bytes)?, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            peer,
        );
        self.store.put_session(peer, session, rng)?;
        let envelope = Envelope::new(EnvelopeKind::GroupControl, token, msg.encode());
        let cid = envelope.content_id();
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                envelope,
            },
            rng,
        )?;
        Ok(Some(cid))
    }

    /// Roster members met only through an announce have identity but no
    /// bundle; where a discovery plane exists, their published prekey
    /// record makes them reachable (paced by the announce retry window).
    async fn resolve_group_peer_bundle(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if self.sessions.contains_key(peer) || self.discoveries.is_empty() {
            return Ok(());
        }
        let Some(mut contact) = self.store.get_contact(peer)? else {
            return Ok(());
        };
        if !contact.bundle.is_empty() {
            return Ok(());
        }
        let Ok(identity) = postcard::from_bytes::<IdentityPublic>(&contact.identity) else {
            return Ok(());
        };
        let Some(bundle) = self.lookup_bundle(identity.address_digest(), now).await else {
            return Ok(());
        };
        contact.hints = bundle.relay_hints.clone();
        contact.bundle = bundle.encode();
        self.store.put_contact(&contact, rng)?;
        Ok(())
    }
}

fn encode_chain(chain: &GroupSenderChain) -> Result<Vec<u8>> {
    postcard::to_allocvec(chain).map_err(|_| NodeError::CorruptState)
}

fn decode_chain(blob: &[u8]) -> Result<GroupSenderChain> {
    postcard::from_bytes(blob).map_err(|_| NodeError::CorruptState)
}

fn ephemeral_retention(body: &[u8]) -> Option<u64> {
    match decode_content(body) {
        DecodedContent::Ephemeral {
            ephemeral:
                Ephemeral::DisappearingText {
                    retention_until, ..
                }
                | Ephemeral::ViewOnceAttachment {
                    retention_until, ..
                },
            ..
        } => Some(retention_until),
        _ => None,
    }
}

/// Announce entries for every roster member but `me`, snapshotting `chain`
/// at its current state (the entitlement point).
fn pending_for(
    chain: &GroupSenderChain,
    members: impl Iterator<Item = [u8; 32]>,
    me: &[u8; 32],
) -> Vec<PendingAnnounce> {
    let (key_id, chain_key, iteration) = chain.snapshot();
    members
        .filter(|p| p != me)
        .map(|peer| PendingAnnounce {
            peer,
            key_id,
            chain_key: *chain_key,
            iteration,
            wire_id: None,
            last_sent: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use kult_crypto::KdfProfile;
    use kult_protocol::{
        CapabilityControl, FormatCapabilities, CONTENT_KIND_EDIT, CONTENT_KIND_TEXT,
    };

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn group_edit_requires_every_current_member_capability() {
        let mut rng = StdRng::seed_from_u64(0x00c3_0004);
        let directory = tempfile::tempdir().unwrap();
        let mut alice =
            Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
        let mut bob =
            Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(1_800_000_000, &mut rng).unwrap();
        let bob_peer = alice
            .add_contact("bob", &bob_bundle, &[], 1_800_000_000, &mut rng)
            .unwrap();
        let group = alice
            .create_group("old client", &[bob_peer], &mut rng)
            .unwrap();
        let alice_peer = alice.identity.public().ed;

        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "unsupported",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::EditUnsupported)
        ));

        let text_only = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_peer, &text_only, &mut rng)
            .unwrap();
        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "old client",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::EditUnsupported)
        ));

        let edit_capable = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT, CONTENT_KIND_EDIT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_peer, &edit_capable, &mut rng)
            .unwrap();
        assert!(matches!(
            alice.group_edit_message(
                &group,
                alice_peer,
                [9; 16],
                "missing target",
                1_800_000_001,
                &mut rng,
            ),
            Err(NodeError::InvalidEdit)
        ));
    }

    #[test]
    fn mention_intersection_fails_closed_on_downgrade_and_missing_snapshot() {
        let mut rng = StdRng::seed_from_u64(0xB17);
        let directory = tempfile::tempdir().unwrap();
        let mut alice =
            Node::create(&directory.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
        let mut bob =
            Node::create(&directory.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(1_800_000_000, &mut rng).unwrap();
        let bob_peer = alice
            .add_contact("same name", &bob_bundle, &[], 1_800_000_000, &mut rng)
            .unwrap();
        let group = alice
            .create_group("capabilities", &[bob_peer], &mut rng)
            .unwrap();

        let supported_snapshot = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT, CONTENT_KIND_MENTION],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_peer, &supported_snapshot, &mut rng)
            .unwrap();
        let supported = alice.group_mention_capability(&group).unwrap();
        assert!(supported.supported());

        let span = [MentionSpan {
            start: 0,
            end: 2,
            target: bob_peer,
        }];
        let mut renamed_contact = alice.store.get_contact(&bob_peer).unwrap().unwrap();
        renamed_contact.name = "\u{2067}同名\u{2069}".to_owned();
        alice.store.put_contact(&renamed_contact, &mut rng).unwrap();
        let renamed = alice.group_mention_capability(&group).unwrap();
        assert!(renamed.supported());
        assert_ne!(supported.review_token, renamed.review_token);
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                supported.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionReviewRequired)
        ));

        let downgraded_snapshot = CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT],
            }],
        };
        alice
            .store
            .put_capabilities(&bob_peer, &downgraded_snapshot, &mut rng)
            .unwrap();
        let downgraded = alice.group_mention_capability(&group).unwrap();
        assert_eq!(
            downgraded.issues,
            vec![MentionCapabilityIssue {
                peer: bob_peer,
                reason: MentionCapabilityIssueReason::Unsupported,
            }]
        );
        assert_ne!(renamed.review_token, downgraded.review_token);
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                renamed.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionReviewRequired)
        ));
        assert!(matches!(
            alice.group_send_mention(
                &group,
                "@b",
                &span,
                downgraded.review_token,
                1_800_000_001,
                &mut rng
            ),
            Err(NodeError::MentionUnsupported)
        ));

        alice.store.delete_capabilities(&bob_peer).unwrap();
        let missing = alice.group_mention_capability(&group).unwrap();
        assert_eq!(
            missing.issues,
            vec![MentionCapabilityIssue {
                peer: bob_peer,
                reason: MentionCapabilityIssueReason::Unknown,
            }]
        );
        assert_ne!(downgraded.review_token, missing.review_token);
    }
}
