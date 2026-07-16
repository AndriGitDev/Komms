//! Derived authenticated group polls (ADR-0022).

use std::collections::HashMap;

use rand_core::CryptoRngCore;

use kult_protocol::{
    decode_content, encode_poll, encode_poll_close_payload, encode_poll_create_payload,
    encode_poll_vote_payload, DecodedContent, Poll, PollOption, PollVote, PollVoteHead,
    CONTENT_KIND_POLL, MAX_POLL_OPTIONS,
};
use kult_store::GroupMessageRecord;

use crate::{Node, NodeError, PollInfo, PollOptionInfo, PollVoteInfo, Result};

/// Maximum locally authored vote revisions per exact poll and identity.
pub const MAX_POLL_VOTE_REVISIONS: usize = 64;
const ID_RETRY_LIMIT: usize = 16;

#[derive(Clone)]
struct WorkingPoll {
    author: [u8; 32],
    id: [u8; 16],
    generation: u64,
    question: String,
    eligible_voters: Vec<[u8; 32]>,
    options: Vec<([u8; 16], String)>,
    votes: HashMap<[u8; 32], PollVoteInfo>,
    close: Option<([u8; 16], Vec<PollVoteInfo>)>,
}

impl Node {
    /// All valid polls for one group, in creation-event insertion order.
    pub fn group_polls(&self, group: &[u8; 32]) -> Result<Vec<PollInfo>> {
        self.store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        Ok(resolve_polls(
            *group,
            self.identity.public().ed,
            self.store.group_messages(group)?,
        ))
    }

    /// Create a visible-vote, single-choice poll over the exact current roster.
    pub fn group_create_poll(
        &mut self,
        group: &[u8; 32],
        question: &str,
        option_texts: &[String],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        if !rec.members.iter().any(|member| member.peer == me)
            || !(2..=MAX_POLL_OPTIONS).contains(&option_texts.len())
        {
            return Err(NodeError::InvalidPoll);
        }
        self.ensure_group_poll_support(
            &rec.members
                .iter()
                .map(|member| member.peer)
                .collect::<Vec<_>>(),
        )?;

        let existing_ids = self
            .store
            .group_messages(group)?
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        let id = mint_unique_id(rng, |candidate| existing_ids.contains(&candidate))?;
        let mut option_ids = Vec::with_capacity(option_texts.len());
        for _ in option_texts {
            option_ids.push(mint_unique_id(rng, |candidate| {
                option_ids.contains(&candidate)
            })?);
        }
        let options = option_ids
            .iter()
            .zip(option_texts)
            .map(|(id, text)| PollOption {
                id: *id,
                text: text.as_str(),
            })
            .collect::<Vec<_>>();
        let mut voters = rec
            .members
            .iter()
            .map(|member| member.peer)
            .collect::<Vec<_>>();
        voters.sort_unstable();
        voters.dedup();
        let payload = encode_poll_create_payload(rec.generation, question, &options, &voters)
            .map_err(|_| NodeError::InvalidPoll)?;
        let wire = encode_poll(id, &payload).map_err(|_| NodeError::InvalidPoll)?;
        self.group_send_content_with_id(group, wire, id, now, now, rng)
    }

    /// Cast or change this authenticated member's single choice.
    pub fn group_vote_poll(
        &mut self,
        group: &[u8; 32],
        poll_author: [u8; 32],
        poll_id: [u8; 16],
        option_id: [u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.ensure_group_poll_support(
            &rec.members
                .iter()
                .map(|member| member.peer)
                .collect::<Vec<_>>(),
        )?;
        let me = self.identity.public().ed;
        let poll = self
            .group_polls(group)?
            .into_iter()
            .find(|poll| poll.author == poll_author && poll.id == poll_id)
            .ok_or(NodeError::InvalidPoll)?;
        if poll.closed {
            return Err(NodeError::PollClosed);
        }
        if !poll.eligible_voters.contains(&me)
            || !poll.options.iter().any(|option| option.id == option_id)
        {
            return Err(NodeError::InvalidPoll);
        }
        let records = self.store.group_messages(group)?;
        let revisions = records
            .iter()
            .filter_map(|record| match decode_content(&record.body) {
                DecodedContent::Poll {
                    poll: Poll::Vote(vote),
                    ..
                } if record.sender == me
                    && vote.poll_author == poll_author
                    && vote.poll_id == poll_id =>
                {
                    Some(vote.revision)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if revisions.len() >= MAX_POLL_VOTE_REVISIONS {
            return Err(NodeError::PollVoteLimit);
        }
        let revision = revisions
            .into_iter()
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(NodeError::PollVoteLimit)?;
        let id = mint_unique_id(rng, |candidate| {
            records.iter().any(|record| record.id == candidate)
        })?;
        let payload = encode_poll_vote_payload(&PollVote {
            poll_author,
            poll_id,
            option_id,
            revision,
        })
        .map_err(|_| NodeError::InvalidPoll)?;
        let wire = encode_poll(id, &payload).map_err(|_| NodeError::InvalidPoll)?;
        self.group_send_content_with_id(group, wire, id, now, now, rng)
    }

    /// Irreversibly close this identity's poll with the exact current vote heads.
    pub fn group_close_poll(
        &mut self,
        group: &[u8; 32],
        poll_author: [u8; 32],
        poll_id: [u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let rec = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.ensure_group_poll_support(
            &rec.members
                .iter()
                .map(|member| member.peer)
                .collect::<Vec<_>>(),
        )?;
        let me = self.identity.public().ed;
        if me != poll_author {
            return Err(NodeError::NotPollCreator);
        }
        let poll = self
            .group_polls(group)?
            .into_iter()
            .find(|poll| poll.author == poll_author && poll.id == poll_id)
            .ok_or(NodeError::InvalidPoll)?;
        if poll.closed {
            return Err(NodeError::PollClosed);
        }
        let heads = poll
            .votes
            .iter()
            .map(|vote| PollVoteHead {
                voter: vote.voter,
                event_id: vote.event_id,
                option_id: vote.option_id,
                revision: vote.revision,
            })
            .collect::<Vec<_>>();
        let records = self.store.group_messages(group)?;
        let id = mint_unique_id(rng, |candidate| {
            records.iter().any(|record| record.id == candidate)
        })?;
        let payload = encode_poll_close_payload(poll_author, poll_id, &heads)
            .map_err(|_| NodeError::InvalidPoll)?;
        let wire = encode_poll(id, &payload).map_err(|_| NodeError::InvalidPoll)?;
        self.group_send_content_with_id(group, wire, id, now, now, rng)
    }

    fn ensure_group_poll_support(&self, members: &[[u8; 32]]) -> Result<()> {
        let me = self.identity.public().ed;
        for peer in members.iter().filter(|peer| **peer != me) {
            if !self.peer_supports_kind(peer, CONTENT_KIND_POLL)? {
                return Err(NodeError::PollUnsupported);
            }
        }
        Ok(())
    }
}

fn mint_unique_id(
    rng: &mut impl CryptoRngCore,
    collision: impl Fn([u8; 16]) -> bool,
) -> Result<[u8; 16]> {
    for _ in 0..ID_RETRY_LIMIT {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        if !collision(id) {
            return Ok(id);
        }
    }
    Err(NodeError::InvalidPoll)
}

fn resolve_polls(
    group: [u8; 32],
    local_peer: [u8; 32],
    records: Vec<GroupMessageRecord>,
) -> Vec<PollInfo> {
    let mut polls = Vec::<WorkingPoll>::new();
    let mut indexes = HashMap::<([u8; 32], [u8; 16]), usize>::new();
    for record in &records {
        let DecodedContent::Poll {
            id,
            poll: Poll::Create(create),
        } = decode_content(&record.body)
        else {
            continue;
        };
        let eligible_voters = create.voters().collect::<Vec<_>>();
        if !eligible_voters.contains(&record.sender) || indexes.contains_key(&(record.sender, id)) {
            continue;
        }
        let index = polls.len();
        indexes.insert((record.sender, id), index);
        polls.push(WorkingPoll {
            author: record.sender,
            id,
            generation: create.generation,
            question: create.question.to_owned(),
            eligible_voters,
            options: create
                .options()
                .map(|option| (option.id, option.text.to_owned()))
                .collect(),
            votes: HashMap::new(),
            close: None,
        });
    }

    for record in &records {
        let DecodedContent::Poll { id, poll } = decode_content(&record.body) else {
            continue;
        };
        match poll {
            Poll::Vote(vote) => {
                let Some(index) = indexes.get(&(vote.poll_author, vote.poll_id)).copied() else {
                    continue;
                };
                let working = &mut polls[index];
                if !working.eligible_voters.contains(&record.sender)
                    || !working
                        .options
                        .iter()
                        .any(|(option, _)| *option == vote.option_id)
                {
                    continue;
                }
                let candidate = PollVoteInfo {
                    voter: record.sender,
                    event_id: id,
                    option_id: vote.option_id,
                    revision: vote.revision,
                };
                let replace = working.votes.get(&record.sender).is_none_or(|current| {
                    (candidate.revision, candidate.event_id) > (current.revision, current.event_id)
                });
                if replace {
                    working.votes.insert(record.sender, candidate);
                }
            }
            Poll::Close(close) if record.sender == close.poll_author => {
                let Some(index) = indexes.get(&(close.poll_author, close.poll_id)).copied() else {
                    continue;
                };
                let working = &mut polls[index];
                let heads = close
                    .heads()
                    .map(|head| PollVoteInfo {
                        voter: head.voter,
                        event_id: head.event_id,
                        option_id: head.option_id,
                        revision: head.revision,
                    })
                    .collect::<Vec<_>>();
                if heads.iter().any(|head| {
                    !working.eligible_voters.contains(&head.voter)
                        || !working
                            .options
                            .iter()
                            .any(|(option, _)| *option == head.option_id)
                }) {
                    continue;
                }
                if working
                    .close
                    .as_ref()
                    .is_none_or(|(current, _)| id < *current)
                {
                    working.close = Some((id, heads));
                }
            }
            _ => {}
        }
    }

    polls
        .into_iter()
        .map(|working| {
            let (close_event_id, mut votes) = match working.close {
                Some((id, heads)) => (Some(id), heads),
                None => (None, working.votes.into_values().collect()),
            };
            votes.sort_unstable_by_key(|vote| vote.voter);
            let options = working
                .options
                .into_iter()
                .map(|(id, text)| PollOptionInfo {
                    id,
                    text,
                    votes: votes.iter().filter(|vote| vote.option_id == id).count() as u32,
                    selected_by_me: votes
                        .iter()
                        .any(|vote| vote.voter == local_peer && vote.option_id == id),
                })
                .collect();
            let closed = close_event_id.is_some();
            PollInfo {
                group,
                author: working.author,
                id: working.id,
                generation: working.generation,
                question: working.question,
                eligible: working.eligible_voters.contains(&local_peer),
                can_close: working.author == local_peer && !closed,
                eligible_voters: working.eligible_voters,
                options,
                votes,
                closed,
                close_event_id,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_protocol::{
        encode_poll_close_payload, encode_poll_create_payload, encode_poll_vote_payload,
    };
    use kult_store::{Direction, GroupDelivery};

    const GROUP: [u8; 32] = [0x10; 32];
    const AUTHOR: [u8; 32] = [0x20; 32];
    const VOTER: [u8; 32] = [0x30; 32];
    const OUTSIDER: [u8; 32] = [0x40; 32];
    const POLL_ID: [u8; 16] = [0x50; 16];
    const OPTION_A: [u8; 16] = [0x60; 16];
    const OPTION_B: [u8; 16] = [0x70; 16];

    fn record(sender: [u8; 32], id: [u8; 16], payload: Vec<u8>) -> GroupMessageRecord {
        GroupMessageRecord {
            id,
            group: GROUP,
            sender,
            direction: Direction::Inbound,
            timestamp: 1,
            body: encode_poll(id, &payload).unwrap(),
            deliveries: Vec::<GroupDelivery>::new(),
            wire_body: None,
        }
    }

    fn create() -> GroupMessageRecord {
        record(
            AUTHOR,
            POLL_ID,
            encode_poll_create_payload(
                9,
                "Pick one",
                &[
                    PollOption {
                        id: OPTION_A,
                        text: "A",
                    },
                    PollOption {
                        id: OPTION_B,
                        text: "B",
                    },
                ],
                &[AUTHOR, VOTER],
            )
            .unwrap(),
        )
    }

    fn vote(
        sender: [u8; 32],
        event_id: [u8; 16],
        option: [u8; 16],
        revision: u64,
    ) -> GroupMessageRecord {
        record(
            sender,
            event_id,
            encode_poll_vote_payload(&PollVote {
                poll_author: AUTHOR,
                poll_id: POLL_ID,
                option_id: option,
                revision,
            })
            .unwrap(),
        )
    }

    #[test]
    fn revisions_duplicates_reordering_and_outsiders_converge() {
        let records = vec![
            create(),
            vote(VOTER, [1; 16], OPTION_A, 1),
            vote(VOTER, [2; 16], OPTION_B, 2),
            vote(VOTER, [3; 16], OPTION_A, 2),
            vote(OUTSIDER, [9; 16], OPTION_B, 99),
            vote(VOTER, [3; 16], OPTION_A, 2),
        ];
        let expected = resolve_polls(GROUP, VOTER, records.clone());
        let mut reordered = records;
        reordered.reverse();
        let actual = resolve_polls(GROUP, VOTER, reordered);
        assert_eq!(actual, expected);
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[0].votes.len(), 1);
        assert_eq!(expected[0].votes[0].option_id, OPTION_A);
        assert_eq!(expected[0].votes[0].revision, 2);
        assert_eq!(expected[0].options[0].votes, 1);
        assert!(expected[0].options[0].selected_by_me);
        assert!(!expected[0].closed);
    }

    #[test]
    fn smallest_valid_close_snapshot_freezes_the_final_tally() {
        let close_b = record(
            AUTHOR,
            [4; 16],
            encode_poll_close_payload(
                AUTHOR,
                POLL_ID,
                &[PollVoteHead {
                    voter: VOTER,
                    event_id: [2; 16],
                    option_id: OPTION_B,
                    revision: 2,
                }],
            )
            .unwrap(),
        );
        let close_a = record(
            AUTHOR,
            [5; 16],
            encode_poll_close_payload(
                AUTHOR,
                POLL_ID,
                &[PollVoteHead {
                    voter: VOTER,
                    event_id: [3; 16],
                    option_id: OPTION_A,
                    revision: 3,
                }],
            )
            .unwrap(),
        );
        let poll = resolve_polls(
            GROUP,
            AUTHOR,
            vec![
                close_a,
                vote(VOTER, [3; 16], OPTION_A, 3),
                create(),
                close_b,
            ],
        )
        .remove(0);
        assert!(poll.closed);
        assert_eq!(poll.close_event_id, Some([4; 16]));
        assert_eq!(poll.votes[0].option_id, OPTION_B);
        assert_eq!(poll.options[1].votes, 1);
        assert!(!poll.can_close);
    }

    #[test]
    fn creation_time_electorate_is_stable_and_visible() {
        let poll = resolve_polls(GROUP, OUTSIDER, vec![create()]).remove(0);
        assert_eq!(poll.generation, 9);
        assert_eq!(poll.eligible_voters, vec![AUTHOR, VOTER]);
        assert!(!poll.eligible);
        assert!(!poll.can_close);
    }
}
