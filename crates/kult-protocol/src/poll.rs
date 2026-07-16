//! Canonical group-poll payloads (ADR-0022).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// First and only supported poll payload version.
pub const POLL_VERSION: u8 = 1;
/// Creator-authored manual close with an explicit final vote-head snapshot.
pub const POLL_CLOSE_MANUAL: u8 = 1;
/// Maximum exact UTF-8 poll question length.
pub const MAX_POLL_QUESTION_LEN: usize = 1_024;
/// Minimum number of choices in a poll.
pub const MIN_POLL_OPTIONS: usize = 2;
/// Maximum number of choices in a poll.
pub const MAX_POLL_OPTIONS: usize = 12;
/// Maximum exact UTF-8 option text length.
pub const MAX_POLL_OPTION_TEXT_LEN: usize = 256;
/// Maximum creation-time electorate size.
pub const MAX_POLL_VOTERS: usize = 64;

const OP_CREATE: u8 = 1;
const OP_VOTE: u8 = 2;
const OP_CLOSE: u8 = 3;
const COMMON_HEADER_LEN: usize = 4;
const CREATE_HEADER_LEN: usize = COMMON_HEADER_LEN + 8 + 2 + 1 + 1;
const VOTE_LEN: usize = COMMON_HEADER_LEN + 32 + 16 + 16 + 8;
const CLOSE_HEADER_LEN: usize = COMMON_HEADER_LEN + 32 + 16 + 1 + 3;
const CLOSE_HEAD_LEN: usize = 32 + 16 + 16 + 8;

/// Caller-provided stable choice for poll creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollOption<'a> {
    /// Random author-minted option id, scoped to this poll.
    pub id: [u8; 16],
    /// Exact UTF-8 label.
    pub text: &'a str,
}

/// One authenticated member's candidate vote event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollVote {
    /// Poll creator identity.
    pub poll_author: [u8; 32],
    /// Creator-minted poll id (the creation content id).
    pub poll_id: [u8; 16],
    /// Selected stable option id.
    pub option_id: [u8; 16],
    /// Positive voter-local monotonic revision.
    pub revision: u64,
}

/// One creator-attested final vote head carried by manual closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollVoteHead {
    /// Eligible authenticated voter.
    pub voter: [u8; 32],
    /// Exact vote event content id accepted by the creator.
    pub event_id: [u8; 16],
    /// Selected stable option id.
    pub option_id: [u8; 16],
    /// Positive voter-local revision.
    pub revision: u64,
}

/// Borrowed, validated poll creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollCreate<'a> {
    /// Exact sender-key group roster generation at creation.
    pub generation: u64,
    /// Exact UTF-8 question.
    pub question: &'a str,
    option_bytes: &'a [u8],
    option_count: u8,
    voter_bytes: &'a [u8],
}

impl<'a> PollCreate<'a> {
    /// Choices in stable author presentation order.
    pub fn options(&self) -> PollOptions<'a> {
        PollOptions {
            bytes: self.option_bytes,
            remaining: self.option_count,
        }
    }

    /// Sorted creation-time electorate.
    pub fn voters(&self) -> PollVoters<'a> {
        PollVoters {
            bytes: self.voter_bytes,
        }
    }
}

/// Iterator over a validated poll's choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollOptions<'a> {
    bytes: &'a [u8],
    remaining: u8,
}

impl<'a> Iterator for PollOptions<'a> {
    type Item = PollOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&self.bytes[..16]);
        let len = u16::from_le_bytes([self.bytes[16], self.bytes[17]]) as usize;
        let text =
            core::str::from_utf8(&self.bytes[18..18 + len]).expect("poll option was validated");
        self.bytes = &self.bytes[18 + len..];
        self.remaining -= 1;
        Some(PollOption { id, text })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PollOptions<'_> {}

/// Iterator over a validated, sorted creation-time electorate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollVoters<'a> {
    bytes: &'a [u8],
}

impl Iterator for PollVoters<'_> {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let mut voter = [0u8; 32];
        voter.copy_from_slice(&self.bytes[..32]);
        self.bytes = &self.bytes[32..];
        Some(voter)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bytes.len() / 32;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PollVoters<'_> {}

/// Borrowed, validated creator-authored closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollClose<'a> {
    /// Poll creator identity; it must match the authenticated event sender.
    pub poll_author: [u8; 32],
    /// Creator-minted poll id.
    pub poll_id: [u8; 16],
    head_bytes: &'a [u8],
}

impl<'a> PollClose<'a> {
    /// Sorted creator-attested final vote heads.
    pub fn heads(&self) -> PollVoteHeads<'a> {
        PollVoteHeads {
            bytes: self.head_bytes,
        }
    }
}

/// Iterator over validated final vote heads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollVoteHeads<'a> {
    bytes: &'a [u8],
}

impl Iterator for PollVoteHeads<'_> {
    type Item = PollVoteHead;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let bytes = &self.bytes[..CLOSE_HEAD_LEN];
        let mut voter = [0u8; 32];
        voter.copy_from_slice(&bytes[..32]);
        let mut event_id = [0u8; 16];
        event_id.copy_from_slice(&bytes[32..48]);
        let mut option_id = [0u8; 16];
        option_id.copy_from_slice(&bytes[48..64]);
        let revision = u64::from_le_bytes(bytes[64..72].try_into().expect("fixed slice"));
        self.bytes = &self.bytes[CLOSE_HEAD_LEN..];
        Some(PollVoteHead {
            voter,
            event_id,
            option_id,
            revision,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bytes.len() / CLOSE_HEAD_LEN;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PollVoteHeads<'_> {}

/// One canonical poll event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll<'a> {
    /// Create a single-choice poll with a fixed electorate.
    Create(PollCreate<'a>),
    /// Replace this authenticated member's earlier vote by deterministic order.
    Vote(PollVote),
    /// Irreversibly close using the creator's exact accepted vote heads.
    Close(PollClose<'a>),
}

/// Total classification of an authenticated poll payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedPoll<'a> {
    /// Canonical supported poll event.
    Poll(Poll<'a>),
    /// A future poll payload version that must remain opaque.
    Unsupported,
    /// Payload violates ADR-0022.
    Malformed,
}

/// Encode a canonical poll creation payload.
pub fn encode_poll_create_payload(
    generation: u64,
    question: &str,
    options: &[PollOption<'_>],
    voters: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let question_bytes = question.as_bytes();
    if generation == 0
        || question_bytes.is_empty()
        || question_bytes.len() > MAX_POLL_QUESTION_LEN
        || !(MIN_POLL_OPTIONS..=MAX_POLL_OPTIONS).contains(&options.len())
        || voters.is_empty()
        || voters.len() > MAX_POLL_VOTERS
        || !strictly_sorted_voters(voters.iter().copied())
    {
        return Err(ProtocolError::Malformed);
    }
    for (index, option) in options.iter().enumerate() {
        if option.text.is_empty()
            || option.text.len() > MAX_POLL_OPTION_TEXT_LEN
            || options[..index]
                .iter()
                .any(|earlier| earlier.id == option.id)
        {
            return Err(if option.text.len() > MAX_POLL_OPTION_TEXT_LEN {
                ProtocolError::TooLarge
            } else {
                ProtocolError::Malformed
            });
        }
    }
    let options_len = options
        .iter()
        .try_fold(0usize, |sum, option| {
            sum.checked_add(18 + option.text.len())
        })
        .ok_or(ProtocolError::TooLarge)?;
    let capacity = CREATE_HEADER_LEN
        .checked_add(question_bytes.len())
        .and_then(|value| value.checked_add(options_len))
        .and_then(|value| value.checked_add(voters.len() * 32))
        .ok_or(ProtocolError::TooLarge)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&[POLL_VERSION, OP_CREATE, POLL_CLOSE_MANUAL, 0]);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&(question_bytes.len() as u16).to_le_bytes());
    out.push(options.len() as u8);
    out.push(voters.len() as u8);
    out.extend_from_slice(question_bytes);
    for option in options {
        out.extend_from_slice(&option.id);
        out.extend_from_slice(&(option.text.len() as u16).to_le_bytes());
        out.extend_from_slice(option.text.as_bytes());
    }
    for voter in voters {
        out.extend_from_slice(voter);
    }
    Ok(out)
}

/// Encode a canonical poll vote payload.
pub fn encode_poll_vote_payload(vote: &PollVote) -> Result<Vec<u8>> {
    if vote.revision == 0 {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Vec::with_capacity(VOTE_LEN);
    out.extend_from_slice(&[POLL_VERSION, OP_VOTE, 0, 0]);
    out.extend_from_slice(&vote.poll_author);
    out.extend_from_slice(&vote.poll_id);
    out.extend_from_slice(&vote.option_id);
    out.extend_from_slice(&vote.revision.to_le_bytes());
    Ok(out)
}

/// Encode a canonical creator-authored manual close payload.
pub fn encode_poll_close_payload(
    poll_author: [u8; 32],
    poll_id: [u8; 16],
    heads: &[PollVoteHead],
) -> Result<Vec<u8>> {
    if heads.len() > MAX_POLL_VOTERS
        || !strictly_sorted_voters(heads.iter().map(|head| head.voter))
        || heads.iter().any(|head| head.revision == 0)
    {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Vec::with_capacity(CLOSE_HEADER_LEN + heads.len() * CLOSE_HEAD_LEN);
    out.extend_from_slice(&[POLL_VERSION, OP_CLOSE, 0, 0]);
    out.extend_from_slice(&poll_author);
    out.extend_from_slice(&poll_id);
    out.push(heads.len() as u8);
    out.extend_from_slice(&[0; 3]);
    for head in heads {
        out.extend_from_slice(&head.voter);
        out.extend_from_slice(&head.event_id);
        out.extend_from_slice(&head.option_id);
        out.extend_from_slice(&head.revision.to_le_bytes());
    }
    Ok(out)
}

/// Decode and validate one poll payload without allocating.
pub fn decode_poll_payload(bytes: &[u8]) -> DecodedPoll<'_> {
    if bytes.len() < COMMON_HEADER_LEN {
        return DecodedPoll::Malformed;
    }
    if bytes[0] != POLL_VERSION {
        return DecodedPoll::Unsupported;
    }
    match bytes[1] {
        OP_CREATE => decode_create(bytes),
        OP_VOTE => decode_vote(bytes),
        OP_CLOSE => decode_close(bytes),
        _ => DecodedPoll::Malformed,
    }
}

fn decode_create(bytes: &[u8]) -> DecodedPoll<'_> {
    if bytes.len() < CREATE_HEADER_LEN || bytes[2] != POLL_CLOSE_MANUAL || bytes[3] != 0 {
        return DecodedPoll::Malformed;
    }
    let generation = u64::from_le_bytes(bytes[4..12].try_into().expect("fixed slice"));
    let question_len = u16::from_le_bytes([bytes[12], bytes[13]]) as usize;
    let option_count = bytes[14] as usize;
    let voter_count = bytes[15] as usize;
    if generation == 0
        || question_len == 0
        || question_len > MAX_POLL_QUESTION_LEN
        || !(MIN_POLL_OPTIONS..=MAX_POLL_OPTIONS).contains(&option_count)
        || voter_count == 0
        || voter_count > MAX_POLL_VOTERS
        || CREATE_HEADER_LEN + question_len > bytes.len()
    {
        return DecodedPoll::Malformed;
    }
    let question_end = CREATE_HEADER_LEN + question_len;
    let Ok(question) = core::str::from_utf8(&bytes[CREATE_HEADER_LEN..question_end]) else {
        return DecodedPoll::Malformed;
    };
    let mut cursor = question_end;
    let options_start = cursor;
    let mut ids = [[0u8; 16]; MAX_POLL_OPTIONS];
    for index in 0..option_count {
        if cursor + 18 > bytes.len() {
            return DecodedPoll::Malformed;
        }
        ids[index].copy_from_slice(&bytes[cursor..cursor + 16]);
        if ids[..index].contains(&ids[index]) {
            return DecodedPoll::Malformed;
        }
        let len = u16::from_le_bytes([bytes[cursor + 16], bytes[cursor + 17]]) as usize;
        cursor += 18;
        if len == 0 || len > MAX_POLL_OPTION_TEXT_LEN || cursor + len > bytes.len() {
            return DecodedPoll::Malformed;
        }
        if core::str::from_utf8(&bytes[cursor..cursor + len]).is_err() {
            return DecodedPoll::Malformed;
        }
        cursor += len;
    }
    let voters_len = match voter_count.checked_mul(32) {
        Some(value) => value,
        None => return DecodedPoll::Malformed,
    };
    if cursor + voters_len != bytes.len() {
        return DecodedPoll::Malformed;
    }
    let voter_bytes = &bytes[cursor..];
    if !strictly_sorted_voters(voter_bytes.chunks_exact(32).map(|chunk| {
        let mut voter = [0u8; 32];
        voter.copy_from_slice(chunk);
        voter
    })) {
        return DecodedPoll::Malformed;
    }
    DecodedPoll::Poll(Poll::Create(PollCreate {
        generation,
        question,
        option_bytes: &bytes[options_start..cursor],
        option_count: option_count as u8,
        voter_bytes,
    }))
}

fn decode_vote(bytes: &[u8]) -> DecodedPoll<'_> {
    if bytes.len() != VOTE_LEN || bytes[2] != 0 || bytes[3] != 0 {
        return DecodedPoll::Malformed;
    }
    let mut poll_author = [0u8; 32];
    poll_author.copy_from_slice(&bytes[4..36]);
    let mut poll_id = [0u8; 16];
    poll_id.copy_from_slice(&bytes[36..52]);
    let mut option_id = [0u8; 16];
    option_id.copy_from_slice(&bytes[52..68]);
    let revision = u64::from_le_bytes(bytes[68..76].try_into().expect("fixed slice"));
    if revision == 0 {
        return DecodedPoll::Malformed;
    }
    DecodedPoll::Poll(Poll::Vote(PollVote {
        poll_author,
        poll_id,
        option_id,
        revision,
    }))
}

fn decode_close(bytes: &[u8]) -> DecodedPoll<'_> {
    if bytes.len() < CLOSE_HEADER_LEN || bytes[2] != 0 || bytes[3] != 0 {
        return DecodedPoll::Malformed;
    }
    let mut poll_author = [0u8; 32];
    poll_author.copy_from_slice(&bytes[4..36]);
    let mut poll_id = [0u8; 16];
    poll_id.copy_from_slice(&bytes[36..52]);
    let count = bytes[52] as usize;
    if count > MAX_POLL_VOTERS
        || bytes[53..56] != [0; 3]
        || CLOSE_HEADER_LEN + count * CLOSE_HEAD_LEN != bytes.len()
    {
        return DecodedPoll::Malformed;
    }
    let head_bytes = &bytes[CLOSE_HEADER_LEN..];
    let mut previous = None;
    for chunk in head_bytes.chunks_exact(CLOSE_HEAD_LEN) {
        let mut voter = [0u8; 32];
        voter.copy_from_slice(&chunk[..32]);
        if previous.is_some_and(|value| value >= voter) {
            return DecodedPoll::Malformed;
        }
        previous = Some(voter);
        let revision = u64::from_le_bytes(chunk[64..72].try_into().expect("fixed slice"));
        if revision == 0 {
            return DecodedPoll::Malformed;
        }
    }
    DecodedPoll::Poll(Poll::Close(PollClose {
        poll_author,
        poll_id,
        head_bytes,
    }))
}

fn strictly_sorted_voters(voters: impl IntoIterator<Item = [u8; 32]>) -> bool {
    let mut previous = None;
    for voter in voters {
        if previous.is_some_and(|value| value >= voter) {
            return false;
        }
        previous = Some(voter);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn creation() -> Vec<u8> {
        encode_poll_create_payload(
            7,
            "Lunch?",
            &[
                PollOption {
                    id: [0x11; 16],
                    text: "Soup",
                },
                PollOption {
                    id: [0x22; 16],
                    text: "Salad",
                },
            ],
            &[[0x33; 32], [0x44; 32]],
        )
        .unwrap()
    }

    #[test]
    fn creation_round_trips_exact_order_and_unicode() {
        let encoded = creation();
        let DecodedPoll::Poll(Poll::Create(create)) = decode_poll_payload(&encoded) else {
            panic!("creation must decode");
        };
        assert_eq!(create.generation, 7);
        assert_eq!(create.question, "Lunch?");
        assert_eq!(
            create.options().collect::<Vec<_>>(),
            vec![
                PollOption {
                    id: [0x11; 16],
                    text: "Soup"
                },
                PollOption {
                    id: [0x22; 16],
                    text: "Salad"
                }
            ]
        );
        assert_eq!(
            create.voters().collect::<Vec<_>>(),
            vec![[0x33; 32], [0x44; 32]]
        );
    }

    #[test]
    fn vote_and_close_round_trip() {
        let vote = PollVote {
            poll_author: [1; 32],
            poll_id: [2; 16],
            option_id: [3; 16],
            revision: 9,
        };
        let encoded = encode_poll_vote_payload(&vote).unwrap();
        assert_eq!(
            decode_poll_payload(&encoded),
            DecodedPoll::Poll(Poll::Vote(vote))
        );

        let heads = [PollVoteHead {
            voter: [4; 32],
            event_id: [5; 16],
            option_id: [3; 16],
            revision: 9,
        }];
        let encoded = encode_poll_close_payload([1; 32], [2; 16], &heads).unwrap();
        let DecodedPoll::Poll(Poll::Close(close)) = decode_poll_payload(&encoded) else {
            panic!("close must decode");
        };
        assert_eq!(close.poll_author, [1; 32]);
        assert_eq!(close.poll_id, [2; 16]);
        assert_eq!(close.heads().collect::<Vec<_>>(), heads);
    }

    #[test]
    fn canonical_constraints_reject_ambiguous_payloads() {
        let options = [
            PollOption {
                id: [1; 16],
                text: "a",
            },
            PollOption {
                id: [1; 16],
                text: "b",
            },
        ];
        assert!(encode_poll_create_payload(1, "q", &options, &[[1; 32]]).is_err());
        assert!(encode_poll_create_payload(1, "q", &options[..1], &[[1; 32]]).is_err());
        assert!(encode_poll_create_payload(
            1,
            "q",
            &[
                PollOption {
                    id: [1; 16],
                    text: "a"
                },
                PollOption {
                    id: [2; 16],
                    text: "b"
                },
            ],
            &[[2; 32], [1; 32]]
        )
        .is_err());
        let mut trailing = creation();
        trailing.push(0);
        assert_eq!(decode_poll_payload(&trailing), DecodedPoll::Malformed);
        assert!(encode_poll_vote_payload(&PollVote {
            poll_author: [1; 32],
            poll_id: [2; 16],
            option_id: [3; 16],
            revision: 0,
        })
        .is_err());
    }

    #[test]
    fn future_poll_payload_version_is_unsupported_not_malformed() {
        assert_eq!(
            decode_poll_payload(&[POLL_VERSION + 1, OP_VOTE, 0, 0]),
            DecodedPoll::Unsupported
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let _ = decode_poll_payload(&bytes);
        }
    }
}
