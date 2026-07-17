//! Fuzz: Poll payload classification is total and canonical values re-encode.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use kult_protocol::{DecodedPoll, Poll};

    if let DecodedPoll::Poll(poll) = kult_protocol::decode_poll_payload(data) {
        let encoded = match poll {
            Poll::Create(create) => kult_protocol::encode_poll_create_payload(
                create.generation,
                create.question,
                &create.options().collect::<Vec<_>>(),
                &create.voters().collect::<Vec<_>>(),
            ),
            Poll::Vote(vote) => kult_protocol::encode_poll_vote_payload(&vote),
            Poll::Close(close) => kult_protocol::encode_poll_close_payload(
                close.poll_author,
                close.poll_id,
                &close.heads().collect::<Vec<_>>(),
            ),
            Poll::ModeratedClose(close) => kult_protocol::encode_poll_moderated_close_payload(
                close.group,
                close.poll_author,
                close.poll_id,
                close.authority_generation,
                &close.heads().collect::<Vec<_>>(),
                close.signature,
            ),
        }
        .unwrap();
        assert_eq!(encoded, data);
    }
});
