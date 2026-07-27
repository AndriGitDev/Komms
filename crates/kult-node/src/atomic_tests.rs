use std::path::PathBuf;

use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_protocol::{Envelope, EnvelopeKind};
use kult_store::{CommitFailpoint, CommitFailure, DeliveryState};

use super::*;

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Clone, Copy, Debug)]
enum Target {
    PairwiseSend,
    HandshakeReceive,
    PairwiseReceive,
    ReceiptReceive,
    Maintenance,
    MaintenanceReset,
    MaintenanceExpiry,
}

struct Fixture {
    _directory: tempfile::TempDir,
    alice_path: PathBuf,
    bob_path: PathBuf,
    alice: Node,
    bob: Node,
    alice_id: [u8; 32],
    bob_id: [u8; 32],
    rng: StdRng,
}

impl Fixture {
    fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let directory = tempfile::tempdir().unwrap();
        let alice_path = directory.path().join("alice.db");
        let bob_path = directory.path().join("bob.db");
        let mut alice = Node::create(&alice_path, b"alice", TEST_KDF, &mut rng).unwrap();
        let mut bob = Node::create(&bob_path, b"bob", TEST_KDF, &mut rng).unwrap();
        let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
        let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
        let bob_id = alice
            .add_contact("bob", &bob_bundle, &[], NOW, &mut rng)
            .unwrap();
        let alice_id = bob
            .add_contact("alice", &alice_bundle, &[], NOW, &mut rng)
            .unwrap();
        Self {
            _directory: directory,
            alice_path,
            bob_path,
            alice,
            bob,
            alice_id,
            bob_id,
            rng,
        }
    }

    fn establish(&mut self) {
        let first_id = [0x11; 16];
        self.alice
            .send_message_with_id(
                &self.bob_id,
                b"first",
                first_id,
                NOW + 1,
                NOW + 1,
                &mut self.rng,
            )
            .unwrap();
        let handshake = queued_message(&self.alice, first_id);
        consume(&mut self.bob, &handshake, None, NOW + 2, &mut self.rng).unwrap();
        let (receipt_sequence, receipt) = queued_control(&self.bob);
        consume(&mut self.alice, &receipt, None, NOW + 3, &mut self.rng).unwrap();
        self.bob.store.queue_ack(receipt_sequence).unwrap();
        self.alice.drain_events();
        self.bob.drain_events();
    }
}

fn queued_message(node: &Node, id: [u8; 16]) -> Envelope {
    node.store
        .queue_all()
        .unwrap()
        .into_iter()
        .find_map(|(_, item)| (item.msg_id == Some(id)).then_some(item.envelope))
        .expect("message envelope")
}

fn queued_control(node: &Node) -> (i64, Envelope) {
    node.store
        .queue_all()
        .unwrap()
        .into_iter()
        .rev()
        .find_map(|(sequence, item)| {
            (item.msg_id.is_none()
                && item.group_msg_id.is_none()
                && item.envelope.kind == EnvelopeKind::Receipt)
                .then_some((sequence, item.envelope))
        })
        .expect("control envelope")
}

fn pending_contains(node: &Node, sequence: i64, content_id: [u8; 16]) -> bool {
    node.store
        .pending_all()
        .unwrap()
        .iter()
        .any(|(candidate_sequence, envelope, _)| {
            *candidate_sequence == sequence && envelope.content_id() == content_id
        })
}

fn consume(
    node: &mut Node,
    envelope: &Envelope,
    pending_sequence: Option<i64>,
    now: u64,
    rng: &mut StdRng,
) -> Result<Consumed> {
    let mut acks = Vec::new();
    let mut established = false;
    node.consume(
        envelope,
        ConsumeOrigin {
            depth: 0,
            pending_sequence,
        },
        now,
        rng,
        &mut acks,
        &mut established,
    )
}

fn run_store_case(
    target: Target,
    point: CommitFailpoint,
    failure: CommitFailure,
    seed: u64,
) -> bool {
    match target {
        Target::PairwiseSend => run_pairwise_send(point, failure, seed),
        Target::HandshakeReceive => run_handshake_receive(point, failure, seed),
        Target::PairwiseReceive => run_pairwise_receive(point, failure, seed),
        Target::ReceiptReceive => run_receipt_receive(point, failure, seed),
        Target::Maintenance => run_maintenance(point, failure, seed),
        Target::MaintenanceReset => run_maintenance_reset(point, failure, seed),
        Target::MaintenanceExpiry => run_maintenance_expiry(point, failure, seed),
    }
}

fn expected_committed(result_ok: bool, point: CommitFailpoint) -> bool {
    result_ok || point == CommitFailpoint::AfterCommit
}

fn run_pairwise_send(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x21; 16];
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.send_message_with_id(
        &fixture.bob_id,
        b"planned send",
        id,
        NOW + 10,
        NOW + 10,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture
        .alice
        .store
        .messages_with(&fixture.bob_id)
        .unwrap()
        .iter()
        .any(|message| message.id == id);
    let queued = fixture
        .alice
        .store
        .queue_all()
        .unwrap()
        .iter()
        .filter(|(_, item)| item.msg_id == Some(id))
        .count();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(queued, usize::from(committed));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    let session_before = alice.store.get_session(&bob_id).unwrap().unwrap();
    let retry =
        alice.send_message_with_id(&bob_id, b"planned send", id, NOW + 10, NOW + 10, &mut rng);
    if committed {
        assert!(retry.is_err());
        assert_eq!(
            postcard::to_allocvec(&session_before).unwrap(),
            postcard::to_allocvec(&alice.store.get_session(&bob_id).unwrap().unwrap()).unwrap()
        );
    } else {
        retry.unwrap();
    }
    assert_eq!(
        alice
            .store
            .messages_with(&bob_id)
            .unwrap()
            .iter()
            .filter(|message| message.id == id)
            .count(),
        1
    );
    assert_eq!(
        alice
            .store
            .queue_all()
            .unwrap()
            .iter()
            .filter(|(_, item)| item.msg_id == Some(id))
            .count(),
        1
    );
    result_ok
}

fn run_handshake_receive(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let id = [0x31; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"handshake payload",
            id,
            NOW + 1,
            NOW + 1,
            &mut fixture.rng,
        )
        .unwrap();
    let envelope = queued_message(&fixture.alice, id);
    let content_id = envelope.content_id();
    let pending_sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 1, &mut fixture.rng)
        .unwrap();
    let prekeys_before = fixture.bob.store.get_prekeys().unwrap().unwrap();
    fixture.bob.arm_commit_failpoint(point, failure);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(pending_sequence),
        NOW + 2,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        pending_contains(&fixture.bob, pending_sequence, content_id),
        !committed
    );
    assert_eq!(
        fixture
            .bob
            .store
            .messages_with(&fixture.alice_id)
            .unwrap()
            .len(),
        usize::from(committed)
    );
    assert_eq!(
        fixture
            .bob
            .store
            .get_session(&fixture.alice_id)
            .unwrap()
            .is_some(),
        committed
    );
    assert_eq!(
        fixture.bob.store.get_prekeys().unwrap().unwrap() != prekeys_before,
        committed
    );

    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(
        &mut bob,
        &envelope,
        (!committed).then_some(pending_sequence),
        NOW + 3,
        &mut rng,
    )
    .unwrap();
    assert_eq!(bob.store.messages_with(&alice_id).unwrap().len(), 1);
    assert!(!pending_contains(&bob, pending_sequence, content_id));
    result_ok
}

fn run_pairwise_receive(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x41; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"pairwise receive",
            id,
            NOW + 10,
            NOW + 10,
            &mut fixture.rng,
        )
        .unwrap();
    let envelope = queued_message(&fixture.alice, id);
    let content_id = envelope.content_id();
    let pending_sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 10, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_commit_failpoint(point, failure);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(pending_sequence),
        NOW + 11,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        pending_contains(&fixture.bob, pending_sequence, content_id),
        !committed
    );
    assert_eq!(
        fixture
            .bob
            .store
            .messages_with(&fixture.alice_id)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"pairwise receive")
            .count(),
        usize::from(committed)
    );

    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(
        &mut bob,
        &envelope,
        (!committed).then_some(pending_sequence),
        NOW + 12,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        bob.store
            .messages_with(&alice_id)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"pairwise receive")
            .count(),
        1
    );
    assert!(!pending_contains(&bob, pending_sequence, content_id));
    result_ok
}

fn run_receipt_receive(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x51; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"receipt target",
            id,
            NOW + 10,
            NOW + 10,
            &mut fixture.rng,
        )
        .unwrap();
    let message = queued_message(&fixture.alice, id);
    consume(&mut fixture.bob, &message, None, NOW + 11, &mut fixture.rng).unwrap();
    let (_, receipt) = queued_control(&fixture.bob);
    let content_id = receipt.content_id();
    let pending_sequence = fixture
        .alice
        .store
        .pending_push(&receipt, NOW + 11, &mut fixture.rng)
        .unwrap();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = consume(
        &mut fixture.alice,
        &receipt,
        Some(pending_sequence),
        NOW + 12,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let state = fixture
        .alice
        .store
        .messages_with(&fixture.bob_id)
        .unwrap()
        .into_iter()
        .find(|message| message.id == id)
        .unwrap()
        .state;
    let committed = state == DeliveryState::Delivered;
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        pending_contains(&fixture.alice, pending_sequence, content_id),
        !committed
    );
    assert_eq!(
        fixture
            .alice
            .store
            .queue_all()
            .unwrap()
            .iter()
            .any(|(_, item)| item.msg_id == Some(id)),
        !committed
    );

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    consume(
        &mut alice,
        &receipt,
        (!committed).then_some(pending_sequence),
        NOW + 13,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        alice
            .store
            .messages_with(&bob_id)
            .unwrap()
            .into_iter()
            .find(|message| message.id == id)
            .unwrap()
            .state,
        DeliveryState::Delivered
    );
    assert!(!pending_contains(&alice, pending_sequence, content_id));
    result_ok
}

fn run_maintenance(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x61; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"malformed source",
            id,
            NOW + 10,
            NOW + 10,
            &mut fixture.rng,
        )
        .unwrap();
    let valid = queued_message(&fixture.alice, id);
    let malformed = Envelope::new(EnvelopeKind::Message, valid.token, vec![0x7f]);
    let content_id = malformed.content_id();
    let pending_sequence = fixture
        .bob
        .store
        .pending_push(&malformed, NOW + 10, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_commit_failpoint(point, failure);
    let result = consume(
        &mut fixture.bob,
        &malformed,
        Some(pending_sequence),
        NOW + 11,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        pending_contains(&fixture.bob, pending_sequence, content_id),
        !committed
    );

    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(
        &mut bob,
        &malformed,
        (!committed).then_some(pending_sequence),
        NOW + 12,
        &mut rng,
    )
    .unwrap();
    assert!(bob.store.is_seen(&content_id).unwrap());
    assert!(!pending_contains(&bob, pending_sequence, content_id));
    result_ok
}

fn prepare_unconfirmed_reset(fixture: &mut Fixture, id: [u8; 16]) {
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"reset candidate",
            id,
            NOW + 15,
            NOW + 15,
            &mut fixture.rng,
        )
        .unwrap();
    fixture
        .alice
        .store
        .put_capabilities(
            &fixture.bob_id,
            &Node::local_capabilities(),
            &mut fixture.rng,
        )
        .unwrap();
}

fn reset_is_committed(node: &Node, peer: &[u8; 32], id: [u8; 16]) -> bool {
    node.store.get_session(peer).unwrap().is_none()
        && node.store.get_capabilities(peer).unwrap().is_none()
        && !node
            .store
            .queue_all()
            .unwrap()
            .iter()
            .any(|(_, item)| item.msg_id == Some(id))
        && node
            .store
            .message_device_deliveries(&id)
            .unwrap()
            .iter()
            .any(|delivery| {
                delivery.device == *peer
                    && delivery.state == DeliveryState::Queued
                    && delivery.wire_id.is_none()
            })
}

fn run_maintenance_reset(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x62; 16];
    prepare_unconfirmed_reset(&mut fixture, id);
    fixture.alice.arm_commit_failpoint(point, failure);
    let result =
        fixture
            .alice
            .reset_unconfirmed_session(&fixture.bob_id, &fixture.bob_id, &mut fixture.rng);
    let result_ok = result.is_ok();
    let committed = reset_is_committed(&fixture.alice, &fixture.bob_id, id);
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .reset_unconfirmed_session(&bob_id, &bob_id, &mut rng)
            .unwrap();
    }
    assert!(reset_is_committed(&alice, &bob_id, id));
    result_ok
}

fn expiry_is_committed(node: &Node, peer: &[u8; 32], id: [u8; 16]) -> bool {
    node.store
        .ephemeral_records()
        .unwrap()
        .iter()
        .any(|record| record.content_id == id && record.state == EphemeralState::Expired)
        && !node
            .store
            .messages_with(peer)
            .unwrap()
            .iter()
            .any(|message| message.id == id)
        && !node
            .store
            .queue_all()
            .unwrap()
            .iter()
            .any(|(_, item)| item.msg_id == Some(id))
}

fn run_maintenance_expiry(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    fixture
        .alice
        .store
        .put_capabilities(
            &fixture.bob_id,
            &Node::local_capabilities(),
            &mut fixture.rng,
        )
        .unwrap();
    let id = fixture
        .alice
        .send_disappearing_message(
            &fixture.bob_id,
            "expiring candidate",
            60,
            NOW + 15,
            &mut fixture.rng,
        )
        .unwrap();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.sweep_ephemeral(NOW + 75, &mut fixture.rng);
    let result_ok = result.is_ok();
    let committed = expiry_is_committed(&fixture.alice, &fixture.bob_id, id);
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice.sweep_ephemeral(NOW + 76, &mut rng).unwrap();
    }
    assert!(expiry_is_committed(&alice, &bob_id, id));
    result_ok
}

fn transition_commits_when_fired(point: TransitionFailpoint) -> bool {
    matches!(
        point,
        TransitionFailpoint::BeforeMemoryReplacement | TransitionFailpoint::AfterMemoryReplacement
    )
}

fn run_pairwise_send_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x71; 16];
    fixture.alice.arm_transition_failpoint(point);
    let result = fixture.alice.send_message_with_id(
        &fixture.bob_id,
        b"send checkpoint",
        id,
        NOW + 20,
        NOW + 20,
        &mut fixture.rng,
    );
    let fired = fixture.alice.transition_failpoint_fired();
    let committed = fixture
        .alice
        .store
        .messages_with(&fixture.bob_id)
        .unwrap()
        .iter()
        .any(|message| message.id == id);
    if fired {
        assert!(result.is_err());
        assert_eq!(committed, transition_commits_when_fired(point));
    } else {
        result.unwrap();
        assert!(committed);
    }
    assert_eq!(
        fixture
            .alice
            .store
            .queue_all()
            .unwrap()
            .iter()
            .filter(|(_, item)| item.msg_id == Some(id))
            .count(),
        usize::from(committed)
    );
    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .send_message_with_id(
                &bob_id,
                b"send checkpoint",
                id,
                NOW + 20,
                NOW + 20,
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(
        alice
            .store
            .messages_with(&bob_id)
            .unwrap()
            .iter()
            .filter(|message| message.id == id)
            .count(),
        1
    );
    fired
}

fn run_handshake_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let id = [0x72; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"handshake checkpoint",
            id,
            NOW + 20,
            NOW + 20,
            &mut fixture.rng,
        )
        .unwrap();
    let envelope = queued_message(&fixture.alice, id);
    let content_id = envelope.content_id();
    let sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 20, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_transition_failpoint(point);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(sequence),
        NOW + 21,
        &mut fixture.rng,
    );
    let fired = fixture.bob.transition_failpoint_fired();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    if fired {
        assert!(result.is_err());
        assert_eq!(committed, transition_commits_when_fired(point));
    } else {
        result.unwrap();
        assert!(committed);
    }
    assert_eq!(
        pending_contains(&fixture.bob, sequence, content_id),
        !committed
    );
    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(
        &mut bob,
        &envelope,
        (!committed).then_some(sequence),
        NOW + 22,
        &mut rng,
    )
    .unwrap();
    assert!(bob.store.get_session(&alice_id).unwrap().is_some());
    assert_eq!(bob.store.messages_with(&alice_id).unwrap().len(), 1);
    fired
}

fn run_pairwise_receive_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x73; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"receive checkpoint",
            id,
            NOW + 20,
            NOW + 20,
            &mut fixture.rng,
        )
        .unwrap();
    let envelope = queued_message(&fixture.alice, id);
    let content_id = envelope.content_id();
    let sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 20, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_transition_failpoint(point);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(sequence),
        NOW + 21,
        &mut fixture.rng,
    );
    let fired = fixture.bob.transition_failpoint_fired();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    if fired {
        assert!(result.is_err());
        assert_eq!(committed, transition_commits_when_fired(point));
    } else {
        result.unwrap();
        assert!(committed);
    }
    assert_eq!(
        pending_contains(&fixture.bob, sequence, content_id),
        !committed
    );
    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(
        &mut bob,
        &envelope,
        (!committed).then_some(sequence),
        NOW + 22,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        bob.store
            .messages_with(&alice_id)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"receive checkpoint")
            .count(),
        1
    );
    fired
}

fn run_receipt_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x74; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"receipt checkpoint",
            id,
            NOW + 20,
            NOW + 20,
            &mut fixture.rng,
        )
        .unwrap();
    let message = queued_message(&fixture.alice, id);
    consume(&mut fixture.bob, &message, None, NOW + 21, &mut fixture.rng).unwrap();
    let (_, receipt) = queued_control(&fixture.bob);
    let content_id = receipt.content_id();
    let sequence = fixture
        .alice
        .store
        .pending_push(&receipt, NOW + 21, &mut fixture.rng)
        .unwrap();
    fixture.alice.arm_transition_failpoint(point);
    let result = consume(
        &mut fixture.alice,
        &receipt,
        Some(sequence),
        NOW + 22,
        &mut fixture.rng,
    );
    let fired = fixture.alice.transition_failpoint_fired();
    let committed = fixture.alice.store.is_seen(&content_id).unwrap();
    if fired {
        assert!(result.is_err());
        assert_eq!(committed, transition_commits_when_fired(point));
    } else {
        result.unwrap();
        assert!(committed);
    }
    assert_eq!(
        pending_contains(&fixture.alice, sequence, content_id),
        !committed
    );
    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    consume(
        &mut alice,
        &receipt,
        (!committed).then_some(sequence),
        NOW + 23,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        alice
            .store
            .messages_with(&bob_id)
            .unwrap()
            .into_iter()
            .find(|message| message.id == id)
            .unwrap()
            .state,
        DeliveryState::Delivered
    );
    fired
}

fn run_maintenance_reset_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let id = [0x78; 16];
    prepare_unconfirmed_reset(&mut fixture, id);
    fixture.alice.arm_transition_failpoint(point);
    let result =
        fixture
            .alice
            .reset_unconfirmed_session(&fixture.bob_id, &fixture.bob_id, &mut fixture.rng);
    let fired = fixture.alice.transition_failpoint_fired();
    let committed = reset_is_committed(&fixture.alice, &fixture.bob_id, id);
    if fired {
        assert!(result.is_err());
        assert_eq!(committed, transition_commits_when_fired(point));
    } else {
        result.unwrap();
        assert!(committed);
    }
    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .reset_unconfirmed_session(&bob_id, &bob_id, &mut rng)
            .unwrap();
    }
    assert!(reset_is_committed(&alice, &bob_id, id));
    fired
}

#[test]
fn every_transaction_statement_is_all_or_nothing_after_restart() {
    let targets = [
        Target::PairwiseSend,
        Target::HandshakeReceive,
        Target::PairwiseReceive,
        Target::ReceiptReceive,
        Target::Maintenance,
        Target::MaintenanceReset,
        Target::MaintenanceExpiry,
    ];
    let mut seed = 0xa280_0000;
    for target in targets {
        for before in [true, false] {
            let mut reached_end = false;
            for statement in 0..64 {
                let point = if before {
                    CommitFailpoint::BeforeStatement(statement)
                } else {
                    CommitFailpoint::AfterStatement(statement)
                };
                seed += 1;
                if run_store_case(target, point, CommitFailure::Interrupted, seed) {
                    reached_end = true;
                    break;
                }
            }
            assert!(reached_end, "{target:?} exceeded the statement test bound");
        }
        for point in [
            CommitFailpoint::BeforeBegin,
            CommitFailpoint::AfterBegin,
            CommitFailpoint::BeforeCommit,
            CommitFailpoint::AfterCommit,
        ] {
            seed += 1;
            assert!(!run_store_case(
                target,
                point,
                CommitFailure::Interrupted,
                seed
            ));
        }
    }
}

#[test]
fn every_candidate_crypto_and_memory_checkpoint_has_a_binary_restart_state() {
    let runners: [fn(TransitionFailpoint, u64) -> bool; 5] = [
        run_pairwise_send_transition,
        run_handshake_transition,
        run_pairwise_receive_transition,
        run_receipt_transition,
        run_maintenance_reset_transition,
    ];
    let mut seed = 0xa281_0000;
    for runner in runners {
        for before in [true, false] {
            let mut reached_end = false;
            for step in 0..16 {
                let point = if before {
                    TransitionFailpoint::BeforeCryptoStep(step)
                } else {
                    TransitionFailpoint::AfterCryptoStep(step)
                };
                seed += 1;
                if !runner(point, seed) {
                    reached_end = true;
                    break;
                }
            }
            assert!(reached_end, "crypto checkpoint test bound exceeded");
        }
        for point in [
            TransitionFailpoint::BeforeMemoryReplacement,
            TransitionFailpoint::AfterMemoryReplacement,
        ] {
            seed += 1;
            assert!(runner(point, seed));
        }
    }
}

#[test]
fn presentation_checkpoint_recovers_with_a_deterministic_resync() {
    for (offset, point) in [
        TransitionFailpoint::BeforeEventDelivery,
        TransitionFailpoint::AfterEventDelivery,
    ]
    .into_iter()
    .enumerate()
    {
        let mut fixture = Fixture::new(0xa282_0000 + offset as u64);
        fixture.establish();
        fixture.alice.drain_events();
        fixture.alice.arm_transition_failpoint(point);
        fixture
            .alice
            .send_message_with_id(
                &fixture.bob_id,
                b"presentation checkpoint",
                [0x75 + offset as u8; 16],
                NOW + 30,
                NOW + 30,
                &mut fixture.rng,
            )
            .unwrap();
        let delivered = fixture.alice.drain_events();
        assert!(fixture.alice.transition_failpoint_fired());
        if point == TransitionFailpoint::BeforeEventDelivery {
            assert!(delivered.is_empty());
        } else {
            assert!(!delivered.is_empty());
        }
        let Fixture {
            _directory,
            alice_path,
            bob_path: _,
            alice,
            bob: _,
            alice_id: _,
            bob_id: _,
            rng: _,
        } = fixture;
        drop(alice);
        let mut alice = Node::open(&alice_path, b"alice").unwrap();
        assert!(alice
            .drain_events()
            .iter()
            .any(|event| matches!(event, Event::StateResyncRequired)));
    }
}

#[test]
fn reordered_deferred_and_duplicate_input_converges_after_restart() {
    let mut fixture = Fixture::new(0xa283_0000);
    let first = [0x76; 16];
    let second = [0x77; 16];
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"first reordered",
            first,
            NOW + 40,
            NOW + 40,
            &mut fixture.rng,
        )
        .unwrap();
    fixture
        .alice
        .send_message_with_id(
            &fixture.bob_id,
            b"second reordered",
            second,
            NOW + 41,
            NOW + 41,
            &mut fixture.rng,
        )
        .unwrap();
    let handshake = queued_message(&fixture.alice, first);
    let later = queued_message(&fixture.alice, second);
    let later_sequence = fixture
        .bob
        .store
        .pending_push(&later, NOW + 41, &mut fixture.rng)
        .unwrap();
    assert!(matches!(
        consume(
            &mut fixture.bob,
            &later,
            Some(later_sequence),
            NOW + 42,
            &mut fixture.rng
        )
        .unwrap(),
        Consumed::Later
    ));
    consume(
        &mut fixture.bob,
        &handshake,
        None,
        NOW + 43,
        &mut fixture.rng,
    )
    .unwrap();
    consume(
        &mut fixture.bob,
        &later,
        Some(later_sequence),
        NOW + 44,
        &mut fixture.rng,
    )
    .unwrap();
    consume(&mut fixture.bob, &later, None, NOW + 45, &mut fixture.rng).unwrap();
    assert!(!pending_contains(
        &fixture.bob,
        later_sequence,
        later.content_id()
    ));
    assert_eq!(
        fixture
            .bob
            .store
            .messages_with(&fixture.alice_id)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"second reordered")
            .count(),
        1
    );
    let Fixture {
        _directory,
        alice_path: _,
        bob_path,
        alice: _,
        bob,
        alice_id,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    consume(&mut bob, &later, None, NOW + 46, &mut rng).unwrap();
    assert_eq!(
        bob.store
            .messages_with(&alice_id)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"second reordered")
            .count(),
        1
    );
}

#[test]
fn disk_constraint_and_duplicate_failures_leave_retryable_inputs() {
    let targets = [
        Target::PairwiseSend,
        Target::HandshakeReceive,
        Target::PairwiseReceive,
        Target::ReceiptReceive,
        Target::Maintenance,
        Target::MaintenanceReset,
        Target::MaintenanceExpiry,
    ];
    let failures = [
        CommitFailure::DiskFull,
        CommitFailure::Constraint,
        CommitFailure::Duplicate,
    ];
    let mut seed = 0xa280_8000;
    for target in targets {
        for failure in failures {
            seed += 1;
            assert!(!run_store_case(
                target,
                CommitFailpoint::BeforeStatement(0),
                failure,
                seed
            ));
        }
    }
}
