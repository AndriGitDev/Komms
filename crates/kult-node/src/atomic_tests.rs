use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::{GroupSenderChain, KdfProfile};
use kult_protocol::{Envelope, EnvelopeKind};
use kult_store::{
    AttachmentStagePlan, AttachmentStatePlan, CommitFailpoint, CommitFailure, DeliveryState,
    DeviceLinkPlan, DeviceProjection, DeviceProjectionPlan, DeviceStateTransition, Direction,
    GroupDelivery, GroupMember, GroupMessageRecord, GroupRecord, GroupSendPlan, GroupStatePlan,
    GroupStateTransition, GroupTransition, IdentityTransition, MediaDirection, MediaObjectRecord,
    MediaRecord, MediaScope, MediaTransferRecord, MediaTransferState, MediaTransferTransition,
    MessageDeviceDeliveryRecord, MessageRecord, ProfileBootstrapPlan, QueueClass, QueueItem, Store,
};
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
};

use super::*;

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Default)]
struct CountingTransport {
    sends: AtomicUsize,
}

#[async_trait]
impl Transport for CountingTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }

    async fn reachable(&self, hint: &DeliveryHint) -> Reachability {
        match hint {
            DeliveryHint::MeshNode(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(
        &self,
        _hint: &DeliveryHint,
        _envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy, Debug)]
enum Target {
    ProfileBootstrap,
    PrekeyPublish,
    PairwiseSend,
    HandshakeReceive,
    PairwiseReceive,
    ReceiptReceive,
    Maintenance,
    MaintenanceReset,
    MaintenanceExpiry,
    GroupState,
    GroupSend,
    GroupReceive,
    AttachmentStage,
    AttachmentState,
    DeviceControl,
    DeviceLink,
    DeviceProjection,
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
    let mut established = false;
    node.consume(
        envelope,
        ConsumeOrigin {
            depth: 0,
            pending_sequence,
        },
        now,
        rng,
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
        Target::ProfileBootstrap => run_profile_bootstrap(point, failure, seed),
        Target::PrekeyPublish => run_prekey_publish(point, failure, seed),
        Target::PairwiseSend => run_pairwise_send(point, failure, seed),
        Target::HandshakeReceive => run_handshake_receive(point, failure, seed),
        Target::PairwiseReceive => run_pairwise_receive(point, failure, seed),
        Target::ReceiptReceive => run_receipt_receive(point, failure, seed),
        Target::Maintenance => run_maintenance(point, failure, seed),
        Target::MaintenanceReset => run_maintenance_reset(point, failure, seed),
        Target::MaintenanceExpiry => run_maintenance_expiry(point, failure, seed),
        Target::GroupState => run_group_state(point, failure, seed),
        Target::GroupSend => run_group_send(point, failure, seed),
        Target::GroupReceive => run_group_receive(point, failure, seed),
        Target::AttachmentStage => run_attachment_stage(point, failure, seed),
        Target::AttachmentState => run_attachment_state(point, failure, seed),
        Target::DeviceControl => run_device_control(point, failure, seed),
        Target::DeviceLink => run_device_link(point, failure, seed),
        Target::DeviceProjection => run_device_projection(point, failure, seed),
    }
}

fn expected_committed(result_ok: bool, point: CommitFailpoint) -> bool {
    result_ok || point == CommitFailpoint::AfterCommit
}

fn run_profile_bootstrap(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut rng = StdRng::seed_from_u64(seed);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.db");
    let store = Store::create(&path, b"profile", TEST_KDF, &mut rng).unwrap();
    let identity = Identity::generate(&mut rng);
    let device_state = devices::fresh_device_state(&identity, &mut rng).unwrap();
    let prekeys = PrekeyVault::generate(&mut rng).encode();
    store.arm_commit_failpoint(point, failure);
    let result = store.commit_plan(
        CommitPlan::ProfileBootstrap(ProfileBootstrapPlan {
            identity: &identity,
            device_state: &device_state,
            prekeys: &prekeys,
        }),
        &mut rng,
    );
    let result_ok = result.is_ok();
    let committed = store.get_identity().unwrap().is_some();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(store.get_device_state().unwrap().is_some(), committed);
    assert_eq!(store.get_prekeys().unwrap().is_some(), committed);
    drop(store);

    let store = Store::open(&path, b"profile").unwrap();
    if !committed {
        store
            .commit_plan(
                CommitPlan::ProfileBootstrap(ProfileBootstrapPlan {
                    identity: &identity,
                    device_state: &device_state,
                    prekeys: &prekeys,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(
        store.get_identity().unwrap().unwrap().public(),
        identity.public()
    );
    assert_eq!(store.get_device_state().unwrap(), Some(device_state));
    assert_eq!(
        store.get_prekeys().unwrap().unwrap().as_slice(),
        prekeys.as_slice()
    );
    result_ok
}

fn run_prekey_publish(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let before = fixture.alice.store.get_prekeys().unwrap().unwrap();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.handshake_bundle(NOW + 9, &mut fixture.rng);
    let result_ok = result.is_ok();
    let committed = fixture.alice.store.get_prekeys().unwrap().unwrap() != before;
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice.handshake_bundle(NOW + 10, &mut rng).unwrap();
    }
    assert_ne!(alice.store.get_prekeys().unwrap().unwrap(), before);
    result_ok
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

fn run_group_state(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let group = fixture
        .alice
        .create_group("state before", &[fixture.bob_id], &mut fixture.rng)
        .unwrap();
    fixture.alice.drain_events();
    let before = fixture.alice.store.get_group(&group).unwrap().unwrap();
    let mut after = before.clone();
    after.name = "state after".to_owned();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.store.commit_plan(
        CommitPlan::GroupState(GroupStatePlan {
            groups: &[GroupStateTransition {
                before: Some(&before),
                after: Some(&after),
            }],
            chains: &[],
            contacts: &[],
            authorities: &[],
            delete_controls: &[],
            presentation_changed: true,
        }),
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture.alice.store.get_group(&group).unwrap() == Some(after.clone());
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .store
            .commit_plan(
                CommitPlan::GroupState(GroupStatePlan {
                    groups: &[GroupStateTransition {
                        before: Some(&before),
                        after: Some(&after),
                    }],
                    chains: &[],
                    contacts: &[],
                    authorities: &[],
                    delete_controls: &[],
                    presentation_changed: true,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(alice.store.get_group(&group).unwrap(), Some(after));
    result_ok
}

fn run_group_send(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let group = fixture
        .alice
        .create_group("planned send", &[fixture.bob_id], &mut fixture.rng)
        .unwrap();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result =
        fixture
            .alice
            .group_send(&group, b"group planned send", NOW + 80, &mut fixture.rng);
    let result_ok = result.is_ok();
    let committed = fixture.alice.store.group_messages(&group).unwrap().len() == 1;
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        fixture
            .alice
            .store
            .queue_all()
            .unwrap()
            .iter()
            .filter(|(_, item)| item.group_msg_id.is_some())
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
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .group_send(&group, b"group planned send", NOW + 81, &mut rng)
            .unwrap();
    }
    assert_eq!(alice.store.group_messages(&group).unwrap().len(), 1);
    result_ok
}

fn run_group_receive(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let group = fixture
        .alice
        .create_group("planned receive", &[fixture.bob_id], &mut fixture.rng)
        .unwrap();
    futures::executor::block_on(fixture.alice.tick_groups(NOW + 90, &mut fixture.rng)).unwrap();
    let announce = fixture
        .alice
        .store
        .queue_all()
        .unwrap()
        .into_iter()
        .find_map(|(_, item)| {
            (item.envelope.kind == EnvelopeKind::GroupControl).then_some(item.envelope)
        })
        .expect("group announce");
    consume(
        &mut fixture.bob,
        &announce,
        None,
        NOW + 91,
        &mut fixture.rng,
    )
    .unwrap();
    fixture
        .bob
        .apply_deferred_controls(NOW + 91, &mut fixture.rng)
        .unwrap();
    let message_id = fixture
        .alice
        .group_send(&group, b"group planned receive", NOW + 92, &mut fixture.rng)
        .unwrap();
    let envelope = fixture
        .alice
        .store
        .queue_all()
        .unwrap()
        .into_iter()
        .find_map(|(_, item)| (item.group_msg_id == Some(message_id)).then_some(item.envelope))
        .expect("group message");
    let content_id = envelope.content_id();
    let pending_sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 92, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_commit_failpoint(point, failure);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(pending_sequence),
        NOW + 93,
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture.bob.store.is_seen(&content_id).unwrap();
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        fixture.bob.store.group_messages(&group).unwrap().len(),
        usize::from(committed)
    );
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
        &envelope,
        (!committed).then_some(pending_sequence),
        NOW + 94,
        &mut rng,
    )
    .unwrap();
    assert_eq!(bob.store.group_messages(&group).unwrap().len(), 1);
    result_ok
}

fn attachment_records(peer: [u8; 32]) -> (MessageRecord, MediaTransferRecord, MediaObjectRecord) {
    let content_id = [0xa1; 16];
    let transfer_id = [0xa2; 16];
    (
        MessageRecord {
            id: content_id,
            peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp: NOW + 100,
            body: vec![1],
            wire_id: None,
        },
        MediaTransferRecord {
            local_id: transfer_id,
            peer,
            direction: MediaDirection::Outbound,
            scope: MediaScope::Pairwise,
            scope_id: [0xa3; 32],
            manifest_author: [0xa4; 32],
            manifest_content_id: content_id,
            entitled_peers: vec![peer],
            state: MediaTransferState::Queued,
            updated_at: NOW + 100,
        },
        MediaObjectRecord {
            local_id: [0xa5; 16],
            transfer_id,
            object_id: [0xa6; 16],
            role: 0,
            total_len: 1,
            chunk_count: 1,
            content_hash: [0xa7; 32],
            media_type: "application/octet-stream".to_owned(),
            filename: Some("planned.bin".to_owned()),
            state: MediaTransferState::Queued,
            verified_bitmap: vec![0],
            chunk_addresses: vec![None],
            verified_bytes: 0,
        },
    )
}

fn run_attachment_stage(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let (message, transfer, object) = attachment_records(fixture.bob_id);
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.store.commit_plan(
        CommitPlan::AttachmentStage(AttachmentStagePlan {
            message: Some(&message),
            group_message: None,
            media_transfers: core::slice::from_ref(&transfer),
            media_objects: core::slice::from_ref(&object),
            ephemeral: None,
            presentation_changed: true,
        }),
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = matches!(
        fixture
            .alice
            .store
            .get_media_transfer(&transfer.local_id)
            .unwrap(),
        Some(MediaRecord::Available(_))
    );
    assert_eq!(committed, expected_committed(result_ok, point));
    assert_eq!(
        fixture
            .alice
            .store
            .messages_with(&fixture.bob_id)
            .unwrap()
            .len(),
        usize::from(committed)
    );

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .store
            .commit_plan(
                CommitPlan::AttachmentStage(AttachmentStagePlan {
                    message: Some(&message),
                    group_message: None,
                    media_transfers: core::slice::from_ref(&transfer),
                    media_objects: core::slice::from_ref(&object),
                    ephemeral: None,
                    presentation_changed: true,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert!(matches!(
        alice.store.get_media_transfer(&transfer.local_id).unwrap(),
        Some(MediaRecord::Available(_))
    ));
    result_ok
}

fn run_attachment_state(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let (_, before, _) = attachment_records(fixture.bob_id);
    fixture
        .alice
        .store
        .put_media_transfer(&before, &mut fixture.rng)
        .unwrap();
    let mut after = before.clone();
    after.state = MediaTransferState::Paused;
    after.updated_at += 1;
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.store.commit_plan(
        CommitPlan::AttachmentState(AttachmentStatePlan {
            media_transfers: &[MediaTransferTransition {
                before: &before,
                after: &after,
            }],
            media_objects: &[],
            delete_controls: &[],
            presentation_changed: true,
        }),
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed = fixture
        .alice
        .store
        .get_media_transfer(&before.local_id)
        .unwrap()
        == Some(MediaRecord::Available(after.clone()));
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .store
            .commit_plan(
                CommitPlan::AttachmentState(AttachmentStatePlan {
                    media_transfers: &[MediaTransferTransition {
                        before: &before,
                        after: &after,
                    }],
                    media_objects: &[],
                    delete_controls: &[],
                    presentation_changed: true,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(
        alice.store.get_media_transfer(&before.local_id).unwrap(),
        Some(MediaRecord::Available(after))
    );
    result_ok
}

fn run_device_control(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let device = fixture.alice.device_id();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture
        .alice
        .rename_linked_device(&device, "Renamed device", &mut fixture.rng);
    let result_ok = result.is_ok();
    let committed = fixture
        .alice
        .store
        .get_device_state()
        .unwrap()
        .unwrap()
        .manifest
        .devices
        .iter()
        .any(|entry| entry.certificate.device_id() == device && entry.name == "Renamed device");
    assert_eq!(committed, expected_committed(result_ok, point));
    assert!(result_ok || fixture.alice.drain_events().is_empty());

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .rename_linked_device(&device, "Renamed device", &mut rng)
            .unwrap();
    }
    assert!(alice
        .linked_devices()
        .iter()
        .any(|entry| entry.id == device && entry.name == "Renamed device"));
    result_ok
}

fn run_device_link(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut rng = StdRng::seed_from_u64(seed);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("target.db");
    let target = Node::create(&path, b"target", TEST_KDF, &mut rng).unwrap();
    let before_identity = Identity::from_bytes(&target.identity.to_bytes());
    let before_state = target.device_state.clone();
    let after_identity = Identity::generate(&mut rng);
    let after_state = devices::fresh_device_state(&after_identity, &mut rng).unwrap();
    target.store.arm_commit_failpoint(point, failure);
    let result = target.store.commit_plan(
        CommitPlan::DeviceLink(DeviceLinkPlan {
            identity: IdentityTransition {
                before: &before_identity,
                after: &after_identity,
            },
            device_state: DeviceStateTransition {
                before: Some(&before_state),
                after: &after_state,
            },
            contacts: &[],
            devices: &[],
            messages: &[],
            groups: &[],
            group_messages: &[],
            authorities: &[],
            local_metadata: &[],
            notes: &[],
            ephemeral: &[],
            sync_events: &[],
            presentation_changed: true,
        }),
        &mut rng,
    );
    let result_ok = result.is_ok();
    let committed =
        target.store.get_identity().unwrap().unwrap().public() == after_identity.public();
    assert_eq!(committed, expected_committed(result_ok, point));
    drop(target);

    let store = Store::open(&path, b"target").unwrap();
    if !committed {
        store
            .commit_plan(
                CommitPlan::DeviceLink(DeviceLinkPlan {
                    identity: IdentityTransition {
                        before: &before_identity,
                        after: &after_identity,
                    },
                    device_state: DeviceStateTransition {
                        before: Some(&before_state),
                        after: &after_state,
                    },
                    contacts: &[],
                    devices: &[],
                    messages: &[],
                    groups: &[],
                    group_messages: &[],
                    authorities: &[],
                    local_metadata: &[],
                    notes: &[],
                    ephemeral: &[],
                    sync_events: &[],
                    presentation_changed: true,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(
        store.get_identity().unwrap().unwrap().public(),
        after_identity.public()
    );
    assert_eq!(store.get_device_state().unwrap(), Some(after_state));
    result_ok
}

fn run_device_projection(point: CommitFailpoint, failure: CommitFailure, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let before = fixture
        .alice
        .store
        .get_contact(&fixture.bob_id)
        .unwrap()
        .unwrap();
    let mut after = before.clone();
    after.name = "Projected contact".to_owned();
    fixture.alice.arm_commit_failpoint(point, failure);
    let result = fixture.alice.store.commit_plan(
        CommitPlan::DeviceProjection(DeviceProjectionPlan {
            projections: &[DeviceProjection::Contact {
                before: Some(&before),
                after: Some(&after),
            }],
            delete_sessions: &[],
            delete_capabilities: &[],
            delete_queue: &[],
            presentation_changed: true,
        }),
        &mut fixture.rng,
    );
    let result_ok = result.is_ok();
    let committed =
        fixture.alice.store.get_contact(&fixture.bob_id).unwrap() == Some(after.clone());
    assert_eq!(committed, expected_committed(result_ok, point));

    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .store
            .commit_plan(
                CommitPlan::DeviceProjection(DeviceProjectionPlan {
                    projections: &[DeviceProjection::Contact {
                        before: Some(&before),
                        after: Some(&after),
                    }],
                    delete_sessions: &[],
                    delete_capabilities: &[],
                    delete_queue: &[],
                    presentation_changed: true,
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(alice.store.get_contact(&after.peer).unwrap(), Some(after));
    result_ok
}

struct LargeGroupFanout {
    before_group: GroupRecord,
    after_group: GroupRecord,
    message: GroupMessageRecord,
    deliveries: Vec<MessageDeviceDeliveryRecord>,
    queue: Vec<QueueItem>,
}

impl LargeGroupFanout {
    fn commit(
        &self,
        node: &Node,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> kult_store::Result<kult_store::CommitReceipt> {
        node.store.commit_plan(
            CommitPlan::GroupSend(GroupSendPlan {
                group: Some(GroupTransition {
                    before: &self.before_group,
                    after: &self.after_group,
                }),
                message: Some(&self.message),
                message_update: None,
                deliveries: &self.deliveries,
                delivery_updates: &[],
                queue: &self.queue,
                scheduled: None,
                ephemeral: None,
                media_transfers: &[],
                delete_chains: &[],
                authority: None,
                presentation_changed: true,
            }),
            rng,
        )
    }
}

fn prepare_large_group_fanout(fixture: &mut Fixture) -> LargeGroupFanout {
    let group = fixture
        .alice
        .create_group("bounded maximum", &[fixture.bob_id], &mut fixture.rng)
        .unwrap();
    let initial = fixture.alice.store.get_group(&group).unwrap().unwrap();
    let mut before_group = initial.clone();
    let mut discriminator = 1u8;
    while before_group.members.len() < 64 {
        let mut peer = [0u8; 32];
        peer[0] = 0x80;
        peer[1] = discriminator;
        discriminator = discriminator.checked_add(1).unwrap();
        if before_group
            .members
            .iter()
            .any(|member| member.peer == peer)
        {
            continue;
        }
        before_group.members.push(GroupMember {
            peer,
            identity: vec![0x49, discriminator],
        });
    }
    fixture
        .alice
        .store
        .commit_plan(
            CommitPlan::GroupState(GroupStatePlan {
                groups: &[GroupStateTransition {
                    before: Some(&initial),
                    after: Some(&before_group),
                }],
                chains: &[],
                contacts: &[],
                authorities: &[],
                delete_controls: &[],
                presentation_changed: false,
            }),
            &mut fixture.rng,
        )
        .unwrap();

    let mut after_group = before_group.clone();
    fixture
        .alice
        .rotate_group(&mut after_group, &mut fixture.rng)
        .unwrap();
    let id = [0xb1; 16];
    let wire = vec![0xc7; 96];
    let mut account_deliveries = Vec::new();
    let mut deliveries = Vec::new();
    let mut queue = Vec::new();
    for (account_index, member) in before_group
        .members
        .iter()
        .filter(|member| member.peer != before_group.creator)
        .enumerate()
    {
        let mut first_wire = None;
        for device_index in 0..8 {
            let mut device = [0u8; 32];
            device[0] = 0xd0;
            device[1] = u8::try_from(account_index + 1).unwrap();
            device[2] = u8::try_from(device_index + 1).unwrap();
            let envelope = Envelope::new(EnvelopeKind::GroupMessage, device, wire.clone());
            let wire_id = envelope.content_id();
            first_wire.get_or_insert(wire_id);
            deliveries.push(MessageDeviceDeliveryRecord {
                message: id,
                account: member.peer,
                device,
                wire_id: Some(wire_id),
                state: DeliveryState::Queued,
            });
            queue.push(QueueItem {
                peer: device,
                msg_id: None,
                group_msg_id: Some(id),
                class: QueueClass::Interactive,
                created_at: NOW + 110,
                attempts: 0,
                next_attempt_at: NOW + 110,
                envelope,
            });
        }
        account_deliveries.push(GroupDelivery {
            peer: member.peer,
            wire_id: first_wire,
            state: DeliveryState::Queued,
        });
    }
    assert_eq!(account_deliveries.len(), 63);
    assert_eq!(deliveries.len(), 504);
    assert_eq!(queue.len(), 504);
    LargeGroupFanout {
        before_group,
        after_group,
        message: GroupMessageRecord {
            id,
            group,
            sender: initial.creator,
            direction: Direction::Outbound,
            timestamp: NOW + 110,
            body: b"maximum bounded group fan-out".to_vec(),
            deliveries: account_deliveries,
            wire_body: None,
        },
        deliveries,
        queue,
    }
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

fn run_group_send_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let group = fixture
        .alice
        .create_group("group send checkpoint", &[fixture.bob_id], &mut fixture.rng)
        .unwrap();
    let id = [0x79; 16];
    fixture.alice.arm_transition_failpoint(point);
    let result = fixture.alice.group_send_with_id(
        &group,
        b"group send checkpoint",
        id,
        NOW + 24,
        NOW + 24,
        &mut fixture.rng,
    );
    let fired = fixture.alice.transition_failpoint_fired();
    let committed = fixture
        .alice
        .store
        .group_messages(&group)
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
    let Fixture {
        _directory,
        alice_path,
        bob_path: _,
        alice,
        bob: _,
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice
            .group_send_with_id(
                &group,
                b"group send checkpoint",
                id,
                NOW + 24,
                NOW + 24,
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(
        alice
            .store
            .group_messages(&group)
            .unwrap()
            .iter()
            .filter(|message| message.id == id)
            .count(),
        1
    );
    fired
}

fn run_prekey_publish_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    let before = fixture.alice.store.get_prekeys().unwrap().unwrap();
    fixture.alice.arm_transition_failpoint(point);
    let result = fixture.alice.handshake_bundle(NOW + 23, &mut fixture.rng);
    let fired = fixture.alice.transition_failpoint_fired();
    let committed = fixture.alice.store.get_prekeys().unwrap().unwrap() != before;
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
        bob_id: _,
        mut rng,
    } = fixture;
    drop(alice);
    let mut alice = Node::open(&alice_path, b"alice").unwrap();
    if !committed {
        alice.handshake_bundle(NOW + 24, &mut rng).unwrap();
    }
    assert_ne!(alice.store.get_prekeys().unwrap().unwrap(), before);
    assert_eq!(
        alice.vault.encode(),
        alice.store.get_prekeys().unwrap().unwrap()
    );
    fired
}

fn run_group_receive_transition(point: TransitionFailpoint, seed: u64) -> bool {
    let mut fixture = Fixture::new(seed);
    fixture.establish();
    let group = fixture
        .alice
        .create_group(
            "group receive checkpoint",
            &[fixture.bob_id],
            &mut fixture.rng,
        )
        .unwrap();
    futures::executor::block_on(fixture.alice.tick_groups(NOW + 25, &mut fixture.rng)).unwrap();
    let announce = fixture
        .alice
        .store
        .queue_all()
        .unwrap()
        .into_iter()
        .find_map(|(_, item)| {
            (item.envelope.kind == EnvelopeKind::GroupControl).then_some(item.envelope)
        })
        .expect("group announce");
    consume(
        &mut fixture.bob,
        &announce,
        None,
        NOW + 26,
        &mut fixture.rng,
    )
    .unwrap();
    fixture
        .bob
        .apply_deferred_controls(NOW + 26, &mut fixture.rng)
        .unwrap();
    let id = [0x7a; 16];
    fixture
        .alice
        .group_send_with_id(
            &group,
            b"group receive checkpoint",
            id,
            NOW + 27,
            NOW + 27,
            &mut fixture.rng,
        )
        .unwrap();
    let envelope = fixture
        .alice
        .store
        .queue_all()
        .unwrap()
        .into_iter()
        .find_map(|(_, item)| (item.group_msg_id == Some(id)).then_some(item.envelope))
        .expect("group message");
    let content_id = envelope.content_id();
    let sequence = fixture
        .bob
        .store
        .pending_push(&envelope, NOW + 27, &mut fixture.rng)
        .unwrap();
    fixture.bob.arm_transition_failpoint(point);
    let result = consume(
        &mut fixture.bob,
        &envelope,
        Some(sequence),
        NOW + 28,
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
        alice_id: _,
        bob_id: _,
        mut rng,
    } = fixture;
    drop(bob);
    let mut bob = Node::open(&bob_path, b"bob").unwrap();
    let retry = consume(
        &mut bob,
        &envelope,
        (!committed).then_some(sequence),
        NOW + 29,
        &mut rng,
    )
    .unwrap();
    assert!(
        matches!(retry, Consumed::Done | Consumed::DoneAtomic),
        "group receive retry remained deferred at {point:?}"
    );
    assert_eq!(
        bob.store
            .group_messages(&group)
            .unwrap()
            .iter()
            .filter(|message| message.body == b"group receive checkpoint")
            .count(),
        1,
        "group receive restart did not converge at {point:?}; fired={fired}, committed={committed}"
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
        Target::ProfileBootstrap,
        Target::PrekeyPublish,
        Target::PairwiseSend,
        Target::HandshakeReceive,
        Target::PairwiseReceive,
        Target::ReceiptReceive,
        Target::Maintenance,
        Target::MaintenanceReset,
        Target::MaintenanceExpiry,
        Target::GroupState,
        Target::GroupSend,
        Target::GroupReceive,
        Target::AttachmentStage,
        Target::AttachmentState,
        Target::DeviceControl,
        Target::DeviceLink,
        Target::DeviceProjection,
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
fn maximum_group_fanout_is_bounded_and_restart_atomic() {
    let points = [
        CommitFailpoint::BeforeStatement(0),
        CommitFailpoint::AfterStatement(505),
        CommitFailpoint::AfterStatement(1009),
        CommitFailpoint::BeforeCommit,
        CommitFailpoint::AfterCommit,
    ];
    for (offset, point) in points.into_iter().enumerate() {
        let mut fixture = Fixture::new(0xa280_4000 + offset as u64);
        let fanout = prepare_large_group_fanout(&mut fixture);
        fixture
            .alice
            .arm_commit_failpoint(point, CommitFailure::Interrupted);
        let result = fanout.commit(&fixture.alice, &mut fixture.rng);
        assert!(result.is_err(), "large fan-out failpoint was not reached");
        let committed = fixture
            .alice
            .store
            .group_messages(&fanout.message.group)
            .unwrap()
            .iter()
            .any(|message| message.id == fanout.message.id);
        assert_eq!(committed, point == CommitFailpoint::AfterCommit);

        let Fixture {
            _directory,
            alice_path,
            bob_path: _,
            alice,
            bob: _,
            alice_id: _,
            bob_id: _,
            mut rng,
        } = fixture;
        drop(alice);
        let alice = Node::open(&alice_path, b"alice").unwrap();
        if !committed {
            fanout.commit(&alice, &mut rng).unwrap();
        }
        assert_eq!(
            alice
                .store
                .message_device_deliveries(&fanout.message.id)
                .unwrap()
                .len(),
            504
        );
        assert_eq!(
            alice
                .store
                .queue_all()
                .unwrap()
                .iter()
                .filter(|(_, item)| item.group_msg_id == Some(fanout.message.id))
                .count(),
            504
        );
        assert_eq!(
            alice
                .store
                .group_messages(&fanout.message.group)
                .unwrap()
                .iter()
                .filter(|message| message.id == fanout.message.id)
                .count(),
            1
        );
    }
}

#[test]
fn group_fanout_rejects_a_ninth_device_for_one_account() {
    let mut fixture = Fixture::new(0xa280_5000);
    let mut fanout = prepare_large_group_fanout(&mut fixture);
    let account = fanout.message.deliveries[0].peer;
    let mut device = [0u8; 32];
    device[0] = 0xd0;
    device[1] = 1;
    device[2] = 9;
    let envelope = Envelope::new(EnvelopeKind::GroupMessage, device, vec![0xc7; 96]);
    let wire_id = envelope.content_id();
    fanout.deliveries.push(MessageDeviceDeliveryRecord {
        message: fanout.message.id,
        account,
        device,
        wire_id: Some(wire_id),
        state: DeliveryState::Queued,
    });
    fanout.queue.push(QueueItem {
        peer: device,
        msg_id: None,
        group_msg_id: Some(fanout.message.id),
        class: QueueClass::Interactive,
        created_at: NOW + 110,
        attempts: 0,
        next_attempt_at: NOW + 110,
        envelope,
    });
    assert!(matches!(
        fanout.commit(&fixture.alice, &mut fixture.rng),
        Err(kult_store::StoreError::InvalidTransition)
    ));
    assert!(fixture
        .alice
        .store
        .group_messages(&fanout.message.group)
        .unwrap()
        .is_empty());
}

#[test]
fn stable_protocol_modules_cannot_call_raw_state_setters() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden = [
        "put_session",
        "delete_session",
        "put_identity",
        "put_prekeys",
        "put_device_state",
        "put_device_sync_event",
        "retain_device_sync_events",
        "put_capabilities",
        "delete_capabilities",
        "delete_contact_device",
        "retarget_message_device_deliveries",
        "put_group",
        "delete_group",
        "put_group_authority",
        "put_group_chain",
        "delete_group_chain",
        "put_group_message",
        "update_group_message",
        "delete_group_message_record",
        "put_ephemeral_record",
        "put_media_transfer",
        "set_media_transfer_state",
        "put_media_object",
        "set_media_object_state",
        "commit_media_chunk",
        "mark_media_complete",
        "delete_media_transfer",
        "delete_media_transfer_with_objects",
        "delete_media_object",
        "mark_seen",
        "put_receipt_replay",
        "put_message",
        "update_message",
        "delete_message_record",
        "put_message_device_delivery",
        "queue_push",
        "queue_ack",
        "queue_update",
        "queue_remove_peer",
        "queue_retarget_peer",
        "queue_remove_message",
        "queue_remove_group_message",
        "queue_remove_envelope",
        "pending_ack",
    ];
    for entry in std::fs::read_dir(source_root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let filename = path.file_name().and_then(|value| value.to_str()).unwrap();
        if filename == "atomic_tests.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let production = source.split("#[cfg(test)]").next().unwrap_or(&source);
        let audited = if filename == "devices.rs" {
            // The pre-C2 contact-admission compatibility bridge remains an
            // explicit ADR-0030 quarantine. No other device path may inherit
            // its raw migration setters.
            let start = production
                .find("pub(crate) fn apply_contact_device_manifest")
                .expect("contact-admission quarantine start");
            let end = production[start..]
                .find("pub(crate) fn account_for_device")
                .map(|offset| start + offset)
                .expect("contact-admission quarantine end");
            format!("{}{}", &production[..start], &production[end..])
        } else {
            production.to_owned()
        };
        let normalized = audited.split_whitespace().collect::<String>();
        assert!(
            !normalized.contains("#[cfg(any())]"),
            "{} retains disabled protocol code",
            path.display()
        );
        for setter in forbidden {
            let needle = format!(".{setter}(");
            assert!(
                !normalized.contains(&needle),
                "{} bypasses a typed transition through {setter}",
                path.display()
            );
        }
        if filename == "devices.rs" {
            let setter = "put_contact_device";
            let needle = format!(".{setter}(");
            assert!(
                !normalized.contains(&needle),
                "{} bypasses a device transition through {setter}",
                path.display()
            );
        }
    }
}

#[test]
fn every_candidate_crypto_and_memory_checkpoint_has_a_binary_restart_state() {
    let crypto_runners: [fn(TransitionFailpoint, u64) -> bool; 8] = [
        run_prekey_publish_transition,
        run_pairwise_send_transition,
        run_handshake_transition,
        run_pairwise_receive_transition,
        run_receipt_transition,
        run_group_send_transition,
        run_group_receive_transition,
        run_maintenance_reset_transition,
    ];
    let mut seed = 0xa281_0000;
    for runner in crypto_runners {
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
    }
    let memory_runners: [fn(TransitionFailpoint, u64) -> bool; 7] = [
        run_prekey_publish_transition,
        run_pairwise_send_transition,
        run_handshake_transition,
        run_pairwise_receive_transition,
        run_receipt_transition,
        run_group_receive_transition,
        run_maintenance_reset_transition,
    ];
    for runner in memory_runners {
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
fn scheduled_activation_commits_before_transport_or_presentation() {
    for (offset, point) in [CommitFailpoint::BeforeCommit, CommitFailpoint::AfterCommit]
        .into_iter()
        .enumerate()
    {
        let mut fixture = Fixture::new(0xa281_8000 + offset as u64);
        fixture.establish();
        fixture
            .alice
            .acknowledge_presentation(&mut fixture.rng)
            .unwrap();
        let transport = Arc::new(CountingTransport::default());
        fixture.alice.add_transport(transport.clone());
        fixture
            .alice
            .set_hints(
                &fixture.bob_id,
                &[DeliveryHint::MeshNode(9)],
                &mut fixture.rng,
            )
            .unwrap();
        fixture.alice.capabilities_advertised.insert(fixture.bob_id);
        let id = fixture
            .alice
            .schedule_message(
                &fixture.bob_id,
                b"scheduled commit boundary",
                NOW + 50,
                NOW + 40,
                &mut fixture.rng,
            )
            .unwrap();
        fixture.alice.drain_events();
        fixture
            .alice
            .arm_commit_failpoint(point, CommitFailure::Interrupted);
        let result = futures::executor::block_on(fixture.alice.tick(NOW + 50, &mut fixture.rng));
        result.unwrap();
        assert_eq!(
            transport.sends.load(Ordering::SeqCst) > 0,
            point == CommitFailpoint::AfterCommit
        );
        assert_eq!(
            fixture
                .alice
                .store
                .get_scheduled_message(&id)
                .unwrap()
                .is_none(),
            point == CommitFailpoint::AfterCommit,
            "scheduled activation failpoint was consumed by a different transition"
        );
        assert_eq!(
            fixture
                .alice
                .store
                .presentation_resync_marker()
                .unwrap()
                .is_some(),
            point == CommitFailpoint::AfterCommit
        );
        assert!(!fixture.alice.drain_events().iter().any(
            |event| matches!(event, Event::ScheduledMessageActivated { id: event } if *event == id)
        ));

        let Fixture {
            _directory,
            alice_path,
            bob_path: _,
            alice,
            bob: _,
            alice_id: _,
            bob_id: _,
            mut rng,
        } = fixture;
        drop(alice);
        let mut alice = Node::open(&alice_path, b"alice").unwrap();
        alice.add_transport(transport.clone());
        let reopen_events = alice.drain_events();
        if point == CommitFailpoint::AfterCommit {
            assert!(reopen_events
                .iter()
                .any(|event| matches!(event, Event::StateResyncRequired)));
        }
        let events = futures::executor::block_on(alice.tick(NOW + 51, &mut rng)).unwrap();
        assert!(transport.sends.load(Ordering::SeqCst) > 0);
        if point == CommitFailpoint::BeforeCommit {
            assert!(events.iter().any(
                |event| matches!(event, Event::ScheduledMessageActivated { id: event } if *event == id)
            ));
        }
        assert!(alice.store.get_scheduled_message(&id).unwrap().is_none());
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
        Target::ProfileBootstrap,
        Target::PrekeyPublish,
        Target::PairwiseSend,
        Target::HandshakeReceive,
        Target::PairwiseReceive,
        Target::ReceiptReceive,
        Target::Maintenance,
        Target::MaintenanceReset,
        Target::MaintenanceExpiry,
        Target::GroupState,
        Target::GroupSend,
        Target::GroupReceive,
        Target::AttachmentStage,
        Target::AttachmentState,
        Target::DeviceControl,
        Target::DeviceLink,
        Target::DeviceProjection,
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

#[test]
fn device_link_group_quota_rejects_without_publishing_partial_state() {
    let mut rng = StdRng::seed_from_u64(0xa284_0000);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("group-quota-target.db");
    let target = Node::create(&path, b"target", TEST_KDF, &mut rng).unwrap();
    let before_identity = Identity::from_bytes(&target.identity.to_bytes());
    let before_state = target.device_state.clone();
    let after_identity = Identity::generate(&mut rng);
    let after_state = devices::fresh_device_state(&after_identity, &mut rng).unwrap();
    let sender_chain = postcard::to_allocvec(&GroupSenderChain::generate(&mut rng)).unwrap();
    let member_identity = postcard::to_allocvec(&after_identity.public()).unwrap();
    let mut groups = Vec::with_capacity(kult_store::MAX_PROFILE_GROUPS + 1);
    for index in 0..=kult_store::MAX_PROFILE_GROUPS {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        groups.push(GroupRecord {
            id,
            name: "bounded profile group".to_owned(),
            creator: after_identity.public().ed,
            members: vec![GroupMember {
                peer: after_identity.public().ed,
                identity: member_identity.clone(),
            }],
            secret: [0x61; 32],
            prev_secret: None,
            generation: 1,
            sender_chain: sender_chain.clone(),
            sent_since_rotation: 0,
            pending: Vec::new(),
        });
    }

    let result = target.store.commit_plan(
        CommitPlan::DeviceLink(DeviceLinkPlan {
            identity: IdentityTransition {
                before: &before_identity,
                after: &after_identity,
            },
            device_state: DeviceStateTransition {
                before: Some(&before_state),
                after: &after_state,
            },
            contacts: &[],
            devices: &[],
            messages: &[],
            groups: &groups,
            group_messages: &[],
            authorities: &[],
            local_metadata: &[],
            notes: &[],
            ephemeral: &[],
            sync_events: &[],
            presentation_changed: true,
        }),
        &mut rng,
    );
    assert!(matches!(result, Err(kult_store::StoreError::GroupLimit)));
    assert_eq!(
        target.store.get_identity().unwrap().unwrap().public(),
        before_identity.public()
    );
    assert!(target.store.groups().unwrap().is_empty());
    drop(target);

    let target = Node::open(&path, b"target").unwrap();
    assert_eq!(
        target.store.get_identity().unwrap().unwrap().public(),
        before_identity.public()
    );
    assert_eq!(target.store.get_device_state().unwrap(), Some(before_state));
    assert!(target.store.groups().unwrap().is_empty());
}
