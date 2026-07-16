//! End-to-end tests for sender-key groups (ADR-0012): invite + sender-key
//! announces over pairwise sessions, encrypt-once fan-out, per-member
//! delivery receipts, membership changes with rotation, restart
//! persistence, and backup/restore with automatic re-announce.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{ContentStatus, Event, MentionSpan, Node, NodeError};
use kult_protocol::{
    decode_content, encode_mention, encode_poll, encode_poll_vote_payload, DecodedContent,
    Envelope, EnvelopeKind, PollVote, CONTENT_HEADER_LEN, CONTENT_MAGIC,
};
use kult_store::DeliveryState;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Net = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

struct MockLink {
    net: Net,
    me: u32,
}

#[async_trait]
impl Transport for MockLink {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Metered,
            broadcast: false,
        }
    }
    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            DeliveryHint::MeshNode(_) => Reachability::Now,
            _ => Reachability::Unreachable,
        }
    }
    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::MeshNode(n) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        self.net
            .lock()
            .unwrap()
            .entry(*n)
            .or_default()
            .push(envelope.clone());
        Ok(SendReceipt::HandedToLink)
    }
    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .entry(self.me)
            .or_default()
            .drain(..)
            .collect())
    }
}

fn group_bodies(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GroupMessageReceived { body, .. } => Some(body.clone()),
            _ => None,
        })
        .collect()
}

fn delivered_to(events: &[Event]) -> Vec<([u8; 16], [u8; 32])> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GroupDeliveryUpdated {
                id,
                peer,
                state: DeliveryState::Delivered,
            } => Some((*id, *peer)),
            _ => None,
        })
        .collect()
}

/// Three nodes, full kitchen-table contact exchange (everyone has everyone's
/// bundle and hint — the documented v1 reachability requirement).
async fn trio(
    dir: &std::path::Path,
    net: &Net,
    rng: &mut StdRng,
) -> (Node, Node, Node, [u8; 32], [u8; 32], [u8; 32]) {
    let mut nodes = Vec::new();
    for (i, name) in ["a", "b", "c"].iter().enumerate() {
        let mut node = Node::create(
            &dir.join(format!("{name}.db")),
            name.as_bytes(),
            TEST_KDF,
            rng,
        )
        .unwrap();
        node.add_transport(Arc::new(MockLink {
            net: net.clone(),
            me: i as u32 + 1,
        }));
        nodes.push(node);
    }
    let ids: Vec<[u8; 32]> = nodes.iter().map(|n| n.peer_id()).collect();
    let bundles: Vec<Vec<Vec<u8>>> = {
        let mut all = Vec::new();
        for node in nodes.iter_mut() {
            // One bundle per prospective contact (each carries its own OPK).
            all.push(vec![
                node.handshake_bundle(NOW, rng).unwrap(),
                node.handshake_bundle(NOW, rng).unwrap(),
            ]);
        }
        all
    };
    for i in 0..3usize {
        let mut handed = 0;
        for j in 0..3usize {
            if i == j {
                continue;
            }
            // Each prospective contact gets their own bundle (distinct
            // one-time prekeys — handing two people the same bundle gets
            // the second handshake correctly dropped).
            let bundle = &bundles[j][if i < j { i } else { i - 1 }];
            nodes[i]
                .add_contact(
                    ["a", "b", "c"][j],
                    bundle,
                    &[DeliveryHint::MeshNode(j as u32 + 1)],
                    NOW,
                    rng,
                )
                .unwrap();
            handed += 1;
        }
        assert_eq!(handed, 2);
    }
    let mut it = nodes.into_iter();
    (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        ids[0],
        ids[1],
        ids[2],
    )
}

async fn settle_trio(
    alice: &mut Node,
    bob: &mut Node,
    carol: &mut Node,
    rng: &mut StdRng,
    start: u64,
) {
    for round in 0..6 {
        let now = start + round * 3;
        for events in [
            alice.tick(now, rng).await.unwrap(),
            bob.tick(now + 1, rng).await.unwrap(),
            carol.tick(now + 2, rng).await.unwrap(),
        ] {
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, Event::MentionReceived { .. })),
                "plain legacy fallback must not emit semantic notification"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Create → announce → send → everyone reads, encrypt-once on the wire,
//    per-member Delivered via ordinary receipts, replies on other members'
//    chains, and everything survives restarts.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn group_round_trip_receipts_and_restart() {
    let mut rng = StdRng::seed_from_u64(11);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let (mut alice, mut bob, mut carol, _a_id, b_id, c_id) = trio(dir.path(), &net, &mut rng).await;

    let gid = alice
        .create_group("expedition", &[b_id, c_id], &mut rng)
        .unwrap();
    assert_eq!(alice.groups().unwrap().len(), 1);

    // Queue a message before any announce has even left: the fan-out must
    // wait for sessions, then flow without further prompting.
    let m1 = alice
        .group_send(&gid, b"meet at the pass at dawn", NOW, &mut rng)
        .unwrap();
    assert!(matches!(
        decode_content(&alice.group_messages(&gid).unwrap()[0].body),
        DecodedContent::LegacyText("meet at the pass at dawn")
    ));

    // Alice's first tick: handshakes + announces queued and flushed.
    alice.tick(NOW + 1, &mut rng).await.unwrap();

    // Encrypt-once: the copies addressed to Bob and Carol carry the *same*
    // group ciphertext body under different delivery tokens.
    {
        let net = net.lock().unwrap();
        let mut bodies = Vec::new();
        for n in [2u32, 3] {
            for env in net.get(&n).into_iter().flatten() {
                if env.kind == EnvelopeKind::GroupMessage {
                    bodies.push(env.body.clone());
                }
            }
        }
        assert_eq!(bodies.len(), 2, "one copy per co-member");
        assert_eq!(bodies[0], bodies[1], "single ciphertext, fanned out");
    }

    // Bob and Carol: handshake unlocks announce unlocks message — one tick.
    let events = bob.tick(NOW + 5, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::GroupUpdated { group } if *group == gid)));
    assert_eq!(
        group_bodies(&events),
        vec![b"meet at the pass at dawn".to_vec()]
    );
    let events = carol.tick(NOW + 5, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&events),
        vec![b"meet at the pass at dawn".to_vec()]
    );
    assert_eq!(bob.groups().unwrap()[0].members.len(), 3);

    // Receipts advance Alice's per-member ladder to Delivered for both.
    let events = alice.tick(NOW + 10, &mut rng).await.unwrap();
    let delivered = delivered_to(&events);
    assert!(delivered.contains(&(m1, b_id)) && delivered.contains(&(m1, c_id)));

    // Bob replies on his own chain (announced to Alice and Carol when he
    // adopted the group).
    bob.group_send(&gid, b"ack from bob", NOW + 20, &mut rng)
        .unwrap();
    bob.tick(NOW + 21, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 25, &mut rng).await.unwrap();
    assert_eq!(group_bodies(&events), vec![b"ack from bob".to_vec()]);
    let events = carol.tick(NOW + 25, &mut rng).await.unwrap();
    assert_eq!(group_bodies(&events), vec![b"ack from bob".to_vec()]);

    // ---- restarts: groups, chains, and history persist ----
    let (a_db, b_db) = (dir.path().join("a.db"), dir.path().join("b.db"));
    drop(alice);
    drop(bob);
    let mut alice = Node::open(&a_db, b"a").unwrap();
    let mut bob = Node::open(&b_db, b"b").unwrap();
    alice.add_transport(Arc::new(MockLink {
        net: net.clone(),
        me: 1,
    }));
    bob.add_transport(Arc::new(MockLink {
        net: net.clone(),
        me: 2,
    }));
    assert_eq!(alice.group_messages(&gid).unwrap().len(), 2);

    carol
        .group_send(&gid, b"carol after the restarts", NOW + 40, &mut rng)
        .unwrap();
    carol.tick(NOW + 41, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 45, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&events),
        vec![b"carol after the restarts".to_vec()]
    );
    let events = bob.tick(NOW + 45, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&events),
        vec![b"carol after the restarts".to_vec()]
    );

    // Once every current co-member has authenticated v1 Text support, the
    // same encrypt-once group path switches to a canonical framed body.
    let framed = alice
        .group_send(&gid, b"framed after negotiation", NOW + 50, &mut rng)
        .unwrap();
    let history = alice.group_messages(&gid).unwrap();
    assert!(matches!(
        decode_content(&history.last().unwrap().body),
        DecodedContent::Text { id, text: "framed after negotiation" } if id == framed
    ));
}

// ---------------------------------------------------------------------------
// 2. Membership: add mid-flight (no history for the newcomer), creator
//    removal (removed member is cut off and told, survivors rotate and keep
//    talking), voluntary leave (creator re-keys the shrunk roster).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn membership_changes_rotate_and_exclude() {
    let mut rng = StdRng::seed_from_u64(12);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let (mut alice, mut bob, mut carol, _a_id, b_id, c_id) = trio(dir.path(), &net, &mut rng).await;

    // Start with Alice + Bob only.
    let gid = alice.create_group("committee", &[b_id], &mut rng).unwrap();
    alice
        .group_send(&gid, b"before carol", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 2, &mut rng).await.unwrap();
    assert_eq!(group_bodies(&events).len(), 1);
    bob.tick(NOW + 3, &mut rng).await.unwrap(); // bob's announce to alice
    alice.tick(NOW + 4, &mut rng).await.unwrap();

    // Add Carol: she learns the group, reads nothing sent before her time.
    alice.group_add(&gid, &c_id, &mut rng).unwrap();
    alice.tick(NOW + 10, &mut rng).await.unwrap();
    let events = carol.tick(NOW + 12, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::GroupUpdated { group } if *group == gid)));
    assert!(group_bodies(&events).is_empty(), "no history for newcomers");
    carol.tick(NOW + 13, &mut rng).await.unwrap(); // carol's announces out
    bob.tick(NOW + 14, &mut rng).await.unwrap(); // bob learns roster, announces to carol
    alice.tick(NOW + 15, &mut rng).await.unwrap();
    bob.tick(NOW + 16, &mut rng).await.unwrap();

    alice
        .group_send(&gid, b"with carol", NOW + 20, &mut rng)
        .unwrap();
    alice.tick(NOW + 21, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&carol.tick(NOW + 22, &mut rng).await.unwrap()),
        vec![b"with carol".to_vec()]
    );
    assert_eq!(
        group_bodies(&bob.tick(NOW + 22, &mut rng).await.unwrap()),
        vec![b"with carol".to_vec()]
    );

    // Remove Carol: she is told (local group gone), survivors rotate and
    // whatever Alice says next never reaches her.
    alice.group_remove(&gid, &c_id, NOW + 30, &mut rng).unwrap();
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    let events = carol.tick(NOW + 33, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::GroupUpdated { group } if *group == gid)));
    assert!(carol.groups().unwrap().is_empty(), "removed member told");
    let events = bob.tick(NOW + 33, &mut rng).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::GroupUpdated { group } if *group == gid)),
        "survivor sees the roster change"
    );
    bob.tick(NOW + 34, &mut rng).await.unwrap(); // bob's rotated announce to alice
    alice.tick(NOW + 35, &mut rng).await.unwrap();

    alice
        .group_send(&gid, b"carol must not read this", NOW + 40, &mut rng)
        .unwrap();
    alice.tick(NOW + 41, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&bob.tick(NOW + 42, &mut rng).await.unwrap()),
        vec![b"carol must not read this".to_vec()]
    );
    assert!(
        group_bodies(&carol.tick(NOW + 42, &mut rng).await.unwrap()).is_empty(),
        "no envelope even addresses the removed member"
    );

    // Bob rotates too: his post-removal chain reaches Alice, not Carol.
    bob.group_send(&gid, b"bob after removal", NOW + 50, &mut rng)
        .unwrap();
    bob.tick(NOW + 51, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&alice.tick(NOW + 52, &mut rng).await.unwrap()),
        vec![b"bob after removal".to_vec()]
    );

    // Voluntary leave: Bob tells Alice, Alice (creator) re-keys, Bob's
    // local group is gone. The group is now just Alice.
    bob.group_leave(&gid, NOW + 60, &mut rng).unwrap();
    assert!(bob.groups().unwrap().is_empty());
    bob.tick(NOW + 61, &mut rng).await.unwrap();
    let events = alice.tick(NOW + 62, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::GroupUpdated { group } if *group == gid)));
    assert_eq!(alice.groups().unwrap()[0].members.len(), 1);

    // Non-creators cannot manage the roster.
    assert!(matches!(
        carol.group_add(&gid, &b_id, &mut rng),
        Err(kult_node::NodeError::UnknownGroup)
    ));
}

// ---------------------------------------------------------------------------
// 3. Backup/restore (KKR5): groups and ordinary history ride the backup; the
//    restored node re-handshakes, announces a fresh chain, co-members
//    redistribute theirs, and messaging resumes in both directions.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_from_backup_reannounces_and_resumes() {
    let mut rng = StdRng::seed_from_u64(13);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let (mut alice, mut bob, mut carol, a_id, b_id, _c_id) = trio(dir.path(), &net, &mut rng).await;
    drop(carol.drain_events());

    let gid = alice.create_group("survivors", &[b_id], &mut rng).unwrap();
    alice
        .group_send(&gid, b"pre-backup", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bob.tick(NOW + 2, &mut rng).await.unwrap();
    bob.tick(NOW + 3, &mut rng).await.unwrap();
    alice.tick(NOW + 4, &mut rng).await.unwrap();

    let pre_backup_capability = alice.group_mention_capability(&gid).unwrap();
    assert!(pre_backup_capability.supported());
    let mention_text = "backup keeps @Bob 👩🏽‍🚀";
    let mention_start = mention_text.find("@Bob").unwrap() as u32;
    let mention_spans = [MentionSpan {
        start: mention_start,
        end: mention_start + "@Bob".len() as u32,
        target: b_id,
    }];
    let pre_backup_mention = alice
        .group_send_mention(
            &gid,
            mention_text,
            &mention_spans,
            pre_backup_capability.review_token,
            NOW + 5,
            &mut rng,
        )
        .unwrap();
    alice.tick(NOW + 6, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 7, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MentionReceived { id } if *id == pre_backup_mention
    )));
    alice.tick(NOW + 9, &mut rng).await.unwrap();

    // Future and malformed Mention bodies remain opaque durable bytes. Have
    // Bob send both inbound so the backup proof covers receiver retention,
    // not only locally-authored history.
    let protocol_spans = mention_spans.map(Into::into);
    let mut future_mention = encode_mention([0x71; 16], mention_text, &protocol_spans).unwrap();
    future_mention[CONTENT_HEADER_LEN] = 2;
    assert!(matches!(
        decode_content(&future_mention),
        DecodedContent::Unsupported {
            format_version: Some(1),
            kind: Some(3),
        }
    ));
    let mut malformed_mention = encode_mention([0x72; 16], mention_text, &protocol_spans).unwrap();
    malformed_mention.pop();
    assert_eq!(
        decode_content(&malformed_mention),
        DecodedContent::Malformed
    );
    bob.group_send(&gid, &future_mention, NOW + 10, &mut rng)
        .unwrap();
    bob.group_send(&gid, &malformed_mention, NOW + 10, &mut rng)
        .unwrap();
    bob.tick(NOW + 11, &mut rng).await.unwrap();
    alice.tick(NOW + 12, &mut rng).await.unwrap();

    // Poll events are ordinary sealed group records, so KKR5 needs no new
    // backup field. Prove the complete derived card survives restore.
    let poll_id = alice
        .group_create_poll(
            &gid,
            "Backup lunch? 🥪",
            &["Soup".to_owned(), "Sandwich".to_owned()],
            NOW + 13,
            &mut rng,
        )
        .unwrap();
    alice.tick(NOW + 14, &mut rng).await.unwrap();
    bob.tick(NOW + 15, &mut rng).await.unwrap();
    let received_poll = bob.group_polls(&gid).unwrap().remove(0);
    let chosen = received_poll.options[1].id;
    bob.group_vote_poll(&gid, a_id, poll_id, chosen, NOW + 16, &mut rng)
        .unwrap();
    bob.tick(NOW + 17, &mut rng).await.unwrap();
    alice.tick(NOW + 18, &mut rng).await.unwrap();
    alice
        .group_close_poll(&gid, a_id, poll_id, NOW + 19, &mut rng)
        .unwrap();
    let before_backup_poll = alice.group_polls(&gid).unwrap().remove(0);
    assert!(before_backup_poll.closed);
    assert_eq!(before_backup_poll.question, "Backup lunch? 🥪");
    assert_eq!(before_backup_poll.votes.len(), 1);
    assert_eq!(before_backup_poll.votes[0].option_id, chosen);
    let pre_backup_history = alice.group_messages(&gid).unwrap();
    assert!(pre_backup_history
        .iter()
        .any(|record| record.body == future_mention));
    assert!(pre_backup_history
        .iter()
        .any(|record| record.body == malformed_mention));

    // Alice's device dies; she restores from backup on a new one.
    let pre_backup_record_count = pre_backup_history.len();
    let (backup, mnemonic) = alice.export_backup(NOW + 20, &mut rng).unwrap();
    drop(alice);
    let mut alice = Node::restore(
        &dir.path().join("a2.db"),
        &backup,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    alice.add_transport(Arc::new(MockLink {
        net: net.clone(),
        me: 1,
    }));
    assert_eq!(alice.peer_id(), a_id, "identity resumes");
    assert_eq!(alice.groups().unwrap().len(), 1, "groups ride the backup");
    assert_eq!(
        alice.group_messages(&gid).unwrap().len(),
        pre_backup_record_count,
        "group history rides the backup"
    );
    let restored_poll = alice.group_polls(&gid).unwrap().remove(0);
    assert!(restored_poll.closed);
    assert_eq!(restored_poll.id, poll_id);
    assert_eq!(restored_poll.question, "Backup lunch? 🥪");
    assert_eq!(restored_poll.votes.len(), 1);
    assert_eq!(restored_poll.votes[0].option_id, chosen);
    let restored_history = alice.group_messages(&gid).unwrap();
    assert!(restored_history
        .iter()
        .any(|record| record.body == future_mention));
    assert!(restored_history
        .iter()
        .any(|record| record.body == malformed_mention));
    let restored_valid_mention = restored_history
        .iter()
        .find(|record| {
            matches!(
                decode_content(&record.body),
                DecodedContent::Mention { id, .. } if id == pre_backup_mention
            )
        })
        .unwrap();
    match decode_content(&restored_valid_mention.body) {
        DecodedContent::Mention { id, mention } => {
            assert_eq!(id, pre_backup_mention);
            assert_eq!(mention.text, mention_text);
            assert_eq!(
                mention.spans().collect::<Vec<_>>(),
                mention_spans.map(Into::into)
            );
        }
        other => panic!("expected restored canonical mention, got {other:?}"),
    }

    // Capability snapshots are intentionally excluded from KKR5 because
    // their authentication is session-bound. The old review token therefore
    // fails closed until the restored device completes a fresh handshake and
    // receives a new authenticated snapshot.
    let reset_capability = alice.group_mention_capability(&gid).unwrap();
    assert!(!reset_capability.supported());
    assert!(matches!(
        alice.group_send_mention(
            &gid,
            mention_text,
            &mention_spans,
            pre_backup_capability.review_token,
            NOW + 11,
            &mut rng,
        ),
        Err(NodeError::MentionReviewRequired)
    ));

    // First tick: re-handshake + fresh-chain announce leave together. Bob
    // adopts both, and his side re-announces over the fresh session.
    alice.tick(NOW + 20, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 22, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == a_id)));
    bob.tick(NOW + 23, &mut rng).await.unwrap();
    alice.tick(NOW + 25, &mut rng).await.unwrap();

    let fresh_capability = alice.group_mention_capability(&gid).unwrap();
    assert!(fresh_capability.supported());
    let restored_mention = alice
        .group_send_mention(
            &gid,
            mention_text,
            &mention_spans,
            fresh_capability.review_token,
            NOW + 26,
            &mut rng,
        )
        .unwrap();
    alice.tick(NOW + 27, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 28, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MentionReceived { id } if *id == restored_mention
    )));
    alice.tick(NOW + 29, &mut rng).await.unwrap();

    // Both directions flow again.
    alice
        .group_send(&gid, b"back from the dead", NOW + 30, &mut rng)
        .unwrap();
    alice.tick(NOW + 31, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&bob.tick(NOW + 32, &mut rng).await.unwrap()),
        vec![b"back from the dead".to_vec()]
    );
    bob.group_send(&gid, b"good to have you back", NOW + 40, &mut rng)
        .unwrap();
    bob.tick(NOW + 41, &mut rng).await.unwrap();
    assert_eq!(
        group_bodies(&alice.tick(NOW + 42, &mut rng).await.unwrap()),
        vec![b"good to have you back".to_vec()]
    );
}

// ---------------------------------------------------------------------------
// 4. B17 semantic mentions: exact capability intersection and roster review,
//    canonical encrypted content, one ciphertext fan-out, stable peer targets,
//    and endpoint-local notification only for the exact authenticated target.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mention_is_capability_gated_roster_bound_and_notifies_exact_target() {
    let mut rng = StdRng::seed_from_u64(17);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let (mut alice, mut bob, mut carol, _a_id, b_id, c_id) = trio(dir.path(), &net, &mut rng).await;
    let gid = alice
        .create_group("duplicate petnames", &[b_id, c_id], &mut rng)
        .unwrap();

    // Before the pairwise capability controls are authenticated, both current
    // co-members fail closed. A snapshot token is never reusable after those
    // session-bound facts change.
    let unknown = alice.group_mention_capability(&gid).unwrap();
    assert!(!unknown.supported());
    assert_eq!(unknown.issues.len(), 2);

    // The explicit readable fallback remains permanent legacy UTF-8 while
    // even one current co-member has no authenticated Text capability.
    // It carries no target table or semantic notification relevance.
    let legacy_fallback = "👋 @Alex and @Alex";
    alice
        .group_send(&gid, legacy_fallback.as_bytes(), NOW, &mut rng)
        .unwrap();
    assert!(matches!(
        decode_content(&alice.group_messages(&gid).unwrap()[0].body),
        DecodedContent::LegacyText(text) if text == legacy_fallback
    ));

    settle_trio(&mut alice, &mut bob, &mut carol, &mut rng, NOW + 1).await;
    assert!(bob.group_messages(&gid).unwrap().iter().any(|record| {
        matches!(
            decode_content(&record.body),
            DecodedContent::LegacyText(text) if text == legacy_fallback
        )
    }));
    let supported = alice.group_mention_capability(&gid).unwrap();
    assert!(supported.supported());
    assert_ne!(unknown.review_token, supported.review_token);

    let text = "👋 @Alex and @Alex";
    let start = text.find("@Alex").unwrap() as u32;
    let end = start + "@Alex".len() as u32;
    let spans = [MentionSpan {
        start,
        end,
        target: b_id,
    }];
    assert!(matches!(
        alice.group_send_mention(&gid, text, &spans, unknown.review_token, NOW + 30, &mut rng,),
        Err(NodeError::MentionReviewRequired)
    ));
    let encoded_bypass = encode_mention(
        [0x55; 16],
        text,
        &spans.iter().copied().map(Into::into).collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(matches!(
        alice.group_send(&gid, &encoded_bypass, NOW + 30, &mut rng),
        Err(NodeError::InvalidMention)
    ));
    assert!(matches!(
        alice.send_message(&b_id, &encoded_bypass, NOW + 30, &mut rng),
        Err(NodeError::InvalidMention)
    ));
    let id = alice
        .group_send_mention(
            &gid,
            text,
            &spans,
            supported.review_token,
            NOW + 31,
            &mut rng,
        )
        .unwrap();

    let history = alice.group_messages(&gid).unwrap();
    match decode_content(&history.last().unwrap().body) {
        DecodedContent::Mention {
            id: decoded_id,
            mention,
        } => {
            assert_eq!(decoded_id, id);
            assert_eq!(mention.text, text);
            assert_eq!(mention.spans().collect::<Vec<_>>(), spans.map(Into::into));
        }
        other => panic!("expected canonical mention, got {other:?}"),
    }

    alice.tick(NOW + 32, &mut rng).await.unwrap();
    let mention_wire_body = {
        let net = net.lock().unwrap();
        let bodies = [2u32, 3]
            .into_iter()
            .flat_map(|node| net.get(&node).into_iter().flatten())
            .filter(|env| env.kind == EnvelopeKind::GroupMessage)
            .map(|env| env.body.clone())
            .collect::<Vec<_>>();
        assert_eq!(bodies.len(), 2, "exactly one fan-out copy per co-member");
        assert_eq!(bodies[0], bodies[1], "one sender-key ciphertext is reused");
        assert!(
            !bodies[0]
                .windows(text.len())
                .any(|window| window == text.as_bytes()),
            "fallback text escaped sender-key encryption"
        );
        assert!(
            !bodies[0]
                .windows(b_id.len())
                .any(|window| window == b_id.as_slice()),
            "mention target escaped sender-key encryption"
        );
        assert!(
            !bodies[0]
                .windows(CONTENT_MAGIC.len())
                .any(|window| window == CONTENT_MAGIC),
            "typed content kind escaped sender-key encryption"
        );
        assert!(
            !bodies[0].windows(id.len()).any(|window| window == id),
            "content id escaped sender-key encryption"
        );
        for offset in [start.to_le_bytes(), end.to_le_bytes()] {
            assert!(
                !bodies[0]
                    .windows(offset.len())
                    .any(|window| window == offset),
                "mention range escaped sender-key encryption"
            );
        }
        bodies[0].clone()
    };

    let bob_events = bob.tick(NOW + 33, &mut rng).await.unwrap();
    assert!(bob_events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived {
            group,
            sender: _,
            id: event_id,
            body,
            content: ContentStatus::Mention { id: content_id, spans: event_spans },
            ..
        } if *group == gid
            && *event_id == id
            && *content_id == id
            && body == text.as_bytes()
            && event_spans == &spans
    )));
    assert_eq!(
        bob_events
            .iter()
            .filter(
                |event| matches!(event, Event::MentionReceived { id: event_id } if *event_id == id)
            )
            .count(),
        1
    );

    let carol_events = carol.tick(NOW + 33, &mut rng).await.unwrap();
    assert!(carol_events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived {
            id: event_id,
            body,
            content: ContentStatus::Mention { .. },
            ..
        } if *event_id == id && body == text.as_bytes()
    )));
    assert!(
        !carol_events
            .iter()
            .any(|event| matches!(event, Event::MentionReceived { .. })),
        "visible fallback names never trigger semantic notification"
    );

    // Ordinary text with the same visible bytes has no semantic signal.
    alice
        .group_send(&gid, text.as_bytes(), NOW + 34, &mut rng)
        .unwrap();
    alice.tick(NOW + 35, &mut rng).await.unwrap();
    {
        let net = net.lock().unwrap();
        let plain_wire_body = net
            .get(&2)
            .into_iter()
            .flatten()
            .find(|envelope| envelope.kind == EnvelopeKind::GroupMessage)
            .map(|envelope| &envelope.body)
            .expect("plain group envelope queued");
        assert_eq!(
            plain_wire_body.len(),
            mention_wire_body.len(),
            "short Mention content uses the same existing padding bucket as ordinary text"
        );
        assert!(
            !plain_wire_body
                .windows(text.len())
                .any(|window| window == text.as_bytes()),
            "ordinary fallback text escaped sender-key encryption"
        );
    }
    assert!(!bob
        .tick(NOW + 36, &mut rng)
        .await
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::MentionReceived { .. })));
    assert!(!carol
        .tick(NOW + 36, &mut rng)
        .await
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::MentionReceived { .. })));

    // Authenticated malformed and future/unknown typed content remains
    // durable as exact bytes for a later decoder, but never exposes guessed
    // text/spans or produces a mention signal.
    let mut malformed = encoded_bypass.clone();
    malformed.pop();
    let mut unknown_kind = encoded_bypass;
    unknown_kind[5..7].copy_from_slice(&999u16.to_le_bytes());
    alice
        .group_send(&gid, &malformed, NOW + 37, &mut rng)
        .unwrap();
    alice
        .group_send(&gid, &unknown_kind, NOW + 37, &mut rng)
        .unwrap();
    alice.tick(NOW + 38, &mut rng).await.unwrap();
    let bob_retention_events = bob.tick(NOW + 39, &mut rng).await.unwrap();
    assert!(bob_retention_events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived {
            body,
            content: ContentStatus::Malformed,
            ..
        } if body.is_empty()
    )));
    assert!(bob_retention_events.iter().any(|event| matches!(
        event,
        Event::GroupMessageReceived {
            body,
            content: ContentStatus::Unsupported {
                format_version: Some(1),
                kind: Some(999),
            },
            ..
        } if body.is_empty()
    )));
    assert!(!bob_retention_events
        .iter()
        .any(|event| matches!(event, Event::MentionReceived { .. })));
    let retained = bob.group_messages(&gid).unwrap();
    assert!(retained.iter().any(|record| record.body == malformed));
    assert!(retained.iter().any(|record| record.body == unknown_kind));
    let carol_retention_events = carol.tick(NOW + 39, &mut rng).await.unwrap();
    assert!(!carol_retention_events
        .iter()
        .any(|event| matches!(event, Event::MentionReceived { .. })));

    // Removing the selected identity invalidates the reviewed snapshot. A
    // fresh snapshot still cannot retarget the historical span to a peer with
    // a matching display name.
    alice.group_remove(&gid, &b_id, NOW + 40, &mut rng).unwrap();
    assert!(matches!(
        alice.group_send_mention(
            &gid,
            text,
            &spans,
            supported.review_token,
            NOW + 41,
            &mut rng,
        ),
        Err(NodeError::MentionReviewRequired)
    ));
    let after_remove = alice.group_mention_capability(&gid).unwrap();
    assert!(matches!(
        alice.group_send_mention(
            &gid,
            text,
            &spans,
            after_remove.review_token,
            NOW + 42,
            &mut rng,
        ),
        Err(NodeError::InvalidMention)
    ));

    // Authenticated history remains bound to Bob's key after he leaves.
    let historic_mention = alice
        .group_messages(&gid)
        .unwrap()
        .into_iter()
        .find(|record| matches!(decode_content(&record.body), DecodedContent::Mention { .. }))
        .expect("semantic mention remains in history");
    match decode_content(&historic_mention.body) {
        DecodedContent::Mention { mention, .. } => {
            assert_eq!(mention.spans().next().unwrap().target, b_id);
            assert_eq!(mention.text, text);
        }
        other => panic!("expected retained mention, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. C5 polls: fixed electorate, visible authenticated revisions, roster
//    changes, creator closure snapshot, and convergent derived tallies.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn polls_converge_across_changed_votes_roster_changes_and_closure() {
    let mut rng = StdRng::seed_from_u64(22);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let (mut alice, mut bob, mut carol, a_id, b_id, c_id) = trio(dir.path(), &net, &mut rng).await;
    let gid = alice.create_group("polls", &[b_id], &mut rng).unwrap();

    // No semantic first flight: capability state is authenticated before a
    // poll can enter sender-key history or any transport queue.
    assert!(matches!(
        alice.group_create_poll(
            &gid,
            "Lunch?",
            &["Soup".to_owned(), "Salad".to_owned()],
            NOW,
            &mut rng,
        ),
        Err(NodeError::PollUnsupported)
    ));
    settle_trio(&mut alice, &mut bob, &mut carol, &mut rng, NOW + 1).await;

    let poll_id = alice
        .group_create_poll(
            &gid,
            "Lunch? 👩🏽‍🚀",
            &["Soup".to_owned(), "Salad".to_owned()],
            NOW + 30,
            &mut rng,
        )
        .unwrap();
    let authored = alice.group_polls(&gid).unwrap().remove(0);
    assert_eq!(authored.id, poll_id);
    let mut electorate = vec![a_id, b_id];
    electorate.sort_unstable();
    assert_eq!(authored.eligible_voters, electorate);
    assert!(authored.can_close);
    let soup = authored.options[0].id;
    let salad = authored.options[1].id;

    // Canonical raw-send bypasses are rejected for both group and pairwise
    // generic APIs; only the exact typed poll commands may author them.
    let bypass_event = [0x91; 16];
    let bypass = encode_poll(
        bypass_event,
        &encode_poll_vote_payload(&PollVote {
            poll_author: a_id,
            poll_id,
            option_id: soup,
            revision: 1,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        alice.group_send(&gid, &bypass, NOW + 30, &mut rng),
        Err(NodeError::InvalidPoll)
    ));
    assert!(matches!(
        alice.send_message(&b_id, &bypass, NOW + 30, &mut rng),
        Err(NodeError::InvalidPoll)
    ));

    alice.tick(NOW + 31, &mut rng).await.unwrap();
    let bob_events = bob.tick(NOW + 32, &mut rng).await.unwrap();
    assert!(bob_events.iter().any(|event| matches!(
        event,
        Event::PollUpdated { group, poll_author, poll_id: event_poll }
            if *group == gid && *poll_author == a_id && *event_poll == poll_id
    )));
    assert_eq!(bob.group_polls(&gid).unwrap()[0].question, "Lunch? 👩🏽‍🚀");

    // Additions do not silently join an existing electorate.
    alice.group_add(&gid, &c_id, &mut rng).unwrap();
    settle_trio(&mut alice, &mut bob, &mut carol, &mut rng, NOW + 34).await;
    assert!(
        carol.group_polls(&gid).unwrap().is_empty(),
        "a new member is not backfilled old group history or electorate state"
    );
    assert!(matches!(
        carol.group_vote_poll(&gid, a_id, poll_id, soup, NOW + 55, &mut rng),
        Err(NodeError::InvalidPoll)
    ));

    // Bob changes his vote. Revisions, not delivery timestamps, decide his
    // live head; all current replicas derive the same visible tally.
    bob.group_vote_poll(&gid, a_id, poll_id, soup, NOW + 56, &mut rng)
        .unwrap();
    bob.group_vote_poll(&gid, a_id, poll_id, salad, NOW + 57, &mut rng)
        .unwrap();
    settle_trio(&mut alice, &mut bob, &mut carol, &mut rng, NOW + 58).await;
    for poll in [
        alice.group_polls(&gid).unwrap().remove(0),
        bob.group_polls(&gid).unwrap().remove(0),
    ] {
        assert_eq!(poll.votes.len(), 1);
        assert_eq!(poll.votes[0].voter, b_id);
        assert_eq!(poll.votes[0].revision, 2);
        assert_eq!(poll.votes[0].option_id, salad);
        assert_eq!(poll.options[1].votes, 1);
    }

    // Removing the later non-electorate member does not change the poll. The
    // creator's closure snapshot carries the exact final head to the original
    // remaining voter, independent of later delivery order.
    alice.group_remove(&gid, &c_id, NOW + 80, &mut rng).unwrap();
    let close_id = alice
        .group_close_poll(&gid, a_id, poll_id, NOW + 81, &mut rng)
        .unwrap();
    assert!(matches!(
        alice.group_vote_poll(&gid, a_id, poll_id, soup, NOW + 82, &mut rng),
        Err(NodeError::PollClosed)
    ));
    alice.tick(NOW + 83, &mut rng).await.unwrap();
    let bob_events = bob.tick(NOW + 84, &mut rng).await.unwrap();
    assert!(bob_events.iter().any(|event| matches!(
        event,
        Event::PollUpdated { poll_id: event_poll, .. } if *event_poll == poll_id
    )));
    let final_alice = alice.group_polls(&gid).unwrap().remove(0);
    let final_bob = bob.group_polls(&gid).unwrap().remove(0);
    for poll in [&final_alice, &final_bob] {
        assert!(poll.closed);
        assert_eq!(poll.close_event_id, Some(close_id));
        assert_eq!(poll.eligible_voters, electorate);
        assert_eq!(poll.votes[0].option_id, salad);
        assert_eq!(poll.options[1].votes, 1);
    }
    alice.group_remove(&gid, &b_id, NOW + 85, &mut rng).unwrap();
    assert_eq!(
        alice.group_polls(&gid).unwrap()[0].votes,
        final_alice.votes,
        "removing a voter never rewrites the closed historic snapshot"
    );
    assert_eq!(
        alice.resolved_group_messages(&gid).unwrap().len(),
        0,
        "poll events render as poll cards, never empty chat bubbles"
    );
}
