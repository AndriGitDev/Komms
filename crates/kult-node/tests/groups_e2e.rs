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
use kult_node::{Event, Node};
use kult_protocol::{decode_content, DecodedContent, Envelope, EnvelopeKind};
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
// 3. Backup/restore (KKR2): groups and history ride the backup; the
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

    // Alice's device dies; she restores from backup on a new one.
    let (backup, mnemonic) = alice.export_backup(NOW + 10, &mut rng).unwrap();
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
        1,
        "group history rides the backup"
    );

    // First tick: re-handshake + fresh-chain announce leave together. Bob
    // adopts both, and his side re-announces over the fresh session.
    alice.tick(NOW + 20, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 22, &mut rng).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::SessionEstablished { peer } if *peer == a_id)));
    bob.tick(NOW + 23, &mut rng).await.unwrap();
    alice.tick(NOW + 25, &mut rng).await.unwrap();

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
