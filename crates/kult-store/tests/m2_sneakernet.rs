//! M2 acceptance (docs/08-roadmap.md): two nodes exchange messages via
//! sneakernet bundle files end-to-end — write → export → *process restart* →
//! import → read — with queue and session state surviving the restart, and a
//! copied database file leaking no plaintext.

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{
    initiate, open_anonymous, respond, seal_anonymous, Identity, InitialMessage, KdfProfile,
    OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle, RatchetMessage, SignedPrekeySecret,
};
use kult_protocol::{
    bundle_export, bundle_import, delivery_token, epoch_day, intro_token, pad, unpad, Envelope,
    EnvelopeKind, MailboxKey,
};
use kult_store::{DeliveryState, Direction, MessageRecord, QueueItem, Store};

const NOW: u64 = 1_800_000_000;
const HS_AD: &[u8] = b"KK-handshake-v1";
/// Fast Argon2id profile for tests only (real profiles are spec §8).
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

const MSG_A1: &[u8] = b"hello bob, this arrived on a USB stick";
const MSG_A2: &[u8] = b"second message, still no network involved";
const MSG_B1: &[u8] = b"got both. replying by the same courier";

#[test]
fn sneakernet_end_to_end_with_restart() {
    let mut rng = StdRng::seed_from_u64(0x5EED);
    let dir = tempfile::tempdir().unwrap();
    let alice_db = dir.path().join("alice.db");
    let bob_db = dir.path().join("bob.db");
    let bundle_a_to_b = dir.path().join("courier1.kkb");
    let bundle_b_to_a = dir.path().join("courier2.kkb");

    // ---- Day 0: both devices initialize their stores --------------------
    let alice_id;
    let bob_id_pub;
    let bob_prekeys_serialized;
    let bob_bundle_bytes;
    {
        let alice = Store::create(&alice_db, b"alice-pass", TEST_KDF, &mut rng).unwrap();
        let a_ident = Identity::generate(&mut rng);
        alice.put_identity(&a_ident, &mut rng).unwrap();
        alice_id = a_ident.public();

        let bob = Store::create(&bob_db, b"bob-pass", TEST_KDF, &mut rng).unwrap();
        let b_ident = Identity::generate(&mut rng);
        bob.put_identity(&b_ident, &mut rng).unwrap();
        bob_id_pub = b_ident.public();

        // Bob's prekeys (serialized like a prekey store would hold them).
        let spk = SignedPrekeySecret::generate(&mut rng, 1);
        let pqspk = PqPrekeySecret::generate(&mut rng, 1);
        let opk = OneTimePrekeySecret::generate(&mut rng, 42);
        bob_prekeys_serialized = (
            spk.to_bytes().to_vec(),
            pqspk.to_bytes().to_vec(),
            pqspk.public().to_vec(),
            opk.to_bytes().to_vec(),
        );
        bob_bundle_bytes =
            PrekeyBundle::build(&b_ident, &spk, &pqspk, Some(&opk), NOW + 7 * 86_400, vec![])
                .encode();
    }

    // ---- Alice: handshake + two messages, queued, exported, "shutdown" --
    {
        let alice = Store::open(&alice_db, b"alice-pass").unwrap();
        let a_ident = alice.get_identity().unwrap().unwrap();

        let bundle = PrekeyBundle::decode(&bob_bundle_bytes)
            .unwrap()
            .verify(NOW)
            .unwrap();
        let (mut session, init) =
            initiate(&a_ident, &bundle, &pad(MSG_A1).unwrap(), NOW, &mut rng).unwrap();

        // Handshake flight: anonymous-boxed so no identity is visible on the wire.
        let hs_env = Envelope::new(
            EnvelopeKind::Handshake,
            intro_token(&bob_id_pub.ed, epoch_day(NOW)),
            seal_anonymous(&bob_id_pub, HS_AD, &init.encode(), &mut rng),
        );
        alice
            .queue_push(
                &QueueItem {
                    peer: bob_id_pub.ed,
                    msg_id: Some([0u8; 16]),
                    envelope: hs_env,
                },
                &mut rng,
            )
            .unwrap();

        // Second message rides the established session.
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(NOW),
        );
        let m2 = session.encrypt(&mut rng, NOW, &pad(MSG_A2).unwrap(), &[]);
        let msg_env = Envelope::new(EnvelopeKind::Message, token, m2.encode());
        alice
            .queue_push(
                &QueueItem {
                    peer: bob_id_pub.ed,
                    msg_id: Some([1u8; 16]),
                    envelope: msg_env,
                },
                &mut rng,
            )
            .unwrap();

        // Persist everything; record both messages as Queued.
        alice
            .put_session(&bob_id_pub.ed, &session, &mut rng)
            .unwrap();
        for (i, body) in [MSG_A1, MSG_A2].iter().enumerate() {
            alice
                .put_message(
                    &MessageRecord {
                        id: [i as u8; 16],
                        peer: bob_id_pub.ed,
                        direction: Direction::Outbound,
                        state: DeliveryState::Queued,
                        timestamp: NOW,
                        body: body.to_vec(),
                        wire_id: None,
                    },
                    &mut rng,
                )
                .unwrap();
        }
        // Alice's device "shuts down" here (store dropped)...
    }

    // ---- ...and restarts: the queue must have survived -------------------
    {
        let alice = Store::open(&alice_db, b"alice-pass").unwrap();
        let queued = alice.queue_all().unwrap();
        assert_eq!(queued.len(), 2, "queue must survive restart");
        let envs: Vec<Envelope> = queued.iter().map(|(_, i)| i.envelope.clone()).collect();
        std::fs::write(&bundle_a_to_b, bundle_export(&envs)).unwrap();
        for (seq, _) in queued {
            alice.queue_ack(seq).unwrap(); // handed to the courier
        }
        assert!(alice.queue_all().unwrap().is_empty());
    }

    // Wrong passphrase must fail closed, not open a broken store.
    assert!(Store::open(&alice_db, b"wrong-pass").is_err());

    // ---- Bob (after his own restart): imports the courier file ----------
    {
        let bob = Store::open(&bob_db, b"bob-pass").unwrap();
        let b_ident = bob.get_identity().unwrap().unwrap();

        // Prekey secrets reloaded from their serialized form.
        let (spk_b, pq_dk, pq_ek, opk_b) = &bob_prekeys_serialized;
        let spk = SignedPrekeySecret::from_bytes(1, &spk_b[..].try_into().unwrap());
        let pqspk = PqPrekeySecret::from_bytes(1, pq_dk, pq_ek).unwrap();
        let opk = OneTimePrekeySecret::from_bytes(42, &opk_b[..].try_into().unwrap());

        let imported = bundle_import(&std::fs::read(&bundle_a_to_b).unwrap()).unwrap();
        assert_eq!(imported.len(), 2);

        let mut session = None;
        let mut received = Vec::new();
        for env in &imported {
            assert!(
                bob.mark_seen(&env.content_id()).unwrap(),
                "no duplicates yet"
            );
            match env.kind {
                EnvelopeKind::Handshake => {
                    // Expected at the public introduction token.
                    assert_eq!(env.token, intro_token(&bob_id_pub.ed, epoch_day(NOW)));
                    let init_bytes = open_anonymous(&b_ident, HS_AD, &env.body).unwrap();
                    let init = InitialMessage::decode(&init_bytes).unwrap();
                    let (s, first) =
                        respond(&b_ident, &spk, &pqspk, Some(&opk), &init, NOW, &mut rng).unwrap();
                    received.push(unpad(&first).unwrap());
                    session = Some(s);
                }
                EnvelopeKind::Message => {
                    let s = session.as_mut().expect("handshake precedes messages");
                    // Bob recognizes his own rotating token.
                    let expect =
                        delivery_token(&MailboxKey::from_bytes(*s.mailbox_key()), epoch_day(NOW));
                    assert_eq!(env.token, expect);
                    let m = RatchetMessage::decode(&env.body).unwrap();
                    let pt = s.decrypt(&mut rng, NOW, &m, &[]).unwrap();
                    received.push(unpad(&pt).unwrap());
                }
                other => panic!("unexpected envelope kind {other:?}"),
            }
        }
        assert_eq!(received, vec![MSG_A1.to_vec(), MSG_A2.to_vec()]);

        // Re-importing the same bundle is a no-op thanks to dedup.
        for env in &imported {
            assert!(!bob.mark_seen(&env.content_id()).unwrap());
        }

        // Bob persists state and queues a reply for the return courier.
        let mut s = session.unwrap();
        let token = delivery_token(&MailboxKey::from_bytes(*s.mailbox_key()), epoch_day(NOW));
        let reply = s.encrypt(&mut rng, NOW, &pad(MSG_B1).unwrap(), &[]);
        bob.queue_push(
            &QueueItem {
                peer: alice_id.ed,
                msg_id: None,
                envelope: Envelope::new(EnvelopeKind::Message, token, reply.encode()),
            },
            &mut rng,
        )
        .unwrap();
        bob.put_session(&alice_id.ed, &s, &mut rng).unwrap();
        bob.put_message(
            &MessageRecord {
                id: [9u8; 16],
                peer: alice_id.ed,
                direction: Direction::Inbound,
                state: DeliveryState::Received,
                timestamp: NOW,
                body: MSG_A1.to_vec(),
                wire_id: None,
            },
            &mut rng,
        )
        .unwrap();
    }

    // ---- Return trip: Bob restarts, exports; Alice restarts, reads ------
    {
        let bob = Store::open(&bob_db, b"bob-pass").unwrap();
        let queued = bob.queue_all().unwrap();
        assert_eq!(queued.len(), 1);
        let envs: Vec<Envelope> = queued.iter().map(|(_, i)| i.envelope.clone()).collect();
        std::fs::write(&bundle_b_to_a, bundle_export(&envs)).unwrap();
    }
    {
        let alice = Store::open(&alice_db, b"alice-pass").unwrap();
        let mut session = alice.get_session(&bob_id_pub.ed).unwrap().unwrap();
        let imported = bundle_import(&std::fs::read(&bundle_b_to_a).unwrap()).unwrap();
        assert_eq!(imported.len(), 1);
        let m = RatchetMessage::decode(&imported[0].body).unwrap();
        let pt = session.decrypt(&mut rng, NOW, &m, &[]).unwrap();
        assert_eq!(unpad(&pt).unwrap(), MSG_B1);
        alice
            .put_session(&bob_id_pub.ed, &session, &mut rng)
            .unwrap();
        let msgs = alice.messages_with(&bob_id_pub.ed).unwrap();
        assert_eq!(msgs.len(), 2); // her two outbound records survived
    }

    // ---- Leakage check: raw DB files contain no plaintext ---------------
    for db in [&alice_db, &bob_db] {
        let raw = std::fs::read(db).unwrap();
        for secret in [MSG_A1, MSG_A2, MSG_B1, b"alice-pass".as_slice()] {
            assert!(
                !raw.windows(secret.len()).any(|w| w == secret),
                "plaintext leaked into {db:?}"
            );
        }
    }
}
