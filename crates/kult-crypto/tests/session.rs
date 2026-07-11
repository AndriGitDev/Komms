//! Handshake and session integration tests, including the M1 acceptance
//! soak: 10 000 messages under random loss and reordering (docs/08-roadmap.md).

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use kult_crypto::{
    initiate, respond, safety_number, CryptoError, Identity, InitialMessage, OneTimePrekeySecret,
    PqPrekeySecret, PrekeyBundle, RatchetMessage, Session, SignedPrekeySecret, StorageKey,
    MAX_SKIP,
};

const NOW: u64 = 1_800_000_000;

struct Peer {
    id: Identity,
    spk: SignedPrekeySecret,
    pqspk: PqPrekeySecret,
    opk: OneTimePrekeySecret,
}

impl Peer {
    fn new(rng: &mut StdRng) -> Self {
        Self {
            id: Identity::generate(rng),
            spk: SignedPrekeySecret::generate(rng, 1),
            pqspk: PqPrekeySecret::generate(rng, 1),
            opk: OneTimePrekeySecret::generate(rng, 7),
        }
    }

    fn bundle(&self, with_opk: bool) -> PrekeyBundle {
        PrekeyBundle::build(
            &self.id,
            &self.spk,
            &self.pqspk,
            with_opk.then_some(&self.opk),
            NOW + 7 * 86_400,
            vec![],
        )
    }
}

fn establish(rng: &mut StdRng, with_opk: bool) -> (Session, Session) {
    let alice = Identity::generate(rng);
    let bob = Peer::new(rng);
    let verified = bob.bundle(with_opk).verify(NOW).unwrap();
    let (a_sess, init) = initiate(&alice, &verified, b"hello bob", NOW, rng).unwrap();

    // Wire round-trip of the first flight.
    let decoded = InitialMessage::decode(&init.encode()).unwrap();
    let (b_sess, first) = respond(
        &bob.id,
        &bob.spk,
        &bob.pqspk,
        with_opk.then_some(&bob.opk),
        &decoded,
        NOW,
        rng,
    )
    .unwrap();
    assert_eq!(first, b"hello bob");
    assert_eq!(a_sess.session_id(), b_sess.session_id());
    (a_sess, b_sess)
}

#[test]
fn handshake_with_and_without_opk() {
    let mut rng = StdRng::seed_from_u64(1);
    for with_opk in [true, false] {
        let (mut a, mut b) = establish(&mut rng, with_opk);
        // Bidirectional traffic immediately after the handshake.
        let m = b.encrypt(&mut rng, NOW, b"hi alice", &[]);
        assert_eq!(a.decrypt(&mut rng, NOW, &m, &[]).unwrap(), b"hi alice");
        let m = a.encrypt(&mut rng, NOW, b"hi again", &[]);
        assert_eq!(b.decrypt(&mut rng, NOW, &m, &[]).unwrap(), b"hi again");
    }
}

#[test]
fn tampered_bundle_is_rejected() {
    let mut rng = StdRng::seed_from_u64(2);
    let bob = Peer::new(&mut rng);

    let mut b = bob.bundle(true);
    b.spk[0] ^= 1; // substitute the signed prekey
    assert!(matches!(b.verify(NOW), Err(CryptoError::InvalidSignature)));

    let mut b = bob.bundle(true);
    b.pqspk[100] ^= 1; // substitute the PQ prekey
    assert!(matches!(b.verify(NOW), Err(CryptoError::InvalidSignature)));

    let mut b = bob.bundle(true);
    let mallory = Identity::generate(&mut rng);
    b.identity = mallory.public(); // swap the identity
    assert!(b.verify(NOW).is_err());

    let b = bob.bundle(true);
    // Expired bundle.
    assert!(matches!(
        b.verify(NOW + 30 * 86_400),
        Err(CryptoError::InvalidBundle)
    ));
}

#[test]
fn tampered_initial_message_fails() {
    let mut rng = StdRng::seed_from_u64(3);
    let alice = Identity::generate(&mut rng);
    let bob = Peer::new(&mut rng);
    let verified = bob.bundle(true).verify(NOW).unwrap();
    let (_a, init) = initiate(&alice, &verified, b"x", NOW, &mut rng).unwrap();

    // Flip a byte of the KEM ciphertext: decapsulation silently yields a
    // different secret (implicit rejection) and the first AEAD must fail.
    let mut bad = init.clone();
    bad.kem_ct[17] ^= 1;
    assert!(respond(
        &bob.id,
        &bob.spk,
        &bob.pqspk,
        Some(&bob.opk),
        &bad,
        NOW,
        &mut rng
    )
    .is_err());

    // Flip a byte of the ephemeral key.
    let mut bad = init.clone();
    bad.ek[3] ^= 1;
    assert!(respond(
        &bob.id,
        &bob.spk,
        &bob.pqspk,
        Some(&bob.opk),
        &bad,
        NOW,
        &mut rng
    )
    .is_err());

    // Wrong prekey ids must be refused before any crypto.
    let mut bad = init;
    bad.spk_id = 999;
    assert!(matches!(
        respond(
            &bob.id,
            &bob.spk,
            &bob.pqspk,
            Some(&bob.opk),
            &bad,
            NOW,
            &mut rng
        ),
        Err(CryptoError::HandshakeMismatch)
    ));
}

#[test]
fn wrong_ad_fails() {
    let mut rng = StdRng::seed_from_u64(4);
    let (mut a, mut b) = establish(&mut rng, true);
    let m = a.encrypt(&mut rng, NOW, b"payload", b"ad-1");
    assert!(b.decrypt(&mut rng, NOW, &m, b"ad-2").is_err());
    assert_eq!(b.decrypt(&mut rng, NOW, &m, b"ad-1").unwrap(), b"payload");
}

#[test]
fn replay_is_rejected() {
    let mut rng = StdRng::seed_from_u64(5);
    let (mut a, mut b) = establish(&mut rng, true);
    let m = a.encrypt(&mut rng, NOW, b"once", &[]);
    assert!(b.decrypt(&mut rng, NOW, &m, &[]).is_ok());
    assert!(b.decrypt(&mut rng, NOW, &m, &[]).is_err());
}

#[test]
fn out_of_order_within_bounds() {
    let mut rng = StdRng::seed_from_u64(6);
    let (mut a, mut b) = establish(&mut rng, true);
    let msgs: Vec<RatchetMessage> = (0..50)
        .map(|i| a.encrypt(&mut rng, NOW, format!("m{i}").as_bytes(), &[]))
        .collect();
    // Deliver in reverse.
    for (i, m) in msgs.iter().enumerate().rev() {
        assert_eq!(
            b.decrypt(&mut rng, NOW, m, &[]).unwrap(),
            format!("m{i}").as_bytes()
        );
    }
}

#[test]
fn skip_beyond_max_fails_closed() {
    let mut rng = StdRng::seed_from_u64(7);
    let (mut a, mut b) = establish(&mut rng, true);
    for _ in 0..(MAX_SKIP + 1) {
        a.encrypt(&mut rng, NOW, b"dropped", &[]);
    }
    let m = a.encrypt(&mut rng, NOW, b"too far", &[]);
    assert_eq!(
        b.decrypt(&mut rng, NOW, &m, &[]).unwrap_err(),
        CryptoError::TooManySkipped
    );
}

#[test]
fn skipped_keys_expire_after_ttl() {
    let mut rng = StdRng::seed_from_u64(8);
    let (mut a, mut b) = establish(&mut rng, true);
    let early = a.encrypt(&mut rng, NOW, b"late delivery", &[]);
    let later = a.encrypt(&mut rng, NOW, b"on time", &[]);
    // Receiving `later` first stores a skipped key for `early`.
    assert!(b.decrypt(&mut rng, NOW, &later, &[]).is_ok());
    // 31 days later the skipped key must be gone.
    let future = NOW + 31 * 86_400;
    assert!(b.decrypt(&mut rng, future, &early, &[]).is_err());
}

#[test]
fn sealed_state_roundtrip() {
    let mut rng = StdRng::seed_from_u64(9);
    let (mut a, b) = establish(&mut rng, true);
    let m1 = a.encrypt(&mut rng, NOW, b"before seal", &[]);

    let key = StorageKey::generate(&mut rng);
    let sealed = b.seal(&key, &mut rng);
    // Wrong key must fail uniformly.
    let other = StorageKey::generate(&mut rng);
    assert!(Session::unseal(&sealed, &other).is_err());

    let mut b2 = Session::unseal(&sealed, &key).unwrap();
    assert_eq!(b2.decrypt(&mut rng, NOW, &m1, &[]).unwrap(), b"before seal");
    // And the restored session keeps ratcheting both directions.
    let m2 = b2.encrypt(&mut rng, NOW, b"from restored", &[]);
    assert_eq!(
        a.decrypt(&mut rng, NOW, &m2, &[]).unwrap(),
        b"from restored"
    );
}

#[test]
fn message_decode_never_panics_on_garbage() {
    let mut rng = StdRng::seed_from_u64(10);
    for len in [0usize, 1, 50, 120, 121, 200] {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf[..]);
        let _ = RatchetMessage::decode(&buf);
        let _ = InitialMessage::decode(&buf);
        let _ = PrekeyBundle::decode(&buf);
    }
}

#[test]
fn safety_numbers_are_symmetric_and_distinct() {
    let mut rng = StdRng::seed_from_u64(11);
    let a = Identity::generate(&mut rng).public();
    let b = Identity::generate(&mut rng).public();
    let c = Identity::generate(&mut rng).public();
    let ab = safety_number(&a, &b);
    let ba = safety_number(&b, &a);
    assert_eq!(ab, ba);
    assert_eq!(ab.digits.len(), 60);
    assert!(ab.digits.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(ab, safety_number(&a, &c));
    assert_eq!(ab.display_groups().split(' ').count(), 12);
}

#[test]
fn kult_address_format() {
    let mut rng = StdRng::seed_from_u64(12);
    let a = Identity::generate(&mut rng).public();
    let addr = a.address();
    assert!(addr.starts_with("kk1"));
    // 34-byte multihash → ceil(34*8/5) = 55 base32 chars.
    assert_eq!(addr.len(), 3 + 55);
    a.verify().unwrap();
}

/// M1 acceptance soak: two parties, 10 000 messages, random direction
/// switches, ~1% permanent loss, shuffled delivery within windows — every
/// delivered message must decrypt, in whatever order it arrives.
#[test]
fn soak_10k_messages_loss_and_reorder() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let (mut a, mut b) = establish(&mut rng, true);

    let mut sent = 0u32;
    let mut delivered = 0u32;
    let mut turn_a = true;

    while sent < 10_000 {
        // Sender emits a burst of 1..=20 messages.
        let burst = rng.gen_range(1..=20).min(10_000 - sent);
        let (tx, rx) = if turn_a {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let mut batch = Vec::with_capacity(burst as usize);
        for _ in 0..burst {
            let body = format!("msg-{sent}");
            batch.push((
                body.clone(),
                tx.encrypt(&mut rng, NOW, body.as_bytes(), &[]),
            ));
            sent += 1;
        }
        // ~1% of messages are lost forever; the rest arrive shuffled.
        batch.retain(|_| rng.gen_range(0..100) != 0);
        batch.shuffle(&mut rng);
        for (body, msg) in &batch {
            let pt = rx.decrypt(&mut rng, NOW, msg, &[]).unwrap();
            assert_eq!(pt, body.as_bytes());
            delivered += 1;
        }
        turn_a = !turn_a;
    }
    assert_eq!(sent, 10_000);
    assert!(delivered > 9_700, "delivered {delivered}");
}
