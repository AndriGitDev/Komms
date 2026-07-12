//! Two-device sneakernet demo: fully offline E2E-encrypted messaging via a
//! `.kkb` courier file. Run with:
//!
//! ```sh
//! cargo run --example sneakernet_demo
//! ```
//!
//! Everything a transport would carry is written to real files in a temp
//! directory; no network is touched at any point.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;

use kult_crypto::{
    initiate, open_anonymous, respond, safety_number, seal_anonymous, Identity, InitialMessage,
    KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle, RatchetMessage,
    SignedPrekeySecret,
};
use kult_protocol::{
    bundle_export, bundle_import, delivery_token, epoch_day, intro_token, pad, unpad, Envelope,
    EnvelopeKind, MailboxKey,
};
use kult_store::Store;

const HS_AD: &[u8] = b"KK-handshake-v1";
const DEMO_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 64 * 1024,
    t_cost: 3,
    p_cost: 4,
};

fn main() {
    let mut rng = OsRng;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let dir = std::env::temp_dir().join(format!("komms-demo-{now}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    println!(
        "Komms sneakernet demo — working dir: {}\n",
        dir.display()
    );

    // -- Two devices, two encrypted stores ---------------------------------
    println!("[alice] creating encrypted store (Argon2id 64 MiB)…");
    let alice_store = Store::create(
        &dir.join("alice.db"),
        b"alice-passphrase",
        DEMO_KDF,
        &mut rng,
    )
    .expect("create alice store");
    let alice = Identity::generate(&mut rng);
    alice_store.put_identity(&alice, &mut rng).unwrap();

    println!("[bob]   creating encrypted store…");
    let bob_store = Store::create(&dir.join("bob.db"), b"bob-passphrase", DEMO_KDF, &mut rng)
        .expect("create bob store");
    let bob = Identity::generate(&mut rng);
    bob_store.put_identity(&bob, &mut rng).unwrap();

    println!("\n[alice] address: {}", alice.public().address());
    println!("[bob]   address: {}", bob.public().address());
    let sn = safety_number(&alice.public(), &bob.public());
    println!(
        "        safety number (verify in person): {}",
        sn.display_groups()
    );

    // -- Bob hands Alice his prekey bundle (QR / sticker / file) -----------
    let spk = SignedPrekeySecret::generate(&mut rng, 1);
    let pqspk = PqPrekeySecret::generate(&mut rng, 1);
    let opk = OneTimePrekeySecret::generate(&mut rng, 1);
    let bundle_bytes =
        PrekeyBundle::build(&bob, &spk, &pqspk, Some(&opk), now + 7 * 86_400, vec![]).encode();
    println!(
        "\n[bob]   prekey bundle exported ({} bytes: X25519 + ML-KEM-768, all signed)",
        bundle_bytes.len()
    );

    // -- Alice: hybrid PQXDH handshake + messages, all onto a USB stick ----
    let verified = PrekeyBundle::decode(&bundle_bytes)
        .unwrap()
        .verify(now)
        .expect("bundle verifies");
    let (mut a_session, init) = initiate(
        &alice,
        &verified,
        &pad(b"meet at the harbour, 09:00").unwrap(),
        now,
        &mut rng,
    )
    .expect("PQXDH handshake");

    let hs_env = Envelope::new(
        EnvelopeKind::Handshake,
        intro_token(&bob.public().ed, epoch_day(now)),
        seal_anonymous(&bob.public(), HS_AD, &init.encode(), &mut rng),
    );
    let token = delivery_token(
        &MailboxKey::from_bytes(*a_session.mailbox_key()),
        epoch_day(now),
        &bob.public().ed,
    );
    let m2 = a_session.encrypt(&mut rng, now, &pad(b"bring the radios").unwrap(), &[]);
    let msg_env = Envelope::new(EnvelopeKind::Message, token, m2.encode());
    alice_store
        .put_session(&bob.public().ed, &a_session, &mut rng)
        .unwrap();

    let courier = dir.join("courier.kkb");
    std::fs::write(&courier, bundle_export(&[hs_env, msg_env])).unwrap();
    println!(
        "[alice] 2 sealed envelopes → {} ({} bytes on the USB stick)",
        courier.display(),
        std::fs::metadata(&courier).unwrap().len()
    );
    println!("        on the wire: rotating tokens + ciphertext. No names, no sizes, no graph.");

    // -- Bob: imports the courier file, no network ever --------------------
    println!("\n[bob]   importing courier file…");
    let envelopes = bundle_import(&std::fs::read(&courier).unwrap()).unwrap();
    let mut b_session = None;
    for env in &envelopes {
        if !bob_store.mark_seen(&env.content_id()).unwrap() {
            continue; // duplicate from another path — normal, dropped
        }
        match env.kind {
            EnvelopeKind::Handshake => {
                let init_bytes = open_anonymous(&bob, HS_AD, &env.body).expect("addressed to bob");
                let init = InitialMessage::decode(&init_bytes).unwrap();
                let (s, first) = respond(&bob, &spk, &pqspk, Some(&opk), &init, now, &mut rng)
                    .expect("handshake response");
                println!(
                    "[bob]   session established (hybrid post-quantum). first message: {:?}",
                    String::from_utf8_lossy(&unpad(&first).unwrap())
                );
                b_session = Some(s);
            }
            EnvelopeKind::Message => {
                let s = b_session.as_mut().expect("session first");
                let m = RatchetMessage::decode(&env.body).unwrap();
                let pt = s.decrypt(&mut rng, now, &m, &[]).expect("decrypts");
                println!(
                    "[bob]   ratchet message decrypted:          {:?}",
                    String::from_utf8_lossy(&unpad(&pt).unwrap())
                );
            }
            other => println!("[bob]   skipping unexpected envelope: {other:?}"),
        }
    }
    bob_store
        .put_session(&alice.public().ed, &b_session.unwrap(), &mut rng)
        .unwrap();

    println!("\nDone. Both stores are sealed at rest; the courier file and a copied");
    println!(
        "database leak nothing but sizes. Delete {} when done.",
        dir.display()
    );
}
