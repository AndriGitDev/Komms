//! Backup round-trip at the store level (docs/07-storage.md §4): export a
//! populated store, restore it into a fresh file, and get identity,
//! contacts, history, and session-reset markers back — never sessions,
//! never prekeys. Wrong mnemonics and tampered files fail whole.

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{
    initiate, mnemonic_to_entropy, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret,
    PrekeyBundle, SignedPrekeySecret,
};
use kult_protocol::pad;
use kult_store::{ContactRecord, DeliveryState, Direction, MessageRecord, Store, StoreError};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only (real profiles are spec §8).
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// A populated store: identity, one contact (with bundle), two messages,
/// one live session, own prekeys. Returns what the backup must carry.
fn populated_store(
    path: &std::path::Path,
    rng: &mut StdRng,
) -> (Store, Identity, ContactRecord, Vec<MessageRecord>, [u8; 32]) {
    let store = Store::create(path, b"old-pass", TEST_KDF, rng).unwrap();
    let identity = Identity::generate(rng);
    store.put_identity(&identity, rng).unwrap();
    store.put_prekeys(b"opaque-vault-blob", rng).unwrap();

    // A real peer with a real bundle, so a session can be initiated.
    let peer_identity = Identity::generate(rng);
    let spk = SignedPrekeySecret::generate(rng, 1);
    let pqspk = PqPrekeySecret::generate(rng, 1);
    let opk = OneTimePrekeySecret::generate(rng, 7);
    let bundle_bytes = PrekeyBundle::build(
        &peer_identity,
        &spk,
        &pqspk,
        Some(&opk),
        NOW + 86_400,
        vec![],
    )
    .encode();
    let peer = peer_identity.public().ed;

    let contact = ContactRecord {
        peer,
        identity: postcard::to_allocvec(&peer_identity.public()).unwrap(),
        name: "ada".to_owned(),
        bundle: bundle_bytes.clone(),
        hints: vec![b"hint-blob".to_vec()],
        verified: true,
    };
    store.put_contact(&contact, rng).unwrap();

    let verified = PrekeyBundle::decode(&bundle_bytes)
        .unwrap()
        .verify(NOW)
        .unwrap();
    let (session, _init) = initiate(&identity, &verified, &pad(b"hi").unwrap(), NOW, rng).unwrap();
    store.put_session(&peer, &session, rng).unwrap();

    let messages = vec![
        MessageRecord {
            id: [1; 16],
            peer,
            direction: Direction::Outbound,
            state: DeliveryState::Delivered,
            timestamp: NOW,
            body: b"hi".to_vec(),
            wire_id: Some([9; 16]),
        },
        MessageRecord {
            id: [2; 16],
            peer,
            direction: Direction::Inbound,
            state: DeliveryState::Received,
            timestamp: NOW + 5,
            body: b"hello back".to_vec(),
            wire_id: None,
        },
    ];
    for message in &messages {
        store.put_message(message, rng).unwrap();
    }
    (store, identity, contact, messages, peer)
}

#[test]
fn backup_round_trip() {
    let mut rng = StdRng::seed_from_u64(11);
    let dir = tempfile::tempdir().unwrap();
    let (store, identity, contact, messages, peer) =
        populated_store(&dir.path().join("old.db"), &mut rng);

    let (file, mnemonic) = store.export_backup(NOW + 100, &mut rng).unwrap();
    assert_eq!(&file[..4], b"KKR1");
    assert!(mnemonic_to_entropy(&mnemonic).is_ok(), "24 valid words");
    drop(store); // the old device is gone

    // Restore on a "new device": new path, new passphrase.
    let new_db = dir.path().join("new.db");
    let restored =
        Store::restore_backup(&new_db, &file, &mnemonic, b"new-pass", TEST_KDF, &mut rng).unwrap();

    // Identity resumes.
    let got = restored.get_identity().unwrap().unwrap();
    assert_eq!(got.public().ed, identity.public().ed);
    // Contacts verbatim — bundle and verification state included.
    assert_eq!(restored.contacts().unwrap(), vec![contact]);
    // History verbatim.
    assert_eq!(restored.messages_with(&peer).unwrap(), messages);
    // The live session became a reset marker; the session itself is gone.
    assert_eq!(restored.reset_markers().unwrap(), vec![peer]);
    assert!(restored.get_session(&peer).unwrap().is_none());
    // Prekeys are never restored — the node layer mints fresh ones.
    assert!(restored.get_prekeys().unwrap().is_none());

    // Markers clear once handled, and the new store opens under the new
    // passphrase only.
    restored.clear_reset_marker(&peer).unwrap();
    assert!(restored.reset_markers().unwrap().is_empty());
    drop(restored);
    assert!(Store::open(&new_db, b"new-pass").is_ok());
    assert!(Store::open(&new_db, b"old-pass").is_err());
}

#[test]
fn restore_fails_closed() {
    let mut rng = StdRng::seed_from_u64(12);
    let dir = tempfile::tempdir().unwrap();
    let (store, _, _, _, _) = populated_store(&dir.path().join("old.db"), &mut rng);
    let (file, mnemonic) = store.export_backup(NOW, &mut rng).unwrap();

    // Wrong mnemonic: valid words, wrong key → uniform crypto failure.
    let wrong = "abandon ".repeat(23) + "art";
    assert!(matches!(
        Store::restore_backup(
            &dir.path().join("w.db"),
            &file,
            &wrong,
            b"p",
            TEST_KDF,
            &mut rng
        ),
        Err(StoreError::Crypto(_))
    ));

    // Garbled mnemonic.
    assert!(Store::restore_backup(
        &dir.path().join("g.db"),
        &file,
        "not a phrase",
        b"p",
        TEST_KDF,
        &mut rng
    )
    .is_err());

    // A flipped ciphertext byte rejects the whole file.
    let mut tampered = file.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        Store::restore_backup(
            &dir.path().join("t.db"),
            &tampered,
            &mnemonic,
            b"p",
            TEST_KDF,
            &mut rng
        ),
        Err(StoreError::Crypto(_))
    ));

    // Truncation and bad magic are not backups at all.
    assert!(matches!(
        Store::restore_backup(
            &dir.path().join("s.db"),
            &file[..20],
            &mnemonic,
            b"p",
            TEST_KDF,
            &mut rng
        ),
        Err(StoreError::NotABackup)
    ));
    let mut bad_magic = file.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        Store::restore_backup(
            &dir.path().join("m.db"),
            &bad_magic,
            &mnemonic,
            b"p",
            TEST_KDF,
            &mut rng
        ),
        Err(StoreError::NotABackup)
    ));

    // Restoring over an existing store is refused.
    let occupied = dir.path().join("occupied.db");
    Store::create(&occupied, b"p", TEST_KDF, &mut rng).unwrap();
    assert!(Store::restore_backup(&occupied, &file, &mnemonic, b"p", TEST_KDF, &mut rng).is_err());
}
