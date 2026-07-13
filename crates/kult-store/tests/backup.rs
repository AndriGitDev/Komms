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
use kult_store::{
    ContactRecord, DeliveryState, Direction, GroupDelivery, GroupMember, GroupMessageRecord,
    GroupRecord, MessageRecord, PendingAnnounce, Store, StoreError,
};

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

    // A group with a live chain and one pending announce (ADR-0012).
    let me = identity.public().ed;
    let chain = kult_crypto::GroupSenderChain::generate(rng);
    store
        .put_group(
            &GroupRecord {
                id: [5; 32],
                name: "expedition".to_owned(),
                creator: me,
                members: vec![
                    GroupMember {
                        peer: me,
                        identity: postcard::to_allocvec(&identity.public()).unwrap(),
                    },
                    GroupMember {
                        peer,
                        identity: postcard::to_allocvec(&peer_identity.public()).unwrap(),
                    },
                ],
                secret: [6; 32],
                prev_secret: Some([7; 32]),
                generation: 3,
                sender_chain: postcard::to_allocvec(&chain).unwrap(),
                sent_since_rotation: 12,
                pending: vec![PendingAnnounce {
                    peer,
                    key_id: chain.key_id(),
                    chain_key: [8; 32],
                    iteration: 0,
                    wire_id: Some([4; 16]),
                    last_sent: NOW,
                }],
            },
            rng,
        )
        .unwrap();
    store
        .put_group_chain(&[5; 32], &peer, b"opaque-receiver-chain", rng)
        .unwrap();
    store
        .put_group_message(
            &GroupMessageRecord {
                id: [3; 16],
                group: [5; 32],
                sender: me,
                direction: Direction::Outbound,
                timestamp: NOW + 8,
                body: b"onward".to_vec(),
                deliveries: vec![GroupDelivery {
                    peer,
                    wire_id: Some([9; 16]),
                    state: DeliveryState::Delivered,
                }],
                wire_body: Some(b"retained-ciphertext".to_vec()),
            },
            rng,
        )
        .unwrap();
    (store, identity, contact, messages, peer)
}

#[test]
fn backup_round_trip() {
    let mut rng = StdRng::seed_from_u64(11);
    let dir = tempfile::tempdir().unwrap();
    let (store, identity, contact, messages, peer) =
        populated_store(&dir.path().join("old.db"), &mut rng);

    let (file, mnemonic) = store.export_backup(NOW + 100, &mut rng).unwrap();
    assert_eq!(&file[..4], b"KKR2");
    assert!(mnemonic_to_entropy(&mnemonic).is_ok(), "24 valid words");
    let old_group = store.groups().unwrap().remove(0);
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

    // The group's identity survives; its chains do not (ADR-0012): a fresh
    // sending chain, announces owed to the whole roster, no receiving
    // chains, and history with the retained ciphertext stripped.
    let group = restored.groups().unwrap().remove(0);
    assert_eq!(
        (group.id, &group.name, group.creator, &group.members),
        (
            [5; 32],
            &old_group.name,
            old_group.creator,
            &old_group.members
        )
    );
    assert_eq!((group.secret, group.generation), ([6; 32], 3));
    assert_eq!(group.prev_secret, None);
    assert_ne!(group.sender_chain, old_group.sender_chain, "fresh chain");
    assert_eq!(group.sent_since_rotation, 0);
    assert_eq!(group.pending.len(), 1);
    assert_eq!(group.pending[0].peer, peer);
    assert_eq!(group.pending[0].wire_id, None);
    assert!(restored.get_group_chain(&[5; 32], &peer).unwrap().is_none());
    let group_msgs = restored.group_messages(&[5; 32]).unwrap();
    assert_eq!(group_msgs.len(), 1);
    assert_eq!(group_msgs[0].body, b"onward");
    assert_eq!(group_msgs[0].wire_body, None);

    // Markers clear once handled, and the new store opens under the new
    // passphrase only.
    restored.clear_reset_marker(&peer).unwrap();
    assert!(restored.reset_markers().unwrap().is_empty());
    drop(restored);
    assert!(Store::open(&new_db, b"new-pass").is_ok());
    assert!(Store::open(&new_db, b"old-pass").is_err());
}

/// A pre-groups `KKR1` file still restores (empty group state).
#[test]
fn legacy_v1_backup_restores() {
    let mut rng = StdRng::seed_from_u64(13);
    let dir = tempfile::tempdir().unwrap();

    // Hand-assemble a v1 file: same header layout, groupless payload
    // (postcard of a struct is the postcard of its fields in order).
    let identity = Identity::generate(&mut rng);
    let peer = [3u8; 32];
    let contacts: Vec<ContactRecord> = vec![];
    let messages = vec![MessageRecord {
        id: [1; 16],
        peer,
        direction: Direction::Inbound,
        state: DeliveryState::Received,
        timestamp: NOW,
        body: b"from the old world".to_vec(),
        wire_id: None,
    }];
    let reset_peers = vec![peer];
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
    ))
    .unwrap();

    let entropy = [0x42u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [7u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR1");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v1.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        restored.get_identity().unwrap().unwrap().public().ed,
        identity.public().ed
    );
    assert_eq!(restored.messages_with(&peer).unwrap(), messages);
    assert_eq!(restored.reset_markers().unwrap(), reset_peers);
    assert!(restored.groups().unwrap().is_empty());
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
