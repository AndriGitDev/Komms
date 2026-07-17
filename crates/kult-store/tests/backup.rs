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
use kult_protocol::{pad, CapabilityControl, FormatCapabilities};
use kult_store::{
    ContactRecord, ConversationId, DeliveryState, Direction, DraftRecord, EphemeralConversation,
    EphemeralMode, EphemeralRecord, EphemeralState, GroupAuthorityRecord, GroupDelivery,
    GroupMember, GroupMessageRecord, GroupRecord, LocalMetadataRecord, MessageRecord,
    NoteMessageRecord, PendingAnnounce, Store, StoreError,
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
    store
        .put_capabilities(
            &peer,
            &CapabilityControl {
                formats: vec![FormatCapabilities {
                    format_version: 1,
                    kinds: vec![1],
                }],
            },
            &mut rng,
        )
        .unwrap();
    let local_metadata = LocalMetadataRecord::Draft(DraftRecord {
        conversation: ConversationId::Peer(peer),
        content: b"backed up local draft".to_vec(),
        updated_at: NOW + 50,
    });
    store.put_local_metadata(&local_metadata, &mut rng).unwrap();
    let note_message = NoteMessageRecord {
        id: [10; 16],
        timestamp: NOW + 60,
        body: "backed up note to self".to_owned(),
    };
    store.put_note_message(&note_message, &mut rng).unwrap();
    let authority = GroupAuthorityRecord {
        group: [5; 32],
        state_id: [12; 16],
        state_payload: b"canonical signed authority".to_vec(),
        consumed_requests: vec![[13; 16], [14; 16]],
    };
    store.put_group_authority(&authority, &mut rng).unwrap();

    let (file, mnemonic) = store.export_backup(NOW + 100, &mut rng).unwrap();
    assert_eq!(&file[..4], b"KKR7");
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
    assert!(
        restored.get_capabilities(&peer).unwrap().is_none(),
        "session-scoped capability state is intentionally excluded"
    );
    // Prekeys are never restored — the node layer mints fresh ones.
    assert!(restored.get_prekeys().unwrap().is_none());
    assert_eq!(restored.local_metadata().unwrap(), vec![local_metadata]);
    assert_eq!(restored.note_messages().unwrap(), vec![note_message]);
    assert_eq!(restored.group_authorities().unwrap(), vec![authority]);

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
    assert!(restored.note_messages().unwrap().is_empty());
}

/// A pre-local-metadata `KKR2` file still restores with empty F5 state.
#[test]
fn legacy_v2_backup_restores() {
    let mut rng = StdRng::seed_from_u64(14);
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate(&mut rng);
    let peer = [4u8; 32];
    let contacts: Vec<ContactRecord> = vec![];
    let messages = vec![MessageRecord {
        id: [2; 16],
        peer,
        direction: Direction::Inbound,
        state: DeliveryState::Received,
        timestamp: NOW,
        body: b"from KKR2".to_vec(),
        wire_id: None,
    }];
    let reset_peers = vec![peer];
    // Empty group vectors are format-identical regardless of their element
    // type, so this pins the exact seven-field KKR2 payload shape without
    // exposing kult-store's private backup DTO.
    let groups = Vec::<()>::new();
    let group_messages = Vec::<GroupMessageRecord>::new();
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
        &groups,
        &group_messages,
    ))
    .unwrap();

    let entropy = [0x43u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [8u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR2");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v2.db"),
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
    assert!(restored.local_metadata().unwrap().is_empty());
    assert!(restored.note_messages().unwrap().is_empty());
}

/// A pre-note-to-self `KKR3` file restores its F5 state with empty note history.
#[test]
fn legacy_v3_backup_restores() {
    let mut rng = StdRng::seed_from_u64(15);
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate(&mut rng);
    let contacts = Vec::<ContactRecord>::new();
    let messages = Vec::<MessageRecord>::new();
    let reset_peers = Vec::<[u8; 32]>::new();
    let groups = Vec::<()>::new();
    let group_messages = Vec::<GroupMessageRecord>::new();
    let local_metadata = vec![LocalMetadataRecord::Draft(DraftRecord {
        conversation: ConversationId::NoteToSelf,
        content: b"old KKR3 draft".to_vec(),
        updated_at: NOW,
    })];
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
        &groups,
        &group_messages,
        &local_metadata,
    ))
    .unwrap();

    let entropy = [0x44u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [9u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR3");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v3.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(restored.local_metadata().unwrap(), local_metadata);
    assert!(restored.note_messages().unwrap().is_empty());
}

/// The immediately previous KKR4 shape remains restore-compatible.
#[test]
fn legacy_v4_backup_restores() {
    let mut rng = StdRng::seed_from_u64(16);
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate(&mut rng);
    let contacts = Vec::<ContactRecord>::new();
    let messages = Vec::<MessageRecord>::new();
    let reset_peers = Vec::<[u8; 32]>::new();
    let groups = Vec::<()>::new();
    let group_messages = Vec::<GroupMessageRecord>::new();
    let local_metadata = Vec::<LocalMetadataRecord>::new();
    let notes = vec![NoteMessageRecord {
        id: [11; 16],
        timestamp: NOW,
        body: "old KKR4 note".to_owned(),
    }];
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
        &groups,
        &group_messages,
        &local_metadata,
        &notes,
    ))
    .unwrap();

    let entropy = [0x45u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [10u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR4");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v4.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(restored.note_messages().unwrap(), notes);
    assert!(restored.ephemeral_records().unwrap().is_empty());
}

/// The pre-authority KKR5 shape restores with no signed authority records.
#[test]
fn legacy_v5_backup_restores() {
    let mut rng = StdRng::seed_from_u64(18);
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate(&mut rng);
    let contacts = Vec::<ContactRecord>::new();
    let messages = Vec::<MessageRecord>::new();
    let reset_peers = Vec::<[u8; 32]>::new();
    let groups = Vec::<()>::new();
    let group_messages = Vec::<GroupMessageRecord>::new();
    let local_metadata = Vec::<LocalMetadataRecord>::new();
    let notes = Vec::<NoteMessageRecord>::new();
    let ephemeral = vec![EphemeralRecord {
        conversation: EphemeralConversation::Pairwise([3; 32]),
        author: [4; 32],
        content_id: [5; 16],
        expires_at: NOW,
        mode: EphemeralMode::DisappearingText,
        state: EphemeralState::Expired,
        transfer_ids: Vec::new(),
    }];
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
        &groups,
        &group_messages,
        &local_metadata,
        &notes,
        &ephemeral,
    ))
    .unwrap();

    let entropy = [0x46u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [11u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR5");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v5.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(restored.ephemeral_records().unwrap(), ephemeral);
    assert!(restored.group_authorities().unwrap().is_empty());
}

/// The immediately previous KKR6 shape restores signed authority and migrates
/// to one fresh physical device without inventing linked-device history.
#[test]
fn legacy_v6_backup_restores_and_mints_device_authority() {
    let mut rng = StdRng::seed_from_u64(19);
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate(&mut rng);
    let contacts = Vec::<ContactRecord>::new();
    let messages = Vec::<MessageRecord>::new();
    let reset_peers = Vec::<[u8; 32]>::new();
    let groups = Vec::<()>::new();
    let group_messages = Vec::<GroupMessageRecord>::new();
    let authority = GroupAuthorityRecord {
        group: [7; 32],
        state_id: [8; 16],
        state_payload: b"signed KKR6 authority".to_vec(),
        consumed_requests: vec![[9; 16]],
    };
    let authorities = vec![authority.clone()];
    let local_metadata = Vec::<LocalMetadataRecord>::new();
    let notes = Vec::<NoteMessageRecord>::new();
    let ephemeral = Vec::<EphemeralRecord>::new();
    let payload = postcard::to_allocvec(&(
        NOW,
        identity.to_bytes().to_vec(),
        &contacts,
        &messages,
        &reset_peers,
        &groups,
        &group_messages,
        &authorities,
        &local_metadata,
        &notes,
        &ephemeral,
    ))
    .unwrap();

    let entropy = [0x47u8; 32];
    let mnemonic = kult_crypto::mnemonic_from_entropy(&entropy);
    let salt = [12u8; 16];
    let kek = kult_crypto::derive_kek(&entropy, &salt, TEST_KDF).unwrap();
    let key = kult_crypto::StorageKey::from_bytes(*kek);
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR6");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &payload, &mut rng));

    let restored = Store::restore_backup(
        &dir.path().join("v6.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(restored.group_authorities().unwrap(), vec![authority]);
    assert!(restored.contact_devices().unwrap().is_empty());
    assert!(restored.device_sync_events().unwrap().is_empty());
    let device = restored
        .get_device_state()
        .unwrap()
        .expect("device migration");
    assert_eq!(device.manifest.account, identity.public());
    assert_eq!(device.manifest.devices.len(), 1);
    assert_eq!(
        device.manifest.devices[0].certificate,
        device.local_certificate
    );
    assert!(device.manifest.devices[0].revoked_at.is_none());
}

#[test]
fn backup_excludes_ephemeral_plaintext_and_restores_only_terminal_tombstone() {
    let mut rng = StdRng::seed_from_u64(17);
    let dir = tempfile::tempdir().unwrap();
    let (store, identity, _, messages, peer) =
        populated_store(&dir.path().join("old.db"), &mut rng);
    let marker = EphemeralRecord {
        conversation: EphemeralConversation::Pairwise(peer),
        author: identity.public().ed,
        content_id: messages[0].id,
        expires_at: NOW + 3_600,
        mode: EphemeralMode::DisappearingText,
        state: EphemeralState::Active,
        transfer_ids: vec![],
    };
    store.put_ephemeral_record(&marker, &mut rng).unwrap();
    let (file, mnemonic) = store.export_backup(NOW + 10, &mut rng).unwrap();
    let restored = Store::restore_backup(
        &dir.path().join("restored.db"),
        &file,
        &mnemonic,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();

    let history = restored.messages_with(&peer).unwrap();
    assert_eq!(history, vec![messages[1].clone()]);
    let tombstones = restored.ephemeral_records().unwrap();
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].state, EphemeralState::Expired);
    assert!(tombstones[0].transfer_ids.is_empty());
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
    let mut mislabeled = file.clone();
    mislabeled[..4].copy_from_slice(b"KKR3");
    assert!(matches!(
        Store::restore_backup(
            &dir.path().join("d.db"),
            &mislabeled,
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
