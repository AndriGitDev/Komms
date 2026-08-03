//! Legacy-backup migration at the store boundary (docs/07-storage.md §4):
//! released copied-root fixtures import only as a sanitized local archive
//! under fresh device authority. Wrong mnemonics and tampered files fail
//! whole.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::Serialize;

use kult_crypto::{
    derive_kek, initiate, mnemonic_from_entropy, mnemonic_to_entropy, DeviceAuthorityManifest,
    DeviceManifest, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle,
    SignedPrekeySecret, StorageKey,
};
use kult_protocol::{pad, CapabilityControl, FormatCapabilities};
use kult_store::{
    ContactDeviceRecord, ContactRecord, ConversationId, DeliveryState, DeviceAuthorityStateRecord,
    Direction, DraftRecord, EphemeralConversation, EphemeralMode, EphemeralRecord, EphemeralState,
    GroupAuthorityRecord, GroupDelivery, GroupMember, GroupMessageRecord, GroupRecord,
    LocalMetadataRecord, MessageRecord, NoteMessageRecord, PendingAnnounce, Store, StoreError,
    AUTHORITY_RESET_HISTORY_KEY,
};

const NOW: u64 = 1_800_000_000;
/// Fast Argon2id profile for tests only (real profiles are spec §8).
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Serialize)]
struct LegacyBackupGroup {
    id: [u8; 32],
    name: String,
    creator: [u8; 32],
    members: Vec<GroupMember>,
    secret: [u8; 32],
    generation: u64,
}

#[derive(Serialize)]
struct LegacyBackupPayload {
    created_at: u64,
    identity: Vec<u8>,
    contacts: Vec<ContactRecord>,
    messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    groups: Vec<LegacyBackupGroup>,
    group_messages: Vec<GroupMessageRecord>,
    group_authorities: Vec<GroupAuthorityRecord>,
    local_metadata: Vec<LocalMetadataRecord>,
    note_messages: Vec<NoteMessageRecord>,
    ephemeral: Vec<EphemeralRecord>,
    device_manifest: Option<DeviceManifest>,
    local_device: Option<[u8; 32]>,
    device_sync_events: Vec<Vec<u8>>,
    contact_devices: Vec<ContactDeviceRecord>,
}

/// Encode the released KKR7 shape inside the test instead of retaining a
/// production API that can mint new copied-root packages.
fn legacy_backup_fixture(
    store: &Store,
    identity: &Identity,
    mut messages: Vec<MessageRecord>,
    reset_peers: Vec<[u8; 32]>,
    now: u64,
    rng: &mut StdRng,
) -> (Vec<u8>, String) {
    let mut ephemeral = store.ephemeral_records().unwrap();
    for record in &mut ephemeral {
        record.state = EphemeralState::Expired;
        record.transfer_ids.clear();
    }
    let me = identity.public().ed;
    messages.retain(|message| {
        let author = if message.direction == Direction::Outbound {
            me
        } else {
            message.peer
        };
        !ephemeral.iter().any(|record| {
            record.conversation == EphemeralConversation::Pairwise(message.peer)
                && record.author == author
                && record.content_id == message.id
        })
    });

    let groups = store.groups().unwrap();
    let mut group_messages = Vec::new();
    for group in &groups {
        group_messages.extend(store.group_messages(&group.id).unwrap());
    }
    for message in &mut group_messages {
        message.wire_body = None;
    }
    let device_state = store.get_device_state().unwrap();
    let payload = LegacyBackupPayload {
        created_at: now,
        identity: identity.to_bytes().to_vec(),
        contacts: store.contacts().unwrap(),
        messages,
        reset_peers,
        groups: groups
            .into_iter()
            .map(|group| LegacyBackupGroup {
                id: group.id,
                name: group.name,
                creator: group.creator,
                members: group.members,
                secret: group.secret,
                generation: group.generation,
            })
            .collect(),
        group_messages,
        group_authorities: store.group_authorities().unwrap(),
        local_metadata: store.local_metadata().unwrap(),
        note_messages: store.note_messages().unwrap(),
        ephemeral,
        device_manifest: device_state.as_ref().map(|state| state.manifest.clone()),
        local_device: device_state
            .as_ref()
            .map(|state| state.local_certificate.device_id()),
        device_sync_events: store.device_sync_events().unwrap(),
        contact_devices: store.contact_devices().unwrap(),
    };
    let plain = postcard::to_allocvec(&payload).unwrap();
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    let mnemonic = mnemonic_from_entropy(&entropy);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let key = StorageKey::from_bytes(*derive_kek(&entropy, &salt, TEST_KDF).unwrap());
    let mut file = Vec::new();
    file.extend_from_slice(b"KKR7");
    file.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
    file.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&key.seal(b"KK-backup-v1", &plain, rng));
    (file, (*mnemonic).clone())
}

fn restore_legacy_archive(
    path: &std::path::Path,
    backup: &[u8],
    mnemonic: &str,
    passphrase: &[u8],
    rng: &mut StdRng,
) -> kult_store::Result<Store> {
    let new_root = Identity::generate(rng);
    let device = Identity::generate(rng);
    let manifest =
        DeviceAuthorityManifest::initial(&new_root, &device, "Archive device".into(), NOW, rng)?;
    let state = DeviceAuthorityStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: manifest.devices()[0].certificate.clone(),
        accepted_recovery_epoch: manifest.recovery_epoch(),
        accepted_recovery_anchor: manifest.recovery_anchor_id(),
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
        conflicts: Vec::new(),
        discovery: kult_store::DiscoveryCapabilityState::default(),
    };
    Store::restore_legacy_backup_as_authority_reset(
        path,
        backup,
        mnemonic,
        passphrase,
        TEST_KDF,
        &new_root.public(),
        &state,
        b"fresh-archive-prekeys",
        NOW + 1,
        rng,
    )
    .map(|(store, _)| store)
}

fn assert_only_reset_ledger(store: &Store) {
    let metadata = store.local_metadata().unwrap();
    assert_eq!(metadata.len(), 1);
    assert!(matches!(
        &metadata[0],
        LocalMetadataRecord::UiPreference(record)
            if record.key == AUTHORITY_RESET_HISTORY_KEY
    ));
}

/// A populated store: identity, one contact (with bundle), two messages,
/// one live session, own prekeys. Returns what the backup must carry.
fn populated_store(
    path: &std::path::Path,
    rng: &mut StdRng,
) -> (Store, Identity, ContactRecord, Vec<MessageRecord>, [u8; 32]) {
    let store = Store::create(path, b"old-pass", TEST_KDF, rng).unwrap();
    let identity = Identity::generate(rng);
    store.put_legacy_identity_fixture(&identity, rng).unwrap();
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
                origin: kult_store::GroupOriginAuthentication::LegacyMembership,
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

    let (file, mnemonic) = legacy_backup_fixture(
        &store,
        &identity,
        messages.clone(),
        vec![peer],
        NOW + 100,
        &mut rng,
    );
    assert_eq!(&file[..4], b"KKR7");
    assert!(mnemonic_to_entropy(&mnemonic).is_ok(), "24 valid words");
    drop(store); // the old device is gone

    // Recover only a former-identity local archive under a fresh authority.
    let new_db = dir.path().join("new.db");
    let restored =
        restore_legacy_archive(&new_db, &file, &mnemonic, b"new-pass", &mut rng).unwrap();

    assert!(restored.get_identity().unwrap().is_none());
    assert!(!restored.contains_legacy_account_root().unwrap());
    let account = restored.get_account_identity().unwrap().unwrap();
    assert_ne!(account, identity.public());
    let reset = restored.authority_reset_history().unwrap().unwrap();
    assert_eq!(reset.former_account, identity.public().ed);
    assert_eq!(reset.new_account, account.ed);
    let archived_contact = restored.contacts().unwrap().remove(0);
    assert_eq!(archived_contact.peer, contact.peer);
    assert_eq!(archived_contact.identity, contact.identity);
    assert_eq!(archived_contact.name, contact.name);
    assert!(archived_contact.bundle.is_empty());
    assert!(archived_contact.hints.is_empty());
    assert!(!archived_contact.verified);
    let mut expected_messages = messages;
    for message in &mut expected_messages {
        message.wire_id = None;
    }
    assert_eq!(restored.messages_with(&peer).unwrap(), expected_messages);
    assert!(restored.reset_markers().unwrap().is_empty());
    assert!(restored.get_session(&peer).unwrap().is_none());
    assert!(
        restored.get_capabilities(&peer).unwrap().is_none(),
        "session-scoped capability state is intentionally excluded"
    );
    assert_eq!(
        restored.get_prekeys().unwrap().unwrap().as_slice(),
        b"fresh-archive-prekeys"
    );
    assert_only_reset_ledger(&restored);
    assert_eq!(restored.note_messages().unwrap(), vec![note_message]);
    assert!(restored.group_authorities().unwrap().is_empty());
    assert!(restored.groups().unwrap().is_empty());
    assert!(restored.get_group_chain(&[5; 32], &peer).unwrap().is_none());
    assert!(restored.group_messages(&[5; 32]).unwrap().is_empty());

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

    let restored = restore_legacy_archive(
        &dir.path().join("v1.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();
    assert!(restored.get_identity().unwrap().is_none());
    assert_eq!(
        restored
            .authority_reset_history()
            .unwrap()
            .unwrap()
            .former_account,
        identity.public().ed
    );
    assert!(restored.messages_with(&peer).unwrap().is_empty());
    assert!(restored.reset_markers().unwrap().is_empty());
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

    let restored = restore_legacy_archive(
        &dir.path().join("v2.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();
    assert!(restored.get_identity().unwrap().is_none());
    assert_eq!(
        restored
            .authority_reset_history()
            .unwrap()
            .unwrap()
            .former_account,
        identity.public().ed
    );
    assert!(restored.messages_with(&peer).unwrap().is_empty());
    assert!(restored.reset_markers().unwrap().is_empty());
    assert!(restored.groups().unwrap().is_empty());
    assert_only_reset_ledger(&restored);
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

    let restored = restore_legacy_archive(
        &dir.path().join("v3.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();
    assert_only_reset_ledger(&restored);
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

    let restored = restore_legacy_archive(
        &dir.path().join("v4.db"),
        &file,
        &mnemonic,
        b"new-pass",
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

    let restored = restore_legacy_archive(
        &dir.path().join("v5.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();
    assert!(restored.ephemeral_records().unwrap().is_empty());
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

    let restored = restore_legacy_archive(
        &dir.path().join("v6.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();
    assert!(restored.group_authorities().unwrap().is_empty());
    assert!(restored.contact_devices().unwrap().is_empty());
    assert!(restored.device_sync_events().unwrap().is_empty());
    let device = restored
        .get_device_authority_state()
        .unwrap()
        .expect("device migration");
    assert_ne!(device.manifest.account(), &identity.public());
    assert_eq!(device.manifest.devices().len(), 1);
    assert_eq!(
        device.manifest.devices()[0].certificate,
        device.local_certificate
    );
    assert!(device.manifest.devices()[0].revoked_at.is_none());
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
    let (file, mnemonic) = legacy_backup_fixture(
        &store,
        &identity,
        messages.clone(),
        vec![peer],
        NOW + 10,
        &mut rng,
    );
    let restored = restore_legacy_archive(
        &dir.path().join("restored.db"),
        &file,
        &mnemonic,
        b"new-pass",
        &mut rng,
    )
    .unwrap();

    let history = restored.messages_with(&peer).unwrap();
    assert_eq!(history, vec![messages[1].clone()]);
    assert!(restored.ephemeral_records().unwrap().is_empty());
}

#[test]
fn restore_fails_closed() {
    let mut rng = StdRng::seed_from_u64(12);
    let dir = tempfile::tempdir().unwrap();
    let (store, identity, _, messages, peer) =
        populated_store(&dir.path().join("old.db"), &mut rng);
    let (file, mnemonic) =
        legacy_backup_fixture(&store, &identity, messages, vec![peer], NOW, &mut rng);

    // Wrong mnemonic: valid words, wrong key → uniform crypto failure.
    let wrong = "abandon ".repeat(23) + "art";
    assert!(matches!(
        restore_legacy_archive(&dir.path().join("w.db"), &file, &wrong, b"p", &mut rng),
        Err(StoreError::Crypto(_))
    ));

    // Garbled mnemonic.
    assert!(restore_legacy_archive(
        &dir.path().join("g.db"),
        &file,
        "not a phrase",
        b"p",
        &mut rng
    )
    .is_err());

    // A flipped ciphertext byte rejects the whole file.
    let mut tampered = file.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        restore_legacy_archive(
            &dir.path().join("t.db"),
            &tampered,
            &mnemonic,
            b"p",
            &mut rng
        ),
        Err(StoreError::Crypto(_))
    ));

    // Truncation and bad magic are not backups at all.
    assert!(matches!(
        restore_legacy_archive(
            &dir.path().join("s.db"),
            &file[..20],
            &mnemonic,
            b"p",
            &mut rng
        ),
        Err(StoreError::NotABackup)
    ));
    let mut bad_magic = file.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        restore_legacy_archive(
            &dir.path().join("m.db"),
            &bad_magic,
            &mnemonic,
            b"p",
            &mut rng
        ),
        Err(StoreError::NotABackup)
    ));
    let mut mislabeled = file.clone();
    mislabeled[..4].copy_from_slice(b"KKR3");
    assert!(matches!(
        restore_legacy_archive(
            &dir.path().join("d.db"),
            &mislabeled,
            &mnemonic,
            b"p",
            &mut rng
        ),
        Err(StoreError::NotABackup)
    ));

    // Restoring over an existing store is refused.
    let occupied = dir.path().join("occupied.db");
    Store::create(&occupied, b"p", TEST_KDF, &mut rng).unwrap();
    assert!(restore_legacy_archive(&occupied, &file, &mnemonic, b"p", &mut rng).is_err());
}
