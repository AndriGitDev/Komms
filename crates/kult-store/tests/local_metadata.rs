//! F5 sealed local metadata acceptance: typed records stay local, survive
//! restart, enforce replacement invariants, and reveal no keys or values in a
//! copied SQLite database.

use rand::{rngs::StdRng, SeedableRng};
use rusqlite::Connection;

use kult_crypto::KdfProfile;
use kult_store::{
    ConversationId, ConversationMetadata, CustomIconRecord, CustomIconTarget, DraftRecord,
    FolderAssignment, FolderRecord, LabelAssignment, LabelRecord, LocalMetadataKey,
    LocalMetadataRecord, PinRecord, Store, StoreError, ThemePreference, UiPreferenceRecord,
    MAX_DRAFT_BYTES,
};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn sample_records() -> Vec<LocalMetadataRecord> {
    let peer = ConversationId::Peer([1; 32]);
    let group = ConversationId::Group([2; 32]);
    vec![
        LocalMetadataRecord::Conversation(ConversationMetadata {
            conversation: peer.clone(),
            created_at: 1_800_000_000,
        }),
        LocalMetadataRecord::Conversation(ConversationMetadata {
            conversation: ConversationId::NoteToSelf,
            created_at: 1_800_000_001,
        }),
        LocalMetadataRecord::Folder(FolderRecord {
            id: [3; 16],
            name: "Expedition plans".to_owned(),
            order: 4,
        }),
        LocalMetadataRecord::FolderAssignment(FolderAssignment {
            conversation: peer.clone(),
            folder: [3; 16],
        }),
        LocalMetadataRecord::Pin(PinRecord {
            conversation: group.clone(),
            order: 7,
        }),
        LocalMetadataRecord::Label(LabelRecord {
            id: [4; 16],
            name: "Needs reply".to_owned(),
            color: "warning".to_owned(),
        }),
        LocalMetadataRecord::LabelAssignment(LabelAssignment {
            label: [4; 16],
            conversation: peer.clone(),
        }),
        LocalMetadataRecord::Draft(DraftRecord {
            conversation: peer,
            content: b"bring the paper map".to_vec(),
            updated_at: 1_800_000_010,
        }),
        LocalMetadataRecord::UiPreference(UiPreferenceRecord {
            key: "appearance.theme".to_owned(),
            value: b"dark".to_vec(),
        }),
        LocalMetadataRecord::CustomIcon(CustomIconRecord {
            target: CustomIconTarget::Folder([3; 16]),
            media_type: "image/png".to_owned(),
            bytes: b"sanitized-png-bytes".to_vec(),
        }),
    ]
}

#[test]
fn theme_preference_is_canonical_idempotent_and_unknown_legacy_is_safe() {
    let mut rng = StdRng::seed_from_u64(0xb12);
    let directory = tempfile::tempdir().unwrap();
    let store = Store::create(
        &directory.path().join("theme.db"),
        b"passphrase",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();

    assert_eq!(store.theme_preference().unwrap(), None);
    assert!(store
        .set_theme_preference(ThemePreference::System, &mut rng)
        .unwrap());
    assert!(!store
        .set_theme_preference(ThemePreference::System, &mut rng)
        .unwrap());
    assert_eq!(
        store.theme_preference().unwrap(),
        Some(ThemePreference::System)
    );

    store
        .put_local_metadata(
            &LocalMetadataRecord::UiPreference(UiPreferenceRecord {
                key: "appearance.theme".to_owned(),
                value: b"sepia".to_vec(),
            }),
            &mut rng,
        )
        .unwrap();
    assert_eq!(store.theme_preference().unwrap(), None);
    assert!(store
        .set_theme_preference(ThemePreference::Dark, &mut rng)
        .unwrap());
    assert_eq!(
        store.theme_preference().unwrap(),
        Some(ThemePreference::Dark)
    );
}

#[test]
fn every_record_round_trips_across_restart_and_stays_sealed() {
    let mut rng = StdRng::seed_from_u64(0x10ca1);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("metadata.db");
    let records = sample_records();

    let store = Store::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    for record in &records {
        store.put_local_metadata(record, &mut rng).unwrap();
    }
    assert_eq!(store.local_metadata().unwrap(), records);
    drop(store);

    let raw = Connection::open(&db).unwrap();
    let mut statement = raw
        .prepare("SELECT blob FROM local_metadata ORDER BY rowid_")
        .unwrap();
    let blobs = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let joined = blobs.concat();
    for secret in [
        &b"Expedition plans"[..],
        &b"Needs reply"[..],
        &b"bring the paper map"[..],
        &b"appearance.theme"[..],
        &b"sanitized-png-bytes"[..],
        &[2u8; 32][..],
        &7u32.to_le_bytes()[..],
    ] {
        assert!(
            !joined.windows(secret.len()).any(|window| window == secret),
            "local metadata plaintext leaked into SQLite"
        );
    }
    drop(statement);
    drop(raw);

    let reopened = Store::open(&db, b"pass").unwrap();
    assert_eq!(reopened.local_metadata().unwrap(), records);
}

#[test]
fn logical_keys_replace_in_place_and_model_folder_and_label_cardinality() {
    let mut rng = StdRng::seed_from_u64(0x10ca2);
    let dir = tempfile::tempdir().unwrap();
    let store =
        Store::create(&dir.path().join("metadata.db"), b"pass", TEST_KDF, &mut rng).unwrap();
    let conversation = ConversationId::Peer([8; 32]);

    for folder in [[1; 16], [2; 16]] {
        store
            .put_local_metadata(
                &LocalMetadataRecord::FolderAssignment(FolderAssignment {
                    conversation: conversation.clone(),
                    folder,
                }),
                &mut rng,
            )
            .unwrap();
    }
    let assignment = store
        .get_local_metadata(&LocalMetadataKey::FolderAssignment(conversation.clone()))
        .unwrap()
        .unwrap();
    assert_eq!(
        assignment,
        LocalMetadataRecord::FolderAssignment(FolderAssignment {
            conversation: conversation.clone(),
            folder: [2; 16],
        })
    );
    assert_eq!(store.local_metadata().unwrap().len(), 1);

    for label in [[3; 16], [4; 16]] {
        store
            .put_local_metadata(
                &LocalMetadataRecord::LabelAssignment(LabelAssignment {
                    label,
                    conversation: conversation.clone(),
                }),
                &mut rng,
            )
            .unwrap();
    }
    assert_eq!(store.local_metadata().unwrap().len(), 3);

    assert!(store
        .delete_local_metadata(&LocalMetadataKey::LabelAssignment(
            [3; 16],
            conversation.clone(),
        ))
        .unwrap());
    assert!(!store
        .delete_local_metadata(&LocalMetadataKey::LabelAssignment([3; 16], conversation,))
        .unwrap());
}

#[test]
fn oversized_or_empty_records_fail_before_storage() {
    let mut rng = StdRng::seed_from_u64(0x10ca3);
    let dir = tempfile::tempdir().unwrap();
    let store =
        Store::create(&dir.path().join("metadata.db"), b"pass", TEST_KDF, &mut rng).unwrap();

    let too_large = LocalMetadataRecord::Draft(DraftRecord {
        conversation: ConversationId::NoteToSelf,
        content: vec![0; MAX_DRAFT_BYTES + 1],
        updated_at: 1,
    });
    assert!(matches!(
        store.put_local_metadata(&too_large, &mut rng),
        Err(StoreError::LocalMetadataBounds)
    ));
    let empty_name = LocalMetadataRecord::Folder(FolderRecord {
        id: [1; 16],
        name: String::new(),
        order: 0,
    });
    assert!(matches!(
        store.put_local_metadata(&empty_name, &mut rng),
        Err(StoreError::LocalMetadataBounds)
    ));
    assert!(store.local_metadata().unwrap().is_empty());
}
