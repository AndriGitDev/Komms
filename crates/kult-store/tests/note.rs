//! B7 store acceptance: note-to-self history is bounded, sealed, local-only,
//! and durable across restart.

use rand::{rngs::StdRng, SeedableRng};
use rusqlite::Connection;

use kult_crypto::KdfProfile;
use kult_store::{NoteMessageRecord, Store, StoreError, MAX_NOTE_TEXT_BYTES};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn note_history_survives_restart_without_plaintext_or_peer_columns() {
    let mut rng = StdRng::seed_from_u64(0x407e);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("notes.db");
    let records = vec![
        NoteMessageRecord {
            id: [1; 16],
            timestamp: 1_800_000_000,
            body: "Remember the paper map".to_owned(),
        },
        NoteMessageRecord {
            id: [2; 16],
            timestamp: 1_800_000_001,
            body: "Battery inventory: 7".to_owned(),
        },
    ];

    let store = Store::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    for record in &records {
        store.put_note_message(record, &mut rng).unwrap();
    }
    assert_eq!(store.note_messages().unwrap(), records);
    drop(store);

    let raw = Connection::open(&database).unwrap();
    let columns = raw
        .prepare("PRAGMA table_info(note_messages)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(columns, vec!["rowid_", "blob"]);
    let blobs = raw
        .prepare("SELECT blob FROM note_messages ORDER BY rowid_")
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .concat();
    assert!(!blobs
        .windows(b"Remember the paper map".len())
        .any(|window| window == b"Remember the paper map"));
    drop(raw);

    assert_eq!(
        Store::open(&database, b"pass")
            .unwrap()
            .note_messages()
            .unwrap(),
        records
    );
}

#[test]
fn empty_and_oversized_notes_fail_before_storage() {
    let mut rng = StdRng::seed_from_u64(0x407f);
    let directory = tempfile::tempdir().unwrap();
    let store = Store::create(
        &directory.path().join("notes.db"),
        b"pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    for body in [String::new(), "x".repeat(MAX_NOTE_TEXT_BYTES + 1)] {
        assert!(matches!(
            store.put_note_message(
                &NoteMessageRecord {
                    id: [3; 16],
                    timestamp: 1,
                    body,
                },
                &mut rng,
            ),
            Err(StoreError::NoteBounds)
        ));
    }
    assert!(store.note_messages().unwrap().is_empty());
}
