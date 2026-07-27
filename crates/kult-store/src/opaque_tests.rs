use std::fs;

use kult_crypto::KdfProfile;
use kult_protocol::{Envelope, EnvelopeKind};
use rand::{rngs::StdRng, SeedableRng};
use rusqlite::params;

#[cfg(unix)]
use crate::store_lock_path;
use crate::store_v2::TableSpec;
use crate::{
    store_v2, ContactRecord, DeliveryState, Direction, GroupMessageRecord, GroupRecord,
    MessageRecord, QueueClass, QueueItem, Store, StoreError,
};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn valid_ciphertext_with_wrong_inner_key_or_index_fails_closed() {
    for (case, key_peer, index_peer, payload_peer) in [
        ("inner-key", [2; 32], [2; 32], [1; 32]),
        ("secondary-index", [1; 32], [2; 32], [1; 32]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{case}.db"));
        let mut rng = StdRng::seed_from_u64(0x2700);
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let record = pairwise_record(7, payload_peer);
        let encoded = postcard::to_allocvec(&record).unwrap();
        store
            .append::<store_v2::MessageRows>(
                &store_v2::MessageKey::new(key_peer, 1, record.id),
                &encoded,
                store_v2::IndexKeys::message(
                    &store_v2::ContentKey::new(record.id),
                    &store_v2::AccountKey::new(index_peer),
                ),
                &mut rng,
            )
            .unwrap();
        drop(store);
        assert!(matches!(
            Store::open(&path, b"pass"),
            Err(StoreError::LogicalKeyMismatch)
        ));
    }
}

#[test]
fn copied_rows_cannot_cross_database_table_or_locator_identity() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let target_path = directory.path().join("target.db");
    let mut rng = StdRng::seed_from_u64(0x2701);
    let source = Store::create(&source_path, b"pass", TEST_KDF, &mut rng).unwrap();
    source
        .put_message(&pairwise_record(1, [1; 32]), &mut rng)
        .unwrap();
    let copied = physical_message_row(&source);
    let target = Store::create(&target_path, b"pass", TEST_KDF, &mut rng).unwrap();
    insert_physical_row(&target, store_v2::MessageRows::DOMAIN, &copied);
    drop(source);
    drop(target);
    assert!(matches!(
        Store::open(&target_path, b"pass"),
        Err(StoreError::Crypto(_))
    ));

    let table_path = directory.path().join("table.db");
    let table = Store::create(&table_path, b"pass", TEST_KDF, &mut rng).unwrap();
    table
        .put_message(&pairwise_record(2, [2; 32]), &mut rng)
        .unwrap();
    let copied = physical_message_row(&table);
    insert_physical_row(&table, store_v2::GroupMessageRows::DOMAIN, &copied);
    drop(table);
    assert!(matches!(
        Store::open(&table_path, b"pass"),
        Err(StoreError::Crypto(_))
    ));

    let locator_path = directory.path().join("locator.db");
    let locator = Store::create(&locator_path, b"pass", TEST_KDF, &mut rng).unwrap();
    locator
        .put_message(&pairwise_record(3, [3; 32]), &mut rng)
        .unwrap();
    locator
        .conn
        .execute(
            "UPDATE store_records SET locator = randomblob(16) WHERE table_domain = ?1",
            params![store_v2::MessageRows::DOMAIN],
        )
        .unwrap();
    drop(locator);
    assert!(matches!(
        Store::open(&locator_path, b"pass"),
        Err(StoreError::Crypto(_))
    ));
}

#[test]
fn locked_database_has_only_opaque_identifier_columns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("locked.db");
    let mut rng = StdRng::seed_from_u64(0x2702);
    let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
    let peer = [0xa1; 32];
    let group = [0xb2; 32];
    let message_id = [0xc3; 16];
    let group_message_id = [0xd4; 16];
    let delivery_token = [0xe5; 32];
    store
        .put_contact(
            &ContactRecord {
                peer,
                identity: vec![1, 2, 3],
                name: "opaque contact".into(),
                bundle: vec![4, 5],
                hints: vec![vec![6]],
                verified: true,
            },
            &mut rng,
        )
        .unwrap();
    store
        .put_message(
            &MessageRecord {
                id: message_id,
                peer,
                direction: Direction::Outbound,
                state: DeliveryState::Queued,
                timestamp: 1,
                body: b"sealed body".to_vec(),
                wire_id: None,
            },
            &mut rng,
        )
        .unwrap();
    store
        .put_group(
            &GroupRecord {
                id: group,
                name: "opaque group".into(),
                creator: peer,
                members: Vec::new(),
                secret: [7; 32],
                prev_secret: None,
                generation: 1,
                sender_chain: vec![8],
                sent_since_rotation: 0,
                pending: Vec::new(),
            },
            &mut rng,
        )
        .unwrap();
    store
        .put_group_message(
            &GroupMessageRecord {
                id: group_message_id,
                group,
                sender: peer,
                direction: Direction::Inbound,
                timestamp: 2,
                body: b"group body".to_vec(),
                deliveries: Vec::new(),
                wire_body: None,
            },
            &mut rng,
        )
        .unwrap();
    let envelope = Envelope::new(EnvelopeKind::Message, delivery_token, vec![9]);
    store
        .queue_push(
            &QueueItem {
                peer,
                msg_id: Some(message_id),
                group_msg_id: None,
                class: QueueClass::Normal,
                created_at: 3,
                attempts: 0,
                next_attempt_at: 3,
                envelope,
            },
            &mut rng,
        )
        .unwrap();

    let schema = store
        .conn
        .prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(schema.len(), 10);
    assert!(schema.iter().all(|(name, sql)| {
        (name.starts_with("store_") || name.starts_with("sqlite_"))
            && !sql.contains("peer")
            && !sql.contains("group")
            && !sql.contains("message_id")
            && !sql.contains("token")
            && !sql.contains("media_id")
    }));

    let logical_identifiers: [&[u8]; 5] = [
        &peer,
        &group,
        &message_id,
        &group_message_id,
        &delivery_token,
    ];
    let mut statement = store
        .conn
        .prepare(
            "SELECT locator, unique_index, index_a, index_b, index_c, index_d
             FROM store_records",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok([
                Some(row.get::<_, Vec<u8>>(0)?),
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ])
        })
        .unwrap();
    for row in rows {
        for physical in row.unwrap().into_iter().flatten() {
            assert!(matches!(physical.len(), 16 | 32));
            assert!(logical_identifiers
                .iter()
                .all(|logical| physical.as_slice() != *logical));
        }
    }
    drop(statement);
    store
        .conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(store);

    let mut bytes = fs::read(&path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        if let Ok(sidecar_bytes) = fs::read(std::path::PathBuf::from(sidecar)) {
            bytes.extend_from_slice(&sidecar_bytes);
        }
    }
    for logical in logical_identifiers {
        assert!(!bytes.windows(logical.len()).any(|window| window == logical));
    }
}

#[test]
fn cursors_are_stable_opaque_and_bound_to_database_conversation_and_row() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cursor.db");
    let other_path = directory.path().join("other.db");
    let mut rng = StdRng::seed_from_u64(0x2703);
    let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
    let peer = [1; 32];
    let other_peer = [2; 32];
    for value in 0..10 {
        store
            .put_message(&pairwise_record(value, peer), &mut rng)
            .unwrap();
        store
            .put_message(&pairwise_record(100 + value, other_peer), &mut rng)
            .unwrap();
    }
    let first = store.messages_page(&peer, None, 3).unwrap();
    assert_eq!(
        first
            .records
            .iter()
            .map(|record| record.id[0])
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let cursor = first.next.unwrap();
    assert_eq!(cursor.as_bytes().len(), 57);
    assert!(!cursor
        .as_bytes()
        .windows(peer.len())
        .any(|window| window == peer));
    let second = store.messages_page(&peer, Some(&cursor), 3).unwrap();
    assert_eq!(
        second
            .records
            .iter()
            .map(|record| record.id[0])
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert!(matches!(
        store.messages_page(&other_peer, Some(&cursor), 3),
        Err(StoreError::InvalidCursor)
    ));
    let mut forged = cursor.as_bytes().to_vec();
    forged[10] ^= 1;
    assert!(matches!(
        store.messages_page(&peer, Some(&crate::HistoryCursor::from_bytes(forged)), 3),
        Err(StoreError::InvalidCursor)
    ));

    let other = Store::create(&other_path, b"pass", TEST_KDF, &mut rng).unwrap();
    assert!(matches!(
        other.messages_page(&peer, Some(&cursor), 3),
        Err(StoreError::InvalidCursor)
    ));
    drop(other);

    assert!(store
        .delete_message_record(&peer, Direction::Inbound, &[2; 16])
        .unwrap());
    assert!(matches!(
        store.messages_page(&peer, Some(&cursor), 3),
        Err(StoreError::InvalidCursor)
    ));
}

#[test]
fn exact_and_conversation_queries_use_the_keyed_sqlite_indexes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plans.db");
    let mut rng = StdRng::seed_from_u64(0x2704);
    let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
    let exact = query_plan(
        &store,
        "EXPLAIN QUERY PLAN SELECT blob FROM store_records
         WHERE table_domain = 4 AND unique_index = randomblob(32)",
    );
    assert!(exact.contains("store_record_unique"), "{exact}");
    let conversation = query_plan(
        &store,
        "EXPLAIN QUERY PLAN SELECT blob FROM store_records
         WHERE table_domain = 4 AND index_a = randomblob(32) AND rowid_ > 0
         ORDER BY rowid_ LIMIT 65",
    );
    assert!(
        conversation.contains("store_record_index_a"),
        "{conversation}"
    );
}

#[cfg(unix)]
#[test]
fn sqlite_sidecars_locks_and_media_are_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("permissions.db");
    let mut rng = StdRng::seed_from_u64(0x2705);
    let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
    store
        .put_message(&pairwise_record(1, [1; 32]), &mut rng)
        .unwrap();
    let lock = store_lock_path(&path).unwrap();
    let media = store.media_dir.clone();
    for file in [&path, &lock] {
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        if sidecar.exists() {
            assert_eq!(
                fs::metadata(sidecar).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    assert_eq!(
        fs::metadata(media).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

type PhysicalRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
);

fn physical_message_row(store: &Store) -> PhysicalRow {
    store
        .conn
        .query_row(
            "SELECT locator, unique_index, index_a, index_b, index_c, index_d, blob
             FROM store_records WHERE table_domain = ?1 LIMIT 1",
            params![store_v2::MessageRows::DOMAIN],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap()
}

fn insert_physical_row(store: &Store, domain: u8, row: &PhysicalRow) {
    store
        .conn
        .execute(
            "INSERT INTO store_records
             (table_domain, locator, unique_index, index_a, index_b, index_c, index_d, blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![domain, &row.0, &row.1, &row.2, &row.3, &row.4, &row.5, &row.6],
        )
        .unwrap();
}

fn pairwise_record(value: u8, peer: [u8; 32]) -> MessageRecord {
    MessageRecord {
        id: [value; 16],
        peer,
        direction: Direction::Inbound,
        state: DeliveryState::Received,
        timestamp: u64::from(value),
        body: vec![value],
        wire_id: None,
    }
}

fn query_plan(store: &Store, sql: &str) -> String {
    store
        .conn
        .prepare(sql)
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n")
}
