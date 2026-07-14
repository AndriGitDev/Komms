//! ADR-0015 media-store acceptance: sealed metadata, atomic chunk files,
//! restart reconciliation, quota enforcement, and KKR4 exclusion.

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::{Identity, KdfProfile};
use kult_protocol::{
    attachment_chunk_count, encode_attachment, AttachmentManifest, AttachmentObject,
    AttachmentRole, ATTACHMENT_CHUNK_DATA_LEN, ATTACHMENT_SEALED_CHUNK_LEN,
};
use kult_store::{
    DeliveryState, Direction, MediaDirection, MediaLimits, MediaObjectRecord, MediaRecord,
    MediaScope, MediaTransferRecord, MediaTransferState, MessageRecord, Store, StoreError,
};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn records() -> (MediaTransferRecord, MediaObjectRecord) {
    let transfer = MediaTransferRecord {
        local_id: [1; 16],
        peer: [2; 32],
        direction: MediaDirection::Inbound,
        scope: MediaScope::Pairwise,
        scope_id: [3; 32],
        manifest_author: [4; 32],
        manifest_content_id: [5; 16],
        entitled_peers: vec![[2; 32]],
        state: MediaTransferState::Queued,
        updated_at: 1_800_000_000,
    };
    let object = MediaObjectRecord {
        local_id: [6; 16],
        transfer_id: transfer.local_id,
        object_id: [7; 16],
        role: 0,
        total_len: 1,
        chunk_count: 1,
        content_hash: [8; 32],
        media_type: "image/png".to_owned(),
        filename: Some("secret-name.png".to_owned()),
        state: MediaTransferState::Queued,
        verified_bitmap: vec![0],
        chunk_addresses: vec![None],
        verified_bytes: 0,
    };
    (transfer, object)
}

#[test]
fn sealed_chunk_commit_reopens_and_leaks_no_metadata() {
    let mut rng = StdRng::seed_from_u64(0x15);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("store.db");
    let media_dir = dir.path().join("store.db.media");
    let (transfer, object) = records();
    let sealed_chunk = vec![0x55; ATTACHMENT_SEALED_CHUNK_LEN];

    {
        let mut store = Store::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
        store.put_media_transfer(&transfer, &mut rng).unwrap();
        store.put_media_object(&object, &mut rng).unwrap();
        let address = store
            .commit_media_chunk(&object.local_id, 0, &sealed_chunk, &mut rng)
            .unwrap();
        assert_eq!(
            store
                .commit_media_chunk(&object.local_id, 0, &sealed_chunk, &mut rng)
                .unwrap(),
            address,
            "duplicate chunk is idempotent"
        );
        assert_eq!(
            store.read_media_chunk(&object.local_id, 0).unwrap(),
            sealed_chunk
        );
        let MediaRecord::Available(stored) =
            store.get_media_object(&object.local_id).unwrap().unwrap()
        else {
            panic!("known record version")
        };
        assert_eq!(stored.verified_bytes, 1);
        assert_eq!(stored.state, MediaTransferState::Transferring);
        store
            .mark_media_complete(&object.local_id, &object.content_hash, &mut rng)
            .unwrap();
        assert_eq!(store.media_usage().unwrap().active_objects, 0);
    }

    let mut reopened = Store::open(&db, b"pass").unwrap();
    assert_eq!(
        reopened.read_media_chunk(&object.local_id, 0).unwrap(),
        sealed_chunk
    );
    assert_eq!(
        reopened.reconcile_media(&mut rng).unwrap(),
        Default::default()
    );

    let db_bytes = std::fs::read(&db).unwrap();
    assert!(!db_bytes
        .windows(b"secret-name.png".len())
        .any(|w| w == b"secret-name.png"));
    assert!(!db_bytes
        .windows(b"image/png".len())
        .any(|w| w == b"image/png"));
    let files: Vec<_> = std::fs::read_dir(&media_dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].file_name().to_string_lossy().len(), 64);
    let local_bytes = std::fs::read(files[0].path()).unwrap();
    assert!(!local_bytes
        .windows(b"secret-name.png".len())
        .any(|w| w == b"secret-name.png"));
    assert!(!local_bytes.windows(32).any(|w| w == object.content_hash));
}

#[test]
fn reconciliation_handles_temps_orphans_and_missing_files() {
    let mut rng = StdRng::seed_from_u64(0x16);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("store.db");
    let media_dir = dir.path().join("store.db.media");
    let (transfer, object) = records();
    let sealed_chunk = vec![0x44; ATTACHMENT_SEALED_CHUNK_LEN];

    let final_path = {
        let mut store = Store::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
        store.put_media_transfer(&transfer, &mut rng).unwrap();
        store.put_media_object(&object, &mut rng).unwrap();
        store
            .commit_media_chunk(&object.local_id, 0, &sealed_chunk, &mut rng)
            .unwrap();
        std::fs::read_dir(&media_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
    };

    std::fs::write(media_dir.join(".tmp-interrupted"), b"partial").unwrap();
    std::fs::write(
        media_dir.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"orphan",
    )
    .unwrap();
    let mut store = Store::open(&db, b"pass").unwrap();
    assert!(
        !media_dir.join(".tmp-interrupted").exists(),
        "open removes stale temp files"
    );
    std::fs::remove_file(final_path).unwrap();
    let report = store.reconcile_media(&mut rng).unwrap();
    assert_eq!(report.missing_objects, 1);
    assert_eq!(report.orphan_files_removed, 1);
    let MediaRecord::Available(stored) = store.get_media_object(&object.local_id).unwrap().unwrap()
    else {
        panic!("known record version")
    };
    assert_eq!(stored.state, MediaTransferState::Unavailable);
}

#[test]
fn quotas_and_protocol_object_bounds_fail_before_writes() {
    let mut rng = StdRng::seed_from_u64(0x17);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("store.db");
    let (transfer, object) = records();
    let mut store = Store::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    store.put_media_transfer(&transfer, &mut rng).unwrap();
    store.put_media_object(&object, &mut rng).unwrap();
    for tag in 10u8..17 {
        let mut active = object.clone();
        active.local_id = [tag; 16];
        active.object_id = [tag.wrapping_add(32); 16];
        store.put_media_object(&active, &mut rng).unwrap();
    }
    let mut ninth = object.clone();
    ninth.local_id = [17; 16];
    ninth.object_id = [49; 16];
    assert!(matches!(
        store.put_media_object(&ninth, &mut rng),
        Err(StoreError::MediaQuota)
    ));
    store
        .set_media_limits(MediaLimits {
            store_bytes: 1,
            ..MediaLimits::default()
        })
        .unwrap();
    assert!(matches!(
        store.commit_media_chunk(
            &object.local_id,
            0,
            &vec![0x33; ATTACHMENT_SEALED_CHUNK_LEN],
            &mut rng
        ),
        Err(StoreError::MediaQuota)
    ));

    let mut oversized = object.clone();
    oversized.local_id = [9; 16];
    oversized.total_len = 536_870_913;
    oversized.chunk_count = attachment_chunk_count(oversized.total_len);
    oversized.verified_bitmap = vec![0; (oversized.chunk_count as usize).div_ceil(8)];
    oversized.chunk_addresses = vec![None; oversized.chunk_count as usize];
    assert!(store.put_media_object(&oversized, &mut rng).is_err());
}

#[test]
fn kkr4_carries_manifest_but_excludes_media_state_and_files() {
    let mut rng = StdRng::seed_from_u64(0x18);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("old.db");
    let restored_db = dir.path().join("restored.db");
    let (transfer, object) = records();
    let mut store = Store::create(&db, b"pass", TEST_KDF, &mut rng).unwrap();
    let identity = Identity::generate(&mut rng);
    store.put_identity(&identity, &mut rng).unwrap();

    let manifest = AttachmentManifest {
        attachment_key: [0x21; 32],
        primary: AttachmentObject {
            role: AttachmentRole::Primary,
            object_id: object.object_id,
            total_len: 1,
            chunk_data_len: ATTACHMENT_CHUNK_DATA_LEN,
            chunk_count: 1,
            content_hash: object.content_hash,
            media_type: "image/png",
            filename: Some("secret-name.png"),
        },
        preview: None,
    };
    let frame = encode_attachment(transfer.manifest_content_id, &manifest).unwrap();
    store
        .put_message(
            &MessageRecord {
                id: transfer.manifest_content_id,
                peer: transfer.peer,
                direction: Direction::Inbound,
                state: DeliveryState::Received,
                timestamp: transfer.updated_at,
                body: frame.clone(),
                wire_id: None,
            },
            &mut rng,
        )
        .unwrap();
    store.put_media_transfer(&transfer, &mut rng).unwrap();
    store.put_media_object(&object, &mut rng).unwrap();
    store
        .commit_media_chunk(
            &object.local_id,
            0,
            &vec![0x66; ATTACHMENT_SEALED_CHUNK_LEN],
            &mut rng,
        )
        .unwrap();
    let (backup, words) = store.export_backup(transfer.updated_at, &mut rng).unwrap();
    drop(store);

    let restored = Store::restore_backup(
        &restored_db,
        &backup,
        &words,
        b"new-pass",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        restored.messages_with(&transfer.peer).unwrap()[0].body,
        frame
    );
    assert!(restored.media_transfers().unwrap().is_empty());
    assert!(restored.media_objects().unwrap().is_empty());
    assert!(std::fs::read_dir(dir.path().join("restored.db.media"))
        .unwrap()
        .next()
        .is_none());
}
