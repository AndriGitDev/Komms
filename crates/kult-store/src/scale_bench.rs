use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kult_crypto::{derive_kek, Identity, StorageKey, KDF_PROFILE_MOBILE};
use rand::{rngs::StdRng, SeedableRng};
use rusqlite::{params, Connection};

use crate::{DeliveryState, Direction, MessageRecord, Store, LEGACY_SCHEMA_CURRENT, WRAP_AD};

struct Budgets {
    migration: Duration,
    unlock: Duration,
    page: Duration,
    exact_edit: Duration,
    exact_delete: Duration,
    migration_peak_delta_bytes: u64,
    database_bytes: u64,
}

#[test]
#[ignore = "large storage qualification; run through scripts/store-scale-gate.sh"]
fn opaque_store_scale_budget() {
    let messages = std::env::var("KOMMS_STORE_BENCH_MESSAGES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .expect("KOMMS_STORE_BENCH_MESSAGES must be 100000 or 1000000");
    assert!(matches!(messages, 100_000 | 1_000_000));
    let budgets = budgets(messages);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!("opaque-scale-{messages}.db"));
    let peer = [0x51; 32];
    create_large_legacy_store(&path, messages, peer);

    let rss_before = resident_bytes();
    let running = Arc::new(AtomicBool::new(true));
    let peak_rss = Arc::new(AtomicU64::new(rss_before.unwrap_or(0)));
    let monitor = rss_before.map(|_| {
        let running = Arc::clone(&running);
        let peak_rss = Arc::clone(&peak_rss);
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Some(current) = resident_bytes() {
                    peak_rss.fetch_max(current, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_millis(10));
            }
        })
    });

    let migration_started = Instant::now();
    let store = Store::open(&path, b"scale-passphrase").unwrap();
    let migration_elapsed = migration_started.elapsed();
    running.store(false, Ordering::Relaxed);
    if let Some(monitor) = monitor {
        monitor.join().unwrap();
    }
    let migration_peak_delta =
        rss_before.map(|baseline| peak_rss.load(Ordering::Relaxed).saturating_sub(baseline));
    assert!(
        migration_elapsed <= budgets.migration,
        "migration took {migration_elapsed:?}, budget {:?}",
        budgets.migration
    );
    if let Some(delta) = migration_peak_delta {
        assert!(
            delta <= budgets.migration_peak_delta_bytes,
            "migration peak RSS delta was {delta} bytes, budget {}",
            budgets.migration_peak_delta_bytes
        );
    }
    drop(store);

    let unlock_started = Instant::now();
    let store = Store::open(&path, b"scale-passphrase").unwrap();
    let unlock_elapsed = unlock_started.elapsed();
    assert!(
        unlock_elapsed <= budgets.unlock,
        "unlock took {unlock_elapsed:?}, budget {:?}",
        budgets.unlock
    );

    let page_started = Instant::now();
    let first_page = store.messages_page(&peer, None, 64).unwrap();
    let page_elapsed = page_started.elapsed();
    assert_eq!(first_page.records.len(), 64);
    assert!(first_page.next.is_some());
    assert!(
        page_elapsed <= budgets.page,
        "page lookup took {page_elapsed:?}, budget {:?}",
        budgets.page
    );

    let edit_value = messages / 2;
    let edited = message_record(edit_value, peer);
    let edited = MessageRecord {
        body: b"edited by exact opaque id lookup".to_vec(),
        ..edited
    };
    let mut rng = StdRng::seed_from_u64(0x0ade_0027);
    let edit_started = Instant::now();
    assert!(store.update_message(&edited, &mut rng).unwrap());
    let edit_elapsed = edit_started.elapsed();
    assert!(
        edit_elapsed <= budgets.exact_edit,
        "exact edit took {edit_elapsed:?}, budget {:?}",
        budgets.exact_edit
    );
    let deleted = message_record(messages - 1, peer);
    let delete_started = Instant::now();
    assert!(store
        .delete_message_record(&deleted.peer, deleted.direction, &deleted.id)
        .unwrap());
    let delete_elapsed = delete_started.elapsed();
    assert!(
        delete_elapsed <= budgets.exact_delete,
        "exact delete took {delete_elapsed:?}, budget {:?}",
        budgets.exact_delete
    );

    let database_bytes = sqlite_bytes(&path);
    assert!(
        database_bytes <= budgets.database_bytes,
        "database uses {database_bytes} bytes, budget {}",
        budgets.database_bytes
    );
    println!(
        "STORE_SCALE_RESULT messages={messages} migration_ms={} unlock_ms={} page_us={} \
         edit_us={} delete_us={} migration_peak_delta_bytes={} database_bytes={} \
         migration_budget_ms={} unlock_budget_ms={} page_budget_us={} edit_budget_us={} \
         delete_budget_us={} memory_budget_bytes={} database_budget_bytes={}",
        migration_elapsed.as_millis(),
        unlock_elapsed.as_millis(),
        page_elapsed.as_micros(),
        edit_elapsed.as_micros(),
        delete_elapsed.as_micros(),
        migration_peak_delta.unwrap_or(0),
        database_bytes,
        budgets.migration.as_millis(),
        budgets.unlock.as_millis(),
        budgets.page.as_micros(),
        budgets.exact_edit.as_micros(),
        budgets.exact_delete.as_micros(),
        budgets.migration_peak_delta_bytes,
        budgets.database_bytes,
    );
}

fn budgets(messages: u64) -> Budgets {
    match messages {
        100_000 => Budgets {
            migration: Duration::from_secs(180),
            unlock: Duration::from_secs(30),
            page: Duration::from_millis(250),
            exact_edit: Duration::from_millis(250),
            exact_delete: Duration::from_millis(250),
            migration_peak_delta_bytes: 512 * 1024 * 1024,
            database_bytes: 64 * 1024 * 1024 + messages * 1_024,
        },
        1_000_000 => Budgets {
            migration: Duration::from_secs(1_800),
            unlock: Duration::from_secs(180),
            page: Duration::from_millis(500),
            exact_edit: Duration::from_millis(500),
            exact_delete: Duration::from_millis(500),
            migration_peak_delta_bytes: 768 * 1024 * 1024,
            database_bytes: 64 * 1024 * 1024 + messages * 1_024,
        },
        _ => unreachable!(),
    }
}

fn create_large_legacy_store(path: &std::path::Path, messages: u64, peer: [u8; 32]) {
    let mut rng = StdRng::seed_from_u64(0x0005_ca1e_0027);
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(LEGACY_SCHEMA_CURRENT).unwrap();
    conn.pragma_update(None, "synchronous", "OFF").unwrap();
    conn.pragma_update(None, "journal_mode", "MEMORY").unwrap();
    let salt = [0x27; 16];
    let master_bytes = [0xa7; 32];
    let master = StorageKey::from_bytes(master_bytes);
    let kek = derive_kek(b"scale-passphrase", &salt, KDF_PROFILE_MOBILE).unwrap();
    let wrapped = StorageKey::from_bytes(*kek).seal(WRAP_AD, &master_bytes, &mut rng);
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('salt', ?1)",
        params![salt.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('kdf', ?1)",
        params![postcard::to_allocvec(&(
            KDF_PROFILE_MOBILE.m_cost_kib,
            KDF_PROFILE_MOBILE.t_cost,
            KDF_PROFILE_MOBILE.p_cost,
        ))
        .unwrap()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('wrapped_sk', ?1)",
        params![wrapped],
    )
    .unwrap();
    let identity = Identity::generate(&mut rng);
    let sealed_identity = master.derive(b"KK-store-identity").seal(
        b"identity",
        identity.to_bytes().as_ref(),
        &mut rng,
    );
    conn.execute(
        "INSERT INTO identity (id, blob) VALUES (1, ?1)",
        params![sealed_identity],
    )
    .unwrap();

    let message_key = master.derive(b"KK-store-messages");
    for start in (0..messages).step_by(4_096) {
        let end = (start + 4_096).min(messages);
        let tx = conn.unchecked_transaction().unwrap();
        {
            let mut insert = tx
                .prepare_cached("INSERT INTO messages (blob) VALUES (?1)")
                .unwrap();
            for value in start..end {
                let encoded = postcard::to_allocvec(&message_record(value, peer)).unwrap();
                let sealed = message_key.seal(b"message", &encoded, &mut rng);
                insert.execute(params![sealed]).unwrap();
            }
        }
        tx.commit().unwrap();
    }
    drop(conn);
}

fn message_record(value: u64, peer: [u8; 32]) -> MessageRecord {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&value.to_be_bytes());
    id[8..].copy_from_slice(&(!value).to_be_bytes());
    MessageRecord {
        id,
        peer,
        direction: Direction::Inbound,
        state: DeliveryState::Received,
        timestamp: value,
        body: vec![0x42; 32],
        wire_id: None,
    }
}

fn sqlite_bytes(path: &std::path::Path) -> u64 {
    let main = fs::metadata(path).unwrap().len();
    let mut wal_name = path.as_os_str().to_owned();
    wal_name.push("-wal");
    main + fs::metadata(std::path::PathBuf::from(wal_name)).map_or(0, |value| value.len())
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    line.split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(1_024)
}

#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}
