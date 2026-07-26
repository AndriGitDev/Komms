use std::process::Command;

use kult_crypto::KdfProfile;
use kult_store::{Store, StoreError};
use rand::rngs::StdRng;
use rand::SeedableRng;

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const CHILD_PATH: &str = "KOMMS_SINGLE_WRITER_CHILD_PATH";
const CHILD_OPERATION: &str = "KOMMS_SINGLE_WRITER_CHILD_OPERATION";
const CHILD_EXPECTATION: &str = "KOMMS_SINGLE_WRITER_CHILD_EXPECTATION";
const CHILD_MARKER: &str = "KOMMS_SINGLE_WRITER_CHILD_MARKER";

fn run_child(path: &std::path::Path, operation: &str, expectation: &str) {
    let mut marker = path.as_os_str().to_os_string();
    marker.push(format!(".{operation}.{expectation}.marker"));
    let marker = std::path::PathBuf::from(marker);
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_store_attempt")
        .arg("--nocapture")
        .env(CHILD_PATH, path)
        .env(CHILD_OPERATION, operation)
        .env(CHILD_EXPECTATION, expectation)
        .env(CHILD_MARKER, &marker)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child store attempt failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(marker.exists(), "filtered child helper did not run");
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn child_store_attempt() {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return;
    };
    let mut rng = StdRng::seed_from_u64(0x10cc);
    let result = match std::env::var(CHILD_OPERATION).unwrap().as_str() {
        "open" => Store::open(std::path::Path::new(&path), b"pass"),
        "create" => Store::create(std::path::Path::new(&path), b"pass", TEST_KDF, &mut rng),
        operation => panic!("unknown child operation {operation}"),
    };
    match std::env::var(CHILD_EXPECTATION).unwrap().as_str() {
        "already-open" => assert!(matches!(result, Err(StoreError::AlreadyOpen))),
        "success" => drop(result.unwrap()),
        expectation => panic!("unknown child expectation {expectation}"),
    }
    std::fs::write(std::env::var_os(CHILD_MARKER).unwrap(), b"completed").unwrap();
}

#[test]
fn writer_lock_excludes_another_process_and_releases_on_drop() {
    let mut rng = StdRng::seed_from_u64(0x10cd);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let store = Store::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();

    run_child(&database, "open", "already-open");
    run_child(&database, "create", "already-open");

    drop(store);
    run_child(&database, "open", "success");
}

#[cfg(unix)]
#[test]
fn writer_sidecar_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let mut rng = StdRng::seed_from_u64(0x10ce);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("private.db");
    let store = Store::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    let mut sidecar = database.into_os_string();
    sidecar.push(".lock");
    let mode = std::fs::metadata(std::path::PathBuf::from(sidecar))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(store);
}

#[cfg(unix)]
#[test]
fn writer_lock_excludes_a_hardlink_alias() {
    let mut rng = StdRng::seed_from_u64(0x10d0);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let alias = directory.path().join("same-inode.db");
    let store = Store::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    std::fs::hard_link(&database, &alias).unwrap();

    run_child(&alias, "open", "already-open");

    drop(store);
    run_child(&database, "open", "success");
}

#[cfg(unix)]
#[test]
fn writer_sidecar_refuses_a_symlink_without_touching_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let mut rng = StdRng::seed_from_u64(0x10d1);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let target = directory.path().join("unrelated");
    std::fs::write(&target, b"preserve").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let sidecar = directory.path().join("node.db.lock");
    symlink(&target, &sidecar).unwrap();

    assert!(matches!(
        Store::create(&database, b"pass", TEST_KDF, &mut rng),
        Err(StoreError::Io(_))
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(!database.exists());
}
