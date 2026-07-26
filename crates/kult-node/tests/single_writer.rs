use kult_crypto::KdfProfile;
use kult_node::{Node, NodeError};
use kult_store::StoreError;
use rand::rngs::StdRng;
use rand::SeedableRng;

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn node_owns_the_store_lock_for_its_complete_lifetime() {
    let mut rng = StdRng::seed_from_u64(0x10cf);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let node = Node::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();

    assert!(matches!(
        Node::open(&database, b"pass"),
        Err(NodeError::Store(StoreError::AlreadyOpen))
    ));
    assert!(matches!(
        Node::create(&database, b"pass", TEST_KDF, &mut rng),
        Err(NodeError::Store(StoreError::AlreadyOpen))
    ));

    drop(node);
    let reopened = Node::open(&database, b"pass").unwrap();
    drop(reopened);
}
