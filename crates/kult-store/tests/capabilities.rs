//! Authenticated capability snapshots use their own sealed, re-creatable
//! domain and survive ordinary store reopen without changing contact records.

use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_protocol::{CapabilityControl, FormatCapabilities};
use kult_store::Store;

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn capability_snapshot_round_trips_and_clears() {
    let mut rng = StdRng::seed_from_u64(0xcab1e);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capabilities.db");
    let peer = [7; 32];
    let control = CapabilityControl {
        formats: vec![FormatCapabilities {
            format_version: 1,
            kinds: vec![1, 3],
        }],
    };

    {
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        assert_eq!(store.get_capabilities(&peer).unwrap(), None);
        store.put_capabilities(&peer, &control, &mut rng).unwrap();
        assert_eq!(
            store.get_capabilities(&peer).unwrap(),
            Some(control.clone())
        );
    }

    let store = Store::open(&path, b"pass").unwrap();
    assert_eq!(store.get_capabilities(&peer).unwrap(), Some(control));
    store.delete_capabilities(&peer).unwrap();
    assert_eq!(store.get_capabilities(&peer).unwrap(), None);
}
