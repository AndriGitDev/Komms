//! Sneakernet transport tests: two peers exchanging sealed envelopes through
//! spool directories, honest receipts, and corrupt-file quarantine.

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    DeliveryHint, Reachability, SendReceipt, SneakernetTransport, Transport, TransportError,
};

fn env(n: u8) -> Envelope {
    Envelope::new(EnvelopeKind::Message, [n; 32], vec![n; 64])
}

#[tokio::test]
async fn two_peers_exchange_via_spools() {
    let dir = tempfile::tempdir().unwrap();
    let alice = SneakernetTransport::new(dir.path().join("alice-inbox")).unwrap();
    let bob = SneakernetTransport::new(dir.path().join("bob-inbox")).unwrap();
    let to_bob = DeliveryHint::Spool(bob.inbox().to_path_buf());
    let to_alice = DeliveryHint::Spool(alice.inbox().to_path_buf());

    assert_eq!(
        alice.reachable(&to_bob).await,
        Reachability::StoreAndForward
    );

    // Alice → Bob: three envelopes.
    for n in 1..=3 {
        let receipt = alice.send(&to_bob, &env(n)).await.unwrap();
        assert_eq!(receipt, SendReceipt::HandedToLink); // never overclaims
    }
    let mut got = bob.recv().await.unwrap();
    got.sort_by_key(|e| e.token[0]);
    assert_eq!(got, vec![env(1), env(2), env(3)]);
    // Drained: second recv is empty.
    assert!(bob.recv().await.unwrap().is_empty());

    // Bob → Alice reply.
    bob.send(&to_alice, &env(9)).await.unwrap();
    assert_eq!(alice.recv().await.unwrap(), vec![env(9)]);
}

#[tokio::test]
async fn corrupt_files_are_quarantined_not_looped() {
    let dir = tempfile::tempdir().unwrap();
    let t = SneakernetTransport::new(dir.path().join("inbox")).unwrap();
    std::fs::write(t.inbox().join("junk.kkb"), b"not a bundle").unwrap();
    std::fs::write(t.inbox().join("note.txt"), b"ignored").unwrap();

    assert!(t.recv().await.unwrap().is_empty());
    // The junk was renamed aside, not deleted, and won't be re-read.
    assert!(t.inbox().join("junk.kkb.bad").exists());
    assert!(!t.inbox().join("junk.kkb").exists());
    assert!(t.recv().await.unwrap().is_empty());
    // Unrelated files untouched.
    assert!(t.inbox().join("note.txt").exists());
}

#[tokio::test]
async fn wrong_hint_kind_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let t = SneakernetTransport::new(dir.path().join("inbox")).unwrap();
    let err = t
        .send(&DeliveryHint::MeshNode(7), &env(1))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::UnsupportedHint));
    assert_eq!(
        t.reachable(&DeliveryHint::Multiaddr("/ip4/1.2.3.4".into()))
            .await,
        Reachability::Unreachable
    );
}
