//! Sneakernet transport tests: two peers exchanging sealed envelopes through
//! spool directories, honest receipts, and corrupt-file quarantine.

use kult_protocol::{Envelope, EnvelopeKind, ProtocolError, MAX_BUNDLE_BYTES, MAX_ENVELOPE_BYTES};
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
async fn quarantine_never_overwrites_an_existing_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let t = SneakernetTransport::new(dir.path().join("inbox")).unwrap();
    std::fs::write(t.inbox().join("junk.kkb"), b"not a bundle").unwrap();
    std::fs::write(t.inbox().join("junk.kkb.bad"), b"operator evidence").unwrap();

    assert!(t.recv().await.unwrap().is_empty());
    assert_eq!(
        std::fs::read(t.inbox().join("junk.kkb.bad")).unwrap(),
        b"operator evidence"
    );
    assert!(!t.inbox().join("junk.kkb").exists());
    assert!(std::fs::read_dir(t.inbox())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .any(
            |entry| entry.file_name().to_string_lossy().starts_with("junk.kkb.")
                && entry.file_name() != "junk.kkb.bad"
        ));
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

#[tokio::test]
async fn oversized_envelope_is_typed_and_touches_no_destination_files() {
    let dir = tempfile::tempdir().unwrap();
    let sender = SneakernetTransport::new(dir.path().join("sender-inbox")).unwrap();
    let destination = dir.path().join("not-created");
    let oversized = Envelope::new(EnvelopeKind::Message, [8; 32], vec![0; MAX_ENVELOPE_BYTES]);

    assert!(matches!(
        sender
            .send(&DeliveryHint::Spool(destination.clone()), &oversized)
            .await
            .unwrap_err(),
        TransportError::Protocol(ProtocolError::EnvelopeTooLarge)
    ));
    assert!(!destination.exists());
}

#[tokio::test]
async fn oversized_bundle_file_is_quarantined_without_whole_file_read() {
    let dir = tempfile::tempdir().unwrap();
    let transport = SneakernetTransport::new(dir.path().join("inbox")).unwrap();
    let path = transport.inbox().join("oversized.kkb");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len((MAX_BUNDLE_BYTES + 1) as u64).unwrap();
    drop(file);

    assert!(transport.recv().await.unwrap().is_empty());
    assert!(!path.exists());
    assert!(transport.inbox().join("oversized.kkb.bad").exists());
}

#[tokio::test]
async fn non_regular_bundle_candidates_cannot_starve_a_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let sender = SneakernetTransport::new(dir.path().join("sender")).unwrap();
    let receiver = SneakernetTransport::new(dir.path().join("receiver")).unwrap();
    for i in 0..256 {
        std::fs::create_dir(receiver.inbox().join(format!("{i:04}.kkb"))).unwrap();
    }
    let expected = env(7);
    sender
        .send(
            &DeliveryHint::Spool(receiver.inbox().to_path_buf()),
            &expected,
        )
        .await
        .unwrap();

    assert_eq!(receiver.recv().await.unwrap(), vec![expected]);
    assert!(receiver.inbox().join("0000.kkb.bad").is_dir());
}
