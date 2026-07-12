//! Libp2p transport tests: QUIC and TCP round trips on localhost, honest
//! ack semantics, and failure on unreachable peers.

use std::time::Duration;

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{DeliveryHint, Libp2pTransport, Reachability, SendReceipt, Transport};

fn test_envelope(fill: u8) -> Envelope {
    Envelope::new(EnvelopeKind::Message, [fill; 32], vec![fill; 300])
}

/// Poll `recv` until envelopes arrive (or 10 s passes).
async fn recv_within(t: &Libp2pTransport) -> Vec<Envelope> {
    for _ in 0..1000 {
        let got = t.recv().await.unwrap();
        if !got.is_empty() {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing received within 10s");
}

async fn round_trip_on(listen: &str) {
    let a = Libp2pTransport::new(&[listen]).await.unwrap();
    let b = Libp2pTransport::new(&[listen]).await.unwrap();
    let b_addr = b.wait_listen_addr().await.unwrap();
    let hint = DeliveryHint::Multiaddr(b_addr);

    assert_eq!(a.reachable(&hint).await, Reachability::Now);

    let env = test_envelope(1);
    let receipt = a.send(&hint, &env).await.unwrap();
    // The next hop acknowledged over the request-response protocol — and
    // that is all we may claim (docs/05-transports.md §1 rule 4).
    assert_eq!(receipt, SendReceipt::AckedByNextHop);

    let got = recv_within(&b).await;
    assert_eq!(got, vec![env]);

    // Second envelope reuses the connection.
    let env2 = test_envelope(2);
    a.send(&hint, &env2).await.unwrap();
    assert_eq!(recv_within(&b).await, vec![env2]);
}

#[tokio::test]
async fn quic_round_trip() {
    round_trip_on("/ip4/127.0.0.1/udp/0/quic-v1").await;
}

#[tokio::test]
async fn tcp_fallback_round_trip() {
    round_trip_on("/ip4/127.0.0.1/tcp/0").await;
}

#[tokio::test]
async fn hints_without_peer_id_are_unreachable() {
    let t = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    // No /p2p component → not addressable.
    let bare = DeliveryHint::Multiaddr("/ip4/127.0.0.1/tcp/1".into());
    assert_eq!(t.reachable(&bare).await, Reachability::Unreachable);
    assert!(t.send(&bare, &test_envelope(3)).await.is_err());
    // Non-multiaddr hints belong to other transports.
    let spool = DeliveryHint::Spool("/tmp/x".into());
    assert_eq!(t.reachable(&spool).await, Reachability::Unreachable);
}

#[tokio::test]
async fn unreachable_peer_fails_honestly() {
    let a = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    // A valid peer id that nobody is running, behind a dead port.
    let ghost = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let ghost_id = ghost.local_peer_id();
    drop(ghost);
    let hint = DeliveryHint::Multiaddr(format!("/ip4/127.0.0.1/tcp/1/p2p/{ghost_id}"));
    assert!(a.send(&hint, &test_envelope(4)).await.is_err());
}
