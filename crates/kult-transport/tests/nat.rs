//! NAT traversal tests (docs/05-transports.md §2): Circuit Relay v2
//! reservations and delivery through circuit addresses, AutoNAT dial-back
//! probing, and honest failures. DCUtR hole punching itself needs two real
//! NATs and is exercised by the M3 acceptance run, not localhost CI — but
//! everything it upgrades (relayed connections) is covered here.

use std::time::Duration;

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{DeliveryHint, Libp2pTransport, NatStatus, SendReceipt, Transport};

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

/// Poll `nat_status` until it settles on `Public` (or 30 s passes).
async fn public_within(t: &Libp2pTransport) {
    for _ in 0..1500 {
        if t.nat_status().await.unwrap() == NatStatus::Public {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("autonat never settled on Public within 30s");
}

/// A sender reaches a recipient through a relay circuit address alone: the
/// recipient reserves a slot at an ordinary node (every node volunteers
/// relay service), hands out the returned circuit address, and envelopes
/// arrive — the relay sees only sealed bytes between transport pseudonyms.
#[tokio::test]
async fn envelope_via_relay_circuit() {
    let relay = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let recipient = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();

    // The full volunteer sequence: the recipient's connection gives the
    // relay its first AutoNAT server; a dial-back confirms the relay's own
    // address, which is what its reservation vouchers advertise.
    let relay_addr = relay.wait_listen_addr().await.unwrap();
    recipient.bootstrap(&[&relay_addr]).await.unwrap();
    public_within(&relay).await;

    let circuit = recipient.reserve_relay(&relay_addr).await.unwrap();

    // The circuit address names the relay first, then the recipient — and
    // is published like any other listen address.
    let tail = format!("/p2p-circuit/p2p/{}", recipient.local_peer_id());
    assert!(
        circuit.ends_with(&tail),
        "unexpected circuit address {circuit}"
    );
    assert!(recipient.listen_addrs().contains(&circuit));

    let env = test_envelope(7);
    let receipt = sender
        .send(&DeliveryHint::Multiaddr(circuit), &env)
        .await
        .unwrap();
    // Honest signal: the recipient acked over the relayed connection.
    assert_eq!(receipt, SendReceipt::AckedByNextHop);
    assert_eq!(recv_within(&recipient).await, vec![env]);

    // The relay itself stored and learned nothing envelope-shaped.
    assert!(relay.recv().await.unwrap().is_empty());
}

/// AutoNAT settles the local reachability verdict from peer dial-backs:
/// on localhost every listen address is dialable, so a connected pair
/// converges on `Public` — the same machinery reports `Private` behind a
/// real NAT, cueing a relay reservation.
#[tokio::test]
async fn autonat_settles_reachability() {
    let a = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let b = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();

    assert_eq!(b.nat_status().await.unwrap(), NatStatus::Unknown);

    // Any connected peer doubles as an AutoNAT server; bootstrap connects.
    let a_addr = a.wait_listen_addr().await.unwrap();
    b.bootstrap(&[&a_addr]).await.unwrap();
    public_within(&b).await;
}

/// A reservation at a dead relay fails honestly instead of hanging.
#[tokio::test]
async fn relay_reservation_fails_honestly() {
    let a = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let ghost = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let ghost_id = ghost.local_peer_id();
    drop(ghost);
    let dead = format!("/ip4/127.0.0.1/tcp/1/p2p/{ghost_id}");
    assert!(a.reserve_relay(&dead).await.is_err());
}
