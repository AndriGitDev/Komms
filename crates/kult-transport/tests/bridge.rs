//! Bridge-transit behavior of the internet carrier (ADR-0009): deposits for
//! unregistered tokens land in the bounded transit buffer (surfaced via
//! `recv_transit`) instead of being refused, registered tokens keep the
//! plain mailbox contract, and a bridge deposits into its *own* mailbox
//! locally without a self-dial.

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    DeliveryHint, Libp2pTransport, MailboxConfig, SendReceipt, Transport, TransportOptions,
};

fn envelope(token: [u8; 32], body: &[u8]) -> Envelope {
    Envelope::new(EnvelopeKind::Message, token, body.to_vec())
}

async fn transport(options: TransportOptions) -> Libp2pTransport {
    Libp2pTransport::with_options(&["/ip4/127.0.0.1/udp/0/quic-v1"], options)
        .await
        .unwrap()
}

#[tokio::test]
async fn unregistered_deposits_become_transit_registered_stay_mailbox() {
    let bridge = transport(TransportOptions {
        mailbox: Some(MailboxConfig::default()),
        bridge_deposits: true,
        ..TransportOptions::default()
    })
    .await;
    let bridge_addr = bridge.wait_listen_addr().await.unwrap();
    let hint = DeliveryHint::Relay(bridge_addr.clone());

    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let collector = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();

    // Unregistered token: accepted — into the transit buffer, not the
    // mailbox store, and out through recv_transit (never recv).
    let mesh_bound = envelope([1u8; 32], b"for someone on the mesh");
    assert_eq!(
        sender.send(&hint, &mesh_bound).await.unwrap(),
        SendReceipt::AckedByNextHop
    );
    assert!(bridge
        .mailbox_contents()
        .unwrap()
        .iter()
        .all(|(_, queue)| queue.is_empty()));
    assert_eq!(bridge.recv().await.unwrap(), vec![]);
    assert_eq!(bridge.recv_transit().await.unwrap(), vec![mesh_bound]);
    assert_eq!(bridge.recv_transit().await.unwrap(), vec![], "drained");

    // Registered token: the plain mailbox contract, untouched by bridging.
    let token = [2u8; 32];
    collector
        .mailbox_checkin(&bridge_addr, &[token])
        .await
        .unwrap();
    let mail = envelope(token, b"for a libp2p collector");
    assert_eq!(
        sender.send(&hint, &mail).await.unwrap(),
        SendReceipt::AckedByNextHop
    );
    assert_eq!(
        bridge.recv_transit().await.unwrap(),
        vec![],
        "registered mail never diverts to the mesh"
    );
    assert_eq!(
        collector
            .mailbox_checkin(&bridge_addr, &[token])
            .await
            .unwrap(),
        1
    );

    // Oversize (past the airtime ceiling): an honest refusal.
    let oversize = envelope([3u8; 32], &[0u8; 5_000]);
    assert!(sender.send(&hint, &oversize).await.is_err());
}

#[tokio::test]
async fn bridge_without_mailbox_service_still_accepts_transit() {
    let bridge = transport(TransportOptions {
        bridge_deposits: true,
        ..TransportOptions::default()
    })
    .await;
    let addr = bridge.wait_listen_addr().await.unwrap();

    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let env = envelope([4u8; 32], b"transit only");
    assert_eq!(
        sender
            .send(&DeliveryHint::Relay(addr.clone()), &env)
            .await
            .unwrap(),
        SendReceipt::AckedByNextHop
    );
    assert_eq!(bridge.recv_transit().await.unwrap(), vec![env]);
    // But check-ins are still refused honestly: no mailbox is served.
    assert!(sender.mailbox_checkin(&addr, &[[4u8; 32]]).await.is_err());
}

#[tokio::test]
async fn self_deposit_reaches_own_mailbox_without_dialing() {
    let bridge = transport(TransportOptions {
        mailbox: Some(MailboxConfig::default()),
        bridge_deposits: true,
        ..TransportOptions::default()
    })
    .await;
    let own_addr = bridge.wait_listen_addr().await.unwrap();
    let own_hint = DeliveryHint::Relay(own_addr.clone());

    // A collector registers its token over the network.
    let collector = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let token = [5u8; 32];
    collector
        .mailbox_checkin(&own_addr, &[token])
        .await
        .unwrap();

    // The bridge deposits mesh-heard transit into its own service locally.
    let env = envelope(token, b"heard on the mesh");
    assert_eq!(
        bridge.send(&own_hint, &env).await.unwrap(),
        SendReceipt::AckedByNextHop
    );
    assert_eq!(
        collector
            .mailbox_checkin(&own_addr, &[token])
            .await
            .unwrap(),
        1
    );

    // Unregistered self-deposits refuse rather than loop into the transit
    // buffer (that would bounce mesh traffic straight back to the mesh).
    let stranger = envelope([6u8; 32], b"nobody here");
    assert!(bridge.send(&own_hint, &stranger).await.is_err());
    assert_eq!(bridge.recv_transit().await.unwrap(), vec![]);
}
