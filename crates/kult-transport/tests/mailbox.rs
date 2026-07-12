//! Mailbox relay integration (docs/05-transports.md §2): deposits are
//! filtered by registered tokens, collection drains through the normal
//! receive path, and refusals — non-serving nodes, unregistered tokens —
//! are honest errors, never silent drops.

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    DeliveryHint, Libp2pTransport, MailboxConfig, Reachability, SendReceipt, Transport,
};

fn envelope(token: [u8; 32], body: &[u8]) -> Envelope {
    Envelope::new(EnvelopeKind::Message, token, body.to_vec())
}

#[tokio::test]
async fn deposit_collect_roundtrip_gated_by_registration() {
    let relay =
        Libp2pTransport::with_mailbox(&["/ip4/127.0.0.1/udp/0/quic-v1"], MailboxConfig::default())
            .await
            .unwrap();
    let relay_addr = relay.wait_listen_addr().await.unwrap();
    let hint = DeliveryHint::Relay(relay_addr.clone());

    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let recipient = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();

    let token = [7u8; 32];
    let env = envelope(token, b"sealed bytes");

    // The scheduler must rank a mailbox as store-and-forward, not immediate.
    assert_eq!(sender.reachable(&hint).await, Reachability::StoreAndForward);

    // No registration yet: the relay refuses, the sender sees a failed send
    // (and its delivery engine would keep the envelope queued).
    assert!(sender.send(&hint, &env).await.is_err());

    // The recipient checks in — registering its filter — and the same
    // deposit now lands.
    assert_eq!(
        recipient
            .mailbox_checkin(&relay_addr, &[token])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sender.send(&hint, &env).await.unwrap(),
        SendReceipt::AckedByNextHop
    );

    // Collection: the envelope arrives via the normal receive path, and the
    // relay's copy is gone.
    assert_eq!(
        recipient
            .mailbox_checkin(&relay_addr, &[token])
            .await
            .unwrap(),
        1
    );
    assert_eq!(recipient.recv().await.unwrap(), vec![env]);
    assert!(relay
        .mailbox_contents()
        .unwrap()
        .iter()
        .all(|(_, queue)| queue.is_empty()));
    assert_eq!(
        recipient
            .mailbox_checkin(&relay_addr, &[token])
            .await
            .unwrap(),
        0,
        "collection deletes"
    );
}

#[tokio::test]
async fn node_without_mailbox_service_refuses_honestly() {
    let bystander = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let addr = bystander.wait_listen_addr().await.unwrap();

    let client = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    assert!(client.mailbox_checkin(&addr, &[[1u8; 32]]).await.is_err());
    assert!(client
        .send(&DeliveryHint::Relay(addr), &envelope([1u8; 32], b"x"))
        .await
        .is_err());
    assert!(bystander.mailbox_contents().is_none());
}
