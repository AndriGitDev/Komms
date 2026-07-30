//! Mailbox relay integration (docs/05-transports.md §2): deposits are
//! filtered by registered tokens, collection drains through the normal
//! receive path, and refusals — non-serving nodes, unregistered tokens —
//! are honest errors, never silent drops.

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    DeliveryHint, Libp2pTransport, MailboxConfig, MailboxServiceConfig, Reachability, SendReceipt,
    Transport, TransportError,
};

fn envelope(token: [u8; 32], body: &[u8]) -> Envelope {
    Envelope::new(EnvelopeKind::Message, token, body.to_vec())
}

#[tokio::test]
async fn deposit_collect_roundtrip_gated_by_registration() {
    let relay_dir = tempfile::tempdir().unwrap();
    let relay = Libp2pTransport::with_mailbox(
        &["/ip4/127.0.0.1/udp/0/quic-v1"],
        MailboxServiceConfig::in_directory(relay_dir.path(), MailboxConfig::default()),
    )
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
    assert!(matches!(
        sender.send(&hint, &env).await.unwrap_err(),
        TransportError::RefusedByNextHop
    ));

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

    // Collection creates a lease and does not delete the relay copy.
    assert_eq!(
        recipient
            .mailbox_checkin(&relay_addr, &[token])
            .await
            .unwrap(),
        1
    );
    assert_eq!(relay.mailbox_metrics().unwrap().stored_items, 1);
    let received = recipient.recv_staged().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].envelope, env);
    recipient
        .settle_recv(received[0].receipt.unwrap(), true)
        .await
        .unwrap();
    for _ in 0..500 {
        if relay.mailbox_metrics().unwrap().stored_items == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        relay.mailbox_metrics().unwrap().stored_items == 0,
        "exact durable endpoint settlement acknowledges the leased row"
    );
    assert_eq!(
        recipient
            .mailbox_checkin(&relay_addr, &[token])
            .await
            .unwrap(),
        0,
        "acknowledged collection is idempotent"
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
    assert!(matches!(
        client
            .send(&DeliveryHint::Relay(addr), &envelope([1u8; 32], b"x"))
            .await
            .unwrap_err(),
        TransportError::RefusedByNextHop
    ));
    assert!(bystander.mailbox_metrics().is_none());
}

#[tokio::test]
async fn multi_operator_duplicates_ack_each_exact_relay_row() {
    let left_dir = tempfile::tempdir().unwrap();
    let right_dir = tempfile::tempdir().unwrap();
    let left = Libp2pTransport::with_mailbox(
        &["/ip4/127.0.0.1/udp/0/quic-v1"],
        MailboxServiceConfig::in_directory(left_dir.path(), MailboxConfig::default()),
    )
    .await
    .unwrap();
    let right = Libp2pTransport::with_mailbox(
        &["/ip4/127.0.0.1/udp/0/quic-v1"],
        MailboxServiceConfig::in_directory(right_dir.path(), MailboxConfig::default()),
    )
    .await
    .unwrap();
    let left_addr = left.wait_listen_addr().await.unwrap();
    let right_addr = right.wait_listen_addr().await.unwrap();
    let recipient = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let token = [0x31u8; 32];
    recipient
        .mailbox_checkin(&left_addr, &[token])
        .await
        .unwrap();
    recipient
        .mailbox_checkin(&right_addr, &[token])
        .await
        .unwrap();
    let env = envelope(token, b"same end-to-end ciphertext");
    sender
        .send(&DeliveryHint::Relay(left_addr.clone()), &env)
        .await
        .unwrap();
    sender
        .send(&DeliveryHint::Relay(right_addr.clone()), &env)
        .await
        .unwrap();
    assert_eq!(
        recipient
            .mailbox_checkin(&left_addr, &[token])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        recipient
            .mailbox_checkin(&right_addr, &[token])
            .await
            .unwrap(),
        1
    );
    let received = recipient.recv_staged().await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(
        received[0].envelope.content_id(),
        received[1].envelope.content_id()
    );
    for item in received {
        recipient
            .settle_recv(item.receipt.unwrap(), true)
            .await
            .unwrap();
    }
    for _ in 0..500 {
        if left.mailbox_metrics().unwrap().stored_items == 0
            && right.mailbox_metrics().unwrap().stored_items == 0
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(left.mailbox_metrics().unwrap().stored_items, 0);
    assert_eq!(right.mailbox_metrics().unwrap().stored_items, 0);
}
