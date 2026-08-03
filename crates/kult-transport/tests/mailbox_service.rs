//! Dedicated mailbox-v2 service boundary and restart integration.

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    initialize_mailbox_service, inspect_mailbox_service, DeliveryHint, Libp2pTransport,
    MailboxConfig, MailboxServiceConfig, MailboxV2Service, Transport, MAILBOX_SERVICE_PROTOCOLS,
};

fn envelope(token: [u8; 32], body: &[u8]) -> Envelope {
    Envelope::new(EnvelopeKind::Message, token, body.to_vec())
}

#[tokio::test]
async fn dedicated_service_negotiates_only_mailbox_v2_and_survives_restart() {
    assert_eq!(MAILBOX_SERVICE_PROTOCOLS, &["/komms/mailbox/2"]);

    let directory = tempfile::tempdir().unwrap();
    let config = MailboxServiceConfig::in_directory(directory.path(), MailboxConfig::default());
    let initialized = initialize_mailbox_service(&config).unwrap();
    assert_eq!(initialized.schema_version, 2);
    assert_eq!(inspect_mailbox_service(&config).unwrap(), initialized);
    assert!(
        initialize_mailbox_service(&config).is_err(),
        "initialization never overwrites durable state"
    );

    let listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    let service = MailboxV2Service::start(&listen, config.clone())
        .await
        .unwrap();
    assert_eq!(service.peer_id(), initialized.peer_id);
    let address = service.wait_listen_addr().await.unwrap();

    let sender = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let recipient = Libp2pTransport::new(&["/ip4/127.0.0.1/udp/0/quic-v1"])
        .await
        .unwrap();
    let token = [0x51; 32];
    let ciphertext = envelope(token, b"dedicated service custody");

    assert!(
        sender
            .send(&DeliveryHint::Multiaddr(address.clone()), &ciphertext)
            .await
            .is_err(),
        "the mailbox artifact must not negotiate endpoint envelopes"
    );
    recipient.mailbox_checkin(&address, &[token]).await.unwrap();
    sender
        .send(&DeliveryHint::Relay(address), &ciphertext)
        .await
        .unwrap();
    assert_eq!(service.metrics().snapshot().unwrap().stored_items, 1);
    service.shutdown().await.unwrap();

    let restarted = MailboxV2Service::start(&listen, config).await.unwrap();
    assert_eq!(restarted.peer_id(), initialized.peer_id);
    assert_eq!(restarted.metrics().snapshot().unwrap().stored_items, 1);
    let restarted_address = restarted.wait_listen_addr().await.unwrap();
    assert_eq!(
        recipient
            .mailbox_checkin(&restarted_address, &[token])
            .await
            .unwrap(),
        1
    );
    let staged = recipient.recv_staged().await.unwrap();
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].envelope, ciphertext);
    recipient
        .settle_recv(staged[0].receipt.expect("lease settlement"), true)
        .await
        .unwrap();
    for _ in 0..500 {
        if restarted.metrics().snapshot().unwrap().stored_items == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(restarted.metrics().snapshot().unwrap().stored_items, 0);
    restarted.shutdown().await.unwrap();
}

#[test]
fn dedicated_service_rejects_mailbox_v1_compatibility() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = MailboxServiceConfig::in_directory(directory.path(), MailboxConfig::default());
    config.allow_v1_compat = true;
    let error = initialize_mailbox_service(&config).unwrap_err();
    assert!(error.to_string().contains("mailbox-v1"));
}
