//! Production `/komms/call/1` path admission: media is direct QUIC or absent.

use std::sync::Arc;
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt};
use kult_transport::{Libp2pTransport, TransportError};

const QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

async fn wait_for_addresses(transport: &Libp2pTransport, count: usize) -> Vec<String> {
    for _ in 0..500 {
        let addresses = transport.listen_addrs();
        if addresses.len() >= count {
            return addresses;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("transport did not bind {count} addresses within 5s");
}

#[tokio::test]
async fn direct_quic_call_stream_is_bidirectional() {
    let alice = Arc::new(Libp2pTransport::new(&[QUIC]).await.unwrap());
    let bob = Arc::new(Libp2pTransport::new(&[QUIC]).await.unwrap());
    let bob_addr = bob.wait_listen_addr().await.unwrap();

    let accept = {
        let bob = Arc::clone(&bob);
        tokio::spawn(async move { bob.accept_call_stream().await.unwrap() })
    };
    let mut outbound = alice.open_call_stream(&bob_addr).await.unwrap();
    let mut inbound = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("inbound stream timed out")
        .expect("accept task");

    assert_eq!(outbound.peer_id(), bob.local_peer_id());
    assert_eq!(inbound.peer_id(), alice.local_peer_id());
    assert!(alice.call_ready(&bob_addr));

    outbound.write_all(b"offer-proof").await.unwrap();
    outbound.flush().await.unwrap();
    let mut proof = [0u8; 11];
    inbound.read_exact(&mut proof).await.unwrap();
    assert_eq!(&proof, b"offer-proof");

    inbound.write_all(b"answer-proof").await.unwrap();
    inbound.flush().await.unwrap();
    let mut answer = [0u8; 12];
    outbound.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"answer-proof");
}

#[tokio::test]
async fn tcp_and_circuit_hints_are_refused_without_fallback() {
    let alice = Libp2pTransport::new(&[QUIC]).await.unwrap();
    let tcp = Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0"])
        .await
        .unwrap();
    let tcp_addr = tcp.wait_listen_addr().await.unwrap();
    assert!(matches!(
        alice.open_call_stream(&tcp_addr).await,
        Err(TransportError::UnsupportedHint)
    ));

    let relayed = format!("{}/p2p-circuit/p2p/{}", tcp_addr, tcp.local_peer_id());
    assert!(matches!(
        alice.open_call_stream(&relayed).await,
        Err(TransportError::UnsupportedHint)
    ));
}

#[tokio::test]
async fn call_preparation_replaces_an_existing_tcp_path_with_direct_quic() {
    let alice = Arc::new(Libp2pTransport::new(&[QUIC]).await.unwrap());
    let bob = Arc::new(
        Libp2pTransport::new(&["/ip4/127.0.0.1/tcp/0", QUIC])
            .await
            .unwrap(),
    );
    let addresses = wait_for_addresses(&bob, 2).await;
    let tcp_addr = addresses
        .iter()
        .find(|address| address.contains("/tcp/"))
        .expect("TCP address")
        .as_str();
    let quic_addr = addresses
        .iter()
        .find(|address| address.contains("/quic-v1"))
        .expect("QUIC address")
        .clone();

    alice.bootstrap(&[tcp_addr]).await.unwrap();
    assert!(!alice.call_ready(&quic_addr));

    let accept = {
        let bob = Arc::clone(&bob);
        tokio::spawn(async move { bob.accept_call_stream().await.unwrap() })
    };
    let mut outbound = alice.open_call_stream(&quic_addr).await.unwrap();
    let mut inbound = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("inbound stream timed out")
        .expect("accept task");
    assert!(alice.call_ready(&quic_addr));

    outbound.write_all(b"direct-only").await.unwrap();
    outbound.flush().await.unwrap();
    let mut bytes = [0u8; 11];
    inbound.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"direct-only");
}
