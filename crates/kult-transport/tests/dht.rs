//! Discovery-plane tests: prekey-style records published to and fetched
//! from the Kademlia DHT across separate nodes (docs/05-transports.md §2).

use kult_transport::{Discovery, DiscoveryNamespace, Libp2pTransport};

const LOCALHOST_QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";

/// Three nodes, no special roles: everyone bootstraps off the first — any
/// reachable peer joins the DHT, nothing is hardcoded. A record published
/// by one node is retrievable by another that never talked to the publisher
/// directly.
#[tokio::test]
async fn record_published_on_one_node_is_found_on_another() {
    let seed = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();

    let publisher = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let reader = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    publisher.bootstrap(&[seed_addr.as_str()]).await.unwrap();
    reader.bootstrap(&[seed_addr.as_str()]).await.unwrap();

    let key = [7u8; 32];
    let value = b"signed prekey bundle bytes".to_vec();
    publisher
        .publish(
            DiscoveryNamespace::LegacyPrekeyV1,
            key,
            value.clone(),
            4_000_000_000,
        )
        .await
        .unwrap();

    let found = reader
        .lookup(DiscoveryNamespace::LegacyPrekeyV1, key)
        .await
        .unwrap();
    assert!(
        found.contains(&value),
        "reader must retrieve the published record"
    );

    // Unknown keys resolve to nothing — an empty answer, not an error.
    assert!(reader
        .lookup(DiscoveryNamespace::LegacyPrekeyV1, [9u8; 32])
        .await
        .unwrap()
        .is_empty());
}

/// The frozen Connect-v2 body is intentionally large and fixed-width. The
/// shared DHT must accept exactly that bound end to end rather than only
/// passing tiny legacy fixtures.
#[tokio::test]
async fn fixed_width_connect_record_is_stored_and_retrieved() {
    let seed = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();

    let publisher = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let reader = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    publisher.bootstrap(&[seed_addr.as_str()]).await.unwrap();
    reader.bootstrap(&[seed_addr.as_str()]).await.unwrap();

    let key = [0x31u8; 32];
    let value = vec![0x5a; kult_crypto::DISCOVERY_RECORD_SIZE];
    publisher
        .publish(
            DiscoveryNamespace::ConnectV2,
            key,
            value.clone(),
            4_000_000_000,
        )
        .await
        .unwrap();

    let found = reader
        .lookup(DiscoveryNamespace::ConnectV2, key)
        .await
        .unwrap();
    assert_eq!(found, vec![value]);
}

/// Re-publishing under the same key replaces the record: readers see the
/// fresh value (rotated prekeys must win over stale ones).
#[tokio::test]
async fn republish_replaces_record() {
    let seed = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();

    let publisher = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let reader = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    publisher.bootstrap(&[seed_addr.as_str()]).await.unwrap();
    reader.bootstrap(&[seed_addr.as_str()]).await.unwrap();

    let key = [3u8; 32];
    publisher
        .publish(
            DiscoveryNamespace::LegacyPrekeyV1,
            key,
            b"old bundle".to_vec(),
            4_000_000_000,
        )
        .await
        .unwrap();
    publisher
        .publish(
            DiscoveryNamespace::LegacyPrekeyV1,
            key,
            b"new bundle".to_vec(),
            4_000_000_000,
        )
        .await
        .unwrap();

    let found = reader
        .lookup(DiscoveryNamespace::LegacyPrekeyV1, key)
        .await
        .unwrap();
    assert!(found.contains(&b"new bundle".to_vec()));
}

/// Bootstrapping off a dead peer fails honestly; a mixed list succeeds if
/// any single peer is alive.
#[tokio::test]
async fn bootstrap_needs_one_live_peer() {
    let node = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();

    let ghost = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let ghost_id = ghost.local_peer_id();
    drop(ghost);
    let dead = format!("/ip4/127.0.0.1/udp/1/quic-v1/p2p/{ghost_id}");

    assert!(node.bootstrap(&[dead.as_str()]).await.is_err());

    let seed = Libp2pTransport::new(&[LOCALHOST_QUIC]).await.unwrap();
    let seed_addr = seed.wait_listen_addr().await.unwrap();
    node.bootstrap(&[dead.as_str(), seed_addr.as_str()])
        .await
        .unwrap();
}
