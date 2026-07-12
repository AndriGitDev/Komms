//! mDNS LAN auto-discovery tests (docs/05-transports.md §3): the M3
//! acceptance criterion is that LAN-only delivery — no internet, no
//! bootstrap peers, no explicit multiaddr exchange — works via mDNS.
//!
//! These tests exercise the real multicast socket on 224.0.0.251:5353;
//! two transports in the same process discover each other over the
//! loopback-enabled group exactly as two hosts on a Wi-Fi network would.

use std::time::Duration;

use kult_protocol::{Envelope, EnvelopeKind};
use kult_transport::{
    DeliveryHint, Discovery, Libp2pTransport, Reachability, SendReceipt, Transport,
    TransportOptions,
};

const LISTEN: &str = "/ip4/0.0.0.0/udp/0/quic-v1";

async fn lan_node() -> Libp2pTransport {
    Libp2pTransport::with_options(
        &[LISTEN],
        TransportOptions {
            lan_discovery: true,
            ..TransportOptions::default()
        },
    )
    .await
    .unwrap()
}

/// Poll until `node` has discovered `peer_id` on the LAN (or 20 s passes),
/// returning the discovered hint.
async fn discover_within(node: &Libp2pTransport, peer_id: &str) -> String {
    for _ in 0..2000 {
        if let Some(hint) = node
            .lan_peers()
            .into_iter()
            .find(|addr| addr.ends_with(peer_id))
        {
            return hint;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("peer {peer_id} not discovered via mDNS within 20s");
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

/// The acceptance path: two nodes, zero configuration — no bootstrap, no
/// address exchange — find each other by mDNS alone and deliver a sealed
/// envelope both ways (announcements are mutual: query + unsolicited
/// response cover whichever node started last).
#[tokio::test]
async fn lan_only_delivery_with_zero_configuration() {
    let a = lan_node().await;
    let b = lan_node().await;

    let b_hint = discover_within(&a, &b.local_peer_id()).await;
    let a_hint = discover_within(&b, &a.local_peer_id()).await;

    let to_b = DeliveryHint::Multiaddr(b_hint);
    assert_eq!(a.reachable(&to_b).await, Reachability::Now);
    let env = Envelope::new(EnvelopeKind::Message, [7; 32], vec![7; 300]);
    assert_eq!(
        a.send(&to_b, &env).await.unwrap(),
        SendReceipt::AckedByNextHop
    );
    assert_eq!(recv_within(&b).await, vec![env]);

    let reply = Envelope::new(EnvelopeKind::Message, [8; 32], vec![8; 300]);
    b.send(&DeliveryHint::Multiaddr(a_hint), &reply)
        .await
        .unwrap();
    assert_eq!(recv_within(&a).await, vec![reply]);
}

/// mDNS seeds the Kademlia routing table, so the *discovery plane* — prekey
/// publish and lookup — also works LAN-only with zero bootstrap peers:
/// adding a contact from a kult address alone never needs the internet on a
/// shared network.
#[tokio::test]
async fn lan_only_dht_records_with_zero_bootstrap() {
    let publisher = lan_node().await;
    let reader = lan_node().await;

    discover_within(&publisher, &reader.local_peer_id()).await;
    discover_within(&reader, &publisher.local_peer_id()).await;

    let key = [42u8; 32];
    let value = b"signed prekey bundle bytes".to_vec();
    publisher.publish(key, value.clone()).await.unwrap();

    let found = reader.lookup(key).await.unwrap();
    assert!(
        found.contains(&value),
        "reader must retrieve the record with no bootstrap configured"
    );
}

/// Discovery off (the default): nothing is collected even while another
/// node is loudly announcing on the same group.
#[tokio::test]
async fn lan_discovery_is_opt_in() {
    let quiet = Libp2pTransport::new(&[LISTEN]).await.unwrap();
    let noisy = lan_node().await;
    // The noisy node announces within its first ticks; give those time to
    // land, then confirm the quiet node heard none of it.
    noisy.wait_listen_addr().await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(quiet.lan_peers().is_empty());
}
