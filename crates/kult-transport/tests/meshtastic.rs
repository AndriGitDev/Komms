//! Meshtastic carrier integration tests (docs/08-roadmap.md M4), driving the
//! in-memory fake radio from `kult_transport::mesh_testutil`: handshake and
//! runtime profile, flooding between radios, noise tolerance, duty-cycle
//! enforcement, and the acceptance pin that a ratcheted 192-bucket message
//! crosses the mesh in ≤ 2 LoRa frames.
#![cfg(feature = "meshtastic")]

use std::time::Duration;

use meshtastic::protobufs::config::lo_ra_config::{ModemPreset, RegionCode};
use meshtastic::protobufs::{self, mesh_packet, PortNum};
use tokio::sync::broadcast;

use kult_protocol::{fragment, Envelope, EnvelopeKind, Reassembler, ENVELOPE_HEADER_LEN};
use kult_transport::mesh_testutil::{spawn_duplex, Air, RadioSpec};
use kult_transport::{
    DeliveryHint, MeshtasticOptions, MeshtasticTransport, Reachability, SendReceipt, Transport,
    TransportError, MESH_BROADCAST,
};

async fn connect(spec: RadioSpec, air: &Air) -> MeshtasticTransport {
    let stream = spawn_duplex(spec, air.clone());
    MeshtasticTransport::connect(stream, MeshtasticOptions::default())
        .await
        .expect("fake radio handshake")
}

/// Drain `transport` until envelopes arrive or `deadline` passes.
async fn recv_within(transport: &MeshtasticTransport, deadline: Duration) -> Vec<Envelope> {
    let start = std::time::Instant::now();
    loop {
        let got = transport.recv().await.expect("recv never errors");
        if !got.is_empty() || start.elapsed() > deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn spec(node_num: u32, region: RegionCode) -> RadioSpec {
    RadioSpec {
        node_num,
        modem_preset: ModemPreset::LongFast as i32,
        region: region as i32,
    }
}

/// The handshake harvests the radio's identity and produces the documented
/// link profile: 233-byte frames, seconds-class latency, airtime-class cost,
/// broadcast medium.
#[tokio::test]
async fn handshake_yields_runtime_profile() {
    let (air, _keep) = broadcast::channel(64);
    let transport = connect(spec(11, RegionCode::Us), &air).await;

    assert_eq!(transport.node_num(), 11);
    let profile = transport.profile();
    assert_eq!(profile.mtu, 233);
    assert_eq!(profile.latency, kult_transport::LatencyClass::Seconds);
    assert_eq!(profile.cost, kult_transport::CostClass::Airtime);
    assert!(profile.broadcast);
    // LongFast per the firmware preset table.
    assert_eq!(transport.modem_params().spreading_factor, 11);
    assert_eq!(transport.modem_params().bandwidth_hz, 250_000);

    assert_eq!(
        transport
            .reachable(&DeliveryHint::MeshNode(MESH_BROADCAST))
            .await,
        Reachability::Now
    );
    assert_eq!(
        transport
            .reachable(&DeliveryHint::Multiaddr("/ip4/1.2.3.4".into()))
            .await,
        Reachability::Unreachable
    );
}

/// Two radios on the same mesh: a broadcast envelope from one arrives at the
/// other, and the sender does not hear its own transmission.
#[tokio::test]
async fn envelopes_flood_between_radios() {
    let (air, _keep) = broadcast::channel(64);
    let alpha = connect(spec(1, RegionCode::Us), &air).await;
    let beta = connect(spec(2, RegionCode::Us), &air).await;

    let envelope = Envelope::new(EnvelopeKind::Message, [7u8; 32], vec![1, 2, 3, 4]);
    let receipt = alpha
        .send(&DeliveryHint::MeshNode(MESH_BROADCAST), &envelope)
        .await
        .unwrap();
    assert_eq!(receipt, SendReceipt::HandedToLink);

    let got = recv_within(&beta, Duration::from_secs(5)).await;
    assert_eq!(got, vec![envelope]);
    // No self-echo.
    assert!(alpha.recv().await.unwrap().is_empty());
}

/// Traffic on other ports and garbage on ours is mesh noise: skipped, never
/// an error, and it does not block later valid envelopes.
#[tokio::test]
async fn foreign_ports_and_noise_are_ignored() {
    let (air, _keep) = broadcast::channel(64);
    let transport = connect(spec(3, RegionCode::Us), &air).await;

    let noise = |portnum: i32, payload: Vec<u8>| protobufs::MeshPacket {
        from: 99,
        to: MESH_BROADCAST,
        payload_variant: Some(mesh_packet::PayloadVariant::Decoded(protobufs::Data {
            portnum,
            payload,
            ..Default::default()
        })),
        ..Default::default()
    };
    // Ordinary Meshtastic text traffic, and garbage on the private port.
    air.send((
        99,
        noise(PortNum::TextMessageApp as i32, b"hi mesh".to_vec()),
    ))
    .unwrap();
    air.send((99, noise(PortNum::PrivateApp as i32, vec![0xff; 40])))
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(transport.recv().await.unwrap().is_empty());

    let envelope = Envelope::new(EnvelopeKind::Receipt, [9u8; 32], vec![5, 6]);
    air.send((99, noise(PortNum::PrivateApp as i32, envelope.encode())))
        .unwrap();
    assert_eq!(
        recv_within(&transport, Duration::from_secs(5)).await,
        vec![envelope]
    );
}

/// Oversized envelopes are the delivery engine's job to fragment; the
/// carrier refuses them honestly instead of truncating.
#[tokio::test]
async fn oversized_envelope_is_refused() {
    let (air, _keep) = broadcast::channel(64);
    let transport = connect(spec(4, RegionCode::Us), &air).await;
    let envelope = Envelope::new(EnvelopeKind::Message, [0u8; 32], vec![0; 300]);
    assert!(matches!(
        transport
            .send(&DeliveryHint::MeshNode(MESH_BROADCAST), &envelope)
            .await,
        Err(TransportError::Protocol(_))
    ));
}

/// M4 acceptance (docs/08-roadmap.md): a real ratcheted text message in the
/// 192-byte padding bucket crosses the mesh in **at most 2 LoRa frames** —
/// exercised end-to-end: encrypt → fragment at the mesh MTU → radio →
/// reassemble → decrypt.
#[tokio::test]
async fn ratcheted_192_bucket_message_needs_at_most_two_frames() {
    use kult_crypto::{
        initiate, respond, Identity, PqPrekeySecret, PrekeyBundle, RatchetMessage,
        SignedPrekeySecret,
    };
    use rand::{rngs::StdRng, SeedableRng};

    const NOW: u64 = 1_800_000_000;
    let mut rng = StdRng::seed_from_u64(42);
    let alice = Identity::generate(&mut rng);
    let bob = Identity::generate(&mut rng);
    let spk = SignedPrekeySecret::generate(&mut rng, 1);
    let pqspk = PqPrekeySecret::generate(&mut rng, 1);
    let bundle = PrekeyBundle::build(&bob, &spk, &pqspk, None, NOW + 1000, vec![])
        .verify(NOW)
        .unwrap();
    let (mut a_sess, init) = initiate(&alice, &bundle, b"init", NOW, &mut rng).unwrap();
    let (mut b_sess, _) = respond(&bob, &spk, &pqspk, None, &init, NOW, &mut rng).unwrap();

    // A realistic short text message: pads into the 192-byte bucket.
    let padded = kult_protocol::pad(b"meet at the old bridge at nine, bring the radio").unwrap();
    assert_eq!(padded.len(), 192);
    let msg = a_sess.encrypt(&mut rng, NOW, &padded, &[]);
    let envelope = Envelope::new(EnvelopeKind::Message, [3u8; 32], msg.encode());

    let (air, _keep) = broadcast::channel(64);
    let alpha = connect(spec(1, RegionCode::Us), &air).await;
    let beta = connect(spec(2, RegionCode::Us), &air).await;
    let mtu = alpha.profile().mtu;

    // The delivery engine's fragmentation path (kult-node::send_via).
    let encoded = envelope.encode();
    let frames: Vec<Envelope> = if encoded.len() <= mtu {
        vec![envelope.clone()]
    } else {
        fragment(&encoded, mtu - ENVELOPE_HEADER_LEN)
            .unwrap()
            .into_iter()
            .map(|body| Envelope::new(EnvelopeKind::Fragment, envelope.token, body))
            .collect()
    };
    assert!(
        frames.len() <= 2,
        "192-bucket message took {} LoRa frames",
        frames.len()
    );

    for frame in &frames {
        alpha
            .send(&DeliveryHint::MeshNode(MESH_BROADCAST), frame)
            .await
            .unwrap();
    }

    // Receive, reassemble, decrypt.
    let mut reassembler = Reassembler::new();
    let mut received = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    'outer: while std::time::Instant::now() < deadline {
        for env in recv_within(&beta, Duration::from_secs(5)).await {
            match env.kind {
                EnvelopeKind::Fragment => {
                    if let Some(payload) = reassembler.insert(&env.body, NOW).unwrap() {
                        received = payload;
                        break 'outer;
                    }
                }
                _ => {
                    received = env.encode();
                    break 'outer;
                }
            }
        }
    }
    let arrived = Envelope::decode(&received).unwrap();
    let ratchet_msg = RatchetMessage::decode(&arrived.body).unwrap();
    let plaintext = b_sess.decrypt(&mut rng, NOW, &ratchet_msg, &[]).unwrap();
    assert_eq!(plaintext, padded);
    assert_eq!(
        kult_protocol::unpad(&plaintext).unwrap(),
        b"meet at the old bridge at nine, bring the radio"
    );
}

/// Duty-cycle enforcement (M4 acceptance): in a 10 %-limited region the
/// carrier refuses sends beyond the budget with an honest retry hint, and
/// records nothing for refused frames.
#[tokio::test]
#[allow(deprecated)] // VeryLongSlow: deprecated in the protobufs, still deployed.
async fn duty_cycle_budget_is_enforced() {
    let (air, _keep) = broadcast::channel(1024);
    // VeryLongSlow in EU868: a full 255-byte frame is 28.59 s on air against
    // a 360 s/h budget → exactly 12 frames fit, the 13th must be refused.
    let transport = connect(
        RadioSpec {
            node_num: 5,
            modem_preset: ModemPreset::VeryLongSlow as i32,
            region: RegionCode::Eu868 as i32,
        },
        &air,
    )
    .await;

    // MTU-filling envelope → the maximal 255-byte on-air frame.
    let envelope = Envelope::new(
        EnvelopeKind::Message,
        [1u8; 32],
        vec![0xab; 233 - ENVELOPE_HEADER_LEN],
    );
    for i in 0..12 {
        transport
            .send(&DeliveryHint::MeshNode(MESH_BROADCAST), &envelope)
            .await
            .unwrap_or_else(|e| panic!("send {i} refused early: {e}"));
    }
    match transport
        .send(&DeliveryHint::MeshNode(MESH_BROADCAST), &envelope)
        .await
    {
        Err(TransportError::AirtimeExhausted { retry_after }) => {
            assert!(retry_after > Duration::ZERO);
            assert!(retry_after <= Duration::from_secs(3600));
        }
        other => panic!("expected airtime refusal, got {other:?}"),
    }
}
