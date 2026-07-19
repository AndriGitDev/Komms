//! ADR-0013 transport spike: measure the generic `/komms/call/1` stream over
//! the exact pinned libp2p QUIC stack before choosing a production media path.
//!
//! This is deliberately not a call implementation. `libp2p-quic 0.13.1`
//! disables QUIC datagrams, so the generic protocol below is a reliable,
//! ordered bidirectional stream. The tests record its useful direct-path
//! baseline and make loss-induced head-of-line behavior explicit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{StreamProtocol, SwarmEvent};
use libp2p::{Multiaddr, SwarmBuilder};
use tokio::net::UdpSocket;

const CALL_PROTOCOL: StreamProtocol = StreamProtocol::new("/komms/call/1");
const FRAME_BYTES: usize = 160;
const FRAME_COUNT: usize = 100;
const FRAME_INTERVAL: Duration = Duration::from_millis(20);

struct SpikeResult {
    observations: Vec<Duration>,
    dropped_datagrams: usize,
}

fn udp_socket_address(address: &Multiaddr) -> SocketAddr {
    let mut ip = None;
    let mut port = None;
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(IpAddr::V4(value)),
            Protocol::Udp(value) => port = Some(value),
            _ => {}
        }
    }
    SocketAddr::new(ip.expect("QUIC IP address"), port.expect("QUIC UDP port"))
}

async fn lossy_udp_proxy(
    server: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let dropped_by_task = Arc::clone(&dropped);
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut datagrams = 0usize;
        let mut buffer = vec![0u8; 65_536];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let destination = if source == server {
                let Some(client) = client else { continue };
                client
            } else {
                client = Some(source);
                server
            };
            datagrams += 1;
            // Preserve the handshake, then deterministically drop 5% of UDP
            // datagrams in both directions. QUIC recovers them; a reliable
            // media stream therefore delivers every frame but stalls behind
            // retransmission instead of exposing packet loss to a jitter buffer.
            if datagrams > 30 && datagrams.is_multiple_of(20) {
                dropped_by_task.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            tokio::time::sleep(Duration::from_millis(3)).await;
            if socket
                .send_to(&buffer[..length], destination)
                .await
                .is_err()
            {
                break;
            }
        }
    });
    (address, task, dropped)
}

async fn run_spike(lossy: bool, receiver_stall: Option<(usize, Duration)>) -> SpikeResult {
    let mut sender = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| libp2p_stream::Behaviour::new())
        .expect("stream behaviour")
        .build();
    let mut receiver = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| libp2p_stream::Behaviour::new())
        .expect("stream behaviour")
        .build();

    let sender_peer = *sender.local_peer_id();
    let receiver_peer = *receiver.local_peer_id();
    let mut sender_control = sender.behaviour().new_control();
    let mut incoming = receiver
        .behaviour()
        .new_control()
        .accept(CALL_PROTOCOL)
        .expect("unique protocol registration");

    receiver
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    let receiver_address = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = receiver.select_next_some().await {
            break address;
        }
    };
    let (mut dial_address, proxy_task, dropped) = if lossy {
        let (proxy, task, dropped) = lossy_udp_proxy(udp_socket_address(&receiver_address)).await;
        (
            format!("/ip4/{}/udp/{}/quic-v1", proxy.ip(), proxy.port())
                .parse()
                .unwrap(),
            Some(task),
            dropped,
        )
    } else {
        (receiver_address, None, Arc::new(AtomicUsize::new(0)))
    };
    dial_address.push(Protocol::P2p(receiver_peer));
    sender.dial(dial_address).unwrap();

    let sender_loop = tokio::spawn(async move {
        loop {
            sender.select_next_some().await;
        }
    });
    let receiver_loop = tokio::spawn(async move {
        loop {
            receiver.select_next_some().await;
        }
    });

    let sent_at: Arc<Mutex<Vec<Option<Instant>>>> = Arc::new(Mutex::new(vec![None; FRAME_COUNT]));
    let receiver_times = Arc::clone(&sent_at);
    let receive = tokio::spawn(async move {
        let (peer, mut stream) = incoming.next().await.expect("inbound call stream");
        let mut observations = Vec::with_capacity(FRAME_COUNT);
        for expected in 0..FRAME_COUNT {
            if receiver_stall.is_some_and(|(sequence, _)| sequence == expected) {
                tokio::time::sleep(receiver_stall.expect("checked").1).await;
            }
            let mut frame = [0u8; FRAME_BYTES];
            stream.read_exact(&mut frame).await.unwrap();
            let sequence = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(sequence, expected, "reliable stream reordered media");
            let started = receiver_times.lock().unwrap()[sequence].expect("send instant");
            observations.push(started.elapsed());
        }
        (peer, observations)
    });

    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        sender_control.open_stream(receiver_peer, CALL_PROTOCOL),
    )
    .await
    .expect("call stream timed out")
    .expect("call stream open");
    let mut ticker = tokio::time::interval(FRAME_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for sequence in 0..FRAME_COUNT {
        ticker.tick().await;
        let mut frame = [0u8; FRAME_BYTES];
        frame[..4].copy_from_slice(&(sequence as u32).to_le_bytes());
        sent_at.lock().unwrap()[sequence] = Some(Instant::now());
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();
    }
    stream.close().await.unwrap();

    let (observed_peer, observations) = tokio::time::timeout(Duration::from_secs(10), receive)
        .await
        .expect("receiver timed out")
        .expect("receiver task");
    assert_eq!(observed_peer, sender_peer);

    sender_loop.abort();
    receiver_loop.abort();
    if let Some(task) = proxy_task {
        task.abort();
    }
    SpikeResult {
        observations,
        dropped_datagrams: dropped.load(Ordering::Relaxed),
    }
}

fn percentile(observations: &[Duration], percentile: usize) -> Duration {
    let mut sorted = observations.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() * percentile / 100]
}

#[tokio::test]
async fn direct_quic_stream_has_a_low_loopback_baseline_but_is_ordered() {
    const STALL_AT: usize = 40;
    let result = run_spike(false, Some((STALL_AT, Duration::from_millis(120)))).await;
    let p95 = percentile(&result.observations[..STALL_AT], 95);
    let stalled = result.observations[STALL_AT];
    eprintln!(
        "direct call stream: frames={FRAME_COUNT} bytes={FRAME_BYTES} p95={p95:?} stalled={stalled:?}"
    );
    assert!(p95 < Duration::from_millis(250), "loopback p95 {p95:?}");
    assert!(
        stalled >= Duration::from_millis(100),
        "ordered stream did not expose the induced receiver stall: {stalled:?}"
    );
}

#[tokio::test]
async fn lossy_quic_stream_retransmits_instead_of_exposing_media_loss() {
    let result = run_spike(true, None).await;
    let p50 = percentile(&result.observations, 50);
    let p95 = percentile(&result.observations, 95);
    let max = result.observations.iter().copied().max().unwrap();
    eprintln!(
        "lossy call stream: frames={FRAME_COUNT} dropped_udp={} p50={p50:?} p95={p95:?} max={max:?}",
        result.dropped_datagrams
    );
    assert!(result.dropped_datagrams > 0, "proxy did not inject loss");
    assert_eq!(result.observations.len(), FRAME_COUNT);
}
