//! M4 hardware-in-loop acceptance: two `kultd` instances attached to **real**
//! stock-firmware Meshtastic radios on USB-serial, all other networking
//! disabled, exchange verified E2EE messages — driven exclusively through
//! their RPC sockets, exactly like `mesh_e2e` but with radio waves instead
//! of a fake air.
//!
//! This test is `#[ignore]`d: it needs two radios on the desk. The nightly
//! bench job (`.github/workflows/hil-nightly.yml`) runs it with `--ignored`;
//! bench setup is documented in `docs/10-hil-bench.md`. Run it by hand with:
//!
//! ```sh
//! KOMMS_HIL_SERIAL_A=/dev/ttyUSB0 KOMMS_HIL_SERIAL_B=/dev/ttyUSB1 \
//!     cargo test -p kultd --test hil -- --ignored --nocapture
//! ```
//!
//! What only hardware can prove — and this test therefore pins — is the
//! real path: serial framing against actual firmware, the radio config
//! handshake (node number, LoRa modem params, region → duty-cycle budget),
//! and delivery over actual RF. The frame-count and duty-cycle *logic* are
//! already pinned deterministically by the fake-radio integration tests;
//! here they run against the real regulatory region the radios report.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use kultd::{Daemon, DaemonConfig};

/// Argon2id light enough for tests: the store lives in a tempdir and holds
/// throwaway bench identities, so the desktop cost profile buys nothing.
const TEST_KDF: kult_crypto::KdfProfile = kult_crypto::KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// LoRa is slow and duty-cycle pacing is honest: the first message carries
/// the PQXDH handshake (~10 frames at the 233 B cap), and a duty-limited
/// region may space retransmissions out. Generous, but finite — the nightly
/// must fail, not hang, when the bench is broken.
const DELIVERY_DEADLINE: Duration = Duration::from_secs(600);

/// Config for a daemon whose only usable carrier is its real radio: mDNS
/// off, no bootstrap peers, loopback-only listen — the two daemons share a
/// bench host, so any internet path between them must be closed off for the
/// test to mean anything.
fn radio_only_config(dir: &Path, name: &str, serial_port: &str) -> DaemonConfig {
    let data = dir.join(name);
    std::fs::create_dir_all(&data).unwrap();
    let mut cfg = DaemonConfig::new(&data, b"test-passphrase".to_vec());
    cfg.kdf = TEST_KDF;
    cfg.listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    cfg.mdns = false;
    cfg.meshtastic_serial = Some(serial_port.to_owned());
    cfg.tick_interval = Duration::from_millis(250);
    cfg
}

/// A minimal RPC client (as in mesh_e2e): sequential request/response with
/// interleaved event lines collected on the side.
struct Client {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    writer: tokio::net::unix::OwnedWriteHalf,
    next_id: u64,
    events: Vec<Value>,
}

impl Client {
    async fn connect(socket: &Path) -> Self {
        let stream = UnixStream::connect(socket).await.expect("connect");
        let (reader, writer) = stream.into_split();
        Self {
            lines: BufReader::new(reader).lines(),
            writer,
            next_id: 0,
            events: Vec::new(),
        }
    }

    async fn ok(&mut self, mut request: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        request["id"] = json!(id);
        self.writer
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write");
        loop {
            let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
                .await
                .expect("response timeout")
                .expect("read")
                .expect("eof");
            let value: Value = serde_json::from_str(&line).expect("json");
            if let Some(event) = value.get("event") {
                self.events.push(event.clone());
                continue;
            }
            assert_eq!(value["id"], json!(id), "correlation id echoes");
            assert!(value.get("err").is_none(), "rpc error: {}", value["err"]);
            return value["ok"].clone();
        }
    }

    /// Wait until an event matching `pred` has arrived (drains the stream).
    async fn wait_event(&mut self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(hit) = self.events.iter().find(|e| pred(e)) {
            return hit.clone();
        }
        let deadline = tokio::time::Instant::now() + DELIVERY_DEADLINE;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
                .expect("read")
                .expect("eof");
            let value: Value = serde_json::from_str(&line).expect("json");
            let Some(event) = value.get("event") else {
                continue;
            };
            self.events.push(event.clone());
            if pred(event) {
                return event.clone();
            }
        }
    }
}

/// A required bench environment variable; a missing one is a *failure*, not
/// a skip — this test only runs when explicitly asked for (`--ignored`), and
/// a misconfigured bench must show up red in the nightly, never green.
fn bench_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} not set — the HIL test needs two USB Meshtastic radios; \
             see docs/10-hil-bench.md"
        )
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "hardware-in-loop: needs two USB Meshtastic radios (KOMMS_HIL_SERIAL_A/_B); see docs/10-hil-bench.md"]
async fn two_real_radios_message_over_the_air_alone() {
    let port_a = bench_env("KOMMS_HIL_SERIAL_A");
    let port_b = bench_env("KOMMS_HIL_SERIAL_B");
    let dir = tempfile::tempdir().unwrap();

    // An unreachable or half-configured radio is a hard startup error by
    // design — the bench reports it as a plain failure with the port name.
    let started = Instant::now();
    let alice = Daemon::start(radio_only_config(dir.path(), "alice", &port_a))
        .await
        .unwrap_or_else(|e| panic!("alice daemon with radio on {port_a}: {e}"));
    let bob = Daemon::start(radio_only_config(dir.path(), "bob", &port_b))
        .await
        .unwrap_or_else(|e| panic!("bob daemon with radio on {port_b}: {e}"));
    println!("radios configured in {:?}", started.elapsed());

    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;

    // Out-of-band pairing (QR codes): bundles over RPC, mesh-broadcast
    // hints only — no internet path exists between these two nodes.
    let a_bundle = a.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_bundle = b.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_peer = a
        .ok(json!({
            "op": "add_contact",
            "name": "bob",
            "bundle": b_bundle,
            "hints": [{ "mesh": u32::MAX }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_peer = b
        .ok(json!({
            "op": "add_contact",
            "name": "alice",
            "bundle": a_bundle,
            "hints": [{ "mesh": u32::MAX }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut a_events = Client::connect(&alice.socket_path).await;
    let mut b_events = Client::connect(&bob.socket_path).await;
    a_events.ok(json!({ "op": "subscribe" })).await;
    b_events.ok(json!({ "op": "subscribe" })).await;

    // A→B: the expensive direction — this message carries the PQXDH
    // handshake, so it exercises fragmentation and reassembly on the air.
    let sent_at = Instant::now();
    let sent = a
        .ok(json!({ "op": "send", "peer": bob_peer, "body": "over the air" }))
        .await;
    let msg_id = sent["id"].as_str().unwrap().to_owned();

    let received = b_events
        .wait_event("bob receiving alice's message", |e| {
            e["type"] == json!("message")
        })
        .await;
    assert_eq!(received["body"], json!("over the air"));
    assert_eq!(received["peer"], json!(alice_peer));
    println!("A→B message (incl. handshake) in {:?}", sent_at.elapsed());

    // The receipt rides the mesh back: the honest `delivered` state.
    a_events
        .wait_event("alice's delivered receipt", |e| {
            e["id"] == json!(msg_id) && e["state"] == json!("delivered")
        })
        .await;
    println!("A→B delivered receipt in {:?}", sent_at.elapsed());

    // B→A on the established session: a 192-bucket text, ≤ 2 LoRa frames.
    let reply_at = Instant::now();
    let reply_sent = b
        .ok(json!({ "op": "send", "peer": alice_peer, "body": "mesh reply" }))
        .await;
    let reply_id = reply_sent["id"].as_str().unwrap().to_owned();
    let reply = a_events
        .wait_event("alice receiving bob's reply", |e| {
            e["type"] == json!("message")
        })
        .await;
    assert_eq!(reply["body"], json!("mesh reply"));
    b_events
        .wait_event("bob's delivered receipt", |e| {
            e["id"] == json!(reply_id) && e["state"] == json!("delivered")
        })
        .await;
    println!(
        "B→A ratcheted message round-trip in {:?}",
        reply_at.elapsed()
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
