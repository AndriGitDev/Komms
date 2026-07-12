//! M4 daemon acceptance: two `kultd` instances whose **only** shared carrier
//! is a Meshtastic mesh (two fake radios on a common "air"), driven
//! exclusively through their RPC sockets. mDNS is off, no bootstrap peers,
//! and the contacts carry mesh hints only — if a message arrives, it rode
//! LoRa frames through the radio client protocol.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::broadcast;

use kult_transport::mesh_testutil::{spawn_tcp, Air, RadioSpec};
use kultd::{Daemon, DaemonConfig};

/// Argon2id light enough for tests.
const TEST_KDF: kult_crypto::KdfProfile = kult_crypto::KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// Config for a daemon whose only usable carrier is its radio: mDNS off and
/// no bootstrap, so the internet transport never finds the peer.
fn mesh_only_config(dir: &Path, name: &str, radio_addr: &str) -> DaemonConfig {
    let data = dir.join(name);
    std::fs::create_dir_all(&data).unwrap();
    let mut cfg = DaemonConfig::new(&data, b"test-passphrase".to_vec());
    cfg.kdf = TEST_KDF;
    cfg.listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    cfg.mdns = false;
    cfg.meshtastic_tcp = Some(radio_addr.to_owned());
    cfg.tick_interval = Duration::from_millis(100);
    cfg
}

/// A minimal RPC client (as in rpc_e2e): sequential request/response with
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
    async fn wait_event(&mut self, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(hit) = self.events.iter().find(|e| pred(e)) {
            return hit.clone();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.next_line())
                .await
                .expect("event timeout")
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

/// Spawn a fake radio serving the framed client protocol on localhost TCP;
/// returns the address `--meshtastic-tcp` would be given.
async fn radio(node_num: u32, air: &Air) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn_tcp(RadioSpec::unbudgeted(node_num), air.clone(), listener);
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn two_daemons_message_over_the_mesh_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (air, _keep) = broadcast::channel(256);

    let alice_radio = radio(1, &air).await;
    let bob_radio = radio(2, &air).await;
    let alice = Daemon::start(mesh_only_config(dir.path(), "alice", &alice_radio))
        .await
        .expect("alice daemon with radio");
    let bob = Daemon::start(mesh_only_config(dir.path(), "bob", &bob_radio))
        .await
        .expect("bob daemon with radio");

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

    // A short text: 192-byte bucket, ≤ 2 LoRa frames on the air.
    let sent = a
        .ok(json!({ "op": "send", "peer": bob_peer, "body": "off-grid hello" }))
        .await;
    let msg_id = sent["id"].as_str().unwrap().to_owned();

    let received = b_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(received["body"], json!("off-grid hello"));
    assert_eq!(received["peer"], json!(alice_peer));

    // The receipt rides the mesh back: the honest `delivered` state.
    a_events
        .wait_event(|e| e["id"] == json!(msg_id) && e["state"] == json!("delivered"))
        .await;

    // Reply on the established session, same medium.
    b.ok(json!({ "op": "send", "peer": alice_peer, "body": "mesh reply" }))
        .await;
    let reply = a_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(reply["body"], json!("mesh reply"));

    alice.shutdown().await;
    bob.shutdown().await;
}
