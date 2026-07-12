//! M4 bridging acceptance (docs/08-roadmap.md, docs/05-transports.md §4.2
//! rule 5): a node with both mesh and internet bridges queued traffic in
//! both directions.
//!
//! Topology — the "village with one terminal":
//!
//! - **vera** is mesh-only: a fake radio, mDNS off, no bootstrap, no
//!   contactable internet listener.
//! - **bridge** has the village's second radio *and* internet, serves the
//!   community mailbox, and (by default, having both carriers) bridges.
//!   It knows neither vera nor rémy — everything it forwards is sealed.
//! - **rémy** is internet-only: reaches the bridge's mailbox over QUIC and
//!   checks in there; his only hint for vera is that mailbox.
//!
//! Delivery is verified end-to-end through RPC sockets in both directions —
//! including the `delivered` states, which require the encrypted *receipts*
//! to cross the bridge the opposite way each time.

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

fn base_config(dir: &Path, name: &str) -> DaemonConfig {
    let data = dir.join(name);
    std::fs::create_dir_all(&data).unwrap();
    let mut cfg = DaemonConfig::new(&data, b"test-passphrase".to_vec());
    cfg.kdf = TEST_KDF;
    cfg.listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    cfg.mdns = false;
    cfg.tick_interval = Duration::from_millis(100);
    cfg.checkin_interval = Duration::from_secs(1);
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
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
async fn bridge_carries_traffic_between_mesh_and_internet_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let (air, _keep) = broadcast::channel(256);

    // The bridge: radio + internet + community mailbox. Bridging engages on
    // its own — both carriers are present.
    let bridge_radio = radio(1, &air).await;
    let mut bridge_cfg = base_config(dir.path(), "bridge");
    bridge_cfg.meshtastic_tcp = Some(bridge_radio);
    bridge_cfg.serve_mailbox = true;
    let bridge = Daemon::start(bridge_cfg).await.expect("bridge daemon");
    let mailbox_addr = bridge.net.wait_listen_addr().await.unwrap();

    // Vera: mesh only.
    let vera_radio = radio(2, &air).await;
    let mut vera_cfg = base_config(dir.path(), "vera");
    vera_cfg.meshtastic_tcp = Some(vera_radio);
    let vera = Daemon::start(vera_cfg).await.expect("vera daemon");

    // Rémy: internet only, collecting at the bridge's mailbox.
    let mut remy_cfg = base_config(dir.path(), "remy");
    remy_cfg.mailboxes = vec![mailbox_addr.clone()];
    let remy = Daemon::start(remy_cfg).await.expect("remy daemon");

    let mut v = Client::connect(&vera.socket_path).await;
    let mut r = Client::connect(&remy.socket_path).await;

    // Out-of-band pairing (QR): vera can only flood the mesh; rémy can only
    // deposit at the bridge's mailbox. Neither has any direct path.
    let v_bundle = v.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let r_bundle = r.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let remy_peer = v
        .ok(json!({
            "op": "add_contact",
            "name": "rémy",
            "bundle": r_bundle,
            "hints": [{ "mesh": u32::MAX }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let vera_peer = r
        .ok(json!({
            "op": "add_contact",
            "name": "vera",
            "bundle": v_bundle,
            "hints": [{ "relay": mailbox_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut v_events = Client::connect(&vera.socket_path).await;
    let mut r_events = Client::connect(&remy.socket_path).await;
    v_events.ok(json!({ "op": "subscribe" })).await;
    r_events.ok(json!({ "op": "subscribe" })).await;

    // Give rémy's first mailbox check-in a moment to register his tokens at
    // the bridge, so vera's flight lands on the fast path instead of a
    // transit retry.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Mesh → internet: vera's handshake flight floods the mesh, the bridge
    // deposits it (sealed, token-blind) into its own mailbox, rémy collects.
    let sent = v
        .ok(json!({ "op": "send", "peer": remy_peer, "body": "hello from the mesh" }))
        .await;
    let v_msg = sent["id"].as_str().unwrap().to_owned();

    let received = r_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(received["body"], json!("hello from the mesh"));
    assert_eq!(received["peer"], json!(vera_peer));

    // Internet → mesh: rémy's receipt is deposited at the bridge, buffered
    // as transit, flooded over LoRa, and closes vera's delivery loop.
    v_events
        .wait_event(|e| e["id"] == json!(v_msg) && e["state"] == json!("delivered"))
        .await;

    // And a full message the other way, receipts crossing back over the
    // mesh → internet path again.
    let sent = r
        .ok(json!({ "op": "send", "peer": vera_peer, "body": "reply from the internet" }))
        .await;
    let r_msg = sent["id"].as_str().unwrap().to_owned();

    let received = v_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(received["body"], json!("reply from the internet"));
    assert_eq!(received["peer"], json!(remy_peer));
    r_events
        .wait_event(|e| e["id"] == json!(r_msg) && e["state"] == json!("delivered"))
        .await;

    // The bridge carried everything without ever learning either identity:
    // it holds no contacts, only sealed envelopes and rotating tokens.
    let mut b = Client::connect(&bridge.socket_path).await;
    let status = b.ok(json!({ "op": "status" })).await;
    assert_eq!(status["contacts"], json!(0));

    vera.shutdown().await;
    bridge.shutdown().await;
    remy.shutdown().await;
}
