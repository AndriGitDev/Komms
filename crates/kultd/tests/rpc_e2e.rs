//! M3 acceptance for the headless daemon: two `kultd` instances on
//! localhost, driven **exclusively** through their local RPC sockets —
//! contact exchange, messaging, honest delivery states, and the event
//! stream. No test reaches into the node; everything goes over the wire a
//! real client would use.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use kultd::{Daemon, DaemonConfig};

/// Argon2id light enough for tests (same profile the node e2e tests use).
const TEST_KDF: kult_crypto::KdfProfile = kult_crypto::KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn test_config(dir: &Path, name: &str) -> DaemonConfig {
    let data = dir.join(name);
    std::fs::create_dir_all(&data).unwrap();
    let mut cfg = DaemonConfig::new(&data, b"test-passphrase".to_vec());
    cfg.kdf = TEST_KDF;
    cfg.listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    cfg.tick_interval = Duration::from_millis(100);
    cfg
}

/// A minimal RPC client: one connection, sequential request/response,
/// with any interleaved event lines collected on the side.
struct Client {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    writer: tokio::net::unix::OwnedWriteHalf,
    next_id: u64,
    pub events: Vec<Value>,
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

    /// Send one request and await its response, stashing event lines.
    async fn call(&mut self, mut request: Value) -> Result<Value, String> {
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
            if let Some(err) = value.get("err") {
                return Err(err.as_str().unwrap_or("?").to_owned());
            }
            return Ok(value["ok"].clone());
        }
    }

    /// Ok-or-panic convenience.
    async fn ok(&mut self, request: Value) -> Value {
        self.call(request).await.expect("rpc ok")
    }

    /// Wait until `n` events matching `pred` have arrived in total (the
    /// running tally includes ones already collected on the side).
    async fn wait_event_count(&mut self, pred: impl Fn(&Value) -> bool, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while self.events.iter().filter(|e| pred(e)).count() < n {
            let line = tokio::time::timeout_at(deadline, self.lines.next_line())
                .await
                .expect("event timeout")
                .expect("read")
                .expect("eof");
            let value: Value = serde_json::from_str(&line).expect("json");
            if let Some(event) = value.get("event") {
                self.events.push(event.clone());
            }
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

/// Poll `status` until at least one listen address is bound.
async fn listen_addr(client: &mut Client) -> String {
    for _ in 0..100 {
        let status = client.ok(json!({ "op": "status" })).await;
        if let Some(addr) = status["listen"].as_array().and_then(|a| a.first()) {
            return addr.as_str().unwrap().to_owned();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no listen address within 5s");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_daemons_message_via_rpc_only() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(dir.path(), "alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(dir.path(), "bob")).await.unwrap();

    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;

    // Status is honest from the start: fresh nodes, empty queues.
    let status = a.ok(json!({ "op": "status" })).await;
    assert_eq!(status["queued"], json!(0));
    assert_eq!(status["contacts"], json!(0));
    assert!(status["address"].as_str().unwrap().starts_with("kk1"));

    let a_addr = listen_addr(&mut a).await;
    let b_addr = listen_addr(&mut b).await;

    // Out-of-band pairing over RPC: each side exports a bundle, the other
    // imports it with a multiaddr hint.
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
            "hints": [{ "multiaddr": b_addr }],
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
            "hints": [{ "multiaddr": a_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();

    // Subscribe both sides, then send.
    let mut a_events = Client::connect(&alice.socket_path).await;
    let mut b_events = Client::connect(&bob.socket_path).await;
    assert_eq!(
        a_events.ok(json!({ "op": "subscribe" })).await,
        json!({ "subscribed": true })
    );
    b_events.ok(json!({ "op": "subscribe" })).await;

    let sent = a
        .ok(json!({ "op": "send", "peer": bob_peer, "body": "hello over the daemon" }))
        .await;
    let msg_id = sent["id"].as_str().unwrap().to_owned();

    // Bob's event stream reports the decrypted message.
    let received = b_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(received["body"], json!("hello over the daemon"));
    assert_eq!(received["peer"], json!(alice_peer));

    // Alice's event stream walks the honest ladder to `delivered` (an
    // end-to-end encrypted receipt, not a transport ack).
    a_events
        .wait_event(|e| e["id"] == json!(msg_id) && e["state"] == json!("delivered"))
        .await;

    // History and state agree over RPC.
    let messages = a.ok(json!({ "op": "messages", "peer": bob_peer })).await;
    let record = &messages["messages"][0];
    assert_eq!(record["state"], json!("delivered"));
    assert_eq!(record["direction"], json!("out"));
    assert_eq!(record["body"], json!("hello over the daemon"));

    // Bob replies over the established session; Alice sees it.
    b.ok(json!({ "op": "send", "peer": alice_peer, "body": "loud and clear" }))
        .await;
    let reply = a_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(reply["body"], json!("loud and clear"));

    // Safety numbers match on both ends, and verification round-trips.
    let sn_a = a
        .ok(json!({ "op": "safety_number", "peer": bob_peer }))
        .await;
    let sn_b = b
        .ok(json!({ "op": "safety_number", "peer": alice_peer }))
        .await;
    assert_eq!(sn_a["digits"], sn_b["digits"]);
    a.ok(json!({ "op": "verify", "peer": bob_peer })).await;
    let contacts = a.ok(json!({ "op": "contacts" })).await;
    assert_eq!(contacts["contacts"][0]["verified"], json!(true));

    // Errors are honest, not fake successes.
    let err = a
        .call(json!({ "op": "send", "peer": "00".repeat(32), "body": "x" }))
        .await
        .unwrap_err();
    assert!(err.contains("not a stored contact"), "got: {err}");
    let err = a
        .call(json!({ "op": "send", "peer": "zz", "body": "x" }))
        .await
        .unwrap_err();
    assert!(err.contains("hex"), "got: {err}");

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Restart persistence: the daemon reopens its store and the history
/// survives — and a wrong passphrase is refused.
#[tokio::test(flavor = "multi_thread")]
async fn daemon_restarts_with_history() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(dir.path(), "alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(dir.path(), "bob")).await.unwrap();

    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;
    let b_addr = listen_addr(&mut b).await;
    let b_bundle = b.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_peer = a
        .ok(json!({
            "op": "add_contact",
            "name": "bob",
            "bundle": b_bundle,
            "hints": [{ "multiaddr": b_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    a.ok(json!({ "op": "send", "peer": bob_peer, "body": "before restart" }))
        .await;
    let mut b_events = Client::connect(&bob.socket_path).await;
    b_events.ok(json!({ "op": "subscribe" })).await;
    b_events.wait_event(|e| e["type"] == json!("message")).await;

    let address_before = alice.address.clone();
    alice.shutdown().await;

    // Wrong passphrase: refused, honestly.
    let mut bad = test_config(dir.path(), "alice");
    bad.passphrase = b"wrong".to_vec();
    assert!(Daemon::start(bad).await.is_err());

    // Right passphrase: same identity, history intact.
    let alice = Daemon::start(test_config(dir.path(), "alice"))
        .await
        .unwrap();
    assert_eq!(alice.address, address_before);
    let mut a = Client::connect(&alice.socket_path).await;
    let messages = a.ok(json!({ "op": "messages", "peer": bob_peer })).await;
    assert_eq!(messages["messages"][0]["body"], json!("before restart"));
    let contacts = a.ok(json!({ "op": "contacts" })).await;
    assert_eq!(contacts["contacts"][0]["name"], json!("bob"));

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Backup over RPC, then a "lost device": a fresh daemon restores from the
/// file + mnemonic alone, resumes the identity with contacts and history,
/// and messaging works again in both directions (docs/07-storage.md §4).
#[tokio::test(flavor = "multi_thread")]
async fn backup_and_restore_via_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(dir.path(), "alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(dir.path(), "bob")).await.unwrap();

    // Pair and converse, so the backup has a session to reset.
    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;
    let a_addr = listen_addr(&mut a).await;
    let b_addr = listen_addr(&mut b).await;
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
            "op": "add_contact", "name": "bob", "bundle": b_bundle,
            "hints": [{ "multiaddr": b_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_peer = b
        .ok(json!({
            "op": "add_contact", "name": "alice", "bundle": a_bundle,
            "hints": [{ "multiaddr": a_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut b_events = Client::connect(&bob.socket_path).await;
    b_events.ok(json!({ "op": "subscribe" })).await;
    a.ok(json!({ "op": "send", "peer": bob_peer, "body": "before the backup" }))
        .await;
    b_events.wait_event(|e| e["type"] == json!("message")).await;

    // Backup over RPC: the file appears (0600, never clobbered), the
    // mnemonic is returned exactly once.
    let backup_path = dir.path().join("alice.kkr");
    let backed = a
        .ok(json!({ "op": "backup", "path": backup_path.display().to_string() }))
        .await;
    let mnemonic = backed["mnemonic"].as_str().unwrap().to_owned();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    assert!(backup_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let err = a
        .call(json!({ "op": "backup", "path": backup_path.display().to_string() }))
        .await
        .unwrap_err();
    assert!(err.contains("backup write"), "got: {err}");

    // The device is lost.
    let address_before = alice.address.clone();
    alice.shutdown().await;

    // A fresh daemon restores from the backup (new data dir, new
    // passphrase) — but never over an existing store.
    let mut restored_cfg = test_config(dir.path(), "alice-new");
    restored_cfg.passphrase = b"new-passphrase".to_vec();
    restored_cfg.restore_from = Some(backup_path.clone());
    restored_cfg.restore_mnemonic = Some(mnemonic.clone());
    let mut over_existing = test_config(dir.path(), "alice");
    over_existing.restore_from = Some(backup_path.clone());
    over_existing.restore_mnemonic = Some(mnemonic);
    assert!(Daemon::start(over_existing).await.is_err());
    let alice = Daemon::start(restored_cfg).await.unwrap();
    assert_eq!(alice.address, address_before);

    // Contacts and history came back.
    let mut a = Client::connect(&alice.socket_path).await;
    let contacts = a.ok(json!({ "op": "contacts" })).await;
    assert_eq!(contacts["contacts"][0]["name"], json!("bob"));
    let messages = a.ok(json!({ "op": "messages", "peer": bob_peer })).await;
    assert_eq!(messages["messages"][0]["body"], json!("before the backup"));

    // The new device listens on a new address; Bob learns it the way any
    // moved contact's address arrives (out-of-band here — the DHT bundle
    // republish covers it in bootstrap deployments).
    let a_addr_new = listen_addr(&mut a).await;
    b.ok(json!({
        "op": "set_hints", "peer": alice_peer,
        "hints": [{ "multiaddr": a_addr_new }],
    }))
    .await;

    // The tick loop re-handshakes Bob (session reset marker): a *second*
    // session_established for the same contact — the first was the
    // original pairing. Only then is Bob's ratchet the fresh one.
    b_events
        .wait_event_count(|e| e["type"] == json!("session_established"), 2)
        .await;
    let mut a_events = Client::connect(&alice.socket_path).await;
    a_events.ok(json!({ "op": "subscribe" })).await;
    b.ok(json!({ "op": "send", "peer": alice_peer, "body": "you're back" }))
        .await;
    let got = a_events.wait_event(|e| e["type"] == json!("message")).await;
    assert_eq!(got["body"], json!("you're back"));
    let sent = a
        .ok(json!({ "op": "send", "peer": bob_peer, "body": "new device, same me" }))
        .await;
    let msg_id = sent["id"].as_str().unwrap().to_owned();
    a_events
        .wait_event(|e| e["id"] == json!(msg_id) && e["state"] == json!("delivered"))
        .await;

    alice.shutdown().await;
    bob.shutdown().await;
}

/// F1 group front-door acceptance: every group operation, record, event,
/// and per-member delivery state crosses only the public RPC boundary.
#[tokio::test(flavor = "multi_thread")]
async fn groups_via_rpc_only() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(dir.path(), "group-alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(dir.path(), "group-bob"))
        .await
        .unwrap();
    let carol = Daemon::start(test_config(dir.path(), "group-carol"))
        .await
        .unwrap();

    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;
    let mut c = Client::connect(&carol.socket_path).await;
    let a_addr = listen_addr(&mut a).await;
    let b_addr = listen_addr(&mut b).await;
    let c_addr = listen_addr(&mut c).await;
    let a_bundle = a.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let b_bundle = b.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let c_bundle = c.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();

    let bob_peer = a
        .ok(json!({
            "op": "add_contact", "name": "bob", "bundle": b_bundle,
            "hints": [{ "multiaddr": b_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let carol_peer = a
        .ok(json!({
            "op": "add_contact", "name": "carol", "bundle": c_bundle,
            "hints": [{ "multiaddr": c_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_peer = b
        .ok(json!({
            "op": "add_contact", "name": "alice", "bundle": a_bundle,
            "hints": [{ "multiaddr": a_addr }],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    c.ok(json!({
        "op": "add_contact", "name": "alice", "bundle": a_bundle,
        "hints": [{ "multiaddr": a_addr }],
    }))
    .await;

    let mut a_events = Client::connect(&alice.socket_path).await;
    let mut b_events = Client::connect(&bob.socket_path).await;
    let mut c_events = Client::connect(&carol.socket_path).await;
    a_events.ok(json!({ "op": "subscribe" })).await;
    b_events.ok(json!({ "op": "subscribe" })).await;
    c_events.ok(json!({ "op": "subscribe" })).await;

    let group = a
        .ok(json!({ "op": "group_create", "name": "trail crew", "members": [bob_peer] }))
        .await["group"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event(|event| event["type"] == json!("group_updated"))
        .await;
    let listed = b.ok(json!({ "op": "groups" })).await;
    assert_eq!(listed["groups"][0]["id"], json!(group));
    assert_eq!(listed["groups"][0]["name"], json!("trail crew"));
    assert_eq!(listed["groups"][0]["creator"], json!(alice_peer));
    assert_eq!(listed["groups"][0]["members"].as_array().unwrap().len(), 2);

    // Membership authority and malformed/unknown ids stay explicit.
    let err = b
        .call(json!({ "op": "group_remove", "group": group, "peer": carol_peer }))
        .await
        .unwrap_err();
    assert!(err.contains("creator"), "got: {err}");
    let err = a
        .call(json!({ "op": "group_send", "group": "zz", "body": "x" }))
        .await
        .unwrap_err();
    assert!(err.contains("group") && err.contains("hex"), "got: {err}");
    let err = a
        .call(json!({ "op": "group_send", "group": "00".repeat(32), "body": "x" }))
        .await
        .unwrap_err();
    assert!(err.contains("no stored group"), "got: {err}");

    a.ok(json!({ "op": "group_add", "group": group, "peer": carol_peer }))
        .await;
    c_events
        .wait_event(|event| event["type"] == json!("group_updated"))
        .await;

    let sent = a
        .ok(json!({ "op": "group_send", "group": group, "body": "meet at the pass" }))
        .await;
    let message_id = sent["id"].as_str().unwrap().to_owned();
    let bob_received = b_events
        .wait_event(|event| event["type"] == json!("group_message"))
        .await;
    let carol_received = c_events
        .wait_event(|event| event["type"] == json!("group_message"))
        .await;
    assert_eq!(bob_received["body"], json!("meet at the pass"));
    assert_eq!(carol_received["body"], json!("meet at the pass"));
    a_events
        .wait_event(|event| {
            event["type"] == json!("group_delivery")
                && event["id"] == json!(message_id)
                && event["peer"] == json!(bob_peer)
                && event["state"] == json!("delivered")
        })
        .await;
    a_events
        .wait_event(|event| {
            event["type"] == json!("group_delivery")
                && event["id"] == json!(message_id)
                && event["peer"] == json!(carol_peer)
                && event["state"] == json!("delivered")
        })
        .await;

    let history = a
        .ok(json!({ "op": "group_messages", "group": group }))
        .await;
    let record = &history["messages"][0];
    assert_eq!(record["body"], json!("meet at the pass"));
    assert_eq!(record["direction"], json!("out"));
    let deliveries = record["deliveries"].as_array().unwrap();
    assert_eq!(deliveries.len(), 2);
    assert!(deliveries
        .iter()
        .all(|delivery| delivery["state"] == json!("delivered")));

    a.ok(json!({ "op": "group_remove", "group": group, "peer": carol_peer }))
        .await;
    c_events
        .wait_event_count(|event| event["type"] == json!("group_updated"), 2)
        .await;
    assert!(c.ok(json!({ "op": "groups" })).await["groups"]
        .as_array()
        .unwrap()
        .is_empty());

    b.ok(json!({ "op": "group_leave", "group": group })).await;
    assert!(b.ok(json!({ "op": "groups" })).await["groups"]
        .as_array()
        .unwrap()
        .is_empty());

    alice.shutdown().await;
    bob.shutdown().await;
    carol.shutdown().await;
}
