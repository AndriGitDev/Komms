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

fn label_parity_fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/b18-label-parity.json"))
        .expect("valid shared B18 label fixture")
}

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

async fn wait_carrier(client: &mut Client, peer: &str, expected: &str) -> Value {
    for _ in 0..100 {
        let snapshots = client.ok(json!({ "op": "carrier_capabilities" })).await;
        if let Some(snapshot) = snapshots["capabilities"].as_array().and_then(|items| {
            items.iter().find(|snapshot| {
                snapshot["peer"] == json!(peer) && snapshot["capability"] == json!(expected)
            })
        }) {
            return snapshot.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {expected} carrier verdict for {peer} within 5s");
}

async fn wait_mention_supported(client: &mut Client, group: &str) -> Value {
    for _ in 0..100 {
        let capability = client
            .ok(json!({ "op": "group_mention_capability", "group": group }))
            .await;
        if capability["supported"] == json!(true) {
            return capability;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("mention capability intersection did not become supported");
}

#[tokio::test(flavor = "multi_thread")]
async fn note_to_self_via_rpc_is_local_and_uses_the_reserved_identity() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "notes"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let mut events = Client::connect(&daemon.socket_path).await;
    events.ok(json!({ "op": "subscribe" })).await;

    let sent = client
        .ok(json!({
            "op": "note_to_self_send",
            "body": "check the radio batteries",
        }))
        .await;
    assert_eq!(sent["conversation"], json!("note_to_self"));
    let id = sent["id"].as_str().unwrap().to_owned();
    let event = events
        .wait_event(|event| event["type"] == json!("note_to_self_message"))
        .await;
    assert_eq!(event["conversation"], json!("note_to_self"));
    assert_eq!(event["id"], json!(id));

    let history = client.ok(json!({ "op": "note_to_self_messages" })).await;
    assert_eq!(history["conversation"], json!("note_to_self"));
    assert_eq!(
        history["messages"][0]["body"],
        json!("check the radio batteries")
    );
    let status = client.ok(json!({ "op": "status" })).await;
    assert_eq!(status["queued"], json!(0));
    assert_eq!(status["contacts"], json!(0));

    // The same local-only contract test also pins scheduling's RPC front
    // door without adding another network-heavy test thread. A self contact
    // is sufficient because activation is deliberately hours away.
    let bob_bundle = client.ok(json!({ "op": "bundle" })).await["bundle"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_peer = client
        .ok(json!({
            "op": "add_contact",
            "name": "bob",
            "bundle": bob_bundle,
            "hints": [],
        }))
        .await["peer"]
        .as_str()
        .unwrap()
        .to_owned();
    let group = client
        .ok(json!({ "op": "group_create", "name": "later", "members": [] }))
        .await["group"]
        .as_str()
        .unwrap()
        .to_owned();
    let future = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;

    let pair = client
        .ok(json!({
            "op": "schedule",
            "peer": bob_peer,
            "body": "first draft",
            "not_before": future,
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .ok(json!({
            "op": "group_schedule",
            "group": group,
            "body": "group later",
            "not_before": future + 60,
        }))
        .await;
    let scheduled = client.ok(json!({ "op": "scheduled_messages" })).await;
    assert_eq!(scheduled["messages"].as_array().unwrap().len(), 2);
    assert_eq!(scheduled["messages"][0]["state"], json!("scheduled"));
    assert_eq!(scheduled["messages"][0]["conversation"], json!("peer"));
    assert_eq!(scheduled["messages"][1]["conversation"], json!("group"));
    let status = client.ok(json!({ "op": "status" })).await;
    assert_eq!(status["scheduled"], json!(2));

    client
        .ok(json!({
            "op": "scheduled_edit",
            "message": pair,
            "body": "final text",
            "not_before": future + 120,
        }))
        .await;
    let scheduled = client.ok(json!({ "op": "scheduled_messages" })).await;
    assert_eq!(scheduled["messages"][0]["body"], json!("final text"));
    assert_eq!(scheduled["messages"][0]["not_before"], json!(future + 120));
    client
        .ok(json!({ "op": "scheduled_cancel", "message": pair }))
        .await;
    assert_eq!(
        client.ok(json!({ "op": "scheduled_messages" })).await["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    daemon.shutdown().await;
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

    let carrier = wait_carrier(&mut a, &bob_peer, "realtime").await;
    assert!(carrier["expires_at"].as_u64().unwrap() > carrier["observed_at"].as_u64().unwrap());

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

    // Attachment input/output stays path-bounded at the RPC edge while all
    // cryptography, consent, progress, and carrier policy remain in the node.
    wait_carrier(&mut b, &alice_peer, "realtime").await;
    let attachment_bytes = b"attachment bytes through RPC\0and after the NUL";
    let preview_bytes = b"RPC local jpeg preview";
    let source = dir.path().join("rpc-source.bin");
    let preview = dir.path().join("rpc-preview.jpg");
    std::fs::write(&source, attachment_bytes).unwrap();
    std::fs::write(&preview, preview_bytes).unwrap();
    let sent_attachment = a
        .ok(json!({
            "op": "attachment_send",
            "peer": bob_peer,
            "path": source.display().to_string(),
            "media_type": "application/octet-stream",
            "filename": "field-notes.bin",
            "preview_path": preview.display().to_string(),
            "preview_media_type": "image/jpeg",
        }))
        .await;
    let attachment_content_id = sent_attachment["id"].as_str().unwrap().to_owned();
    let outbound = a.ok(json!({ "op": "attachments" })).await;
    let outbound_transfer = outbound["attachments"][0]["transfer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        outbound["attachments"][0]["content_id"],
        attachment_content_id
    );
    assert_eq!(outbound["attachments"][0]["direction"], json!("out"));
    assert_eq!(
        outbound["attachments"][0]["objects"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        outbound["attachments"][0]["objects"][0]["filename"],
        json!("field-notes.bin")
    );

    // Lifecycle controls use only the random local transfer id.
    a.ok(json!({ "op": "attachment_pause", "transfer": outbound_transfer }))
        .await;
    assert_eq!(
        a.ok(json!({ "op": "attachments" })).await["attachments"][0]["state"],
        json!("paused")
    );
    a.ok(json!({ "op": "attachment_resume", "transfer": outbound_transfer }))
        .await;

    let offer = b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["direction"] == json!("in")
        })
        .await;
    let inbound_transfer = offer["attachment"]["transfer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(offer["attachment"]["content_id"], attachment_content_id);
    assert_eq!(offer["attachment"]["state"], json!("awaiting_consent"));
    let attachment_message = b_events
        .wait_event(|event| {
            event["type"] == json!("message") && event["content_kind"] == json!("attachment")
        })
        .await;
    assert_eq!(attachment_message["body"], json!(""));

    b.ok(json!({ "op": "attachment_accept", "transfer": inbound_transfer }))
        .await;
    b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["transfer_id"] == json!(inbound_transfer)
                && event["attachment"]["state"] == json!("complete")
        })
        .await;
    let completed = b.ok(json!({ "op": "attachments" })).await;
    assert_eq!(
        completed["attachments"][0]["objects"][0]["verified_bytes"],
        json!(attachment_bytes.len())
    );
    assert_eq!(
        completed["attachments"][0]["objects"][1]["verified_bytes"],
        json!(preview_bytes.len())
    );
    let exported = dir.path().join("rpc-export.bin");
    b.ok(json!({
        "op": "attachment_export",
        "transfer": inbound_transfer,
        "path": exported.display().to_string(),
    }))
    .await;
    assert_eq!(std::fs::read(&exported).unwrap(), attachment_bytes);
    let exported_preview = dir.path().join("rpc-export-preview.jpg");
    b.ok(json!({
        "op": "attachment_export",
        "transfer": inbound_transfer,
        "path": exported_preview.display().to_string(),
        "preview": true,
    }))
    .await;
    assert_eq!(std::fs::read(&exported_preview).unwrap(), preview_bytes);
    let overwrite = b
        .call(json!({
            "op": "attachment_export",
            "transfer": inbound_transfer,
            "path": exported.display().to_string(),
        }))
        .await
        .unwrap_err();
    assert!(overwrite.contains("attachment export"), "got: {overwrite}");
    assert_eq!(std::fs::read(&exported).unwrap(), attachment_bytes);
    b.ok(json!({ "op": "attachment_reject", "transfer": inbound_transfer }))
        .await;
    assert_eq!(
        b.ok(json!({ "op": "attachments" })).await["attachments"][0]["state"],
        json!("rejected")
    );
    a.ok(json!({ "op": "attachment_cancel", "transfer": outbound_transfer }))
        .await;
    assert_eq!(
        a.ok(json!({ "op": "attachments" })).await["attachments"][0]["state"],
        json!("cancelled")
    );

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
    // `send` persists the outbound record before returning. Assert that
    // precondition directly instead of waiting for unrelated network delivery,
    // which can race with the other RPC integration tests on a busy runner.
    a.ok(json!({ "op": "send", "peer": bob_peer, "body": "before restart" }))
        .await;
    let before_restart = a.ok(json!({ "op": "messages", "peer": bob_peer })).await;
    assert_eq!(
        before_restart["messages"][0]["body"],
        json!("before restart")
    );

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
    let label_fixture = label_parity_fixture();
    let dir = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(dir.path(), "group-alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(dir.path(), "group-bob"))
        .await
        .unwrap();

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
    let mut a_events = Client::connect(&alice.socket_path).await;
    let mut b_events = Client::connect(&bob.socket_path).await;
    a_events.ok(json!({ "op": "subscribe" })).await;
    b_events.ok(json!({ "op": "subscribe" })).await;

    let group = a
        .ok(json!({ "op": "group_create", "name": "trail crew", "members": [] }))
        .await["group"]
        .as_str()
        .unwrap()
        .to_owned();
    a.ok(json!({ "op": "group_add", "group": group, "peer": bob_peer }))
        .await;
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
        .call(json!({ "op": "group_add", "group": group, "peer": alice_peer }))
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

    let sent = a
        .ok(json!({ "op": "group_send", "group": group, "body": "meet at the pass" }))
        .await;
    let message_id = sent["id"].as_str().unwrap().to_owned();
    let bob_received = b_events
        .wait_event(|event| event["type"] == json!("group_message"))
        .await;
    assert_eq!(bob_received["body"], json!("meet at the pass"));
    a_events
        .wait_event(|event| {
            event["type"] == json!("group_delivery")
                && event["id"] == json!(message_id)
                && event["peer"] == json!(bob_peer)
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
    assert_eq!(deliveries.len(), 1);
    assert!(deliveries
        .iter()
        .all(|delivery| delivery["state"] == json!("delivered")));

    // B17 stays structured through RPC: the client supplies exact UTF-8 byte
    // ranges and peer ids, then the daemon atomically revalidates the review
    // token before network send. No display-name inference or raw frame bytes
    // cross this boundary.
    let capability = wait_mention_supported(&mut a, &group).await;
    assert!(capability["issues"].as_array().unwrap().is_empty());
    let review_token = capability["review_token"].as_str().unwrap().to_owned();
    let history_before_invalid = a
        .ok(json!({ "op": "group_messages", "group": group }))
        .await["messages"]
        .as_array()
        .unwrap()
        .len();
    let err = a
        .call(json!({
            "op": "group_mention_send",
            "group": group,
            "text": "👩",
            "spans": [{ "start": 1, "end": 4, "target": bob_peer }],
            "review_token": review_token,
        }))
        .await
        .unwrap_err();
    assert!(err.contains("invalid group mention"), "got: {err}");
    let history_after_invalid = a
        .ok(json!({ "op": "group_messages", "group": group }))
        .await["messages"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        history_after_invalid, history_before_invalid,
        "invalid RPC byte ranges are rejected before persistence or send"
    );

    let text = "hi @bob 👋";
    let mention = a
        .ok(json!({
            "op": "group_mention_send",
            "group": group,
            "text": text,
            "spans": [{ "start": 3, "end": 7, "target": bob_peer }],
            "review_token": review_token,
        }))
        .await;
    let mention_id = mention["id"].as_str().unwrap().to_owned();
    let mention_event = b_events
        .wait_event(|event| {
            event["type"] == json!("group_message") && event["id"] == json!(mention_id)
        })
        .await;
    assert_eq!(mention_event["body"], json!(text));
    assert_eq!(mention_event["content_kind"], json!("mention"));
    assert_eq!(mention_event["mention_spans"][0]["start"], json!(3));
    assert_eq!(mention_event["mention_spans"][0]["end"], json!(7));
    assert_eq!(mention_event["mention_spans"][0]["target"], json!(bob_peer));
    let local_signal = b_events
        .wait_event(|event| {
            event["type"] == json!("mention_received") && event["id"] == json!(mention_id)
        })
        .await;
    assert_eq!(local_signal.as_object().unwrap().len(), 2);

    let history = a
        .ok(json!({ "op": "group_messages", "group": group }))
        .await;
    let record = history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == json!(mention_id))
        .unwrap();
    assert_eq!(record["body"], json!(text));
    assert_eq!(record["content_kind"], json!("mention"));
    assert_eq!(record["mention_spans"][0]["target"], json!(bob_peer));
    assert!(record.get("wire_body").is_none());

    let err = a
        .call(json!({
            "op": "group_mention_send",
            "group": group,
            "text": "hi @bob",
            "spans": [{ "start": 3, "end": 7, "target": "bob" }],
            "review_token": review_token,
        }))
        .await
        .unwrap_err();
    assert!(err.contains("peer") && err.contains("hex"), "got: {err}");

    // B18 stays local and structured through RPC: exact label ids plus exact
    // typed targets, never display-name inference. Duplicate names are
    // disambiguated by canonical color and durable order.
    let queued_before_labels = a.ok(json!({ "op": "status" })).await["queued"].clone();
    let first_label = a
        .ok(json!({
            "op": "label_create",
            "name": label_fixture["duplicate_name"],
            "color": label_fixture["create_colors"][0],
        }))
        .await;
    let second_label = a
        .ok(json!({
            "op": "label_create",
            "name": label_fixture["duplicate_name"],
            "color": label_fixture["create_colors"][1],
        }))
        .await;
    let first_id = first_label["id"].as_str().unwrap().to_owned();
    let second_id = second_label["id"].as_str().unwrap().to_owned();
    assert_ne!(first_id, second_id);
    assert_eq!(first_label["order"], label_fixture["expected_orders"][0]);
    assert_eq!(second_label["order"], label_fixture["expected_orders"][1]);
    assert_eq!(first_id.len(), 32);

    for target in [
        json!({ "type": "peer", "id": bob_peer }),
        json!({ "type": "group", "id": group }),
        json!({ "type": "note_to_self" }),
    ] {
        assert_eq!(
            a.ok(json!({ "op": "label_assign", "label": first_id, "target": target }))
                .await["changed"],
            json!(true)
        );
    }
    for target in [
        json!({ "type": "group", "id": group }),
        json!({ "type": "note_to_self" }),
    ] {
        a.ok(json!({ "op": "label_assign", "label": second_id, "target": target }))
            .await;
    }
    assert_eq!(
        a.ok(json!({
            "op": "label_assign",
            "label": second_id,
            "target": { "type": "note_to_self" },
        }))
        .await["changed"],
        json!(false)
    );

    let labels = a.ok(json!({ "op": "labels" })).await;
    assert_eq!(labels["labels"][0]["name"], first_label["name"]);
    assert_eq!(labels["labels"][0]["color"], json!("teal"));
    assert_eq!(labels["labels"][1]["color"], json!("pink"));
    let membership = a
        .ok(json!({ "op": "label_membership", "label": first_id }))
        .await;
    assert_eq!(membership["members"].as_array().unwrap().len(), 3);
    assert_eq!(
        membership["members"][0]["type"],
        label_fixture["membership_target_kinds"][0]
    );
    assert_eq!(membership["members"][0]["id"], json!(bob_peer));
    assert_eq!(
        membership["members"][1]["type"],
        label_fixture["membership_target_kinds"][1]
    );
    assert_eq!(membership["members"][1]["id"], json!(group));
    assert_eq!(
        membership["members"][2]["type"],
        label_fixture["membership_target_kinds"][2]
    );
    let for_group = a
        .ok(json!({
            "op": "labels_for_conversation",
            "target": { "type": "group", "id": group },
        }))
        .await;
    assert_eq!(for_group["labels"].as_array().unwrap().len(), 2);

    let any = a
        .ok(json!({
            "op": "label_filter",
            "labels": [first_id, first_id],
            "mode": "any",
        }))
        .await;
    assert_eq!(any["selected"], json!([first_id]));
    assert_eq!(
        any["conversations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["type"].clone())
            .collect::<Vec<_>>(),
        label_fixture["match_any_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );
    let all = a
        .ok(json!({
            "op": "label_filter",
            "labels": [first_id, second_id],
            "mode": "all",
        }))
        .await;
    assert_eq!(
        all["conversations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["type"].clone())
            .collect::<Vec<_>>(),
        label_fixture["match_all_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );

    let updated = a
        .ok(json!({
            "op": "label_update",
            "label": first_id,
            "name": label_fixture["renamed_name"],
            "color": label_fixture["renamed_color"],
        }))
        .await;
    assert_eq!(updated["id"], json!(first_id));
    assert_eq!(updated["order"], json!(0));
    assert_eq!(
        a.ok(json!({ "op": "label_delete_preview", "label": first_id }))
            .await["assignments"],
        label_fixture["expected_assignment_count"]
    );
    let err = a
        .call(json!({ "op": "label_delete", "label": first_id, "confirm": false }))
        .await
        .unwrap_err();
    assert_eq!(err, "label deletion requires explicit confirmation");
    assert_eq!(
        a.ok(json!({ "op": "label_delete", "label": first_id, "confirm": true }))
            .await["assignments_deleted"],
        label_fixture["expected_assignment_count"]
    );
    assert!(a
        .call(json!({ "op": "label_get", "label": first_id }))
        .await
        .unwrap_err()
        .contains("does not exist"));
    assert!(a.ok(json!({ "op": "label_stale" })).await["stale"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        a.ok(json!({ "op": "status" })).await["queued"],
        queued_before_labels
    );

    let group_attachment_bytes = b"one ciphertext set for the group";
    let group_source = dir.path().join("rpc-group-source.bin");
    std::fs::write(&group_source, group_attachment_bytes).unwrap();
    let group_attachment = a
        .ok(json!({
            "op": "group_attachment_send",
            "group": group,
            "path": group_source.display().to_string(),
            "media_type": "application/octet-stream",
            "filename": "group.bin",
        }))
        .await;
    let group_content_id = group_attachment["id"].as_str().unwrap().to_owned();
    let group_offer = b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["conversation"] == json!("group")
                && event["attachment"]["content_id"] == json!(group_content_id)
        })
        .await;
    assert_eq!(group_offer["attachment"]["group"], json!(group));
    let group_transfer = group_offer["attachment"]["transfer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    b.ok(json!({ "op": "attachment_accept", "transfer": group_transfer }))
        .await;
    b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["transfer_id"] == json!(group_transfer)
                && event["attachment"]["state"] == json!("complete")
        })
        .await;
    let group_export = dir.path().join("rpc-group-export.bin");
    b.ok(json!({
        "op": "attachment_export",
        "transfer": group_transfer,
        "path": group_export.display().to_string(),
    }))
    .await;
    assert_eq!(std::fs::read(group_export).unwrap(), group_attachment_bytes);

    a.ok(json!({ "op": "group_remove", "group": group, "peer": bob_peer }))
        .await;
    b_events
        .wait_event_count(|event| event["type"] == json!("group_updated"), 2)
        .await;
    assert!(b.ok(json!({ "op": "groups" })).await["groups"]
        .as_array()
        .unwrap()
        .is_empty());

    let leave_group = a
        .ok(json!({ "op": "group_create", "name": "short trip", "members": [bob_peer] }))
        .await["group"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event_count(|event| event["type"] == json!("group_updated"), 3)
        .await;
    assert_eq!(
        b.ok(json!({ "op": "group_leave", "group": leave_group }))
            .await,
        json!({})
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
