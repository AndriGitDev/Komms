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

fn folder_parity_fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/b10-folder-parity.json"))
        .expect("valid shared B10 folder fixture")
}

fn pin_parity_fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/b11-pin-parity.json"))
        .expect("valid shared B11 pin fixture")
}

fn theme_parity_fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/b12-theme-parity.json"))
        .expect("valid shared B12 theme fixture")
}

fn custom_icon_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b13-custom-icon-parity.json"
    ))
    .expect("valid shared B13 custom-icon fixture")
}

fn screen_security_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b14-screen-security-parity.json"
    ))
    .expect("valid shared B14 screen-security fixture")
}

fn incognito_keyboard_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b15-incognito-keyboard-parity.json"
    ))
    .expect("valid shared B15 incognito-keyboard fixture")
}

fn contact_rename_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b5-contact-rename-parity.json"
    ))
    .expect("valid shared B5 contact-rename fixture")
}

fn text_formatting_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b9-text-formatting-parity.json"
    ))
    .expect("valid shared B9 text-formatting fixture")
}

fn file_presentation_parity_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/c1-file-presentation-parity.json"
    ))
    .expect("valid shared C1 file-presentation fixture")
}

fn ephemeral_parity_fixture() -> Value {
    serde_json::from_str(include_str!("../../../fixtures/c4-ephemeral-parity.json"))
        .expect("valid shared C4 ephemeral fixture")
}

#[tokio::test(flavor = "multi_thread")]
async fn file_presentation_via_strict_rpc_matches_shared_fail_closed_policy() {
    let fixture = file_presentation_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "file-presentation-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();

    for case in fixture["cases"].as_array().unwrap() {
        let presentation = client
            .ok(json!({
                "op": "attachment_file_presentation",
                "media_type": case["media_type"],
                "filename": case["filename"],
            }))
            .await;
        assert_eq!(presentation["kind"], case["kind"]);
        assert_eq!(presentation["open_policy"], case["open_policy"]);
        assert_eq!(presentation["warnings"], case["warnings"]);
    }

    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn safe_text_formatting_via_strict_rpc_matches_shared_corpus_without_delivery_work() {
    let fixture = text_formatting_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "text-formatting-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();
    for case in fixture["cases"].as_array().unwrap() {
        let formatted = client
            .ok(json!({
                "op": "format_text",
                "source": case["source"],
                "highlights": case["highlights"],
            }))
            .await;
        assert_eq!(formatted["source"], case["source"], "{}", case["name"]);
        assert_eq!(
            formatted["plain_text"], case["plain_text"],
            "{}",
            case["name"]
        );
        assert_eq!(
            formatted["used_fallback"], case["used_fallback"],
            "{}",
            case["name"]
        );
        assert_eq!(
            formatted["blocks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|block| block["kind"].clone())
                .collect::<Vec<_>>(),
            case["block_kinds"].as_array().unwrap().clone()
        );
    }
    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_contact_rename_via_strict_rpc_is_normalized_warned_and_delivery_free() {
    let fixture = contact_rename_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let alice = Daemon::start(test_config(directory.path(), "contact-rename-rpc-alice"))
        .await
        .unwrap();
    let bob = Daemon::start(test_config(directory.path(), "contact-rename-rpc-bob"))
        .await
        .unwrap();
    let mut a = Client::connect(&alice.socket_path).await;
    let mut b = Client::connect(&bob.socket_path).await;
    let queued = a.ok(json!({ "op": "status" })).await["queued"].clone();
    let self_bundle = a.ok(json!({ "op": "bundle" })).await["bundle"].clone();
    let bob_bundle = b.ok(json!({ "op": "bundle" })).await["bundle"].clone();
    a.ok(json!({
        "op": "add_contact",
        "name": fixture["duplicate_name"],
        "bundle": self_bundle,
    }))
    .await;
    let bob_peer = a
        .ok(json!({
            "op": "add_contact",
            "name": "Bob",
            "bundle": bob_bundle,
        }))
        .await["peer"]
        .clone();

    let normalized = a
        .ok(json!({
            "op": "rename_contact",
            "peer": bob_peer,
            "name": fixture["decomposed_name"],
        }))
        .await;
    assert_eq!(normalized["normalized_name"], fixture["normalized_name"]);
    assert_eq!(normalized["changed_by_normalization"], true);

    let duplicate = a
        .ok(json!({
            "op": "contact_name_assessment",
            "peer": bob_peer,
            "name": fixture["duplicate_name"],
        }))
        .await;
    assert_eq!(duplicate["duplicate_count"], 1);
    assert_eq!(duplicate["warnings"], json!(["duplicate_name"]));
    assert!(a
        .call(json!({
            "op": "rename_contact",
            "peer": bob_peer,
            "name": fixture["duplicate_name"],
        }))
        .await
        .is_err());
    a.ok(json!({
        "op": "rename_contact",
        "peer": bob_peer,
        "name": fixture["duplicate_name"],
        "accept_warnings": true,
    }))
    .await;
    assert_eq!(
        a.ok(json!({ "op": "contacts" })).await["contacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|contact| contact["name"] == fixture["duplicate_name"])
            .count(),
        2
    );
    assert_eq!(a.ok(json!({ "op": "status" })).await["queued"], queued);
    alice.shutdown().await;
    bob.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn incognito_keyboard_policy_via_strict_rpc_matches_platforms_without_delivery_work() {
    let fixture = incognito_keyboard_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "incognito-keyboard-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();

    for platform in ["android", "ios", "desktop"] {
        let policy = client
            .ok(json!({ "op": "incognito_keyboard_policy", "platform": platform }))
            .await;
        assert_eq!(policy["platform"], platform);
        assert_eq!(policy["always_on"], true);
        assert_eq!(policy["applies_before_unlock"], true);
        assert_eq!(
            policy["personalized_learning"],
            fixture["platforms"][platform]["personalized_learning"]
        );
        assert_eq!(policy["protected_fields"], fixture["protected_fields"]);
        assert!(!policy["limitations"].as_array().unwrap().is_empty());
    }
    assert!(client
        .call(json!({ "op": "incognito_keyboard_policy", "platform": "web" }))
        .await
        .is_err());
    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn screen_security_policy_via_strict_rpc_matches_all_platforms_without_delivery_work() {
    let fixture = screen_security_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "screen-security-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();

    for platform in ["android", "ios", "desktop"] {
        let policy = client
            .ok(json!({ "op": "screen_security_policy", "platform": platform }))
            .await;
        assert_eq!(policy["platform"], platform);
        assert_eq!(policy["always_on"], true);
        assert_eq!(
            policy["capture_prevention"],
            fixture["platforms"][platform]["capture_prevention"]
        );
        assert_eq!(
            policy["background_obscuring"],
            fixture["platforms"][platform]["background_obscuring"]
        );
        assert!(!policy["limitations"].as_array().unwrap().is_empty());
    }
    assert!(client
        .call(json!({ "op": "screen_security_policy", "platform": "web" }))
        .await
        .is_err());
    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    daemon.shutdown().await;
}

fn relative_luminance(hex: &str) -> f64 {
    let channel = |start| {
        let value = u8::from_str_radix(&hex[start..start + 2], 16).unwrap() as f64 / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5)
}

fn contrast(first: &str, second: &str) -> f64 {
    let first = relative_luminance(first);
    let second = relative_luminance(second);
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

#[test]
fn b12_reference_palettes_meet_wcag_normal_text_contrast() {
    let fixture = theme_parity_fixture();
    let minimum = fixture["wcag"]["normal_text_min"].as_f64().unwrap();
    for mode in ["light", "dark"] {
        let palette = &fixture["reference_palettes"][mode];
        let background = palette["background"].as_str().unwrap();
        for role in ["text_primary", "text_secondary", "danger", "warning"] {
            let ratio = contrast(palette[role].as_str().unwrap(), background);
            assert!(ratio >= minimum, "{mode} {role} contrast {ratio:.2}");
        }
        let ratio = contrast(
            palette["on_action"].as_str().unwrap(),
            palette["action"].as_str().unwrap(),
        );
        assert!(ratio >= minimum, "{mode} action contrast {ratio:.2}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn private_theme_via_strict_rpc_defaults_changes_and_stays_local() {
    let fixture = theme_parity_fixture();
    assert_eq!(fixture["preferences"], json!(["system", "light", "dark"]));
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "theme-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let initial = client.ok(json!({ "op": "theme" })).await;
    assert_eq!(
        initial,
        json!({ "preference": "system", "persisted": false })
    );
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();
    let mut events = Client::connect(&daemon.socket_path).await;
    events.ok(json!({ "op": "subscribe" })).await;
    let changed = client
        .ok(json!({ "op": "theme_set", "preference": "dark" }))
        .await;
    assert_eq!(changed["changed"], true);
    assert_eq!(changed["preference"], "dark");
    assert!(!client
        .ok(json!({ "op": "theme_set", "preference": "dark" }))
        .await["changed"]
        .as_bool()
        .unwrap());
    let event = events
        .wait_event(|event| event["type"] == "theme_changed")
        .await;
    assert_eq!(event.as_object().unwrap().len(), 1);
    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    let error = client
        .call(json!({ "op": "theme_set", "preference": "sepia" }))
        .await
        .unwrap_err();
    assert!(error.contains("system, light, dark"));
    daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn private_custom_icons_via_strict_rpc_are_canonical_durable_and_local() {
    let fixture = custom_icon_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(test_config(directory.path(), "icons-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&daemon.socket_path).await;
    let mut events = Client::connect(&daemon.socket_path).await;
    events.ok(json!({ "op": "subscribe" })).await;
    let note = json!({ "type": "note_to_self" });
    assert!(client
        .ok(json!({ "op": "custom_icon", "target": note }))
        .await["icon"]
        .is_null());
    let queued = client.ok(json!({ "op": "status" })).await["queued"].clone();

    let note_icon = client
        .ok(json!({
            "op": "custom_icon_set_bundled",
            "target": note,
            "glyph": fixture["bundled_glyphs"][7],
        }))
        .await;
    assert_eq!(
        note_icon["media_type"],
        fixture["canonical_output"]["media_type"]
    );
    assert_eq!(note_icon["width"], fixture["canonical_output"]["width"]);
    assert_eq!(note_icon["height"], fixture["canonical_output"]["height"]);
    assert!(note_icon["bytes"].as_str().unwrap().starts_with("89504e47"));
    events
        .wait_event(|event| event["type"] == "custom_icons_changed")
        .await;

    let folder = client
        .ok(json!({ "op": "folder_create", "name": "Icon target" }))
        .await;
    let folder_target = json!({ "type": "folder", "id": folder["id"] });
    let folder_icon = client
        .ok(json!({
            "op": "custom_icon_set_bundled",
            "target": folder_target,
            "glyph": "folder",
        }))
        .await;
    assert_ne!(folder_icon["bytes"], note_icon["bytes"]);
    let usage = client.ok(json!({ "op": "custom_icon_usage" })).await;
    assert_eq!(usage["records"], 2);
    assert_eq!(
        usage["bytes"].as_u64().unwrap(),
        (note_icon["bytes"].as_str().unwrap().len() + folder_icon["bytes"].as_str().unwrap().len())
            as u64
            / 2
    );
    assert_eq!(client.ok(json!({ "op": "status" })).await["queued"], queued);
    assert!(client
        .call(json!({
            "op": "custom_icon_set_bundled",
            "target": note,
            "glyph": "remote-url",
        }))
        .await
        .unwrap_err()
        .contains("custom icon"));
    assert!(client
        .ok(json!({ "op": "custom_icon_clear", "target": folder_target }))
        .await["changed"]
        .as_bool()
        .unwrap());
    assert!(!client
        .ok(json!({ "op": "custom_icon_clear", "target": folder_target }))
        .await["changed"]
        .as_bool()
        .unwrap());
    daemon.shutdown().await;

    let reopened = Daemon::start(test_config(directory.path(), "icons-rpc"))
        .await
        .unwrap();
    let mut client = Client::connect(&reopened.socket_path).await;
    assert_eq!(
        client
            .ok(json!({ "op": "custom_icon", "target": note }))
            .await["icon"]["bytes"],
        note_icon["bytes"]
    );
    assert_eq!(
        client.ok(json!({ "op": "custom_icon_usage" })).await["records"],
        1
    );
    reopened.shutdown().await;
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

async fn wait_poll_revision(
    client: &mut Client,
    group: &str,
    poll_id: &str,
    revision: u64,
) -> Value {
    for _ in 0..100 {
        let listed = client
            .ok(json!({ "op": "group_polls", "group": group }))
            .await;
        if let Some(poll) = listed["polls"].as_array().and_then(|polls| {
            polls.iter().find(|poll| {
                poll["id"] == json!(poll_id)
                    && poll["votes"].as_array().is_some_and(|votes| {
                        votes.iter().any(|vote| vote["revision"] == json!(revision))
                    })
            })
        }) {
            return poll.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("poll {poll_id} did not reach vote revision {revision}");
}

async fn wait_poll_closed(client: &mut Client, group: &str, poll_id: &str) -> Value {
    for _ in 0..100 {
        let listed = client
            .ok(json!({ "op": "group_polls", "group": group }))
            .await;
        if let Some(poll) = listed["polls"].as_array().and_then(|polls| {
            polls
                .iter()
                .find(|poll| poll["id"] == json!(poll_id) && poll["closed"] == json!(true))
        }) {
            return poll.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("poll {poll_id} did not close");
}

async fn wait_authority_generation(client: &mut Client, group: &str, generation: u64) -> Value {
    for _ in 0..100 {
        let authority = client
            .ok(json!({ "op": "group_authority", "group": group }))
            .await;
        if authority["signed"] == json!(true)
            && authority["generation"]
                .as_u64()
                .is_some_and(|seen| seen >= generation)
        {
            return authority;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("group authority did not reach generation {generation}");
}

async fn wait_group_presence(client: &mut Client, group: &str, present: bool) {
    for _ in 0..100 {
        let groups = client.ok(json!({ "op": "groups" })).await;
        let found = groups["groups"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["id"] == json!(group)));
        if found == present {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("group {group} presence did not become {present}");
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
    let ephemeral = ephemeral_parity_fixture();
    let hour = ephemeral["text_lifetimes"][1].as_u64().unwrap();
    assert_eq!(ephemeral["content_kind"], json!(5));
    assert_eq!(
        ephemeral["guarantees"]["remote_erasure_promised"],
        json!(false)
    );
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

    let disappearing = a
        .ok(json!({
            "op": "send_disappearing",
            "peer": bob_peer,
            "body": "temporary over strict RPC",
            "lifetime_secs": hour,
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let temporary = b_events
        .wait_event(|event| event["type"] == json!("message") && event["id"] == json!(disappearing))
        .await;
    assert_eq!(temporary["content_kind"], json!("disappearing_text"));
    assert!(temporary["expires_at"].as_u64().is_some());
    let temporary_history = b.ok(json!({ "op": "messages", "peer": alice_peer })).await;
    let temporary_row = temporary_history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["id"] == json!(disappearing))
        .unwrap();
    assert_eq!(temporary_row["content_kind"], json!("disappearing_text"));
    assert_eq!(temporary_row["expires_at"], temporary["expires_at"]);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let editable = a
        .ok(json!({
            "op": "send",
            "peer": bob_peer,
            "body": "editable RPC original",
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event(|event| {
            event["type"] == json!("message")
                && event["id"] == json!(editable)
                && event["content_kind"] == json!("text")
        })
        .await;
    a_events
        .wait_event(|event| event["id"] == json!(editable) && event["state"] == json!("delivered"))
        .await;
    let edit = a
        .ok(json!({
            "op": "edit_message",
            "peer": bob_peer,
            "target_author": alice_peer,
            "target_content_id": editable,
            "text": "editable RPC revised",
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let refresh = b_events
        .wait_event(|event| event["type"] == json!("message_edited"))
        .await;
    assert_eq!(refresh["peer"], json!(alice_peer));
    assert_eq!(refresh["target_content_id"], json!(editable));
    a_events
        .wait_event(|event| event["id"] == json!(edit) && event["state"] == json!("delivered"))
        .await;
    for history in [
        a.ok(json!({ "op": "messages", "peer": bob_peer })).await,
        b.ok(json!({ "op": "messages", "peer": alice_peer })).await,
    ] {
        let messages = history["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3, "Edit events remain hidden");
        let message = messages
            .iter()
            .find(|message| message["id"] == json!(editable))
            .unwrap();
        assert_eq!(message["body"], json!("editable RPC revised"));
        assert_eq!(message["edited"], json!(true));
        assert_eq!(message["edit_revision"], json!(1));
        assert_eq!(message["versions"].as_array().unwrap().len(), 2);
    }

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

    let once_bytes = b"strict RPC view-once bytes";
    let once_source = dir.path().join("rpc-view-once.bin");
    std::fs::write(&once_source, once_bytes).unwrap();
    let once_id = a
        .ok(json!({
            "op": "attachment_send_view_once",
            "peer": bob_peer,
            "path": once_source.display().to_string(),
            "media_type": "application/octet-stream",
            "filename": "reveal-once.bin",
            "lifetime_secs": hour,
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let once_offer = b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["content_id"] == json!(once_id)
        })
        .await;
    assert_eq!(once_offer["attachment"]["view_once"], json!(true));
    assert!(once_offer["attachment"]["expires_at"].as_u64().is_some());
    let once_transfer = once_offer["attachment"]["transfer_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let once_message = b_events
        .wait_event(|event| event["type"] == json!("message") && event["id"] == json!(once_id))
        .await;
    assert_eq!(once_message["content_kind"], json!("view_once_attachment"));
    b.ok(json!({ "op": "attachment_accept", "transfer": once_transfer }))
        .await;
    b_events
        .wait_event(|event| {
            event["type"] == json!("attachment_updated")
                && event["attachment"]["transfer_id"] == json!(once_transfer)
                && event["attachment"]["state"] == json!("complete")
        })
        .await;
    assert!(b
        .call(json!({
            "op": "attachment_export",
            "transfer": once_transfer,
            "path": dir.path().join("forbidden-view-once.bin").display().to_string(),
        }))
        .await
        .unwrap_err()
        .contains("view-once"));
    let once_output = dir.path().join("rpc-view-once-output.bin");
    b.ok(json!({
        "op": "attachment_consume_view_once",
        "transfer": once_transfer,
        "path": once_output.display().to_string(),
    }))
    .await;
    assert_eq!(std::fs::read(&once_output).unwrap(), once_bytes);
    assert!(b
        .call(json!({
            "op": "attachment_consume_view_once",
            "transfer": once_transfer,
            "path": dir.path().join("second-view-once.bin").display().to_string(),
        }))
        .await
        .is_err());

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
    let folder_fixture = folder_parity_fixture();
    let pin_fixture = pin_parity_fixture();
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

    tokio::time::sleep(Duration::from_millis(300)).await;
    let editable = a
        .ok(json!({
            "op": "group_send",
            "group": group,
            "body": "editable group RPC original",
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event(|event| {
            event["type"] == json!("group_message")
                && event["id"] == json!(editable)
                && event["content_kind"] == json!("text")
        })
        .await;
    a_events
        .wait_event(|event| {
            event["type"] == json!("group_delivery")
                && event["id"] == json!(editable)
                && event["state"] == json!("delivered")
        })
        .await;
    let edit = a
        .ok(json!({
            "op": "group_edit_message",
            "group": group,
            "target_author": alice_peer,
            "target_content_id": editable,
            "text": "editable group RPC revised",
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let refresh = b_events
        .wait_event(|event| event["type"] == json!("group_message_edited"))
        .await;
    assert_eq!(refresh["group"], json!(group));
    assert_eq!(refresh["sender"], json!(alice_peer));
    assert_eq!(refresh["target_content_id"], json!(editable));
    a_events
        .wait_event(|event| {
            event["type"] == json!("group_delivery")
                && event["id"] == json!(edit)
                && event["state"] == json!("delivered")
        })
        .await;
    for history in [
        a.ok(json!({ "op": "group_messages", "group": group }))
            .await,
        b.ok(json!({ "op": "group_messages", "group": group }))
            .await,
    ] {
        let message = history["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["id"] == json!(editable))
            .unwrap();
        assert_eq!(message["body"], json!("editable group RPC revised"));
        assert_eq!(message["edited"], json!(true));
        assert_eq!(message["edit_revision"], json!(1));
        assert_eq!(message["versions"].as_array().unwrap().len(), 2);
    }

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

    // C5 uses only stable ids across RPC. Votes are explicitly visible, a
    // member's last deterministic revision wins, and the creator's close
    // snapshot makes the final tally independent of delivery order.
    let chat_rows_before_poll = a
        .ok(json!({ "op": "group_messages", "group": group }))
        .await["messages"]
        .as_array()
        .unwrap()
        .len();
    let poll_id = a
        .ok(json!({
            "op": "group_poll_create",
            "group": group,
            "question": "Lunch? 👩🏽‍🚀",
            "options": ["Soup", "Salad"],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let poll_event = b_events
        .wait_event(|event| {
            event["type"] == json!("poll_updated") && event["poll_id"] == json!(poll_id)
        })
        .await;
    assert_eq!(poll_event["poll_author"], json!(alice_peer));
    let poll = b.ok(json!({ "op": "group_polls", "group": group })).await["polls"][0].clone();
    assert_eq!(poll["question"], json!("Lunch? 👩🏽‍🚀"));
    assert_eq!(poll["votes_visible"], json!(true));
    assert_eq!(poll["anonymous"], json!(false));
    assert_eq!(poll["close_policy"], json!("manual_creator_snapshot"));
    let soup = poll["options"][0]["id"].as_str().unwrap().to_owned();
    let salad = poll["options"][1]["id"].as_str().unwrap().to_owned();

    for option_id in [&soup, &salad] {
        b.ok(json!({
            "op": "group_poll_vote",
            "group": group,
            "poll_author": alice_peer,
            "poll_id": poll_id,
            "option_id": option_id,
        }))
        .await;
        a_events
            .wait_event(|event| {
                event["type"] == json!("poll_updated") && event["poll_id"] == json!(poll_id)
            })
            .await;
    }
    for poll in [
        wait_poll_revision(&mut a, &group, &poll_id, 2).await,
        wait_poll_revision(&mut b, &group, &poll_id, 2).await,
    ] {
        assert_eq!(poll["votes"].as_array().unwrap().len(), 1);
        assert_eq!(poll["votes"][0]["voter"], json!(bob_peer));
        assert_eq!(poll["votes"][0]["revision"], json!(2));
        assert_eq!(poll["votes"][0]["option_id"], json!(salad));
        assert_eq!(poll["options"][1]["votes"], json!(1));
    }

    let close_id = a
        .ok(json!({
            "op": "group_poll_close",
            "group": group,
            "poll_author": alice_peer,
            "poll_id": poll_id,
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event(|event| {
            event["type"] == json!("poll_updated") && event["poll_id"] == json!(poll_id)
        })
        .await;
    let final_poll = wait_poll_closed(&mut b, &group, &poll_id).await;
    assert_eq!(final_poll["closed"], json!(true));
    assert_eq!(final_poll["close_event_id"], json!(close_id));
    assert_eq!(final_poll["votes"][0]["option_id"], json!(salad));
    let err = b
        .call(json!({
            "op": "group_poll_vote",
            "group": group,
            "poll_author": alice_peer,
            "poll_id": poll_id,
            "option_id": soup,
        }))
        .await
        .unwrap_err();
    assert!(err.contains("closed"), "got: {err}");
    assert_eq!(
        a.ok(json!({ "op": "group_messages", "group": group }))
            .await["messages"]
            .as_array()
            .unwrap()
            .len(),
        chat_rows_before_poll,
        "poll events never become empty chat rows"
    );

    // C6 remains typed across RPC: capability-gated legacy upgrade, owner
    // role changes, generation-bound admin requests, signed moderation, and
    // ownership transfer all converge without exposing authority payloads.
    let legacy_authority = a
        .ok(json!({ "op": "group_authority", "group": group }))
        .await;
    assert_eq!(legacy_authority["signed"], json!(false));
    assert_eq!(legacy_authority["owner"], json!(alice_peer));
    assert_eq!(legacy_authority["my_role"], json!("owner"));
    let upgrade_generation = legacy_authority["generation"].as_u64().unwrap() + 1;
    a.ok(json!({ "op": "group_upgrade_authority", "group": group }))
        .await;
    let upgraded = wait_authority_generation(&mut b, &group, upgrade_generation).await;
    assert_eq!(upgraded["owner"], json!(alice_peer));
    assert_eq!(upgraded["my_role"], json!("member"));
    assert_eq!(upgraded["members"].as_array().unwrap().len(), 2);

    a.ok(json!({
        "op": "group_set_role",
        "group": group,
        "peer": bob_peer,
        "role": "admin",
    }))
    .await;
    let admin_generation = upgrade_generation + 1;
    let administered = wait_authority_generation(&mut b, &group, admin_generation).await;
    assert_eq!(administered["my_role"], json!("admin"));
    let err = b
        .call(json!({
            "op": "group_set_role",
            "group": group,
            "peer": alice_peer,
            "role": "member",
        }))
        .await
        .unwrap_err();
    assert!(err.contains("owner"), "got: {err}");

    let rename_request = b
        .ok(json!({
            "op": "group_rename",
            "group": group,
            "name": "authority trail crew",
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rename_generation = admin_generation + 1;
    let rename_result = b_events
        .wait_event(|event| {
            event["type"] == json!("group_admin_request_resolved")
                && event["request_id"] == json!(rename_request)
        })
        .await;
    assert_eq!(rename_result["accepted"], json!(true));
    assert_eq!(rename_result["generation"], json!(rename_generation));
    assert!(rename_result["state_id"].as_str().is_some());
    wait_authority_generation(&mut b, &group, rename_generation).await;
    let renamed_groups = b.ok(json!({ "op": "groups" })).await;
    assert!(renamed_groups["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|listed| {
            listed["id"] == json!(group) && listed["name"] == json!("authority trail crew")
        }));

    let moderated_poll = a
        .ok(json!({
            "op": "group_poll_create",
            "group": group,
            "question": "Close for weather?",
            "options": ["Keep open", "Close"],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    b_events
        .wait_event(|event| {
            event["type"] == json!("poll_updated") && event["poll_id"] == json!(moderated_poll)
        })
        .await;
    let moderation_request = b
        .ok(json!({
            "op": "group_poll_moderate_close",
            "group": group,
            "poll_author": alice_peer,
            "poll_id": moderated_poll,
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let moderation_generation = rename_generation + 1;
    let moderation_result = b_events
        .wait_event(|event| {
            event["type"] == json!("group_admin_request_resolved")
                && event["request_id"] == json!(moderation_request)
        })
        .await;
    assert_eq!(moderation_result["accepted"], json!(true));
    assert_eq!(
        moderation_result["generation"],
        json!(moderation_generation)
    );
    let moderated = wait_poll_closed(&mut b, &group, &moderated_poll).await;
    assert_eq!(moderated["moderated_by"], json!(alice_peer));
    assert_eq!(moderated["close_policy"], json!("signed_owner_snapshot"));

    a.ok(json!({
        "op": "group_transfer_owner",
        "group": group,
        "peer": bob_peer,
    }))
    .await;
    let bob_owner_generation = moderation_generation + 1;
    let bob_owner = wait_authority_generation(&mut b, &group, bob_owner_generation).await;
    assert_eq!(bob_owner["owner"], json!(bob_peer));
    assert_eq!(bob_owner["owner_epoch"], json!(1));
    assert_eq!(bob_owner["my_role"], json!("owner"));
    let err = b
        .call(json!({ "op": "group_leave", "group": group }))
        .await
        .unwrap_err();
    assert!(err.contains("owner"), "got: {err}");

    b.ok(json!({
        "op": "group_transfer_owner",
        "group": group,
        "peer": alice_peer,
    }))
    .await;
    let alice_owner_generation = bob_owner_generation + 1;
    let alice_owner = wait_authority_generation(&mut a, &group, alice_owner_generation).await;
    assert_eq!(alice_owner["owner"], json!(alice_peer));
    assert_eq!(alice_owner["owner_epoch"], json!(2));
    a.ok(json!({
        "op": "group_set_role",
        "group": group,
        "peer": bob_peer,
        "role": "member",
    }))
    .await;
    wait_authority_generation(&mut b, &group, alice_owner_generation + 1).await;

    // B10 stays local and structured through RPC: explicit random folder ids,
    // complete-set reorder, and exact typed targets without name inference.
    let queued_before_folders = a.ok(json!({ "op": "status" })).await["queued"].clone();
    let first_folder = a
        .ok(json!({
            "op": "folder_create",
            "name": folder_fixture["duplicate_name"],
        }))
        .await;
    let second_folder = a
        .ok(json!({
            "op": "folder_create",
            "name": folder_fixture["duplicate_name"],
        }))
        .await;
    let first_folder_id = first_folder["id"].as_str().unwrap().to_owned();
    let second_folder_id = second_folder["id"].as_str().unwrap().to_owned();
    assert_ne!(first_folder_id, second_folder_id);
    assert_eq!(
        first_folder["order"],
        folder_fixture["expected_initial_orders"][0]
    );
    assert_eq!(
        second_folder["order"],
        folder_fixture["expected_initial_orders"][1]
    );
    let reordered = a
        .ok(json!({
            "op": "folder_reorder",
            "folders": [second_folder_id, first_folder_id],
        }))
        .await;
    assert_eq!(reordered["folders"][0]["id"], json!(second_folder_id));
    assert_eq!(reordered["folders"][1]["id"], json!(first_folder_id));
    for target in [
        json!({ "type": "peer", "id": bob_peer }),
        json!({ "type": "group", "id": group }),
    ] {
        assert_eq!(
            a.ok(json!({ "op": "folder_move", "folder": first_folder_id, "target": target }))
                .await["changed"],
            json!(true)
        );
    }
    assert_eq!(
        a.ok(json!({
            "op": "folder_move",
            "folder": second_folder_id,
            "target": { "type": "note_to_self" },
        }))
        .await["changed"],
        json!(true)
    );
    assert_eq!(
        a.ok(json!({
            "op": "folder_move",
            "folder": second_folder_id,
            "target": { "type": "note_to_self" },
        }))
        .await["changed"],
        json!(false)
    );
    let membership = a
        .ok(json!({ "op": "folder_membership", "folder": first_folder_id }))
        .await;
    assert_eq!(
        membership["members"][0]["type"],
        folder_fixture["first_folder_target_kinds"][0]
    );
    assert_eq!(
        membership["members"][1]["type"],
        folder_fixture["first_folder_target_kinds"][1]
    );

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

    let composed = a
        .ok(json!({
            "op": "folder_conversations",
            "selection": { "type": "folder", "id": first_folder_id },
            "labels": [first_id],
            "mode": "any",
        }))
        .await;
    assert_eq!(
        composed["conversations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["type"].clone())
            .collect::<Vec<_>>(),
        folder_fixture["folder_then_any_label_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );
    assert_eq!(
        a.ok(json!({
            "op": "folder_unfile",
            "target": { "type": "peer", "id": bob_peer },
        }))
        .await["changed"],
        json!(true)
    );
    let unfiled = a
        .ok(json!({
            "op": "folder_conversations",
            "selection": { "type": "unfiled" },
            "labels": [],
            "mode": "any",
        }))
        .await;
    assert_eq!(
        unfiled["conversations"][0]["type"],
        folder_fixture["unfiled_after_move_target_kinds"][0]
    );
    assert_eq!(
        a.ok(json!({
            "op": "conversation_folder",
            "target": { "type": "note_to_self" },
        }))
        .await["folder"]["id"],
        json!(second_folder_id)
    );
    assert!(a
        .call(json!({
            "op": "folder_delete",
            "folder": first_folder_id,
            "confirm": false,
        }))
        .await
        .unwrap_err()
        .contains("confirmation"));
    assert_eq!(
        a.ok(json!({ "op": "folder_delete_preview", "folder": first_folder_id }))
            .await["assignments"],
        folder_fixture["expected_delete_assignment_count"]
    );
    assert_eq!(
        a.ok(json!({ "op": "folder_delete", "folder": first_folder_id, "confirm": true }))
            .await["assignments_deleted"],
        folder_fixture["expected_delete_assignment_count"]
    );
    let replacement = a
        .ok(json!({ "op": "folder_create", "name": folder_fixture["duplicate_name"] }))
        .await;
    assert_ne!(replacement["id"], json!(first_folder_id));
    assert!(a
        .ok(json!({ "op": "folder_membership", "folder": replacement["id"] }))
        .await["members"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(a.ok(json!({ "op": "folder_stale" })).await["stale"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        a.ok(json!({ "op": "status" })).await["queued"],
        queued_before_folders
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

    // B11 remains private and local through RPC. Exact typed ids append
    // idempotently, reorder only as the complete durable set, and form the
    // leading block after folder and label eligibility have been applied.
    let queued_before_pins = a.ok(json!({ "op": "status" })).await["queued"].clone();
    let pin_targets = [
        json!({ "type": "peer", "id": bob_peer }),
        json!({ "type": "group", "id": group }),
        json!({ "type": "note_to_self" }),
    ];
    for (index, target) in pin_targets.iter().enumerate() {
        let pinned = a.ok(json!({ "op": "pin", "target": target })).await;
        assert_eq!(pinned["changed"], json!(true));
        assert_eq!(
            pinned["pin"]["order"],
            pin_fixture["expected_append_orders"][index]
        );
    }
    assert_eq!(
        a.ok(json!({ "op": "pin", "target": pin_targets[0] })).await["changed"],
        json!(false)
    );
    let pins = a.ok(json!({ "op": "pins" })).await;
    assert_eq!(
        pins["pins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pin| pin["target"]["type"].clone())
            .collect::<Vec<_>>(),
        pin_fixture["initial_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );
    assert_eq!(
        a.ok(json!({ "op": "pin_state", "target": pin_targets[1] }))
            .await["pin"]["active"],
        json!(true)
    );
    let reordered_targets = [
        pin_targets[2].clone(),
        pin_targets[1].clone(),
        pin_targets[0].clone(),
    ];
    let reordered = a
        .ok(json!({ "op": "pin_reorder", "targets": reordered_targets }))
        .await;
    assert_eq!(
        reordered["pins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pin| pin["target"]["type"].clone())
            .collect::<Vec<_>>(),
        pin_fixture["reordered_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );
    assert!(a
        .call(json!({ "op": "pin_reorder", "targets": [pin_targets[0]] }))
        .await
        .unwrap_err()
        .contains("complete pin order"));
    assert!(a
        .call(json!({
            "op": "pin_stale_cleanup",
            "target": pin_targets[1],
        }))
        .await
        .unwrap_err()
        .contains("active"));
    let composed = a
        .ok(json!({
            "op": "pin_conversations",
            "selection": { "type": "all" },
            "labels": [],
            "mode": "any",
        }))
        .await;
    assert_eq!(
        composed["conversations"]
            .as_array()
            .unwrap()
            .iter()
            .take(3)
            .map(|conversation| conversation["target"]["type"].clone())
            .collect::<Vec<_>>(),
        pin_fixture["composed_pinned_target_kinds"]
            .as_array()
            .unwrap()
            .clone()
    );
    assert!(composed["conversations"]
        .as_array()
        .unwrap()
        .iter()
        .take(3)
        .all(|conversation| conversation["pinned"] == json!(true)));
    assert!(a.ok(json!({ "op": "pin_stale" })).await["stale"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        a.ok(json!({ "op": "unpin", "target": pin_targets[0] }))
            .await["changed"],
        json!(true)
    );
    assert_eq!(
        a.ok(json!({ "op": "unpin", "target": pin_targets[0] }))
            .await["changed"],
        json!(false)
    );
    assert_eq!(
        a.ok(json!({ "op": "status" })).await["queued"],
        queued_before_pins
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
    wait_group_presence(&mut b, &group, false).await;
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
    wait_group_presence(&mut b, &leave_group, true).await;
    assert_eq!(
        b.ok(json!({ "op": "group_leave", "group": leave_group }))
            .await,
        json!({})
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
