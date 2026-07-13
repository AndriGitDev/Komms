//! M5 first-slice acceptance for the FFI layer: two nodes driven
//! **exclusively** through the public `kult-ffi` surface — pairing, honest
//! delivery states, the event listener, history, safety numbers, restart
//! persistence, and honest errors. No test reaches into Rust internals;
//! everything goes through the API a Kotlin/Swift shell would use. Plain
//! `#[test]`s on purpose: the FFI is blocking, exactly like a foreign
//! caller.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kult_ffi::{
    default_config, Config, DeliveryState, Event, EventListener, Hint, KdfChoice, KultNode,
};

/// Records every event; tests poll it like an app's view-model would.
#[derive(Clone, Default)]
struct Recorder {
    events: Arc<Mutex<Vec<Event>>>,
}

impl EventListener for Recorder {
    fn on_event(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

impl Recorder {
    /// Wait until an event matching `pred` has arrived.
    fn wait(&self, what: &str, pred: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(hit) = self.events.lock().unwrap().iter().find(|e| pred(e)) {
                return hit.clone();
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until `n` matching events have arrived in total.
    fn wait_count(&self, what: &str, pred: impl Fn(&Event) -> bool, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| pred(event))
                .count()
                >= n
            {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn test_config(dir: &Path, name: &str) -> Config {
    let mut cfg = default_config(
        dir.join(name).display().to_string(),
        "test-passphrase".to_owned(),
    );
    // The mobile Argon2id profile keeps store creation fast enough for CI;
    // localhost QUIC only, no mDNS — hints are explicit, the test hermetic.
    cfg.kdf = KdfChoice::Mobile;
    cfg.listen = vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()];
    cfg.mdns = false;
    cfg.tick_ms = 100;
    cfg
}

/// Poll `status` until at least one listen address is bound.
fn listen_addr(node: &KultNode) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = node.status().expect("status");
        if let Some(addr) = status.listen.into_iter().next() {
            return addr;
        }
        assert!(Instant::now() < deadline, "no listen address within 5s");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn two_nodes_message_via_ffi_only() {
    let dir = tempfile::tempdir().unwrap();
    let a_rec = Recorder::default();
    let b_rec = Recorder::default();
    let alice = KultNode::start(test_config(dir.path(), "alice"), Box::new(a_rec.clone()))
        .expect("alice starts");
    let bob = KultNode::start(test_config(dir.path(), "bob"), Box::new(b_rec.clone()))
        .expect("bob starts");

    // Status is honest from the start: fresh nodes, empty queues.
    let status = alice.status().unwrap();
    assert_eq!(status.queued, 0);
    assert_eq!(status.contacts, 0);
    assert!(alice.address().starts_with("kk1"));
    assert_eq!(status.peer, alice.peer());

    let a_addr = listen_addr(&alice);
    let b_addr = listen_addr(&bob);

    // Out-of-band pairing: each side exports a bundle (bytes, as a QR code
    // would carry), the other imports it with a multiaddr hint.
    let a_bundle = alice.handshake_bundle().unwrap();
    let b_bundle = bob.handshake_bundle().unwrap();
    let bob_peer = alice
        .add_contact(
            "bob".to_owned(),
            b_bundle,
            vec![Hint::Multiaddr { addr: b_addr }],
        )
        .unwrap();
    let alice_peer = bob
        .add_contact(
            "alice".to_owned(),
            a_bundle,
            vec![Hint::Multiaddr { addr: a_addr }],
        )
        .unwrap();
    assert_eq!(bob_peer, bob.peer());
    assert_eq!(alice_peer, alice.peer());

    // Send; the listener walks the honest ladder to `delivered` (an
    // end-to-end encrypted receipt, not a transport ack).
    let msg_id = alice
        .send(bob_peer.clone(), "hello through the bindings".to_owned())
        .unwrap();
    let received = b_rec.wait("bob's message event", |e| {
        matches!(e, Event::MessageReceived { .. })
    });
    match received {
        Event::MessageReceived { peer, body, .. } => {
            assert_eq!(peer, alice_peer);
            assert_eq!(body, "hello through the bindings");
        }
        other => panic!("wrong event: {other:?}"),
    }
    a_rec.wait("alice's delivered event", |e| {
        matches!(e, Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == msg_id)
    });

    // History and state agree with the events.
    let history = alice.messages_with(bob_peer.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, msg_id);
    assert_eq!(history[0].state, DeliveryState::Delivered);
    assert_eq!(history[0].body, "hello through the bindings");

    // Bob replies over the established session; Alice sees it.
    bob.send(alice_peer.clone(), "loud and clear".to_owned())
        .unwrap();
    let reply = a_rec.wait("alice's message event", |e| {
        matches!(e, Event::MessageReceived { .. })
    });
    match reply {
        Event::MessageReceived { body, .. } => assert_eq!(body, "loud and clear"),
        other => panic!("wrong event: {other:?}"),
    }

    // Safety numbers match on both ends, and verification round-trips.
    let sn_a = alice.safety_number(bob_peer.clone()).unwrap();
    let sn_b = bob.safety_number(alice_peer.clone()).unwrap();
    assert_eq!(sn_a.digits, sn_b.digits);
    assert_eq!(sn_a.qr, sn_b.qr);
    assert_eq!(sn_a.display.split(' ').count(), 12);
    alice.mark_verified(bob_peer.clone()).unwrap();
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "bob");
    assert!(contacts[0].verified);

    // Errors are honest, not fake successes.
    let err = alice
        .send("00".repeat(32), "x".to_owned())
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a stored contact"), "got: {err}");
    let err = alice
        .send("zz".to_owned(), "x".to_owned())
        .unwrap_err()
        .to_string();
    assert!(err.contains("hex"), "got: {err}");

    // Stop is idempotent, and a stopped handle refuses honestly.
    alice.stop();
    alice.stop();
    let err = alice.contacts().unwrap_err().to_string();
    assert!(err.contains("stopped"), "got: {err}");
    bob.stop();
}

#[test]
fn backup_and_restore_via_ffi_only() {
    let dir = tempfile::tempdir().unwrap();
    let a_rec = Recorder::default();
    let b_rec = Recorder::default();
    let alice = KultNode::start(test_config(dir.path(), "alice"), Box::new(a_rec.clone()))
        .expect("alice starts");
    let bob = KultNode::start(test_config(dir.path(), "bob"), Box::new(b_rec.clone()))
        .expect("bob starts");

    // Pair and converse, so the backup carries a contact, history, and a
    // live session to reset.
    let a_addr = listen_addr(&alice);
    let b_addr = listen_addr(&bob);
    let a_bundle = alice.handshake_bundle().unwrap();
    let b_bundle = bob.handshake_bundle().unwrap();
    let bob_peer = alice
        .add_contact(
            "bob".to_owned(),
            b_bundle,
            vec![Hint::Multiaddr { addr: b_addr }],
        )
        .unwrap();
    let alice_peer = bob
        .add_contact(
            "alice".to_owned(),
            a_bundle,
            vec![Hint::Multiaddr { addr: a_addr }],
        )
        .unwrap();
    let msg_id = alice
        .send(bob_peer.clone(), "before the backup".to_owned())
        .unwrap();
    a_rec.wait("alice's delivered event", |e| {
        matches!(e, Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == msg_id)
    });

    // Backup through the FFI: file appears, mnemonic comes back once, and
    // an existing file is never clobbered.
    let backup_path = dir.path().join("alice.kkr").display().to_string();
    let mnemonic = alice.export_backup(backup_path.clone()).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    let err = alice
        .export_backup(backup_path.clone())
        .unwrap_err()
        .to_string();
    assert!(err.contains("backup write"), "got: {err}");

    // The device is lost.
    let address_before = alice.address();
    alice.stop();

    // A wrong mnemonic is refused at startup — never a half-running node.
    let wrong = "abandon ".repeat(23) + "art";
    assert!(KultNode::restore(
        test_config(dir.path(), "alice-wrong"),
        backup_path.clone(),
        wrong,
        Box::new(Recorder::default()),
    )
    .is_err());

    // Restore onto a "new device" (new data dir, new passphrase).
    let a_rec = Recorder::default();
    let mut cfg = test_config(dir.path(), "alice-new");
    cfg.passphrase = "new-passphrase".to_owned();
    let alice = KultNode::restore(cfg, backup_path, mnemonic, Box::new(a_rec.clone()))
        .expect("alice restores");

    // Identity, contacts, and history came back.
    assert_eq!(alice.address(), address_before);
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "bob");
    let history = alice.messages_with(bob_peer.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "before the backup");

    // The tick loop re-handshakes Bob: a *second* session establishment
    // for the same contact (the first was the original pairing).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let rekeys = b_rec
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Event::SessionEstablished { peer } if *peer == alice_peer))
            .count();
        if rekeys >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "timed out waiting for re-key");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Bob learns the new device's address (out-of-band here), then traffic
    // flows in both directions on the fresh ratchet.
    let a_addr_new = listen_addr(&alice);
    bob.set_hints(
        alice_peer.clone(),
        vec![Hint::Multiaddr { addr: a_addr_new }],
    )
    .unwrap();
    bob.send(alice_peer, "glad you're back".to_owned()).unwrap();
    let got = a_rec.wait("alice's message event", |e| {
        matches!(e, Event::MessageReceived { .. })
    });
    match got {
        Event::MessageReceived { body, .. } => assert_eq!(body, "glad you're back"),
        other => panic!("wrong event: {other:?}"),
    }
    let reply_id = alice
        .send(bob_peer, "new device, same me".to_owned())
        .unwrap();
    a_rec.wait("alice's delivered event", |e| {
        matches!(e, Event::DeliveryUpdated { id, state: DeliveryState::Delivered } if *id == reply_id)
    });

    alice.stop();
    bob.stop();
}

#[test]
fn restart_persists_history_and_refuses_wrong_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let a_rec = Recorder::default();
    let b_rec = Recorder::default();
    let alice = KultNode::start(test_config(dir.path(), "alice"), Box::new(a_rec.clone()))
        .expect("alice starts");
    let bob = KultNode::start(test_config(dir.path(), "bob"), Box::new(b_rec.clone()))
        .expect("bob starts");

    let b_addr = listen_addr(&bob);
    let b_bundle = bob.handshake_bundle().unwrap();
    let bob_peer = alice
        .add_contact(
            "bob".to_owned(),
            b_bundle,
            vec![Hint::Multiaddr { addr: b_addr }],
        )
        .unwrap();
    alice
        .send(bob_peer.clone(), "before restart".to_owned())
        .unwrap();
    b_rec.wait("bob's message event", |e| {
        matches!(e, Event::MessageReceived { .. })
    });

    let address_before = alice.address();
    alice.stop();

    // Wrong passphrase: refused, honestly.
    let mut bad = test_config(dir.path(), "alice");
    bad.passphrase = "wrong".to_owned();
    assert!(KultNode::start(bad, Box::new(Recorder::default())).is_err());

    // Right passphrase: same identity, history intact.
    let alice = KultNode::start(
        test_config(dir.path(), "alice"),
        Box::new(Recorder::default()),
    )
    .expect("alice restarts");
    assert_eq!(alice.address(), address_before);
    let history = alice.messages_with(bob_peer).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "before restart");
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts[0].name, "bob");

    alice.stop();
    bob.stop();
}

/// F1 group front-door acceptance through only the public UniFFI-shaped API.
#[test]
fn groups_via_ffi_only() {
    let dir = tempfile::tempdir().unwrap();
    let a_rec = Recorder::default();
    let b_rec = Recorder::default();
    let alice = KultNode::start(
        test_config(dir.path(), "group-alice"),
        Box::new(a_rec.clone()),
    )
    .expect("alice starts");
    let bob = KultNode::start(
        test_config(dir.path(), "group-bob"),
        Box::new(b_rec.clone()),
    )
    .expect("bob starts");

    let a_addr = listen_addr(&alice);
    let b_addr = listen_addr(&bob);
    let a_bundle = alice.handshake_bundle().unwrap();
    let b_bundle = bob.handshake_bundle().unwrap();
    let bob_peer = alice
        .add_contact(
            "bob".to_owned(),
            b_bundle,
            vec![Hint::Multiaddr { addr: b_addr }],
        )
        .unwrap();
    let alice_peer = bob
        .add_contact(
            "alice".to_owned(),
            a_bundle.clone(),
            vec![Hint::Multiaddr {
                addr: a_addr.clone(),
            }],
        )
        .unwrap();
    let group = alice
        .create_group("trail crew".to_owned(), Vec::new())
        .unwrap();
    alice
        .add_group_member(group.clone(), bob_peer.clone())
        .unwrap();
    b_rec.wait(
        "bob's group invite",
        |event| matches!(event, Event::GroupUpdated { group: id } if *id == group),
    );
    let groups = bob.groups().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, group);
    assert_eq!(groups[0].name, "trail crew");
    assert_eq!(groups[0].creator, alice_peer);
    assert_eq!(groups[0].members.len(), 2);

    // Creator-only and id-validation failures remain explicit.
    let err = bob
        .add_group_member(group.clone(), alice_peer.clone())
        .unwrap_err()
        .to_string();
    assert!(err.contains("creator"), "got: {err}");
    let err = alice
        .send_group("zz".to_owned(), "x".to_owned())
        .unwrap_err()
        .to_string();
    assert!(err.contains("group") && err.contains("hex"), "got: {err}");
    let err = alice
        .send_group("00".repeat(32), "x".to_owned())
        .unwrap_err()
        .to_string();
    assert!(err.contains("no stored group"), "got: {err}");

    let message_id = alice
        .send_group(group.clone(), "meet at the pass".to_owned())
        .unwrap();
    b_rec.wait("bob's group message", |event| {
        matches!(event, Event::GroupMessageReceived {
            group: id,
            sender,
            body,
            ..
        } if *id == group && *sender == alice_peer && body == "meet at the pass")
    });
    a_rec.wait("bob's delivered copy", |event| {
        matches!(event, Event::GroupDeliveryUpdated {
            id,
            peer,
            state: DeliveryState::Delivered,
        } if *id == message_id && *peer == bob_peer)
    });
    let history = alice.group_messages(group.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "meet at the pass");
    assert_eq!(history[0].deliveries.len(), 1);
    assert!(history
        .iter()
        .flat_map(|message| &message.deliveries)
        .all(|delivery| delivery.state == DeliveryState::Delivered));

    alice
        .remove_group_member(group.clone(), bob_peer.clone())
        .unwrap();
    b_rec.wait_count(
        "bob's removal",
        |event| matches!(event, Event::GroupUpdated { group: id } if *id == group),
        2,
    );
    assert!(bob.groups().unwrap().is_empty());

    let leave_group = alice
        .create_group("short trip".to_owned(), vec![bob_peer])
        .unwrap();
    b_rec.wait_count(
        "bob's second group invite",
        |event| matches!(event, Event::GroupUpdated { .. }),
        3,
    );
    bob.leave_group(leave_group).unwrap();

    alice.stop();
    bob.stop();
}
