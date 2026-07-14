//! Desktop-shell acceptance: two app backends driven through exactly the
//! layer the Tauri commands wrap ([`Session`]) — pairing via the bundle
//! *hex* a user pastes or scans, honest delivery states arriving as the
//! `node-event` payloads the webview would receive, verification,
//! settings persistence, and the backup → mnemonic → restore flow.
//!
//! No webview is involved: `commands.rs` is one-line wrappers over these
//! same methods, so this pins the whole behavior a UI click reaches.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use komms_desktop::session::{hex_decode, NetworkSettings, Session, UiEvent, UiHint};
use kult_ffi::KdfChoice;

/// Collects `node-event` payloads exactly as the webview would.
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<UiEvent>>>);

impl Events {
    fn sink(&self) -> komms_desktop::session::EventSink {
        let events = self.0.clone();
        Box::new(move |event| events.lock().unwrap().push(event))
    }

    fn wait(&self, what: &str, pred: impl Fn(&UiEvent) -> bool) -> UiEvent {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(hit) = self.0.lock().unwrap().iter().find(|e| pred(e)) {
                return hit.clone();
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Hermetic settings: loopback QUIC only, no mDNS — hints are explicit.
fn test_settings() -> NetworkSettings {
    NetworkSettings {
        listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
        mdns: false,
        ..NetworkSettings::default()
    }
}

fn open(dir: &Path, name: &str, events: &Events) -> Session {
    // Mirror the unlock command: persist settings, then boot.
    let data_dir = dir.join(name);
    let settings = test_settings();
    settings.save(&data_dir).expect("settings save");
    Session::open(
        &data_dir,
        "test-passphrase".to_owned(),
        &settings,
        KdfChoice::Mobile,
        events.sink(),
    )
    .expect("session opens")
}

/// Poll status until a listen address is bound.
fn listen_addr(session: &Session) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = session.status().expect("status");
        if let Some(addr) = status.listen.into_iter().next() {
            return addr;
        }
        assert!(Instant::now() < deadline, "no listen address within 5s");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn multiaddr_hint(addr: String) -> Vec<UiHint> {
    vec![UiHint {
        kind: "multiaddr".to_owned(),
        value: addr,
    }]
}

#[test]
fn two_desktops_pair_by_bundle_hex_and_message() {
    let dir = tempfile::tempdir().unwrap();
    let a_ev = Events::default();
    let b_ev = Events::default();
    let alice = open(dir.path(), "alice", &a_ev);
    let bob = open(dir.path(), "bob", &b_ev);

    // The status bar's first snapshot is honest: nothing queued, nothing
    // bridged, no contacts, and a kult address to show.
    let status = alice.status().unwrap();
    assert!(status.address.starts_with("kk1"));
    assert_eq!((status.queued, status.transit, status.contacts), (0, 0, 0));
    assert_eq!(status.nat, "unknown");

    // Pairing exactly as the UI does it: each side renders its bundle as
    // hex + QR (the QR carries the same hex), the other side pastes it.
    let a_bundle = alice.my_bundle().unwrap();
    let b_bundle = bob.my_bundle().unwrap();
    assert!(a_bundle.qr_svg.contains("<svg"));
    assert!(hex_decode(&a_bundle.hex).is_some());
    // Scanned input arrives uppercase/wrapped — decoding must not care.
    let scanned = b_bundle.hex.to_uppercase();

    let a_addr = listen_addr(&alice);
    let b_addr = listen_addr(&bob);
    let bob_peer = alice
        .add_contact("bob".to_owned(), &scanned, &multiaddr_hint(b_addr))
        .unwrap();
    let alice_peer = bob
        .add_contact("alice".to_owned(), &a_bundle.hex, &multiaddr_hint(a_addr))
        .unwrap();

    // The desktop command/session surface exposes the distinct scheduled
    // state and edit/cancel lifecycle without entering the delivery queue.
    let future = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let scheduled_id = alice
        .schedule(bob_peer.clone(), "first draft".to_owned(), future)
        .unwrap();
    a_ev.wait(
        "scheduled update",
        |event| matches!(event, UiEvent::ScheduledMessageUpdated { id } if *id == scheduled_id),
    );
    assert_eq!(alice.status().unwrap().scheduled, 1);
    assert_eq!(alice.status().unwrap().queued, 0);
    let scheduled = alice.scheduled_messages().unwrap();
    assert_eq!(scheduled[0].state, "scheduled");
    assert_eq!(scheduled[0].conversation, "peer");
    alice
        .edit_scheduled(scheduled_id.clone(), "final draft".to_owned(), future + 60)
        .unwrap();
    assert_eq!(alice.scheduled_messages().unwrap()[0].body, "final draft");
    alice.cancel_scheduled(scheduled_id).unwrap();
    assert!(alice.scheduled_messages().unwrap().is_empty());

    // Send → the webview's event stream walks the honest ladder.
    let msg_id = alice
        .send(bob_peer.clone(), "hello from the desktop".to_owned())
        .unwrap();
    let got = b_ev.wait("bob's message event", |e| {
        matches!(e, UiEvent::MessageReceived { .. })
    });
    match got {
        UiEvent::MessageReceived { peer, body, .. } => {
            assert_eq!(peer, alice_peer);
            assert_eq!(body, "hello from the desktop");
        }
        other => panic!("wrong event: {other:?}"),
    }
    a_ev.wait(
        "alice's delivered event",
        |e| matches!(e, UiEvent::DeliveryUpdated { id, state: "delivered" } if *id == msg_id),
    );

    // History rows carry what the bubbles render: direction, state, body.
    let history = alice.messages(bob_peer.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].outbound);
    assert_eq!(history[0].state, "delivered");
    let inbox = bob.messages(alice_peer.clone()).unwrap();
    assert_eq!(inbox.len(), 1);
    assert!(!inbox[0].outbound);
    assert_eq!(inbox[0].state, "received");

    // The verify screen: identical digits and QR on both ends, and the
    // "mark verified" button reflects into the contact list badge.
    let sn_a = alice.safety_number(bob_peer.clone()).unwrap();
    let sn_b = bob.safety_number(alice_peer.clone()).unwrap();
    assert_eq!(sn_a.digits, sn_b.digits);
    assert_eq!(sn_a.qr_svg, sn_b.qr_svg);
    alice.mark_verified(bob_peer.clone()).unwrap();
    let contacts = alice.contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "bob");
    assert!(contacts[0].verified);

    // The hints editor accepts a replacement and rejects garbage honestly.
    alice
        .set_hints(
            bob_peer.clone(),
            &[UiHint {
                kind: "mesh".to_owned(),
                value: "broadcast".to_owned(),
            }],
        )
        .unwrap();
    let err = alice
        .set_hints(
            bob_peer.clone(),
            &[UiHint {
                kind: "mesh".to_owned(),
                value: "over-the-rainbow".to_owned(),
            }],
        )
        .unwrap_err();
    assert!(err.contains("node number"), "got: {err}");

    // Errors the composer surfaces are the node's own words.
    let err = alice.send("00".repeat(32), "x".to_owned()).unwrap_err();
    assert!(err.contains("not a stored contact"), "got: {err}");
    let err = alice
        .add_contact("mallory".to_owned(), "not hex!", &[])
        .unwrap_err();
    assert!(err.contains("hex"), "got: {err}");

    alice.stop();
    bob.stop();
}

#[test]
fn desktop_group_ux_create_roster_message_and_partial_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let a_ev = Events::default();
    let b_ev = Events::default();
    // The embedded FFI runtime admits two live nodes per process. Capture a
    // real third identity first, then keep Carol offline so delivery can be
    // proven independently per member.
    let carol = open(dir.path(), "group-carol", &Events::default());
    let carol_bundle = carol.my_bundle().unwrap();
    carol.stop();
    let alice = open(dir.path(), "group-alice", &a_ev);
    let bob = open(dir.path(), "group-bob", &b_ev);

    let alice_addr = listen_addr(&alice);
    let bob_addr = listen_addr(&bob);
    let alice_bundle = alice.my_bundle().unwrap();
    let bob_bundle = bob.my_bundle().unwrap();
    let bob_peer = alice
        .add_contact("Bob".to_owned(), &bob_bundle.hex, &multiaddr_hint(bob_addr))
        .unwrap();
    let carol_peer = alice
        .add_contact(
            "Carol".to_owned(),
            &carol_bundle.hex,
            &multiaddr_hint("/ip4/127.0.0.1/udp/9/quic-v1".to_owned()),
        )
        .unwrap();
    let alice_at_bob = bob
        .add_contact(
            "Alice".to_owned(),
            &alice_bundle.hex,
            &multiaddr_hint(alice_addr.clone()),
        )
        .unwrap();
    // The new-group dialog starts with one selected stored contact; the
    // creator then adds another from the members screen.
    let group = alice
        .create_group("Trail crew".to_owned(), vec![bob_peer.clone()])
        .unwrap();
    b_ev.wait(
        "Bob's group invite",
        |event| matches!(event, UiEvent::GroupUpdated { group: id } if *id == group),
    );
    let listed = alice.groups().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Trail crew");
    assert_eq!(listed[0].members.len(), 2);

    alice
        .add_group_member(group.clone(), carol_peer.clone())
        .unwrap();
    let listed = alice.groups().unwrap();
    assert_eq!(listed[0].members.len(), 3);

    // Only the creator gets roster controls; the shell surfaces the core's
    // explicit error to a non-creator instead of pretending it succeeded.
    let err = bob
        .add_group_member(group.clone(), carol_peer.clone())
        .unwrap_err();
    assert!(err.contains("creator"), "got: {err}");

    // Group conversation history is identical across the shell boundary.
    // Bob receives while offline Carol remains queued/sent: outbound rows
    // expose a distinct truthful state for each member rather than one
    // misleading group-level checkmark.
    let first = alice
        .send_group(group.clone(), "Meet at the north trailhead".to_owned())
        .unwrap();
    b_ev.wait("Bob's group message", |event| {
        matches!(event, UiEvent::GroupMessageReceived { body, .. }
            if body == "Meet at the north trailhead")
    });
    a_ev.wait("Bob's group copy delivered", |event| {
        matches!(event, UiEvent::GroupDeliveryUpdated { id, peer, state: "delivered" }
            if *id == first && *peer == bob_peer)
    });
    let history = alice.group_messages(group.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert!(history[0].outbound);
    assert_eq!(history[0].deliveries.len(), 2);
    assert_eq!(
        history[0]
            .deliveries
            .iter()
            .find(|delivery| delivery.peer == bob_peer)
            .unwrap()
            .state,
        "delivered"
    );
    assert_ne!(
        history[0]
            .deliveries
            .iter()
            .find(|delivery| delivery.peer == carol_peer)
            .unwrap()
            .state,
        "delivered"
    );
    let bob_history = bob.group_messages(group.clone()).unwrap();
    assert_eq!(bob_history[0].sender, alice_at_bob);
    assert!(!bob_history[0].outbound);
    assert!(bob_history[0].deliveries.is_empty());

    // Creator removal rotates the roster immediately. A member can leave;
    // their live group disappears locally and the creator converges too.
    alice
        .remove_group_member(group.clone(), carol_peer)
        .unwrap();
    assert_eq!(alice.groups().unwrap()[0].members.len(), 2);
    bob.leave_group(group.clone()).unwrap();
    assert!(bob.groups().unwrap().is_empty());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if alice.groups().unwrap()[0].members.len() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "creator did not apply Bob's leave"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    alice.stop();
    bob.stop();
}

#[test]
fn note_to_self_is_local_sealed_and_durable() {
    let dir = tempfile::tempdir().unwrap();
    let events = Events::default();
    let session = open(dir.path(), "notes", &events);

    assert_eq!(session.note_to_self_id(), "note_to_self");
    let id = session
        .send_note_to_self("remember the glacier map".to_owned())
        .unwrap();
    let added = events.wait("local note event", |event| {
        matches!(event, UiEvent::NoteToSelfMessageAdded { id: event_id, .. } if *event_id == id)
    });
    match added {
        UiEvent::NoteToSelfMessageAdded {
            conversation, body, ..
        } => {
            assert_eq!(conversation, "note_to_self");
            assert_eq!(body, "remember the glacier map");
        }
        other => panic!("wrong event: {other:?}"),
    }
    let status = session.status().unwrap();
    assert_eq!((status.queued, status.contacts), (0, 0));
    assert_eq!(
        session.note_to_self_messages().unwrap()[0].body,
        "remember the glacier map"
    );
    session.stop();

    let session = open(dir.path(), "notes", &Events::default());
    let history = session.note_to_self_messages().unwrap();
    assert_eq!(history[0].conversation, "note_to_self");
    assert_eq!(history[0].body, "remember the glacier map");
    assert_eq!(session.status().unwrap().queued, 0);
    session.stop();
}

#[test]
fn backup_mnemonic_restore_flow() {
    let dir = tempfile::tempdir().unwrap();
    let a_ev = Events::default();
    let b_ev = Events::default();
    let alice = open(dir.path(), "alice", &a_ev);
    let bob = open(dir.path(), "bob", &b_ev);

    let a_addr = listen_addr(&alice);
    let b_addr = listen_addr(&bob);
    let bob_peer = alice
        .add_contact(
            "bob".to_owned(),
            &bob.my_bundle().unwrap().hex,
            &multiaddr_hint(b_addr),
        )
        .unwrap();
    let alice_peer = bob
        .add_contact(
            "alice".to_owned(),
            &alice.my_bundle().unwrap().hex,
            &multiaddr_hint(a_addr),
        )
        .unwrap();
    let msg_id = alice
        .send(bob_peer.clone(), "before the backup".to_owned())
        .unwrap();
    a_ev.wait(
        "delivered",
        |e| matches!(e, UiEvent::DeliveryUpdated { id, state: "delivered" } if *id == msg_id),
    );
    alice
        .send_note_to_self("packed in the backup".to_owned())
        .unwrap();

    // The backup dialog: mnemonic comes back exactly once, 24 words; an
    // existing file is refused, not clobbered.
    let backup = dir.path().join("komms-backup.kkr").display().to_string();
    let mnemonic = alice.export_backup(backup.clone()).unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
    assert!(alice.export_backup(backup.clone()).is_err());

    let address_before = alice.address();
    alice.stop();

    // The gate's restore tab: wrong mnemonic refused at startup…
    let bad = Session::restore(
        &dir.path().join("alice-wrong"),
        "new-pass".to_owned(),
        backup.clone(),
        "abandon ".repeat(23) + "art",
        &test_settings(),
        KdfChoice::Mobile,
        Events::default().sink(),
    );
    assert!(bad.is_err());

    // …right mnemonic restores identity, contacts, and history.
    let a_ev = Events::default();
    let alice = Session::restore(
        &dir.path().join("alice-new"),
        "new-pass".to_owned(),
        backup,
        mnemonic,
        &test_settings(),
        KdfChoice::Mobile,
        a_ev.sink(),
    )
    .expect("restore succeeds");
    assert_eq!(alice.address(), address_before);
    assert_eq!(alice.contacts().unwrap()[0].name, "bob");
    let history = alice.messages(bob_peer.clone()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "before the backup");
    assert_eq!(
        alice.note_to_self_messages().unwrap()[0].body,
        "packed in the backup"
    );

    // The restored node re-handshakes automatically; after Bob learns the
    // new address, messaging resumes in both directions.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let rekeys = b_ev
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, UiEvent::SessionEstablished { peer } if *peer == alice_peer))
            .count();
        if rekeys >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "timed out waiting for re-key");
        std::thread::sleep(Duration::from_millis(50));
    }
    let a_addr_new = listen_addr(&alice);
    bob.set_hints(alice_peer.clone(), &multiaddr_hint(a_addr_new))
        .unwrap();
    bob.send(alice_peer, "glad you're back".to_owned()).unwrap();
    let got = a_ev.wait("alice's message event", |e| {
        matches!(e, UiEvent::MessageReceived { .. })
    });
    match got {
        UiEvent::MessageReceived { body, .. } => assert_eq!(body, "glad you're back"),
        other => panic!("wrong event: {other:?}"),
    }
    let reply = alice
        .send(bob_peer, "new machine, same me".to_owned())
        .unwrap();
    a_ev.wait(
        "reply delivered",
        |e| matches!(e, UiEvent::DeliveryUpdated { id, state: "delivered" } if *id == reply),
    );

    alice.stop();
    bob.stop();
}

#[test]
fn unlock_refuses_wrong_passphrase_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let events = Events::default();
    let alice = open(dir.path(), "alice", &events);
    let address = alice.address();
    alice.stop();

    // Wrong passphrase at the gate: an honest startup error.
    let err = Session::open(
        &dir.path().join("alice"),
        "wrong".to_owned(),
        &test_settings(),
        KdfChoice::Mobile,
        Events::default().sink(),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(err.contains("startup"), "got: {err}");

    // Right passphrase: same identity. Settings persisted alongside.
    let alice = open(dir.path(), "alice", &Events::default());
    assert_eq!(alice.address(), address);
    let saved = NetworkSettings::load(&dir.path().join("alice")).unwrap();
    assert!(!saved.mdns);
    alice.stop();
}
