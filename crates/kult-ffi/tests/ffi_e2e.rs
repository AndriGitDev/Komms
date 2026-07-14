//! M5 first-slice acceptance for the FFI layer: two nodes driven
//! **exclusively** through the public `kult-ffi` surface — pairing, honest
//! delivery states, the event listener, history, safety numbers, restart
//! persistence, and honest errors. No test reaches into Rust internals;
//! everything goes through the API a Kotlin/Swift shell would use. Plain
//! `#[test]`s on purpose: the FFI is blocking, exactly like a foreign
//! caller.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kult_ffi::{
    default_config, edit_image, probe_edited_image, probe_recorded_audio, AttachmentDirection,
    AttachmentState, CarrierCapability, Config, ContentKind, DeliveryState, Event, EventListener,
    Hint, ImageCrop, ImageEditRecipe, ImageEditRegion, ImageEditRegionKind, KdfChoice, KultNode,
    ScheduledConversation,
};

fn edited_image(directory: &Path, prefix: &str) -> (PathBuf, Vec<u8>) {
    use image::{ImageBuffer, ImageEncoder, Rgba};

    let source = directory.join(format!("{prefix}-original.png"));
    let output = directory.join(format!("{prefix}-final.png"));
    let pixels = ImageBuffer::from_fn(4, 3, |x, y| {
        Rgba([(x * 50) as u8, (y * 70) as u8, (x * 9 + y) as u8, 255])
    });
    let file = std::fs::File::create(&source).unwrap();
    image::codecs::png::PngEncoder::new(file)
        .write_image(
            pixels.as_raw(),
            pixels.width(),
            pixels.height(),
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    let info = edit_image(
        source.display().to_string(),
        output.display().to_string(),
        ImageEditRecipe {
            crop: Some(ImageCrop {
                x: 1,
                y: 0,
                width: 3,
                height: 3,
            }),
            rotation_quarter_turns: 1,
            regions: vec![ImageEditRegion {
                kind: ImageEditRegionKind::Pixelate,
                x: 0,
                y: 0,
                width: 2,
                height: 2,
                strength: 2,
            }],
        },
    )
    .unwrap();
    assert_eq!((info.width, info.height), (3, 3));
    let bytes = std::fs::read(&output).unwrap();
    assert_ne!(bytes, std::fs::read(source).unwrap());
    assert_eq!(
        probe_edited_image(output.display().to_string()).unwrap(),
        info
    );
    (output, bytes)
}

fn canonical_audio(samples: usize) -> Vec<u8> {
    let data_len = (samples * 2) as u32;
    let mut bytes = Vec::with_capacity(44 + data_len as usize);
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&(36 + data_len).to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&16_000u32.to_le_bytes());
    bytes.extend_from_slice(&32_000u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&16u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&data_len.to_le_bytes());
    for index in 0..samples {
        bytes.extend_from_slice(&((index as i16 % 2_000) - 1_000).to_le_bytes());
    }
    bytes
}

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
fn note_to_self_via_ffi_only_is_local_and_durable() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "notes"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    assert_eq!(node.note_to_self_id(), "note_to_self");

    let id = node
        .send_note_to_self("remember the charging cable".to_owned())
        .unwrap();
    let event = recorder.wait("note-to-self event", |event| {
        matches!(event, Event::NoteToSelfMessageAdded { id: event_id, .. } if *event_id == id)
    });
    assert!(matches!(
        event,
        Event::NoteToSelfMessageAdded { conversation, body, .. }
            if conversation == "note_to_self" && body == "remember the charging cable"
    ));
    let history = node.note_to_self_messages().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].conversation, "note_to_self");
    assert_eq!(history[0].body, "remember the charging cable");
    assert_eq!(node.status().unwrap().queued, 0);
    assert_eq!(node.status().unwrap().contacts, 0);

    // Pin scheduling's complete FFI front door in this existing single-node
    // test so the network-heavy e2e cases do not gain another parallel node.
    let own_peer = node
        .add_contact("self".to_owned(), node.handshake_bundle().unwrap(), vec![])
        .unwrap();
    let group = node.create_group("later".to_owned(), vec![]).unwrap();
    let future = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;

    let pair = node
        .schedule(own_peer.clone(), "first draft".to_owned(), future)
        .unwrap();
    node.schedule_group(group.clone(), "group later".to_owned(), future + 60)
        .unwrap();
    let scheduled = node.scheduled_messages().unwrap();
    assert_eq!(scheduled.len(), 2);
    assert_eq!(scheduled[0].conversation, ScheduledConversation::Peer);
    assert_eq!(scheduled[0].destination, own_peer);
    assert_eq!(scheduled[1].conversation, ScheduledConversation::Group);
    assert_eq!(scheduled[1].destination, group);
    assert_eq!(node.status().unwrap().scheduled, 2);

    node.edit_scheduled(pair.clone(), "final text".to_owned(), future + 120)
        .unwrap();
    let scheduled = node.scheduled_messages().unwrap();
    assert_eq!(scheduled[0].body, "final text");
    assert_eq!(scheduled[0].not_before, future + 120);
    node.cancel_scheduled(pair).unwrap();
    assert_eq!(node.scheduled_messages().unwrap().len(), 1);
    node.stop();

    let reopened = KultNode::start(
        test_config(directory.path(), "notes"),
        Box::new(Recorder::default()),
    )
    .expect("node reopens");
    assert_eq!(reopened.note_to_self_messages().unwrap()[0].id, id);
    assert_eq!(reopened.scheduled_messages().unwrap().len(), 1);
    reopened.stop();
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

    // The same carrier verdict that gates attachment activation crosses the
    // bindings as an expiring snapshot and a change event.
    a_rec.wait("alice's realtime carrier verdict", |event| {
        matches!(
            event,
            Event::CarrierCapabilityChanged { snapshot }
                if snapshot.peer == bob_peer
                    && snapshot.capability == CarrierCapability::Realtime
        )
    });
    let carriers = alice.carrier_capabilities().unwrap();
    assert_eq!(carriers.len(), 1);
    assert_eq!(carriers[0].peer, bob_peer);
    assert_eq!(carriers[0].capability, CarrierCapability::Realtime);
    assert!(carriers[0].expires_at > carriers[0].observed_at);

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

    // Attachment calls are path-bounded, typed, and event-compatible across
    // Kotlin/Swift generation without exposing protocol or store internals.
    let attachment_bytes = b"attachment bytes through UniFFI\0exactly";
    let source = dir.path().join("ffi-source.bin");
    let preview = dir.path().join("ffi-preview.jpg");
    let preview_bytes = b"locally generated preview";
    std::fs::write(&source, attachment_bytes).unwrap();
    std::fs::write(&preview, preview_bytes).unwrap();
    let attachment_content_id = alice
        .send_attachment_with_preview(
            bob_peer.clone(),
            source.display().to_string(),
            "application/octet-stream".to_owned(),
            Some("field-notes.bin".to_owned()),
            preview.display().to_string(),
            "image/jpeg".to_owned(),
        )
        .unwrap();
    let outbound = alice.attachments().unwrap();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].content_id, attachment_content_id);
    assert_eq!(outbound[0].direction, AttachmentDirection::Outbound);
    assert_eq!(outbound[0].objects.len(), 2);
    assert_eq!(
        outbound[0].objects[0].filename.as_deref(),
        Some("field-notes.bin")
    );
    alice
        .pause_attachment(outbound[0].transfer_id.clone())
        .unwrap();
    assert_eq!(
        alice.attachments().unwrap()[0].state,
        AttachmentState::Paused
    );
    alice
        .resume_attachment(outbound[0].transfer_id.clone())
        .unwrap();

    let offered = b_rec.wait("attachment offer", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.direction == AttachmentDirection::Inbound
                    && attachment.content_id == attachment_content_id
        )
    });
    let inbound_transfer = match offered {
        Event::AttachmentUpdated { attachment } => {
            assert_eq!(attachment.state, AttachmentState::AwaitingConsent);
            attachment.transfer_id
        }
        other => panic!("wrong event: {other:?}"),
    };
    b_rec.wait("typed attachment message", |event| {
        matches!(
            event,
            Event::MessageReceived { body, content_kind: ContentKind::Attachment, .. }
                if body.is_empty()
        )
    });
    bob.accept_attachment(inbound_transfer.clone()).unwrap();
    b_rec.wait("attachment completion", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.transfer_id == inbound_transfer
                    && attachment.state == AttachmentState::Complete
        )
    });
    let completed = bob.attachments().unwrap();
    assert_eq!(
        completed[0].objects[0].verified_bytes,
        attachment_bytes.len() as u64
    );
    assert_eq!(
        completed[0].objects[1].verified_bytes,
        preview_bytes.len() as u64
    );
    let exported = dir.path().join("ffi-export.bin");
    bob.export_attachment(inbound_transfer.clone(), exported.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(&exported).unwrap(), attachment_bytes);
    let exported_preview = dir.path().join("ffi-export-preview.jpg");
    bob.export_attachment_preview(
        inbound_transfer.clone(),
        exported_preview.display().to_string(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&exported_preview).unwrap(), preview_bytes);
    assert!(bob
        .export_attachment(inbound_transfer, exported.display().to_string())
        .is_err());
    assert_eq!(std::fs::read(&exported).unwrap(), attachment_bytes);
    bob.reject_attachment(completed[0].transfer_id.clone())
        .unwrap();
    assert_eq!(
        bob.attachments().unwrap()[0].state,
        AttachmentState::Rejected
    );
    alice
        .cancel_attachment(outbound[0].transfer_id.clone())
        .unwrap();
    assert_eq!(
        alice.attachments().unwrap()[0].state,
        AttachmentState::Cancelled
    );

    // The same deterministic canonical clip is imported, transferred, and
    // probed through the exact public surface every shell consumes.
    let audio_bytes = canonical_audio(1_600);
    let audio_source = dir.path().join("ffi-audio-message.wav");
    std::fs::write(&audio_source, &audio_bytes).unwrap();
    let audio_info = probe_recorded_audio(audio_source.display().to_string()).unwrap();
    assert_eq!(audio_info.duration_ms, 100);
    let audio_content = alice
        .send_attachment(
            bob_peer.clone(),
            audio_source.display().to_string(),
            "audio/wav".to_owned(),
            Some("audio-message.wav".to_owned()),
        )
        .unwrap();
    let audio_offer = b_rec.wait("audio attachment offer", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.content_id == audio_content
                && attachment.direction == AttachmentDirection::Inbound)
    });
    let audio_transfer = match audio_offer {
        Event::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(audio_transfer.clone()).unwrap();
    b_rec.wait("audio attachment completion", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.transfer_id == audio_transfer
                && attachment.state == AttachmentState::Complete)
    });
    let audio_export = dir.path().join("ffi-audio-received.wav");
    bob.export_attachment(audio_transfer, audio_export.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(&audio_export).unwrap(), audio_bytes);
    assert_eq!(
        probe_recorded_audio(audio_export.display().to_string())
            .unwrap()
            .duration_ms,
        100
    );

    // Only the metadata-free final edit crosses F3; the original remains a
    // distinct local path and the receiver exports byte-for-byte final PNG.
    let (image_source, image_bytes) = edited_image(dir.path(), "ffi-pairwise-image");
    let image_content = alice
        .send_attachment(
            bob_peer.clone(),
            image_source.display().to_string(),
            "image/png".to_owned(),
            Some("edited-image.png".to_owned()),
        )
        .unwrap();
    let image_offer = b_rec.wait("edited image offer", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.content_id == image_content
                && attachment.direction == AttachmentDirection::Inbound)
    });
    let image_transfer = match image_offer {
        Event::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(image_transfer.clone()).unwrap();
    b_rec.wait("edited image completion", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.transfer_id == image_transfer
                && attachment.state == AttachmentState::Complete)
    });
    let image_export = dir.path().join("ffi-pairwise-image-received.png");
    bob.export_attachment(image_transfer, image_export.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(&image_export).unwrap(), image_bytes);
    probe_edited_image(image_export.display().to_string()).unwrap();

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
    let note_id = alice
        .send_note_to_self("survives the backup too".to_owned())
        .unwrap();

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
    let notes = alice.note_to_self_messages().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].id, note_id);
    assert_eq!(notes[0].conversation, "note_to_self");

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

    let group_attachment_bytes = canonical_audio(1_600);
    let group_source = dir.path().join("ffi-group-source.bin");
    std::fs::write(&group_source, &group_attachment_bytes).unwrap();
    let group_content_id = alice
        .send_group_attachment(
            group.clone(),
            group_source.display().to_string(),
            "audio/wav".to_owned(),
            Some("audio-message.wav".to_owned()),
        )
        .unwrap();
    let group_offer = b_rec.wait("group attachment offer", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.conversation == kult_ffi::AttachmentConversation::Group
                    && attachment.content_id == group_content_id
        )
    });
    let group_transfer = match group_offer {
        Event::AttachmentUpdated { attachment } => {
            assert_eq!(attachment.group.as_deref(), Some(group.as_str()));
            attachment.transfer_id
        }
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(group_transfer.clone()).unwrap();
    b_rec.wait("group attachment completion", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.transfer_id == group_transfer
                    && attachment.state == AttachmentState::Complete
        )
    });
    let group_export = dir.path().join("ffi-group-export.bin");
    bob.export_attachment(group_transfer, group_export.display().to_string())
        .unwrap();
    assert_eq!(
        std::fs::read(&group_export).unwrap(),
        group_attachment_bytes
    );
    assert_eq!(
        probe_recorded_audio(group_export.display().to_string())
            .unwrap()
            .duration_ms,
        100
    );

    let (group_image_source, group_image_bytes) = edited_image(dir.path(), "ffi-group-image");
    let group_image_content = alice
        .send_group_attachment(
            group.clone(),
            group_image_source.display().to_string(),
            "image/png".to_owned(),
            Some("edited-image.png".to_owned()),
        )
        .unwrap();
    let group_image_offer = b_rec.wait("group edited image offer", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.content_id == group_image_content
                && attachment.conversation == kult_ffi::AttachmentConversation::Group)
    });
    let group_image_transfer = match group_image_offer {
        Event::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(group_image_transfer.clone()).unwrap();
    b_rec.wait("group edited image completion", |event| {
        matches!(event, Event::AttachmentUpdated { attachment }
            if attachment.transfer_id == group_image_transfer
                && attachment.state == AttachmentState::Complete)
    });
    let group_image_export = dir.path().join("ffi-group-image-received.png");
    bob.export_attachment(
        group_image_transfer,
        group_image_export.display().to_string(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&group_image_export).unwrap(),
        group_image_bytes
    );
    probe_edited_image(group_image_export.display().to_string()).unwrap();

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
